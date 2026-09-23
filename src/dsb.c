// dsb — debian superuser bridge: run a command as a bounded middle identity,
// never root.
//
// The client side. It hands its own stdin/stdout/stderr to dsbd over a unix
// socket and waits for the exit status; it relays nothing but signals.
// Protocol: dsb-proto.h. Design: docs/design.md.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dsb-proto.h"

static const char usage_text[] =
"usage: dsb [options] [--] [CMD [ARG...]]\n"
"  (no CMD)        interactive shell as the identity, prompt \"IDENT> \"\n"
"  -s [CMD...]     shell; with CMD, run it through the shell\n"
"  -i [CMD...]     login shell (profile read, starts in the identity's home)\n"
"  -c 'LINE'       run a shell command line                   (dsh -c)\n"
"  -f FILE         run the command line read from FILE        (dsh -f)\n"
"  -p FILE         feed FILE to the command's stdin           (dsh -p)\n"
"  -e FILE...      edit FILEs: the editor runs as you, the result is\n"
"                  written back as the identity                (sudoedit)\n"
"  -l [CMD]        what the identity is and may do (from dsb.conf); with\n"
"                  CMD, where it resolves and whether it is allowed\n"
"  -D DIR          run in DIR (default: the current directory if the\n"
"                  identity can enter it, else its home)\n"
"  -u IDENT        use identity IDENT (default: dsb); root is refused\n"
"  --preserve-env=VAR[,VAR...]  pass these variables too\n"
"  -v -k -K -n -H  accepted, no effect (no password, nothing to cache)\n"
"  -h, --help      show this help\n"
"\n"
"The command gets your stdin, stdout and stderr themselves (no pty, no\n"
"copying); dsb exits with its status. What an identity may run, whether it\n"
"has a shell, which variables pass (of TERM, COLORTERM, LANG, LANGUAGE,\n"
"LC_* and --preserve-env) is decided by dsbd from /etc/dsb/dsb.conf.\n"
"Socket: $DSB_RUNDIR/IDENT.sock (default /run/dsb, owned by root).\n";

static const char *rundir = "/run/dsb";
static const char *ident = "dsb";
static char sockpath[PATH_MAX];

static void die(const char *fmt, const char *arg) {
    fputs("dsb: ", stderr);
    fprintf(stderr, fmt, arg);
    fputc('\n', stderr);
    exit(1);
}

// --- a growable list of strings, for argv and env --------------------------
struct list { char **v; size_t n, cap; };
static void add(struct list *l, const char *s) {
    if (l->n + 1 >= l->cap) {
        l->cap = l->cap ? 2 * l->cap : 16;
        l->v = realloc(l->v, l->cap * sizeof(char *));
        if (!l->v) die("%s", "out of memory");
    }
    l->v[l->n++] = strdup(s);
    l->v[l->n] = NULL;
}

// --- the request ------------------------------------------------------------
struct blob { char *p; size_t n, cap; };
static void put(struct blob *b, const char *s) {
    size_t k = strlen(s) + 1;
    if (b->n + k > b->cap) {
        while (b->n + k > b->cap) b->cap = b->cap ? 2 * b->cap : 4096;
        b->p = realloc(b->p, b->cap);
        if (!b->p) die("%s", "out of memory");
    }
    memcpy(b->p + b->n, s, k);
    b->n += k;
}
static void put_count(struct blob *b, size_t n) {
    char s[32];
    snprintf(s, sizeof(s), "%zu", n);
    put(b, s);
}

static volatile sig_atomic_t pending[65];
static void on_signal(int sig) { pending[sig] = 1; }
static const int relayed[] = { SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGWINCH };
#define NRELAYED (sizeof(relayed) / sizeof(relayed[0]))

// Runs argv as the identity with the given fds; returns its exit status.
static int run(const char *mode, struct list *argv, const char *cwd, int strict,
               struct list *env, const int fds[3]) {
    struct blob b = { 0 };
    put(&b, DSB_VERSION);
    put(&b, mode);
    put(&b, cwd);
    put(&b, strict ? "1" : "0");
    put_count(&b, argv->n);
    for (size_t i = 0; argv->v && i < argv->n; i++) put(&b, argv->v[i]);
    put_count(&b, env->n);
    for (size_t i = 0; i < env->n; i++) put(&b, env->v[i]);
    if (b.n > DSB_REQ_MAX) die("%s", "request too large");

    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    if (strlen(sockpath) >= sizeof(a.sun_path)) die("socket path too long: %s", sockpath);
    memcpy(a.sun_path, sockpath, strlen(sockpath) + 1);
    if (s < 0 || connect(s, (struct sockaddr *)&a, sizeof(a)) < 0)
        die("cannot reach %s", sockpath);

    char hdr[DSB_MAGIC_LEN + 4];
    uint32_t len = (uint32_t)b.n;
    memcpy(hdr, DSB_MAGIC, DSB_MAGIC_LEN);
    memcpy(hdr + DSB_MAGIC_LEN, &len, 4);
    struct iovec iov[2] = { { hdr, sizeof(hdr) }, { b.p, b.n } };
    union { struct cmsghdr h; char buf[CMSG_SPACE(3 * sizeof(int))]; } ctl;
    memset(&ctl, 0, sizeof(ctl));
    struct msghdr m = { .msg_iov = iov, .msg_iovlen = 2,
                        .msg_control = ctl.buf, .msg_controllen = sizeof(ctl.buf) };
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(3 * sizeof(int));
    memcpy(CMSG_DATA(c), fds, 3 * sizeof(int));
    ssize_t sent = sendmsg(s, &m, MSG_NOSIGNAL);
    if (sent < 0) die("cannot send the request to %s", sockpath);
    size_t total = sizeof(hdr) + b.n;
    // the fds rode on the first byte; the rest of a large request follows
    for (size_t off = (size_t)sent; off < total; ) {
        const char *p = off < sizeof(hdr) ? hdr + off : b.p + (off - sizeof(hdr));
        size_t k = off < sizeof(hdr) ? sizeof(hdr) - off : total - off;
        ssize_t w = send(s, p, k, MSG_NOSIGNAL);
        if (w < 0) { if (errno == EINTR) continue; die("cannot send the request to %s", sockpath); }
        off += (size_t)w;
    }
    free(b.p);

    // wait for the status; meanwhile pass on the signals the terminal sends us
    sigset_t block, empty;
    sigemptyset(&block);
    sigemptyset(&empty);
    for (size_t i = 0; i < NRELAYED; i++) sigaddset(&block, relayed[i]);
    sigprocmask(SIG_BLOCK, &block, NULL);
    char reply[DSB_MAGIC_LEN + 1];
    size_t got = 0;
    struct pollfd p = { s, POLLIN, 0 };
    for (;;) {
        for (size_t i = 0; i < NRELAYED; i++)
            if (pending[relayed[i]]) {
                pending[relayed[i]] = 0;
                unsigned char sig = (unsigned char)relayed[i];
                if (send(s, &sig, 1, MSG_NOSIGNAL) < 0) { /* reply tells */ }
            }
        if (ppoll(&p, 1, NULL, &empty) < 0) {
            if (errno == EINTR) continue;
            die("%s", "poll failed");
        }
        ssize_t r = read(s, reply + got, sizeof(reply) - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) die("identity %s closed the connection without a status (see its journal)", ident);
        got += (size_t)r;
        if (got == sizeof(reply)) break;
    }
    sigprocmask(SIG_UNBLOCK, &block, NULL);
    close(s);
    if (memcmp(reply, DSB_MAGIC, DSB_MAGIC_LEN)) die("%s", "bad reply");
    return (unsigned char)reply[DSB_MAGIC_LEN];
}

static uint64_t hash_file(int fd) {
    uint64_t h = 1469598103934665603ULL;
    char buf[65536];
    ssize_t r;
    lseek(fd, 0, SEEK_SET);
    while ((r = read(fd, buf, sizeof(buf))) > 0)
        for (ssize_t i = 0; i < r; i++) h = (h ^ (unsigned char)buf[i]) * 1099511628211ULL;
    return h;
}

// sudoedit: dsbd reads the file as the identity, the caller edits a copy,
// dsbd writes it back into the same inode (owner and mode of an existing
// file stay).
static int edit(int argc, char **argv, struct list *env) {
    const char *editor = getenv("SUDO_EDITOR");
    if (!editor || !*editor) editor = getenv("VISUAL");
    if (!editor || !*editor) editor = getenv("EDITOR");
    if (!editor || !*editor) editor = "vi";
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir || !*tmpdir) tmpdir = "/tmp";
    int rc = 0;
    for (int i = 0; i < argc; i++) {
        char abs[PATH_MAX], cwd[PATH_MAX], tmp[PATH_MAX];
        if (argv[i][0] == '/') snprintf(abs, sizeof(abs), "%s", argv[i]);
        else if (!getcwd(cwd, sizeof(cwd))) die("%s", "cannot resolve the current directory");
        else if (snprintf(abs, sizeof(abs), "%s/%s", cwd, argv[i]) >= (int)sizeof(abs))
            die("path too long: %s", argv[i]);
        const char *base = strrchr(abs, '/') + 1;
        snprintf(tmp, sizeof(tmp), "%s/dsb.XXXXXX-%s", tmpdir, base);
        int t = mkstemps(tmp, (int)strlen(base) + 1);
        if (t < 0) die("cannot create a temporary file in %s", tmpdir);

        struct list a = { 0 };
        add(&a, abs);
        int devnull = open("/dev/null", O_RDONLY);
        int out[3] = { devnull, t, 2 };
        int r = run("read", &a, "", 0, env, out);
        if (r != 0 && r != 2) {                 // 2: a new file; else dsbd said why
            unlink(tmp); rc = 1; continue;
        }
        close(devnull);
        uint64_t before = hash_file(t);

        pid_t pid = fork();
        if (pid == 0) {
            execl("/bin/sh", "sh", "-c", "exec $0 \"$1\"", editor, tmp, (char *)NULL);
            _exit(127);
        }
        int st;
        waitpid(pid, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st)) {
            fprintf(stderr, "dsb: editor failed, %s unchanged\n", argv[i]);
            unlink(tmp); rc = 1; continue;
        }
        close(t);
        t = open(tmp, O_RDONLY);
        if (hash_file(t) == before) {
            fprintf(stderr, "dsb: %s unchanged\n", argv[i]);
            unlink(tmp); continue;
        }
        lseek(t, 0, SEEK_SET);
        int in[3] = { t, 1, 2 };
        if (run("write", &a, "", 0, env, in) != 0) {
            fprintf(stderr, "dsb: cannot write %s; your edit is kept in %s\n", argv[i], tmp);
            rc = 1; continue;
        }
        close(t);
        unlink(tmp);
    }
    return rc;
}

int main(int argc, char **argv) {
    enum { CMD, SHELL, LOGIN, LINE, EDIT, LIST } mode = CMD;
    const char *line = NULL, *dir = NULL, *stdin_file = NULL;
    struct list keep = { 0 };
    const char *defaults[] = { "TERM", "COLORTERM", "LANG", "LANGUAGE" };
    for (size_t i = 0; i < 4; i++) add(&keep, defaults[i]);

    int i = 1;
    for (; i < argc && argv[i][0] == '-'; i++) {
        const char *o = argv[i];
        int more = i + 1 < argc;
        if (!strcmp(o, "--")) { i++; break; }
        else if (!strcmp(o, "-s")) mode = SHELL;
        else if (!strcmp(o, "-i")) mode = LOGIN;
        else if (!strcmp(o, "-e")) mode = EDIT;
        else if (!strcmp(o, "-l")) mode = LIST;
        else if (!strcmp(o, "-c") && more) { mode = LINE; line = argv[++i]; }
        else if (!strcmp(o, "-f") && more) {
            FILE *fp = strcmp(argv[++i], "-") ? fopen(argv[i], "r") : stdin;
            if (!fp) die("cannot read %s", argv[i]);
            static char buf[DSB_REQ_MAX / 2];
            size_t k = fread(buf, 1, sizeof(buf) - 1, fp);
            buf[k] = 0;
            mode = LINE; line = buf;
        }
        else if (!strcmp(o, "-p") && more) stdin_file = argv[++i];
        else if (!strcmp(o, "-D") && more) dir = argv[++i];
        else if (!strcmp(o, "-u") && more) ident = argv[++i];
        else if (!strncmp(o, "--preserve-env=", 15)) {
            char *v = strdup(o + 15), *save = NULL;
            for (char *t = strtok_r(v, ",", &save); t; t = strtok_r(NULL, ",", &save)) add(&keep, t);
        }
        else if (!strcmp(o, "-v") || !strcmp(o, "-k") || !strcmp(o, "-K") ||
                 !strcmp(o, "-n") || !strcmp(o, "-H")) ;
        else if (!strcmp(o, "-h") || !strcmp(o, "--help")) { fputs(usage_text, stdout); return 0; }
        else die("unknown option or missing argument: %s (see dsb -h)", o);
    }
    int nargs = argc - i;
    char **args = argv + i;

    if (!strcmp(ident, "root") || !strcmp(ident, "0")) die("%s", "the target is never root");
    if (!*ident || strspn(ident, "abcdefghijklmnopqrstuvwxyz0123456789_-") != strlen(ident))
        die("bad identity name: %s", ident);
    if (mode == CMD && nargs == 0) mode = SHELL;                 // bare `dsb`

    const char *rd = getenv("DSB_RUNDIR");
    if (rd && *rd) rundir = rd;
    struct stat st;
    if (stat(rundir, &st) < 0) die("no dsb here (%s missing: the admin installs and enables it)", rundir);
    if (!(rd && *rd) && st.st_uid != 0) die("%s is not owned by root; refusing to use it", rundir);
    snprintf(sockpath, sizeof(sockpath), "%s/%s.sock", rundir, ident);
    if (stat(sockpath, &st) < 0 || !S_ISSOCK(st.st_mode))
        die("no identity '%s' here (the admin adds identities in /etc/dsb/dsb.conf)", ident);

    struct list env = { 0 };
    extern char **environ;
    for (char **e = environ; *e; e++) {
        size_t k = strcspn(*e, "=");
        int pass = !strncmp(*e, "LC_", 3);
        for (size_t j = 0; j < keep.n && !pass; j++)
            pass = strlen(keep.v[j]) == k && !strncmp(*e, keep.v[j], k);
        if (pass) add(&env, *e);
    }

    if (mode == EDIT) {
        if (nargs == 0) die("%s", "-e needs at least one file");
        return edit(nargs, args, &env);
    }

    struct list rargv = { 0 };
    static const char *wire[] = { "cmd", "shell", "login", "line", "", "list" };
    const char *m = wire[mode];
    if (mode == LINE) add(&rargv, line);
    else if (mode == LIST && nargs > 0) { m = "which"; add(&rargv, args[0]); }
    else if (mode != LIST) for (int j = 0; j < nargs; j++) add(&rargv, args[j]);

    char cwd[PATH_MAX] = "";
    int strict = 0;
    if (dir) { snprintf(cwd, sizeof(cwd), "%s", dir); strict = 1; }
    else if (mode != LOGIN && !getcwd(cwd, sizeof(cwd))) cwd[0] = 0;

    int fds[3] = { 0, 1, 2 };
    if (stdin_file && (fds[0] = open(stdin_file, O_RDONLY)) < 0) die("cannot read %s", stdin_file);

    struct sigaction sa = { .sa_handler = on_signal };
    for (size_t j = 0; j < NRELAYED; j++) sigaction(relayed[j], &sa, NULL);
    // Ctrl-Z would stop only us and leave the command on the terminal
    signal(SIGTSTP, SIG_IGN);
    return run(m, &rargv, cwd, strict, &env, fds);
}
