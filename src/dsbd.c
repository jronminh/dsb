// dsbd — the daemon side of dsb, and the tool that turns dsb.conf into
// systemd units.
//
// Serving (what dsb-NAME@.service runs, once per call):
//
//   dsbd --identity NAME [--config FILE]
//
//   systemd starts it per connection (Accept=yes, StandardInput=socket),
//   already as the identity and inside the unit's sandbox; dsbd holds no
//   privilege and changes none. It is the policy point: it checks the caller
//   against dsb.conf, decides whether the mode is allowed, resolves and
//   checks the command, sets the environment, applies the timeout, and runs
//   shells, file reads and writes itself. The kernel backs the command list
//   (ExecPaths=), so a shell or a script cannot reach past it either.
//
// Admin side (used by dsb-admin and the systemd generator):
//
//   dsbd --check      [--config FILE]   validate; "error:"/"warning:" lines
//   dsbd --identities [--config FILE]   enabled identities, one per line
//   dsbd --sysusers   [--config FILE]   sysusers.d lines for static users
//   dsbd --generate DIR [--config FILE] [--dev --rundir DIR] [--dsbd PATH]
//                                        write the units into DIR
//
// Protocol: dsb-proto.h. Every call is logged to stderr (the journal).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "dsb-conf.h"
#include "dsb-proto.h"

#define SOCK 0
#define ID_PATH "/usr/local/bin:/usr/bin:/bin"
#define DSBD_DEFAULT "/usr/libexec/dsb/dsbd"

static void die(const char *msg) {
    fprintf(stderr, "dsbd: %s\n", msg);
    exit(1);
}

static char *kv(const char *k, const char *v) {
    char *s;
    if (asprintf(&s, "%s=%s", k, v) < 0) die("out of memory");
    return s;
}

static int read_full(int fd, void *buf, size_t len) {
    char *p = buf;
    while (len) {
        ssize_t r = read(fd, p, len);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        p += r; len -= (size_t)r;
    }
    return 0;
}

static int write_full(int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len) {
        ssize_t w = write(fd, p, len);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        p += w; len -= (size_t)w;
    }
    return 0;
}

// Walks the NUL-terminated fields of the request.
struct fields { char *p, *end; };
static char *next_field(struct fields *f) {
    if (f->p >= f->end) die("truncated request");
    char *s = f->p;
    char *nul = memchr(s, 0, (size_t)(f->end - s));
    if (!nul) die("unterminated field");
    f->p = nul + 1;
    return s;
}
static long next_count(struct fields *f) {
    char *s = next_field(f), *e;
    long n = strtol(s, &e, 10);
    if (*s == 0 || *e || n < 0 || n > 65536) die("bad count");
    return n;
}

static int allowed_signal(int sig) {
    return sig == SIGINT || sig == SIGTERM || sig == SIGHUP ||
           sig == SIGQUIT || sig == SIGWINCH;
}

static void print_strs(FILE *f, const struct strs *s, const char *none) {
    if (s->n == 0) fputs(none, f);
    for (size_t i = 0; i < s->n; i++) fprintf(f, "%s%s", i ? " " : "", s->v[i]);
    fputc('\n', f);
}

static int is_dsb_user(const struct ident *id) {
    return !id->dynamic && conf_own_user(id->user);
}

// --- admin side -------------------------------------------------------------

static const char *shell_candidates[] = { "/bin/bash", "/bin/sh", NULL };
static const char *lib_dirs[] = {
    "/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
    "/usr/lib/arm-linux-gnueabihf", "/usr/lib/i386-linux-gnu",
    "/usr/lib64", "/lib64", NULL
};

static void exec_path(FILE *f, const char *p) {
    char real[PATH_MAX];
    fprintf(f, " -%s", realpath(p, real) ? real : p);
}

static void generate(struct conf *c, const char *dir, const char *confpath,
                     int dev, const char *rundir, const char *dsbd) {
    char path[PATH_MAX + 64], dsbd_dir[PATH_MAX];
    snprintf(dsbd_dir, sizeof(dsbd_dir), "%s", dsbd);
    *strrchr(dsbd_dir, '/') = 0;
    snprintf(path, sizeof(path), "%s/sockets.target.wants", dir);
    mkdir(path, 0755);
    for (size_t i = 0; i < c->n; i++) {
        struct ident *id = &c->ids[i];
        if (id->callers.n == 0) continue;

        snprintf(path, sizeof(path), "%s/dsb-%s.socket", dir, id->name);
        FILE *f = fopen(path, "w");
        if (!f) die("cannot write units");
        fprintf(f, "# generated from %s by dsbd --generate; edit that file instead\n"
                   "[Unit]\nDescription=dsb identity %s\n\n[Socket]\n"
                   "ListenStream=%s/%s.sock\nAccept=yes\nMaxConnections=64\n"
                   "RemoveOnStop=yes\n",
                confpath, id->name, rundir, id->name);
        if (dev) {
            fputs("SocketMode=0600\n", f);
        } else if (id->callers.n == 1) {
            // only the caller's primary group may connect; SO_PEERCRED
            // then narrows it to the caller itself
            struct passwd *pw = getpwnam(id->callers.v[0]);
            struct group *g = pw ? getgrgid(pw->pw_gid) : NULL;
            fprintf(f, "SocketUser=root\nSocketGroup=%s\nSocketMode=0660\nDirectoryMode=0755\n",
                    g ? g->gr_name : "root");
        } else {
            // several callers: anyone may connect, SO_PEERCRED decides
            fputs("SocketUser=root\nSocketMode=0666\nDirectoryMode=0755\n", f);
        }
        fputs("\n[Install]\nWantedBy=sockets.target\n", f);
        fclose(f);

        snprintf(path, sizeof(path), "%s/dsb-%s@.service", dir, id->name);
        f = fopen(path, "w");
        if (!f) die("cannot write units");
        fprintf(f, "# generated from %s by dsbd --generate; edit that file instead\n"
                   "[Unit]\nDescription=dsb identity %s, one call\n"
                   "CollectMode=inactive-or-failed\n\n[Service]\n"
                   "ExecStart=%s --identity %s", confpath, id->name, dsbd, id->name);
        if (strcmp(confpath, DSB_CONF_DEFAULT)) fprintf(f, " --config %s", confpath);
        fputs("\nStandardInput=socket\nStandardOutput=journal\nStandardError=journal\n"
              "KillMode=control-group\n", f);
        if (!dev) {
            if (id->dynamic) fputs("DynamicUser=yes\n", f);
            else fprintf(f, "User=%s\n", id->user);
            if (is_dsb_user(id)) fprintf(f, "StateDirectory=dsb/%s\n", id->name);
            if (id->groups.n) { fputs("SupplementaryGroups=", f); print_strs(f, &id->groups, ""); }
            fputs("CapabilityBoundingSet=", f);
            print_strs(f, &id->caps, "");
            if (id->caps.n) { fputs("AmbientCapabilities=", f); print_strs(f, &id->caps, ""); }
            fputs("ProtectKernelTunables=yes\nProtectKernelModules=yes\n"
                  "ProtectControlGroups=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\n", f);
        }
        fputs("NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nPrivateTmp=yes\n", f);
        if (id->write.n) {
            fputs("ReadWritePaths=", f);
            for (size_t j = 0; j < id->write.n; j++) fprintf(f, "%s-%s", j ? " " : "", id->write.v[j]);
            fputc('\n', f);
        }
        if (strcmp(id->commands.v[0], "*")) {
            // the kernel's copy of the command list: nothing else is executable
            fputs("NoExecPaths=/\nExecPaths=", f);
            fprintf(f, "-%s", dsbd_dir);
            for (const char **l = lib_dirs; *l; l++) exec_path(f, *l);
            if (id->shell) for (const char **s = shell_candidates; *s; s++) exec_path(f, *s);
            for (size_t j = 0; j < id->commands.n; j++) exec_path(f, id->commands.v[j]);
            fputc('\n', f);
        }
        if (id->timeout) fprintf(f, "RuntimeMaxSec=%ld\n", id->timeout + 10);
        fclose(f);

        char link[PATH_MAX + 64], target[PATH_MAX + 64];
        snprintf(link, sizeof(link), "%s/sockets.target.wants/dsb-%s.socket", dir, id->name);
        snprintf(target, sizeof(target), "../dsb-%s.socket", id->name);
        unlink(link);
        if (symlink(target, link) < 0) die("cannot link the socket into sockets.target");
    }
}

// --- serving ----------------------------------------------------------------

struct call {
    struct ident *id;
    struct ucred cred;
    int fds[3];
    const char *home;
    char **env;
};

__attribute__((format(printf, 2, 3)))
static void say(struct call *k, const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    dprintf(k->fds[2], "dsb: %s\n", buf);
}

// Resolves a command the way execvp would, with the identity's PATH.
static int resolve(const char *cmd, char *out, size_t n) {
    if (strchr(cmd, '/')) {
        char cwd[PATH_MAX];
        if (cmd[0] == '/' || !getcwd(cwd, sizeof(cwd))) snprintf(out, n, "%s", cmd);
        else if (snprintf(out, n, "%s/%s", cwd, cmd) >= (int)n) return -1;
        return access(out, F_OK);
    }
    char dirs[] = ID_PATH, *save = NULL;
    for (char *d = strtok_r(dirs, ":", &save); d; d = strtok_r(NULL, ":", &save)) {
        struct stat st;
        snprintf(out, n, "%s/%s", d, cmd);
        // not access(X_OK): under NoExecPaths= that hides a refused command
        // behind "not found"; policy says "not allowed", exec says the rest
        if (stat(out, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 0111)) return 0;
    }
    return -1;
}

static const char *pick_shell(int *is_bash) {
    *is_bash = access("/bin/bash", X_OK) == 0;
    return *is_bash ? "/bin/bash" : "/bin/sh";
}

static void list(struct call *k) {
    FILE *f = fdopen(dup(k->fds[1]), "w");
    if (!f) return;
    struct ident *id = k->id;
    fprintf(f, "identity  %s\n", id->name);
    if (id->dynamic) fprintf(f, "user      dynamic, a new uid per call (this one: %u)\n", getuid());
    else fprintf(f, "user      %s (uid %u)\n", id->user, getuid());
    fprintf(f, "home      %s\n", k->home);
    fputs("callers   ", f); print_strs(f, &id->callers, "-");
    fprintf(f, "shell     %s\nedit      %s\n", id->shell ? "yes" : "no", id->edit ? "yes" : "no");
    fputs("commands  ", f); print_strs(f, &id->commands, "-");
    fputs("write     ", f); print_strs(f, &id->write, "-");
    fputs("groups    ", f); print_strs(f, &id->groups, "-");
    fputs("caps      ", f); print_strs(f, &id->caps, "-");
    if (id->timeout) fprintf(f, "timeout   %lds\n", id->timeout);
    else fputs("timeout   none\n", f);
    fputs("env       ", f); print_strs(f, &id->env, "-");
    fclose(f);
}

static int which(struct call *k, const char *cmd) {
    char p[PATH_MAX];
    if (resolve(cmd, p, sizeof(p)) < 0) { say(k, "%s: not found", cmd); return 1; }
    int ok = conf_command_ok(k->id, p);
    dprintf(k->fds[1], "%s%s\n", p, ok ? "" : " (not allowed)");
    return ok ? 0 : 1;
}

static int copy_fd(int in, int out) {
    char buf[65536];
    for (;;) {
        ssize_t r = read(in, buf, sizeof(buf));
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) return -1;
        if (r == 0) return 0;
        if (write_full(out, buf, (size_t)r) < 0) return -1;
    }
}

// dsb -e: the file is read and written by the identity, in this sandbox.
// write truncates in place, so an existing file keeps its inode, owner, mode.
static int file_io(struct call *k, int writing, const char *path) {
    if (path[0] != '/') { say(k, "%s: not an absolute path", path); return 1; }
    int fd = writing ? open(path, O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0644)
                     : open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (!writing && errno == ENOENT) return 2;
        say(k, "%s: %s", path, strerror(errno));
        return 1;
    }
    int r = writing ? copy_fd(k->fds[0], fd) : copy_fd(fd, k->fds[1]);
    if (close(fd) < 0) r = -1;
    if (r < 0) { say(k, "%s: %s", path, strerror(errno)); return 1; }
    return 0;
}

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

// Forks the command into its own session on the caller's fds; relays the
// caller's signals and enforces the timeout until it exits.
static int spawn(struct call *k, const char *exe, char **argv, const char *rc) {
    pid_t pid = fork();
    if (pid < 0) die("fork failed");
    if (pid == 0) {
        setsid();
        signal(SIGPIPE, SIG_DFL);
        for (int i = 0; i < 3; i++)
            if (dup2(k->fds[i], i) < 0) _exit(126);   // also closes the socket (fd 0)
        if (rc) {
            // the rc arrives on fd 3; the shell's startup noise about job
            // control goes to /dev/null, the rc restores stderr from fd 4
            int m = memfd_create("dsb-rc", 0);
            if (m < 0 || write_full(m, rc, strlen(rc)) < 0 || lseek(m, 0, SEEK_SET) < 0 ||
                dup2(m, 3) < 0 || dup2(2, 4) < 0) _exit(126);
            int nul = open("/dev/null", O_WRONLY);
            if (nul < 0 || dup2(nul, 2) < 0) _exit(126);
        }
        execve(exe, argv, k->env);
        int e = errno;
        if (rc) dup2(4, 2);
        dprintf(2, "dsb: %s: %s\n", argv[0], strerror(e));
        _exit(e == ENOENT ? 127 : 126);
    }

    int pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
    if (pidfd < 0) die("pidfd_open failed");
    struct pollfd p[2] = { { pidfd, POLLIN, 0 }, { SOCK, POLLIN, 0 } };
    long deadline = k->id->timeout ? now_ms() + k->id->timeout * 1000L : -1;
    int timed_out = 0, status = 0;
    for (;;) {
        int wait = deadline < 0 ? -1 : (int)(deadline - now_ms() > 0 ? deadline - now_ms() : 0);
        int n = poll(p, 2, wait);
        if (n < 0) { if (errno == EINTR) continue; die("poll failed"); }
        if (n == 0) {                   // past the deadline: TERM, then KILL
            kill(-pid, timed_out ? SIGKILL : SIGTERM);
            if (!timed_out) {
                say(k, "timed out after %lds", k->id->timeout);
                fprintf(stderr, "dsbd: timed out\n");
            }
            timed_out = 1;
            deadline = now_ms() + 5000;
            continue;
        }
        if (p[0].revents) {
            if (waitpid(pid, &status, 0) < 0) die("waitpid failed");
            break;
        }
        if (p[1].revents) {
            unsigned char sig;
            ssize_t r = read(SOCK, &sig, 1);
            if (r == 1 && allowed_signal(sig)) {
                if (kill(-pid, sig) < 0) kill(pid, sig);
            } else if (r <= 0) {            // caller gone
                kill(-pid, SIGHUP);
                p[1].fd = -1;
            }
        }
    }
    if (timed_out) return 124;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static int serve(struct conf *c, const char *name) {
    struct call k = { 0 };
    k.id = conf_find(c, name);
    if (!k.id) die("no such identity in dsb.conf");
    signal(SIGPIPE, SIG_IGN);

    // 1. who is calling: the kernel's answer, before anything is read
    socklen_t cl = sizeof(k.cred);
    if (getsockopt(SOCK, SOL_SOCKET, SO_PEERCRED, &k.cred, &cl) < 0)
        die("stdin is not a unix socket (run from dsb-NAME.socket)");
    if (!conf_caller_ok(k.id, k.cred.uid)) {
        fprintf(stderr, "dsbd: refused pid %d uid %u: not a caller of %s\n",
                k.cred.pid, k.cred.uid, name);
        return 1;
    }

    // 2. header + the caller's three fds, in one message
    char hdr[DSB_MAGIC_LEN + 4];
    union { struct cmsghdr h; char buf[CMSG_SPACE(3 * sizeof(int))]; } ctl;
    struct iovec iov = { hdr, sizeof(hdr) };
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                          .msg_control = ctl.buf, .msg_controllen = sizeof(ctl.buf) };
    ssize_t r = recvmsg(SOCK, &msg, MSG_CMSG_CLOEXEC | MSG_WAITALL);
    if (r != (ssize_t)sizeof(hdr) || memcmp(hdr, DSB_MAGIC, DSB_MAGIC_LEN))
        die("bad request header");
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    if (!cm || cm->cmsg_level != SOL_SOCKET || cm->cmsg_type != SCM_RIGHTS ||
        cm->cmsg_len != CMSG_LEN(3 * sizeof(int)) || (msg.msg_flags & MSG_CTRUNC))
        die("request carries no stdin/stdout/stderr");
    memcpy(k.fds, CMSG_DATA(cm), sizeof(k.fds));
    uint32_t len;
    memcpy(&len, hdr + DSB_MAGIC_LEN, 4);
    if (len == 0 || len > DSB_REQ_MAX) die("bad request length");
    char *req = malloc(len);
    if (!req || read_full(SOCK, req, len) < 0) die("truncated request");

    // 3. fields: version, mode, cwd, cwd_strict, argc, argv..., envc, env...
    struct fields f = { req, req + len };
    if (strcmp(next_field(&f), DSB_VERSION)) {
        dprintf(k.fds[2], "dsb: client and dsbd versions differ\n");
        die("protocol version mismatch");
    }
    const char *mode = next_field(&f);
    char *cwd = next_field(&f);
    int strict = !strcmp(next_field(&f), "1");
    long cargc = next_count(&f);
    char **cargv = calloc((size_t)cargc + 1, sizeof(char *));
    for (long i = 0; i < cargc; i++) cargv[i] = next_field(&f);
    long cenvc = next_count(&f);
    k.env = calloc((size_t)cenvc + 8, sizeof(char *));
    long n = 0;
    for (long i = 0; i < cenvc; i++) {
        char *e = next_field(&f);
        // only what dsb.conf lets through, never the identity's own vars
        if (!conf_env_ok(k.id, e) || !strncmp(e, "HOME=", 5) || !strncmp(e, "USER=", 5) ||
            !strncmp(e, "LOGNAME=", 8) || !strncmp(e, "SHELL=", 6) ||
            !strncmp(e, "PATH=", 5) || !strncmp(e, "DSB_", 4) || !strncmp(e, "LD_", 3) ||
            !strncmp(e, "ENV=", 4) || !strncmp(e, "BASH_ENV=", 9))
            continue;
        k.env[n++] = e;
    }
    struct passwd *pw = getpwuid(getuid());
    k.home = pw && pw->pw_dir && *pw->pw_dir ? pw->pw_dir : "/";
    const char *uname = pw ? pw->pw_name : "dsb";
    int is_bash;
    const char *sh = pick_shell(&is_bash);
    k.env[n++] = kv("HOME", k.home);
    k.env[n++] = kv("USER", uname);
    k.env[n++] = kv("LOGNAME", uname);
    k.env[n++] = kv("SHELL", sh);
    k.env[n++] = "PATH=" ID_PATH;
    k.env[n++] = kv("DSB_IDENTITY", name);
    k.env[n] = NULL;

    fprintf(stderr, "dsbd: pid %d uid %u mode %s cwd %s argv", k.cred.pid, k.cred.uid,
            mode, *cwd ? cwd : "~");
    for (long i = 0; i < cargc; i++) fprintf(stderr, " [%s]", cargv[i]);
    fputc('\n', stderr);

    // 4. policy, then the mode
    int status;
    int shell_mode = !strcmp(mode, "shell") || !strcmp(mode, "login") || !strcmp(mode, "line");
    int tty = isatty(k.fds[0]) && isatty(k.fds[1]);
    if (shell_mode && (!k.id->shell || k.id->dynamic)) {
        say(&k, "identity %s has no shell (shell = no in dsb.conf); run a command instead", name);
        status = 1;
    } else if ((!strcmp(mode, "read") || !strcmp(mode, "write")) && !k.id->edit) {
        say(&k, "identity %s may not edit files (edit = no in dsb.conf)", name);
        status = 1;
    } else if (!strcmp(mode, "list")) {
        list(&k);
        status = 0;
    } else if (!strcmp(mode, "which") && cargc == 1) {
        status = which(&k, cargv[0]);
    } else if ((!strcmp(mode, "read") || !strcmp(mode, "write")) && cargc == 1) {
        status = file_io(&k, mode[0] == 'w', cargv[0]);
    } else {
        // everything else runs in a directory: the caller's, or home
        const char *dir = *cwd ? cwd : k.home;
        if (chdir(dir) < 0) {
            if (strict) { say(&k, "cannot enter %s: %s", dir, strerror(errno)); goto reply1; }
            say(&k, "cannot enter %s, using %s", dir, k.home);
            if (chdir(k.home) < 0 && chdir("/") < 0) goto reply1;
        }
        char exe[PATH_MAX], *rc = NULL;
        char **av = calloc((size_t)cargc + 8, sizeof(char *));
        int a = 0;
        if (!strcmp(mode, "cmd") && cargc > 0) {
            if (resolve(cargv[0], exe, sizeof(exe)) < 0) {
                say(&k, "%s: command not found", cargv[0]);
                status = 127; goto reply;
            }
            if (!conf_command_ok(k.id, exe)) {
                say(&k, "%s: not allowed for identity %s (commands in dsb.conf)", exe, name);
                fprintf(stderr, "dsbd: refused command %s\n", exe);
                goto reply1;
            }
            for (long i = 0; i < cargc; i++) av[a++] = cargv[i];
        } else if (!strcmp(mode, "line") && cargc == 1) {
            snprintf(exe, sizeof(exe), "/bin/sh");
            av[a++] = "sh"; av[a++] = "-c"; av[a++] = cargv[0];
        } else if (!strcmp(mode, "shell") || !strcmp(mode, "login")) {
            int login = mode[0] == 'l';
            snprintf(exe, sizeof(exe), "%s", sh);
            av[a++] = is_bash ? "bash" : "sh";
            if (cargc > 0) {                     // -s CMD / -i CMD
                av[a++] = login ? "-lc" : "-c";
                av[a++] = "\"$@\"";
                av[a++] = "dsb";
                for (long i = 0; i < cargc; i++) av[a++] = cargv[i];
            } else if (!tty) {                   // a script on stdin
                if (login) av[a++] = "-l";
            } else {
                // interactive: the rc sets the prompt last, so no profile can
                // hide which identity this is
                const char *profile = login ?
                    "[ -r /etc/profile ] && . /etc/profile\n"
                    "for f in ~/.bash_profile ~/.profile; do [ -r \"$f\" ] && { . \"$f\"; break; }; done\n"
                    : is_bash ? "[ -r ~/.bashrc ] && . ~/.bashrc\n" : "";
                if (asprintf(&rc, "exec 2>&4 4>&-\n%sPS1='%s> '\n", is_bash ? profile : "", name) < 0)
                    die("out of memory");
                if (is_bash) {
                    av[a++] = "--rcfile"; av[a++] = "/dev/fd/3"; av[a++] = "-i";
                } else {
                    k.env[n++] = "ENV=/dev/fd/3";
                    k.env[n] = NULL;
                    if (login) av[a++] = "-l";
                    av[a++] = "-i";
                }
            }
        } else {
            say(&k, "bad request (mode %s)", mode);
            goto reply1;
        }
        av[a] = NULL;
        status = spawn(&k, exe, av, rc);
    }
    goto reply;
reply1:
    status = 1;
reply:;
    char out[DSB_MAGIC_LEN + 1];
    memcpy(out, DSB_MAGIC, DSB_MAGIC_LEN);
    out[DSB_MAGIC_LEN] = (char)(unsigned char)status;
    if (write(SOCK, out, sizeof(out)) < 0) { /* caller gone; nothing to tell */ }
    fprintf(stderr, "dsbd: pid %d exit %d\n", k.cred.pid, status);
    return 0;
}

int main(int argc, char **argv) {
    const char *confpath = DSB_CONF_DEFAULT, *identity = NULL, *gendir = NULL;
    const char *rundir = "/run/dsb", *dsbd = DSBD_DEFAULT;
    int check = 0, idents = 0, sysusers = 0, dev = 0;
    for (int i = 1; i < argc; i++) {
        int more = i + 1 < argc;
        if (!strcmp(argv[i], "--identity") && more) identity = argv[++i];
        else if (!strcmp(argv[i], "--config") && more) confpath = argv[++i];
        else if (!strcmp(argv[i], "--generate") && more) gendir = argv[++i];
        else if (!strcmp(argv[i], "--rundir") && more) rundir = argv[++i];
        else if (!strcmp(argv[i], "--dsbd") && more) dsbd = argv[++i];
        else if (!strcmp(argv[i], "--check")) check = 1;
        else if (!strcmp(argv[i], "--identities")) idents = 1;
        else if (!strcmp(argv[i], "--sysusers")) sysusers = 1;
        else if (!strcmp(argv[i], "--dev")) dev = 1;
        else die("usage: dsbd --identity NAME | --check | --identities | --sysusers |"
                 " --generate DIR [--dev] [--rundir DIR] [--dsbd PATH]  [--config FILE]");
    }
    struct conf c;
    if (conf_load(&c, confpath) < 0) {
        fprintf(stderr, "dsbd: %s\n", c.err);
        return 1;
    }
    if (identity) return serve(&c, identity);
    if (check) {
        int e = conf_check(&c);
        if (e) printf("%s: %d error%s\n", confpath, e, e > 1 ? "s" : "");
        return e ? 1 : 0;
    }
    if (idents) {
        for (size_t i = 0; i < c.n; i++)
            if (c.ids[i].callers.n) puts(c.ids[i].name);
        return 0;
    }
    if (sysusers) {
        for (size_t i = 0; i < c.n; i++)
            if (c.ids[i].callers.n && is_dsb_user(&c.ids[i]))
                printf("u %s - \"dsb identity %s\" /var/lib/dsb/%s /usr/sbin/nologin\n",
                       c.ids[i].user, c.ids[i].name, c.ids[i].name);
        return 0;
    }
    if (gendir) {
        // a generator must never fail the boot: a bad config enables nothing
        if (conf_check(&c)) { fprintf(stderr, "dsbd: dsb.conf has errors; no identity enabled\n"); return 0; }
        generate(&c, gendir, confpath, dev, rundir, dsbd);
        return 0;
    }
    die("nothing to do (see the top of dsbd.c)");
}
