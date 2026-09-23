// dsb configuration parser and checker; format in dsb-conf.h.
#define _GNU_SOURCE
#include "dsb-conf.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void seterr(struct conf *c, const char *file, int line, const char *msg, const char *arg) {
    if (c->err) return;
    if (asprintf(&c->err, "%s:%d: %s%s%s", file, line, msg, arg ? ": " : "", arg ? arg : "") < 0)
        c->err = "out of memory";
}

static void strs_split(struct strs *s, const char *val) {
    char *copy = strdup(val), *save = NULL;
    s->v = NULL; s->n = 0;
    for (char *t = strtok_r(copy, " \t", &save); t; t = strtok_r(NULL, " \t", &save)) {
        s->v = realloc(s->v, (s->n + 2) * sizeof(char *));
        s->v[s->n++] = strdup(t);
        s->v[s->n] = NULL;
    }
    free(copy);
}

// deny-* keys add up across dsb.conf and conf.d/, like the deny list itself
static void strs_append(struct strs *s, const char *val) {
    struct strs more;
    strs_split(&more, val);
    for (size_t i = 0; i < more.n; i++) {
        s->v = realloc(s->v, (s->n + 2) * sizeof(char *));
        s->v[s->n++] = more.v[i];
        s->v[s->n] = NULL;
    }
    free(more.v);
}

static int parse_bool(const char *v, int *out) {
    if (!strcmp(v, "yes") || !strcmp(v, "true") || !strcmp(v, "1")) { *out = 1; return 0; }
    if (!strcmp(v, "no") || !strcmp(v, "false") || !strcmp(v, "0")) { *out = 0; return 0; }
    return -1;
}

static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = 0;
    return s;
}

static int load_file(struct conf *c, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { seterr(c, path, 0, "cannot read", strerror(errno)); return -1; }
    char buf[4096];
    int line = 0;
    struct ident *cur = NULL;
    int in_global = 0;
    while (fgets(buf, sizeof(buf), f)) {
        line++;
        char *hash = strchr(buf, '#');
        if (hash) *hash = 0;
        char *s = trim(buf);
        if (!*s) continue;
        if (*s == '[') {
            char *end = strchr(s, ']');
            if (!end || end[1]) { seterr(c, path, line, "bad section", s); break; }
            *end = 0;
            char *sec = trim(s + 1);
            if (!strcmp(sec, "global")) { in_global = 1; cur = &c->global; continue; }
            if (strncmp(sec, "identity", 8) || !isspace((unsigned char)sec[8])) {
                seterr(c, path, line, "unknown section", sec); break;
            }
            char *name = trim(sec + 8);
            if (conf_find(c, name)) { seterr(c, path, line, "identity defined twice", name); break; }
            c->ids = realloc(c->ids, (c->n + 1) * sizeof(struct ident));
            cur = &c->ids[c->n++];
            memset(cur, 0, sizeof(*cur));
            cur->name = strdup(name);
            cur->edit = 1;
            cur->network = cur->jit = 1;
            in_global = 0;
            continue;
        }
        if (!cur) { seterr(c, path, line, "key outside a section", s); break; }
        char *eq = strchr(s, '=');
        if (!eq) { seterr(c, path, line, "expected key = value", s); break; }
        *eq = 0;
        char *k = trim(s), *v = trim(eq + 1);
        int global_ok = !strcmp(k, "callers") || !strcmp(k, "env") || !strcmp(k, "timeout");
        int global_only = !strncmp(k, "deny-", 5);
        if (in_global && !global_ok && !global_only) { seterr(c, path, line, "not a [global] key", k); break; }
        if (!in_global && global_only) { seterr(c, path, line, "only in [global]", k); break; }
        if (!strcmp(k, "callers")) { strs_split(&cur->callers, v); cur->has_callers = 1; }
        else if (!strcmp(k, "env")) { strs_split(&cur->env, v); cur->has_env = 1; }
        else if (!strcmp(k, "timeout")) {
            char *e;
            cur->timeout = strtol(v, &e, 10);
            if (!*v || *e || cur->timeout < 0) { seterr(c, path, line, "bad timeout", v); break; }
            cur->has_timeout = 1;
        }
        else if (!strcmp(k, "user")) {
            if (!strcmp(v, "dynamic")) cur->dynamic = 1; else cur->user = strdup(v);
        }
        else if (!strcmp(k, "shell")) { if (parse_bool(v, &cur->shell)) { seterr(c, path, line, "shell: yes or no", v); break; } }
        else if (!strcmp(k, "edit")) { if (parse_bool(v, &cur->edit)) { seterr(c, path, line, "edit: yes or no", v); break; } }
        else if (!strcmp(k, "commands")) { strs_split(&cur->commands, v); cur->has_commands = 1; }
        else if (!strcmp(k, "network")) { if (parse_bool(v, &cur->network)) { seterr(c, path, line, "network: yes or no", v); break; } }
        else if (!strcmp(k, "jit")) { if (parse_bool(v, &cur->jit)) { seterr(c, path, line, "jit: yes or no", v); break; } }
        else if (!strcmp(k, "namespaces")) { if (parse_bool(v, &cur->namespaces)) { seterr(c, path, line, "namespaces: yes or no", v); break; } }
        else if (!strcmp(k, "devices")) {
            if (!strcmp(v, "auto")) cur->no_devices = 0;
            else if (!strcmp(v, "none")) cur->no_devices = 1;
            else { seterr(c, path, line, "devices: auto or none", v); break; }
        }
        else if (!strcmp(k, "write")) strs_split(&cur->write, v);
        else if (!strcmp(k, "groups")) strs_split(&cur->groups, v);
        else if (!strcmp(k, "caps")) strs_split(&cur->caps, v);
        else if (!strcmp(k, "write-extra")) strs_split(&cur->write_extra, v);
        else if (!strcmp(k, "groups-extra")) strs_split(&cur->groups_extra, v);
        else if (!strcmp(k, "caps-extra")) strs_split(&cur->caps_extra, v);
        else if (!strcmp(k, "deny-paths")) strs_append(&cur->deny_paths, v);
        else if (!strcmp(k, "deny-groups")) strs_append(&cur->deny_groups, v);
        else if (!strcmp(k, "deny-caps")) strs_append(&cur->deny_caps, v);
        else { seterr(c, path, line, "unknown key", k); break; }
    }
    fclose(f);
    return c->err ? -1 : 0;
}

int conf_load(struct conf *c, const char *path) {
    memset(c, 0, sizeof(*c));
    c->global.edit = 1;
    if (load_file(c, path) < 0) return -1;
    char dir[PATH_MAX], pat[PATH_MAX + 16];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) *slash = 0; else snprintf(dir, sizeof(dir), ".");
    snprintf(pat, sizeof(pat), "%s/conf.d/*.conf", dir);
    glob_t g;
    if (glob(pat, 0, NULL, &g) == 0) {
        for (size_t i = 0; i < g.gl_pathc; i++)
            if (load_file(c, g.gl_pathv[i]) < 0) { globfree(&g); return -1; }
        globfree(&g);
    }
    for (size_t i = 0; i < c->n; i++) {
        struct ident *id = &c->ids[i];
        if (!id->has_callers) id->callers = c->global.callers;
        if (!id->has_env) id->env = c->global.env;
        if (!id->has_timeout) id->timeout = c->global.timeout;
        if (!id->has_commands) strs_split(&id->commands, "*");
        if (!id->user) {
            if (asprintf(&id->user, "%s%s", strcmp(id->name, "dsb") ? "dsb-" : "",
                         strcmp(id->name, "dsb") ? id->name : "dsb") < 0) return -1;
        }
    }
    return 0;
}

int conf_own_user(const char *user) {
    return !strcmp(user, "dsb") || !strncmp(user, "dsb-", 4);
}

struct ident *conf_find(struct conf *c, const char *name) {
    for (size_t i = 0; i < c->n; i++)
        if (!strcmp(c->ids[i].name, name)) return &c->ids[i];
    return NULL;
}

int conf_caller_ok(const struct ident *id, uid_t uid) {
    for (size_t i = 0; i < id->callers.n; i++) {
        struct passwd *pw = getpwnam(id->callers.v[i]);
        if (pw && pw->pw_uid == uid && uid != 0) return 1;
    }
    return 0;
}

int conf_env_ok(const struct ident *id, const char *kv) {
    size_t k = strcspn(kv, "=");
    if (!kv[k]) return 0;
    for (size_t i = 0; i < id->env.n; i++) {
        const char *p = id->env.v[i];
        size_t n = strlen(p);
        if (n && p[n - 1] == '*') { if (k >= n - 1 && !strncmp(kv, p, n - 1)) return 1; }
        else if (n == k && !strncmp(kv, p, k)) return 1;
    }
    return 0;
}

int conf_command_ok(const struct ident *id, const char *path) {
    char real[PATH_MAX], lreal[PATH_MAX];
    int have_real = realpath(path, real) != NULL;
    for (size_t i = 0; i < id->commands.n; i++) {
        const char *c = id->commands.v[i];
        if (!strcmp(c, "*")) return 1;
        if (!strcmp(c, path)) return 1;
        if (have_real && realpath(c, lreal) && !strcmp(lreal, real)) return 1;
    }
    return 0;
}

// --- checks -------------------------------------------------------------------
//
// The fixed limits and their sources: docs/standards.md. Each field has an
// allowlist (KEY =, silent), room outside it (KEY-extra =, warned) and a deny
// list no key reaches. The deny list is compiled in, so it cannot go missing
// and fail open; [global] deny-* only adds to it.

struct entry { const char *name, *why; };

// Rule 4: paths root reads as instructions or executes (FHS 3.0). A write
// on one, or on a parent of one, feeds root.
static const struct entry deny_paths[] = {
    { "/etc", "host config, read by root (FHS)" },
    { "/usr", "programs and libraries root executes (FHS)" },
    { "/bin", "programs (FHS)" }, { "/sbin", "programs (FHS)" },
    { "/lib", "libraries (FHS)" }, { "/lib64", "libraries (FHS)" },
    { "/opt", "add-on software, executed (FHS)" },
    { "/boot", "kernel and boot loader (FHS)" },
    { "/root", "root's home" },
    { "/home", "users' dotfiles, run by their shells" },
    { "/run/user", "users' runtime dirs, with their own systemd and D-Bus" },
    { "/var/spool", "work queued for root daemons: cron, mail (FHS)" },
    { "/var/lib/dpkg", "the package database" },
    { "/var/lib/apt", "package lists apt trusts as verified" },
    { "/var/cache/apt", "packages apt installs" },
    { "/var/cache/debconf", "answers root's package scripts read" },
    { "/var/lib/polkit-1", "polkit authorizations" },
    { "/var/lib/sudo", "sudo's timestamps" },
    { "/var/lib/systemd", "systemd state: linger, timers, credentials" },
    { "/var/lib/private", "other services' DynamicUser state" },
    { "/var/lib/dsb", "the homes of dsb identities" },
    { "/proc", "kernel interfaces" }, { "/sys", "kernel interfaces" },
    { "/dev", "devices" },
    { NULL, NULL }
};
// Rule 4, the allowlist: data directories (FHS 3.0), strictly below these...
static const char *std_write_below[] = { "/srv", "/var/lib", "/var/cache", NULL };
// ...or at or below these (/var/www: a Debian convention)
static const char *std_write_at[] = { "/var/www", NULL };

// Rule 2: groups base-passwd (/usr/share/doc/base-passwd/users-and-groups.txt)
// or their own package documents as root-equivalent or privileged.
static const struct entry deny_groups[] = {
    { "root", "the superuser's group (base-passwd)" },
    { "sudo", "\"may run any command as any user\" (base-passwd)" },
    { "wheel", "sudo's group on other distributions" },
    { "admin", "sudo's group on older Ubuntu" },
    { "disk", "\"mostly equivalent to root access\" (base-passwd)" },
    { "staff", "\"effectively equivalent to root access\" (base-passwd)" },
    { "kmem", "reads system memory (base-passwd)" },
    { "shadow", "reads /etc/shadow (base-passwd)" },
    { "tty", "writes to other users' terminals (base-passwd)" },
    { "utmp", "writes login records (base-passwd)" },
    { "src", "manages /usr/src (base-passwd)" },
    { "adm", "reads every log, and logs hold secrets (stricter than base-passwd)" },
    { "docker", "the docker daemon runs anything as root" },
    { "lxd", "lxd starts privileged containers" },
    { "incus-admin", "incus starts privileged containers" },
    { "libvirt", "libvirt starts VMs with host devices" },
    { NULL, NULL }
};
// Rule 2, the allowlist: device groups with no path to root (base-passwd),
// and systemd-journal (reads the journal); dsb's own groups are added in
// std_group().
static const char *std_groups[] = {
    "audio", "video", "render", "plugdev", "dialout", "cdrom", "floppy", "tape",
    "systemd-journal", NULL
};
static const char *device_groups[] = {
    "audio", "video", "render", "plugdev", "dialout", "cdrom", "floppy", "tape", NULL
};

// Rule 3: capabilities that lead to full root. The first 19 are Spengler's,
// "False Boundaries and Arbitrary Code Execution" (grsecurity, 2011); the
// last four are newer than that paper.
static const struct entry deny_caps[] = {
    { "CAP_SYS_ADMIN", "mounts over any binary (Spengler)" },
    { "CAP_SYS_TTY_CONFIG", "remaps the admin's keyboard (Spengler)" },
    { "CAP_MKNOD", "creates disk devices (Spengler)" },
    { "CAP_SYS_PTRACE", "takes over any process (Spengler)" },
    { "CAP_SYS_RAWIO", "raw I/O into the kernel (Spengler)" },
    { "CAP_SYS_MODULE", "loads kernel code (Spengler)" },
    { "CAP_SETFCAP", "gives files any capability (Spengler)" },
    { "CAP_FSETID", "keeps setgid bits on files it writes (Spengler)" },
    { "CAP_SETGID", "becomes any group (Spengler)" },
    { "CAP_SETUID", "becomes root (Spengler)" },
    { "CAP_DAC_OVERRIDE", "writes files root runs (Spengler)" },
    { "CAP_SETPCAP", "gains any capability (Spengler)" },
    { "CAP_IPC_OWNER", "takes over privileged IPC (Spengler)" },
    { "CAP_CHOWN", "takes /etc/shadow (Spengler)" },
    { "CAP_SYS_CHROOT", "runs setuid programs over a forged libc (Spengler)" },
    { "CAP_DAC_READ_SEARCH", "reads /etc/shadow and root's keys (Spengler)" },
    { "CAP_SYS_BOOT", "boots another kernel (Spengler)" },
    { "CAP_AUDIT_CONTROL", "logs the admin's terminal (Spengler)" },
    { "CAP_FOWNER", "chmods any file (Spengler)" },
    { "CAP_BPF", "loads kernel programs (newer than Spengler)" },
    { "CAP_PERFMON", "reads kernel memory by tracing (newer than Spengler)" },
    { "CAP_MAC_ADMIN", "changes the LSM policy" },
    { "CAP_MAC_OVERRIDE", "bypasses the LSM policy" },
    { NULL, NULL }
};
// Rule 3, the allowlist: no known path to root (Spengler; capabilities(7)).
static const char *std_caps[] = {
    "CAP_NET_BIND_SERVICE", "CAP_NET_RAW", "CAP_SYS_NICE", "CAP_SYS_TIME",
    "CAP_IPC_LOCK", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", NULL
};
// Every other capability: caps-extra only. CAP_NET_ADMIN is here: not root
// (Spengler), but it reconfigures the whole network.
static const char *other_caps[] = {
    "CAP_NET_ADMIN", "CAP_NET_BROADCAST", "CAP_KILL", "CAP_LEASE",
    "CAP_LINUX_IMMUTABLE", "CAP_AUDIT_READ", "CAP_AUDIT_WRITE", "CAP_SYSLOG",
    "CAP_SYS_PACCT", "CAP_SYS_RESOURCE", "CAP_CHECKPOINT_RESTORE", NULL
};

// Programs that run other programs or code: allowing one allows whatever it
// can reach (still bounded by the exec allowlist and the sandbox).
static const char *runners[] = {
    "sh", "bash", "dash", "zsh", "ksh", "fish", "busybox", "env", "xargs", "find",
    "python3", "python", "perl", "ruby", "node", "lua", "awk", "gawk", "mawk",
    "sed", "vi", "vim", "nvim", "less", "more", "tar", "make", "git", "ssh",
    "sudo", "su", "nohup", "timeout", "nice", "flock", "script", NULL
};

static int in_list(const char *s, const char **l) {
    for (; *l; l++) if (!strcmp(s, *l)) return 1;
    return 0;
}

static int in_strs(const char *s, const struct strs *l) {
    for (size_t i = 0; i < l->n; i++) if (!strcmp(s, l->v[i])) return 1;
    return 0;
}

// 1 if A equals B or one contains the other, comparing path components.
static int overlaps(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b), n = la < lb ? la : lb;
    if (strncmp(a, b, n)) return 0;
    if (la == lb) return 1;
    const char *longer = la > lb ? a : b;
    return n == 1 || longer[n] == '/';     // n == 1: one of them is "/"
}

// 1 if A is B or below it
static int at_or_below(const char *a, const char *b) {
    size_t lb = strlen(b);
    return !strncmp(a, b, lb) && (a[lb] == 0 || a[lb] == '/');
}

static const char *added = "added in [global]";

static const char *denied(const char *s, const struct entry *l, const struct strs *more) {
    for (; l->name; l++) if (!strcmp(s, l->name)) return l->why;
    return in_strs(s, more) ? added : NULL;
}

// The deny entry PATH overlaps, or NULL. With dev, your own runtime dir is
// allowed: in --dev mode the identity is you.
static const struct entry *denied_path(struct conf *c, const char *path, int dev) {
    static struct entry hit;
    char own[64];
    snprintf(own, sizeof(own), "/run/user/%u", (unsigned)getuid());
    int mine = dev && at_or_below(path, own) && strcmp(path, own);
    for (const struct entry *e = deny_paths; e->name; e++) {
        if (mine && !strcmp(e->name, "/run/user")) continue;
        if (overlaps(path, e->name)) return e;
    }
    for (size_t i = 0; i < c->global.deny_paths.n; i++)
        if (overlaps(path, c->global.deny_paths.v[i])) {
            hit.name = c->global.deny_paths.v[i]; hit.why = added;
            return &hit;
        }
    return NULL;
}

static int std_path(const char *path) {
    for (const char **p = std_write_below; *p; p++)
        if (at_or_below(path, *p) && strcmp(path, *p)) return 1;
    for (const char **p = std_write_at; *p; p++)
        if (at_or_below(path, *p)) return 1;
    return 0;
}

// 1 if a package owns PATH or anything below it, 0 if none does, -1 if dpkg
// cannot say. Runs dpkg-query with an empty environment (no DPKG_ADMINDIR).
static int package_owned(const char *path) {
    if (access("/usr/bin/dpkg-query", X_OK)) return -1;
    char below[PATH_MAX + 4];
    snprintf(below, sizeof(below), "%s/*", path);
    const char *pats[] = { path, below };
    fflush(stdout);
    for (int i = 0; i < 2; i++) {
        pid_t p = fork();
        if (p < 0) return -1;
        if (p == 0) {
            int nul = open("/dev/null", O_RDWR);
            if (nul >= 0) { dup2(nul, 1); dup2(nul, 2); }
            char *env[] = { NULL };
            execle("/usr/bin/dpkg-query", "dpkg-query", "-S", pats[i], (char *)NULL, env);
            _exit(127);
        }
        int st;
        if (waitpid(p, &st, 0) < 0 || !WIFEXITED(st)) return -1;
        if (WEXITSTATUS(st) == 0) return 1;
        if (WEXITSTATUS(st) != 1) return -1;
    }
    return 0;
}

static int std_group(const char *g) {
    return in_list(g, std_groups) || conf_own_user(g);
}

int conf_wants_devices(const struct ident *id) {
    if (id->no_devices) return 0;
    if (id->groups_extra.n) return 1;       // unknown groups: assume devices
    for (size_t i = 0; i < id->groups.n; i++)
        if (in_list(id->groups.v[i], device_groups)) return 1;
    return 0;
}

int conf_has_cap(const struct ident *id, const char *cap) {
    return in_strs(cap, &id->caps) || in_strs(cap, &id->caps_extra);
}

void conf_show_deny(struct conf *c) {
    printf("%-6s %-22s %s\n", "KIND", "ENTRY", "WHY");
    for (const struct entry *e = deny_paths; e->name; e++) printf("%-6s %-22s %s\n", "path", e->name, e->why);
    for (size_t i = 0; i < c->global.deny_paths.n; i++) printf("%-6s %-22s %s\n", "path", c->global.deny_paths.v[i], added);
    for (const struct entry *e = deny_groups; e->name; e++) printf("%-6s %-22s %s\n", "group", e->name, e->why);
    for (size_t i = 0; i < c->global.deny_groups.n; i++) printf("%-6s %-22s %s\n", "group", c->global.deny_groups.v[i], added);
    for (const struct entry *e = deny_caps; e->name; e++) printf("%-6s %-22s %s\n", "cap", e->name, e->why);
    for (size_t i = 0; i < c->global.deny_caps.n; i++) printf("%-6s %-22s %s\n", "cap", c->global.deny_caps.v[i], added);
}

int conf_check(struct conf *c, int flags) {
    int errors = 0, deep = flags & CONF_DEEP, dev = flags & CONF_DEV;
#define ERR(...)  do { printf("error: " __VA_ARGS__); putchar('\n'); errors++; } while (0)
#define WARN(...) do { printf("warning: " __VA_ARGS__); putchar('\n'); } while (0)
    if (c->n == 0) WARN("no [identity] defined");
    for (size_t j = 0; j < c->global.deny_paths.n; j++)
        if (c->global.deny_paths.v[j][0] != '/')
            ERR("[global]: deny-paths %s is not absolute", c->global.deny_paths.v[j]);
    for (size_t i = 0; i < c->n; i++) {
        struct ident *id = &c->ids[i];
        const char *nm = id->name;
        if (!*nm || strlen(nm) > 24 || strspn(nm, "abcdefghijklmnopqrstuvwxyz0123456789_-") != strlen(nm))
            ERR("[identity %s]: name must be 1-24 of a-z 0-9 _ -", nm);

        // rule 1: dsb's own system users or a dynamic uid, never a person,
        // a service, nobody or root (Debian Policy 9.2.2)
        if (!strcmp(nm, "root") || !strcmp(id->user, "root"))
            ERR("[identity %s]: the target is never root", nm);
        else if (!id->dynamic && !conf_own_user(id->user))
            ERR("[identity %s]: user %s: only dsb, dsb-NAME or dynamic; an identity never "
                "runs as a person or another service", nm, id->user);
        else if (!id->dynamic) {
            struct passwd *pw = getpwnam(id->user);
            if (pw && (pw->pw_uid < 100 || pw->pw_uid > 999))
                ERR("[identity %s]: user %s exists with uid %u, outside the system range 100-999",
                    nm, id->user, (unsigned)pw->pw_uid);
        }
        if (id->dynamic && id->shell)
            ERR("[identity %s]: user = dynamic cannot have shell = yes (files would outlive their uid)", nm);

        if (id->callers.n == 0)
            WARN("[identity %s]: no callers; it will not be enabled", nm);
        for (size_t j = 0; j < id->callers.n; j++) {
            struct passwd *pw = getpwnam(id->callers.v[j]);
            if (!pw) ERR("[identity %s]: caller %s: no such user", nm, id->callers.v[j]);
            else if (pw->pw_uid == 0) ERR("[identity %s]: root is never a caller", nm);
        }

        if (id->commands.n == 0)
            ERR("[identity %s]: commands is empty (use * for anything)", nm);
        for (size_t j = 0; j < id->commands.n; j++) {
            const char *cmd = id->commands.v[j];
            if (!strcmp(cmd, "*")) {
                if (id->commands.n > 1) ERR("[identity %s]: * must be the only command", nm);
                continue;
            }
            if (cmd[0] != '/') { ERR("[identity %s]: command %s is not absolute", nm, cmd); continue; }
            if (access(cmd, X_OK)) WARN("[identity %s]: command %s is not executable here", nm, cmd);
            const char *base = strrchr(cmd, '/') + 1;
            if (in_list(base, runners))
                WARN("[identity %s]: %s runs other programs or code: allowing it allows "
                     "everything else in commands through it", nm, cmd);
        }

        // rule 4: write
        for (int extra = 0; extra < 2; extra++) {
            const struct strs *ws = extra ? &id->write_extra : &id->write;
            const char *key = extra ? "write-extra" : "write";
            for (size_t j = 0; j < ws->n; j++) {
                const char *w = ws->v[j];
                if (w[0] != '/') { ERR("[identity %s]: %s %s is not absolute", nm, key, w); continue; }
                char real[PATH_MAX];
                const char *r = realpath(w, real) ? real : w;
                const struct entry *d = denied_path(c, w, dev);
                if (!d) d = denied_path(c, r, dev);
                if (d) {
                    ERR("[identity %s]: %s %s overlaps %s, which root reads or runs: %s",
                        nm, key, w, d->name, d->why);
                    continue;
                }
                if (access(w, F_OK)) WARN("[identity %s]: %s %s does not exist; skipped", nm, key, w);
                if (extra) {
                    WARN("[identity %s]: write-extra %s is outside the standard data dirs; "
                         "make sure no root process reads or runs anything there", nm, w);
                    continue;
                }
                if (!std_path(w) || !std_path(r)) {
                    ERR("[identity %s]: write %s is outside the standard data dirs "
                        "(below /srv, /var/lib, /var/cache; /var/www); use write-extra "
                        "once you have checked it", nm, w);
                    continue;
                }
                if (deep) {
                    int owned = package_owned(r);
                    if (owned > 0)
                        ERR("[identity %s]: write %s: a package owns it or something below it; "
                            "use write-extra once you have checked it", nm, w);
                    else if (owned < 0)
                        WARN("[identity %s]: write %s: dpkg cannot say whether a package owns it", nm, w);
                }
            }
        }

        // rule 2: groups
        for (int extra = 0; extra < 2; extra++) {
            const struct strs *gs = extra ? &id->groups_extra : &id->groups;
            const char *key = extra ? "groups-extra" : "groups";
            for (size_t j = 0; j < gs->n; j++) {
                const char *g = gs->v[j], *why = denied(g, deny_groups, &c->global.deny_groups);
                if (why) ERR("[identity %s]: group %s is root-equivalent: %s", nm, g, why);
                else if (!getgrnam(g)) ERR("[identity %s]: %s %s: no such group", nm, key, g);
                else if (!extra && !std_group(g))
                    ERR("[identity %s]: group %s is outside the standard allowlist; use "
                        "groups-extra once you have checked it", nm, g);
                else if (extra)
                    WARN("[identity %s]: groups-extra %s is outside the standard allowlist", nm, g);
            }
        }

        // rule 3: capabilities
        for (int extra = 0; extra < 2; extra++) {
            const struct strs *cs = extra ? &id->caps_extra : &id->caps;
            const char *key = extra ? "caps-extra" : "caps";
            for (size_t j = 0; j < cs->n; j++) {
                const char *cap = cs->v[j], *why = denied(cap, deny_caps, &c->global.deny_caps);
                if (why) ERR("[identity %s]: capability %s leads to root: %s", nm, cap, why);
                else if (!in_list(cap, std_caps) && !in_list(cap, other_caps))
                    ERR("[identity %s]: %s %s: no such capability", nm, key, cap);
                else if (!extra && !in_list(cap, std_caps))
                    ERR("[identity %s]: capability %s is outside the standard allowlist; use "
                        "caps-extra once you have checked it", nm, cap);
                else if (extra)
                    WARN("[identity %s]: caps-extra %s is outside the standard allowlist", nm, cap);
            }
        }
    }
    FILE *t = fopen("/proc/sys/dev/tty/legacy_tiocsti", "r");
    if (t) {
        int v = fgetc(t);
        if (v == '1') ERR("dev.tty.legacy_tiocsti = 1: a command could type into the caller's terminal");
        fclose(t);
    }
    return errors;
}
