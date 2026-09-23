// dsb configuration parser and checker; format in dsb-conf.h.
#define _GNU_SOURCE
#include "dsb-conf.h"

#include <ctype.h>
#include <errno.h>
#include <glob.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
            in_global = 0;
            continue;
        }
        if (!cur) { seterr(c, path, line, "key outside a section", s); break; }
        char *eq = strchr(s, '=');
        if (!eq) { seterr(c, path, line, "expected key = value", s); break; }
        *eq = 0;
        char *k = trim(s), *v = trim(eq + 1);
        int global_ok = !strcmp(k, "callers") || !strcmp(k, "env") || !strcmp(k, "timeout");
        if (in_global && !global_ok) { seterr(c, path, line, "not a [global] key", k); break; }
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
        else if (!strcmp(k, "write")) strs_split(&cur->write, v);
        else if (!strcmp(k, "groups")) strs_split(&cur->groups, v);
        else if (!strcmp(k, "caps")) strs_split(&cur->caps, v);
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

// Paths root later reads as instructions or executes: writing any of them,
// or a parent of one, would let an identity feed root.
static const char *forbidden_paths[] = {
    "/etc/sudoers", "/etc/sudoers.d", "/etc/systemd", "/usr/lib/systemd",
    "/lib/systemd", "/etc/tmpfiles.d", "/etc/sysusers.d", "/etc/udev",
    "/etc/pam.d", "/etc/security", "/etc/polkit-1", "/etc/ld.so.preload",
    "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/crontab", "/etc/cron.d",
    "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
    "/var/spool/cron", "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/subuid", "/etc/subgid", "/etc/profile", "/etc/profile.d",
    "/etc/environment", "/etc/bash.bashrc", "/etc/init.d", "/etc/apt",
    "/etc/dpkg", "/var/lib/dpkg", "/etc/modprobe.d", "/etc/modules-load.d",
    "/etc/sysctl.d", "/etc/dsb", "/usr", "/bin", "/sbin", "/lib", "/lib64",
    "/boot", "/root", "/etc/ssh", "/etc/login.defs", "/etc/nsswitch.conf",
    NULL
};
static const char *forbidden_groups[] = {
    "root", "sudo", "wheel", "admin", "adm", "disk", "shadow", "docker", "lxd",
    "incus-admin", "libvirt", "staff", "src", NULL
};
static const char *allowed_caps[] = {
    "CAP_NET_BIND_SERVICE", "CAP_NET_RAW", "CAP_NET_ADMIN", "CAP_SYS_NICE",
    "CAP_SYS_TIME", "CAP_IPC_LOCK", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", NULL
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

// 1 if A equals B or one contains the other, comparing path components.
static int overlaps(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b), n = la < lb ? la : lb;
    if (strncmp(a, b, n)) return 0;
    if (la == lb) return 1;
    const char *longer = la > lb ? a : b;
    return n == 1 || longer[n] == '/';     // n == 1: one of them is "/"
}

int conf_check(struct conf *c) {
    int errors = 0;
#define ERR(...)  do { printf("error: " __VA_ARGS__); putchar('\n'); errors++; } while (0)
#define WARN(...) do { printf("warning: " __VA_ARGS__); putchar('\n'); } while (0)
    if (c->n == 0) WARN("no [identity] defined");
    for (size_t i = 0; i < c->n; i++) {
        struct ident *id = &c->ids[i];
        const char *nm = id->name;
        if (!*nm || strlen(nm) > 24 || strspn(nm, "abcdefghijklmnopqrstuvwxyz0123456789_-") != strlen(nm))
            ERR("[identity %s]: name must be 1-24 of a-z 0-9 _ -", nm);
        if (!strcmp(nm, "root") || !strcmp(id->user, "root"))
            ERR("[identity %s]: the target is never root", nm);
        if (!id->dynamic && getpwnam(id->user) && getpwnam(id->user)->pw_uid < 100 &&
            !conf_own_user(id->user))
            ERR("[identity %s]: user %s is a system account not made for dsb", nm, id->user);
        if (!id->dynamic && !getpwnam(id->user) && !conf_own_user(id->user))
            ERR("[identity %s]: user %s does not exist (only dsb and dsb-* users are created)", nm, id->user);
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
        for (size_t j = 0; j < id->write.n; j++) {
            const char *w = id->write.v[j];
            if (w[0] != '/') { ERR("[identity %s]: write %s is not absolute", nm, w); continue; }
            if (access(w, F_OK)) WARN("[identity %s]: write %s does not exist; skipped", nm, w);
            for (const char **f = forbidden_paths; *f; f++)
                if (overlaps(w, *f)) {
                    ERR("[identity %s]: write %s overlaps %s, which root reads or executes", nm, w, *f);
                    break;
                }
        }
        for (size_t j = 0; j < id->groups.n; j++) {
            if (in_list(id->groups.v[j], forbidden_groups))
                ERR("[identity %s]: group %s is root-equivalent", nm, id->groups.v[j]);
            else if (!getgrnam(id->groups.v[j]))
                ERR("[identity %s]: group %s: no such group", nm, id->groups.v[j]);
        }
        for (size_t j = 0; j < id->caps.n; j++)
            if (!in_list(id->caps.v[j], allowed_caps))
                ERR("[identity %s]: capability %s is not on the allowlist", nm, id->caps.v[j]);
    }
    FILE *t = fopen("/proc/sys/dev/tty/legacy_tiocsti", "r");
    if (t) {
        int v = fgetc(t);
        if (v == '1') ERR("dev.tty.legacy_tiocsti = 1: a command could type into the caller's terminal");
        fclose(t);
    }
    return errors;
}
