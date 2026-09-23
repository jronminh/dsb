// dsb configuration: /etc/dsb/dsb.conf, then /etc/dsb/conf.d/*.conf.
//
//   [global]                    defaults for every identity
//   callers  = alice           users allowed to call (SO_PEERCRED)
//   env      = TERM LANG LC_*   caller variables passed through (* = prefix)
//   timeout  = 0                seconds, 0 = none
//
//   [identity NAME]             one identity, socket /run/dsb/NAME.sock
//   user     = dsb-NAME        system user (default: dsb for "dsb",
//                               dsb-NAME otherwise), or "dynamic"
//                               (DynamicUser: a new uid per call)
//   callers, env, timeout       override [global]
//   shell    = no               yes: interactive shell, -s, -i, -c allowed
//   edit     = yes              no: dsb -e refused
//   commands = *                absolute paths the identity may execute,
//                               or * for anything; enforced by dsbd on
//                               argv[0] and by the kernel (ExecPaths=)
//   write    =                  paths made writable (ReadWritePaths=)
//   groups   =                  supplementary groups
//   caps     =                  ambient capabilities (short allowlist)
//
// Values are space-separated; "#" starts a comment. Unknown keys are errors.
#ifndef DSB_CONF_H
#define DSB_CONF_H

#include <stddef.h>
#include <sys/types.h>

#define DSB_CONF_DEFAULT "/etc/dsb/dsb.conf"

struct strs { char **v; size_t n; };

struct ident {
    char *name;
    char *user;            // resolved default filled in by conf_load
    int dynamic;
    int shell, edit;
    long timeout;
    struct strs callers, env, commands, write, groups, caps;
    int has_callers, has_env, has_timeout, has_commands;
};

struct conf {
    struct ident global;
    struct ident *ids;
    size_t n;
    char *err;             // first load error, NULL if none
};

// Loads PATH and PATH's sibling conf.d/*.conf. Returns 0, or -1 with c->err.
int conf_load(struct conf *c, const char *path);
// 1 if USER is one dsb-admin creates: "dsb" or "dsb-*".
int conf_own_user(const char *user);
struct ident *conf_find(struct conf *c, const char *name);
// Validates everything; prints "error: ..." / "warning: ..." lines to stdout.
// Returns the number of errors.
int conf_check(struct conf *c);
int conf_caller_ok(const struct ident *id, uid_t uid);
int conf_env_ok(const struct ident *id, const char *kv);
// 1 if PATH (absolute) is an allowed command of ID.
int conf_command_ok(const struct ident *id, const char *path);

#endif
