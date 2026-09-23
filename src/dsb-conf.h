// dsb configuration: /etc/dsb/dsb.conf, then /etc/dsb/conf.d/*.conf.
//
//   [global]                    defaults for every identity
//   callers  = alice           users allowed to call (SO_PEERCRED)
//   env      = TERM LANG LC_*   caller variables passed through (* = prefix)
//   timeout  = 0                seconds, 0 = none
//   deny-groups, deny-paths, deny-caps
//                               added to the built-in deny list (never removed)
//
//   [identity NAME]             one identity, socket /run/dsb/NAME.sock
//   user     = dsb-NAME        dsb-NAME (the default), dsb (the default for
//                               "dsb"), or "dynamic" (a new uid per call)
//   callers, env, timeout       override [global]
//   shell    = no               yes: interactive shell, -s, -i, -c allowed
//   edit     = yes              no: dsb -e refused
//   commands = *                absolute paths the identity may execute,
//                               or * for anything; enforced by dsbd on
//                               argv[0] and by the kernel (ExecPaths=)
//   write    =                  paths made writable (ReadWritePaths=)
//   groups   =                  supplementary groups
//   caps     =                  ambient capabilities
//   write-extra, groups-extra, caps-extra
//                               outside the standard allowlists: allowed
//                               unless on the deny list, with a warning
//   network  = yes              no: PrivateNetwork=
//   devices  = auto             auto: /dev only with a device group; none
//   jit      = yes              no: MemoryDenyWriteExecute=
//   namespaces = no             yes: may create namespaces (bwrap, unshare)
//
// Values are space-separated; "#" starts a comment. Unknown keys are errors.
// What each allowlist and the deny list hold, and why: docs/standards.md.
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
    int network, jit, namespaces, no_devices;
    long timeout;
    struct strs callers, env, commands, write, groups, caps;
    struct strs write_extra, groups_extra, caps_extra;
    struct strs deny_paths, deny_groups, deny_caps;     // [global] only
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
// Returns the number of errors. CONF_DEEP also asks dpkg which write paths a
// package owns (not at boot); CONF_DEV allows your own runtime dir, since in
// --dev mode the identity is you.
#define CONF_DEEP 1
#define CONF_DEV  2
int conf_check(struct conf *c, int flags);
// Prints the deny list in effect: built in (with its source) or added.
void conf_show_deny(struct conf *c);
// 1 if ID may need devices: devices = auto and a device group.
int conf_wants_devices(const struct ident *id);
// 1 if ID has the capability CAP (in caps or caps-extra).
int conf_has_cap(const struct ident *id, const char *cap);
int conf_caller_ok(const struct ident *id, uid_t uid);
int conf_env_ok(const struct ident *id, const char *kv);
// 1 if PATH (absolute) is an allowed command of ID.
int conf_command_ok(const struct ident *id, const char *path);

#endif
