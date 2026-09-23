# rootcall: fixed root commands, as a companion to dsb (proposal)

**Status: proposal, not implemented.** Discussion:
[issue #1](https://github.com/jronminh/dsb/issues/1). This document records
the needs survey behind it and the scope that came out of it.

It is the first companion in the model of
[a core and companions](design.md#growing-the-shell-a-core-and-companions).

dsb never runs anything as root. Some jobs do need root, but always the same
fixed command: restart one service, read one drive's health. rootcall would
be a separate package that does only that:

```
rootcall NAME        # runs /etc/rootcall/NAME as root, if you may execute it
rootcall -l          # the calls you may run
```

## Where it fits: the `adb shell` model

dsb's model is `adb shell`, but uid 2000 on its own is weak. `adb shell` is
useful because of privileged companions around it. Android has three
layers; dsb covers two:

| layer | Android | Linux + dsb |
|---|---|---|
| way in | `adbd`, USB or pairing | systemd socket, `SO_PEERCRED` |
| identity | uid `shell` + groups | `dsb-NAME` + allowlisted groups |
| confinement | SELinux domain `shell` | systemd sandbox, [`standards.md`](standards.md) |
| privileged services acting on its behalf | `system_server`, `installd`, init's `ctl.start` | polkit (by session only); **rootcall** |

| Android | Linux |
|---|---|
| `run-as PKG`: shell becomes an app's uid | `dsb -u NAME` |
| `pm`, `cmd`, `settings`: binder calls checked against the caller's permissions | D-Bus + polkit, which decides by active session, so a `dsb-NAME` caller is refused |
| `bugreport`: `setprop ctl.start dumpstate`, init runs a fixed root service | `rootcall NAME`, with the file's permissions as the policy |
| `logcat`: group `log` | group `systemd-journal` |
| `adb root`, `su`: userdebug builds only | `sudo`; out of scope |

## Needs survey (2026-09)

### What people grant today

A sample of 100 public `sudoers.d` files with `NOPASSWD` (GitHub code
search, `NOPASSWD path:sudoers.d`, 192 hits) plus monitoring agents'
documentation. The grants fall into five kinds:

| kind | examples | callers | fits rootcall? |
|---|---|---|---|
| A. read-only queries | `smartctl`, `nvme smart-log`, `iptables -L`, `ipset list`, `nft list`, `ss -p`, `check_hdd_temp.sh` | service accounts (telegraf, netdata, nagios), no session | **yes**: needs the output back |
| B. admin-written scripts | `NOPASSWD: /usr/local/bin/backup.bash`, `restart.bash`, `lock.bash`, … | users, cron | **yes**: this is rootcall, done through sudo |
| C. service and power control | `systemctl start/stop/restart X`, `reboot`, `shutdown` (the most common after `ALL`) | users | **yes**, replacing custom polkit rules |
| D. network, with arguments | `wpa_cli`, `ifup IF`, `iptables -A`, `wg-quick up X` | users, scripts | only as one file per variant |
| E. general tools | `ALL` (the most common: 11 of 100), `rm`, `cp`, `find`, `apt-get`, `passwd` | convenience | **no**: that is root |

Kind E shows how `NOPASSWD` grants drift towards full root. Kind A is large
enough that Netdata wrote its own helper (`ndsudo`), and telegraf's SMART
plugin documents a sudoers line for `smartctl`.

### Existing tools

| tool | model | Debian popcon installs | lesson |
|---|---|---|---|
| `sudo` NOPASSWD | setuid, config language, argument wildcards | 251 935 | powerful, drifts to `ALL` |
| polkit + a unit | daemon, JavaScript rules, decided by session | 155 763 | no output back to the caller; sessionless callers need a rule each |
| `super` | setuid; `super.tab` maps a command name to a program | 124 | the same named-command idea, but a 684 KB setuid binary, arguments and a config language |
| `userv` | setuid client + root daemon; services in `/etc/userv` | 42 | general any-user-to-any-user calls; little used |
| Netdata `ndsudo` | setuid, command list compiled in | (with netdata) | **CVE-2024-32019**: ran `nvme` by `PATH`, so any user got root. Exec absolute paths, clean environment |
| Android `ctl.start` | init starts a named service; SELinux decides who may | — | no arguments, no data passed in |

The named-command idea exists, but always tied to setuid and a config
language, or to one application. None combines: a socket (so it works
under `NoNewPrivileges`), file permissions as the policy, no arguments, and
the output back to the caller.

### On the reference machine

`master` has no root; `docs/polkit.md` in sudo-less lists what a custom
polkit rule (`49-master-android-shell.rules`) grants it instead:

| grant today | rootcall? |
|---|---|
| start/stop/restart six units | **yes**: one file per verb and unit |
| suspend, reboot, poweroff | **yes** |
| SMART: `CAP_SYS_RAWIO` on the world-executable `smartctl` plus a `uaccess` ACL (active local session only; an earlier `master-smart-check` wrapper was removed) | **yes, and better**: works over SSH, and the capability can go |
| `nmcli` connect to network X, `udisksctl mount` device Y, `hostnamectl set-hostname NAME` | **no**: they need arguments |
| NetworkManager, udisks, GNOME settings asking polkit over D-Bus | **no**: that is the desktop's polkit; removing it breaks the session |

A dsb identity (`dsb -u sl-fresh`) gets none of the polkit grants, because it
has no session.

## Scope

rootcall **replaces custom polkit rules and `NOPASSWD` lines for fixed
actions** (kinds A to C). It does not replace polkit itself: the desktop's
default policy and actions that take arguments stay with polkit.

First calls, to prove it: `waydroid-restart`, `smart-health`, `suspend`.
Together they would remove the service and power part of the custom polkit
rule and the `CAP_SYS_RAWIO` on `smartctl`.

## Design

```
rootcall NAME ──unix socket──▶ systemd (Accept=yes; root, sandboxed)
                                 rootcalld: read NAME (one line)
                                   ├ NAME matches [a-z0-9._-]+
                                   ├ /etc/rootcall and NAME: root-owned regular
                                   │   files, writable by no one else
                                   ├ fork, switch to the caller's uid and groups
                                   │   (SO_PEERCRED, SO_PEERGROUPS), access(X_OK)
                                   └ execve /etc/rootcall/NAME: clean env,
                                     stdin /dev/null, none of the caller's fds
                                 stdout/stderr go back over the socket,
                                 then one byte of exit status
```

- **No arguments, no options, no config file.** A variant is another file
  (`governor-performance`, `governor-powersave`). A query that would take a
  device name covers every device instead (`smart-health` checks them all).
- **The file's permissions are the policy.** `chgrp ops NAME; chmod 0750
  NAME`, or an ACL. The kernel decides; rootcall has no permission logic.
  `ls -l /etc/rootcall` shows who may run what.
- **A socket, not setuid.** dsb identities run with `NoNewPrivileges`, so a
  setuid helper would never work from dsb. setuid also inherits the
  caller's environment, fds and rlimits: the sudo/pkexec bug class.
- **Regular files only**: no symlinks, so the ownership check is on the
  file that runs. To call a binary, write a two-line script with `exec` and
  an absolute path (the `ndsudo` lesson).
- **Output back to the caller**, since most real needs are queries.
- `rootcall -l` lists the calls the caller may run, with the same
  `access()` check.
- Target size: a few hundred lines of C and two unit files.

### Use with dsb

No change in dsb: an identity that may run `/usr/bin/rootcall` and is in the
file's group can make that one call.

```ini
[identity monitor]
groups   = rootcall-smart
commands = /usr/bin/rootcall
```

### Limits

rootcall guarantees "this exact command, nothing else". It cannot tell
whether the command is safe: a call that reads a file a user can write
(config in `/home`, `/tmp`), runs `sh -c "$VAR"`, installs packages or loads
modules is still root for whoever may run it. The clean source principle of
[`standards.md`](standards.md) applies to every call file.

## Open questions

- **Journal volume.** Monitoring agents poll every 10 to 60 seconds; one
  log line per call floods the journal. Rate-limit, or log only failures
  and first calls?
- **Limits per call.** A default timeout, `MaxConnections`, and whether a
  call may run concurrently with itself.
- **Checking call files.** A `rootcall check` could warn when a script
  names a path outside root-owned directories. Not in the prototype.
