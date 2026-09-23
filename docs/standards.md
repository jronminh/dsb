# Standards for the fixed limits

dsb enforces a floor that no config can lower. The floor lives in
`src/dsbd.c` (the directives every unit gets) and `src/dsb-conf.c` (what
`dsb-admin check` refuses). A hand-written denylist fails open: whatever it
forgets is allowed. So each part of the floor follows one principle and an
external standard, and wherever possible it is an **allowlist**, so that
something forgotten is refused instead of allowed. Every rule can be traced
to a source anyone can check, and "why X but not Y" has an answer.

## The principle: clean source

> A less trusted principal must never control anything that a more
> trusted principal reads as instructions, executes, or authenticates
> with.

This is the "clean source" principle from Microsoft's tiered access model:
whatever controls a Tier 0 asset is itself Tier 0. For dsb, the most
trusted principal is root and the least trusted is the caller. An identity
sits between them. So an identity must not control:

- files root executes or reads as config (rule 4);
- a principal that can become root (rules 1 and 2);
- a kernel interface that bypasses permissions (rule 3);
- a way out of its own sandbox (rule 5).

## 1. Target user: Debian UID ranges

**Source:** Debian Policy §9.2.2 (UID and GID classes); systemd,
*Users, Groups, UIDs and GIDs on systemd Systems*.

| range | Debian / systemd meaning | dsb |
|---|---|---|
| 0 | root | refused |
| 1–99 | static system accounts (base-passwd) | refused |
| 100–999 | dynamic system accounts | only `dsb` / `dsb-NAME`, which dsb creates with sysusers |
| 1000–59999 | human users | refused |
| 61184–65519 | systemd `DynamicUser` | allowed via `user = dynamic` |
| 65534 | `nobody` | refused (shared by unrelated services) |

`user =` accepts `dsb`, `dsb-NAME` or `dynamic`, nothing else. If a `dsb*`
account already exists outside 100–999, `check` refuses it.

**Why:** a human account has a login session, a user manager, dotfiles,
and often `sudo`. An identity that ran as that account would control all of
them (see [the user's own systemd](#closed-gap-the-users-own-systemd)). A
service account such as `www-data` gives the identity everything that
service can do; share data through a group instead.

## 2. Groups: base-passwd's documentation

**Source:** `/usr/share/doc/base-passwd/users-and-groups.txt`, Debian's
reference for what each static group grants; a package's own documentation
for its group.

**Allowlist** (`groups =`): `dsb` and `dsb-*`; the device groups
`audio`, `video`, `render`, `plugdev`, `dialout`, `cdrom`, `floppy`,
`tape`; and `systemd-journal`.

`input` is not on it: it reads every keyboard, including the admin's
password as it is typed. Use `groups-extra` if you mean it.

**Deny list:**

| group | why |
|---|---|
| `root` | the superuser's group |
| `sudo`, `wheel`, `admin` | "may run any command as any user" (base-passwd; other distributions) |
| `disk` | "mostly equivalent to root access" (base-passwd) |
| `staff` | "effectively equivalent to root access" (base-passwd) |
| `kmem` | reads system memory |
| `shadow` | reads `/etc/shadow` |
| `tty` | writes to other users' terminals |
| `utmp` | writes login records |
| `src` | manages `/usr/src` |
| `adm` | reads every log, and logs hold secrets (stricter than base-passwd) |
| `docker`, `lxd`, `incus-admin`, `libvirt` | their daemons start anything as root |

## 3. Capabilities: capabilities(7) and root-equivalence research

**Sources:** capabilities(7); Brad Spengler, *False Boundaries and
Arbitrary Code Execution* (grsecurity, 2011), which lists the 19
capabilities that lead to full root.

**Allowlist** (`caps =`), none of them on Spengler's list:

| capability | grants |
|---|---|
| `CAP_NET_BIND_SERVICE` | ports < 1024 |
| `CAP_NET_RAW` | raw and packet sockets (ping) |
| `CAP_SYS_NICE` | priorities, CPU affinity, realtime |
| `CAP_SYS_TIME` | sets the clock: breaks TLS, logs and Kerberos, but not root |
| `CAP_IPC_LOCK` | `mlock` |
| `CAP_WAKE_ALARM` | wake-up timers |
| `CAP_BLOCK_SUSPEND` | blocks suspend |

**Deny list:** Spengler's 19 (`CAP_SYS_ADMIN`, `CAP_SYS_TTY_CONFIG`,
`CAP_MKNOD`, `CAP_SYS_PTRACE`, `CAP_SYS_RAWIO`, `CAP_SYS_MODULE`,
`CAP_SETFCAP`, `CAP_FSETID`, `CAP_SETGID`, `CAP_SETUID`,
`CAP_DAC_OVERRIDE`, `CAP_SETPCAP`, `CAP_IPC_OWNER`, `CAP_CHOWN`,
`CAP_SYS_CHROOT`, `CAP_DAC_READ_SEARCH`, `CAP_SYS_BOOT`,
`CAP_AUDIT_CONTROL`, `CAP_FOWNER`), and four newer than the paper:
`CAP_BPF`, `CAP_PERFMON`, `CAP_MAC_ADMIN`, `CAP_MAC_OVERRIDE`.

Everything else (`CAP_NET_ADMIN`, `CAP_KILL`, `CAP_SYS_RESOURCE`,
`CAP_SYSLOG`, …) needs `caps-extra`. `CAP_NET_ADMIN` is not on Spengler's
list, but it reconfigures the whole network, so it is a deliberate choice,
not a default.

## 4. Write paths: FHS and the package database

**Sources:** Filesystem Hierarchy Standard 3.0; the dpkg database.

**Allowlist** (`write =`): strictly below `/srv`, `/var/lib` or
`/var/cache`, or at or below `/var/www` (a Debian convention), and owned by
no package: `check` runs `dpkg-query -S PATH` and `dpkg-query -S 'PATH/*'`,
with an empty environment, and refuses the path if either finds an owner.
Files from packages are what root installed, and often what root runs. A
path the table forgets is refused.

`/var/log` is not on it: root rotates logs and reads them as the admin. Use
`write-extra` for a log directory you have checked.

**Deny list:** a path is refused if it overlaps an entry, that is, equals
it, lies below it, or contains it (so `write = /var/lib` is refused for
containing `/var/lib/dpkg`). The check runs on the path as written and on
its `realpath`.

| path | why |
|---|---|
| `/etc` | host config, read by root |
| `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/opt`, `/boot` | programs, libraries, kernel |
| `/root`, `/home` | dotfiles are executed |
| `/run/user` | users' runtime dirs, with their own systemd and D-Bus |
| `/var/spool` | work queued for root daemons (cron, mail) |
| `/var/lib/dpkg`, `/var/lib/apt`, `/var/cache/apt`, `/var/cache/debconf` | what the package manager trusts |
| `/var/lib/polkit-1`, `/var/lib/sudo`, `/var/lib/systemd`, `/var/lib/private` | authorizations, timestamps, other services' state |
| `/var/lib/dsb` | the homes of dsb identities |
| `/proc`, `/sys`, `/dev` | kernel interfaces |

In `--dev` mode the identity is you, so `write-extra` may name a directory
below your own `/run/user/UID`.

**Known limit:** the package lookup runs at `check` time. A package
installed later could claim the path; run `dsb-admin check` after large
upgrades.

## 5. Unit hardening: `systemd-analyze security`

**Source:** `systemd-analyze security`, systemd's own exposure score for a
unit, maintained with systemd itself (`--offline`, `--threshold`;
systemd ≥ 250).

Before these rules, a generated unit scored **5.2 MEDIUM**. Now every unit
gets, with no key to turn them off:

`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`,
`PrivateTmp`, `InaccessiblePaths=-/run/user`, `ProtectKernelTunables`,
`ProtectKernelLogs`, `ProtectControlGroups`,
`ProtectHostname`, `ProtectProc=invisible`, `RestrictSUIDSGID`,
`LockPersonality`, `RemoveIPC`, `SystemCallArchitectures=native`, and
`SystemCallFilter=~@cpu-emulation @module @obsolete @raw-io @reboot @swap`.

Some follow from a grant:

| directive | dropped when |
|---|---|
| `ProtectClock`, `~@clock` | `CAP_SYS_TIME` is granted |
| `RestrictRealtime` | `CAP_SYS_NICE` is granted |
| `RestrictNamespaces`, `~@mount`, `ProtectKernelModules` | `namespaces = yes` (its hidden `/usr/lib/modules` is a mount under `/usr`, which stops an overlay on `/usr`; modules stay blocked by the empty bounding set and `~@module`) |
| `MemoryDenyWriteExecute` | set only with `jit = no` |
| `PrivateDevices` | a device group, or any `groups-extra`, is granted and `devices` is not `none` |
| `PrivateNetwork`, `RestrictAddressFamilies=AF_UNIX` | set with `network = no`; otherwise `AF_UNIX AF_INET AF_INET6 AF_NETLINK`, plus `AF_PACKET` with `CAP_NET_RAW` |

**Left out on purpose:** `PrivateUsers` hides other users' files, which a
shared identity may need to read. `UMask=0027` would make files in a
`write =` directory unreadable to the service that serves them.
`~@debug` would break debuggers and `strace` in a shell identity; ptrace is
still bounded by the uid and `NoNewPrivileges`. `IPAddressDeny` and
`DeviceAllow` need per-site lists.

**The score as a check:** `dsb-admin check` generates the units into a
temporary directory and runs `systemd-analyze security --offline=yes
--threshold=45` on each. Measured on systemd 261:

| identity | exposure |
|---|---|
| `commands = ...`, `network = no`, `jit = no` | 1.1 |
| defaults | 1.8 |
| every allowlisted key at once | 4.3 |

Above 4.5, an identity with only standard keys is an **error**: dsb or
systemd changed, and a new directive in a later systemd shows up here
without anyone having to notice it. An identity with `*-extra` grants gets
a **warning**, like its other extras. In `--dev` mode the units are user
units, which systemd scores differently, so they are not scored.

## Configuration syntax

Every field that grants something works in the same three levels:

| level | syntax | `check` |
|---|---|---|
| inside the standard (the allowlist) | `KEY = ...` | silent |
| outside the allowlist, not root-equivalent | `KEY-extra = ...` | a warning on every run |
| root-equivalent (the deny list) | none | refused |

The allowlists are built into dsb. The admin never writes them out, so a
config that stays inside the standards is as short as before.

| field | `KEY =` accepts | `KEY-extra =` | default |
|---|---|---|---|
| `user` | `dsb-NAME`, `dsb`, `dynamic` | none | `dsb-NAME` (`dsb` for the default identity) |
| `groups` | the allowlist in rule 2 | any existing group not on the deny list | none |
| `caps` | the allowlist in rule 3 | any capability not on the deny list | none |
| `write` | the allowlist in rule 4 | any path not on the deny list | none |
| `network` | `yes`, `no` | none | `yes` (an identity is no more than a user, who has the network anyway) |
| `devices` | `auto`, `none` | none | `auto`: devices only with a device group |
| `jit` | `yes`, `no` | none | `yes`; `no` sets `MemoryDenyWriteExecute` |
| `namespaces` | `yes`, `no` | none | `no`; `yes` allows user namespaces and mounts (bwrap, podman, unshare) |

`callers`, `commands`, `shell`, `edit`, `timeout` and `env` are unchanged.
The rest of rule 5 has no key at all.

A full identity:

```ini
[identity cam]
callers      = master
user         = dsb-cam
groups       = video
groups-extra = bluetooth        # warning
caps         = CAP_NET_RAW
write        = /srv/cam
write-extra  = /data/cam        # warning
network      = yes
devices      = auto
jit          = no
namespaces   = no
commands     = /usr/bin/ffmpeg
shell        = no
edit         = no
timeout      = 600
```

## The deny list: built in, extended, never reduced

The deny list holds what is root-equivalent by definition: the groups,
capabilities and paths that rules 2 to 4 always refuse. No `-extra` key
reaches it.

- **Compiled into dsb, not read from a file.** A missing or broken file
  would mean an empty list, which fails open. A compiled list cannot fail
  that way. dsb is small, so a new entry means a new release.
- **The admin may add, never remove.** Every site has root-equivalents dsb
  cannot know: a group that local sudo rules trust, a directory a root cron
  job reads. There is no syntax to remove a built-in entry. Granting root
  through dsb is never the right tool: that is what `sudo`, or a fixed
  command through [rootcall](rootcall.md), is
  for.

```ini
[global]
deny-groups = ops deploy
deny-paths  = /srv/deploy
deny-caps   = CAP_SYS_TIME
```

`deny-*` keys are accepted only in `[global]`, and they add up across
`conf.d` files. `dsb-admin check --show-deny` prints the list in effect, with
each entry's source, or "added in [global]".

## Closed gap: the user's own systemd

Before these rules, `user =` could be an existing human account. If that
account had a running user manager (logged in, or lingering), the identity
could talk to `/run/user/UID/bus` and start a transient unit there
(`systemd-run --user`), **outside dsb's sandbox**, able to write the
account's dotfiles and wait for its next `sudo`.

It is closed twice: rule 1 refuses human accounts as targets, and every
unit has `InaccessiblePaths=-/run/user`.

## What these rules still do not cover

- Reading: `ProtectSystem` limits writes, not reads. An identity reads
  whatever its uid, groups and ambient capabilities allow.
- Arguments: `commands =` matches programs, not their arguments.
- What the admin grants on purpose: a `write =` on a site's data lets the
  identity change the site; an `-extra` grant is only as safe as the
  admin's check of it.
- Kernel and systemd sandbox escapes.
