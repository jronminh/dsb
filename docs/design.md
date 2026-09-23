# dsb design

`dsb` (debian superuser bridge) is `sudo` for a bounded middle identity
instead of the super user: same usage, never root.

## The idea, taken from Android

`adb shell` runs commands as Android's `shell` uid. `shell` is not root: it
has no effective capabilities, and what it can reach (a few groups, some
settings, `/proc`) is fixed by the system, not by `adb`. So `adb shell` can
run *any* command and still be safe, because the identity it runs as is
bounded.

Only that part is copied:

> **A command that runs anything, as an identity whose power is fixed by the
> admin in advance and enforced by the kernel.**

Nothing else from Android (SELinux, adbd, pairing) is copied. Unlike Android's
`shell`, the policy is not baked in: one file, `/etc/dsb/dsb.conf`, says who
may call which identity and what it may do, and `dsbd` enforces it on every
call.

| Android | role | dsb |
|---|---|---|
| `adb shell` | the command the user types | `dsb` client |
| USB/wireless debugging + pairing | who may reach the daemon | a unix socket only the callers can open, caller uid re-checked with `SO_PEERCRED` |
| `adbd` | accepts a call, runs it, returns the status | `dsb-NAME.socket` (`Accept=yes`) + `dsbd`, one instance per call, already running as the identity |
| the fixed `shell` policy | what may run | `commands`, `shell`, `edit`, `env`, `timeout`, **configurable** |
| uid 2000 `shell` | the bounded identity | a `dsb-NAME` system user, or a `DynamicUser` per call |
| `shell`'s groups | what the identity reaches | `groups =` (`SupplementaryGroups=`) |
| SELinux `shell` domain | a limit the identity cannot lift | the systemd sandbox (below) |

## Usage: `sudo` with a different target

`dsb` takes `sudo`'s options wherever they make sense, so muscle memory and
scripts carry over (`sudo mkdir -p /srv/x` → `dsb mkdir -p /srv/x`), plus
`-c`/`-f`/`-p`.

```sh
dsb                      # interactive shell, prompt "dsb> "          (adb shell)
dsb CMD [ARG...]         # run CMD as the default identity            (sudo CMD)
dsb -s [CMD]             # shell, or CMD through it                   (sudo -s)
dsb -i [CMD]             # login shell                                (sudo -i)
dsb -e FILE...           # edit FILEs                                 (sudoedit)
dsb -l [CMD]             # what the identity may do; with CMD: would it (sudo -l)
dsb -D DIR CMD           # run in DIR                                 (sudo -D)
dsb --preserve-env=VAR,... CMD    # offer extra variables             (sudo --preserve-env=)
dsb -u IDENT CMD         # another identity                           (sudo -u)
dsb -c 'CMD LINE'        # run a shell command line
dsb -f FILE              # run the command line read from FILE
dsb -p FILE CMD          # stream FILE to CMD's stdin
dsb -v | -k | -K | -n | -H   # accepted, do nothing: there is no password
```

Behaviour a `sudo` user expects, kept:

- stdin, stdout, stderr and the exit status pass through. The command gets
  the caller's own file descriptors, so a pipe stays a byte-exact pipe and a
  terminal stays the same terminal (window size, raw mode, full-screen
  programs); Ctrl-C and the other terminal signals are relayed;
- the current directory is kept when the identity can enter it, else its
  home, with a warning; `-D` fails instead;
- the environment is reset, as sudo's `env_reset` does: the client offers
  `TERM`, `COLORTERM`, `LANG`, `LANGUAGE`, `LC_*` and `--preserve-env`
  variables, `dsbd` keeps those matching the identity's `env =`; `HOME`,
  `PATH`, `USER`, `LOGNAME`, `SHELL` are always the identity's, and `LD_*`,
  `ENV`, `BASH_ENV`, `DSB_*` never pass;
- `-e` works like `sudoedit`: `dsbd` reads the file, `$EDITOR` runs as the
  **caller** on a private copy, and `dsbd` writes it back in place (same
  inode and mode), so the editor never runs with the identity's rights;
- arguments are passed as an argv, so `dsb touch 'a b'` makes one file.

One command for both uses, as `adb shell` is: with a command it is a
scripting interface, without one it is a terminal.

- **bare `dsb` opens a shell**; `-s`/`-i` stay for sudo habits;
- **the prompt names the identity**, `dsb> ` or `web> `, set after every
  profile so nothing can hide it;
- **shells are opt-in per identity** (`shell = yes`) and need a persistent
  identity (see "Identities");
- no job control inside the shell: the command has no controlling terminal
  (the terminal belongs to the caller's session), so Ctrl-Z is ignored.

Differences from sudo, on purpose:

- no password and no credential cache: the gate is the socket and
  `callers =`, so `-v`/`-k`/`-K` are no-ops kept for script compatibility;
- the target is never root: `-u root` is refused, and `-u` takes only the
  identities the admin configured;
- `dsb` is not installed as `sudo`: a script that calls `sudo` should fail
  loudly, not get the identity's rights by surprise.

## What bounds an identity

Four locks, all written by the admin in `dsb.conf`, all enforced by the
kernel. None depends on what command the caller sends.

| lock | mechanism | effect |
|---|---|---|
| **identity** | a system user with its own group, plus only the groups granted with `groups =` | ordinary DAC: the identity reaches what those groups reach, nothing more |
| **filesystem** | `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`, and `ReadWritePaths=` from `write =` | everything is read-only except the listed paths, **even if** DAC would allow a write |
| **no way up** | `NoNewPrivileges=yes`, `RestrictSUIDSGID=yes`, empty `CapabilityBoundingSet=` (or allowlisted ones via `AmbientCapabilities=`) | `sudo`, `su`, `pkexec` and every setuid binary lose their power inside; no capability can be regained |
| **commands** (when `commands =` is a list) | `dsbd` checks the resolved program; the unit gets `NoExecPaths=/` + `ExecPaths=` those programs, the libraries, `dsbd` and (with `shell = yes`) the shells | a shell, script or allowed program cannot `exec` anything off the list: the kernel answers `Permission denied` |

The filesystem lock is what keeps the rule **never feed root** honest: paths
that root later reads or executes (`/etc/sudoers*`, `/etc/systemd`,
`/etc/tmpfiles.d`, `/etc/udev`, `/etc/pam.d`, `/etc/polkit-1`,
`/etc/ld.so.*`, cron, `/etc/passwd` and friends, `/etc/apt`,
`/var/lib/dpkg`, `/etc/dsb` itself, `/usr`, `/boot`, …) must never be
writable. `dsb-admin` refuses a `write =` that equals, contains or lies under
any of them, a root-equivalent group (`sudo`, `disk`, `docker`, `shadow`, …)
and any capability off a short allowlist, and it warns when `commands =`
names a program that runs other programs (`sh`, `python3`, `find`, `env`,
…), since allowing it lets the rest of the system through it.

The accepted trade-off, as with `adb shell`: any process a caller runs can
call `dsb`. That is fine because the identity's power is small, written down
in one file, and reviewed.

## How it is wired

Native pieces only: systemd socket activation, unix sockets, `SO_PEERCRED`,
`SCM_RIGHTS`. No polkit, no ssh, no daemon running as root.

```
dsb CMD  (client, as the caller)
   │  connect(); one sendmsg: the request + its own fds 0, 1, 2 (SCM_RIGHTS)
   ▼
/run/dsb/NAME.sock      root:<caller's group> 0660 (one caller)
   │  dsb-NAME.socket, Accept=yes: one service instance per call
   ▼
dsb-NAME@.service       User=dsb-NAME (or DynamicUser) + the four locks
   ExecStart=/usr/libexec/dsb/dsbd --identity NAME
   │  reads /etc/dsb/dsb.conf
   │  SO_PEERCRED: the caller must be in callers =, checked before anything else
   │  policy: mode allowed? command on the list? env filtered, timeout armed
   │  fork: setsid, dup2 the caller's fds onto 0/1/2, chdir, clean env, exec
   ▼
CMD, as the identity, on the caller's own stdin/stdout/stderr
   │  exit status back over the socket; signals forwarded the other way
   ▼
dsbd exits → systemd kills whatever is left in the instance's cgroup
```

The protocol (`src/dsb-proto.h`) is one request and one reply; the kernel
does the rest:

- **who may call**: the socket's mode, then `SO_PEERCRED`, the kernel's record
  of the caller's uid. No keys, no crypto: nothing crosses a network.
- **the data path is not a path**: `SCM_RIGHTS` passes the caller's file
  descriptors themselves. Nothing is relayed or re-encoded, so there is
  nothing to get wrong about binary data, buffering, stderr or window size,
  and no pty to allocate.
- **what the command is**: an argv plus a mode (`cmd`, `shell`, `login`,
  `line`, `list`, `which`, `read`, `write`). The client builds no scripts;
  `dsbd` resolves the argv with the identity's `PATH`, checks it and
  `execve`s it, with no shell in between unless the mode asks for one and the
  identity allows it. Shells get their rc (prompt, profile) from `dsbd` on a
  memfd; `-e` reads and writes the file inside `dsbd` itself.
- **cleanup**: the per-call service's cgroup, so a killed client leaves no
  orphan.

Also required, set by the package (`/usr/lib/sysctl.d/60-dsb.conf`) and
checked by `dsb-admin`: `dev.tty.legacy_tiocsti = 0` (the default since
Linux 6.2). The command holds the caller's terminal; with legacy `TIOCSTI`
it could type into the caller's shell after it exits.

Rejected:

- `ssh` (`sshd -i` behind the socket, the first prototype): a large program
  whose behaviour we would depend on in detail (pty allocation, environment
  handling, login records, config defaults). A non-root `sshd` also cannot
  `chown` the pty or write login records, so interactive sessions broke.
- a setuid-to-identity helper: it inherits the caller's environment, fds and
  rlimits into a process with other rights.
- polkit / `run0`: a rules engine outside the base system; `run0` targets
  root.
- a long-running root daemon that switches to the identity itself: it would
  be a second `sudo` to audit. systemd already holds the socket and starts
  each call as the identity, so `dsbd` never has root to lose.

## Identities: persistent per grant, or one per call

**Per grant: a static user `dsb-NAME`** (`dsb` for the default identity).
Created by `dsb-admin apply` (`systemd-sysusers`), home
`/var/lib/dsb/NAME` (`StateDirectory=`), with its own socket, unit pair and
sandbox. Files it writes keep a stable owner, a later call can change them,
and a grant for one purpose is not a grant for another. An existing
user can be named with `user =`; root and the base system accounts
(uid < 100) cannot.

**Per call: `user = dynamic`** (`DynamicUser=yes`). systemd allocates a fresh
uid for each call and releases it afterwards; the name resolves through
`nss-systemd`. But a file it writes outside systemd-managed directories keeps
a dead owner:

| step | result |
|---|---|
| call 1 (uid 62932) `touch /run/x/f` | `f` owned by 62932 |
| after call 1 | uid 62932 no longer exists |
| call 2 (uid 62416) appends to `f` | **denied** |

Nobody but root can fix that file later, and systemd may hand the same uid
to another service, which would then own it. So per-call identities fit calls
that **leave nothing behind** (reads, checks, probes), and they refuse
shells.

## Configuration: `/etc/dsb/dsb.conf`

The policy is one file plus `conf.d/*.conf`, shipped with nothing enabled.
Example:

```ini
[global]
callers = alice                       # who may call (SO_PEERCRED)
env     = TERM COLORTERM LANG LANGUAGE LC_*

[identity dsb]                        # the default: a shell, any command
shell    = yes
commands = *

[identity web]                        # dsb -u web ...
write    = /srv/www /etc/nginx/sites-enabled
commands = /usr/bin/mkdir /usr/bin/install /usr/bin/ln /usr/bin/rm

[identity probe]                      # a new uid per call, nothing left behind
user     = dynamic
commands = /usr/bin/ping /usr/bin/ss
caps     = CAP_NET_RAW
timeout  = 60
```

Keys per identity: `user` (default `dsb-NAME`; an existing user; or
`dynamic`), `callers`, `shell` (default no), `edit` (default yes), `commands`
(default `*`), `write`, `groups`, `caps`, `env`, `timeout`. Unknown keys and
sections are errors. The reference is the top of the shipped file and
`src/dsb-conf.h`.

Two consumers read it: `dsbd` on every call (callers, modes, commands, env,
timeout), and the generator (`dsbd --generate`), which turns it into one
`dsb-NAME.socket` + `dsb-NAME@.service` per identity that has callers.
Units are never edited by hand; they are regenerated at every boot and
`daemon-reload`, so the file cannot drift from what runs. A file with errors
enables nothing (and never fails the boot).

With one caller the socket is `root:<caller's primary group> 0660`; with
several it is `0666` and `SO_PEERCRED` alone decides.

## The package is the admin step

| file | what |
|---|---|
| `/usr/bin/dsb` | the client, for any user |
| `/usr/libexec/dsb/dsbd` | runs per call, as the identity, never as root |
| `/usr/sbin/dsb-admin` | `check`, `apply`, `list` |
| `/usr/lib/systemd/system-generators/dsb-generator` | units from `dsb.conf` |
| `/etc/dsb/dsb.conf`, `conf.d/` | the policy (conffile: kept on upgrade, removed on purge) |
| `/usr/lib/sysctl.d/60-dsb.conf` | `dev.tty.legacy_tiocsti = 0` |

`postinst` sets the sysctl and runs `dsb-admin apply`; with the shipped file
that enables nothing. From then on the admin's part is one step per grant:

```sh
editor /etc/dsb/dsb.conf       # or drop a file into /etc/dsb/conf.d/
dsb-admin apply                # check → create users (systemd-sysusers)
                               # → daemon-reload (generator) → restart the
                               # sockets, stop removed identities
```

`apply` validates first; with any error nothing changes. Removing the package
stops the sockets; purging removes `/etc/dsb` and `/var/lib/dsb`, not the
users (their uids may still own files).

## Use cases

Anything a user legitimately needs beyond their own files, that an admin is
willing to grant once instead of handing out `sudo`:

- **a service's config dir**: `write = /etc/nginx/sites-enabled` for the web
  team, with no way to touch the rest of `/etc`;
- **a device or log group** without the group itself on the user:
  `groups = adm` for reading logs, `groups = dialout` for a serial port;
- **network probes**: `user = dynamic`, `caps = CAP_NET_RAW`, `commands =
  /usr/bin/ping`;
- **a shared maintenance account** several people can use, each call logged
  in the journal with the caller's uid;
- **userspace package managers** such as
  [sudo-less](https://github.com/jronminh/sudo-less), where a package whose
  only obstacle is one privileged step (a `mkdir` under `/etc/lighttpd`, a
  directory in group `utmp`) runs that step through a narrow identity instead
  of root. Root-executed config (`/etc/tmpfiles.d`, units, PAM, setuid) stays
  out of reach by design.

## Testing without root

`tests/dev-test.sh` runs the whole stack as runtime user units
(`dsb-admin --dev`): the sandbox, the policy, the protocol and the client are
real, but a user manager cannot switch users, so both ends are the same uid.
It checks exit and signal status, quoting, stdin, cwd, environment filtering,
`-l`, `commands =` refusals, the kernel's `ExecPaths=` block, timeouts,
`shell = no`, `edit = no`, the read-only sandbox, `NoNewPrivs`, empty
capabilities, `-e` write-back (same inode and mode), and the interactive
prompt and exit status.

Also checked by hand: 30 MB through a pipe byte-exact in 0.12 s; ≈ 55 ms per
call; Ctrl-C at the prompt cancels the line, during a command gives 130;
`less` works; `kill -9` on the client leaves no orphan. `ProtectSystem=strict`
alone left `/home` writable, so `ProtectHome=read-only` is required; a plain
`systemd-socket-activate` (no cgroup) leaves orphans, a socket unit does not.

Not yet verified: the package installed system-wide, so a different uid on
the far end, `DynamicUser=` with `dsbd`, `AmbientCapabilities=`, the
generator at boot.

## Open questions

- Audit: every call is a journal entry of its `dsb-NAME@<n>.service` (caller
  pid and uid, cwd, argv, exit status). Enough?
- Several callers share socket mode `0666` (`SO_PEERCRED` still decides); a
  per-identity caller group would keep the kernel DAC layer too.
- `commands =` matches programs, not arguments. Argument patterns would need
  a real matcher; left out on purpose so far.
