# dsb — debian sandboxed bridge

`sudo` for a **bounded middle identity** instead of root.

![license: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue)
![platform: Debian + systemd](https://img.shields.io/badge/platform-Debian%20%2B%20systemd-A81D33)
![target: never root](https://img.shields.io/badge/target-never%20root-brightgreen)

```sh
dsb -u web mkdir -p /srv/www/app            # as identity "web", not as root
dsb -u web -e /srv/www/app/index.html        # sudoedit-style
dsb                                          # a shell: "dsb> "
dsb -l                                       # what may I do here?
```

The admin decides once, in `/etc/dsb/dsb.conf`, what each identity may do:
which paths it can write, which groups and capabilities it has, which
commands it may run, whether it gets a shell. The kernel enforces it. Users
then get the familiar `sudo` interface for exactly that much power, with no
password, and no way to reach root through it.

The idea comes from Android's `adb shell`: a command that runs anything, as
an identity (`shell`, uid 2000) whose power is fixed in advance. dsb makes
that identity configurable.

**The name.** *debian*: the limits come from Debian's own standards (Debian
Policy's UID ranges, base-passwd's group list, the dpkg database).
*sandboxed*: every call runs in a fresh systemd sandbox, never as root.
*bridge*: it carries you across to another identity, with your terminal,
pipes and exit status intact. (It was first "superuser bridge", which
described what it replaces, not what it is.)

> [!CAUTION]
> **Early, AI-assisted and unaudited.** Written with an AI assistant, tested
> on one Debian sid machine. Read the code (≈ 1 500 lines of C and sh) before trusting it.
> See [`SECURITY.md`](SECURITY.md).

## How it works

```
dsb CMD ──unix socket + its own fds 0,1,2──▶ systemd (Accept=yes)
                                               │ one sandboxed service per call,
                                               ▼ already running as the identity
                                             dsbd: check caller (SO_PEERCRED),
                                               policy, env, then execve CMD
```

- **No root daemon.** systemd holds the socket and starts each call as the
  identity; `dsbd` never has root to lose.
- **No relaying.** The caller's stdin/stdout/stderr are passed with
  `SCM_RIGHTS`: pipes stay byte-exact, the terminal stays the terminal,
  exit status and signals come back.
- **Kernel-enforced locks** per identity: its own user and granted
  groups; `ProtectSystem=strict` with only the `write =` paths writable;
  `NoNewPrivileges` and no capabilities beyond an allowlist; optionally
  `ExecPaths=` so only the listed commands can be executed at all. Around
  them, a hardened unit: no `/run/user`, no devices, namespaces, realtime
  or clock changes unless the policy grants them.
- **Never feed root.** Every grant is checked against a published standard
  ([`docs/standards.md`](docs/standards.md)): `write =` only to data dirs no
  package owns, groups from base-passwd's safe list, capabilities off
  Spengler's root-equivalence list, and a `systemd-analyze security` score
  for every unit. Outside that, `KEY-extra =` works with a warning; a
  built-in deny list (`/etc`, `/usr`, `/run/user`, `sudo`, `disk`,
  `CAP_SYS_ADMIN`, …) is out of reach of any key.

Full design, rejected alternatives and test results:
[`docs/design.md`](docs/design.md). Every fixed limit and its source:
[`docs/standards.md`](docs/standards.md).

dsb never runs anything as root. For a fixed root command (restart one
service, read one drive's health), see the companion proposal
[rootcall](docs/rootcall.md), which would replace custom polkit rules and
`NOPASSWD` lines for fixed actions. More power comes from such companion
packages, never from dsb itself
([design](docs/design.md#growing-the-shell-a-core-and-companions)).

## Build and install

Needs a C compiler, Debian with systemd (tested on sid; systemd ≥ 247 for
`ExecPaths=`), and no libraries.

```sh
./build.sh          # out/dsb, out/dsbd
./build-deb.sh      # out/dsb_0.1.0_<arch>.deb
sudo apt install ./out/dsb_0.1.0_*.deb
```

The package enables nothing by itself. Then, as root:

```sh
editor /etc/dsb/dsb.conf       # or add a file in /etc/dsb/conf.d/
dsb-admin check                # errors, warnings for each -extra, unit scores
dsb-admin apply                # validate, create users, generate units, start sockets
dsb-admin list
```

## Configuration

```ini
[global]
callers = alice bob                   # who may call
env     = TERM COLORTERM LANG LANGUAGE LC_*

[identity dsb]                        # `dsb` with no -u: a shell, any command
shell    = yes

[identity web]                        # dsb -u web ...
write    = /srv/www
commands = /usr/bin/mkdir /usr/bin/install /usr/bin/ln /usr/bin/rm
callers  = alice

[identity probe]                      # a fresh uid per call
user     = dynamic
commands = /usr/bin/ping /usr/bin/ss
caps     = CAP_NET_RAW
timeout  = 60

[identity logs]
commands    = /usr/bin/journalctl
groups      = systemd-journal         # on the allowlist: silent
write-extra = /var/log/myapp          # outside it: a warning on every check
network     = no
```

Every grant has three levels: `KEY =` inside the standard allowlist,
`KEY-extra =` outside it with a warning, and a built-in deny list no key
reaches (`dsb-admin check --show-deny`).

Keys: `user`, `callers`, `shell`, `edit`, `commands`, `write`, `groups`,
`caps` (and their `-extra` forms), `network`, `devices`, `jit`,
`namespaces`, `env`, `timeout`; `deny-paths`, `deny-groups`, `deny-caps` in
`[global]`. The shipped [`etc/dsb.conf`](etc/dsb.conf) documents each one.
A config with any error enables nothing.

## Usage

```
dsb [-u IDENT] CMD [ARG...]      run CMD
dsb [-u IDENT]                   interactive shell (if shell = yes)
dsb -s [CMD] | -i [CMD]          shell / login shell
dsb -c 'LINE' | -f FILE          run a shell command line
dsb -e FILE...                   edit as the identity; your $EDITOR runs as you
dsb -l [CMD]                     list the identity's policy / would CMD run?
dsb -D DIR | -p FILE | --preserve-env=VAR,...
```

`-v -k -K -n -H` are accepted and ignored, so `sudo` scripts port by
changing one word. `-u root` is always refused.

## Try it without root

```sh
tests/dev-test.sh
```

runs the real daemon, policy and sandbox as your own runtime user units
(`src/dsb-admin --dev`). Both ends are your uid, so it tests everything but
the uid switch. To play by hand:

```sh
src/dsb-admin --dev --config my.conf apply    # prints: export DSB_RUNDIR=...
out/dsb -l
src/dsb-admin --dev stop
```

## Status

0.1.0, a working prototype. Tested rootless (`tests/dev-test.sh`, 67
checks) and installed system-wide on Debian sid with separate uids, a `DynamicUser`
identity and an ambient capability (results in
[`docs/design.md`](docs/design.md#testing)). Not yet verified:
the generator at an actual boot. Linux-only by design (`SO_PEERCRED`,
systemd).

## Used by

- [sudo-less](https://github.com/jronminh/sudo-less) — userspace `apt`/`dpkg`
  into `~/.local`; its dsb policy gives the developer a fresh empty account
  for testing installs and a journal reader, without root.

## License

[GPL-3.0-or-later](LICENSE). Built by **jronminh** with Claude (Anthropic) as
pairing assistant.
