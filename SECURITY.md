# Security

dsb changes who can do what on a machine, so its security model is the
product. Please read this before deploying it.

## Status

**Unaudited.** dsb 0.1.0 is a prototype written with AI assistance. Its
policy, protocol and sandbox are tested with both ends running as the same
uid (`tests/dev-test.sh`); the installed, cross-uid setup has not been
tested yet. Do not rely on it where a mistake would be costly.

## Threat model

**Trusted:** root, the kernel, systemd, and the admin who writes
`/etc/dsb/dsb.conf`.

**Not trusted:** the caller and everything the caller sends: arguments,
environment, current directory, file descriptors, the terminal. Any process
running as a caller may call dsb.

**Goal:** a caller can do, through an identity, exactly what that identity's
configuration allows, and no more. In particular:

1. no path to root: not through setuid programs, capabilities, root-read
   config, or the daemon itself (which never runs as root);
2. no write outside the identity's `write =` paths (and its own state dir);
3. with a `commands =` list, no execution of any other program, even from an
   allowed shell or interpreter;
4. no identity is reachable by a uid not in its `callers =`;
5. nothing the identity does outlives the call (cgroup cleanup).

**Out of scope:** what the admin grants on purpose. An identity allowed to
write `/srv/www` can deface the site; one with `commands = *` and `shell =
yes` can run anything its uid and sandbox allow. Granting a program that
runs other programs (`sh`, `python3`, `find`, `env`, `vim`, …) grants all
of the rest of `commands` too; `dsb-admin check` warns about those.

Also out of scope: kernel or systemd sandbox escapes, and side channels.

## Known limits

- The command runs on the caller's terminal. Legacy `TIOCSTI` would let it
  type into the caller's shell afterwards; the package sets
  `dev.tty.legacy_tiocsti = 0` and `dsb-admin` refuses to run with it on.
  Other terminal tricks (escape sequences) are possible, as with `sudo`.
- `commands =` matches programs, not their arguments.
- With several `callers`, the socket is mode `0666` and `SO_PEERCRED` alone
  decides who may call.
- `user = dynamic` identities may leave files owned by a released uid if
  they write outside `/run` or `/var/lib`; shells are refused for them.

## Reporting a vulnerability

Please report privately through GitHub's **Report a vulnerability**
(Security → Advisories) on this repository, not in a public issue. Include
the config, the command, and what happened. You will get an answer within a
week; fixes are credited unless you prefer otherwise.
