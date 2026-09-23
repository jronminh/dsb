#!/bin/bash
# End-to-end test without root: builds dsb, applies a test policy as runtime
# user units (dsb-admin --dev), checks the client, the daemon's policy and the
# systemd sandbox, then removes the units. Both ends run as you (a user
# manager cannot switch users), so the separate uid is not covered here.
#
# Needs: systemd user session, cc, script(1) for the interactive checks.
# Usage: tests/dev-test.sh [--keep]    (--keep leaves the units running)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RT="${XDG_RUNTIME_DIR:?needs a systemd user session}"
W="$RT/dsb-test-rw"          # visible inside the sandbox (/tmp is private)
C="$(mktemp -d)"
ADMIN="$ROOT/src/dsb-admin"
D="$ROOT/out/dsb"
export DSBD="$ROOT/out/dsbd"   # also for the non-dev checks
pass=0 fail=0

cleanup() {
  rm -rf "$C"
  if [ "${1:-}" != --keep ]; then "$ADMIN" --dev stop >/dev/null 2>&1; rm -rf "$W"; fi
}
trap 'cleanup "${KEEP:-}"' EXIT
[ "${1:-}" = --keep ] && KEEP=--keep

# check NAME EXPECTED_RC PATTERN -- CMD...   (PATTERN: grep -E on stdout+stderr, or "")
check() {
  local name="$1" want="$2" pat="$3"; shift 4
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if [ "$rc" = "$want" ] && { [ -z "$pat" ] || grep -qE -- "$pat" <<<"$out"; }; then
    pass=$((pass + 1)); printf 'ok    %s\n' "$name"
  else
    fail=$((fail + 1)); printf 'FAIL  %s (rc %s, want %s)\n%s\n' "$name" "$rc" "$want" "$out" | sed '2,$s/^/      /'
  fi
}

mkdir -p "$W" "$C/conf.d"
cat > "$C/dsb.conf" <<EOF
[global]
callers = $(id -un)
env     = TERM COLORTERM LANG LANGUAGE LC_* FOO*

[identity dsb]
shell = yes
write-extra = $W

[identity web]
commands = /usr/bin/ls /usr/bin/id /usr/bin/cat
write-extra = $W
timeout  = 2
edit     = no

[identity tight]
shell    = yes
commands = /usr/bin/id /usr/bin/sleep
timeout  = 2
EOF
cat > "$C/bad.conf" <<'EOF'
[identity evil]
user     = dynamic
shell    = yes
commands = sh
write    = /etc/systemd/system /usr/local
groups   = sudo
caps     = CAP_SYS_ADMIN
EOF

cat > "$C/rules.conf" <<EOF
[identity rules]
user     = $(id -un)
callers  = nobody
commands = /usr/bin/id
write    = /var/log /srv
groups   = input
caps     = CAP_NET_ADMIN CAP_BPF
EOF
cat > "$C/std.conf" <<EOF
[global]
callers    = $(id -un)
deny-paths = /srv/private
deny-caps  = CAP_KILL

[identity plain]
commands = /usr/bin/id

[identity open]
shell      = yes
namespaces = yes
caps       = CAP_SYS_TIME
caps-extra = CAP_KILL

[identity closed]
commands = /usr/bin/id
network  = no
jit      = no
groups   = video
devices  = none
write    = /srv/private/x
EOF

echo "== policy check"
check "valid config passes"          0 "ok$"     -- "$ADMIN" --dev --config "$C/dsb.conf" check
cp "$C/bad.conf" "$C/conf.d/bad.conf"
check "bad config: 6 errors"         1 "6 errors" -- "$ADMIN" --dev --config "$C/dsb.conf" check
check "bad config is not applied"    1 "nothing changed" -- "$ADMIN" --dev --config "$C/dsb.conf" apply
rm "$C/conf.d/bad.conf"
R() { "$ADMIN" --config "$C/rules.conf" check; }
check "rule 1: a person is refused"  1 "only dsb, dsb-NAME or dynamic" -- R
check "rule 2: input is not std"     1 "group input is outside" -- R
check "rule 3: NET_ADMIN needs -extra" 1 "CAP_NET_ADMIN is outside" -- R
check "rule 3: BPF is denied"        1 "CAP_BPF leads to root" -- R
check "rule 4: /var/log is not std"  1 "write /var/log is outside" -- R
check "rule 4: /srv itself is not"   1 "write /srv is outside" -- R
S() { "$ADMIN" --config "$C/std.conf" check; }
check "deny-caps adds to the list"   1 "CAP_KILL leads to root: added" -- S
check "deny-paths adds to the list"  1 "/srv/private/x overlaps /srv/private" -- S
check "--show-deny lists both"       0 "cap +CAP_KILL +added" -- "$ADMIN" --config "$C/std.conf" check --show-deny
check "--show-deny has the built-ins" 0 "path +/run/user" -- "$ADMIN" --config "$C/std.conf" check --show-deny
printf '[identity x]\ndeny-paths = /x\n' > "$C/global.conf"
check "deny-paths only in [global]"  1 "only in \\[global\\]" -- "$ROOT/out/dsbd" --check --config "$C/global.conf"

echo "== generated units (rule 5)"
sed -i -e '/^deny-caps/d' -e '/^write    = \/srv/d' "$C/std.conf"
mkdir "$C/u"; "$ROOT/out/dsbd" --generate "$C/u" --config "$C/std.conf" >/dev/null
P="$C/u/dsb-plain@.service" O="$C/u/dsb-open@.service" X="$C/u/dsb-closed@.service"
check "/run/user is inaccessible"    0 "" -- grep -qx 'InaccessiblePaths=-/run/user' "$P"
check "no devices by default"        0 "" -- grep -qx 'PrivateDevices=yes' "$P"
check "no namespaces by default"     0 "" -- grep -qx 'RestrictNamespaces=yes' "$P"
check "clock protected by default"   0 "" -- grep -qx 'ProtectClock=yes' "$P"
check "network by default"           1 "" -- grep -q 'PrivateNetwork' "$P"
check "namespaces = yes lifts it"    1 "" -- grep -qE 'RestrictNamespaces|@mount|ProtectKernelModules' "$O"
check "modules still filtered"       0 "" -- grep -q '@module' "$O"
check "CAP_SYS_TIME lifts ProtectClock" 1 "" -- grep -qE 'ProtectClock|@clock' "$O"
check "caps-extra is granted"        0 "" -- grep -qx 'AmbientCapabilities=CAP_SYS_TIME CAP_KILL' "$O"
check "network = no"                 0 "" -- grep -qx 'PrivateNetwork=yes' "$X"
check "jit = no"                     0 "" -- grep -qx 'MemoryDenyWriteExecute=yes' "$X"
check "devices = none despite video" 0 "" -- grep -qx 'PrivateDevices=yes' "$X"
if systemd-analyze security --help 2>/dev/null | grep -q -- --offline; then
  check "units score within the limit" 0 "ok$" -- S
fi

echo "== apply"
printf '[identity gone]\ncommands = /usr/bin/id\n' > "$C/conf.d/gone.conf"
check "apply enables 4 identities"   0 "enabled: gone" -- "$ADMIN" --dev --config "$C/dsb.conf" apply
rm "$C/conf.d/gone.conf"
check "apply stops a removed one"    0 "stopped: gone" -- "$ADMIN" --dev --config "$C/dsb.conf" apply
check "its socket file is gone"      0 ""        -- test ! -e "$RT/dsb-dev/gone.sock"
export DSB_RUNDIR="$RT/dsb-dev"

echo "== commands"
check "exit status passes"           7 ""        -- "$D" sh -c 'exit 7'
check "signal death is 128+N"        143 ""      -- "$D" sh -c 'kill -TERM $$'
check "missing command is 127"       127 "not found" -- "$D" no-such-command-xyz
check "quoting survives"             0 "^a b\|c$" -- "$D" printf '%s|%s\n' 'a b' c
check "stdin passes"                 0 "^hello$" -- bash -c "echo hello | '$D' cat"
check "-p feeds a file"              0 "."       -- "$D" -p /etc/hostname cat
check "-c runs a line"               0 "^2$"     -- "$D" -c 'echo $((1+1))'
check "-D fails hard"                1 "cannot enter" -- "$D" -D /nonexistent true
check "cwd kept"                     0 "^$W$"    -- bash -c "cd '$W' && '$D' pwd"

echo "== environment"
check "env pattern passes FOO*"      0 "FOOBAR=1 BAZ= " -- env FOOBAR=1 BAZ=2 "$D" --preserve-env=FOOBAR,BAZ sh -c 'echo "FOOBAR=$FOOBAR BAZ=$BAZ "'
check "PATH is the identity's"       0 "^/usr/local/bin:/usr/bin:/bin$" -- env PATH="/evil:$PATH" "$D" sh -c 'echo $PATH'
check "LD_PRELOAD never passes"      0 "^-$"     -- env LD_PRELOAD=/x "$D" --preserve-env=LD_PRELOAD sh -c 'echo ${LD_PRELOAD:--}'
check "identity is named"            0 "^dsb$"   -- "$D" sh -c 'echo $DSB_IDENTITY'

echo "== policy"
check "-l lists the identity"        0 "commands  \*" -- "$D" -l
check "allowed command runs"         0 "."       -- "$D" -u web id -u
check "allowed by path too"          0 "."       -- "$D" -u web /bin/id -u
check "other command refused"        1 "not allowed" -- "$D" -u web touch "$W/x"
check "-l CMD says not allowed"      1 "not allowed" -- "$D" -u web -l touch
check "shell = no refuses -c"        1 "has no shell" -- "$D" -u web -c id
check "shell = no refuses -s"        1 "has no shell" -- "$D" -u web -s
check "edit = no refuses -e"         1 "may not edit" -- "$D" -u web -e /etc/hostname
check "kernel blocks off-list exec"  126 "Permission denied" -- "$D" -u tight -c 'id -u; ls /'
check "timeout kills with 124"       124 "timed out" -- "$D" -u tight sleep 5
check "root is refused"              1 "never root" -- "$D" -u root id
check "unknown identity"             1 "no identity" -- "$D" -u nope id

echo "== sandbox"
check "/etc is read-only"            1 "Read-only" -- "$D" touch /etc/dsb-test
check "home is read-only"            1 "Read-only" -- "$D" touch "$HOME/.dsb-test"
check "write = dir is writable"      0 ""        -- "$D" touch "$W/ok"
check "no new privileges"            0 "NoNewPrivs:[[:space:]]1" -- "$D" grep NoNewPrivs /proc/self/status
check "no capabilities"              0 "CapEff:[[:space:]]0+$" -- "$D" grep CapEff /proc/self/status

echo "== edit (-e)"
cp /etc/hostname "$W/f"; chmod 640 "$W/f"; ino=$(stat -c %i "$W/f")
printf '#!/bin/sh\necho edited >> "$1"\n' > "$C/ed"; chmod +x "$C/ed"
check "edit writes back"             0 ""        -- env EDITOR="$C/ed" "$D" -e "$W/f"
check "same inode and mode"          0 "^$ino 640$" -- stat -c '%i %a' "$W/f"
check "unchanged file not written"   0 "unchanged" -- env EDITOR=true "$D" -e "$W/f"
check "new file created"             0 ""        -- env EDITOR="$C/ed" "$D" -e "$W/new"
check "read-only target keeps edit"  1 "your edit is kept" -- env EDITOR="$C/ed" "$D" -e /etc/hostname
rm -f /tmp/dsb.*-hostname

echo "== interactive"
if command -v script >/dev/null; then
  shell() { (sleep 1; printf '%s\n' "$2"; sleep 1) | script -qec "$D $1" /dev/null | tr -d '\r'; }
  check "bare dsb: prompt, tty, status" 0 "dsb> .*" -- shell "" 'tty; exit 0'
  check "prompt names the identity"  0 "tight> " -- shell "-u tight" 'exit'
  check "exit status of the shell"   0 ""        -- bash -c "(sleep 1; echo 'exit 3'; sleep 1) | script -qec '$D' /dev/null >/dev/null; [ \$? = 3 ]"
else
  echo "skip  interactive checks (no script(1))"
fi

echo
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]
