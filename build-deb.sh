#!/bin/sh
# Build dsb_VERSION_ARCH.deb into out/. No root needed to build; installing
# it is the admin step that enables dsb (docs/design.md).
#
# Maintainer: $DEBFULLNAME <$DEBEMAIL>, else git config user.name/email.
#
#   /usr/bin/dsb                               the client (any user)
#   /usr/libexec/dsb/dsbd                     the daemon, run per call by systemd
#   /usr/sbin/dsb-admin                        check | apply | list
#   /usr/lib/systemd/system-generators/dsb-generator
#                                               units from dsb.conf, every boot
#                                               and daemon-reload
#   /etc/dsb/dsb.conf, /etc/dsb/conf.d/      the policy (conffile)
#   /usr/lib/sysctl.d/60-dsb.conf              dev.tty.legacy_tiocsti = 0
set -eu
umask 022
cd "$(dirname "$0")"
VERSION=0.1.0
ARCH="$(dpkg --print-architecture)"
MAINT="${DEBFULLNAME:-$(git config user.name || echo unknown)} <${DEBEMAIL:-$(git config user.email || echo unknown@invalid)}>"
./build.sh >/dev/null
R="$(mktemp -d)"; chmod 755 "$R"
trap 'rm -rf "$R"' EXIT

install -D -m 755 out/dsb "$R/usr/bin/dsb"
install -D -m 755 out/dsbd "$R/usr/libexec/dsb/dsbd"
install -D -m 755 src/dsb-admin "$R/usr/sbin/dsb-admin"
install -D -m 644 etc/dsb.conf "$R/etc/dsb/dsb.conf"
mkdir -p "$R/etc/dsb/conf.d"
install -d "$R/usr/lib/systemd/system-generators" "$R/usr/lib/sysctl.d" "$R/usr/share/doc/dsb"
cat > "$R/usr/lib/systemd/system-generators/dsb-generator" <<'EOF'
#!/bin/sh
# One socket + service template per enabled identity in /etc/dsb/dsb.conf.
exec /usr/libexec/dsb/dsbd --generate "$1"
EOF
chmod 755 "$R/usr/lib/systemd/system-generators/dsb-generator"
cat > "$R/usr/lib/sysctl.d/60-dsb.conf" <<'EOF'
# dsb hands the caller's terminal to the identity: it must not be able to
# type into it (TIOCSTI).
dev.tty.legacy_tiocsti = 0
EOF
install -m 644 README.md docs/design.md docs/standards.md SECURITY.md "$R/usr/share/doc/dsb/"

mkdir -p "$R/DEBIAN"
cat > "$R/DEBIAN/control" <<EOF
Package: dsb
Version: $VERSION
Architecture: $ARCH
Maintainer: $MAINT
Depends: libc6, systemd
Section: admin
Priority: optional
Description: run commands as a bounded middle identity, never root
 A sudo-like client and a socket-activated daemon. The admin decides in
 /etc/dsb/dsb.conf which users may act as which identity, and what that
 identity may run and write; systemd sandboxes every call. No setuid binary,
 no password, no ssh, no long-running root process.
EOF
echo /etc/dsb/dsb.conf > "$R/DEBIAN/conffiles"
cat > "$R/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = configure ] && [ -d /run/systemd/system ]; then
  sysctl -q -w dev.tty.legacy_tiocsti=0 2>/dev/null || true
  dsb-admin apply || echo "dsb: fix /etc/dsb/dsb.conf, then run dsb-admin apply" >&2
fi
EOF
cat > "$R/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
  for u in $(systemctl list-units --plain --no-legend --all 'dsb-*.socket' | awk '{print $1}'); do
    systemctl stop "$u" || true
  done
fi
EOF
cat > "$R/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
[ ! -d /run/systemd/system ] || systemctl daemon-reload || true
# the identities' users stay (their uids may own files); their homes go
[ "$1" != purge ] || rm -rf /var/lib/dsb /var/lib/private/dsb
EOF
chmod 755 "$R/DEBIAN/postinst" "$R/DEBIAN/prerm" "$R/DEBIAN/postrm"
dpkg-deb --root-owner-group -Zxz --build "$R" "out/dsb_${VERSION}_${ARCH}.deb" >/dev/null
echo "built: $(pwd)/out/dsb_${VERSION}_${ARCH}.deb"
