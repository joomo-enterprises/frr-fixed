#!/bin/sh
# Install the patched FRRouting build (CVE-2026-119776) from the release tarball.
#
#   sudo ./install.sh
#
# Overrides:
#   PREFIX=/usr/local   install root (skips root check when not /usr)
#   SKIP_VERIFY=1       don't check sha256sums.txt
#
# It does NOT start any daemon. It replaces an existing FRR tree, which is what
# you want — the daemons and libfrr must come from the same build.
set -eu

TARBALL="frr-10.9-dev-cve-2026-119776-bookworm-x86_64.tar.xz"
TAG="10.9-dev-cve-2026-119776"
PREFIX="${PREFIX:-/usr}"
HERE=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" -ne 0 ] && [ "$PREFIX" = "/usr" ]; then
  echo "Run as root, or set PREFIX to a writable path." >&2
  exit 1
fi

if [ ! -f "$HERE/$TARBALL" ]; then
  echo "Missing $TARBALL next to this script." >&2
  echo "Download it from https://github.com/joomo-enterprises/frr-fixed/releases" >&2
  exit 1
fi

echo "== dependencies =="
if command -v apt-get >/dev/null; then
  # xz-utils is needed to unpack; the rest are the daemons' runtime libs
  DEPS="xz-utils libjson-c5 libreadline8 libpcre2-8-0 libcap2 libelf1"
  MISSING=""
  for p in $DEPS; do
    dpkg -s "$p" >/dev/null 2>&1 || MISSING="$MISSING $p"
  done
  if [ -n "$MISSING" ]; then
    echo "installing$MISSING"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $MISSING
  fi
elif ! command -v xz >/dev/null; then
  echo "Need xz (xz-utils) to unpack this tarball." >&2
  exit 1
else
  echo "not Debian: ensure libjson-c, libreadline, libpcre2, libcap, libelf are present" >&2
fi

if [ "${SKIP_VERIFY:-0}" != "1" ] && [ -f "$HERE/sha256sums.txt" ] && command -v sha256sum >/dev/null; then
  echo "== verifying checksums =="
  ( cd "$HERE" && sha256sum -c sha256sums.txt )
fi

echo "== unpacking =="
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM
tar -xJf "$HERE/$TARBALL" -C "$WORK"
REL="$WORK/frr-release"

echo "== installing to $PREFIX =="
mkdir -p "$PREFIX"
cp -a "$REL/usr/." "$PREFIX"/
ldconfig

echo "== frr user and runtime dirs =="
if ! id frr >/dev/null 2>&1; then
  groupadd -r frr 2>/dev/null || true
  useradd -r -g frr -d /var/run/frr -s /usr/sbin/nologin frr 2>/dev/null || true
fi
mkdir -p /etc/frr /var/run/frr /var/log/frr
chown -R frr:frr /var/run/frr /var/log/frr 2>/dev/null || true

echo "== untagged symlinks (so /etc/frr/daemons keeps working) =="
for f in "$PREFIX"/sbin/*-"$TAG"; do
  [ -e "$f" ] || continue
  base=$(basename "$f" "-$TAG")
  ln -sf "$(basename "$f")" "$PREFIX/sbin/$base"
done
for f in "$PREFIX"/bin/*-"$TAG"; do
  [ -e "$f" ] || continue
  base=$(basename "$f" "-$TAG")
  ln -sf "$(basename "$f")" "$PREFIX/bin/$base"
done

echo "== sample configs (only if absent) =="
if [ ! -f /etc/frr/ospf6d.conf ]; then
  cat > /etc/frr/ospf6d.conf <<'EOF'
! sample — edit interfaces before starting
hostname r1
!
interface eth0
 ipv6 ospf6 area 0.0.0.0
!
router ospf6
 ospf6 router-id 10.0.0.1
!
log file /var/log/frr/ospf6d.log
EOF
  chown frr:frr /etc/frr/ospf6d.conf
fi
if [ ! -f /etc/frr/daemons ]; then
  cat > /etc/frr/daemons <<EOF
zebra=yes
ospf6d=yes
ospfd=no
bgpd=no
isisd=no
pimd=no
pim6d=no
ldpd=no
ripd=no
ripngd=no
staticd=yes
# daemons run from $PREFIX/sbin; tagged binaries are symlinked untagged
EOF
fi

echo
echo "Installed FRRouting $TAG to $PREFIX"
echo "Verify the fix is present:"
echo "  grep -a 'non-LL source' $PREFIX/sbin/ospf6d-$TAG"
echo "Check it runs:"
echo "  $PREFIX/sbin/ospf6d-$TAG --version"
echo "Then edit /etc/frr/ospf6d.conf and start the service:"
echo "  systemctl enable --now frr    # or /usr/lib/frr/frrinit.sh start"
