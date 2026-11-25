#!/usr/bin/env bash
# Build FRRouting at master commit 92ac4f5326 (contains CVE-2026-119776 fix
# eaccfcdb35 "ospf6d: tighten packet address checks") and package the release.
# Runs inside a Debian bookworm container; output lands in /out/frr-release/.
set -euxo pipefail

FRR_SHA="${FRR_SHA:-92ac4f532632}"
WORK=/build
OUT=/out

# 1. build deps (minimal, no optional yang/snmp)
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  build-essential autoconf automake libtool bison flex \
  libjson-c-dev libreadline-dev libpcre2-dev libcap-dev libelf-dev \
  cmake pkg-config protobuf-c-compiler libprotobuf-c-dev gcc-12-plugin-dev \
  python3-dev git ca-certificates wget file > /dev/null

# 2a. libyang >= 2.1.128 (FRR master hard-dep; bookworm's 2.1.30 is too old).
# Built once into $WORK/libyang-root and re-installed into the container on
# every run, so repeat runs are cheap and the FRR objects stay incremental.
LYANG_SHA="${LYANG_SHA:-v2.1.148}"
LYROOT="$WORK/libyang-root"
mkdir -p "$WORK"
cd "$WORK"
if [ ! -e "$LYROOT/usr/lib/libyang.so" ] && [ ! -e "$LYROOT/usr/lib/x86_64-linux-gnu/libyang.so" ]; then
if [ ! -f libyang.tar.gz ]; then
  wget -q "https://codeload.github.com/CESNET/libyang/tar.gz/refs/tags/$LYANG_SHA" -O libyang.tar.gz
fi
rm -rf libyang-src
mkdir libyang-src
tar -xzf libyang.tar.gz -C libyang-src --strip-components=1
cd libyang-src
mkdir -p build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_LYD_PRIV=ON -DENABLE_VALGRIND=OFF .. > /dev/null
make -j"$(nproc)" > /dev/null
make install DESTDIR="$LYROOT" > /dev/null
cd "$WORK"
fi
cp -a "$LYROOT"/usr/. /usr/
ldconfig
pkg-config --atleast-version=2.1.128 libyang

# 2. fetch the fixed tree (full source txz via codeload at the pinned sha)
if [ ! -f frr.tar.gz ]; then
  wget -q "https://codeload.github.com/FRRouting/frr/tar.gz/$FRR_SHA" -O frr.tar.gz
fi
if [ ! -d frr/ospf6d ]; then
  rm -rf frr
  mkdir frr
  # codeload sha tarballs extract to a dir named frr-<sha>
  tar -xzf frr.tar.gz -C frr --strip-components=1
fi
cd frr

# 3. sanity: fix present in this tree
grep -q "discarding packet with bogus destination" ospf6d/ospf6_message.c
grep -q "discarding packet from non-LL source" ospf6d/ospf6_message.c

# 4. build
if [ ! -f Makefile ]; then
  ./bootstrap.sh > /dev/null 2>&1
  ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
    --disable-doc --disable-snmp --disable-zeromq --disable-ospfapi \
    --disable-ospfclient --enable-vtysh \
    > /dev/null
fi
make -j"$(nproc)" > /dev/null

# 5. stage a real install tree (make install puts the linked ELF binaries,
#    not the libtool wrapper scripts, and lays libfrr out where the daemons
#    can find it)
REL="$OUT/frr-release"
rm -rf "$REL"; mkdir -p "$REL"
make install DESTDIR="$REL" > /dev/null

# bundle the libyang we built: bookworm's 2.1.30 is too old, so the tree has
# to carry its own (otherwise the daemons won't load on a stock system)
cp -a "$LYROOT"/usr/. "$REL"/usr/

TAG="10.9-dev-cve-2026-119776"
SBIN="$REL/usr/sbin"; BIN="$REL/usr/bin"
[ -d "$SBIN" ] || SBIN="$REL/usr/local/sbin"
[ -d "$BIN" ] || BIN="$REL/usr/local/bin"

# rename every installed daemon with the CVE tag (user rule: headline binary
# carries the CVE it fixes)
for d in "$SBIN"/* "$BIN"/*; do
  [ -f "$d" ] || continue
  base=$(basename "$d")
  case "$base" in
    *-"$TAG"|*.so*|*.py|*.json|*.yang|*.sh) continue ;;
  esac
  if head -c4 "$d" | grep -q $'\x7fELF'; then
    mv "$d" "$d-$TAG"
  fi
done

# 6. smoke test: version + fix strings in the installed ospf6d
OSPF6="$SBIN/ospf6d-$TAG"; [ -x "$OSPF6" ] || OSPF6="$BIN/ospf6d-$TAG"
export LD_LIBRARY_PATH="$REL/usr/lib:$REL/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
"$OSPF6" --version 2>&1 | head -3
# grep -c (not -q) so strings isn't killed by SIGPIPE under pipefail
test "$(strings "$OSPF6" | grep -c "bogus destination")" -ge 1
test "$(strings "$OSPF6" | grep -c "non-LL source")" -ge 1
echo "libfrr: $(ldd "$OSPF6" | grep libfrr | head -1)"

# 7. copy the source so the binary can be audited against the sha
cp "$WORK/frr.tar.gz" "$REL/frr-$FRR_SHA-source.tar.gz"

echo "=== staged tree ==="
find "$REL" -maxdepth 3 -type d | sort | head -20
ls -la "$SBIN" | head -25

# 8. functional test: does the patched ospf6d actually refuse an off-link Hello
#    while still accepting a link-local one? (needs NET_ADMIN in the container)
if [ "${FUNCTIONAL_TEST:-1}" = "1" ]; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iproute2 > /dev/null
  REL="$REL" bash /build-src/test/test-ospf6d.sh
fi

echo "BUILD-OK"