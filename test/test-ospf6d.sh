#!/usr/bin/env bash
# Functional test for the OSPFv3 address check (CVE-2026-119776).
# Runs as root inside a throwaway container with NET_ADMIN.
#
#   A (negative): Hello from a global source, same /64, AllSPFRouters dst
#                 -> must be discarded, no neighbor.
#   B (control) : Hello from a link-local source
#                 -> must be accepted, neighbor appears in Init.
#
# If B passes and A is discarded, the check is doing exactly what the fix
# claims: rejecting off-link sources while still speaking OSPFv3 normally.
set -uo pipefail

REL="${REL:-/out/frr-release}"
TAG="10.9-dev-cve-2026-119776"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "== installing staged tree over /usr =="
cp -a "$REL"/usr/. /usr/
ldconfig
# FRR daemons drop privileges to the "frr" user
id frr >/dev/null 2>&1 || {
  groupadd -r frr
  useradd -r -g frr -d /var/run/frr -s /usr/sbin/nologin frr
}
mkdir -p /etc/frr /var/run/frr /var/log/frr
touch /etc/frr/vtysh.conf /etc/frr/frr.conf
chown -R frr:frr /var/run/frr /var/log/frr

cat > /etc/frr/zebra.conf <<'EOF'
hostname r1
!
interface v0
 ipv6 address fe80::1/64
 ipv6 address 2001:db8:1::1/64
!
log file /var/log/frr/zebra.log
EOF

cat > /etc/frr/ospf6d.conf <<'EOF'
hostname r1
!
interface v0
 ipv6 ospf6 area 0.0.0.0
!
router ospf6
 ospf6 router-id 10.0.0.1
!
debug ospf6 message all
debug ospf6 neighbor detail
log file /var/log/frr/ospf6d.log
EOF

echo "== building two namespaces over a veth pair =="
ip netns del r 2>/dev/null; ip netns del a 2>/dev/null
ip netns add r
ip netns add a
ip link add v0 type veth peer name v1
ip link set v0 netns r
ip link set v1 netns a
ip -n r link set lo up
ip -n a link set lo up
ip -n r link set v0 up
ip -n a link set v1 up
ip -n r addr add fe80::1/64 dev v0
ip -n r addr add 2001:db8:1::1/64 dev v0
ip -n a addr add fe80::2/64 dev v1
ip -n a addr add 2001:db8:1::2/64 dev v1
sleep 1

echo "== starting zebra + patched ospf6d in ns r =="
ip netns exec r /usr/sbin/zebra-$TAG -f /etc/frr/zebra.conf \
  -i /var/run/frr/zebra.pid --vty_socket /var/run/frr -d || {
    echo "FAIL: zebra did not start"; cat /var/log/frr/zebra.log 2>/dev/null; exit 1; }
sleep 2
ip netns exec r /usr/sbin/ospf6d-$TAG -f /etc/frr/ospf6d.conf \
  -i /var/run/frr/ospf6d.pid --vty_socket /var/run/frr \
  -z /var/run/frr/zserv.api -d || {
    echo "FAIL: ospf6d did not start"; cat /var/log/frr/ospf6d.log 2>/dev/null; exit 1; }
sleep 4
if ! kill -0 "$(cat /var/run/frr/ospf6d.pid 2>/dev/null)" 2>/dev/null; then
  echo "FAIL: ospf6d exited"; tail -30 /var/log/frr/ospf6d.log; exit 1
fi

echo "--- ospf6 interfaces ---"
ip netns exec r /usr/bin/vtysh-$TAG --vty_socket /var/run/frr \
  -c "show ipv6 ospf6 interface v0" 2>&1 | head -30
echo "--- joined multicast ---"
ip -n r maddr show dev v0 2>&1 | head -8
echo "--- link counters before ---"
ip -n r -s link show v0 | head -6

# capture what actually reaches the router interface (proto 89 = OSPF)
command -v tcpdump >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tcpdump > /dev/null
ip netns exec r timeout 40 tcpdump -ni v0 -c 20 'ip6 proto 89' > /tmp/cap.txt 2>&1 &
CAP_PID=$!

neighbors() {
  ip netns exec r /usr/bin/vtysh-$TAG --vty_socket /var/run/frr \
    -c "show ipv6 ospf6 neighbor" 2>&1
}

echo
echo "== A: Hello from global source 2001:db8:1::2 (must be discarded) =="
ip netns exec a python3 "$HERE/ospf6_hello.py" global v1
sleep 3
NB_A="$(neighbors)"
echo "--- neighbor table ---"
echo "$NB_A"
echo "--- log tail ---"
tail -5 /var/log/frr/ospf6d.log
A_WARN=$(grep -c "discarding packet from non-LL source" /var/log/frr/ospf6d.log)
A_NEIGH=$(echo "$NB_A" | grep -c "Full/Dr\|2-Way\|Init/")
echo "A: non-LL discards=$A_WARN  neighbors=$A_NEIGH"

echo
echo "== B: Hello from link-local source fe80::2 (must be accepted) =="
ip netns exec a python3 "$HERE/ospf6_hello.py" ll v1
sleep 4
NB_B="$(neighbors)"
echo "--- neighbor table ---"
echo "$NB_B"
B_NEIGH=$(echo "$NB_B" | grep -c "Init/\|2-Way\|ExStart\|Full")
echo "B: neighbors=$B_NEIGH"
echo "--- log tail ---"
tail -8 /var/log/frr/ospf6d.log

echo
echo "--- link counters after ---"
ip -n r -s link show v0 | head -6
wait $CAP_PID 2>/dev/null
echo "--- tcpdump on v0 (proto 89) ---"
cat /tmp/cap.txt 2>/dev/null | head -20

echo
echo "================ RESULT ================"
rc=0
if [ "$A_WARN" -ge 1 ] && [ "$A_NEIGH" -eq 0 ]; then
  echo "PASS  off-link Hello rejected (warn logged, no adjacency)"
else
  echo "FAIL  off-link Hello was not rejected (warn=$A_WARN neighbors=$A_NEIGH)"; rc=1
fi
if [ "$B_NEIGH" -ge 1 ]; then
  echo "PASS  link-local Hello accepted (neighbor seen)"
else
  echo "FAIL  link-local Hello not accepted"; rc=1
fi
kill "$(cat /var/run/frr/ospf6d.pid 2>/dev/null)" 2>/dev/null
echo "========================================"
exit $rc
