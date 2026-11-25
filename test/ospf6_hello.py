#!/usr/bin/env python3
"""Send a crafted OSPFv3 Hello from an arbitrary IPv6 source.

mode "global" : source is a global address (2001:db8:1::2) -> must be REJECTED
mode "ll"     : source is link-local (fe80::2)            -> must be ACCEPTED

Raw AF_INET6 socket: we build the full IPv6 header ourselves, and compute the
OSPFv3 checksum over the RFC 5340 pseudo-header, so the packet is well-formed
by every measure except the address rules under test.
"""
import socket
import struct
import sys
import time

IFACE = sys.argv[2] if len(sys.argv) > 2 else "v1"
IPPROTO_OSPF = 89
MODE = sys.argv[1] if len(sys.argv) > 1 else "global"

SRC = "2001:db8:1::2" if MODE == "global" else "fe80::2"
DST = "ff02::5"          # AllSPFRouters
RID = "10.0.0.2"
AREA = "0.0.0.0"


def a6(addr):
    return socket.inet_pton(socket.AF_INET6, addr)


def a4(addr):
    return socket.inet_pton(socket.AF_INET, addr)


def checksum(payload, src, dst):
    """RFC 5340 A.3.1 pseudo-header checksum (next header 89)."""
    pseudo = a6(src) + a6(dst) + struct.pack("!I", len(payload)) + b"\x00\x00\x00" + bytes([89])
    buf = pseudo + payload
    if len(buf) % 2:
        buf += b"\x00"
    total = 0
    for i in range(0, len(buf), 2):
        total += (buf[i] << 8) | buf[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def hello_packet():
    # OSPFv3 header (16 bytes), checksum zeroed while computing
    hdr_len = 16
    body = struct.pack("!I", 5)          # interface id
    body += struct.pack("!B", 1)         # priority
    body += b"\x00\x00\x13"              # options
    body += struct.pack("!H", 10)        # hello interval
    body += struct.pack("!H", 40)        # router dead interval
    body += a4("0.0.0.0")                # DR
    body += a4("0.0.0.0")                # BDR
    # no neighbors listed -> we should appear in Init

    length = hdr_len + len(body)
    hdr = struct.pack("!BBH", 3, 1, length)
    hdr += a4(RID)
    hdr += a4(AREA)
    hdr += b"\x00\x00"                   # checksum placeholder
    hdr += b"\x00"                       # instance id
    hdr += b"\x00"                       # reserved
    pkt = bytearray(hdr + body)
    csum = checksum(bytes(pkt), SRC, DST)
    pkt[12:14] = struct.pack("!H", csum)
    return bytes(pkt)


def send(count=3):
    payload = hello_packet()
    # AF_INET6 SOCK_RAW: the kernel prepends the IPv6 header itself (unlike
    # AF_INET), so we bind the source address and hand over OSPF only.
    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, IPPROTO_OSPF)
    idx = socket.if_nametoindex(IFACE)
    s.bind((SRC, 0, 0, idx))
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 1)

    for _ in range(count):
        s.sendto(payload, (DST, 0, 0, idx))
        time.sleep(0.5)
    print("sent %d hello(s) src=%s dst=%s on %s" % (count, SRC, DST, IFACE))


if __name__ == "__main__":
    send()
