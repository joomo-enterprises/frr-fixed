# FRRouting 10.9.0-dev — patched build (CVE-2026-119776)

**FRRouting built from master at `92ac4f532632`, for Debian bookworm / x86_64 —
the tree that carries the OSPFv3 address check upstream never backported.**

Source: `FRRouting/frr` @ `92ac4f532632` (contains fix
`eaccfcdb35bce8d94621b06633417ba3fa657f34`, 2026-11-02). Built 2026-11-25 in
`debian:bookworm-slim`, libyang 2.1.148 compiled from source and bundled.

## Why this build

CVE-2026-119776 is the OSPFv3 read path trusting packets it should never have
accepted: no link-local source check, no destination check beyond the RFC 5340
hop-limit rule. An off-link speaker that can reach `ff02::5` can form an
adjacency and inject LSAs into the LSDB.

Upstream fixed it in master on 2026-11-02. **No stable branch has the
backport, and Debian records bookworm/trixie/forky as vulnerable.** For an
operator on bookworm there is no package to install, so this repo builds one
and proves it works.

See **PATCHES.md** for the change itself and why it is not in any distro.

## Download & verify

```bash
# 1. grab the tarball from the release page, then:
sha256sum -c sha256sums.txt

# 2. confirm the binary carries the fix before you trust it
tar -xJf frr-10.9-dev-cve-2026-119776-bookworm-x86_64.tar.xz
grep -a -o "discarding packet from non-LL source[^\"]*" \
  frr-release/usr/sbin/ospf6d-10.9-dev-cve-2026-119776
# discarding packet from non-LL source %pI6, faulty neighbor?
```

## Install

```bash
sudo ./install.sh           # unpacks the tarball in the current directory
```

`install.sh` copies the tree to `/usr`, runs `ldconfig`, creates the `frr`
user and runtime directories, installs a sample `ospf6d` config, and adds
untagged symlinks (`/usr/sbin/ospf6d` → `ospf6d-10.9-dev-cve-2026-119776`) so
`/etc/frr/daemons` and existing unit files keep working. The tagged binaries
stay exactly as built.

Daemons land in `/usr/sbin` with the `-10.9-dev-cve-2026-119776` suffix;
`vtysh` in `/usr/bin`. Everything else (`/usr/lib/libfrr.so*`,
`/usr/lib/x86_64-linux-gnu/libyang.so*`, `/usr/share/yang`) comes with it.

## Verified, not assumed

`TEST-RESULTS.txt` is the real output of two network namespaces over a veth
pair, running the **installed** `ospf6d`, with a crafted OSPFv3 Hello:

| Case | Packet | Result |
|---|---|---|
| A | src `2001:db8:1::2` (global, same /64) → `ff02::5`, hlim 1 | 3 discards logged, neighbour table empty — **PASS** |
| B | src `fe80::2` (link-local) → `ff02::5`, hlim 1 | neighbour `10.0.0.2` in `Init` on `v0` — **PASS** |

The hellos are byte-identical apart from the source address, carry correct
RFC 5340 pseudo-header checksums, and `tcpdump` on the router interface shows
both arriving. B is the control: the daemon still speaks OSPFv3 normally, and
still refuses the off-link speaker.

Reproduce with `test/test-ospf6d.sh` (needs `NET_ADMIN`, `SYS_ADMIN`,
`NET_RAW`).

## Package contents

```
frr-release/usr/sbin/          daemons, tagged: zebra, ospf6d, ospfd, bgpd, isisd,
                               ripd, ripngd, pimd, pim6d, ldpd, bfdd, staticd,
                               mgmtd, pathd, pbrd, babeld, eigrpd, fabricd, watchfrr
frr-release/usr/bin/           vtysh, mtracebis, frr-reload, support-bundle tools
frr-release/usr/lib/           libfrr.so*, proto libs
frr-release/usr/lib/x86_64-linux-gnu/  libyang 2.1.148 (bundled — bookworm has 2.1.30)
frr-release/usr/share/yang/    YANG models
frr-release/frr-92ac4f532632-source.tar.gz  upstream source, unmodified
```

## Caveats — read before deploying

- **Master dev build (`10.9.0-dev`), not a distro package.** Not ABI-compatible
  with distro FRR; replace the whole tree, don't mix and match.
- Built `--disable-snmp --disable-zeromq --disable-ospfapi --disable-ospfclient`,
  no docs. Rebuild with `build-package.sh` if you need those.
- Binaries are unstripped with debug info (~120 MB extracted).
- This repo is a carry-forward, not a maintained fork. When your distro ships
  the fix, move to it and delete this.

## Rebuild

```bash
# on a bookworm container/host with the deps from the top of build-package.sh
bash build-package.sh
```

`build-package.sh` needs `--cap-add=NET_ADMIN --cap-add=SYS_ADMIN
--cap-add=NET_RAW` for the namespace test. `FRR_SHA` and `LYANG_SHA` are
overridable; output lands in `/out/frr-release`.

## Disclosure series

Repo → article: the ten-part OwlMan disclosure on FRRouting is at
`https://owlman.info/article/routing-protocols/frrouting-part-07-the-first-and-most-fundamental-flaw`
(CVE-2026-119776) and
`https://owlman.info/article/routing-protocols/frrouting-part-10-the-way-out`
(control-plane ACLs, authentication, and the backport nobody shipped).

## License

FRRouting is GPL-2.0-or-later, with some parts under other free licenses; the
binaries carry upstream's terms. This repo adds no restrictions. Upstream
source is included unmodified so every binary can be audited against
`92ac4f532632`.
