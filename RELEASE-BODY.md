# FRRouting 10.9.0-dev — CVE-2026-119776 patch line (pre-built, linux x86_64 / bookworm)

Pre-built **FRRouting master @ 92ac4f532632** — the tree that carries the
OSPFv3 address check upstream never backported — for Debian bookworm / x86_64.
libyang 2.1.148 is compiled in and bundled.

Upstream landed the fix (`eaccfcdb35`, "ospf6d: tighten packet address
checks", 2026-11-02) on master only. **Debian records bookworm, trixie and
forky as vulnerable**; there is no fixed package to install on a stable distro.

## What the patch does (full detail: PATCHES.md in the repo)

- **Destination check** — OSPFv3 packets must go to a link-local address or to
  `ff02::5` / `ff02::6` with hop limit 1. Anything else is dropped.
  `discarding packet with bogus destination`
- **Source check** — the sender must be `fe80::/10`. Anything else is dropped
  and logged. `discarding packet from non-LL source ... faulty neighbor?`

The second check is what closes the CVE: an off-link speaker can no longer form
an adjacency, so it can no longer inject LSAs into the LSDB.

## Verified, not assumed

`TEST-RESULTS.txt` is real output from two network namespaces over a veth pair,
running the **installed** `ospf6d`, with a crafted OSPFv3 Hello:

| Case | Packet | Result |
|---|---|---|
| A | src `2001:db8:1::2` (global, same /64) → `ff02::5`, hlim 1 | 3 discards logged, neighbour table empty — **PASS** |
| B | src `fe80::2` (link-local) → `ff02::5`, hlim 1 | neighbour `10.0.0.2` in `Init` on `v0` — **PASS** |

The hellos are byte-identical apart from the source address, carry correct
RFC 5340 pseudo-header checksums, and `tcpdump` shows both arriving. B is the
control: the daemon still speaks OSPFv3 normally.

## Assets

- `frr-10.9-dev-cve-2026-119776-bookworm-x86_64.tar.xz` — full install tree
  (`usr/sbin` daemons tagged with the CVE, `usr/lib` libfrr + libyang, YANG
  models) plus the upstream source tarball
- `PATCH-cve-2026-119776-ospf6d.patch` — the change alone (+22/−2)
- `frr-92ac4f532632-source.tar.gz` — upstream source, unmodified
- `TEST-RESULTS.txt`, `BUILD-LOG.txt` — the evidence
- `sha256sums.txt` — checksums for every asset

## Install & verify

```bash
sha256sum -c sha256sums.txt
sudo ./install.sh                      # repo file; reads the tarball beside it
strings /usr/sbin/ospf6d-10.9-dev-cve-2026-119776 | grep "non-LL source"
```

Enforce the control-plane ACL as well — the software check is the fix, the ACL
is the belt-and-braces the article argues for.

Source disclosure series: https://owlman.info/article/routing-protocols/frrouting-part-10-the-way-out
