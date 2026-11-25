# Patches in this build (FRRouting 10.9.0-dev)

This build is FRRouting master at `92ac4f532632`, which contains exactly one
change relevant to CVE-2026-119776:

## Patch matrix

| Patch (CVE) | Commit | What it fixes | Severity | Status here |
|---|---|---|---|---|
| **CVE-2026-119776** | `eaccfcdb35` "ospf6d: tighten packet address checks" (2026-11-02, +22/−2) | OSPFv3 accepts packets from non-link-local sources and to bogus destinations → off-link adjacency, LSA injection | High (remote control-plane) | ✅ Fixed |

No other CVE patches are carried. This is upstream master, not a curated
backport set — anything else that landed in master before `92ac4f532632` is in
the tree too, for better and worse.

## The change

`ospf6d/ospf6_message.c`, in `ospf6_read_helper()`:

```c
-	/* RFC5340:A.1 Ignore multicast with invalid hop limit */
-	if (IN6_IS_ADDR_MULTICAST(&dst) && hoplim != 1)
+	if (IN6_IS_ADDR_LINKLOCAL(&dst)) {
+		/* no further check - LL destination is acceptable */
+	} else if (IPV6_ADDR_SAME(&dst, &allspfrouters6) || IPV6_ADDR_SAME(&dst, &alldrouters6)) {
+		/* RFC5340:A.1 Ignore multicast with invalid hop limit */
+		if (hoplim != 1)
+			return OSPF6_READ_CONTINUE;
+	} else {
+		/* anything else: only for virtual links, not supported yet */
+		if (IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_UNKNOWN, RECV_HDR))
+			zlog_debug("discarding packet with bogus destination %pI6", &dst);
 		return OSPF6_READ_CONTINUE;
+	}
+
+	if (!IN6_IS_ADDR_LINKLOCAL(&src)) {
+		zlog_warn("discarding packet from non-LL source %pI6, faulty neighbor?", &src);
+		return OSPF6_READ_CONTINUE;
+	}
```

Two checks, both RFC 5340 scoping rules that were simply never written:

1. **Destination** must be link-local, or `ff02::5` / `ff02::6` with hop
   limit 1. Anything else (global unicast, other multicast) is dropped.
2. **Source** must be `fe80::/10`. Anything else is dropped and logged —
   this is the one that closes the CVE.

Full patch: `PATCH-cve-2026-119776-ospf6d.patch` (applies to the parent commit
`3215a12809`).

## Why master and not a stable backport

The change is self-contained — 22 added lines in one function, no new state,
no ABI change — so it *could* be backported to any 8.x/9.x/10.x branch. Nobody
has: upstream landed it on master only, and Debian records bookworm, trixie and
forky as vulnerable. There is no fixed package to install on a stable distro.

That makes the honest options:

| Option | Reality |
|---|---|
| Wait for a distro package | **No fix in bookworm/trixie/forky — sid only** |
| Cherry-pick the 22 lines onto your distro's source | Viable, if you build packages yourself |
| Run this master build | Viable, if you accept a dev tree |
| IPv6 control-plane ACL | Effective and free; enforce it regardless |
| OSPFv3 authentication (RFC 7166 / IPsec AH) | Defence in depth, not a substitute |

## Verify this binary carries the fix

```bash
strings frr-release/usr/sbin/ospf6d-10.9-dev-cve-2026-119776 \
  | grep -E "bogus destination|non-LL source"
```

Or run the functional test: `test/test-ospf6d.sh` — an off-link Hello must be
discarded with a `non-LL source` warning, and a link-local Hello must still
form a neighbour. Expected output is in `TEST-RESULTS.txt`.
