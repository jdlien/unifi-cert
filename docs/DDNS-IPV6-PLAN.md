# DDNS: IPv6 — Plan

**Status:** planned, not started. Tracked in `.taskmaster/tasks/tasks.json` (tasks 1 and 2).
**Written:** 2026-09-30
**Owner:** JD

## Two different features

"IPv6 DDNS" means two things here, and they don't share a design:

| | **A. The router's AAAA** | **B. The LAN's prefix** |
| :--- | :--- | :--- |
| Publishes | the UDM's own WAN address | the /64 its LAN clients get addresses from |
| Record | AAAA on the DDNS name | TXT on a name of its own (below) |
| For | reaching the router over IPv6 | apps asking "is this client on the site's network?" |
| Blocker | inbound IPv6 firewall | none in unifi-cert; needs a consumer that reads it |
| Status | designed, deferred (`DDNS-CLOUDFLARE-PLAN.md`) | this document |

**A** is designed in `DDNS-CLOUDFLARE-PLAN.md` → "IPv6 / AAAA — deferred": a v6-pinned
lookup from the UDM, a reachability gate before the first publish, and a `ddns_ipv6 = true`
opt-in. Nothing here changes that.

**B** is new. With IPv4, a whole site shares one NAT'd address, so "the client's address
equals the DDNS name's A record" means "the client is on the site's network". Apps rely on
that: one admits a shared device to sign in by PIN only from the site's own connection. Over
IPv6 there is no NAT. Every client has its own addresses, usually privacy addresses that
change daily, so the router's address (feature A) never matches a client. What is shared is
the network's prefix. An app that wants its own hostname reachable over IPv6 without breaking
that check needs the prefix published, and that's this feature.

## Where the prefix comes from

**From the router's LAN interface, never from a lookup service.** A what's-my-address
service sees the router's WAN address, which is feature A's value, not B's. The bridge the
clients sit on already carries the prefix. Measured on a UDM with Telus prefix delegation
(`DDNS-CLOUDFLARE-PLAN.md`):

```
br0  (LAN): 2001:db8:1234:5600::1/64
```

```sh
ip -6 -o addr show dev br0 scope global
```

Its network (`ipaddress.IPv6Interface(...).network`) is the value. That means no TLS, no
third party and no on-path rewrite. Skip addresses flagged `deprecated` or `tentative`.
During ISP renumbering the old prefix stays on the interface, deprecated, beside the new one.

## Record shape

**A TXT record on a name of its own**, holding the prefix in CIDR form:

```
_lan6.example.com.  120  IN  TXT  "2001:db8:1234:5600::/64"
```

- **Not a AAAA on the DDNS name.** A AAAA tells clients to connect there, and clients prefer
  IPv6 (RFC 6724). A prefix's `::` isn't a host, so everything that connects to the name,
  the router's UI and a VPN among them, would try a dead address first.
- **Not a AAAA on a separate name.** It would work, but the prefix length would be implied
  by convention. A TXT says it, and nothing ever connects to a TXT.
- **More than one prefix** (two networks, or renumbering): space-separated CIDRs in one
  value. *Open question:* publish each non-deprecated prefix, or only the newest?

## Invariants it must keep

- **Never create.** The TXT is created by hand once; the updater finds it and edits it by ID,
  and a missing record is an error, as for the A record (`CLAUDE.md`).
- **Opt-in, per device, with no fallback.** The A record's `ddns_domain` falls back to the
  cert CN, and two devices behind one router may both update it safely, because they see the
  same WAN address. **That argument doesn't hold for prefixes:** each network has its own
  /64, so a second device on another VLAN would publish a different value to the same record
  and flap it every five minutes. So the record name and interface must both be set
  explicitly (`ddns_lan6_name`, `ddns_lan6_interface`), nothing defaults them, and only the
  router should have them.
- **Validate before publishing**, like `is_public_ipv4()`: a global unicast IPv6 network
  (`is_global`, which excludes ULA `fc00::/7`, link-local and `2001:db8::/32`), prefix length
  64. Anything else is an error, never written.
- **No prefix means say so, not keep the old one.** When the interface has no valid global
  prefix (IPv6 off, delegation lost), write `none` and report it as a failure. ISPs reassign
  prefixes, so a stale one can later belong to someone else's network, and a consumer would
  count that network as the site.
- **Failures escalate on their own key** in `DDNS_STATE_FILE` (e.g. `_lan6.example.com/TXT`),
  so `--status` shows the prefix and the A record separately.

## Work

1. `get_lan_prefixes(interface)`: parse `ip -6 -o addr`, drop deprecated and tentative,
   validate, return CIDRs.
2. Generalize `_ddns_get_a_record()` / `_ddns_put_a_record()` to a record type.
   `_ddns_list_records()` already takes `rtype`. Check how Cloudflare round-trips a TXT
   `content` (quoting) before comparing it for the idempotent no-op, or every run will
   rewrite it.
3. Config keys, `--ddns-update` writing both records, the `none` sentinel, and `--status`
   showing the interface's prefix beside the published one.
4. Tests: `ip` output fixtures (one prefix, renumbering with a deprecated prefix, ULA only,
   no IPv6), validation, never-create (missing TXT is an error, no POST), the no-op, the
   sentinel.
5. README "DDNS Auto-Refresh" and `CLAUDE.md`'s invariants.

## The consumer's side

What an app does with it, so the record's format is the contract:

- Resolve the TXT; split on spaces; `none` or no record means the site has no IPv6 network,
  so fall back to IPv4 alone.
- A client address matches if it's inside any published prefix.
- Keep the last good answer through a failed lookup, as for the A record, but believe `none`.
- Give the app's own hostname an AAAA only after the prefix has been published and matched
  end to end. Before that, an AAAA silently moves IPv6 clients outside the check.

## Before building

Confirm the site has IPv6 at all: a global address on the WAN, a delegated prefix, the LAN
set to prefix delegation, and which bridge the shared devices actually join.
