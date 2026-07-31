# DDNS: Cloudflare Support — Plan & Post-Mortem

**Status:** code shipped in 2.1.0; Beehive deployed 2026-07-31. Outstanding work below.
**Written:** 2026-07-31, after an all-night incident on `beehive.jdlien.com`
**Owner:** JD

## Where this stands

| | |
| :--- | :--- |
| ✅ Cloudflare DDNS backend | shipped in 2.1.0 |
| ✅ DDNS target decoupled from cert CN | shipped in 2.1.0 |
| ✅ Failure visibility | shipped in 2.1.0 |
| ✅ Tests | 466 passing, 89% coverage |
| ✅ Beehive deployment, steps 1–4 and 6 | 2026-07-31 |
| ❌ **Beehive step 5 — delete the two `cloudflare:` blocks from the UniFi DDNS UI** | **still live; recreates the duplicate on the next IP change** |
| ❌ `bar.rednex.ca` — Option A vs B decision, then rollout | not started |
| ❌ Retire DigitalOcean (`jdlien.com`, `rednex.ca` nameserver moves) | not started |
| ❌ Open decision 4 — external mismatch monitor | not started |
| ⏸ AAAA / IPv6 records | deliberately deferred; see below |

Keep this document until those are done. Past that it still earns its place as the
post-mortem behind the invariants in `CLAUDE.md` — "never create" and "DDNS target is
configured separately from the cert CN" read as arbitrary without the story here — and the
Cloudflare gotchas section is reusable the next time a token misbehaves.

### Beehive, as deployed 2026-07-31

```ini
domain           = beehive.jdlien.com                  # unchanged, ACME via DigitalOcean
ddns_domain      = home.jdlien.ca,*.home.jdlien.ca
ddns_provider    = cloudflare
ddns_credentials = /data/unifi-cert/credentials/cloudflare.ini
```

Verified: normal run is a correct no-op; `--force` edits both records **in place** — record
IDs `620dfff9…` / `6088d3ba…` unchanged, zone still holding exactly three A records, apex
untouched. The prior install had 6,366 consecutive failures and zero successes.

Also cleaned up: `/root/.secrets/certbot/` held a byte-identical duplicate of the live
DigitalOcean token from the April install. Deleted, and `default_credentials_path()` now
defaults to the persistent root on-device so it can't come back.

### IPv6 / AAAA — deferred, and easier than first assessed

Not in 2.1.0. The initial objection — that a public IP-lookup service reports the
*requester's* address rather than the router's — dissolves once you notice the cron job runs
**on the UDM**, so the requester is the device we want to publish. Measured on Beehive:

```
eth9 (WAN): 2001:56a:f8e6:e00:d221:f9ff:fe69:e532/128   ← EUI-64, stable, not a privacy address
br0  (LAN): 2001:56a:f8e6:e00::1/64
```

`curl https://ipv6.my-ip.ca/ip/` from the UDM returns exactly that eth9 address, and the
host is v6-pinned, so the lookup fails cleanly rather than falsely when there's no v6 path.
The record plumbing is nearly free — `_ddns_list_records()` already takes an `rtype`, and
Cloudflare uses `content` for both A and AAAA.

The real blocker is the **inbound IPv6 firewall**. UniFi drops inbound v6 by default, and
clients *prefer* IPv6 when a AAAA exists (RFC 6724). Publishing before the firewall is open
makes the preferred path the broken one — this same outage, with priority. So AAAA needs a
reachability gate before first publish, plus a `ddns_ipv6 = true` opt-in, since adding a
AAAA changes client behaviour.

> **Implementation notes (2026-07-31).** All four work items below are built and
> tested. Four things ended up different from what's written here — each for a
> reason worth keeping:
>
> 1. **Credentials do *not* fall back independently of the provider.** "Each key
>    falls back to the cert value" is unsafe for `ddns_credentials`: handing a
>    DigitalOcean token to Cloudflare's API produces an opaque 401 rather than a
>    diagnosis. The fallback now applies when the provider is unchanged, or when
>    the cert credentials file happens to contain the DDNS provider's field too
>    (a combined file). Otherwise it refuses and names the missing key.
> 2. **Zone resolution probes candidate suffixes rather than listing zones.**
>    Any paged listing has to stop somewhere, and stopping early reports a zone
>    you *do* own as unowned — a false negative wearing a config error's
>    clothing. `GET /zones?name=…` (Cloudflare) and `GET /domains/{name}`
>    (DigitalOcean) have no such boundary. Listing survives only to enrich the
>    "this token sees…" error.
> 3. **`ddns_enabled = false` was added**, because Option B for `bar.rednex.ca`
>    needs a way to turn DDNS off, and hand-deleting the cron line can't stick:
>    `self_heal()` rewrites `CRON_FILE` on every renewal and every boot.
> 4. **Provisioning-time validation is a loud warning, not a refusal.** The
>    certificate is already installed by the time DDNS is checked; failing the
>    install over an unrelated A record would be the wrong trade.
>
> Open decision 2 is answered: `--status` **warns**, it does not hard-fail.
> Open decision 1 is answered: yes, `ddns_domain` takes a list.

---

## TL;DR

`--ddns-update` has never successfully updated a record. Not once. It targets the cert CN
(`beehive.jdlien.com`), which is a **CNAME**, so there is no A record to update — 6,295
consecutive failures in the current log window, zero successes.

Meanwhile the UDM's built-in DDNS (inadyn) was "working" by creating a **duplicate** A
record on every WAN IP change, which is what actually broke remote access to UniFi Protect.

Two fixes are needed here, and the second one matters more than the first:

1. Add a **Cloudflare backend** to the DDNS path (currently DigitalOcean-only).
2. **Decouple the DDNS target from the cert CN** — they are legitimately different records,
   in different zones, at different providers.

Plus: make DDNS failure *visible*, because 6,295 silent failures is its own bug.

---

## What happened

`https://beehive.jdlien.com/protect` stopped loading reliably. Investigation found
`home.jdlien.ca` carrying **two** A records:

| IP | Created | State |
| :--- | :--- | :--- |
| `173.183.229.156` | 2026-03-08 22:18 | stale — port 443 closed |
| `198.53.200.179` | 2026-07-26 16:31 | current WAN IP |

Clients round-robin between them. Each attempt on the dead IP burned a full ~3s connect
timeout before failover — measured 3.02s via DNS versus 0.013s direct. Protect opens
several independent connections (main origin, WebSocket, API), so the stalls compound past
the app's internal timeouts. It presented as "won't load", not "slow", which is why it read
as a total outage rather than a DNS problem.

`2026-07-26` was a power outage. Telus issued a new lease, and the duplicate was born.

**Resolved** by deleting both stale records (`home.jdlien.ca` and `*.home.jdlien.ca`).
Load time went 3.02s → 0.013s. But the *cause* is unfixed — the next reboot with a new IP
recreates it.

---

## Why all three DDNS systems failed

There were three independent updaters running on that box. None of them kept
`home.jdlien.ca` correct.

### 1. inadyn → Cloudflare (UniFi built-in) — creates duplicates

inadyn 2.13.0, config generated by `ubios-udapi-server` at `/run/ddns-eth9-inadyn.conf`.

Its cache stores **only the IP it sent**, never the Cloudflare record ID:

```
/var/cache/inadyn/default@cloudflare.com-home.cache  →  198.53.200.179
--cache-dir=PATH   Persistent cache dir of IP sent to providers
```

So every update re-resolves the record via the API. Evidence says that lookup cannot match
when the IP has changed — the only two duplicate records in the zone were created on the
only two days the WAN IP changed (Mar 8, Jul 26), while 30-day forced refreshes with an
unchanged IP updated correctly the whole time. *(Mechanism inferred from record timestamps
and cache design, not from reading inadyn's source — worth confirming if anyone cares.)*

**It cannot detect this failure.** Cloudflare returns `200 — record created`, inadyn takes
the success and caches the IP:

```
Jul 26 10:31:05  Update forced for alias home, new IP# 198.53.200.179
Jul 26 10:31:09  Updating IPv4 cache for home
```

No error, no warning. There is no config knob to fix this — the behaviour is compiled into
the `cloudflare.com` plugin, and inadyn's `custom` provider (plain GET + basic auth) cannot
express Cloudflare's `PATCH`-with-JSON API.

**Action: delete both `cloudflare:` blocks from the UniFi DDNS UI.**

### 2. inadyn → Dynu (`jdlien.freeddns.org`) — worked perfectly, unused

```
jdlien.freeddns.org  →  198.53.200.179   ✅ correct
```

dyndns2 is a dumb GET where the *provider* replaces the record, so it structurally cannot
duplicate. It has been tracking the WAN IP correctly this entire time. Nothing pointed at
it, so it did nobody any good.

**Action: keep it.** Costs nothing, unreferenced, and it's an independent second path to
find the house when the Cloudflare side breaks. Do *not* make anything depend on it — a
free provider is not a foundation.

### 3. unifi-cert `--ddns-update` — right design, wrong target

The architecture here is correct and is exactly what inadyn gets wrong: resolve zone →
`_ddns_get_a_record` → fetch record ID → `_ddns_put_a_record` → update **by ID**. Never
creates. Idempotent no-op when the record already matches. Cron every 5 minutes.

It has simply never run successfully:

```
✗ No A record found for beehive.jdlien.com; create it first in the DigitalOcean web UI.

failures in current log : 6,295
successful updates ever :     0
```

`beehive.jdlien.com` is a CNAME to `home.jdlien.ca`. There is no A record at that name and
never was. At 5-minute intervals that's ~22 days in the current window; the log rotates at
1 MB, so this likely dates to the April install.

---

## Current state of the world

Concrete facts so the next session doesn't have to re-derive them.

### DNS topology

```
beehive.jdlien.com   CNAME → home.jdlien.ca      (jdlien.com zone → DigitalOcean NS)
home.jdlien.ca       A     → <WAN IP>            (jdlien.ca  zone → Cloudflare NS)
*.home.jdlien.ca     A     → <WAN IP>
jdlien.freeddns.org  A     → <WAN IP>            (Dynu, updated by inadyn, unreferenced)
```

- `jdlien.ca` zone ID: `f625a1d7dbb0228633c5273a1a66ea4c`
- `jdlien.com` nameservers: `ns{1,2,3}.digitalocean.com`
- `jdlien.ca` nameservers: `isla` / `marty.ns.cloudflare.com`
- Records are DNS-only (grey cloud), not proxied

**The DDNS anchor is `home.jdlien.ca`, on Cloudflare. The cert CN is `beehive.jdlien.com`,
on DigitalOcean.** That mismatch is the whole bug.

### Second site — dad's business (`bar.rednex.ca`)

Same trap, different shape. Verified 2026-07-31:

```
bar.rednex.ca        CNAME → rednex.freeddns.org   (rednex.ca zone → DigitalOcean NS)  TTL 300
rednex.freeddns.org  A     → 173.183.167.214       (Dynu)                              TTL 120
```

- `rednex.ca` nameservers: `ns{1,2,3}.digitalocean.com`
- The cert CN (`bar.rednex.ca`) is **also a CNAME**, so `--ddns-update` on that UDM is
  expected to be failing identically — `No A record found for bar.rednex.ca`, every 5
  minutes. Confirm against its log before changing anything.
- That site's DDNS is carried entirely by **Dynu**, which is working. Nothing is currently
  broken there; it's just unmonitored and one free-tier policy change from breaking.

This host is the stated blocker on retiring DigitalOcean, so it drives the migration plan
below rather than being an afterthought.

### unifi-cert on Beehive (192.168.1.1)

```
script    : /data/scripts/unifi-cert.py
root      : /data/unifi-cert/
creds     : /data/unifi-cert/credentials/digitalocean.ini   (no cloudflare.ini yet)
cron      : 17 3 * * *   --renew
            */5 * * * *  --ddns-update
```

```ini
# /data/unifi-cert/unifi-cert.conf
domain = beehive.jdlien.com
email = jd@jdlien.com
dns_provider = digitalocean
dns_credentials = /data/unifi-cert/credentials/digitalocean.ini
```

Cert: `CN=beehive.jdlien.com`, Let's Encrypt, valid to **2026-09-25**. ACME via DigitalOcean
DNS-01 — that part works and is not in scope.

---

## What to build

### 1. Cloudflare DDNS backend

`DNS_PROVIDERS['cloudflare']` already exists for ACME with the right field name
(`dns_cloudflare_api_token`), so `_ddns_extract_token` needs no special-casing. The work is
parameterizing the four request helpers and dropping the `!= 'digitalocean'` guard in
`ddns_update()`.

| Step | DigitalOcean | Cloudflare |
| :--- | :--- | :--- |
| base | `https://api.digitalocean.com/v2` | `https://api.cloudflare.com/client/v4` |
| zone resolve | `GET /domains`, suffix-match | `GET /zones?name=<zone>` → `result[0].id` |
| find A record | `GET /domains/{zone}/records?type=A&name={host}` | `GET /zones/{zid}/dns_records?type=A&name={fqdn}` |
| update | `PUT …/records/{id}` `{"data": ip}` | `PATCH …/dns_records/{id}` `{"content": ip}` |
| auth | `Authorization: Bearer <token>` | `Authorization: Bearer <token>` |
| success shape | record object | `{"success": true, "result": {...}}` |

Both use bearer auth and JSON, so `_ddns_request` mostly needs a provider-aware base URL
plus a response-envelope unwrap for Cloudflare's `{success, result, errors}` wrapper.

**Keep the never-create invariant.** If the record is missing, error out and say so — do not
POST. That refusal is the entire reason this tool is better than inadyn, and it's what makes
it safe to run every 5 minutes.

Handle the wildcard (`*.home.jdlien.ca`). Cloudflare accepts `*` in the `name` query
parameter, but it must be URL-encoded.

### 2. Decouple the DDNS target from the cert CN

The more important half. Today `ddns_update()` derives its target from `domain`, which
conflates two genuinely separate things.

Add optional provisioning keys, each falling back to the cert value when absent so existing
installs are unaffected:

```ini
domain           = beehive.jdlien.com          # cert CN, ACME
dns_provider     = digitalocean                # ACME DNS-01 provider
dns_credentials  = /data/unifi-cert/credentials/digitalocean.ini

ddns_enabled     = true                        # NEW — false omits the cron line
ddns_domain      = home.jdlien.ca,*.home.jdlien.ca   # NEW — list; falls back to `domain`
ddns_provider    = cloudflare                  # NEW — falls back to `dns_provider`
ddns_credentials = …/credentials/cloudflare.ini  # NEW — see note 1 above
```

`ddns_domain` takes a comma-separated list, since `home` and `*.home` both need updating.

**Validate at provisioning time.** If `ddns_domain` resolves to a CNAME rather than an A
record, refuse and say why. That single check would have caught this in April instead of
July.

### 3. Make failure visible

6,295 silent failures ran for months. Fix the observability, not just the bug:

- Track last-success timestamp and consecutive-failure count in the provisioning root
- Surface both in `--status`
- Escalate log level once failures exceed a threshold — the same message 6,295 times is
  indistinguishable from noise
- Consider a `--status` warning when the target resolves to more than one A record; that's
  the exact fingerprint of the inadyn duplicate bug and worth detecting even after inadyn
  is gone

### 4. Tests

Repo is at 88% coverage; don't regress it. Cover: Cloudflare zone resolve, record lookup
hit/miss, update-by-ID, the envelope unwrap, the never-create refusal, and the
ddns_*-falls-back-to-cert-values config logic.

---

## Deployment

### Beehive (192.168.1.1)

1. Create a Cloudflare **User** API token, `Zone:DNS:Edit` + `Zone:Zone:Read` on `jdlien.ca`
2. Write `/data/unifi-cert/credentials/cloudflare.ini` with `dns_cloudflare_api_token = …`, mode 0600
3. Add the `ddns_*` keys to `unifi-cert.conf`
4. Deploy the new script, run `--ddns-update` manually, confirm a real success line
5. **Delete both `cloudflare:` blocks from the UniFi DDNS UI** — leave the Dynu entry
6. Confirm `home.jdlien.ca` still has exactly one A record after a forced update

### Dad's UDM Pro — `bar.rednex.ca` (business site)

This is the site that unblocks retiring DigitalOcean, and it needs a decision before code
ships. Two viable end states:

**Option A — migrate `rednex.ca` to Cloudflare (recommended).**
Move the zone, then replace the CNAME with a direct A record:

```
bar.rednex.ca   A → <his WAN IP>     updated by unifi-cert via Cloudflare
```

Drops DigitalOcean *and* Dynu from that site in one move, removes the CNAME indirection
that caused this whole class of bug, and lets the cert CN and DDNS target be the same
record — so the `ddns_*` keys aren't even needed there. Requires the Cloudflare backend to
exist first, which is exactly the work below.

**Option B — keep `rednex.ca` on DigitalOcean.**
Then he needs the `ddns_*` decoupling too, pointing at `rednex.freeddns.org`… which
unifi-cert can't update (Dynu isn't a supported provider and shouldn't become one). In
practice that means leaving Dynu to do the job and disabling `--ddns-update` on his box to
stop the log spam. Workable, but it keeps a free-tier provider load-bearing at a business.

**Recommend A.** It's the reason to do this work at all.

Rollout notes either way:

- Separate Cloudflare token scoped to *his* zone only — never reuse Beehive's
- Confirm his `--ddns-update` failure mode in `/data/unifi-cert/unifi-cert.log` first, so
  there's a before/after
- Check whether his UDM also runs UniFi's built-in Cloudflare DDNS; if so it carries the
  same duplicate bug and should be removed at the same time
- Business site — schedule the nameserver cutover deliberately, and pre-lower TTLs
- Remote deploy via `--host` is already supported and SCPs only when the sha256 differs

---

## Follow-on: retire DigitalOcean entirely

DigitalOcean is only in this picture out of inertia — specifically, because unifi-cert's
DDNS path never learned Cloudflare. Two zones are affected:

| Zone | Current NS | After |
| :--- | :--- | :--- |
| `jdlien.com` | DigitalOcean | Cloudflare — `beehive.jdlien.com` becomes a direct A record |
| `rednex.ca` | DigitalOcean | Cloudflare — `bar.rednex.ca` becomes a direct A record |

Both migrations do the same two things: collapse to one provider (one token type, one API,
one set of gotchas), and **eliminate the CNAME indirection** that made the cert CN
un-updatable. After both, `domain` and `ddns_domain` are the same record at both sites, the
`ddns_*` fallback covers everything, and Dynu drops out of the critical path entirely.

Sequencing matters: **the Cloudflare backend must ship first**, since neither zone can move
until unifi-cert can update records there. Do the code, prove it on Beehive, then migrate
`jdlien.com`, then `rednex.ca` last — it's a business site and deserves the most-tested
version of the pipeline.

The nameserver moves themselves stay **out of scope** for the DDNS work. Pre-lower TTLs,
schedule deliberately, do it rested.

---

## Cloudflare API gotchas learned the hard way

Tonight cost several hours to these. Worth encoding in the tool.

**Two separate token stores.** *User* tokens live under My Profile → API Tokens; *Account*
tokens under Manage account → Account API tokens. Different lists, easily confused. The
prefix tells you which: **`cfut_` = User, `cfat_` = Account.**

**Verify against the matching namespace.** `GET /client/v4/user/tokens/verify` only resolves
User tokens. An Account token checked there returns a generic `1000 Invalid API Token`,
which reads as "revoked" but only means "wrong namespace". Use
`GET /client/v4/accounts/{account_id}/tokens/verify` for `cfat_` tokens — **and prefer a
functional probe** (`GET /zones`) over any verify endpoint, since a real call also catches
IP-allowlist and permission-scope failures that verify does not.

**Creating a token does not revoke the old one.** Only *Roll* (same token ID, new secret) or
*Delete* does. A rolled token keeps its ID, which is how you confirm you rolled the right row.

**IP allowlists fail closed and silently.** A token restricted to specific IPs returns
`Invalid API Token` from anywhere else — it will not tell you the IP is the problem. Check
egress with `curl https://cloudflare.com/cdn-cgi/trace`, and remember curl prefers IPv6 when
available, so both families need allowlisting.

**A token being valid does not mean it can do the job.** Read-only tokens verify happily and
then 401 on write. `Zone DNS Settings Read` is not `Zone DNS Edit`.

---

## Open decisions

1. Should `ddns_domain` accept a list, so `home` and `*.home` are both maintained? (Leaning
   yes — the wildcard has the same duplicate exposure.)
2. Should `--status` hard-fail when the DDNS target is a CNAME, or just warn?
3. ~~Does dad's UDM need the `ddns_*` decoupling?~~ **Answered:** `bar.rednex.ca` is a CNAME
   to `rednex.freeddns.org`, so today yes. But if `rednex.ca` migrates to Cloudflare
   (Option A above), the CNAME disappears and the fallback covers him — which is a good
   argument for migrating rather than configuring around it.
4. Add the external mismatch monitor (`dig` vs actual WAN IP, alert on mismatch *or* on >1 A
   record) to night-watchman on the DO box — independent of this tool, catches the failure
   class no self-reporting updater can. Should cover both sites, not just Beehive.
5. ~~Is `173.183.167.214` actually dad's current WAN IP?~~ **Answered 2026-07-31: yes.**
   `443` is open and serves a valid Let's Encrypt cert for `CN=bar.rednex.ca`
   (Jun 28 → Sep 26 2026). Dynu is tracking correctly and that site is healthy today —
   the concern there is dependency risk, not a live fault. No urgency; migrate deliberately.
