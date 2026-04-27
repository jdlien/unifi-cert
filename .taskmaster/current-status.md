# unifi-cert — current status

**Released:** v2.0.0 (2026-04-27). Tag pushed, `main` is at the v2 head, `curl -sL jdlien.com/unifi-cert | python3 -` serves v2.
**Phase:** monitoring. No active work.

## Recent shipped commits (top of `main`)

```
f220075 fix(ui): point 'Verify by visiting' at cert CN, not localhost
4d672ed fix(ui): drop duplicate program header in interactive_mode
e747c55 docs(readme): expand Features list + GlennR-migration callout + --status-led troubleshooting
1af8dea docs(changelog): pin 2.0.0 release date + cutover bug fixes
a13c037 fix(install): never re-download script when running from PERMANENT_SCRIPT_PATH
ed303fc fix(migrate): widen email inventory + accept CLI overrides
10a79f7 fix(migrate): skip /etc/letsencrypt rsync when dest already owns the lineage
6433490 refactor(main)+docs: verb-dispatch table + finalize 2.0.0 docs
41c5de3 feat(status): add --status verb + --host plumbing for remote verbs
a602b5c feat(ddns): keep DigitalOcean A-record fresh via existing API token
d8b8c5f feat(migrate): add --migrate-glennr to import + uninstall GlennR's footprint
```

Tests: `pytest -q` → 338 passed at 88% coverage.

## Beehive: shipped state

- Cert valid through **Jul 26 2026** (issued Apr 27, 89 days remaining at ship).
- Provisioning persisted under `/data/unifi-cert/unifi-cert.conf`: domain=beehive.jdlien.com, email=jd@jdlien.com, dns_provider=digitalocean, dns_credentials=/data/unifi-cert/credentials/digitalocean.ini.
- Cron `/etc/cron.d/unifi-cert`: daily `--renew` at 03:17 + `--ddns-update` every 5 min.
- Renewal hook installed; GlennR residue zero; snapshot tarball at `/data/unifi-cert/backups/20260427T225547Z.tar.gz` for any future rollback.

## Burn-in test (firmware-wipe simulation, 2026-04-27 17:24)

- Wiped: `certbot-venv/`, `/etc/cron.d/unifi-cert`, post-renewal hook
- `--status` correctly flagged all three as missing
- `--self-heal --host beehive.jdlien.com`: 27.8s to rebuild the venv from cached wheels (`/data/unifi-cert/wheels/`, 24 wheels @ 6.2 MB), reinstall cron + hook, exit clean
- Rebuilt certbot reports `4.2.0` and `certbot certificates` finds the existing lineage intact
- nginx + unifi-core never restarted; port 443 stayed up throughout — blast radius was exactly the renewal plumbing, as designed

## Bugs caught + fixed during ship (all on `main`)

1. **`_rsync_etc_letsencrypt`** — would have clobbered a working newer lineage with stale GlennR data. Now early-returns when dest fullchain.pem exists; uses `-aHu` for partial-state recovery.
2. **`inventory_glennr` email gap** — certbot doesn't write `email` to `renewal/<domain>.conf`. Now falls back through `~/.secrets/certbot/config.ini` and `accounts/*/regr.json`.
3. **`ensure_script_installed`** — `'__file__' in dir()` checked function locals, not module globals. Every `--self-heal` was silently re-downloading main-branch HEAD. Fixed via `os.path.abspath(__file__)` with `NameError` fallback.
4. **Duplicate program header** in interactive curl-pipe sessions (main() + interactive_mode() both printed it).
5. **"Verify by visiting https://localhost"** — meaningless on a headless device. Now uses `args.host` (workstation flow) → `args.domain` (cert CN) → generic fallback.

## Next-on-the-clock checkpoint

The first real cron-fired `--renew` will be when the cert hits 30 days, around **2026-06-26**. That firing will:
- acquire the lock, run `self_heal()` (idempotent), call `is_renewal_due()` → True, call `run_certbot()` for ACME renewal via DigitalOcean DNS-01, then `install_certificate()` to sync EUS + WebUI + keystore.

Worth scheduling a one-shot agent ~Jun 27 to verify the firing actually happened, the cert got rotated, and `--status` looks healthy. (Optional — the renewal is a no-op for ~60 days.)

## Resume entry point

In a fresh session: `/statusresume` reads this file. Sanity:
- `git log --oneline -5 main` → top is `f220075`
- `python3 -m pytest -q` → 338 passed
- `python3 unifi-cert.py --status --host beehive.jdlien.com` → healthy report
- `gh release view v2.0.0` → shipped release notes (after Task #15 lands)
