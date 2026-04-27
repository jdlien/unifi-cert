# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-04-27

End-to-end verified against beehive (UniFi OS 5.1.8): `--status`, `--ddns-update`, remote dispatch via `--host`, and the full `--migrate-glennr` cutover all proven on real hardware. Cert intact, GlennR footprint removed, cron-fired `--renew` and `--ddns-update` driving the steady state from the persistent provisioning config.

### Breaking Changes

- **`--renew` now actually runs ACME.** Previous behavior was sync-only: it copied files from `/etc/letsencrypt/live/<domain>/` to the EUS / WebUI paths but never invoked certbot. A cron entry calling the old `--renew` would silently let certs expire. New pipeline: `acquire_lock → load_provisioning_config → self_heal → if is_renewal_due() or --force → run_certbot → install_certificate`. Cron-fired `--renew` (no CLI args) self-configures from `/data/unifi-cert/unifi-cert.conf`.
- **Renewal hook no longer auto-updates `unifi-cert.py` from GitHub by default.** The previous hook ran `curl -sL .../unifi-cert.py -o $SCRIPT && python3 $SCRIPT --renew`, which races against an in-flight script and is the same anti-pattern that broke GlennR's installer. Hook now runs the locally installed script only. Re-enable the download path with `--setup-hook --enable-hook-autoupdate` (refused unless `HOOK_AUTOUPDATE_SHA256` is set in the script; verifies the download against the pin before replacing).

### Added

- **Persistent product root** at `/data/unifi-cert/` (survives UniFi OS firmware wipes): certbot venv, Let's Encrypt state, wheel cache, provisioning config, credentials, log, lock, backups.
- **Certbot bootstrap pipeline** — `--bootstrap` builds/repairs `/data/unifi-cert/certbot-venv` with pinned `certbot` + `certbot-dns-<provider>` from PyPI, caching wheels for offline rebuild after a firmware wipe.
- **`--deploy-hook`** — certbot post-renewal entry. Reads `$RENEWED_LINEAGE` and syncs that lineage to the UniFi platform. No ACME, no bootstrap. Shares the same lock as `--renew` so concurrent invocations serialize cleanly.
- **`--self-heal`** — idempotent repair entry. Ensures venv + cron + hook + boot script are present. Never runs ACME. Used by the boot script and any other automation context.
- **`--migrate-glennr`** — full migration from GlennR's `unifi-easy-encrypt.sh`. Pipeline: `inventory_glennr` → `import_provisioning` → snapshot to `/data/unifi-cert/backups/<ts>.tar.gz` → rsync `/etc/letsencrypt/` → allowlisted uninstall (3 dirs, 3 file globs, 4 specific crons + 1 glob + content-checked `/etc/cron.d/certbot`, 2 hook globs, 4 apt sources) → `self_heal()`. `--dry-run` previews; `--force` skips per-path confirms; `/etc/letsencrypt/` is removed last and only after the migrated lineage is verified at the new path.
- **`--ddns-update`** — refreshes the cert hostname's A record at the DNS provider (DigitalOcean only for v1) using the existing API token. Cron entry at `/etc/cron.d/unifi-cert` runs every 5 minutes; idempotent no-op when the record already matches public IP. Drops the dependency on a third-party DDNS service for users with rotating WAN IPs.
- **`--status`** — one-shot health report: provisioning config, cert metadata + days remaining, certbot venv version, cron / hook / boot script presence, lock state, GlennR-residue scan, last 20 log lines. Pure read-only.
- **`--host` plumbing for lifecycle verbs.** `--status`, `--renew`, `--self-heal`, `--migrate-glennr`, `--ddns-update`, `--bootstrap`, and `--setup-hook` all accept `--host <device>`. The script is SCPed to `/data/scripts/unifi-cert.py` only when local + remote sha256 differ; the verb is then SSH-executed and stdout is forwarded back. `--migrate-glennr --host` requires `--dry-run` or `--force` (no TTY for prompts).
- **Daily cron schedule** at `/etc/cron.d/unifi-cert` invoking `--renew` once a day at 03:17 plus `--ddns-update` every 5 minutes. Installed automatically by the obtain-new flow on local installs.
- **Best-effort boot script** at `/data/on_boot.d/15-unifi-cert.sh` (when `unifi-utilities/on-boot-script` is installed) re-asserts state on every boot via `--self-heal`. No-op with a warning when `/data/on_boot.d/` is absent.
- **Provisioning config** at `/data/unifi-cert/unifi-cert.conf` (mode 0600) — domain, email, DNS provider, credentials path. Persisted by obtain-new; consumed by cron-fired `--renew`.
- **fcntl.flock-based locking** at `/data/unifi-cert/unifi-cert.lock` serializes `--renew` against `--deploy-hook`.
- **Size-based log rotation** — `/data/unifi-cert/unifi-cert.log` is truncated to the last 100 KB once it exceeds 1 MB, preserving record boundaries.

### Changed

- **`main()` refactored to verb-dispatch table.** Per-verb logic now lives in `_handle_<verb>(args)` functions; `main()` runs the shared prep (UI, remote short-circuit, interactive mode, domain auto-detect, validation) and dispatches via `VERB_HANDLERS`. No CLI surface change.

### Fixed

- **UniFi OS 5.x cert-deploy paths.** Removes GlennR's `ssl:` override at `/data/unifi-core/config/overrides/local.yml` (which broke unifi-core's UUID cert lookup on 5.x), ensures nginx serves the active UUID cert, and replaces the Java `unifi-network` PKCS#12 keystore at `/usr/lib/unifi/data/keystore` directly via `openssl pkcs12 -export` (no JDK / keytool / pyjks required).
- **`--migrate-glennr` rsync no longer clobbers a working newer lineage with stale GlennR data.** Caught during the beehive cutover prep: GlennR's `/etc/letsencrypt/archive/<domain>/cert1.pem` and the new tool's `/data/unifi-cert/letsencrypt/archive/<domain>/cert1.pem` share the same relative path, so the original `rsync -aH` would have replaced a valid Apr 27 cert with stale Feb 2 GlennR files. Fix: early-return when `<dst>/live/<domain>/fullchain.pem` already exists; switch the rsync flag to `-aHu` (`--update`) for the partial-state recovery path.
- **`inventory_glennr()` now finds the email even when certbot didn't write it to `renewal/<domain>.conf`** (the common case). Falls back through `~/.secrets/certbot/config.ini` (the v1 user-prefs file) and `/etc/letsencrypt/accounts/*/*/*/regr.json` (certbot's ACME account registration JSON, which records the contact `mailto:`). `--migrate-glennr` also accepts `-d / -e / --dns-provider / --dns-credentials` as inventory overrides for any field the discovery missed.
- **`ensure_script_installed()` no longer re-downloads the script from `main` on every call.** The pre-fix guard `'__file__' in dir()` checked function locals, not module globals, so `current_path` was always `None` and the curl-from-GitHub branch always ran — silently clobbering newly-deployed local scripts (most painfully during `--self-heal` right after a SCP push). Now uses `os.path.abspath(__file__)` with a `NameError` fallback for the genuine stdin/curl-pipe case.

## [1.0.0] - 2025-02-04

### Added

- Initial release of UniFi Certificate Manager
- Dual-path certificate installation (EUS nginx + WebUI PostgreSQL)
- Interactive and non-interactive CLI modes
- DNS validation support for multiple providers:
  - DigitalOcean, Cloudflare, Route53, Google Cloud DNS, Linode, Namecheap, OVH
- Remote installation via SSH/SCP
- Local installation on UniFi devices
- Automatic certbot renewal hook setup
- Certificate metadata extraction via OpenSSL
- Auto-detection of domain from existing certificates
- Persistent configuration for email and DNS provider preferences
- Curl-pipe installation support (`curl ... | python3 -`)

### Fixed

- DNS credential field name bug (GlennR's API returns wrong field names)
- WebUI certificate desync issue (PostgreSQL now updated alongside file installation)

### Technical

- Pure Python stdlib implementation (no external dependencies)
- Single-file design for easy deployment
- Python 3.9+ compatible with explicit UTF-8 encoding for future-proofing
- 95% test coverage

[2.0.0]: https://github.com/jdlien/unifi-cert/releases/tag/v2.0.0
[1.0.0]: https://github.com/jdlien/unifi-cert/releases/tag/v1.0.0
