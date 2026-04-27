# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Lifecycle-ownership branch. Targeting 2.0.0. Not yet exercised on a real UDM Pro end-to-end — Step 8 of the lifecycle plan is the beehive cutover.

### Breaking Changes

- **`--renew` now actually runs ACME.** Previous behavior was sync-only: it copied files from `/etc/letsencrypt/live/<domain>/` to the EUS / WebUI paths but never invoked certbot. A cron entry calling the old `--renew` would silently let certs expire. New pipeline: `acquire_lock → load_provisioning_config → self_heal → if is_renewal_due() or --force → run_certbot → install_certificate`. Cron-fired `--renew` (no CLI args) self-configures from `/data/unifi-cert/unifi-cert.conf`.
- **Renewal hook no longer auto-updates `unifi-cert.py` from GitHub by default.** The previous hook ran `curl -sL .../unifi-cert.py -o $SCRIPT && python3 $SCRIPT --renew`, which races against an in-flight script and is the same anti-pattern that broke GlennR's installer. Hook now runs the locally installed script only. Re-enable the download path with `--setup-hook --enable-hook-autoupdate` (refused unless `HOOK_AUTOUPDATE_SHA256` is set in the script; verifies the download against the pin before replacing).

### Added

- **Persistent product root** at `/data/unifi-cert/` (survives UniFi OS firmware wipes): certbot venv, Let's Encrypt state, wheel cache, provisioning config, credentials, log, lock, backups.
- **Certbot bootstrap pipeline** — `--bootstrap` builds/repairs `/data/unifi-cert/certbot-venv` with pinned `certbot` + `certbot-dns-<provider>` from PyPI, caching wheels for offline rebuild after a firmware wipe.
- **`--deploy-hook`** — certbot post-renewal entry. Reads `$RENEWED_LINEAGE` and syncs that lineage to the UniFi platform. No ACME, no bootstrap. Shares the same lock as `--renew` so concurrent invocations serialize cleanly.
- **`--self-heal`** — idempotent repair entry. Ensures venv + cron + hook + boot script are present. Never runs ACME. Used by the boot script and any other automation context.
- **Daily cron schedule** at `/etc/cron.d/unifi-cert` invoking `--renew` once a day. Installed automatically by the obtain-new flow on local installs.
- **Best-effort boot script** at `/data/on_boot.d/15-unifi-cert.sh` (when `unifi-utilities/on-boot-script` is installed) re-asserts state on every boot via `--self-heal`. No-op with a warning when `/data/on_boot.d/` is absent.
- **Provisioning config** at `/data/unifi-cert/unifi-cert.conf` (mode 0600) — domain, email, DNS provider, credentials path. Persisted by obtain-new; consumed by cron-fired `--renew`.
- **fcntl.flock-based locking** at `/data/unifi-cert/unifi-cert.lock` serializes `--renew` against `--deploy-hook`.
- **Size-based log rotation** — `/data/unifi-cert/unifi-cert.log` is truncated to the last 100 KB once it exceeds 1 MB, preserving record boundaries.

### Fixed

- **UniFi OS 5.x cert-deploy paths.** Removes GlennR's `ssl:` override at `/data/unifi-core/config/overrides/local.yml` (which broke unifi-core's UUID cert lookup on 5.x), ensures nginx serves the active UUID cert, and replaces the Java `unifi-network` PKCS#12 keystore at `/usr/lib/unifi/data/keystore` directly via `openssl pkcs12 -export` (no JDK / keytool / pyjks required).

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

[1.0.0]: https://github.com/jdlien/unifi-cert/releases/tag/v1.0.0
