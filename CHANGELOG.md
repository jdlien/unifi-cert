# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.1] - 2026-04-28

End-to-end verified against bar (UDM Pro SE) + the Rednex NVR (UNVR). Eight migration-flow + remote-dispatch bugs uncovered during back-to-back GlennR cutovers and fixed at the source. Both hosts now on a single canonical lineage with a fresh LE cert; future installs should run end-to-end with no manual sed-and-rename.

### Fixed

- **`run_certbot()` now passes `--cert-name <domain>` to certbot.** Without this, any drift between the migrated `renewal/<domain>.conf` flags and the current CLI flags makes certbot fork to `<domain>-0001` instead of refreshing the existing lineage. The script then syncs the *old* lineage and the device keeps serving the about-to-expire cert. `--cert-name` pins the lineage by name in both the obtain-new and renew code paths.
- **`migrate_glennr()` strips the GlennR post-renewal hook references the rsync brought along.** The rsync of `/etc/letsencrypt/` carries `(pre|post)_hook = .../EUS_<domain>.sh` lines in `renewal/<domain>.conf` plus the `renewal-hooks/{pre,post}/EUS_*.sh` scripts themselves. Once `/srv/EUS` is uninstalled, every renewal bombs the hook with `/srv/EUS/temp_file: No such file or directory`. New `_purge_glennr_residue_in_lineage()` removes both byte-by-byte after the rsync.
- **`migrate_glennr()` rewrites legacy `/etc/letsencrypt/*` paths in the migrated `renewal/<domain>.conf`.** The rsync preserves absolute path fields verbatim (`archive_dir`, `cert`, `privkey`, `chain`, `fullchain`), so once `/etc/letsencrypt/` is removed in step 6 of the migration, certbot reads stale paths, decides the lineage is missing, and forks to `<domain>-0001` despite `--cert-name`. New `_normalize_renewal_paths_in_lineage()` rewrites these prefixes to `CERTBOT_CONFIG_DIR/`. Also rewrites `dns_<provider>_credentials` to the canonical `CREDENTIALS_DIR/<provider>.ini` when the original path is outside the persistent root.
- **`migrate_glennr()` dedupes orphaned Let's Encrypt accounts.** A partially-failed earlier install can leave an unreferenced account under `accounts/<server>/directory/<id>/`; certbot then refuses to run non-interactively (`Please choose an account`). New `_dedupe_le_accounts()` removes account directories not referenced by any `account = <id>` line in the migrated renewal configs. No-op when no accounts are referenced (defense against deleting blind).
- **`_rsync_etc_letsencrypt()` falls back to `shutil.copytree(symlinks=True, dirs_exist_ok=True)` when `rsync` isn't installed.** Stock UDM Pro SE images don't ship rsync, so the migration was hard-aborting with bare `Errno 2`. The fallback preserves the `live/` → `archive/` symlink farm via `symlinks=True`. Pure stdlib, Python 3.8+ compatible.
- **`run_remote()` and `scp_file()` now multiplex SSH connections via `ControlMaster` / `ControlPath` / `ControlPersist`.** Without this, `dispatch_remote_verb()`'s 2-4 quick sub-sessions per call (sha256 compare, scp, chmod, run) trip IDS rate-limit signatures like Suricata SID 2001219 (`ET SCAN Potential SSH Scan`) which is enabled by default in UniFi CyberSecure. The IDS silently drops the burst and the box appears unreachable. Multiplexing collapses the connections into one TCP+TLS session from the wire's POV, pre-empting the trigger entirely without touching the IDS config.
- **`import_provisioning_from_glennr()` defaults the saved `dns_credentials` field to `CREDENTIALS_DIR/<provider>.ini` when the GlennR-referenced source file is missing.** Previous behavior preserved the dangling source path (e.g. `/root/.secrets/digitalocean.ini`), trapping users with a stale reference that broke renewals weeks later. The new default + a loud warning give users a straightforward "drop the file here" recovery path.
- **`ensure_remote_script()`'s `chmod failed on <host>` warning is gone in practice.** It was the 4th back-to-back SSH connection in the dispatch flow, getting rate-limit-dropped by the IDS in the same way as above. Resolved as a side-effect of the multiplexing fix; no separate code change required.

### Tests

- 350 → 357 collected (`+9` net: argv assertions for `--cert-name`, the rsync→copytree fallback, ControlMaster flag presence in `ssh`/`scp` argv, path-normalization helper coverage, account-dedupe coverage, and migrate-flow ordering with the new helper). 88% coverage maintained.

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

[2.0.1]: https://github.com/jdlien/unifi-cert/releases/tag/v2.0.1
[2.0.0]: https://github.com/jdlien/unifi-cert/releases/tag/v2.0.0
[1.0.0]: https://github.com/jdlien/unifi-cert/releases/tag/v1.0.0
