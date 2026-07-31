# UniFi Certificate Manager - Development Guidelines

## Project Origins & Mission

This tool replaces GlennR's 6000-line `unifi-easy-encrypt.sh` bash script with a clean, maintainable Python implementation.

### Problems Solved

1. **DNS Credential Bug**: GlennR's API returns wrong field name (`DO_AUTH_TOKEN` instead of `dns_digitalocean_token`)
2. **WebUI Desync**: Original script updates cert files but not PostgreSQL, so WebUI shows stale cert info
3. **External Dependencies**: Original relies on `api.glennr.nl` for geo lookup, DNS validation, version checks
4. **Maintainability**: 6000-line bash is unwieldy; Python is testable and readable

### Design Principles

- **Single file**: `unifi-cert.py` should remain a single file for curl-pipe installation
- **Pure stdlib**: No external dependencies (no requests, no rich) - maximum compatibility
- **Dual-path installation**: Always update both EUS certs (nginx) AND WebUI certs (PostgreSQL)
- **Remote-first**: Designed to run from a workstation and SSH to UniFi devices

## Architecture

```
unifi-cert.py (~3500 lines, 88% test coverage)
├── CONFIGURATION         - DNS providers, paths, constants (incl. UNIFI_CERT_ROOT)
├── UI LAYER              - ANSI colors, spinners, prompts
├── CERTIFICATE META      - OpenSSL metadata extraction
├── IP LOOKUP             - Multi-provider fallback (powers --ddns-update)
├── CONFIG FILE           - User prefs + provisioning config (/data/unifi-cert/unifi-cert.conf)
├── DNS CREDENTIALS       - Validation and creation
├── UNIFI PLATFORM        - Device detection
├── GLENNR MIGRATION      - inventory_glennr() + migrate_glennr() (--migrate-glennr)
├── CERT INSTALLATION     - Local installation logic (incl. UniFi OS 5.x keystore + override)
├── CERTBOT               - Let's Encrypt integration
├── CERTBOT BOOTSTRAP     - Persistent venv + apt prereqs (firmware-wipe survival)
├── SCHEDULE & SELF-HEAL  - cron, boot script, lock, log rotation, renewal-due, self_heal()
├── DDNS                  - A-record auto-refresh, DigitalOcean + Cloudflare (--ddns-update)
├── HOOK                  - certbot post-renewal hook + opt-in pinned autoupdate
├── STATUS                - print_status() composes a one-shot health report
├── REMOTE SSH            - SSH/SCP + dispatch_remote_verb() (--host plumbing)
├── VERB HANDLERS         - one _handle_<verb>() per CLI verb; VERB_HANDLERS table
└── CLI & MAIN            - Argument parsing, interactive mode, verb dispatch
```

## Persistent Root

Everything that needs to survive UniFi OS firmware updates lives under `/data/unifi-cert/`:

```
/data/unifi-cert/
├── unifi-cert.conf      # provisioning config (domain, email, dns provider, creds path, ddns_*)
├── unifi-cert.log       # main log (rotated >1 MB, keep last 100 KB)
├── ddns-state.json      # per-target last success / failure streak / duplicate count
├── unifi-cert.lock      # fcntl.flock — serializes --renew vs --deploy-hook
├── credentials/         # DNS provider credentials (mode 0600)
├── letsencrypt/         # certbot --config-dir (accounts, archive, live, renewal)
├── certbot-venv/        # python -m venv target; CERTBOT_BIN points here
├── wheels/              # pip-cached wheels for offline rebuild
├── work/                # certbot --work-dir
├── logs/                # certbot --logs-dir
└── backups/<ts>/        # GlennR snapshots (Step 5)
```

The script itself stays at `/data/scripts/unifi-cert.py` — that path is referenced by cron and the renewal hook.

## Verbs (mutually exclusive)

Each verb has a `_handle_<verb>(args) -> int` function; `main()` dispatches via the `VERB_HANDLERS` table after the shared prep (UI, `--host` short-circuit, interactive mode, domain auto-detect, validation).

| Verb | Purpose | `--host` |
|---|---|:---:|
| (default, no flags) | obtain-new: bootstrap → certbot → install → cron + hook + provisioning save | yes |
| `--renew` | cron entry. lock → load provisioning → self_heal → ACME-if-due → install | yes |
| `--deploy-hook` | certbot post-renewal entry. Reads `$RENEWED_LINEAGE`, syncs that lineage. No ACME. | no |
| `--self-heal` | idempotent repair (venv + cron + hook + boot). Never runs ACME. | yes |
| `--install` | install an existing cert/key pair (local or `--host`) | yes (separate path: SCP cert+key) |
| `--setup-hook` | rewrite the renewal hook (use `--enable-hook-autoupdate` for opt-in autoupdate) | yes |
| `--bootstrap` | build/repair `/data/unifi-cert/certbot-venv` and exit | yes |
| `--migrate-glennr` | import GlennR provisioning + uninstall its footprint | yes (requires `--dry-run` or `--force`) |
| `--ddns-update` | refresh the DDNS target A record(s); cron-fired every 5 min | yes |
| `--status` | read-only health report (cert, certbot venv, cron, hook, GlennR residue, log tail) | yes |

### `--host` plumbing

`dispatch_remote_verb()` SCPs `unifi-cert.py` to `/data/scripts/unifi-cert.py` only when local + remote sha256 differ (`ensure_remote_script()` does the compare via `sha256sum` over SSH), then SSH-executes the verb with the curated forwardable args. `--no-color` is always appended so the captured output is plain text. `--migrate-glennr` over `--host` requires `--dry-run` or `--force` because BatchMode SSH has no TTY for confirmation prompts.

## GlennR Migration

`--migrate-glennr` is the upgrade path from `unifi-easy-encrypt.sh`. Pipeline: `inventory_glennr` → `import_provisioning_from_glennr` → `snapshot_glennr` → `_rsync_etc_letsencrypt` → allowlisted uninstall (`_remove_glennr_path` per entry) → `self_heal()`.

Key invariants (changing any of these is a regression):

- **Allowlist is explicit** — no escaping globs. 3 dirs (`/srv/EUS`, `/usr/lib/EUS`, `/root/EUS`), 3 file globs (`/root/unifi-easy-encrypt*.sh`), 4 specific crons + 1 glob (`eus_certificate_migration_*`) + content-checked `/etc/cron.d/certbot` (only deletes if it invokes `/usr/bin/certbot` — preserves user-authored cron files), 2 hook globs (`pre/EUS_*.sh`, `post/EUS_*.sh`), 4 apt sources.
- **Snapshot precedes any deletion.** `snapshot_glennr()` tars every removable path plus `/etc/letsencrypt/` to `/data/unifi-cert/backups/<ts>.tar.gz`. Recovery is `tar xzf <tarball> -C /`.
- **`/etc/letsencrypt/` is removed last** and only when the migrated lineage is verified at `<CERTBOT_CONFIG_DIR>/live/<domain>/fullchain.pem`.
- **`--dry-run` previews** every action without writing. **`--force` skips per-path confirms** but never bypasses the snapshot or the verification check.

## DDNS Auto-Refresh

`--ddns-update` keeps the DDNS target's A record fresh against the current public IP. Built for users on Telus / Comcast / similar where the modem rotates the WAN IP on every reboot or DHCP-lease expiry, and we don't want a third-party DDNS dependency. Backends: DigitalOcean and Cloudflare.

Pipeline: `_ddns_settings()` (resolve targets/provider/creds) → `_ddns_token()` → `get_public_ip()` → per target: `_ddns_resolve_zone()` → `_ddns_get_a_record()` → diff → `_ddns_put_a_record()` if changed. Idempotent — no-op when the record already matches.

Invariants (changing any of these is a regression):

- **Never create.** Records are looked up and edited *by ID*; a missing record is an error, never a POST. Updaters that re-resolve by name create a duplicate A record when the lookup misses — that's what broke `home.jdlien.ca` (see `docs/DDNS-CLOUDFLARE-PLAN.md`). `_ddns_list_records()` re-verifies each returned row's name and type and drops rows without an id, so a slipped filter can't cause the wrong record to be edited.
- **The DDNS target is configured separately from the cert CN.** `ddns_domain` / `ddns_provider` / `ddns_credentials` fall back to the cert equivalents; `ddns_credentials` only falls back when the provider is unchanged or the file also carries the DDNS provider's field. `ddns_domain` takes a comma-separated list (wildcards need the same maintenance as the record they shadow).
- **Cloudflare responses must be a well-formed `{success: true, result: …}` envelope.** An empty or unrecognized body raises rather than being treated as a successful write — an unconfirmable PATCH must never be logged as an update.
- **Zone resolution probes candidate suffixes** (`GET /zones?name=` / `GET /domains/{name}`) rather than walking a paged listing, which would have a cap and would report an owned zone as unowned. Listing survives only to enrich the "this token sees…" error.
- **Failures escalate, they don't repeat.** `DDNS_STATE_FILE` tracks last success, streak, and last error per target; reports fire on the first failure, any *new* error, then hourly/daily milestones. Synthetic `(configuration)` / `(public-ip)` keys clear on recovery and removed targets are pruned, so `--status` can't be permanently red.
- **`ddns_enabled = false`** omits the DDNS cron line. Required because `self_heal()` rewrites `CRON_FILE` on every renewal and boot, so hand-deleting the line can't stick.
- **The published IP is validated** with `is_public_ipv4()` — a captive portal answering with RFC1918 would otherwise be written straight into public DNS.

`ddns_validate()` is the read-only provisioning-time check (resolve zone + find A record, no writes). obtain-new runs it and warns; it never fails the install, since the certificate is already in place by then.

Cron line is installed alongside `--renew` by `install_cron_schedule()`:

```
*/5 * * * * root /usr/bin/python3 /data/scripts/unifi-cert.py --ddns-update >> /data/unifi-cert/unifi-cert.log 2>&1
```

## Status Report

`--status` is read-only. `print_status(host=None)` composes existing helpers (no new probes):

- `load_provisioning_config()` — domain / email / DNS provider / credentials path
- `CertMetadata.from_cert_file()` — issuer, valid_from, valid_to, SANs (tries persistent lineage first, then EUS path)
- `is_renewal_due()` — within-30-days check
- `subprocess.run([CERTBOT_BIN, '--version'])` — venv health
- `os.path.exists()` against `CRON_FILE` / `RENEWAL_HOOK_PATH` / `BOOT_SCRIPT_PATH`
- `acquire_lock(timeout=0)` round-trip — held vs idle
- `inventory_glennr()` — residue scan (reuses the migration allowlist)
- `_print_ddns_section()` — DDNS config plus `DDNS_STATE_FILE` (offline; reports the last run, not a live probe). Warns on a duplicate A record and on a last-success older than `DDNS_STALE_SUCCESS_SECONDS`, which means cron itself has stopped
- last `STATUS_LOG_TAIL_LINES` (20) of `LOG_FILE`

When `host` is set, `print_status()` short-circuits to `dispatch_remote_verb('--status', host, args)` so the same code path runs on the device.

## UniFi Certificate Paths

UniFi OS uses two certificate locations that MUST both be updated:

1. **EUS Certificates** (nginx serves these):
   - `/data/eus_certificates/unifi-os.crt`
   - `/data/eus_certificates/unifi-os.key`

2. **WebUI Certificates** (PostgreSQL + files):
   - `/data/unifi-core/config/{UUID}.crt`
   - `/data/unifi-core/config/{UUID}.key`
   - `activeCertId` in `/data/unifi-core/config/settings.yaml`
   - `user_certificates` table in PostgreSQL (`unifi-core` database)

## Development Guidelines

### Code Style

- Python 3.8+ compatible (UniFi devices have Python 3.9+)
- Type hints for function signatures
- Docstrings for public functions
- Keep functions focused and testable

### Testing

```bash
# Syntax check
python3 -m py_compile unifi-cert.py

# Help output
python3 unifi-cert.py --help

# Dry run (no changes)
python3 unifi-cert.py --install --cert test.crt --key test.key -d example.com --host 192.168.1.1 --dry-run

# Verbose mode
python3 unifi-cert.py ... -v
```

### Test Devices

- **Beehive (home)**: 192.168.1.1, domain: beehive.jdlien.com
- SSH as root, key auth configured

### Common Verification Commands

```bash
# Check nginx serves correct cert
echo | openssl s_client -connect 192.168.1.1:443 2>/dev/null | openssl x509 -noout -dates -subject

# Check PostgreSQL
ssh root@192.168.1.1 'psql -U unifi-core -d unifi-core -c "SELECT name, fingerprint, valid_to FROM user_certificates"'

# Check active cert ID
ssh root@192.168.1.1 'grep activeCertId /data/unifi-core/config/settings.yaml'
```

## DNS Provider Reference

When adding new providers, use the CORRECT certbot field name:

| Provider | Field Name (CORRECT) | Common Wrong Name |
|----------|---------------------|-------------------|
| digitalocean | `dns_digitalocean_token` | `DO_AUTH_TOKEN` |
| cloudflare | `dns_cloudflare_api_token` | `CF_API_TOKEN` |

## File Locations

- Credentials: `~/.secrets/certbot/<provider>.ini`
- Local certs: `~/letsencrypt/<domain>/`
- Device certs: `/etc/letsencrypt/live/<domain>/`

## Commit Guidelines

- Keep commits focused and atomic
- Test with `--dry-run` before pushing changes that affect installation logic
- Update README.md if CLI interface changes
