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
├── DDNS                  - DigitalOcean A-record auto-refresh (--ddns-update)
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
├── unifi-cert.conf      # provisioning config (domain, email, dns provider, creds path)
├── unifi-cert.log       # main log (rotated >1 MB, keep last 100 KB)
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
| `--ddns-update` | refresh A record at DNS provider; cron-fired every 5 min | yes |
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

`--ddns-update` keeps the cert hostname's A record fresh against the current public IP. Built for users on Telus / Comcast / similar where the modem rotates the WAN IP on every reboot or DHCP-lease expiry, and we don't want a third-party DDNS dependency.

Pipeline: `get_public_ip()` (multi-provider fallback chain) → `_ddns_resolve_zone()` (longest-suffix match against the user's actual DigitalOcean zones, so multi-part TLDs work without a public-suffix list) → `_ddns_get_a_record()` → diff → `_ddns_put_a_record()` if changed. Idempotent — no-op API call when the record already matches.

Provider lock-in: DigitalOcean only for v1, but the dispatch shape supports Cloudflare / Route53 / others — branch on `dns_provider` and add `_ddns_*_<provider>()` helpers.

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
