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
unifi-cert.py (~1300 lines)
├── CONFIGURATION      - DNS providers, paths, constants
├── UI LAYER           - ANSI colors, spinners, prompts
├── CERTIFICATE META   - OpenSSL metadata extraction
├── IP LOOKUP          - Multi-provider fallback (unused currently, for future)
├── DNS CREDENTIALS    - Validation and creation
├── UNIFI PLATFORM     - Device detection
├── CERT INSTALLATION  - Local installation logic
├── POSTGRESQL         - Database updates for WebUI sync
├── CERTBOT            - Let's Encrypt integration
├── REMOTE SSH         - SSH/SCP operations
└── CLI & MAIN         - Argument parsing, interactive mode
```

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
