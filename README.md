# UniFi Certificate Manager

A clean Python tool for managing Let's Encrypt SSL certificates on UniFi OS devices.

**Why this exists:** The popular GlennR script has bugs - it uses the wrong DNS credential field name and doesn't update PostgreSQL, so the WebUI shows stale certificate info. This tool fixes both issues.

## Features

- **Fixes DNS credential bug** - Uses correct field names (`dns_digitalocean_token` not `DO_AUTH_TOKEN`)
- **Syncs WebUI** - Updates PostgreSQL so the UniFi interface shows accurate cert info
- **Auto-detects domain** - Reads CN from existing certificate, no need to specify `-d` when syncing
- **No dependencies** - Pure Python stdlib, works anywhere Python 3.8+ runs
- **Remote installation** - Run from your workstation, install via SSH
- **Curl-pipe friendly** - Single file, works with `curl | python3 -`

## Quick Start

### One-Liner (Run on Router)

SSH into your UniFi device and run:

```bash
# First, create credentials file (one-time setup)
mkdir -p ~/.secrets/certbot && cat > ~/.secrets/certbot/digitalocean.ini << 'EOF'
dns_digitalocean_token = YOUR_TOKEN_HERE
EOF
chmod 600 ~/.secrets/certbot/digitalocean.ini

# Then obtain and install certificate
curl -sL https://raw.githubusercontent.com/jdlien/unifi-cert/main/unifi-cert.py | python3 - \
  -d your-domain.com \
  -e you@example.com \
  --dns-provider digitalocean \
  --dns-credentials ~/.secrets/certbot/digitalocean.ini
```

### Sync Existing Certificate to WebUI

If you previously used GlennR's script (or have certs in EUS but UI shows wrong info):

```bash
# Domain is auto-detected from the certificate - no -d needed!
curl -sL https://raw.githubusercontent.com/jdlien/unifi-cert/main/unifi-cert.py | python3 - \
  --install \
  --cert /data/eus_certificates/unifi-os.crt \
  --key /data/eus_certificates/unifi-os.key
```

### Remote Installation (From Workstation)

```bash
python3 unifi-cert.py --install \
  --cert /path/to/fullchain.pem \
  --key /path/to/privkey.pem \
  -d example.com \
  --host 192.168.1.1
```

### Interactive Mode

```bash
python3 unifi-cert.py
```

## DNS Credentials

Create a credentials file with the **correct** field name:

```bash
mkdir -p ~/.secrets/certbot
chmod 700 ~/.secrets/certbot
```

**DigitalOcean** (`~/.secrets/certbot/digitalocean.ini`):
```ini
dns_digitalocean_token = dop_v1_your_token_here
```

**Cloudflare** (`~/.secrets/certbot/cloudflare.ini`):
```ini
dns_cloudflare_api_token = your_token_here
```

```bash
chmod 600 ~/.secrets/certbot/*.ini
```

<details>
<summary>Other DNS Providers</summary>

| Provider | Credential Field |
|----------|------------------|
| digitalocean | `dns_digitalocean_token` |
| cloudflare | `dns_cloudflare_api_token` |
| route53 | Uses AWS credentials |
| google | Service account JSON |
| linode | `dns_linode_key` |
| namecheap | `dns_namecheap_api_key` |
| ovh | `dns_ovh_application_key` |

</details>

## Command Reference

```
Usage: unifi-cert.py [OPTIONS]

Certificate Options:
  -d, --domain DOMAIN        Domain name for certificate
  -e, --email EMAIL          Email for Let's Encrypt
  --dns-provider PROVIDER    digitalocean, cloudflare, route53, google, linode, ovh
  --dns-credentials FILE     Path to credentials file
  --propagation SECONDS      DNS propagation wait (default: 60)

Installation Options:
  --install                  Install existing certificate
  --cert FILE                Certificate file (fullchain.pem)
  --key FILE                 Private key file (privkey.pem)
  --host HOST                Remote UniFi device IP/hostname

Renewal Options:
  --renew                    Renew existing certificate
  --setup-hook               Set up certbot renewal hook

Modifiers:
  --dry-run                  Test without making changes
  --force                    Force renewal even if not due
  --skip-postgres            Skip database update
  --skip-restart             Skip service restart
  -v, --verbose              Verbose output
```

## How It Works

UniFi OS stores certificates in two places that must stay synchronized:

```
┌─────────────────────────────┐    ┌─────────────────────────────┐
│     EUS Certificates        │    │     WebUI/PostgreSQL        │
│   (what nginx serves)       │    │   (what the UI displays)    │
├─────────────────────────────┤    ├─────────────────────────────┤
│ /data/eus_certificates/     │    │ /data/unifi-core/config/    │
│   unifi-os.crt              │◄──►│   {UUID}.crt                │
│   unifi-os.key              │    │   {UUID}.key                │
└─────────────────────────────┘    │ PostgreSQL user_certificates│
                                   │ settings.yaml activeCertId  │
                                   └─────────────────────────────┘
```

**The GlennR script bug:** Only updates the EUS path, leaving the WebUI showing stale certificate information.

**This tool's approach:** Updates **both** paths with the same certificate, keeping them synchronized. Uses PostgreSQL UPSERT to handle edge cases where the UI has deleted a certificate but files remain.

### Important Notes

- **Service Restart:** By default, the tool restarts `unifi-core` after installation. This briefly takes the console offline (~10-30 seconds). Use `--skip-restart` to avoid this, but the WebUI won't reflect changes until the next restart.
- **UI Removal:** If you remove a certificate via the UniFi UI, it only removes the PostgreSQL entry and UUID files. The EUS certificates (what's actually served) remain untouched. This tool can re-sync them.

## Supported Devices

- UniFi Dream Machine (UDM, UDM Pro, UDM SE)
- UniFi Cloud Key Gen2 / Gen2 Plus
- UniFi NVR (see [docs/NVR-SETUP.md](docs/NVR-SETUP.md) for additional steps)

## Troubleshooting

### Verify Installation

```bash
# Check what nginx is serving
echo | openssl s_client -connect 192.168.1.1:443 2>/dev/null | \
  openssl x509 -noout -dates -subject

# Check database
ssh root@192.168.1.1 'psql -U unifi-core -d unifi-core -c \
  "SELECT name, valid_to FROM user_certificates"'
```

### SSH Issues

```bash
# Test connection
ssh root@192.168.1.1 'echo OK'

# Copy your key if needed
ssh-copy-id root@192.168.1.1
```

### WebUI Still Shows Old Cert

```bash
ssh root@192.168.1.1 'systemctl restart unifi-core'
```

### NVR Devices

See [docs/NVR-SETUP.md](docs/NVR-SETUP.md) for NVR-specific configuration.

## Requirements

- Python 3.8+
- SSH access to UniFi device (for remote installation)
- certbot + DNS plugin (for obtaining new certificates)

## Development

### Setup

```bash
# Clone the repo
git clone https://github.com/jdlien/unifi-cert.git
cd unifi-cert

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=. --cov-report=term-missing
```

### Testing on a Device

```bash
# Dry run (no changes)
python3 unifi-cert.py --install \
  --cert /path/to/cert.pem --key /path/to/key.pem \
  -d example.com --host 192.168.1.1 --dry-run -v

# Skip service restart during testing
python3 unifi-cert.py --install \
  --cert /path/to/cert.pem --key /path/to/key.pem \
  -d example.com --host 192.168.1.1 --skip-restart -v
```

### Project Structure

```
unifi-cert.py          # Single-file tool (no dependencies for runtime)
pyproject.toml         # Dev dependencies only
tests/                 # Pytest test suite (93%+ coverage)
docs/                  # Additional documentation
```

## License

MIT
