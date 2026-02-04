# UniFi Certificate Manager

A Python tool for managing Let's Encrypt SSL certificates on UniFi OS devices.

Inspired by [GlennR's UniFi Easy Encrypt](https://community.ui.com/questions/UniFi-OS-Server-Installation-Scripts-or-UniFi-Network-Application-Installation-Scripts-or-UniFi-Eas/ccbc7530-dd61-40a7-82ec-22b17f027776) script, this tool improves on it in several key ways:

- **Fixes the WebUI desync** - GlennR's script updates certificate files but not PostgreSQL, so the UniFi interface shows stale cert info. This tool updates both.
- **Fixes DNS credential fields** - Uses correct certbot field names (e.g., `dns_digitalocean_token` instead of `DO_AUTH_TOKEN`)
- **Simpler codebase** - ~800 lines of Python vs ~6000 lines of bash, making it easier to maintain and debug
- **Interactive wizard** - Just run it and answer prompts; no need to remember CLI flags

## Features

- **Auto-detects domain** - Reads CN from existing certificate, no need to specify `-d` when syncing
- **Auto-detects credentials** - Finds `~/.secrets/certbot/{provider}.ini` automatically
- **Remembers preferences** - Saves email and DNS provider to `~/.secrets/certbot/config.ini`
- **No dependencies** - Pure Python stdlib, works anywhere Python 3.8+ runs
- **Remote installation** - Run from your workstation, install via SSH
- **Curl-pipe friendly** - Single file, works with `curl | python3 -`

## Quick Start

SSH into your UniFi device and run:

```bash
curl -sL jdlien.com/unifi-cert | python3 -
```

> This redirects to the [GitHub raw URL](https://raw.githubusercontent.com/jdlien/unifi-cert/main/unifi-cert.py) - use that directly if you prefer.

That's it. The interactive wizard will walk you through everything:
- Domain name (auto-detected if you have an existing cert)
- Email for Let's Encrypt
- DNS provider selection
- API credentials (creates the file for you if needed)
- **Automatic renewal hook** (keeps WebUI in sync after renewals)

### Sync Existing Certificate to WebUI

If you previously used GlennR's script (or have certs in EUS but UI shows wrong info):

```bash
curl -sL jdlien.com/unifi-cert | python3 - \
  --install \
  --cert /data/eus_certificates/unifi-os.crt \
  --key /data/eus_certificates/unifi-os.key
```

### Non-Interactive / Scripted Usage

For automation, pass all options on the command line:

```bash
curl -sL jdlien.com/unifi-cert | python3 - \
  -d your-domain.com \
  -e you@example.com \
  --dns-provider digitalocean
```

Credentials are auto-detected from `~/.secrets/certbot/{provider}.ini`.

### Remote Installation (From Workstation)

```bash
python3 unifi-cert.py --install \
  --cert /path/to/fullchain.pem \
  --key /path/to/privkey.pem \
  -d example.com \
  --host 192.168.1.1
```

## DNS Credentials

> **Note:** The interactive wizard can create this file for you. Just run the tool and it will prompt for your API token if the file doesn't exist.

To set up credentials manually:

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
  --no-color                 Disable colored output
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

### Automatic Renewal

When you obtain a certificate using this tool, it automatically installs a renewal hook at `/etc/letsencrypt/renewal-hooks/post/unifi-cert-hook.sh`. This ensures that when certbot auto-renews your certificate (typically 30 days before expiry), the new cert is automatically synced to both the EUS paths and PostgreSQL, keeping the WebUI in sync.

The renewal hook:
- Attempts to download the latest script from GitHub (self-updating)
- Falls back to existing script if download fails (resilient to network issues)
- Saves to `/data/scripts/unifi-cert.py` (persistent across firmware updates)
- Syncs the renewed cert to UniFi

Certbot's renewal runs automatically via systemd timer. You can verify the hook:

```bash
cat /etc/letsencrypt/renewal-hooks/post/unifi-cert-hook.sh
```

To manually test renewal sync:
```bash
/data/scripts/unifi-cert.py --renew -d your-domain.com
```

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
tests/                 # Pytest test suite (90%+ coverage)
docs/                  # Additional documentation
```

## License

MIT
