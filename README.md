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
curl -sL jdlien.com/unifi-cert | python3 - --install \
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

> The interactive wizard can create this file for you. Just run the tool and it will prompt for your API token if the file doesn't exist.

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

| Provider     | Credential Field           |
|:-------------|:---------------------------|
| digitalocean | `dns_digitalocean_token`   |
| cloudflare   | `dns_cloudflare_api_token` |
| route53      | Uses AWS credentials       |
| google       | Service account JSON       |
| linode       | `dns_linode_key`           |
| namecheap    | `dns_namecheap_api_key`    |
| ovh          | `dns_ovh_application_key`  |

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
  --renew                    Cron entry point. Acquires lock, runs self-heal,
                             checks expiry, runs ACME if due, syncs to UniFi.
  --deploy-hook              certbot post-renewal hook entry. Reads
                             $RENEWED_LINEAGE and syncs that lineage only.
  --self-heal                Idempotent repair: ensure venv + cron + hook +
                             boot script. Never runs ACME.
  --setup-hook               Set up certbot renewal hook
  --bootstrap                Build/repair the persistent certbot venv at
                             /data/unifi-cert/certbot-venv
  --enable-hook-autoupdate   Re-enable the renewal hook GitHub auto-update
                             path (default off; requires SHA-256 pin)

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
- **Renewal Hook Overrides Manual Changes:** Once installed, the renewal hook will replace *any* certificate on the device when certbot renews - including certificates you manually uploaded via the WebUI. If you change your hostname or want to use a different certificate, remove the renewal hook first: `rm /etc/letsencrypt/renewal-hooks/post/unifi-cert-hook.sh`

### Automatic Renewal

When you obtain a certificate locally with this tool, it sets up the full renewal pipeline:

- **Daily cron** at `/etc/cron.d/unifi-cert` runs `unifi-cert.py --renew` once a day. `--renew` acquires a lock, self-heals (rebuilds venv / cron / hook if anything was wiped by a firmware update), checks expiry, and only calls Let's Encrypt when the cert is within 30 days of expiry.
- **certbot post-renewal hook** at `/etc/letsencrypt/renewal-hooks/post/unifi-cert-hook.sh` runs `unifi-cert.py --deploy-hook` whenever certbot itself renews a lineage. The hook reads `$RENEWED_LINEAGE` from certbot's environment and syncs that lineage to the EUS paths and PostgreSQL.
- **Persistent product root** at `/data/unifi-cert/` holds everything that needs to survive UniFi OS firmware updates: certbot venv (`certbot-venv/`), Let's Encrypt state (`letsencrypt/`), wheel cache (`wheels/`), provisioning config (`unifi-cert.conf`), credentials (`credentials/`), and the renewal log (`unifi-cert.log`).
- **Provisioning config** at `/data/unifi-cert/unifi-cert.conf` records domain, email, DNS provider, and credentials path so cron-fired `--renew` (no flags) can self-configure.

The hook does **not** download a fresh copy of the script from GitHub on every renewal. That auto-update behavior is opt-in via `--setup-hook --enable-hook-autoupdate` and requires a SHA-256 pin baked into `unifi-cert.py`; the hook then verifies the download against the pin before atomic-replacing the script. By default the hook simply runs the locally installed script.

Verify the install:

```bash
ssh root@192.168.1.1 cat /etc/cron.d/unifi-cert
ssh root@192.168.1.1 cat /etc/letsencrypt/renewal-hooks/post/unifi-cert-hook.sh
ssh root@192.168.1.1 ls /data/unifi-cert/
```

Force a renewal pass without waiting for the next day:

```bash
ssh root@192.168.1.1 /data/scripts/unifi-cert.py --renew --force
```

Or just the post-renewal sync (no ACME) for an existing lineage:

```bash
ssh root@192.168.1.1 'RENEWED_LINEAGE=/data/unifi-cert/letsencrypt/live/your-domain.com \
  /data/scripts/unifi-cert.py --deploy-hook'
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
