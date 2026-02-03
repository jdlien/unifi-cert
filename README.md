# UniFi Certificate Manager

A clean Python tool for managing Let's Encrypt SSL certificates on UniFi OS devices.

**Why this exists:** The popular GlennR script has bugs - it uses the wrong DNS credential field name and doesn't update PostgreSQL, so the WebUI shows stale certificate info. This tool fixes both issues.

## Features

- **Fixes DNS credential bug** - Uses correct field names (`dns_digitalocean_token` not `DO_AUTH_TOKEN`)
- **Syncs WebUI** - Updates PostgreSQL so the UniFi interface shows accurate cert info
- **No dependencies** - Pure Python stdlib, works anywhere Python 3.8+ runs
- **Remote installation** - Run from your workstation, install via SSH
- **Curl-pipe friendly** - Single file, works with `curl | python3 -`

## Quick Start

### Install an Existing Certificate

```bash
python3 unifi-cert.py --install \
  --cert /path/to/fullchain.pem \
  --key /path/to/privkey.pem \
  --domain example.com \
  --host 192.168.1.1
```

### Obtain & Install a New Certificate

```bash
python3 unifi-cert.py \
  --domain example.com \
  --email you@example.com \
  --dns-provider digitalocean \
  --dns-credentials ~/.secrets/certbot/digitalocean.ini \
  --host 192.168.1.1
```

### Interactive Mode

```bash
python3 unifi-cert.py
```

### Curl-Pipe Usage

```bash
curl -sL https://raw.githubusercontent.com/jdlien/unifi-cert/main/unifi-cert.py | \
  python3 - --help
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

UniFi OS stores certificates in two places:

1. **Nginx** reads from `/data/eus_certificates/unifi-os.crt|.key`
2. **WebUI** reads from PostgreSQL `user_certificates` table + UUID-named files

This tool updates **both**, ensuring the certificate works AND the WebUI displays correct information.

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

## License

MIT
