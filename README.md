# UniFi Certificate Manager

A clean, maintainable Python tool for managing Let's Encrypt SSL certificates on UniFi OS devices (UDM, UDM Pro, Cloud Key Gen2+).

## Features

- **Fixes known bugs** in GlennR's `unifi-easy-encrypt.sh`:
  - Correct DNS credential field names (e.g., `dns_digitalocean_token` not `DO_AUTH_TOKEN`)
  - Proper WebUI sync via PostgreSQL updates
  - No external API dependencies (geo lookup, version checks)

- **Dual-path certificate installation**:
  - EUS certificates (nginx): `/data/eus_certificates/`
  - WebUI certificates (PostgreSQL): `/data/unifi-core/config/{UUID}.crt|.key`

- **Multiple installation modes**:
  - Local: Run directly on UniFi device
  - Remote: Install via SSH from any machine
  - Curl-pipe: One-liner installation

- **Pure Python stdlib**: No external dependencies (no Rich, no requests)

## Quick Start

### Install Existing Certificate (Remote)

```bash
# From your local machine, install a certificate to your UniFi device
python3 unifi-cert.py --install \
  --cert ~/letsencrypt/example.com/example.com.crt \
  --key ~/letsencrypt/example.com/example.com.key \
  --domain example.com \
  --host 192.168.1.1
```

### Obtain & Install Certificate

```bash
# Obtain Let's Encrypt certificate and install
python3 unifi-cert.py \
  --domain example.com \
  --email admin@example.com \
  --dns-provider digitalocean \
  --dns-credentials ~/.secrets/certbot/digitalocean.ini \
  --host 192.168.1.1
```

### Interactive Mode

```bash
# Guided setup - prompts for all required information
python3 unifi-cert.py
```

### Curl-Pipe Installation

```bash
# Run directly without downloading
curl -sL https://raw.githubusercontent.com/jdlien/unifi-cert/main/unifi-cert.py | \
  python3 - --install --cert cert.pem --key key.pem -d example.com --host 192.168.1.1
```

## DNS Provider Credentials

Create a credentials file with secure permissions:

```bash
mkdir -p ~/.secrets/certbot
chmod 700 ~/.secrets/certbot
```

### DigitalOcean

```ini
# ~/.secrets/certbot/digitalocean.ini
dns_digitalocean_token = your_api_token_here
```

### Cloudflare

```ini
# ~/.secrets/certbot/cloudflare.ini
dns_cloudflare_api_token = your_api_token_here
```

### Other Providers

| Provider | Plugin | Credential Field |
|----------|--------|------------------|
| digitalocean | certbot-dns-digitalocean | `dns_digitalocean_token` |
| cloudflare | certbot-dns-cloudflare | `dns_cloudflare_api_token` |
| route53 | certbot-dns-route53 | Uses AWS credentials |
| google | certbot-dns-google | Service account JSON |
| linode | certbot-dns-linode | `dns_linode_key` |
| namecheap | certbot-dns-namecheap | `dns_namecheap_api_key` |
| ovh | certbot-dns-ovh | `dns_ovh_application_key` |

Set secure permissions:

```bash
chmod 600 ~/.secrets/certbot/*.ini
```

## Command Reference

```
Usage: unifi-cert.py [OPTIONS]

Options:
  -d, --domain DOMAIN        Domain name for certificate
  -e, --email EMAIL          Email for Let's Encrypt notifications
  --dns-provider PROVIDER    DNS provider (digitalocean, cloudflare, etc.)
  --dns-credentials FILE     Path to credentials file
  --propagation SECONDS      DNS propagation wait (default: 60)

  --install                  Install existing cert (requires --cert, --key)
  --cert FILE                Certificate file path
  --key FILE                 Private key file path
  --host HOST                Remote UniFi host for SSH installation

  --renew                    Renew existing certificate
  --setup-hook               Set up certbot renewal hook only

  --dry-run                  Test without making changes
  --force                    Force renewal even if not due
  --skip-postgres            Skip PostgreSQL update
  --skip-restart             Skip service restart

  -v, --verbose              Verbose output
  --no-color                 Disable colored output
```

## How It Works

### Certificate Paths

UniFi OS uses two certificate locations:

1. **EUS Certificates** (nginx serves these):
   - `/data/eus_certificates/unifi-os.crt`
   - `/data/eus_certificates/unifi-os.key`

2. **WebUI Certificates** (PostgreSQL metadata + files):
   - `/data/unifi-core/config/{UUID}.crt`
   - `/data/unifi-core/config/{UUID}.key`
   - `activeCertId` in `/data/unifi-core/config/settings.yaml`
   - `user_certificates` table in PostgreSQL

This tool updates **both** paths, ensuring the WebUI displays correct certificate information.

### PostgreSQL Schema

```sql
CREATE TABLE user_certificates (
  id UUID PRIMARY KEY,
  name VARCHAR,
  cert TEXT,
  key TEXT,
  issuer JSONB,
  subject JSONB,
  subject_alt_name JSONB,
  valid_from TIMESTAMP WITH TIME ZONE,
  valid_to TIMESTAMP WITH TIME ZONE,
  serial_number VARCHAR,
  fingerprint VARCHAR,
  version INTEGER,
  created_at TIMESTAMP WITH TIME ZONE,
  updated_at TIMESTAMP WITH TIME ZONE
);
```

## Setting Up Auto-Renewal

```bash
# Set up the renewal hook (creates /etc/letsencrypt/renewal-hooks/post/unifi-cert-hook.sh)
python3 unifi-cert.py --setup-hook --domain example.com

# Test renewal
certbot renew --dry-run
```

## Troubleshooting

### SSH Connection Failed

Ensure SSH is enabled on your UniFi device and your key is authorized:

```bash
# Test connection
ssh root@192.168.1.1 'echo Connected'

# If needed, copy your SSH key
ssh-copy-id root@192.168.1.1
```

### Certificate Not Showing in WebUI

The script updates PostgreSQL to sync the WebUI. If you still see old info:

```bash
# Verify database was updated
ssh root@192.168.1.1 'psql -U unifi-core -d unifi-core -c "SELECT name, valid_to FROM user_certificates"'

# Restart unifi-core
ssh root@192.168.1.1 'systemctl restart unifi-core'
```

### Wrong DNS Credential Field Name

This is the main bug this tool fixes. Make sure your credentials file uses the correct field name:

```bash
# WRONG (GlennR API bug)
DO_AUTH_TOKEN = ...

# CORRECT
dns_digitalocean_token = ...
```

### Verify Certificate Installation

```bash
# Check nginx is serving the new cert
echo | openssl s_client -connect 192.168.1.1:443 2>/dev/null | openssl x509 -noout -dates

# Check PostgreSQL
ssh root@192.168.1.1 'psql -U unifi-core -d unifi-core -c "SELECT name, fingerprint, valid_to FROM user_certificates"'
```

## Requirements

- Python 3.8+
- SSH access to UniFi device (for remote installation)
- certbot + DNS plugin (for obtaining certificates)

## Supported Devices

- UniFi Dream Machine (UDM)
- UniFi Dream Machine Pro (UDM Pro)
- UniFi Dream Machine SE
- UniFi Cloud Key Gen2 (Plus)
- Other UniFi OS devices (5.x+)

## License

MIT
