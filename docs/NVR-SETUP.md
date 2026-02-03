# UniFi NVR Certificate Setup

Additional steps for UniFi NVR devices (UNVR, UNVR Pro) that may not automatically pick up certificates.

## The Problem

On some NVR devices, nginx uses a UUID-based certificate path instead of the EUS certificate location. After certificate installation, you may still see the old/self-signed certificate.

## Check if Affected

```bash
ssh root@<NVR_IP> 'cat /data/unifi-core/config/http/local-certs.conf'
```

If it shows a UUID path like:
```
ssl_certificate     /data/unifi-core/config/e94ceb86-c69d-4b87-b5b7-945b34d5fece.crt;
ssl_certificate_key /data/unifi-core/config/e94ceb86-c69d-4b87-b5b7-945b34d5fece.key;
```

You need the fix below.

## The Fix

Update nginx to read from the EUS certificate location:

```bash
ssh root@<NVR_IP> 'echo -e "ssl_certificate     /data/eus_certificates/unifi-os.crt;\nssl_certificate_key /data/eus_certificates/unifi-os.key;" > /data/unifi-core/config/http/local-certs.conf && systemctl reload nginx'
```

## Verify

```bash
echo | openssl s_client -connect <NVR_IP>:443 2>/dev/null | openssl x509 -noout -dates -subject
```

Should show the new Let's Encrypt cert with your domain and future expiry date.

## After the Fix

Once configured, the certificate flow works automatically:

1. `unifi-cert.py` installs cert to `/data/eus_certificates/`
2. Nginx reads from `/data/eus_certificates/` via `local-certs.conf`
3. Future renewals update the same files

## Alternative: Use UUID Path

If you prefer to use the UUID path (for WebUI consistency), ensure `unifi-cert.py` is run with PostgreSQL updates enabled (the default). The script updates both:
- EUS path (`/data/eus_certificates/`)
- UUID path (`/data/unifi-core/config/{UUID}.crt|.key`)

To check which path nginx is using and update the UUID certificates:

```bash
# Get the UUID from settings
UUID=$(ssh root@<NVR_IP> "grep 'activeCertId:' /data/unifi-core/config/settings.yaml | awk '{print \$2}'")
echo "Active cert ID: $UUID"

# Install to UUID path
python3 unifi-cert.py --install \
  --cert /path/to/cert.crt \
  --key /path/to/cert.key \
  --domain example.com \
  --host <NVR_IP>
```
