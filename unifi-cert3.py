#!/usr/bin/env python3
"""
UniFi Certificate Manager

A clean, maintainable tool for managing Let's Encrypt SSL certificates on UniFi OS devices.
Fixes known bugs in GlennR's script and adds proper WebUI/PostgreSQL integration.

Author: jdlien
License: MIT
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

# =============================================================================
# CONFIGURATION
# =============================================================================

# DNS provider configurations - fixes the GlennR API field name bug
DNS_PROVIDERS = {
    'digitalocean': {
        'plugin': 'certbot-dns-digitalocean',
        'field': 'dns_digitalocean_token',  # CORRECT - GlennR API returns DO_AUTH_TOKEN which is wrong
        'propagation': 60,
        'description': 'DigitalOcean DNS',
    },
    'cloudflare': {
        'plugin': 'certbot-dns-cloudflare',
        'field': 'dns_cloudflare_api_token',
        'propagation': 10,
        'description': 'Cloudflare DNS',
    },
    'route53': {
        'plugin': 'certbot-dns-route53',
        'field': 'aws_access_key_id',  # Uses AWS credentials
        'propagation': 10,
        'description': 'Amazon Route 53',
    },
    'google': {
        'plugin': 'certbot-dns-google',
        'field': 'credentials_file',  # Uses service account JSON
        'propagation': 60,
        'description': 'Google Cloud DNS',
    },
    'linode': {
        'plugin': 'certbot-dns-linode',
        'field': 'dns_linode_key',
        'propagation': 120,
        'description': 'Linode DNS',
    },
    'namecheap': {
        'plugin': 'certbot-dns-namecheap',
        'field': 'dns_namecheap_api_key',
        'propagation': 30,
        'description': 'Namecheap DNS',
    },
    'ovh': {
        'plugin': 'certbot-dns-ovh',
        'field': 'dns_ovh_application_key',
        'propagation': 30,
        'description': 'OVH DNS',
    },
}

# UniFi paths
UNIFI_PATHS = {
    'settings_yaml': '/data/unifi-core/config/settings.yaml',
    'config_dir': '/data/unifi-core/config',
    'eus_cert': '/data/eus_certificates/unifi-os.crt',
    'eus_key': '/data/eus_certificates/unifi-os.key',
    'eus_dir': '/data/eus_certificates',
}

# IP lookup providers (fallback chain)
IP_PROVIDERS = [
    ('https://ipwho.is/', lambda d: d.get('ip')),
    ('https://json.geoiplookup.io/', lambda d: d.get('ip')),
    ('http://ip-api.com/json/', lambda d: d.get('query')),
    ('https://api.ipify.org?format=json', lambda d: d.get('ip')),
]


# =============================================================================
# UI LAYER - Pure stdlib ANSI terminal output
# =============================================================================

class UI:
    """Terminal UI with ANSI colors and Unicode spinners. Falls back gracefully."""

    # ANSI color codes
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

    # Unicode spinner frames
    SPINNER_FRAMES = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'

    def __init__(self, color: bool = True, verbose: bool = False):
        self.color = color and sys.stdout.isatty()
        self.verbose = verbose
        self._spinner_running = False
        self._spinner_thread: Optional[threading.Thread] = None

    def _c(self, code: str, text: str) -> str:
        """Apply color code if colors enabled."""
        if self.color:
            return f'{code}{text}{self.RESET}'
        return text

    def header(self, text: str) -> None:
        """Print a section header."""
        print()
        print(self._c(self.BOLD + self.CYAN, f'━━━ {text} ━━━'))

    def status(self, text: str) -> None:
        """Print a status message."""
        print(self._c(self.BLUE, '→ ') + text)

    def success(self, text: str) -> None:
        """Print a success message."""
        print(self._c(self.GREEN, '✓ ') + text)

    def warning(self, text: str) -> None:
        """Print a warning message."""
        print(self._c(self.YELLOW, '⚠ ') + text)

    def error(self, text: str) -> None:
        """Print an error message."""
        print(self._c(self.RED, '✗ ') + text, file=sys.stderr)

    def info(self, text: str) -> None:
        """Print an info message."""
        print(self._c(self.DIM, '  ') + text)

    def debug(self, text: str) -> None:
        """Print a debug message (only in verbose mode)."""
        if self.verbose:
            print(self._c(self.DIM, '  [debug] ') + text)

    def table(self, rows: list[tuple[str, str]], indent: int = 2) -> None:
        """Print a simple two-column table."""
        if not rows:
            return
        max_key = max(len(row[0]) for row in rows)
        for key, value in rows:
            prefix = ' ' * indent
            key_fmt = self._c(self.CYAN, key.ljust(max_key))
            print(f'{prefix}{key_fmt}  {value}')

    def spinner_start(self, text: str) -> None:
        """Start a spinner with message."""
        if not self.color:
            print(text + '...')
            return

        self._spinner_running = True

        def spin():
            i = 0
            while self._spinner_running:
                frame = self.SPINNER_FRAMES[i % len(self.SPINNER_FRAMES)]
                print(f'\r{self.CYAN}{frame}{self.RESET} {text}', end='', flush=True)
                time.sleep(0.1)
                i += 1
            # Clear spinner line
            print('\r' + ' ' * (len(text) + 4) + '\r', end='', flush=True)

        self._spinner_thread = threading.Thread(target=spin, daemon=True)
        self._spinner_thread.start()

    def spinner_stop(self) -> None:
        """Stop the spinner."""
        self._spinner_running = False
        if self._spinner_thread:
            self._spinner_thread.join(timeout=0.5)
            self._spinner_thread = None

    def prompt(self, text: str, default: Optional[str] = None) -> str:
        """Prompt user for input."""
        if default:
            prompt_text = f'{text} [{default}]: '
        else:
            prompt_text = f'{text}: '
        value = input(self._c(self.YELLOW, '? ') + prompt_text).strip()
        return value if value else (default or '')

    def confirm(self, text: str, default: bool = True) -> bool:
        """Prompt user for yes/no confirmation."""
        suffix = '[Y/n]' if default else '[y/N]'
        response = input(self._c(self.YELLOW, '? ') + f'{text} {suffix}: ').strip().lower()
        if not response:
            return default
        return response in ('y', 'yes')

    def select(self, text: str, options: list[str]) -> int:
        """Prompt user to select from options."""
        print(self._c(self.YELLOW, '? ') + text)
        for i, opt in enumerate(options, 1):
            print(f'  {self._c(self.CYAN, str(i))}. {opt}')
        while True:
            try:
                choice = int(input(self._c(self.YELLOW, '  Enter choice: ')))
                if 1 <= choice <= len(options):
                    return choice - 1
            except ValueError:
                pass
            print(self._c(self.RED, '  Invalid choice, try again'))


# Global UI instance
ui = UI()


# =============================================================================
# CERTIFICATE METADATA
# =============================================================================

@dataclass
class CertMetadata:
    """Certificate metadata extracted from the certificate file."""
    cn: str
    issuer_c: str
    issuer_o: str
    issuer_cn: str
    sans: list[str]
    valid_from: str
    valid_to: str
    serial: str
    fingerprint: str

    @classmethod
    def from_cert_file(cls, cert_path: str) -> 'CertMetadata':
        """Extract metadata from a certificate file using openssl."""
        def run_openssl(*args: str) -> str:
            try:
                result = subprocess.run(
                    ['openssl', 'x509', '-in', cert_path, '-noout', *args],
                    capture_output=True, text=True, check=True
                )
                return result.stdout.strip()
            except subprocess.CalledProcessError:
                return ''

        # Extract subject CN
        subject = run_openssl('-subject')
        cn_match = re.search(r'CN\s*=\s*([^,/\n]+)', subject)
        cn = cn_match.group(1).strip() if cn_match else ''

        # Extract issuer details
        issuer = run_openssl('-issuer')
        issuer_c_match = re.search(r'C\s*=\s*([^,/\n]+)', issuer)
        issuer_o_match = re.search(r'O\s*=\s*([^,/\n]+)', issuer)
        issuer_cn_match = re.search(r'CN\s*=\s*([^,/\n]+)', issuer)
        issuer_c = issuer_c_match.group(1).strip() if issuer_c_match else ''
        issuer_o = issuer_o_match.group(1).strip() if issuer_o_match else ''
        issuer_cn = issuer_cn_match.group(1).strip() if issuer_cn_match else ''

        # Extract SANs
        sans_output = run_openssl('-ext', 'subjectAltName')
        sans = re.findall(r'DNS:([^\s,]+)', sans_output)

        # Extract dates
        valid_from_raw = run_openssl('-startdate').replace('notBefore=', '')
        valid_to_raw = run_openssl('-enddate').replace('notAfter=', '')

        # Convert to PostgreSQL timestamp format
        def convert_date(date_str: str) -> str:
            if not date_str:
                return ''
            try:
                # Parse format: "Jan  1 00:00:00 2024 GMT"
                dt = datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
                return dt.strftime('%Y-%m-%d %H:%M:%S+00')
            except ValueError:
                try:
                    # Alternative format without timezone
                    dt = datetime.strptime(date_str.rstrip(' GMT'), '%b %d %H:%M:%S %Y')
                    return dt.strftime('%Y-%m-%d %H:%M:%S+00')
                except ValueError:
                    return date_str

        valid_from = convert_date(valid_from_raw)
        valid_to = convert_date(valid_to_raw)

        # Extract serial number
        serial_output = run_openssl('-serial')
        serial = serial_output.replace('serial=', '')

        # Extract fingerprint
        fingerprint_output = run_openssl('-fingerprint', '-sha1')
        fingerprint = re.sub(r'^(sha1 |SHA1 )?Fingerprint=', '', fingerprint_output)

        return cls(
            cn=cn,
            issuer_c=issuer_c,
            issuer_o=issuer_o,
            issuer_cn=issuer_cn,
            sans=sans,
            valid_from=valid_from,
            valid_to=valid_to,
            serial=serial,
            fingerprint=fingerprint,
        )


def detect_domain_from_cert(cert_path: str = None) -> Optional[str]:
    """
    Auto-detect domain from an existing certificate.

    Args:
        cert_path: Path to certificate file. If None, uses default EUS cert path.

    Returns:
        Domain name (CN) if found, None otherwise.
    """
    if cert_path is None:
        cert_path = UNIFI_PATHS['eus_cert']

    if not os.path.exists(cert_path):
        return None

    try:
        meta = CertMetadata.from_cert_file(cert_path)
        if meta.cn and meta.cn != 'localhost' and not meta.cn.startswith('UniFi'):
            ui.debug(f'Auto-detected domain from certificate: {meta.cn}')
            return meta.cn
    except Exception as e:
        ui.debug(f'Failed to extract domain from certificate: {e}')

    return None


# =============================================================================
# IP LOOKUP - Multi-provider fallback
# =============================================================================

def get_public_ip(timeout: float = 2.0) -> Optional[str]:
    """Get public IP address using fallback providers."""
    import urllib.request
    import urllib.error

    for url, extractor in IP_PROVIDERS:
        try:
            ui.debug(f'Trying IP provider: {url}')
            req = urllib.request.Request(url, headers={'User-Agent': 'unifi-cert/1.0'})
            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = json.loads(response.read().decode())
                ip = extractor(data)
                if ip and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                    ui.debug(f'Got IP: {ip}')
                    return ip
        except (urllib.error.URLError, json.JSONDecodeError, KeyError, TimeoutError):
            continue
    return None


# =============================================================================
# DNS CREDENTIAL VALIDATION
# =============================================================================

def validate_dns_credentials(provider: str, creds_file: str) -> tuple[bool, str]:
    """Validate DNS credentials file format."""
    if provider not in DNS_PROVIDERS:
        return False, f"Unknown DNS provider: {provider}"

    if not os.path.exists(creds_file):
        return False, f"Credentials file not found: {creds_file}"

    config = DNS_PROVIDERS[provider]
    expected_field = config['field']

    try:
        with open(creds_file, 'r') as f:
            content = f.read()

        # Check for the correct field name
        if expected_field not in content:
            # Check if using wrong field name (common bug)
            if provider == 'digitalocean' and 'DO_AUTH_TOKEN' in content:
                return False, (
                    f"Wrong field name in credentials file.\n"
                    f"Found 'DO_AUTH_TOKEN' but certbot expects '{expected_field}'.\n"
                    f"Please update your credentials file."
                )
            return False, f"Missing required field '{expected_field}' in credentials file"

        # Check file permissions (should be 600 or 400)
        mode = os.stat(creds_file).st_mode & 0o777
        if mode not in (0o600, 0o400):
            return False, f"Insecure permissions on credentials file (mode {oct(mode)}). Use chmod 600."

        return True, "Credentials validated"
    except IOError as e:
        return False, f"Cannot read credentials file: {e}"


def create_credentials_file(provider: str, token: str, output_path: str) -> bool:
    """Create a properly formatted DNS credentials file."""
    if provider not in DNS_PROVIDERS:
        ui.error(f"Unknown DNS provider: {provider}")
        return False

    config = DNS_PROVIDERS[provider]
    field = config['field']

    content = f"# Certbot DNS {provider} credentials\n{field} = {token}\n"

    try:
        # Create directory if needed
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # Write file with secure permissions
        with open(output_path, 'w') as f:
            f.write(content)
        os.chmod(output_path, 0o600)

        ui.success(f"Created credentials file: {output_path}")
        return True
    except IOError as e:
        ui.error(f"Failed to create credentials file: {e}")
        return False


# =============================================================================
# UNIFI PLATFORM DETECTION
# =============================================================================

@dataclass
class UnifiPlatform:
    """Detected UniFi platform information."""
    device_type: str
    core_version: str
    has_eus_certs: bool
    has_postgres: bool
    active_cert_id: Optional[str]

    @classmethod
    def detect(cls) -> Optional['UnifiPlatform']:
        """Detect UniFi platform details."""
        # Check if we're on a UniFi device
        if not os.path.exists('/data/unifi-core'):
            return None

        # Get UniFi Core version
        core_version = ''
        try:
            result = subprocess.run(
                ['dpkg-query', '-W', '-f=${Version}', 'unifi-core'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                core_version = result.stdout.strip()
        except FileNotFoundError:
            pass

        # Check for EUS certificates directory
        has_eus_certs = os.path.exists(UNIFI_PATHS['eus_dir'])

        # Check for PostgreSQL
        has_postgres = shutil.which('psql') is not None

        # Get active certificate ID from settings.yaml
        active_cert_id = None
        settings_path = UNIFI_PATHS['settings_yaml']
        if os.path.exists(settings_path):
            try:
                with open(settings_path, 'r') as f:
                    for line in f:
                        if line.strip().startswith('activeCertId:'):
                            active_cert_id = line.split(':', 1)[1].strip()
                            break
            except IOError:
                pass

        # Detect device type
        device_type = 'Unknown'
        model_path = '/sys/firmware/devicetree/base/model'
        if os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    model = f.read().decode('utf-8', errors='ignore').strip('\x00')
                    if 'Dream Machine' in model:
                        device_type = 'UDM'
                    elif 'Cloud Key' in model:
                        device_type = 'CloudKey'
            except IOError:
                pass
        elif os.path.exists('/usr/lib/version'):
            device_type = 'UDM'  # Likely UDM if version file exists

        return cls(
            device_type=device_type,
            core_version=core_version,
            has_eus_certs=has_eus_certs,
            has_postgres=has_postgres,
            active_cert_id=active_cert_id,
        )


# =============================================================================
# CERTIFICATE INSTALLATION
# =============================================================================

def backup_file(path: str) -> Optional[str]:
    """Create a backup of a file."""
    if not os.path.exists(path):
        return None
    backup_path = f"{path}.bak.{datetime.now().strftime('%Y%m%d%H%M%S')}"
    try:
        shutil.copy2(path, backup_path)
        return backup_path
    except IOError:
        return None


def install_certificate(
    cert_path: str,
    key_path: str,
    domain: str,
    platform: UnifiPlatform,
    skip_postgres: bool = False,
    skip_restart: bool = False,
    dry_run: bool = False,
) -> bool:
    """Install certificate to UniFi device (dual-path: EUS + WebUI/PostgreSQL)."""

    # Read certificate and key content
    try:
        with open(cert_path, 'r') as f:
            cert_content = f.read()
        with open(key_path, 'r') as f:
            key_content = f.read()
    except IOError as e:
        ui.error(f"Cannot read certificate files: {e}")
        return False

    # Extract metadata
    ui.status("Extracting certificate metadata...")
    metadata = CertMetadata.from_cert_file(cert_path)

    ui.table([
        ('Domain', metadata.cn),
        ('Issuer', metadata.issuer_cn or metadata.issuer_o),
        ('Valid From', metadata.valid_from),
        ('Valid To', metadata.valid_to),
        ('SANs', ', '.join(metadata.sans) if metadata.sans else 'None'),
    ])

    # Generate certificate name
    cert_name = f"{datetime.now().strftime('%Y-%m')}-{domain}"

    if dry_run:
        ui.warning("DRY RUN - No changes will be made")

    # Step 1: Install to EUS path (nginx)
    if platform.has_eus_certs:
        ui.status("Installing to EUS certificates path (nginx)...")
        eus_cert = UNIFI_PATHS['eus_cert']
        eus_key = UNIFI_PATHS['eus_key']

        if not dry_run:
            # Create directory if needed
            os.makedirs(os.path.dirname(eus_cert), exist_ok=True)

            # Only copy if source and destination are different files
            if not os.path.exists(eus_cert) or not os.path.samefile(cert_path, eus_cert):
                backup_file(eus_cert)
                shutil.copy2(cert_path, eus_cert)
                os.chmod(eus_cert, 0o644)
            else:
                ui.debug("Source and destination are same file, skipping copy")

            if not os.path.exists(eus_key) or not os.path.samefile(key_path, eus_key):
                backup_file(eus_key)
                shutil.copy2(key_path, eus_key)
                os.chmod(eus_key, 0o644)
            else:
                ui.debug("Source and destination are same file, skipping copy")

        ui.success(f"EUS certificates: {eus_cert}")

    # Step 2: Install to UUID path (WebUI)
    cert_id = platform.active_cert_id
    if not cert_id:
        cert_id = str(uuid.uuid4()).lower()
        ui.info(f"No active certificate ID found, generated new: {cert_id}")

    uuid_cert = os.path.join(UNIFI_PATHS['config_dir'], f'{cert_id}.crt')
    uuid_key = os.path.join(UNIFI_PATHS['config_dir'], f'{cert_id}.key')

    ui.status(f"Installing to WebUI path ({cert_id[:8]}...)...")
    if not dry_run:
        # Only copy if source and destination are different files
        if not os.path.exists(uuid_cert) or not os.path.samefile(cert_path, uuid_cert):
            backup_file(uuid_cert)
            shutil.copy2(cert_path, uuid_cert)
            os.chmod(uuid_cert, 0o644)
        else:
            ui.debug("Source and destination are same file, skipping copy")

        if not os.path.exists(uuid_key) or not os.path.samefile(key_path, uuid_key):
            backup_file(uuid_key)
            shutil.copy2(key_path, uuid_key)
            os.chmod(uuid_key, 0o644)
        else:
            ui.debug("Source and destination are same file, skipping copy")

    ui.success(f"WebUI certificates: {uuid_cert}")

    # Step 3: Update settings.yaml if new cert ID
    if not platform.active_cert_id:
        ui.status("Updating settings.yaml with new certificate ID...")
        settings_path = UNIFI_PATHS['settings_yaml']
        if not dry_run and os.path.exists(settings_path):
            try:
                with open(settings_path, 'r') as f:
                    content = f.read()

                if 'activeCertId:' in content:
                    content = re.sub(r'^activeCertId:.*$', f'activeCertId: {cert_id}',
                                   content, flags=re.MULTILINE)
                else:
                    content += f'\nactiveCertId: {cert_id}\n'

                with open(settings_path, 'w') as f:
                    f.write(content)
                ui.success("Updated settings.yaml")
            except IOError as e:
                ui.warning(f"Could not update settings.yaml: {e}")

    # Step 4: Update PostgreSQL
    if platform.has_postgres and not skip_postgres:
        ui.status("Updating PostgreSQL certificate database...")
        if not dry_run:
            success = update_postgres(cert_id, cert_name, cert_content, key_content, metadata)
            if success:
                ui.success("PostgreSQL updated")
            else:
                ui.warning("PostgreSQL update may have had issues")
    elif skip_postgres:
        ui.info("Skipping PostgreSQL update (--skip-postgres)")

    # Step 5: Restart services
    if not skip_restart:
        ui.status("Restarting services...")
        if not dry_run:
            restart_services()
            ui.success("Services restarted")
    else:
        ui.info("Skipping service restart (--skip-restart)")

    return True


def update_postgres(
    cert_id: str,
    name: str,
    cert: str,
    key: str,
    meta: CertMetadata,
    is_new: bool = False,
) -> bool:
    """Update PostgreSQL user_certificates table using UPSERT."""
    # Prepare JSON fields - escape single quotes for SQL
    subject_json = json.dumps({'CN': meta.cn}).replace("'", "''")
    issuer_json = json.dumps({'C': meta.issuer_c, 'O': meta.issuer_o, 'CN': meta.issuer_cn}).replace("'", "''")
    sans_json = json.dumps({'DNS': meta.sans}).replace("'", "''")

    # Escape name for SQL
    name_escaped = name.replace("'", "''")

    # Use UPSERT to handle both insert and update cases
    # This avoids issues where settings.yaml has an ID but PostgreSQL row was deleted
    sql = f"""
INSERT INTO user_certificates (id, name, cert, key, subject, issuer, subject_alt_name, valid_from, valid_to, serial_number, fingerprint, version, created_at, updated_at)
VALUES (
    '{cert_id}',
    '{name_escaped}',
    $cert${cert}$cert$,
    $key${key}$key$,
    '{subject_json}',
    '{issuer_json}',
    '{sans_json}',
    '{meta.valid_from}',
    '{meta.valid_to}',
    '{meta.serial}',
    '{meta.fingerprint}',
    3,
    NOW(),
    NOW()
)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    cert = EXCLUDED.cert,
    key = EXCLUDED.key,
    subject = EXCLUDED.subject,
    issuer = EXCLUDED.issuer,
    subject_alt_name = EXCLUDED.subject_alt_name,
    valid_from = EXCLUDED.valid_from,
    valid_to = EXCLUDED.valid_to,
    serial_number = EXCLUDED.serial_number,
    fingerprint = EXCLUDED.fingerprint,
    updated_at = NOW();
"""

    try:
        result = subprocess.run(
            ['psql', '-U', 'unifi-core', '-d', 'unifi-core', '-c', sql],
            capture_output=True, text=True
        )
        return result.returncode == 0
    except FileNotFoundError:
        ui.error("psql not found")
        return False


def restart_services() -> None:
    """Restart UniFi services."""
    services = ['nginx', 'unifi-core']
    for service in services:
        try:
            subprocess.run(['systemctl', 'restart', service],
                         capture_output=True, check=False)
        except FileNotFoundError:
            pass


# =============================================================================
# CERTBOT INTEGRATION
# =============================================================================

def run_certbot(
    domain: str,
    email: str,
    dns_provider: str,
    dns_credentials: str,
    propagation: int = 60,
    dry_run: bool = False,
    force: bool = False,
) -> tuple[bool, str, str]:
    """Run certbot to obtain/renew a certificate.

    Returns: (success, cert_path, key_path)
    """
    config = DNS_PROVIDERS.get(dns_provider)
    if not config:
        ui.error(f"Unknown DNS provider: {dns_provider}")
        return False, '', ''

    # Build certbot command
    cmd = [
        'certbot', 'certonly',
        f'--dns-{dns_provider}',
        f'--dns-{dns_provider}-credentials', dns_credentials,
        f'--dns-{dns_provider}-propagation-seconds', str(propagation),
        '--domain', domain,
        '--email', email,
        '--agree-tos',
        '--non-interactive',
    ]

    if dry_run:
        cmd.append('--dry-run')

    if force:
        cmd.append('--force-renewal')

    ui.status(f"Running certbot for {domain}...")
    ui.debug(f"Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            ui.error(f"Certbot failed: {result.stderr}")
            return False, '', ''
    except FileNotFoundError:
        ui.error("certbot not found. Please install certbot and the DNS plugin.")
        return False, '', ''

    # Find certificate files
    live_dir = f'/etc/letsencrypt/live/{domain}'
    cert_path = os.path.join(live_dir, 'fullchain.pem')
    key_path = os.path.join(live_dir, 'privkey.pem')

    if dry_run:
        ui.success("Certbot dry-run completed successfully")
        return True, '', ''

    if os.path.exists(cert_path) and os.path.exists(key_path):
        ui.success(f"Certificate obtained: {cert_path}")
        return True, cert_path, key_path
    else:
        ui.error(f"Certificate files not found at {live_dir}")
        return False, '', ''


def setup_renewal_hook(domain: str, script_path: str) -> bool:
    """Set up certbot renewal hook."""
    hook_dir = '/etc/letsencrypt/renewal-hooks/post'
    hook_path = os.path.join(hook_dir, 'unifi-cert-hook.sh')

    hook_content = f"""#!/bin/bash
# UniFi Certificate renewal hook
# Auto-generated by unifi-cert.py

RENEWED_DOMAINS="${{RENEWED_DOMAINS:-{domain}}}"

/usr/bin/python3 {script_path} --renew --domain "$RENEWED_DOMAINS"
"""

    try:
        os.makedirs(hook_dir, exist_ok=True)
        with open(hook_path, 'w') as f:
            f.write(hook_content)
        os.chmod(hook_path, 0o755)
        ui.success(f"Created renewal hook: {hook_path}")
        return True
    except IOError as e:
        ui.error(f"Failed to create renewal hook: {e}")
        return False


# =============================================================================
# REMOTE SSH OPERATIONS
# =============================================================================

def run_remote(host: str, command: str, timeout: int = 30) -> tuple[bool, str]:
    """Run a command on a remote host via SSH."""
    try:
        result = subprocess.run(
            ['ssh', '-o', 'ConnectTimeout=5', '-o', 'BatchMode=yes',
             f'root@{host}', command],
            capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, result.stdout
    except subprocess.TimeoutExpired:
        return False, 'Timeout'
    except FileNotFoundError:
        return False, 'SSH not found'


def scp_file(local_path: str, host: str, remote_path: str) -> bool:
    """Copy a file to a remote host via SCP."""
    try:
        result = subprocess.run(
            ['scp', '-q', local_path, f'root@{host}:{remote_path}'],
            capture_output=True, timeout=60
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def install_certificate_remote(
    cert_path: str,
    key_path: str,
    domain: str,
    host: str,
    skip_postgres: bool = False,
    skip_restart: bool = False,
    dry_run: bool = False,
) -> bool:
    """Install certificate to a remote UniFi device via SSH."""

    # Test SSH connection
    ui.status(f"Connecting to {host}...")
    success, _ = run_remote(host, 'true')
    if not success:
        ui.error(f"Cannot connect to {host} via SSH. Make sure SSH is enabled and your key is authorized.")
        return False
    ui.success(f"Connected to {host}")

    # Get platform info from remote
    ui.status("Detecting UniFi platform...")
    success, output = run_remote(host, f"grep 'activeCertId:' {UNIFI_PATHS['settings_yaml']} 2>/dev/null | awk '{{print $2}}'")
    active_cert_id = output.strip() if success and output.strip() else None

    success, _ = run_remote(host, f"test -d {UNIFI_PATHS['eus_dir']}")
    has_eus = success

    success, _ = run_remote(host, "which psql")
    has_postgres = success

    ui.table([
        ('Active Cert ID', active_cert_id or 'None (will create)'),
        ('Has EUS Certs', 'Yes' if has_eus else 'No'),
        ('Has PostgreSQL', 'Yes' if has_postgres else 'No'),
    ])

    # Generate cert name
    cert_name = f"{datetime.now().strftime('%Y-%m')}-{domain}"

    # Get or generate certificate ID
    cert_id = active_cert_id
    if not cert_id:
        cert_id = str(uuid.uuid4()).lower()
        ui.info(f"Generated new certificate ID: {cert_id}")

    if dry_run:
        ui.warning("DRY RUN - No changes will be made")
        return True

    # Read local certificate content
    with open(cert_path, 'r') as f:
        cert_content = f.read()
    with open(key_path, 'r') as f:
        key_content = f.read()

    # Extract metadata
    metadata = CertMetadata.from_cert_file(cert_path)

    # Upload to EUS path
    if has_eus:
        ui.status("Uploading to EUS certificates path...")
        if not scp_file(cert_path, host, UNIFI_PATHS['eus_cert']):
            ui.error("Failed to upload EUS certificate")
            return False
        if not scp_file(key_path, host, UNIFI_PATHS['eus_key']):
            ui.error("Failed to upload EUS key")
            return False
        ui.success("EUS certificates uploaded")

    # Upload to UUID path
    remote_cert = os.path.join(UNIFI_PATHS['config_dir'], f'{cert_id}.crt')
    remote_key = os.path.join(UNIFI_PATHS['config_dir'], f'{cert_id}.key')

    ui.status("Uploading to WebUI path...")
    if not scp_file(cert_path, host, remote_cert):
        ui.error("Failed to upload WebUI certificate")
        return False
    if not scp_file(key_path, host, remote_key):
        ui.error("Failed to upload WebUI key")
        return False
    ui.success("WebUI certificates uploaded")

    # Update settings.yaml if new cert
    if not active_cert_id:
        ui.status("Updating settings.yaml...")
        cmd = f"grep -q 'activeCertId:' {UNIFI_PATHS['settings_yaml']} && " \
              f"sed -i 's/^activeCertId:.*/activeCertId: {cert_id}/' {UNIFI_PATHS['settings_yaml']} || " \
              f"echo 'activeCertId: {cert_id}' >> {UNIFI_PATHS['settings_yaml']}"
        run_remote(host, cmd)
        ui.success("Updated settings.yaml")

    # Update PostgreSQL
    if has_postgres and not skip_postgres:
        ui.status("Updating PostgreSQL...")
        subject_json = json.dumps({'CN': metadata.cn}).replace("'", "''")
        issuer_json = json.dumps({'C': metadata.issuer_c, 'O': metadata.issuer_o, 'CN': metadata.issuer_cn}).replace("'", "''")
        sans_json = json.dumps({'DNS': metadata.sans}).replace("'", "''")

        if active_cert_id:
            sql = f"""
UPDATE user_certificates
SET
    name = '{cert_name}',
    cert = $cert${cert_content}$cert$,
    key = $key${key_content}$key$,
    subject = '{subject_json}',
    issuer = '{issuer_json}',
    subject_alt_name = '{sans_json}',
    valid_from = '{metadata.valid_from}',
    valid_to = '{metadata.valid_to}',
    serial_number = '{metadata.serial}',
    fingerprint = '{metadata.fingerprint}',
    updated_at = NOW()
WHERE id = '{cert_id}';
"""
        else:
            sql = f"""
INSERT INTO user_certificates (id, name, cert, key, subject, issuer, subject_alt_name, valid_from, valid_to, serial_number, fingerprint, version, created_at, updated_at)
VALUES (
    '{cert_id}',
    '{cert_name}',
    $cert${cert_content}$cert$,
    $key${key_content}$key$,
    '{subject_json}',
    '{issuer_json}',
    '{sans_json}',
    '{metadata.valid_from}',
    '{metadata.valid_to}',
    '{metadata.serial}',
    '{metadata.fingerprint}',
    3,
    NOW(),
    NOW()
);
"""

        # Write SQL to temp file and execute remotely
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sql', delete=False) as f:
            f.write(sql)
            sql_file = f.name

        try:
            remote_sql = '/tmp/unifi-cert-update.sql'
            scp_file(sql_file, host, remote_sql)
            success, output = run_remote(host, f"psql -U unifi-core -d unifi-core -f {remote_sql}")
            run_remote(host, f"rm -f {remote_sql}")
            if success:
                ui.success("PostgreSQL updated")
            else:
                ui.warning(f"PostgreSQL update may have had issues: {output}")
        finally:
            os.unlink(sql_file)
    elif skip_postgres:
        ui.info("Skipping PostgreSQL update (--skip-postgres)")

    # Restart services
    if not skip_restart:
        ui.status("Restarting services...")
        run_remote(host, "systemctl restart unifi-core")
        ui.success("Services restarted")
    else:
        ui.info("Skipping service restart (--skip-restart)")

    return True


# =============================================================================
# CLI & MAIN
# =============================================================================

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='UniFi Certificate Manager - Manage Let\'s Encrypt certificates on UniFi OS devices',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (prompts for missing info)
  %(prog)s

  # Obtain and install certificate
  %(prog)s -d example.com -e admin@example.com \\
    --dns-provider digitalocean --dns-credentials ~/.secrets/do.ini

  # Install existing certificate
  %(prog)s --install --cert /path/to/cert.pem --key /path/to/key.pem -d example.com

  # Install to remote UniFi device
  %(prog)s --install --cert cert.pem --key key.pem -d example.com --host 192.168.1.1

  # Renew existing certificate
  %(prog)s --renew -d example.com

  # Curl-pipe usage
  curl -sL https://raw.githubusercontent.com/jdlien/unifi-cert/main/unifi-cert.py | python3 - --help
"""
    )

    # Domain and email
    parser.add_argument('-d', '--domain', help='Domain name for certificate')
    parser.add_argument('-e', '--email', help='Email for Let\'s Encrypt')

    # DNS provider options
    parser.add_argument('--dns-provider',
                       choices=list(DNS_PROVIDERS.keys()),
                       help='DNS provider for ACME challenge')
    parser.add_argument('--dns-credentials', help='Path to DNS credentials file')
    parser.add_argument('--propagation', type=int, default=60,
                       help='DNS propagation wait time in seconds (default: 60)')

    # Installation options
    parser.add_argument('--install', action='store_true',
                       help='Install existing certificate (requires --cert and --key)')
    parser.add_argument('--cert', help='Path to certificate file')
    parser.add_argument('--key', help='Path to private key file')

    # Remote options
    parser.add_argument('--host', help='Remote UniFi host (IP or hostname) for SSH installation')

    # Renewal options
    parser.add_argument('--renew', action='store_true',
                       help='Renew existing certificate')
    parser.add_argument('--setup-hook', action='store_true',
                       help='Set up certbot renewal hook only')

    # Operation modifiers
    parser.add_argument('--dry-run', action='store_true',
                       help='Test without making changes')
    parser.add_argument('--force', action='store_true',
                       help='Force renewal even if not due')
    parser.add_argument('--skip-postgres', action='store_true',
                       help='Skip PostgreSQL update')
    parser.add_argument('--skip-restart', action='store_true',
                       help='Skip service restart')

    # Output options
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--no-color', action='store_true',
                       help='Disable colored output')

    return parser.parse_args()


def interactive_mode() -> dict:
    """Gather configuration interactively."""
    config = {}

    ui.header('UniFi Certificate Manager')
    print()

    # Try to auto-detect domain from existing certificate
    detected_domain = detect_domain_from_cert()
    eus_cert = UNIFI_PATHS['eus_cert']
    eus_key = UNIFI_PATHS['eus_key']
    has_existing_eus = os.path.exists(eus_cert) and os.path.exists(eus_key)

    # If we have an existing certificate, offer streamlined options
    if detected_domain and has_existing_eus:
        ui.success(f'Found existing certificate for: {detected_domain}')
        print()
        choice = ui.select('What would you like to do?', [
            'Sync existing certificate to WebUI (fixes UI showing wrong cert info)',
            'Renew/obtain new certificate via Let\'s Encrypt',
            'Install a different certificate file',
        ])

        if choice == 0:
            # Sync existing cert to WebUI
            config['domain'] = detected_domain
            config['install'] = True
            config['cert'] = eus_cert
            config['key'] = eus_key
            return config
        elif choice == 1:
            # Renew via certbot - continue with normal flow
            config['domain'] = detected_domain
            config['install'] = False
        else:
            # Install different cert
            config['domain'] = ui.prompt('Domain name', default=detected_domain)
            config['install'] = True
            config['cert'] = ui.prompt('Certificate file path')
            config['key'] = ui.prompt('Private key file path')
            return config
    else:
        # No existing cert - ask for domain
        config['domain'] = ui.prompt('Domain name', default=detected_domain)
        if not config['domain']:
            ui.error('Domain is required')
            sys.exit(1)

        # Check if installing existing cert or obtaining new
        has_cert = ui.confirm('Do you have an existing certificate to install?', default=False)

        if has_cert:
            config['install'] = True
            config['cert'] = ui.prompt('Certificate file path')
            config['key'] = ui.prompt('Private key file path')
            return config
        else:
            config['install'] = False

    # Getting new cert via certbot - need email and DNS provider
    config['email'] = ui.prompt('Email for Let\'s Encrypt')

    # DNS provider selection
    providers = list(DNS_PROVIDERS.keys())
    idx = ui.select('Select DNS provider:', providers)
    config['dns_provider'] = providers[idx]

    # Credentials
    default_creds = os.path.expanduser(f'~/.secrets/certbot/{config["dns_provider"]}.ini')
    config['dns_credentials'] = ui.prompt('DNS credentials file', default=default_creds)

    # Check if credentials exist, offer to create
    if not os.path.exists(config['dns_credentials']):
        if ui.confirm(f'Credentials file not found. Create it?'):
            field = DNS_PROVIDERS[config['dns_provider']]['field']
            token = ui.prompt(f'Enter your {config["dns_provider"]} API token ({field})')
            create_credentials_file(config['dns_provider'], token, config['dns_credentials'])

    # Remote or local installation
    platform = UnifiPlatform.detect()
    if platform:
        ui.info(f'Detected local UniFi device: {platform.device_type}')
        config['host'] = None
    else:
        if ui.confirm('Install to a remote UniFi device?'):
            config['host'] = ui.prompt('Remote host (IP or hostname)', default='192.168.1.1')
        else:
            config['host'] = None

    return config


def main() -> int:
    """Main entry point."""
    global ui

    args = parse_args()
    ui = UI(color=not args.no_color, verbose=args.verbose)

    ui.header('UniFi Certificate Manager')

    # Determine if we should run interactive mode
    # Run interactive if: TTY available (check stdout since stdin may be pipe from curl),
    # not --install, not --setup-hook, and missing required args for certbot
    needs_interactive = (
        sys.stdout.isatty() and
        not args.install and
        not args.setup_hook and
        (not args.domain or not args.email or not args.dns_provider)
    )

    if needs_interactive:
        config = interactive_mode()
        args.domain = config.get('domain')
        args.email = config.get('email')
        args.dns_provider = config.get('dns_provider')
        args.dns_credentials = config.get('dns_credentials')
        args.install = config.get('install', False)
        args.cert = config.get('cert')
        args.key = config.get('key')
        args.host = config.get('host')

    # Auto-detect domain from existing certificate if not specified
    if not args.domain and not args.setup_hook:
        # For --install with a cert file, try to detect from that cert
        if args.install and args.cert and os.path.exists(args.cert):
            detected = detect_domain_from_cert(args.cert)
            if detected:
                ui.info(f'Auto-detected domain from certificate: {detected}')
                args.domain = detected
        # For local installations, try the EUS cert
        elif not args.host:
            detected = detect_domain_from_cert()
            if detected:
                ui.info(f'Auto-detected domain from existing certificate: {detected}')
                args.domain = detected

    # Validate required args (after auto-detection attempt)
    if not args.domain and not args.setup_hook:
        ui.error('Domain is required. Use -d/--domain or run interactively.')
        ui.info('Tip: If a certificate is already installed, the domain can be auto-detected.')
        return 1

    # Setup renewal hook only
    if args.setup_hook:
        script_path = os.path.abspath(__file__)
        if setup_renewal_hook(args.domain or 'example.com', script_path):
            ui.success('Renewal hook configured')
            return 0
        return 1

    # Install existing certificate
    if args.install:
        if not args.cert or not args.key:
            ui.error('--install requires --cert and --key')
            return 1

        if not os.path.exists(args.cert):
            ui.error(f'Certificate file not found: {args.cert}')
            return 1
        if not os.path.exists(args.key):
            ui.error(f'Key file not found: {args.key}')
            return 1

        # Remote or local installation
        if args.host:
            success = install_certificate_remote(
                args.cert, args.key, args.domain, args.host,
                skip_postgres=args.skip_postgres,
                skip_restart=args.skip_restart,
                dry_run=args.dry_run,
            )
        else:
            platform = UnifiPlatform.detect()
            if not platform:
                ui.error('Not running on a UniFi device. Use --host for remote installation.')
                return 1

            success = install_certificate(
                args.cert, args.key, args.domain, platform,
                skip_postgres=args.skip_postgres,
                skip_restart=args.skip_restart,
                dry_run=args.dry_run,
            )

        if success:
            ui.header('Installation Complete')
            ui.success(f'Certificate for {args.domain} installed successfully!')
            ui.info(f'Verify by visiting https://{args.host or "localhost"}')
            return 0
        return 1

    # Obtain new certificate with certbot
    if not args.email:
        ui.error('Email is required for obtaining new certificates. Use -e/--email.')
        return 1

    if not args.dns_provider:
        ui.error('DNS provider is required. Use --dns-provider.')
        return 1

    # Auto-detect credentials from default location if not specified
    if not args.dns_credentials:
        default_creds = os.path.expanduser(f'~/.secrets/certbot/{args.dns_provider}.ini')
        if os.path.exists(default_creds):
            ui.info(f'Using credentials from: {default_creds}')
            args.dns_credentials = default_creds
        else:
            ui.error('DNS credentials file is required. Use --dns-credentials.')
            ui.info(f'Tip: Create {default_creds} with your API token.')
            return 1

    # Validate credentials
    valid, msg = validate_dns_credentials(args.dns_provider, args.dns_credentials)
    if not valid:
        ui.error(msg)
        return 1

    # Run certbot
    success, cert_path, key_path = run_certbot(
        args.domain,
        args.email,
        args.dns_provider,
        args.dns_credentials,
        propagation=args.propagation,
        dry_run=args.dry_run,
        force=args.force,
    )

    if not success:
        return 1

    if args.dry_run:
        ui.success('Dry run completed successfully')
        return 0

    # Install the obtained certificate
    if args.host:
        success = install_certificate_remote(
            cert_path, key_path, args.domain, args.host,
            skip_postgres=args.skip_postgres,
            skip_restart=args.skip_restart,
            dry_run=args.dry_run,
        )
    else:
        platform = UnifiPlatform.detect()
        if platform:
            success = install_certificate(
                cert_path, key_path, args.domain, platform,
                skip_postgres=args.skip_postgres,
                skip_restart=args.skip_restart,
                dry_run=args.dry_run,
            )
        else:
            ui.warning('Not running on a UniFi device. Certificate obtained but not installed.')
            ui.info(f'Certificate: {cert_path}')
            ui.info(f'Key: {key_path}')
            ui.info('Use --host to install to a remote device.')
            return 0

    if success:
        ui.header('Complete')
        ui.success(f'Certificate for {args.domain} obtained and installed!')
        ui.table([
            ('Certificate', cert_path),
            ('Key', key_path),
        ])
        return 0
    return 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('\nCancelled')
        sys.exit(130)
