#!/usr/bin/env python3
"""
UniFi Certificate Manager

A clean, maintainable tool for managing Let's Encrypt SSL certificates on UniFi OS devices.
Fixes known bugs in GlennR's script and adds proper WebUI/PostgreSQL integration.

Author: jdlien
License: MIT
"""

import argparse
import fcntl
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

# UniFi Core (Node.js, port 443 nginx) override + nginx local-cert config:
# GlennR's installer writes a YAML override at UNIFI_CORE_OVERRIDE that
# repoints unifi-core's `ssl.crt` and `ssl.key` to /data/eus_certificates/.
# On UniFi OS 5.x, unifi-core computes the active UUID cert path from
# dirname(E.ssl.crt), so the override breaks WebUI cert lookup — port 443
# falls back to a self-signed unifi.local cert. Removing the override lets
# unifi-core resolve the active cert correctly via /data/unifi-core/config/.
UNIFI_CORE_OVERRIDE = '/data/unifi-core/config/overrides/local.yml'
UNIFI_CORE_LOCAL_CERTS_CONF = '/data/unifi-core/config/http/local-certs.conf'

# UniFi Network (Java, port 8443) keystore. Despite the .keystore extension
# this is a PKCS#12 file (verified on UDM Pro: magic bytes 30 82, openssl
# pkcs12 reads it cleanly). We can replace it with `openssl pkcs12 -export`,
# no JDK / keytool / pyjks required.
UNIFI_NETWORK_KEYSTORE = '/usr/lib/unifi/data/keystore'
UNIFI_NETWORK_KEYSTORE_PASS = 'aircontrolenterprise'  # well-known UniFi default
UNIFI_NETWORK_KEYSTORE_ALIAS = 'unifi'

# Persistent product root - everything the tool owns lives under /data so it
# survives UniFi OS firmware updates (which wipe non-/data paths).
UNIFI_CERT_ROOT = '/data/unifi-cert'
CERTBOT_VENV = f'{UNIFI_CERT_ROOT}/certbot-venv'
CERTBOT_BIN = f'{CERTBOT_VENV}/bin/certbot'
CERTBOT_PIP = f'{CERTBOT_VENV}/bin/pip'
CERTBOT_PYTHON = f'{CERTBOT_VENV}/bin/python'
CERTBOT_CONFIG_DIR = f'{UNIFI_CERT_ROOT}/letsencrypt'
CERTBOT_WORK_DIR = f'{UNIFI_CERT_ROOT}/work'
CERTBOT_LOGS_DIR = f'{UNIFI_CERT_ROOT}/logs'
WHEELS_DIR = f'{UNIFI_CERT_ROOT}/wheels'
BACKUPS_DIR = f'{UNIFI_CERT_ROOT}/backups'
CREDENTIALS_DIR = f'{UNIFI_CERT_ROOT}/credentials'
LOG_FILE = f'{UNIFI_CERT_ROOT}/unifi-cert.log'
LOCK_FILE = f'{UNIFI_CERT_ROOT}/unifi-cert.lock'
PROVISIONING_CONFIG = f'{UNIFI_CERT_ROOT}/unifi-cert.conf'

# apt prerequisites for the bootstrap path. UDM Pro firmware ships python3 but
# strips python3-pip / python3-venv / python3-distutils; bootstrap re-installs
# them and re-asserts on every boot via self-heal.
APT_PREREQS = ('python3-pip', 'python3-venv', 'python3-distutils')

# Config file for persisting user preferences
CONFIG_FILE = os.path.expanduser('~/.secrets/certbot/config.ini')

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
        self._tty = None  # For reading input when stdin is a pipe

    def _input(self, prompt: str) -> str:
        """Read input from user, using /dev/tty if stdin is a pipe (e.g., curl | python)."""
        print(prompt, end='', flush=True)
        if sys.stdin.isatty():
            return input().strip()
        else:
            # stdin is a pipe, read from /dev/tty directly
            if self._tty is None:
                try:
                    self._tty = open('/dev/tty', 'r', encoding='utf-8')
                except OSError:
                    # No TTY available (e.g., in tests or non-interactive environment)
                    raise EOFError("No TTY available for input")
            return self._tty.readline().strip()

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
        value = self._input(self._c(self.YELLOW, '? ') + prompt_text)
        return value if value else (default or '')

    def confirm(self, text: str, default: bool = True) -> bool:
        """Prompt user for yes/no confirmation."""
        suffix = '[Y/n]' if default else '[y/N]'
        response = self._input(self._c(self.YELLOW, '? ') + f'{text} {suffix}: ').lower()
        if not response:
            return default
        return response in ('y', 'yes')

    def select(self, text: str, options: list[str], default: int = None) -> int:
        """Prompt user to select from options. Default is 0-indexed."""
        print(self._c(self.YELLOW, '? ') + text)
        for i, opt in enumerate(options, 1):
            marker = ' (default)' if default is not None and i - 1 == default else ''
            print(f'  {self._c(self.CYAN, str(i))}. {opt}{marker}')

        prompt_suffix = f' [{default + 1}]' if default is not None else ''
        while True:
            try:
                raw = self._input(self._c(self.YELLOW, f'  Enter choice{prompt_suffix}: '))
                if not raw and default is not None:
                    return default
                choice = int(raw)
                if 1 <= choice <= len(options):
                    return choice - 1
            except ValueError:
                if not raw and default is not None:
                    return default
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
# CONFIG FILE - Persists user preferences
# =============================================================================

def load_config() -> dict:
    """Load saved configuration from config file."""
    config = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        config[key.strip()] = value.strip()
        except IOError:
            pass
    return config


def save_config(email: str = None, dns_provider: str = None) -> bool:
    """Save configuration to config file."""
    # Load existing config to preserve other values
    config = load_config()

    if email:
        config['email'] = email
    if dns_provider:
        config['dns_provider'] = dns_provider

    try:
        # Ensure directory exists with secure permissions
        config_dir = os.path.dirname(CONFIG_FILE)
        os.makedirs(config_dir, mode=0o700, exist_ok=True)

        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            f.write("# UniFi Certificate Manager config\n")
            for key, value in config.items():
                f.write(f"{key} = {value}\n")
        os.chmod(CONFIG_FILE, 0o600)
        return True
    except IOError:
        return False


def save_provisioning_config(domain: str, email: str, dns_provider: str,
                              dns_credentials: str) -> bool:
    """Persist provisioning fields to PROVISIONING_CONFIG.

    Consumed by cron-fired --renew (no CLI args) so the daily renewal can
    self-configure. Stores the credentials *path*; secrets stay in the
    credentials file under CREDENTIALS_DIR (mode 0600).
    """
    try:
        os.makedirs(UNIFI_CERT_ROOT, mode=0o755, exist_ok=True)
        with open(PROVISIONING_CONFIG, 'w', encoding='utf-8') as fh:
            fh.write('# UniFi Certificate Manager provisioning config\n')
            fh.write('# Auto-generated; consumed by --renew when called without flags\n')
            fh.write(f'domain = {domain}\n')
            fh.write(f'email = {email}\n')
            fh.write(f'dns_provider = {dns_provider}\n')
            fh.write(f'dns_credentials = {dns_credentials}\n')
        os.chmod(PROVISIONING_CONFIG, 0o600)
        return True
    except OSError as e:
        ui.error(f'Failed to save provisioning config: {e}')
        return False


def load_provisioning_config() -> dict:
    """Read PROVISIONING_CONFIG (key = value lines). Returns {} if absent."""
    config = {}
    if not os.path.exists(PROVISIONING_CONFIG):
        return config
    try:
        with open(PROVISIONING_CONFIG, 'r', encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()
    except OSError:
        pass
    return config


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
        with open(creds_file, 'r', encoding='utf-8') as f:
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
        with open(output_path, 'w', encoding='utf-8') as f:
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
                with open(settings_path, 'r', encoding='utf-8') as f:
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
                    if 'Dream Machine' in model or 'UDM' in model.upper():
                        device_type = 'UDM'
                    elif 'Cloud Key' in model:
                        device_type = 'CloudKey'
                    elif 'NVR' in model or 'UNVR' in model:
                        device_type = 'NVR'
            except IOError:
                pass

        # Fallback: if still unknown but has unifi-core version file, likely a UDM
        if device_type == 'Unknown' and os.path.exists('/usr/lib/version'):
            device_type = 'UDM'

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
        with open(cert_path, 'r', encoding='utf-8') as f:
            cert_content = f.read()
        with open(key_path, 'r', encoding='utf-8') as f:
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
                with open(settings_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                if 'activeCertId:' in content:
                    content = re.sub(r'^activeCertId:.*$', f'activeCertId: {cert_id}',
                                   content, flags=re.MULTILINE)
                else:
                    content += f'\nactiveCertId: {cert_id}\n'

                with open(settings_path, 'w', encoding='utf-8') as f:
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

    # Step 5: Update UniFi Network (Java, port 8443) PKCS#12 keystore.
    # Must happen before unifi service restart so the new keystore is read
    # at startup. No-op if the device doesn't run the embedded Network
    # controller (NVR / Cloud Key without Network app).
    network_keystore_updated = install_unifi_network_keystore(
        cert_path, key_path, dry_run=dry_run,
    )

    # Step 6: Remove GlennR's `ssl:` override at /data/unifi-core/config/
    # overrides/local.yml. On UniFi OS 5.x, this override breaks unifi-core's
    # active-cert lookup and causes port 443 to fall back to a self-signed
    # `unifi.local` cert on every restart. Removing it lets unifi-core's
    # startup wire nginx to the UUID cert correctly.
    remove_glennr_ssl_override(dry_run=dry_run)

    # Step 7: Restart services. Restart the Java `unifi` Network service only
    # when its keystore was actually updated (avoids a needless ~30-60s blip
    # on the Network UI for every renewal).
    if not skip_restart:
        ui.status("Restarting services...")
        if not dry_run:
            restart_services(restart_unifi_network=network_keystore_updated)
            ui.success("Services restarted")
    else:
        ui.info("Skipping service restart (--skip-restart)")

    # Step 8: After unifi-core's restart, explicitly point nginx
    # local-certs.conf at the active UUID cert. unifi-core's own startup
    # should do this once the override is gone, but writing it here makes
    # renewals self-healing across future unifi-core internal changes.
    if not skip_restart:
        ensure_nginx_uses_active_cert(cert_id, dry_run=dry_run)

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


def remove_glennr_ssl_override(dry_run: bool = False) -> bool:
    """
    Remove GlennR's UniFi Core SSL override that repoints `ssl.crt`/`ssl.key`
    to /data/eus_certificates/.

    The override is conservative: only the ssl: stanza is removed, only when
    it actually points at the EUS path. If the override file ends up empty
    after removal, it's deleted. Other YAML keys in the override file are
    preserved.
    """
    path = UNIFI_CORE_OVERRIDE
    if not os.path.exists(path):
        return True

    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
    except IOError as e:
        ui.warning(f"Could not read {path}: {e}")
        return False

    if '/data/eus_certificates/unifi-os.crt' not in content:
        # Override exists but doesn't reference the EUS cert path — leave alone.
        return True

    if dry_run:
        ui.info(f"Would remove GlennR UniFi Core SSL override: {path}")
        return True

    backup_file(path)

    # Strip the ssl: top-level stanza and its crt/key children. Match either
    # tabs or spaces for indentation; tolerate trailing whitespace; preserve
    # any other top-level YAML keys present in the file.
    remaining = re.sub(
        r'(?ms)^ssl:\n(?:[ \t]+(?:crt|key):[^\n]*\n?)+',
        '',
        content,
    ).strip()

    try:
        if remaining:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(remaining + '\n')
        else:
            os.unlink(path)
    except IOError as e:
        ui.warning(f"Could not write/remove {path}: {e}")
        return False

    ui.success(f"Removed GlennR UniFi Core SSL override")
    return True


def ensure_nginx_uses_active_cert(cert_id: str, dry_run: bool = False) -> bool:
    """
    Write `/data/unifi-core/config/http/local-certs.conf` so nginx serves the
    active UUID cert on port 443.

    With GlennR's override removed, unifi-core's startup writes this file via
    its `cy()` path resolving the active cert from settings.yaml. We do an
    explicit post-restart write as a belt-and-suspenders so renewals are
    self-healing even if startup timing or unifi-core internals shift in a
    future version.
    """
    cert = os.path.join(UNIFI_PATHS['config_dir'], f'{cert_id}.crt')
    key = os.path.join(UNIFI_PATHS['config_dir'], f'{cert_id}.key')
    content = f"\nssl_certificate     {cert};\nssl_certificate_key {key};\n"

    if dry_run:
        ui.info(f"Would point nginx local-certs.conf at {cert_id[:8]}...")
        return True

    try:
        os.makedirs(os.path.dirname(UNIFI_CORE_LOCAL_CERTS_CONF), exist_ok=True)
        with open(UNIFI_CORE_LOCAL_CERTS_CONF, 'w', encoding='utf-8') as f:
            f.write(content)
    except IOError as e:
        ui.warning(f"Could not update {UNIFI_CORE_LOCAL_CERTS_CONF}: {e}")
        return False

    # Reload nginx so the new config takes effect without dropping connections.
    try:
        subprocess.run(['nginx', '-s', 'reload'], capture_output=True, check=False, timeout=10)
    except (subprocess.TimeoutExpired, OSError):
        pass

    ui.success(f"nginx local-certs.conf points at {cert_id[:8]}...")
    return True


def install_unifi_network_keystore(
    cert_path: str, key_path: str, dry_run: bool = False,
) -> bool:
    """
    Replace the UniFi Network (Java, port 8443) keystore with a PKCS#12
    bundle of the new cert + key.

    The keystore is an unsigned PKCS#12 (NOT JKS — verified by magic bytes
    30 82 and `openssl pkcs12 -info`). Using `openssl pkcs12 -export`
    avoids any JDK / keytool / pyjks dependency, which is critical because
    apt-installed packages get wiped by UniFi OS firmware updates.

    Returns True iff the keystore was actually written (caller uses this
    to decide whether to restart the unifi service). Returns True on dry
    run as well, but no file is touched.

    No-op when /usr/lib/unifi/data/ doesn't exist (i.e., on a UDM device
    that isn't running the embedded UniFi Network controller).
    """
    if not os.path.isdir('/usr/lib/unifi/data'):
        return False

    if dry_run:
        ui.info(f"Would update UniFi Network keystore: {UNIFI_NETWORK_KEYSTORE}")
        return True

    # Backup existing keystore under /data/unifi-cert/backups/network-keystore/
    # so a bad export is recoverable. Persistent location, not /tmp.
    backup_dir = os.path.join(BACKUPS_DIR, 'network-keystore')
    try:
        os.makedirs(backup_dir, mode=0o755, exist_ok=True)
    except OSError as e:
        ui.warning(f"Could not create keystore backup dir: {e}")
        # Continue anyway — backups are nice-to-have, not blocking.

    if os.path.exists(UNIFI_NETWORK_KEYSTORE):
        backup_path = os.path.join(
            backup_dir,
            f'keystore.{datetime.now().strftime("%Y%m%d%H%M%S")}',
        )
        try:
            shutil.copy2(UNIFI_NETWORK_KEYSTORE, backup_path)
        except IOError as e:
            ui.warning(f"Could not back up existing keystore: {e}")

    # Build the new PKCS#12. Write to a temp file in UNIFI_CERT_ROOT (same
    # filesystem) so the final atomic move can't cross devices.
    try:
        os.makedirs(UNIFI_CERT_ROOT, mode=0o755, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            dir=UNIFI_CERT_ROOT, prefix='keystore.', delete=False,
        ) as tmp:
            tmp_path = tmp.name
    except OSError as e:
        ui.warning(f"Could not create temp file for keystore: {e}")
        return False

    try:
        result = subprocess.run([
            'openssl', 'pkcs12', '-export',
            '-inkey', key_path,
            '-in', cert_path,
            '-out', tmp_path,
            '-name', UNIFI_NETWORK_KEYSTORE_ALIAS,
            '-password', f'pass:{UNIFI_NETWORK_KEYSTORE_PASS}',
            '-keypbe', 'AES-256-CBC',
            '-certpbe', 'AES-256-CBC',
            '-macalg', 'sha256',
        ], capture_output=True, text=True, timeout=30)
    except (subprocess.TimeoutExpired, OSError) as e:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        ui.warning(f"openssl pkcs12 -export errored: {e}")
        return False

    if result.returncode != 0:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        ui.warning(f"openssl pkcs12 -export failed: {result.stderr.strip()}")
        return False

    try:
        shutil.move(tmp_path, UNIFI_NETWORK_KEYSTORE)
        try:
            shutil.chown(UNIFI_NETWORK_KEYSTORE, user='unifi', group='unifi')
        except (LookupError, PermissionError):
            # Owner group may not exist on some devices; not fatal.
            pass
        os.chmod(UNIFI_NETWORK_KEYSTORE, 0o644)
    except (IOError, OSError) as e:
        ui.warning(f"Could not install keystore at {UNIFI_NETWORK_KEYSTORE}: {e}")
        return False

    ui.success(f"Updated UniFi Network keystore: {UNIFI_NETWORK_KEYSTORE}")
    return True


def restart_services(restart_unifi_network: bool = False) -> None:
    """Restart UniFi services.

    Always restarts nginx and unifi-core (they pick up the new active cert
    from settings.yaml + the http/local-certs.conf). Restarts the Java
    `unifi` Network service only when its keystore was updated, since that
    restart takes ~30-60s and would needlessly blip the Network UI on
    every renewal that doesn't touch the keystore (e.g., remote-only
    deploys or NVR devices).
    """
    services = ['nginx', 'unifi-core']
    if restart_unifi_network:
        services.append('unifi')
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

    # Ensure certbot is bootstrapped (idempotent, fast no-op when healthy).
    bootstrap_ok, bootstrap_msg = bootstrap_certbot(dns_provider)
    if not bootstrap_ok:
        ui.error(f"certbot bootstrap failed: {bootstrap_msg}")
        return False, '', ''

    certbot = resolve_certbot_bin()

    # Build certbot command. certbot_argv_base() prepends --config-dir / --work-dir /
    # --logs-dir flags so all certbot state lives under /data/unifi-cert/.
    cmd = [certbot, *certbot_argv_base(), 'certonly',
           f'--dns-{dns_provider}',
           f'--dns-{dns_provider}-credentials', dns_credentials,
           f'--dns-{dns_provider}-propagation-seconds', str(propagation),
           '--domain', domain,
           '--email', email,
           '--agree-tos',
           '--non-interactive']

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
        ui.error("certbot not found at expected path after bootstrap.")
        return False, '', ''

    # Find certificate files. Persistent root is preferred; fall back to the
    # legacy /etc/letsencrypt/ layout for systems that haven't been migrated.
    live_dir = certbot_live_dir(domain)
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


# =============================================================================
# CERTBOT BOOTSTRAP - persistent venv + apt prereqs (firmware-wipe survival)
# =============================================================================

def resolve_certbot_bin() -> str:
    """
    Return the path to the certbot binary to use.

    Prefers the persistent venv at /data/unifi-cert/certbot-venv/bin/certbot.
    Falls back to PATH lookup so callers on non-UniFi systems (e.g., dev / CI)
    can still exercise run_certbot() with a system certbot.
    """
    if os.path.exists(CERTBOT_BIN):
        return CERTBOT_BIN
    return 'certbot'


def certbot_argv_base() -> list[str]:
    """
    Return the certbot CLI flags that route state into the persistent root.

    Only emitted when /data/unifi-cert/letsencrypt/ exists — this means
    pre-migration runs (where /etc/letsencrypt/ is still authoritative) get
    the empty list and certbot uses its default paths.
    """
    if os.path.isdir(CERTBOT_CONFIG_DIR):
        return [
            '--config-dir', CERTBOT_CONFIG_DIR,
            '--work-dir', CERTBOT_WORK_DIR,
            '--logs-dir', CERTBOT_LOGS_DIR,
        ]
    return []


def certbot_live_dir(domain: str) -> str:
    """Return the directory containing fullchain.pem / privkey.pem for `domain`."""
    persistent = os.path.join(CERTBOT_CONFIG_DIR, 'live', domain)
    if os.path.isdir(persistent):
        return persistent
    return f'/etc/letsencrypt/live/{domain}'


def certbot_health_check() -> bool:
    """Return True iff the persistent certbot binary executes and reports a version."""
    if not os.path.exists(CERTBOT_BIN):
        return False
    try:
        result = subprocess.run(
            [CERTBOT_BIN, '--version'],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _dpkg_installed(package: str) -> bool:
    """Return True if `package` is currently installed (status 'installed')."""
    try:
        result = subprocess.run(
            ['dpkg-query', '-W', '-f=${db:Status-Status}\n', package],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0 and result.stdout.strip() == 'installed'


def _ensure_apt_prereqs() -> tuple[bool, str]:
    """
    Ensure apt prereqs (python3-pip / python3-venv / python3-distutils) are installed.

    These ship pre-stripped on UniFi OS firmware images, so we apt-install them
    on demand. They get wiped on every firmware update — self-heal handles the
    re-install on next renewal.

    Returns: (success, message)
    """
    needed = [pkg for pkg in APT_PREREQS if not _dpkg_installed(pkg)]
    if not needed:
        return True, "all prereqs present"

    ui.status(f"Installing apt prereqs: {' '.join(needed)}")
    env = os.environ.copy()
    env['DEBIAN_FRONTEND'] = 'noninteractive'

    # apt-get update first so missing packages can resolve. Don't fail hard if
    # it errors — repo state may be temporarily unavailable but installed lists
    # may still be sufficient.
    try:
        subprocess.run(['apt-get', 'update'], capture_output=True, env=env, timeout=120)
    except (subprocess.TimeoutExpired, OSError) as e:
        ui.warning(f"apt-get update failed (non-fatal): {e}")

    try:
        result = subprocess.run(
            ['apt-get', 'install', '-y', '--no-install-recommends', *needed],
            capture_output=True, text=True, env=env, timeout=300,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"apt-get install errored: {e}"

    if result.returncode != 0:
        return False, f"apt-get install failed: {result.stderr.strip()}"
    return True, f"installed {' '.join(needed)}"


def _ensure_persistent_dirs() -> tuple[bool, str]:
    """
    Create the /data/unifi-cert/ directory tree with sane perms.

    Returns (False, reason) on filesystem errors (e.g., running on a non-UniFi
    host where /data doesn't exist) instead of raising — callers expect
    bootstrap_certbot() to return a clean (success, message) tuple.
    """
    try:
        for path in (UNIFI_CERT_ROOT, WHEELS_DIR, BACKUPS_DIR,
                     CERTBOT_CONFIG_DIR, CERTBOT_WORK_DIR, CERTBOT_LOGS_DIR):
            os.makedirs(path, mode=0o755, exist_ok=True)
        # Credentials directory is more sensitive — owner-only.
        os.makedirs(CREDENTIALS_DIR, mode=0o700, exist_ok=True)
    except OSError as e:
        return False, f"could not create {UNIFI_CERT_ROOT} tree: {e}"
    return True, "ok"


def _dns_plugin_installed(dns_provider: str) -> bool:
    """Check if the certbot DNS plugin for `dns_provider` is installed in the venv."""
    if not os.path.exists(CERTBOT_PIP):
        return False
    plugin = DNS_PROVIDERS.get(dns_provider, {}).get('plugin')
    if not plugin:
        return False
    try:
        result = subprocess.run(
            [CERTBOT_PIP, 'show', plugin],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0


def cache_wheels(packages: list[str]) -> bool:
    """
    Download wheels for `packages` into /data/unifi-cert/wheels/ for offline rebuild.

    Non-fatal if it fails — bootstrap can still succeed without a fresh cache,
    it just means the next firmware-wipe rebuild needs PyPI access.
    """
    if not os.path.exists(CERTBOT_PIP):
        return False
    os.makedirs(WHEELS_DIR, mode=0o755, exist_ok=True)
    ui.status(f"Caching wheels to {WHEELS_DIR}...")
    try:
        result = subprocess.run(
            [CERTBOT_PIP, 'download', '-d', WHEELS_DIR, *packages],
            capture_output=True, text=True, timeout=300,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        ui.warning(f"Wheel cache failed (non-fatal): {e}")
        return False
    if result.returncode != 0:
        ui.warning(f"Wheel cache failed (non-fatal): {result.stderr.strip()}")
        return False
    ui.debug(f"Cached wheels for {' '.join(packages)}")
    return True


def bootstrap_certbot(dns_provider: str, force: bool = False) -> tuple[bool, str]:
    """
    Build /data/unifi-cert/certbot-venv and install certbot + the requested DNS plugin.

    Idempotent — if the venv is healthy and the plugin is already present, returns
    immediately without invoking pip or apt. Set force=True to rebuild from scratch
    (e.g., after a Python minor-version bump that broke the venv).

    Tries the wheel cache (offline path) before reaching for PyPI, so a previously
    bootstrapped device with a populated /data/unifi-cert/wheels/ can recover after
    a firmware wipe even if PyPI is unreachable.

    Returns: (success, message)
    """
    if dns_provider not in DNS_PROVIDERS:
        return False, f"unknown DNS provider: {dns_provider}"

    dirs_ok, dirs_msg = _ensure_persistent_dirs()
    if not dirs_ok:
        return False, dirs_msg

    if not force and certbot_health_check() and _dns_plugin_installed(dns_provider):
        ui.debug(f"certbot venv at {CERTBOT_VENV} is healthy; skipping bootstrap")
        return True, "already healthy"

    ok, msg = _ensure_apt_prereqs()
    if not ok:
        return False, f"apt prereqs unavailable: {msg}"

    if force and os.path.exists(CERTBOT_VENV):
        ui.status(f"Removing existing venv at {CERTBOT_VENV} (force rebuild)...")
        shutil.rmtree(CERTBOT_VENV)

    if not os.path.exists(CERTBOT_BIN):
        ui.status(f"Creating venv at {CERTBOT_VENV}...")
        try:
            result = subprocess.run(
                ['python3', '-m', 'venv', CERTBOT_VENV],
                capture_output=True, text=True, timeout=120,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            return False, f"venv creation errored: {e}"
        if result.returncode != 0:
            return False, f"venv creation failed: {result.stderr.strip()}"

    ui.status("Upgrading pip in venv...")
    try:
        subprocess.run(
            [CERTBOT_PIP, 'install', '--upgrade', 'pip'],
            capture_output=True, text=True, timeout=120,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        ui.warning(f"pip upgrade failed (non-fatal): {e}")

    plugin = DNS_PROVIDERS[dns_provider]['plugin']
    packages = ['certbot', plugin]

    # Try offline install from wheel cache first.
    installed_from_cache = False
    if os.path.isdir(WHEELS_DIR) and any(os.scandir(WHEELS_DIR)):
        ui.status(f"Installing {' '.join(packages)} from wheel cache...")
        try:
            result = subprocess.run(
                [CERTBOT_PIP, 'install', '--no-index',
                 f'--find-links={WHEELS_DIR}', *packages],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode == 0:
                installed_from_cache = True
                ui.success("Installed from wheel cache")
            else:
                ui.warning(f"Wheel cache install failed; falling back to PyPI: "
                           f"{result.stderr.strip()[:200]}")
        except (subprocess.TimeoutExpired, OSError) as e:
            ui.warning(f"Wheel cache install errored; falling back to PyPI: {e}")

    if not installed_from_cache:
        ui.status(f"Installing {' '.join(packages)} from PyPI...")
        try:
            result = subprocess.run(
                [CERTBOT_PIP, 'install', *packages],
                capture_output=True, text=True, timeout=600,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            return False, f"pip install errored: {e}"
        if result.returncode != 0:
            return False, f"pip install failed: {result.stderr.strip()}"
        # Refresh the wheel cache so future rebuilds can run offline.
        cache_wheels(packages)

    if not certbot_health_check():
        return False, "certbot installed but health check failed"

    ui.success(f"certbot bootstrapped at {CERTBOT_BIN}")
    return True, "bootstrapped"


PERMANENT_SCRIPT_PATH = '/data/scripts/unifi-cert.py'


def ensure_script_installed() -> str:
    """
    Ensure the script is installed at a permanent location.
    Returns the path to the permanent script location.
    """
    script_dir = os.path.dirname(PERMANENT_SCRIPT_PATH)

    # If we're already running from the permanent location, we're good
    current_path = os.path.abspath(__file__) if '__file__' in dir() else None
    if current_path and os.path.exists(current_path) and os.path.samefile(current_path, PERMANENT_SCRIPT_PATH):
        return PERMANENT_SCRIPT_PATH

    # Create directory if needed
    try:
        os.makedirs(script_dir, exist_ok=True)
    except IOError as e:
        ui.warning(f"Could not create {script_dir}: {e}")
        return current_path or PERMANENT_SCRIPT_PATH

    # Copy current script to permanent location
    try:
        if current_path and os.path.exists(current_path):
            shutil.copy2(current_path, PERMANENT_SCRIPT_PATH)
            os.chmod(PERMANENT_SCRIPT_PATH, 0o755)
            ui.info(f"Installed script to {PERMANENT_SCRIPT_PATH}")
        else:
            # Running from stdin (curl pipe) - download from GitHub
            ui.info("Downloading script to permanent location...")
            result = subprocess.run(
                ['curl', '-sL', 'https://raw.githubusercontent.com/jdlien/unifi-cert/main/unifi-cert.py',
                 '-o', PERMANENT_SCRIPT_PATH],
                capture_output=True, timeout=30
            )
            if result.returncode == 0:
                os.chmod(PERMANENT_SCRIPT_PATH, 0o755)
                ui.success(f"Installed script to {PERMANENT_SCRIPT_PATH}")
            else:
                ui.warning(f"Could not download script: {result.stderr.decode()}")
    except subprocess.TimeoutExpired:
        ui.warning("Download timed out")
    except IOError as e:
        ui.warning(f"Could not install script to {PERMANENT_SCRIPT_PATH}: {e}")

    return PERMANENT_SCRIPT_PATH


# =============================================================================
# SCHEDULE & SELF-HEAL - cron, boot script, lock, log rotation, renewal-due
# =============================================================================

CRON_FILE = '/etc/cron.d/unifi-cert'
BOOT_SCRIPT_DIR = '/data/on_boot.d'
BOOT_SCRIPT_PATH = f'{BOOT_SCRIPT_DIR}/15-unifi-cert.sh'

# Daily renewal cron line. Offset 03:17 to avoid the on-the-hour cluster of
# system cron jobs. Output appended to LOG_FILE so failures surface to --status.
CRON_LINE = (
    f'17 3 * * * root /usr/bin/python3 {PERMANENT_SCRIPT_PATH} --renew '
    f'>> {LOG_FILE} 2>&1\n'
)

LOG_ROTATE_THRESHOLD = 1 * 1024 * 1024  # 1 MB triggers rotate
LOG_ROTATE_KEEP = 100 * 1024            # keep last 100 KB


def acquire_lock(timeout: float = 0.0):
    """Acquire an exclusive flock on LOCK_FILE.

    Serializes --renew vs --deploy-hook vs concurrent --self-heal so only
    one ACME / install pipeline runs at a time. Returns the open file
    handle on success; raises BlockingIOError when timeout=0 and the lock
    is held. Pass timeout>0 to wait up to that many seconds.
    """
    os.makedirs(UNIFI_CERT_ROOT, mode=0o755, exist_ok=True)
    fh = open(LOCK_FILE, 'w')
    try:
        if timeout <= 0:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        else:
            deadline = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.5)
    except BlockingIOError:
        fh.close()
        raise
    return fh


def release_lock(fh) -> None:
    """Release the flock and close the lock file handle."""
    if fh is None:
        return
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        fh.close()
    except OSError:
        pass


def rotate_log() -> bool:
    """Truncate LOG_FILE to the last LOG_ROTATE_KEEP bytes when oversized.

    No-op if the log is missing or below LOG_ROTATE_THRESHOLD. Returns
    True on success or graceful skip, False on filesystem error.
    """
    if not os.path.exists(LOG_FILE):
        return True
    try:
        size = os.path.getsize(LOG_FILE)
    except OSError:
        return False
    if size <= LOG_ROTATE_THRESHOLD:
        return True
    try:
        with open(LOG_FILE, 'rb') as fh:
            fh.seek(-LOG_ROTATE_KEEP, os.SEEK_END)
            tail = fh.read()
        # Drop partial first line so rotated log starts at a record boundary.
        nl = tail.find(b'\n')
        if 0 <= nl < len(tail) - 1:
            tail = tail[nl + 1:]
        with open(LOG_FILE, 'wb') as fh:
            fh.write(tail)
    except OSError:
        return False
    return True


def is_renewal_due(domain: str, days: int = 30) -> bool:
    """Return True if the cert for `domain` is missing or expires within `days`.

    A missing or unparseable cert returns True so the renewal pipeline
    runs and recovers rather than silently no-opping.
    """
    live_dir = certbot_live_dir(domain)
    cert_path = os.path.join(live_dir, 'cert.pem')
    if not os.path.exists(cert_path):
        cert_path = os.path.join(live_dir, 'fullchain.pem')
    if not os.path.exists(cert_path):
        return True
    try:
        meta = CertMetadata.from_cert_file(cert_path)
    except Exception:
        return True
    if not meta.valid_to:
        return True
    try:
        expiry = datetime.strptime(meta.valid_to, '%Y-%m-%d %H:%M:%S+00')
    except ValueError:
        return True
    remaining = expiry - datetime.utcnow()
    return remaining.days < days


def install_cron_schedule() -> bool:
    """Write CRON_FILE with the daily --renew line. Idempotent overwrite."""
    try:
        os.makedirs(os.path.dirname(CRON_FILE), exist_ok=True)
        with open(CRON_FILE, 'w', encoding='utf-8') as fh:
            fh.write('# UniFi cert auto-renewal\n')
            fh.write('# Auto-generated by unifi-cert.py self_heal()\n')
            fh.write(CRON_LINE)
        os.chmod(CRON_FILE, 0o644)
        ui.success(f'Installed cron schedule: {CRON_FILE}')
        return True
    except OSError as e:
        ui.error(f'Failed to install cron schedule: {e}')
        return False


def install_boot_script() -> bool:
    """Best-effort: write BOOT_SCRIPT_PATH to re-assert state on every boot.

    Skipped with a warning when /data/on_boot.d/ is absent (the case on
    devices without unifi-utilities/on-boot-script — e.g., beehive). The
    cron at /etc/cron.d/unifi-cert is the primary persistence mechanism;
    the boot script is layer 3 of defense, not layer 4.
    """
    if not os.path.isdir(BOOT_SCRIPT_DIR):
        ui.warning(
            f'{BOOT_SCRIPT_DIR} not present; skipping boot script. '
            'Install unifi-utilities/on-boot-script for firmware-wipe survival.'
        )
        return True

    content = (
        '#!/bin/sh\n'
        '# UniFi cert boot-time self-heal\n'
        '# Auto-generated by unifi-cert.py self_heal()\n'
        f'/usr/bin/python3 {PERMANENT_SCRIPT_PATH} --self-heal '
        f'>> {LOG_FILE} 2>&1\n'
    )
    try:
        with open(BOOT_SCRIPT_PATH, 'w', encoding='utf-8') as fh:
            fh.write(content)
        os.chmod(BOOT_SCRIPT_PATH, 0o755)
        ui.success(f'Installed boot script: {BOOT_SCRIPT_PATH}')
        return True
    except OSError as e:
        ui.error(f'Failed to install boot script: {e}')
        return False


def self_heal(dns_provider: Optional[str] = None,
              domain: Optional[str] = None) -> bool:
    """Idempotent repair: ensure venv + script + cron + hook + boot.

    NEVER runs ACME — safe to call from boot or before every renewal.
    `dns_provider` and `domain` fall back to load_provisioning_config()
    when not supplied (the cron-fired case).
    """
    if dns_provider is None or domain is None:
        cfg = load_provisioning_config()
        dns_provider = dns_provider or cfg.get('dns_provider')
        domain = domain or cfg.get('domain')

    ok = True

    if dns_provider:
        ok_b, msg = bootstrap_certbot(dns_provider)
        if not ok_b:
            ui.warning(f'self-heal: bootstrap deferred ({msg})')
            ok = False
    else:
        ui.debug('self-heal: no dns_provider known; skipping bootstrap')

    ensure_script_installed()
    ok = install_cron_schedule() and ok
    if domain:
        ok = setup_renewal_hook(domain) and ok
    install_boot_script()  # never blocks success — best-effort layer
    return ok


def setup_renewal_hook(domain: str, script_path: str = None) -> bool:
    """Set up certbot renewal hook."""
    hook_dir = '/etc/letsencrypt/renewal-hooks/post'
    hook_path = os.path.join(hook_dir, 'unifi-cert-hook.sh')

    # Always use the permanent script location for the hook
    permanent_path = script_path or PERMANENT_SCRIPT_PATH

    hook_content = f"""#!/bin/bash
# UniFi Certificate renewal hook
# Auto-generated by unifi-cert.py

RENEWED_DOMAINS="${{RENEWED_DOMAINS:-{domain}}}"
SCRIPT="{permanent_path}"

# Try to update to latest version (but don't fail if download fails)
curl -sL --connect-timeout 10 --max-time 30 \
    https://raw.githubusercontent.com/jdlien/unifi-cert/main/unifi-cert.py \
    -o "$SCRIPT.new" 2>/dev/null

if [ -s "$SCRIPT.new" ]; then
    mv "$SCRIPT.new" "$SCRIPT"
    chmod +x "$SCRIPT"
else
    rm -f "$SCRIPT.new" 2>/dev/null
fi

# Run the script (use existing if download failed)
if [ -x "$SCRIPT" ]; then
    /usr/bin/python3 "$SCRIPT" --renew --domain "$RENEWED_DOMAINS"
else
    echo "ERROR: unifi-cert.py not found at $SCRIPT" >&2
    exit 1
fi
"""

    try:
        os.makedirs(hook_dir, exist_ok=True)
        with open(hook_path, 'w', encoding='utf-8') as f:
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
    with open(cert_path, 'r', encoding='utf-8') as f:
        cert_content = f.read()
    with open(key_path, 'r', encoding='utf-8') as f:
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
                       help='Renew existing certificate (cron entry point: '
                            'lock + self-heal + ACME-if-due + sync)')
    parser.add_argument('--deploy-hook', action='store_true',
                       help='certbot deploy-hook entry point. Reads '
                            '$RENEWED_LINEAGE and syncs that lineage only. '
                            'No ACME, no bootstrap.')
    parser.add_argument('--self-heal', action='store_true',
                       help='Idempotent repair: ensure venv + cron + hook + '
                            'boot script. Never runs ACME.')
    parser.add_argument('--setup-hook', action='store_true',
                       help='Set up certbot renewal hook only')
    parser.add_argument('--bootstrap', action='store_true',
                       help='Build/repair the persistent certbot venv at '
                            '/data/unifi-cert/certbot-venv and exit')
    parser.add_argument('--enable-hook-autoupdate', action='store_true',
                       help='Re-enable the renewal hook GitHub auto-update path '
                            '(default off). Requires a baked-in SHA-256 pin.')

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

    # Load saved preferences
    saved_config = load_config()

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
    saved_email = saved_config.get('email')
    config['email'] = ui.prompt('Email for Let\'s Encrypt', default=saved_email)

    # DNS provider selection
    providers = list(DNS_PROVIDERS.keys())
    saved_provider = saved_config.get('dns_provider')
    default_idx = providers.index(saved_provider) if saved_provider in providers else None
    idx = ui.select('Select DNS provider:', providers, default=default_idx)
    config['dns_provider'] = providers[idx]

    # Save preferences for next time
    save_config(email=config['email'], dns_provider=config['dns_provider'])

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

    # Automation verbs run non-interactively even on a TTY — cron, certbot
    # deploy-hooks, and on_boot.d invoke us, never a human.
    automation_verb = (
        args.renew or args.deploy_hook or args.self_heal or args.bootstrap
    )

    # Determine if we should run interactive mode
    # Run interactive if: TTY available (check stdout since stdin may be pipe from curl),
    # not --install, not --setup-hook, not an automation verb, and missing args.
    needs_interactive = (
        sys.stdout.isatty() and
        not args.install and
        not args.setup_hook and
        not automation_verb and
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
    if not args.domain and not args.setup_hook and not automation_verb:
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

    # Validate required args (after auto-detection attempt). Automation verbs
    # are exempt — they pull state from PROVISIONING_CONFIG / $RENEWED_LINEAGE.
    if not args.domain and not args.setup_hook and not automation_verb:
        ui.error('Domain is required. Use -d/--domain or run interactively.')
        ui.info('Tip: If a certificate is already installed, the domain can be auto-detected.')
        return 1

    # Bootstrap-only: build/repair /data/unifi-cert/certbot-venv and exit.
    # Useful for verifying the bootstrap path independently of cert obtain/renew,
    # and for self-heal contexts where we want to ensure certbot is available
    # without immediately running ACME.
    if args.bootstrap:
        if not args.dns_provider:
            ui.error('--dns-provider is required for bootstrap (controls which DNS plugin to install).')
            return 1
        ok, msg = bootstrap_certbot(args.dns_provider, force=args.force)
        if ok:
            ui.success(f'Bootstrap complete: {msg}')
            return 0
        ui.error(f'Bootstrap failed: {msg}')
        return 1

    # Setup renewal hook only
    if args.setup_hook:
        ensure_script_installed()
        if setup_renewal_hook(args.domain or 'example.com'):
            ui.success('Renewal hook configured')
            return 0
        return 1

    # certbot deploy-hook entry point. Reads $RENEWED_LINEAGE (set by certbot
    # in renewal-hook env) and syncs that lineage to the UniFi platform. No
    # ACME, no bootstrap. Acquires the same lock as --renew so concurrent
    # invocations serialize cleanly.
    if args.deploy_hook:
        lineage = os.environ.get('RENEWED_LINEAGE', '').rstrip('/')
        if not lineage:
            ui.error('--deploy-hook requires $RENEWED_LINEAGE in env (set by certbot).')
            return 1
        cert_path = os.path.join(lineage, 'fullchain.pem')
        key_path = os.path.join(lineage, 'privkey.pem')
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            ui.error(f'Lineage incomplete at {lineage} (missing fullchain or privkey)')
            return 1
        domain = args.domain or os.path.basename(lineage)
        platform = UnifiPlatform.detect()
        if not platform:
            ui.error('Not running on a UniFi device.')
            return 1
        try:
            lock_fh = acquire_lock(timeout=30)
        except BlockingIOError:
            ui.error('Another --renew or --deploy-hook is running; refusing to overlap.')
            return 1
        try:
            success = install_certificate(
                cert_path, key_path, domain, platform,
                skip_postgres=args.skip_postgres,
                skip_restart=args.skip_restart,
                dry_run=args.dry_run,
            )
        finally:
            release_lock(lock_fh)
        if success:
            ui.success(f'Deploy-hook synced renewed cert for {domain}')
            return 0
        return 1

    # Self-heal entry point. Idempotent repair: ensure venv + cron + hook +
    # boot script are present. Never runs ACME — safe to call from boot or
    # any other automation context.
    if args.self_heal:
        ok = self_heal(dns_provider=args.dns_provider, domain=args.domain)
        return 0 if ok else 1

    # Renewal entry point (cron-fired). Pipeline:
    #   rotate_log → load_provisioning_config (when CLI args missing) →
    #   acquire_lock → self_heal → if is_renewal_due() or --force → run_certbot
    #   → install_certificate. The lock prevents overlap with --deploy-hook
    #   if a foreign certbot triggers our post-hook mid-renewal.
    if args.renew:
        rotate_log()

        cfg = load_provisioning_config()
        domain = args.domain or cfg.get('domain')
        email = args.email or cfg.get('email')
        dns_provider = args.dns_provider or cfg.get('dns_provider')
        dns_credentials = args.dns_credentials or cfg.get('dns_credentials')

        if not domain:
            ui.error('No domain available. Provide -d/--domain or run obtain-new '
                     'first to seed /data/unifi-cert/unifi-cert.conf.')
            return 1

        try:
            lock_fh = acquire_lock(timeout=0)
        except BlockingIOError:
            ui.error('Another --renew or --deploy-hook is running; refusing to overlap.')
            return 1

        try:
            # Self-heal first so cron + venv + hook are correct even when
            # this firing decides not to call certbot.
            self_heal(dns_provider=dns_provider, domain=domain)

            if not (args.force or is_renewal_due(domain)):
                ui.info(f'Certificate for {domain} is not yet due for renewal; '
                        'skipping ACME.')
                return 0

            if not (email and dns_provider and dns_credentials):
                ui.error('--renew requires email + dns_provider + dns_credentials, '
                         'either via flags or saved in '
                         '/data/unifi-cert/unifi-cert.conf.')
                return 1

            success, cert_path, key_path = run_certbot(
                domain, email, dns_provider, dns_credentials,
                propagation=args.propagation,
                dry_run=args.dry_run,
                force=args.force,
            )
            if not success:
                return 1
            if args.dry_run:
                ui.success('Dry-run renewal completed successfully')
                return 0

            platform = UnifiPlatform.detect()
            if not platform:
                ui.error('Not running on a UniFi device.')
                return 1

            success = install_certificate(
                cert_path, key_path, domain, platform,
                skip_postgres=args.skip_postgres,
                skip_restart=args.skip_restart,
                dry_run=args.dry_run,
            )
            if success:
                ui.success(f'Renewed certificate for {domain} synced to UniFi')
                return 0
            return 1
        finally:
            release_lock(lock_fh)

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
        # Install script to permanent location, set up renewal hook + cron,
        # and persist provisioning config so cron-fired --renew can self-configure.
        ensure_script_installed()
        if setup_renewal_hook(args.domain):
            ui.info('Renewal hook installed - UI will stay in sync after renewals')
        else:
            ui.warning('Could not set up renewal hook. Run --setup-hook manually.')

        # Local installs (no --host) get the cron schedule + persisted provisioning
        # config. Remote installs run from a workstation; the device-side schedule
        # gets installed during --renew/--self-heal on the device itself.
        if not args.host:
            install_cron_schedule()
            save_provisioning_config(
                domain=args.domain,
                email=args.email,
                dns_provider=args.dns_provider,
                dns_credentials=args.dns_credentials,
            )

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
