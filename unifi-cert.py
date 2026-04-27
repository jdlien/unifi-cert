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
import glob
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
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
# GLENNR MIGRATION - import provisioning + uninstall the unifi-easy-encrypt.sh footprint
# =============================================================================
#
# GlennR's installer scatters state across /srv/EUS/, /usr/lib/EUS/, /root/EUS/,
# six different cron files in /etc/cron.d/, EUS_*.sh hooks under
# /etc/letsencrypt/renewal-hooks/, and apt sources at
# /etc/apt/sources.list.d/glennr-install-script*.{list,sources}. Migration is:
# inventory → import provisioning → snapshot → rsync /etc/letsencrypt/ →
# allowlisted uninstall → bootstrap + schedule + hook. The allowlist is
# explicit and ordered — no escaping globs.

GLENNR_REMOVABLE_DIRS = (
    '/srv/EUS',
    '/usr/lib/EUS',
    '/root/EUS',
)

GLENNR_REMOVABLE_FILE_GLOBS = (
    '/root/unifi-easy-encrypt.sh',
    '/root/unifi-easy-encrypt.sh.tmp',
    '/root/unifi-easy-encrypt-*.sh',
)

GLENNR_REMOVABLE_CRONS = (
    '/etc/cron.d/eus_script',
    '/etc/cron.d/eus_script_uc_ck',
    '/etc/cron.d/eus_lets_encrypt_retry',
    '/etc/cron.d/eus_certbot',
)
GLENNR_REMOVABLE_CRON_GLOBS = (
    '/etc/cron.d/eus_certificate_migration_*',
)

# Generic name shared with apt's certbot package — only remove if the file
# content actually invokes /usr/bin/certbot (the apt-installed cron). A
# user-authored /etc/cron.d/certbot might predate this tool.
GLENNR_REMOVABLE_CRON_GENERIC = '/etc/cron.d/certbot'

GLENNR_REMOVABLE_HOOK_GLOBS = (
    '/etc/letsencrypt/renewal-hooks/pre/EUS_*.sh',
    '/etc/letsencrypt/renewal-hooks/post/EUS_*.sh',
)

GLENNR_REMOVABLE_APT_SOURCES = (
    '/etc/apt/sources.list.d/glennr-install-script.list',
    '/etc/apt/sources.list.d/glennr-install-script.sources',
    '/etc/apt/sources.list.d/glennr-install-script-unmet.list',
    '/etc/apt/sources.list.d/glennr-install-script-unmet.sources',
)


@dataclass
class GlennRInventory:
    """Result of inventory_glennr() — provisioning hints + removal targets."""
    domain: Optional[str] = None
    email: Optional[str] = None
    dns_provider: Optional[str] = None
    dns_credentials_path: Optional[str] = None
    glennr_version: Optional[str] = None
    # list of (absolute_path, kind, reason) tuples; kind ∈ {'dir','file','cron','hook','apt-source'}
    detected_paths: list = field(default_factory=list)


def _cron_d_certbot_invokes_glennr(path: str) -> bool:
    """Return True iff /etc/cron.d/certbot runs the apt-installed certbot binary.

    The path is generic (apt installs `certbot` package with its own cron
    file). We only delete when the file content matches the apt-cron shape,
    so a user's hand-rolled /etc/cron.d/certbot is preserved.
    """
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            content = fh.read()
    except OSError:
        return False
    return '/usr/bin/certbot' in content or 'certbot -q renew' in content


def _email_from_v1_prefs() -> Optional[str]:
    """Read email from the v1 user-prefs file at ~/.secrets/certbot/config.ini.

    The pre-2.0 interactive flow saved preferences here; users upgrading
    from v1 (or from GlennR through v1) will have it populated.
    """
    if not os.path.exists(CONFIG_FILE):
        return None
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as fh:
            for line in fh:
                m = re.match(r'\s*email\s*=\s*(\S+)', line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return None


def _email_from_certbot_accounts() -> Optional[str]:
    """Read email from certbot's ACME account registration JSON.

    Certbot stores `mailto:` contacts under
    /etc/letsencrypt/accounts/<server>/directory/<acct>/regr.json. This is
    the canonical record of the email used when the account was created.
    """
    pattern = '/etc/letsencrypt/accounts/*/*/*/regr.json'
    for path in sorted(glob.glob(pattern)):
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        contacts = data.get('body', {}).get('contact') or []
        for c in contacts:
            if isinstance(c, str) and c.startswith('mailto:'):
                return c[len('mailto:'):]
    return None


def inventory_glennr() -> GlennRInventory:
    """Read-only probe of GlennR state on the current device.

    Reads /etc/letsencrypt/renewal/*.conf for domain / dns provider /
    credentials path (the most reliable provisioning source). For email
    (which certbot rarely persists in renewal/<domain>.conf), falls back
    through the v1 user-prefs file and certbot's accounts/regr.json.
    Probes /root/unifi-easy-encrypt.sh for the GlennR script version.
    Builds the list of removable paths matching the allowlist. Performs
    no writes.
    """
    inv = GlennRInventory()

    # Renewal config: certbot's own record of the lineage.
    renewal_dir = '/etc/letsencrypt/renewal'
    if os.path.isdir(renewal_dir):
        for conf_name in sorted(os.listdir(renewal_dir)):
            if not conf_name.endswith('.conf'):
                continue
            domain = conf_name[:-len('.conf')]
            inv.domain = inv.domain or domain
            try:
                with open(os.path.join(renewal_dir, conf_name), 'r', encoding='utf-8') as fh:
                    content = fh.read()
            except OSError:
                continue
            m = re.search(r'^\s*email\s*=\s*(\S+)', content, re.MULTILINE)
            if m and not inv.email:
                inv.email = m.group(1)
            m = re.search(r'authenticator\s*=\s*dns-([a-z0-9]+)', content)
            if m and not inv.dns_provider:
                inv.dns_provider = m.group(1)
            m = re.search(r'dns_[a-z0-9]+_credentials\s*=\s*(\S+)', content)
            if m and not inv.dns_credentials_path:
                inv.dns_credentials_path = m.group(1)
            # Stop after the first lineage so we don't mix providers across domains.
            break

    # Email fallbacks — certbot's renewal conf rarely has it.
    if not inv.email:
        inv.email = _email_from_v1_prefs() or _email_from_certbot_accounts()

    # GlennR script version (best-effort; not load-bearing).
    for candidate in ('/root/unifi-easy-encrypt.sh',
                      '/root/EUS/unifi-easy-encrypt.sh'):
        if not os.path.exists(candidate):
            continue
        try:
            with open(candidate, 'r', encoding='utf-8') as fh:
                head = fh.read(8192)
        except OSError:
            continue
        m = re.search(r'script_version=["\']?([0-9.]+)', head)
        if m:
            inv.glennr_version = m.group(1)
        break

    # Build the removable-paths list.
    detected = []
    for d in GLENNR_REMOVABLE_DIRS:
        if os.path.isdir(d):
            detected.append((d, 'dir', 'GlennR data directory'))
    for pattern in GLENNR_REMOVABLE_FILE_GLOBS:
        for path in sorted(glob.glob(pattern)):
            if os.path.isfile(path):
                detected.append((path, 'file', 'GlennR script'))
    for cron in GLENNR_REMOVABLE_CRONS:
        if os.path.isfile(cron):
            detected.append((cron, 'cron', 'GlennR cron job'))
    for pattern in GLENNR_REMOVABLE_CRON_GLOBS:
        for path in sorted(glob.glob(pattern)):
            if os.path.isfile(path):
                detected.append((path, 'cron', 'GlennR cron job (auto-generated)'))
    if (os.path.isfile(GLENNR_REMOVABLE_CRON_GENERIC)
            and _cron_d_certbot_invokes_glennr(GLENNR_REMOVABLE_CRON_GENERIC)):
        detected.append((
            GLENNR_REMOVABLE_CRON_GENERIC, 'cron',
            'apt-installed certbot cron (replaced by /etc/cron.d/unifi-cert)',
        ))
    for pattern in GLENNR_REMOVABLE_HOOK_GLOBS:
        for path in sorted(glob.glob(pattern)):
            if os.path.isfile(path):
                detected.append((path, 'hook', 'GlennR renewal hook'))
    for src in GLENNR_REMOVABLE_APT_SOURCES:
        if os.path.isfile(src):
            detected.append((src, 'apt-source', 'GlennR apt source'))

    inv.detected_paths = detected
    return inv


def import_provisioning_from_glennr(inv: GlennRInventory) -> bool:
    """Persist GlennR-derived provisioning under /data/unifi-cert/.

    Writes unifi-cert.conf with the inventory fields and copies the DNS
    credentials file (if accessible) to /data/unifi-cert/credentials/.
    Refuses when the inventory lacks domain + dns_provider — those are the
    minimum required for cron-fired --renew to work.
    """
    if not (inv.domain and inv.dns_provider):
        ui.error('Inventory incomplete: cannot import without domain + dns_provider.')
        return False

    new_creds_path = os.path.join(CREDENTIALS_DIR, f'{inv.dns_provider}.ini')
    if inv.dns_credentials_path and os.path.exists(inv.dns_credentials_path):
        try:
            os.makedirs(CREDENTIALS_DIR, mode=0o700, exist_ok=True)
            shutil.copy(inv.dns_credentials_path, new_creds_path)
            os.chmod(new_creds_path, 0o600)
            ui.success(f'Copied credentials to {new_creds_path}')
        except OSError as e:
            ui.error(f'Failed to copy credentials: {e}')
            return False
    elif inv.dns_credentials_path:
        ui.warning(
            f'Credentials path {inv.dns_credentials_path} does not exist; '
            'config will reference it but credentials must be restored manually.'
        )
        new_creds_path = inv.dns_credentials_path

    return save_provisioning_config(
        domain=inv.domain,
        email=inv.email or '',
        dns_provider=inv.dns_provider,
        dns_credentials=new_creds_path,
    )


def snapshot_glennr(inv: GlennRInventory,
                     timestamp: Optional[str] = None) -> Optional[str]:
    """Tar everything that would be removed plus /etc/letsencrypt/ into BACKUPS_DIR.

    Recovery is `tar xzf <tarball>` from /. Returns the tarball path on
    success, None on failure (no removals should follow a snapshot failure).
    """
    timestamp = timestamp or datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    try:
        os.makedirs(BACKUPS_DIR, mode=0o755, exist_ok=True)
    except OSError as e:
        ui.error(f'Failed to create backups dir: {e}')
        return None
    tarball = os.path.join(BACKUPS_DIR, f'{timestamp}.tar.gz')

    paths = [p for (p, _, _) in inv.detected_paths if os.path.exists(p)]
    if os.path.isdir('/etc/letsencrypt'):
        paths.append('/etc/letsencrypt')
    if not paths:
        ui.warning('No GlennR paths to snapshot.')
        return None

    cmd = ['tar', 'czf', tarball, *paths]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except (subprocess.TimeoutExpired, OSError) as e:
        ui.error(f'tar errored: {e}')
        return None
    if result.returncode != 0:
        ui.error(f'tar failed: {result.stderr.strip()}')
        return None
    ui.success(f'Snapshot: {tarball}')
    return tarball


def _rsync_etc_letsencrypt(domain: Optional[str] = None) -> bool:
    """rsync /etc/letsencrypt/ → /data/unifi-cert/letsencrypt/ preserving symlinks.

    Trailing slash on the source means contents-only; we don't end up with
    a nested letsencrypt/letsencrypt/ subtree. -aH preserves perms, links,
    times, and hardlinks (live/ is a symlink farm into archive/).

    Idempotency guard: if the destination already has fullchain.pem for
    `domain`, the new tool already owns a working lineage. Skipping the
    rsync prevents stale GlennR archive files (often older but bigger
    than the new lineage's files, since GlennR predates ECDSA defaults)
    from clobbering the working cert. `-u` (--update) is the second
    safety net for partial-state cases where the dest lineage is missing
    only some files.
    """
    src = '/etc/letsencrypt/'
    dst = CERTBOT_CONFIG_DIR + '/'
    if not os.path.isdir(src):
        ui.warning(f'{src} not present; nothing to migrate.')
        return True

    if domain:
        dest_fullchain = os.path.join(dst, 'live', domain, 'fullchain.pem')
        if os.path.exists(dest_fullchain):
            ui.info(
                f'{dest_fullchain} already exists; skipping rsync to preserve '
                'the newer lineage. (Re-obtain via certbot if you want to '
                'replace it.)'
            )
            return True

    try:
        os.makedirs(CERTBOT_CONFIG_DIR, mode=0o755, exist_ok=True)
    except OSError as e:
        ui.error(f'Failed to create {CERTBOT_CONFIG_DIR}: {e}')
        return False
    cmd = ['rsync', '-aHu', src, dst]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except (subprocess.TimeoutExpired, OSError) as e:
        ui.error(f'rsync errored: {e}')
        return False
    if result.returncode != 0:
        ui.error(f'rsync failed: {result.stderr.strip()}')
        return False
    ui.success(f'Migrated /etc/letsencrypt/ → {CERTBOT_CONFIG_DIR}/')
    return True


def _remove_glennr_path(path: str, kind: str, force: bool) -> bool:
    """Remove a single GlennR path with per-path confirmation unless --force.

    Returns True on success or graceful skip; False on filesystem error.
    """
    if not force:
        if not ui.confirm(f'Remove {kind} {path}?', default=False):
            ui.info(f'Skipped {path}')
            return True
    try:
        if kind == 'dir':
            shutil.rmtree(path)
        else:
            os.remove(path)
    except OSError as e:
        ui.error(f'Failed to remove {path}: {e}')
        return False
    ui.success(f'Removed {path}')
    return True


def migrate_glennr(dry_run: bool = False, force: bool = False,
                    domain_override: Optional[str] = None,
                    email_override: Optional[str] = None,
                    dns_provider_override: Optional[str] = None,
                    dns_credentials_override: Optional[str] = None) -> bool:
    """Full GlennR-to-unifi-cert migration.

    Order: inventory → apply CLI overrides → import provisioning →
    snapshot → rsync LE state → allowlisted uninstall → self_heal
    (bootstrap + cron + hook + boot).

    The `*_override` arguments are layered on top of the inventory so
    callers can fill gaps the inventory missed (most commonly email,
    which certbot doesn't persist in renewal/<domain>.conf). Overrides
    win when set; otherwise the inventory value is kept.

    --dry-run lists planned actions and performs nothing destructive.
    --force skips the per-path confirmation prompts.
    """
    ui.header('GlennR migration')

    inv = inventory_glennr()

    if domain_override:
        inv.domain = domain_override
    if email_override:
        inv.email = email_override
    if dns_provider_override:
        inv.dns_provider = dns_provider_override
    if dns_credentials_override:
        inv.dns_credentials_path = dns_credentials_override

    has_le = os.path.isdir('/etc/letsencrypt')
    if not inv.detected_paths and not has_le:
        ui.info('No GlennR footprint detected; nothing to migrate.')
        return True

    ui.info(f'Domain:         {inv.domain or "(unknown)"}')
    ui.info(f'Email:          {inv.email or "(unknown)"}')
    ui.info(f'DNS provider:   {inv.dns_provider or "(unknown)"}')
    ui.info(f'GlennR version: {inv.glennr_version or "(unknown)"}')
    ui.info(f'Removable GlennR paths: {len(inv.detected_paths)}')

    if dry_run:
        for path, kind, reason in inv.detected_paths:
            ui.info(f'  [dry-run] {kind:11s} {path}  ({reason})')
        if has_le:
            dest_fullchain = (
                os.path.join(CERTBOT_CONFIG_DIR, 'live', inv.domain, 'fullchain.pem')
                if inv.domain else None
            )
            if dest_fullchain and os.path.exists(dest_fullchain):
                ui.info(
                    f'  [dry-run] {dest_fullchain} already exists; rsync would '
                    'be SKIPPED to preserve the newer lineage'
                )
            else:
                ui.info(f'  [dry-run] would rsync /etc/letsencrypt/ → {CERTBOT_CONFIG_DIR}/')
            ui.info(f'  [dry-run] would remove /etc/letsencrypt/ after verification')
        ui.info(f'  [dry-run] would import provisioning to {PROVISIONING_CONFIG}')
        ui.info(f'  [dry-run] would snapshot to {BACKUPS_DIR}/<timestamp>.tar.gz')
        ui.info(f'  [dry-run] would run --self-heal (bootstrap + cron + hook + boot)')
        return True

    # 1. Import provisioning first — if this fails the rest is pointless.
    if not import_provisioning_from_glennr(inv):
        ui.error('Failed to import provisioning from GlennR; aborting.')
        return False

    # 2. Snapshot — must happen before any deletion.
    timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    if snapshot_glennr(inv, timestamp) is None:
        ui.error('Snapshot failed; aborting before any destructive change.')
        return False

    # 3. Migrate LE state to the persistent root.
    if has_le and not _rsync_etc_letsencrypt(domain=inv.domain):
        ui.error('LE state migration failed; aborting before deletion.')
        return False

    # 4. Verify the new path has the lineage before we delete the old one.
    skip_le_dir_deletion = False
    if has_le and inv.domain:
        new_fullchain = os.path.join(CERTBOT_CONFIG_DIR, 'live', inv.domain, 'fullchain.pem')
        if not os.path.exists(new_fullchain):
            ui.warning(
                f'Migrated lineage missing {new_fullchain}; '
                'will skip /etc/letsencrypt/ deletion as a safety net.'
            )
            skip_le_dir_deletion = True

    # 5. Per-path uninstall (allowlisted, with confirms unless --force).
    for path, kind, _ in inv.detected_paths:
        _remove_glennr_path(path, kind, force=force)

    if has_le and not skip_le_dir_deletion:
        _remove_glennr_path('/etc/letsencrypt', 'dir', force=force)

    # 6. Bootstrap + schedule + hook + boot via self_heal().
    self_heal(dns_provider=inv.dns_provider, domain=inv.domain)

    ui.success('GlennR migration complete.')
    return True


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

    # If we're already running from the permanent location, we're good.
    # `'__file__' in dir()` was a stale guard — dir() inside a function
    # returns local names, so __file__ (a module-level attribute) was
    # never visible and current_path was always None. That made every
    # --self-heal call re-download main-branch HEAD from GitHub,
    # silently clobbering newer locally-deployed scripts. We now look
    # up __file__ directly and only fall back to download when it's
    # genuinely undefined (curl-pipe / `python3 -` from stdin).
    current_path: Optional[str]
    try:
        current_path = os.path.abspath(__file__)
    except NameError:
        current_path = None

    if (current_path
            and os.path.exists(current_path)
            and os.path.exists(PERMANENT_SCRIPT_PATH)
            and os.path.samefile(current_path, PERMANENT_SCRIPT_PATH)):
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
    """Write CRON_FILE with daily --renew + 5-min --ddns-update lines.

    Idempotent overwrite. DDNS runs every 5 minutes so a fresh WAN IP gets
    pushed promptly; --renew is daily because ACME doesn't need higher
    cadence and rate limits favour caution.
    """
    try:
        os.makedirs(os.path.dirname(CRON_FILE), exist_ok=True)
        with open(CRON_FILE, 'w', encoding='utf-8') as fh:
            fh.write('# UniFi cert auto-renewal + DDNS\n')
            fh.write('# Auto-generated by unifi-cert.py self_heal()\n')
            fh.write(CRON_LINE)
            fh.write(DDNS_CRON_LINE)
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


# =============================================================================
# DDNS - DigitalOcean A-record auto-refresh
# =============================================================================
#
# Telus rotates the WAN IP on every modem reboot / DHCP-lease expiry / power
# blip, which silently breaks inbound connectivity to the cert hostname even
# while DNS-01 cert obtain keeps working. We reuse the existing DigitalOcean
# API token (used for cert obtain) to keep the cert hostname's A-record fresh.
# Drops the dependency on a third-party DDNS service.
#
# Provider lock-in: DigitalOcean only for v1. Same provisioning shape supports
# Cloudflare / Route53 / others later — dispatch on dns_provider value.

DDNS_API_BASE = 'https://api.digitalocean.com/v2'
DDNS_TIMEOUT = 10  # seconds, per-request

DDNS_CRON_LINE = (
    f'*/5 * * * * root /usr/bin/python3 {PERMANENT_SCRIPT_PATH} --ddns-update '
    f'>> {LOG_FILE} 2>&1\n'
)


def _ddns_request(method: str, url: str, token: str,
                   body: Optional[dict] = None) -> dict:
    """Issue a DigitalOcean API request, return parsed JSON.

    Raises urllib.error.URLError on transport failure, RuntimeError on
    HTTP non-2xx. Returns parsed dict on success ({} for empty body).
    """
    data = None
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json',
    }
    if body is not None:
        data = json.dumps(body).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=DDNS_TIMEOUT) as resp:
        status = getattr(resp, 'status', None) or resp.getcode()
        if status >= 300:
            raise RuntimeError(f'{method} {url}: HTTP {status}')
        raw = resp.read()
        if not raw:
            return {}
        return json.loads(raw.decode('utf-8'))


def _ddns_extract_token(creds_path: str, provider: str = 'digitalocean') -> Optional[str]:
    """Extract dns_<provider>_token value from a certbot credentials INI."""
    field_name = DNS_PROVIDERS.get(provider, {}).get('field')
    if not field_name:
        return None
    try:
        with open(creds_path, 'r', encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                if k.strip() == field_name:
                    return v.strip()
    except OSError:
        return None
    return None


def _ddns_resolve_zone(token: str, domain: str) -> tuple[Optional[str], Optional[str]]:
    """Find the DigitalOcean zone that owns `domain`.

    Lists user's DigitalOcean domains and finds the longest suffix match —
    handles multi-part TLDs (e.g. co.uk) without hardcoding a public-suffix
    list. Returns (zone, host) where host is '@' for the apex.
    """
    try:
        data = _ddns_request('GET', f'{DDNS_API_BASE}/domains', token)
    except (urllib.error.URLError, RuntimeError, json.JSONDecodeError) as e:
        ui.error(f'DigitalOcean API error listing domains: {e}')
        return None, None

    names = [d.get('name', '') for d in data.get('domains', [])]
    matches = [n for n in names if n and (domain == n or domain.endswith('.' + n))]
    if not matches:
        return None, None
    zone = max(matches, key=len)
    host = '@' if domain == zone else domain[:-(len(zone) + 1)]
    return zone, host


def _ddns_get_a_record(token: str, zone: str,
                        host: str) -> tuple[Optional[int], Optional[str]]:
    """Return (record_id, current_ip) for the A record at host.zone.

    Returns (None, None) if the record doesn't exist or the API call fails.
    """
    name = zone if host == '@' else f'{host}.{zone}'
    url = f'{DDNS_API_BASE}/domains/{zone}/records?type=A&name={name}'
    try:
        data = _ddns_request('GET', url, token)
    except (urllib.error.URLError, RuntimeError, json.JSONDecodeError) as e:
        ui.error(f'DigitalOcean API error fetching A record: {e}')
        return None, None
    records = data.get('domain_records', [])
    if not records:
        return None, None
    rec = records[0]
    return rec.get('id'), rec.get('data')


def _ddns_put_a_record(token: str, zone: str, record_id: int, new_ip: str) -> bool:
    """PUT a new IP value for the A record. Returns True on HTTP 2xx."""
    url = f'{DDNS_API_BASE}/domains/{zone}/records/{record_id}'
    try:
        _ddns_request('PUT', url, token, body={'data': new_ip})
    except (urllib.error.URLError, RuntimeError, json.JSONDecodeError) as e:
        ui.error(f'DigitalOcean API error updating record: {e}')
        return False
    return True


def ddns_update(domain: Optional[str] = None,
                dns_credentials: Optional[str] = None,
                force: bool = False) -> bool:
    """Refresh the DigitalOcean A record for `domain` to the current public IP.

    Reads provisioning config when args missing (the cron-fired case).
    Idempotent — matching IP is a no-op (debug log only). Pass force=True
    to PATCH even when the record matches.
    """
    cfg = load_provisioning_config()
    domain = domain or cfg.get('domain')
    dns_credentials = dns_credentials or cfg.get('dns_credentials')
    dns_provider = cfg.get('dns_provider', 'digitalocean')

    if not domain:
        ui.error('--ddns-update needs a domain (use -d or seed provisioning config).')
        return False
    if dns_provider != 'digitalocean':
        ui.error(f'--ddns-update currently supports digitalocean only '
                 f'(provisioning config has dns_provider={dns_provider}).')
        return False
    if not dns_credentials or not os.path.exists(dns_credentials):
        ui.error(f'DNS credentials file not found: {dns_credentials}')
        return False

    token = _ddns_extract_token(dns_credentials, dns_provider)
    if not token:
        ui.error(f'Could not extract dns_{dns_provider}_token from {dns_credentials}.')
        return False

    public_ip = get_public_ip(timeout=5)
    if not public_ip:
        ui.error('Could not determine public IP from any provider.')
        return False

    zone, host = _ddns_resolve_zone(token, domain)
    if not zone:
        ui.error(f'No DigitalOcean zone found for {domain}.')
        return False

    record_id, current_ip = _ddns_get_a_record(token, zone, host)
    if record_id is None:
        ui.error(f'No A record found for {host}.{zone}; create it first '
                 'in the DigitalOcean web UI.')
        return False

    if current_ip == public_ip and not force:
        ui.debug(f'A record {host}.{zone} already up to date: {public_ip}')
        return True

    if _ddns_put_a_record(token, zone, record_id, public_ip):
        ui.success(f'Updated {host}.{zone} A → {public_ip} (was {current_ip})')
        return True
    return False


# Set this to a SHA-256 hex digest of a known-good unifi-cert.py release to
# enable --enable-hook-autoupdate. Empty string disables the path entirely
# (refusing the flag at install time) — that's the safe default. Bumping the
# pin is a code change, not a runtime upgrade.
HOOK_AUTOUPDATE_SHA256 = ''


def setup_renewal_hook(domain: str, script_path: str = None,
                        enable_autoupdate: bool = False) -> bool:
    """Set up the certbot post-renewal hook.

    The hook calls --deploy-hook against the locally installed script.
    By default it does NOT phone home or self-update. The previous
    GitHub-curl-and-replace-mid-run pattern overwrote an in-flight
    unifi-cert.py with main-branch HEAD on 2026-04-27, which is the
    same anti-pattern that bit GlennR's installer.

    Pass enable_autoupdate=True to re-enable the download path; that
    requires HOOK_AUTOUPDATE_SHA256 to be set to a known-good pin. The
    hook then verifies the download matches the pin before atomic-replacing
    the script — mismatches are logged and the existing script is kept.
    """
    hook_dir = '/etc/letsencrypt/renewal-hooks/post'
    hook_path = os.path.join(hook_dir, 'unifi-cert-hook.sh')

    permanent_path = script_path or PERMANENT_SCRIPT_PATH

    if enable_autoupdate and not HOOK_AUTOUPDATE_SHA256:
        ui.error(
            '--enable-hook-autoupdate requires a HOOK_AUTOUPDATE_SHA256 pin '
            'baked into unifi-cert.py. Refusing to install an unpinned '
            'auto-update hook.'
        )
        return False

    if enable_autoupdate:
        autoupdate_block = f'''
# Pinned auto-update: download, sha256-verify against the baked-in pin, then
# atomic replace. Mismatches keep the existing script and log to stderr.
TMP="$SCRIPT.new"
curl -sL --connect-timeout 10 --max-time 30 \\
    https://raw.githubusercontent.com/jdlien/unifi-cert/main/unifi-cert.py \\
    -o "$TMP" 2>/dev/null

if [ -s "$TMP" ]; then
    ACTUAL=$(sha256sum "$TMP" | awk '{{print $1}}')
    if [ "$ACTUAL" = "{HOOK_AUTOUPDATE_SHA256}" ]; then
        mv "$TMP" "$SCRIPT"
        chmod +x "$SCRIPT"
    else
        echo "unifi-cert hook: sha256 mismatch (got $ACTUAL); keeping existing script" >&2
        rm -f "$TMP"
    fi
else
    rm -f "$TMP" 2>/dev/null
fi
'''
    else:
        autoupdate_block = (
            '# Auto-update disabled by default; ship updates via pinned releases.\n'
            '# Re-enable with `--setup-hook --enable-hook-autoupdate` once a SHA-256\n'
            '# pin is baked into unifi-cert.py (HOOK_AUTOUPDATE_SHA256).\n'
        )

    hook_content = f"""#!/bin/bash
# UniFi Certificate renewal hook
# Auto-generated by unifi-cert.py — do not edit by hand.
# Domain: {domain}

SCRIPT="{permanent_path}"
RENEWED_LINEAGE="${{RENEWED_LINEAGE:-}}"
{autoupdate_block}
if [ ! -x "$SCRIPT" ]; then
    echo "ERROR: unifi-cert.py not found at $SCRIPT" >&2
    exit 1
fi

# Sync the renewed lineage to UniFi. --deploy-hook reads $RENEWED_LINEAGE
# from the env certbot sets when firing renewal hooks.
if [ -n "$RENEWED_LINEAGE" ]; then
    /usr/bin/python3 "$SCRIPT" --deploy-hook >> {LOG_FILE} 2>&1
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
# STATUS - human-readable health report
# =============================================================================
#
# print_status() composes existing helpers (CertMetadata, certbot venv version,
# cron / hook / boot-script presence, inventory_glennr(), log tail, lock state)
# into a one-shot report for "is this device set up correctly?". When --host is
# passed, the verb is dispatched to the remote device via _dispatch_remote_verb
# and the output is forwarded back. The local code path is the canonical
# implementation; the remote path is just SCP+SSH around the same code.

RENEWAL_HOOK_PATH = '/etc/letsencrypt/renewal-hooks/post/unifi-cert-hook.sh'
STATUS_LOG_TAIL_LINES = 20


def _format_cert_block(meta: 'CertMetadata', source_label: str,
                        domain: Optional[str]) -> None:
    """Emit cert metadata + days-remaining + renewal-due as a UI table."""
    days_remaining = ''
    try:
        if meta.valid_to:
            expiry = datetime.strptime(meta.valid_to, '%Y-%m-%d %H:%M:%S+00')
            delta = expiry - datetime.utcnow()
            days_remaining = f'{delta.days} days'
    except ValueError:
        days_remaining = '(unparseable)'

    rows = [
        ('Source', source_label),
        ('CN', meta.cn or '(unknown)'),
        ('Issuer', meta.issuer_o or '(unknown)'),
        ('Valid from', meta.valid_from or '(unknown)'),
        ('Valid to', meta.valid_to or '(unknown)'),
        ('Remaining', days_remaining or '(unknown)'),
        ('SANs', ', '.join(meta.sans) if meta.sans else '(none)'),
    ]
    ui.table(rows)
    if domain:
        try:
            due = is_renewal_due(domain)
            if due:
                ui.warning(f'Renewal due for {domain} (within 30 days)')
            else:
                ui.success(f'Renewal not yet due for {domain}')
        except Exception as e:
            ui.debug(f'is_renewal_due() raised: {e}')


def _print_certificate_section(domain: Optional[str]) -> bool:
    """Print certificate metadata block. Returns True if a cert was found."""
    candidates: list[tuple[str, str]] = []
    if domain:
        candidates.append((
            f'lineage ({CERTBOT_CONFIG_DIR}/live/{domain}/fullchain.pem)',
            os.path.join(certbot_live_dir(domain), 'fullchain.pem'),
        ))
    candidates.append(('EUS cert', UNIFI_PATHS['eus_cert']))

    for label, path in candidates:
        if not os.path.exists(path):
            continue
        try:
            meta = CertMetadata.from_cert_file(path)
        except Exception as e:
            ui.warning(f'Could not parse {path}: {e}')
            continue
        _format_cert_block(meta, label, domain)
        return True

    ui.warning('No certificate found at expected paths')
    for _, path in candidates:
        ui.info(f'  tried: {path}')
    return False


def _print_certbot_section() -> None:
    """Report certbot venv presence + reported version."""
    if not os.path.exists(CERTBOT_BIN):
        ui.warning(f'Certbot venv missing: {CERTBOT_BIN}')
        return
    try:
        result = subprocess.run(
            [CERTBOT_BIN, '--version'],
            capture_output=True, text=True, timeout=10,
        )
        version = (result.stdout or result.stderr).strip() or '(no output)'
    except (subprocess.TimeoutExpired, OSError) as e:
        ui.warning(f'Certbot venv at {CERTBOT_BIN} but failed to run: {e}')
        return
    ui.success(f'Certbot venv: {CERTBOT_BIN}')
    ui.info(f'  {version}')


def _print_schedule_section() -> None:
    """Cron file, renewal hook, on_boot.d boot script."""
    if os.path.exists(CRON_FILE):
        ui.success(f'Cron: {CRON_FILE}')
        try:
            with open(CRON_FILE, 'r', encoding='utf-8') as fh:
                for line in fh:
                    stripped = line.strip()
                    if stripped and not stripped.startswith('#'):
                        ui.info(f'  {stripped}')
        except OSError as e:
            ui.warning(f'Could not read cron file: {e}')
    else:
        ui.warning(f'Cron missing: {CRON_FILE}')

    if os.path.exists(RENEWAL_HOOK_PATH):
        ui.success(f'Renewal hook: {RENEWAL_HOOK_PATH}')
    else:
        ui.warning(f'Renewal hook missing: {RENEWAL_HOOK_PATH}')

    if os.path.exists(BOOT_SCRIPT_PATH):
        ui.success(f'Boot script: {BOOT_SCRIPT_PATH}')
    elif os.path.isdir(BOOT_SCRIPT_DIR):
        ui.warning(f'Boot script missing: {BOOT_SCRIPT_PATH}')
    else:
        ui.info(f'Boot script: skipped ({BOOT_SCRIPT_DIR} not present)')


def _print_lock_section() -> None:
    """Lock file mtime + held/idle state."""
    if not os.path.exists(LOCK_FILE):
        ui.info('Lock file: not present (no renewal has acquired it)')
        return
    try:
        mtime = datetime.fromtimestamp(os.path.getmtime(LOCK_FILE)).isoformat(
            timespec='seconds'
        )
    except OSError:
        mtime = '(unknown)'
    held = False
    try:
        fh = acquire_lock(timeout=0)
    except BlockingIOError:
        held = True
    else:
        release_lock(fh)
    state = 'HELD (renewal in progress)' if held else 'idle'
    ui.info(f'Lock file: {LOCK_FILE} ({state}, mtime {mtime})')


def _print_glennr_section() -> None:
    """GlennR residue scan via inventory_glennr()."""
    inv = inventory_glennr()
    if not inv.detected_paths:
        ui.success('No GlennR residue detected')
        return
    ui.warning(f'{len(inv.detected_paths)} GlennR path(s) still present:')
    for path, kind, _ in inv.detected_paths:
        ui.info(f'  {kind:11s} {path}')
    ui.info('Run --migrate-glennr to import provisioning + clean up.')


def _print_log_tail_section() -> None:
    """Last STATUS_LOG_TAIL_LINES of LOG_FILE."""
    if not os.path.exists(LOG_FILE):
        ui.info(f'No log file at {LOG_FILE} yet')
        return
    try:
        with open(LOG_FILE, 'r', encoding='utf-8', errors='replace') as fh:
            lines = fh.readlines()
    except OSError as e:
        ui.warning(f'Could not read log: {e}')
        return
    if not lines:
        ui.info(f'{LOG_FILE} is empty')
        return
    tail = lines[-STATUS_LOG_TAIL_LINES:]
    ui.info(f'{LOG_FILE} (last {len(tail)} lines):')
    for line in tail:
        print(f'    {line.rstrip()}')


def print_status(host: Optional[str] = None,
                  args: Optional[argparse.Namespace] = None) -> int:
    """Print a human-readable status report.

    Local mode (host=None): inspect the current device's cert state, certbot
    venv, cron/hook/boot script, lock state, GlennR residue, and log tail.
    Remote mode (host=...): SCP the script to the device if needed and
    SSH-execute `--status` there, forwarding stdout back to the caller.
    """
    if host:
        if args is None:
            args = argparse.Namespace(
                domain=None, email=None, dns_provider=None, dns_credentials=None,
                dry_run=False, force=False, verbose=False, no_color=False,
                propagation=60,
            )
        return dispatch_remote_verb('--status', host, args)

    ui.header('UniFi Certificate Status')

    cfg = load_provisioning_config()
    domain = cfg.get('domain') or detect_domain_from_cert()
    ui.table([
        ('Domain', cfg.get('domain') or '(unset)'),
        ('Email', cfg.get('email') or '(unset)'),
        ('DNS provider', cfg.get('dns_provider') or '(unset)'),
        ('DNS credentials', cfg.get('dns_credentials') or '(unset)'),
        ('Provisioning config', PROVISIONING_CONFIG
            if os.path.exists(PROVISIONING_CONFIG) else '(missing)'),
    ])

    ui.header('Certificate')
    _print_certificate_section(domain)

    ui.header('Certbot')
    _print_certbot_section()

    ui.header('Schedule & hooks')
    _print_schedule_section()
    _print_lock_section()

    ui.header('GlennR residue')
    _print_glennr_section()

    ui.header('Log tail')
    _print_log_tail_section()

    return 0


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


# Verbs supported via --host. --install is intentionally absent — it has its
# own remote path (install_certificate_remote) that streams cert+key by SCP.
REMOTE_DISPATCH_VERBS = (
    '--status', '--renew', '--self-heal', '--migrate-glennr',
    '--ddns-update', '--bootstrap', '--setup-hook',
)


def _local_script_path() -> Optional[str]:
    """Return absolute path to the running script, or None when curl-piped.

    Pipe-from-stdin invocations have no real __file__ to upload, so remote
    dispatch refuses to run rather than silently using a stale device-side
    copy.
    """
    if '__file__' not in globals():
        return None
    candidate = os.path.abspath(__file__)
    if not os.path.isfile(candidate):
        return None
    return candidate


def _file_sha256(path: str) -> str:
    """Hex SHA-256 of a file, or '' on read error."""
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as fh:
            for chunk in iter(lambda: fh.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ''


def ensure_remote_script(host: str, local_path: Optional[str] = None) -> bool:
    """SCP the local script to PERMANENT_SCRIPT_PATH on host when sha differs.

    Compares the local sha256 against the remote sha256. If they match, no
    upload is needed. Creates the parent directory and chmod's 0755 after
    upload. Returns False if no usable local script exists, the SSH probe
    fails, or the SCP fails.
    """
    if local_path is None:
        local_path = _local_script_path()
    if not local_path:
        ui.error('Cannot determine local script path (was the script piped from stdin?). '
                 'Clone the repo and run from a checked-out unifi-cert.py.')
        return False

    local_sha = _file_sha256(local_path)
    if not local_sha:
        ui.error(f'Could not hash local script: {local_path}')
        return False

    success, output = run_remote(
        host,
        f'sha256sum {shlex.quote(PERMANENT_SCRIPT_PATH)} 2>/dev/null',
        timeout=15,
    )
    remote_sha = ''
    if success and output:
        parts = output.strip().split()
        if parts:
            remote_sha = parts[0]

    if remote_sha == local_sha:
        ui.debug(f'Remote script up-to-date on {host} (sha256 {local_sha[:12]}…)')
        return True

    ui.status(f'Deploying script to {host}:{PERMANENT_SCRIPT_PATH}')
    mkdir_ok, _ = run_remote(
        host,
        f'mkdir -p {shlex.quote(os.path.dirname(PERMANENT_SCRIPT_PATH))}',
        timeout=10,
    )
    if not mkdir_ok:
        ui.error(f'Could not create remote script dir on {host}')
        return False
    if not scp_file(local_path, host, PERMANENT_SCRIPT_PATH):
        ui.error(f'SCP to {host}:{PERMANENT_SCRIPT_PATH} failed')
        return False
    chmod_ok, _ = run_remote(host, f'chmod 0755 {shlex.quote(PERMANENT_SCRIPT_PATH)}',
                              timeout=10)
    if not chmod_ok:
        ui.warning(f'Uploaded script but chmod failed on {host}')
    ui.success(f'Deployed (sha256 {local_sha[:12]}…)')
    return True


def _build_remote_command(verb: str, args: argparse.Namespace) -> str:
    """Build the shell command string sent over SSH for a remote verb.

    Forwards the curated set of args that make sense across verbs. String-
    valued flags are shlex-quoted; flag-only switches pass-through. The
    --no-color flag is always appended so remote stdout is plain text.
    """
    parts: list[str] = ['/usr/bin/python3', PERMANENT_SCRIPT_PATH, verb]

    string_flags = (
        ('-d', getattr(args, 'domain', None)),
        ('-e', getattr(args, 'email', None)),
        ('--dns-provider', getattr(args, 'dns_provider', None)),
        ('--dns-credentials', getattr(args, 'dns_credentials', None)),
    )
    for flag, value in string_flags:
        if value:
            parts.extend([flag, str(value)])

    bool_flags = (
        ('--dry-run', getattr(args, 'dry_run', False)),
        ('--force', getattr(args, 'force', False)),
        ('--skip-postgres', getattr(args, 'skip_postgres', False)),
        ('--skip-restart', getattr(args, 'skip_restart', False)),
        ('-v', getattr(args, 'verbose', False)),
    )
    for flag, value in bool_flags:
        if value:
            parts.append(flag)

    # Always strip ANSI on the remote so we forward plain text.
    parts.append('--no-color')

    return ' '.join(shlex.quote(p) for p in parts)


def dispatch_remote_verb(verb: str, host: str, args: argparse.Namespace,
                          timeout: int = 600) -> int:
    """SCP-then-SSH a verb to a remote UniFi device.

    Refuses --migrate-glennr without --dry-run/--force (no TTY for prompts).
    Returns the verb's exit status (0 on success, 1 on failure).
    """
    if verb not in REMOTE_DISPATCH_VERBS:
        ui.error(f'Verb not supported for remote dispatch: {verb}')
        return 1

    if verb == '--migrate-glennr' and not (
        getattr(args, 'dry_run', False) or getattr(args, 'force', False)
    ):
        ui.error(
            'Remote --migrate-glennr requires --dry-run or --force '
            '(SSH session has no TTY for confirmation prompts).'
        )
        return 1

    # SSH sanity probe before bothering with hashing/upload.
    success, _ = run_remote(host, 'true', timeout=10)
    if not success:
        ui.error(f'Cannot SSH to {host} (is the host up and your key authorized?)')
        return 1

    if not ensure_remote_script(host):
        return 1

    cmd = _build_remote_command(verb, args)
    ui.status(f'Running on {host}: {verb}')
    success, output = run_remote(host, cmd, timeout=timeout)
    if output:
        # Forward remote output verbatim. Strip a trailing newline so we
        # don't double up with print()'s own newline.
        sys.stdout.write(output if output.endswith('\n') else output + '\n')
        sys.stdout.flush()
    return 0 if success else 1


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
    parser.add_argument('--migrate-glennr', action='store_true',
                       help='Import GlennR provisioning, snapshot, rsync '
                            '/etc/letsencrypt → /data/unifi-cert/letsencrypt, '
                            'and uninstall GlennR\'s footprint. Use --dry-run '
                            'to preview, --force to skip per-path confirms.')
    parser.add_argument('--ddns-update', action='store_true',
                       help='Refresh the cert hostname A record at the DNS '
                            'provider to current public IP. DigitalOcean only.')
    parser.add_argument('--status', action='store_true',
                       help='Print a health report (cert, certbot venv, cron, '
                            'hook, GlennR residue, log tail). Combine with '
                            '--host to inspect a remote device.')

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

    # main() already printed the program header before dispatching here;
    # don't duplicate it.
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


# =============================================================================
# VERB HANDLERS - one function per CLI verb, dispatched by VERB_HANDLERS below.
# =============================================================================
#
# Each handler reads the parsed args namespace and returns the process exit
# code (0 success, 1 failure). The shared prep logic in main() — UI setup,
# remote dispatch short-circuit, interactive mode, domain auto-detect — runs
# before dispatch lands here. Handlers assume args.domain is either set or
# explicitly optional for that verb (automation verbs that read from
# PROVISIONING_CONFIG / $RENEWED_LINEAGE).

def _handle_bootstrap(args: argparse.Namespace) -> int:
    """`--bootstrap`: build/repair the persistent certbot venv only."""
    if not args.dns_provider:
        ui.error('--dns-provider is required for bootstrap '
                 '(controls which DNS plugin to install).')
        return 1
    ok, msg = bootstrap_certbot(args.dns_provider, force=args.force)
    if ok:
        ui.success(f'Bootstrap complete: {msg}')
        return 0
    ui.error(f'Bootstrap failed: {msg}')
    return 1


def _handle_setup_hook(args: argparse.Namespace) -> int:
    """`--setup-hook`: write the certbot post-renewal hook (no ACME)."""
    ensure_script_installed()
    if setup_renewal_hook(args.domain or 'example.com',
                           enable_autoupdate=args.enable_hook_autoupdate):
        ui.success('Renewal hook configured')
        return 0
    return 1


def _handle_deploy_hook(args: argparse.Namespace) -> int:
    """`--deploy-hook`: certbot post-renewal entry. Reads $RENEWED_LINEAGE."""
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


def _handle_self_heal(args: argparse.Namespace) -> int:
    """`--self-heal`: idempotent repair (venv + cron + hook + boot)."""
    ok = self_heal(dns_provider=args.dns_provider, domain=args.domain)
    return 0 if ok else 1


def _handle_migrate_glennr(args: argparse.Namespace) -> int:
    """`--migrate-glennr`: import GlennR provisioning + uninstall its footprint.

    CLI flags (-d / -e / --dns-provider / --dns-credentials) override the
    inventory's discovered values. Useful when the inventory can't find a
    field (most often email, since certbot rarely persists it).
    """
    ok = migrate_glennr(
        dry_run=args.dry_run,
        force=args.force,
        domain_override=args.domain,
        email_override=args.email,
        dns_provider_override=args.dns_provider,
        dns_credentials_override=args.dns_credentials,
    )
    return 0 if ok else 1


def _handle_ddns_update(args: argparse.Namespace) -> int:
    """`--ddns-update`: refresh A record at DNS provider to current public IP."""
    rotate_log()
    ok = ddns_update(domain=args.domain,
                     dns_credentials=args.dns_credentials,
                     force=args.force)
    return 0 if ok else 1


def _handle_renew(args: argparse.Namespace) -> int:
    """`--renew`: cron entry — lock + self-heal + ACME-if-due + sync.

    Self-heals first so cron + venv + hook are correct even when this
    firing decides not to call certbot. ACME runs only when renewal is
    due (or --force). The lock prevents overlap with --deploy-hook if a
    foreign certbot triggers our post-hook mid-renewal.
    """
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


def _handle_install(args: argparse.Namespace) -> int:
    """`--install`: install an existing cert/key pair (local or via --host)."""
    if not args.cert or not args.key:
        ui.error('--install requires --cert and --key')
        return 1
    if not os.path.exists(args.cert):
        ui.error(f'Certificate file not found: {args.cert}')
        return 1
    if not os.path.exists(args.key):
        ui.error(f'Key file not found: {args.key}')
        return 1

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


def _handle_obtain_new(args: argparse.Namespace) -> int:
    """Default verb: obtain via certbot, install, save provisioning + schedule."""
    if not args.email:
        ui.error('Email is required for obtaining new certificates. Use -e/--email.')
        return 1
    if not args.dns_provider:
        ui.error('DNS provider is required. Use --dns-provider.')
        return 1

    if not args.dns_credentials:
        default_creds = os.path.expanduser(
            f'~/.secrets/certbot/{args.dns_provider}.ini')
        if os.path.exists(default_creds):
            ui.info(f'Using credentials from: {default_creds}')
            args.dns_credentials = default_creds
        else:
            ui.error('DNS credentials file is required. Use --dns-credentials.')
            ui.info(f'Tip: Create {default_creds} with your API token.')
            return 1

    valid, msg = validate_dns_credentials(args.dns_provider, args.dns_credentials)
    if not valid:
        ui.error(msg)
        return 1

    success, cert_path, key_path = run_certbot(
        args.domain, args.email, args.dns_provider, args.dns_credentials,
        propagation=args.propagation,
        dry_run=args.dry_run,
        force=args.force,
    )
    if not success:
        return 1
    if args.dry_run:
        ui.success('Dry run completed successfully')
        return 0

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

    if not success:
        return 1

    # Install script to permanent location, set up renewal hook + cron, and
    # persist provisioning config so cron-fired --renew can self-configure.
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


# Verb-dispatch table. Each entry is (args attribute, handler). Order is
# the resolution order when multiple verb flags are set on argv. --status
# and remote-host dispatch are short-circuited in main() before this loop.
VERB_HANDLERS = (
    ('bootstrap', _handle_bootstrap),
    ('setup_hook', _handle_setup_hook),
    ('deploy_hook', _handle_deploy_hook),
    ('self_heal', _handle_self_heal),
    ('migrate_glennr', _handle_migrate_glennr),
    ('ddns_update', _handle_ddns_update),
    ('renew', _handle_renew),
    ('install', _handle_install),
)


def main() -> int:
    """Main entry point."""
    global ui

    args = parse_args()
    ui = UI(color=not args.no_color, verbose=args.verbose)

    ui.header('UniFi Certificate Manager')

    # Remote dispatch short-circuit. Verbs in REMOTE_DISPATCH_VERBS combined
    # with --host SCP the script to the device (when sha differs) and SSH-
    # execute the verb there, then forward stdout back. --install has its
    # own remote path and is intentionally excluded.
    if args.host:
        remote_verb = None
        if args.status:
            remote_verb = '--status'
        elif args.renew:
            remote_verb = '--renew'
        elif args.self_heal:
            remote_verb = '--self-heal'
        elif args.migrate_glennr:
            remote_verb = '--migrate-glennr'
        elif args.ddns_update:
            remote_verb = '--ddns-update'
        elif args.bootstrap:
            remote_verb = '--bootstrap'
        elif args.setup_hook:
            remote_verb = '--setup-hook'
        if remote_verb:
            return dispatch_remote_verb(remote_verb, args.host, args)

    # Status report (local). Compose existing helpers — no side effects.
    if args.status:
        return print_status()

    # Automation verbs run non-interactively even on a TTY — cron, certbot
    # deploy-hooks, and on_boot.d invoke us, never a human.
    automation_verb = (
        args.renew or args.deploy_hook or args.self_heal or args.bootstrap
        or args.migrate_glennr or args.ddns_update
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

    # Verb dispatch — each handler returns the process exit code. Order
    # matters only because multiple verbs can co-occur on argv (e.g. a
    # human passing --renew --setup-hook by mistake); the first match wins.
    for attr, handler in VERB_HANDLERS:
        if getattr(args, attr, False):
            return handler(args)

    return _handle_obtain_new(args)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('\nCancelled')
        sys.exit(130)
