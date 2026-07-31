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
import ipaddress
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
import urllib.parse
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

# IP lookup providers (fallback chain). Each extractor takes the raw response
# body as text and returns an address string, so plain-text endpoints can sit
# alongside JSON ones.
#
# Ordering is load-bearing, for two reasons:
#
#   1. IPv4-ONLY HOSTNAMES FIRST. We are filling in an A record, which can only
#      hold an IPv4 address — but a dual-stack device (Telus hands out IPv6)
#      will happily reach a dual-stack lookup service over v6, and be told its
#      v6 address. Observed live: ipwho.is answered 2001:56a:… from the same
#      machine where ipify answered 198.53.200.179. Hostnames that publish only
#      an A record force the connection over v4, so the answer is the address
#      we actually need. The dual-stack services stay as fallbacks: they're
#      correct on v4-only networks, and get skipped by is_public_ipv4()
#      elsewhere.
#   2. TLS BEFORE PLAINTEXT. Whatever comes back here is published in DNS, so
#      an answer an on-path party could rewrite is the last resort.
#
# my-ip.ca leads because it's first-party (no third-party rate limits, and its
# operator is the person running this tool). The public services stay behind it
# so a single host being down can't stall DDNS — hence a chain, not one source.
IP_PROVIDERS = [
    # /ip/ is the plain-text endpoint. The bare host content-negotiates and
    # serves a full HTML page to anything it doesn't recognize as a CLI.
    ('https://ipv4.my-ip.ca/ip/', lambda b: b.strip()),
    ('https://api4.ipify.org?format=json', lambda b: json.loads(b).get('ip')),
    ('https://ipv4.icanhazip.com', lambda b: b.strip()),
    ('https://ipwho.is/', lambda b: json.loads(b).get('ip')),
    ('https://json.geoiplookup.io/', lambda b: json.loads(b).get('ip')),
    ('https://api.ipify.org?format=json', lambda b: json.loads(b).get('ip')),
    ('http://ip-api.com/json/', lambda b: json.loads(b).get('query')),
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

def is_public_ipv4(value: Optional[str]) -> bool:
    """True only for a syntactically valid, globally routable IPv4 address.

    A regex match isn't enough here: this value is published as an A record.
    A captive portal or hijacked DNS answering with 192.168.x.x would sail
    past a shape check and then point the hostname at nothing reachable.
    """
    try:
        addr = ipaddress.IPv4Address((value or '').strip())
    except (ipaddress.AddressValueError, ValueError):
        return False
    return addr.is_global and not addr.is_multicast


def get_public_ip(timeout: float = 2.0) -> Optional[str]:
    """Get public IP address using fallback providers."""
    import urllib.request
    import urllib.error

    for url, extractor in IP_PROVIDERS:
        try:
            ui.debug(f'Trying IP provider: {url}')
            req = urllib.request.Request(url, headers={'User-Agent': 'unifi-cert/1.0'})
            with urllib.request.urlopen(req, timeout=timeout) as response:
                ip = extractor(response.read().decode())
                if is_public_ipv4(ip):
                    ui.debug(f'Got IP: {ip}')
                    return ip.strip()
                if ip:
                    # Most often an IPv6 address from a dual-stack service
                    # reached over v6. Not an error — just not something an
                    # A record can hold. Try the next provider.
                    #
                    # Truncate: a service that content-negotiates can answer
                    # with an entire HTML page, and this line would otherwise
                    # land in the log every five minutes forever.
                    shown = ip if len(ip) <= 60 else ip[:60].replace('\n', ' ') + '…'
                    ui.debug(f'{url} returned {shown!r}, which is not a public '
                             'IPv4 address; skipping')
        except (urllib.error.URLError, ValueError, KeyError, AttributeError,
                TimeoutError):
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


# Provisioning keys written in this order. The ddns_* trio each falls back to
# its cert equivalent at read time (see _ddns_settings), so an install whose
# cert CN *is* the A record never needs them.
PROVISIONING_KEYS = (
    'domain', 'email', 'dns_provider', 'dns_credentials',
    'ddns_enabled', 'ddns_domain', 'ddns_provider', 'ddns_credentials',
)


def save_provisioning_config(domain: str = None, email: str = None,
                              dns_provider: str = None,
                              dns_credentials: str = None,
                              ddns_domain: str = None,
                              ddns_provider: str = None,
                              ddns_credentials: str = None) -> bool:
    """Persist provisioning fields to PROVISIONING_CONFIG.

    Consumed by cron-fired --renew (no CLI args) so the daily renewal can
    self-configure. Stores the credentials *path*; secrets stay in the
    credentials file under CREDENTIALS_DIR (mode 0600).

    Merges with what's already on disk rather than overwriting it. The ddns_*
    keys are typically hand-added after install, and a later obtain-new run
    must not silently drop them — a wiped ddns_domain falls back to the cert
    CN, which is exactly the misconfiguration this tool exists to prevent.
    """
    config = load_provisioning_config()
    updates = {
        'domain': domain,
        'email': email,
        'dns_provider': dns_provider,
        'dns_credentials': dns_credentials,
        'ddns_domain': ddns_domain,
        'ddns_provider': ddns_provider,
        'ddns_credentials': ddns_credentials,
    }
    config.update({k: v for k, v in updates.items() if v is not None})

    try:
        os.makedirs(UNIFI_CERT_ROOT, mode=0o755, exist_ok=True)
        with open(PROVISIONING_CONFIG, 'w', encoding='utf-8') as fh:
            fh.write('# UniFi Certificate Manager provisioning config\n')
            fh.write('# Auto-generated; consumed by --renew when called without flags\n')
            for key in PROVISIONING_KEYS:
                if key in config:
                    fh.write(f'{key} = {config[key]}\n')
            for key in sorted(set(config) - set(PROVISIONING_KEYS)):
                fh.write(f'{key} = {config[key]}\n')
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


def default_credentials_path(provider: str) -> str:
    """Where to look for, or create, a provider's credentials file.

    On a UniFi device this has to be the persistent root. `~/.secrets` is
    `/root/.secrets` there, which a firmware update wipes — and a credentials
    file left behind becomes a second, forgotten copy of a live API token
    that nothing references and nobody remembers to rotate. Off-device runs
    keep the conventional workstation location.
    """
    if os.path.isdir(UNIFI_PATHS['config_dir']):
        return os.path.join(CREDENTIALS_DIR, f'{provider}.ini')
    return os.path.expanduser(f'~/.secrets/certbot/{provider}.ini')


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
        # Source path doesn't exist (already removed, or moved). Default the
        # config to the canonical persistent path; user must drop the file
        # there before --renew can run. Surfacing the canonical path here
        # avoids leaving a dangling /root/.secrets/<provider>.ini reference
        # that certbot will trip on weeks later.
        ui.warning(
            f'Credentials path {inv.dns_credentials_path} does not exist. '
            f'Provisioning will reference {new_creds_path} — copy your '
            f'{inv.dns_provider} credentials there before the next renewal.'
        )

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

    # Stock UDM Pro SE images don't ship rsync. Fall back to shutil.copytree
    # with symlinks=True so the live/ → archive/ symlink farm survives.
    if shutil.which('rsync') is None:
        ui.info('rsync not found; falling back to shutil.copytree.')
        try:
            shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)
        except (OSError, shutil.Error) as e:
            ui.error(f'copytree fallback failed: {e}')
            return False
        ui.success(f'Migrated /etc/letsencrypt/ → {CERTBOT_CONFIG_DIR}/ (copytree)')
        return True

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


def _purge_glennr_residue_in_lineage() -> None:
    """Strip GlennR-specific hook references from the migrated lineage.

    The rsync of /etc/letsencrypt/ → /data/unifi-cert/letsencrypt/ carries
    GlennR's `pre_hook` / `post_hook = .../EUS_*.sh` lines in
    renewal/<domain>.conf and the `renewal-hooks/{pre,post}/EUS_*.sh`
    scripts themselves. Once `/srv/EUS` is uninstalled those hooks bomb on
    every renewal. We own these files now (they live under the persistent
    root) so editing them in place doesn't violate the migration's
    allowlist invariant.
    """
    renewal_dir = os.path.join(CERTBOT_CONFIG_DIR, 'renewal')
    if os.path.isdir(renewal_dir):
        eus_hook_re = re.compile(r'^\s*(?:pre|post)_hook\s*=.*EUS_', re.IGNORECASE)
        for conf in glob.glob(os.path.join(renewal_dir, '*.conf')):
            try:
                with open(conf, 'r') as f:
                    lines = f.readlines()
            except OSError as e:
                ui.warning(f'Could not read {conf}: {e}')
                continue
            kept = [ln for ln in lines if not eus_hook_re.match(ln)]
            if len(kept) != len(lines):
                try:
                    with open(conf, 'w') as f:
                        f.writelines(kept)
                    ui.info(f'Stripped GlennR hook line(s) from {conf}')
                except OSError as e:
                    ui.warning(f'Could not rewrite {conf}: {e}')

    for sub in ('pre', 'post'):
        for path in glob.glob(os.path.join(
                CERTBOT_CONFIG_DIR, 'renewal-hooks', sub, 'EUS_*.sh')):
            try:
                os.remove(path)
                ui.info(f'Removed migrated GlennR hook {path}')
            except OSError as e:
                ui.warning(f'Could not remove {path}: {e}')


def _normalize_renewal_paths_in_lineage() -> None:
    """Rewrite legacy /etc/letsencrypt/* paths in migrated renewal/<domain>.conf.

    The rsync of /etc/letsencrypt/ → CERTBOT_CONFIG_DIR/ copies the renewal
    config byte-for-byte, including absolute path fields that still reference
    the soon-to-be-deleted /etc/letsencrypt/. Once /etc/letsencrypt/ is
    removed in step 5 of migrate_glennr, certbot reads `archive_dir = /etc/
    letsencrypt/archive/<domain>`, finds nothing there, decides the lineage
    is missing, and forks to <domain>-0001 on the next --renew despite
    --cert-name. The same applies to GlennR's `/root/.secrets/<provider>.ini`
    credentials reference, which won't exist post-migration.

    This helper rewrites:
      - archive_dir / cert / privkey / chain / fullchain prefixes
        /etc/letsencrypt/ → CERTBOT_CONFIG_DIR/
      - dns_<provider>_credentials → CREDENTIALS_DIR/<provider>.ini when the
        original path is outside CERTBOT_CONFIG_DIR/CREDENTIALS_DIR (the
        canonical credentials location set up by import_provisioning_from_glennr).
    """
    renewal_dir = os.path.join(CERTBOT_CONFIG_DIR, 'renewal')
    if not os.path.isdir(renewal_dir):
        return

    legacy_prefix = '/etc/letsencrypt/'
    new_prefix = CERTBOT_CONFIG_DIR.rstrip('/') + '/'
    path_field_re = re.compile(
        r'^(\s*(?:archive_dir|cert|privkey|chain|fullchain)\s*=\s*)'
        + re.escape(legacy_prefix) + r'(.*)$'
    )
    creds_field_re = re.compile(
        r'^(\s*dns_([a-z0-9]+)_credentials\s*=\s*)(\S+)\s*$',
        re.IGNORECASE,
    )

    persistent_roots = (
        CERTBOT_CONFIG_DIR.rstrip('/') + '/',
        CREDENTIALS_DIR.rstrip('/') + '/',
    )

    for conf in glob.glob(os.path.join(renewal_dir, '*.conf')):
        try:
            with open(conf, 'r') as f:
                lines = f.readlines()
        except OSError as e:
            ui.warning(f'Could not read {conf}: {e}')
            continue

        rewritten = []
        changed = False
        for line in lines:
            eol = '\n' if line.endswith('\n') else ''
            stripped = line.rstrip('\n')
            m_path = path_field_re.match(stripped)
            if m_path:
                rewritten.append(m_path.group(1) + new_prefix
                                 + m_path.group(2) + eol)
                changed = True
                continue
            m_creds = creds_field_re.match(stripped)
            if m_creds:
                old_value = m_creds.group(3)
                if not any(old_value.startswith(root) for root in persistent_roots):
                    canonical = os.path.join(
                        CREDENTIALS_DIR, f'{m_creds.group(2).lower()}.ini')
                    rewritten.append(m_creds.group(1) + canonical + eol)
                    changed = True
                    continue
            rewritten.append(line)

        if changed:
            try:
                with open(conf, 'w') as f:
                    f.writelines(rewritten)
                ui.info(f'Normalized paths in {conf}')
            except OSError as e:
                ui.warning(f'Could not rewrite {conf}: {e}')


def _dedupe_le_accounts() -> None:
    """Remove Let's Encrypt accounts not referenced by any renewal config.

    A partially-failed earlier install can leave a second account under
    accounts/<server>/directory/<id>/. certbot then refuses to run
    non-interactively ("Please choose an account"). The migrated
    renewal/<domain>.conf files carry `account = <id>`, which is the
    authoritative answer; everything else is dead weight.
    """
    renewal_dir = os.path.join(CERTBOT_CONFIG_DIR, 'renewal')
    accounts_root = os.path.join(CERTBOT_CONFIG_DIR, 'accounts')
    if not (os.path.isdir(renewal_dir) and os.path.isdir(accounts_root)):
        return

    referenced: set[str] = set()
    account_re = re.compile(r'^\s*account\s*=\s*([0-9a-f]+)\s*$', re.IGNORECASE)
    for conf in glob.glob(os.path.join(renewal_dir, '*.conf')):
        try:
            with open(conf, 'r') as f:
                for line in f:
                    m = account_re.match(line)
                    if m:
                        referenced.add(m.group(1).lower())
        except OSError:
            continue

    if not referenced:
        return  # Don't delete anything we can't justify.

    # accounts/<server>/directory/<id>/
    for server in os.listdir(accounts_root):
        directory = os.path.join(accounts_root, server, 'directory')
        if not os.path.isdir(directory):
            continue
        for acct_id in os.listdir(directory):
            if acct_id.lower() in referenced:
                continue
            acct_path = os.path.join(directory, acct_id)
            try:
                shutil.rmtree(acct_path)
                ui.info(f'Removed unreferenced LE account {acct_id}')
            except OSError as e:
                ui.warning(f'Could not remove {acct_path}: {e}')


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

    # 3a. Scrub GlennR-specific debris that came along in the rsync, and
    # rewrite legacy /etc/letsencrypt/* paths in renewal/*.conf to point
    # at the new persistent root before /etc/letsencrypt/ is removed.
    if has_le:
        _purge_glennr_residue_in_lineage()
        _normalize_renewal_paths_in_lineage()
        _dedupe_le_accounts()

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
    # --cert-name pins the lineage. Without it, any drift between the migrated
    # renewal/<domain>.conf flags and the current CLI flags makes certbot fork
    # to <domain>-0001, after which the script syncs the wrong lineage.
    cmd = [certbot, *certbot_argv_base(), 'certonly',
           '--cert-name', domain,
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


def ddns_is_enabled(cfg: Optional[dict] = None) -> bool:
    """Whether the DDNS cron line should be installed.

    Defaults to on. Set `ddns_enabled = false` in the provisioning config for
    sites whose DDNS is handled elsewhere — without this the cron line is
    unremovable in practice, since self_heal() rewrites CRON_FILE on every
    renewal and every boot.
    """
    if cfg is None:
        cfg = load_provisioning_config()
    return str(cfg.get('ddns_enabled', 'true')).strip().lower() not in (
        'false', 'no', '0', 'off')


def install_cron_schedule() -> bool:
    """Write CRON_FILE with the daily --renew line, plus 5-min --ddns-update.

    Idempotent overwrite. DDNS runs every 5 minutes so a fresh WAN IP gets
    pushed promptly; --renew is daily because ACME doesn't need higher
    cadence and rate limits favour caution. The DDNS line is omitted when
    ddns_enabled is false.
    """
    ddns_enabled = ddns_is_enabled()
    try:
        os.makedirs(os.path.dirname(CRON_FILE), exist_ok=True)
        with open(CRON_FILE, 'w', encoding='utf-8') as fh:
            fh.write('# UniFi cert auto-renewal + DDNS\n')
            fh.write('# Auto-generated by unifi-cert.py self_heal()\n')
            fh.write(CRON_LINE)
            if ddns_enabled:
                fh.write(DDNS_CRON_LINE)
            else:
                fh.write('# DDNS disabled (ddns_enabled = false in '
                         f'{PROVISIONING_CONFIG})\n')
        os.chmod(CRON_FILE, 0o644)
        ui.success(f'Installed cron schedule: {CRON_FILE}')
        if not ddns_enabled:
            ui.info('DDNS cron line omitted (ddns_enabled = false)')
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
# DDNS - A-record auto-refresh (DigitalOcean + Cloudflare)
# =============================================================================
#
# Telus and similar residential ISPs rotate the WAN IP on every modem reboot /
# DHCP-lease expiry / power blip, which silently breaks inbound connectivity to
# the device even while DNS-01 cert obtain keeps working. We reuse a DNS API
# token already on the box to keep the target A record fresh, dropping the
# dependency on a third-party DDNS service.
#
# Two invariants make this safe to fire every five minutes:
#
#   1. NEVER CREATE. We look the record up, edit it *by ID*, and refuse when
#      it's missing. UniFi's built-in inadyn re-resolves by name on every
#      update and POSTs a second record when that lookup misses — which is how
#      home.jdlien.ca ended up carrying two A records, one stale, with clients
#      round-robining onto a dead IP and burning a 3s connect timeout per try.
#      Editing by ID structurally cannot duplicate.
#
#   2. THE DDNS TARGET IS CONFIGURED SEPARATELY FROM THE CERT CN. They are
#      genuinely different records: beehive.jdlien.com (cert CN, DigitalOcean)
#      is a CNAME to home.jdlien.ca (DDNS anchor, Cloudflare). Deriving the
#      target from the cert CN produced 6,295 consecutive "No A record found"
#      failures and zero successful updates. ddns_domain / ddns_provider /
#      ddns_credentials each fall back to the cert equivalent, so installs
#      whose CN *is* the A record need no extra configuration.
#
# Failures are tracked in DDNS_STATE_FILE and reported on an escalating
# schedule rather than every run — the same error 6,295 times is
# indistinguishable from noise, which is how the outage stayed invisible.

DDNS_API_BASES = {
    'digitalocean': 'https://api.digitalocean.com/v2',
    'cloudflare': 'https://api.cloudflare.com/client/v4',
}
DDNS_PROVIDERS = tuple(sorted(DDNS_API_BASES))

DDNS_TIMEOUT = 10           # seconds, per-request
# Page sizes for the diagnostic zone listing only. Zone *resolution* uses
# exact per-name lookups, so no cap here can turn an owned zone into a
# "no such zone" error — these numbers only bound how many names an error
# message is willing to quote back at you.
DDNS_ZONE_PAGE_SIZE = 50    # Cloudflare
DDNS_DO_PER_PAGE = 200      # DigitalOcean max; its default of 20 truncates silently

DDNS_STATE_FILE = f'{UNIFI_CERT_ROOT}/ddns-state.json'

# State keys for failures that belong to the run rather than to any one
# target. Held separately so they can be cleared once the run gets past them.
DDNS_CONFIG_TARGET = '(configuration)'
DDNS_PUBLIC_IP_TARGET = '(public-ip)'
DDNS_SYNTHETIC_TARGETS = (DDNS_CONFIG_TARGET, DDNS_PUBLIC_IP_TARGET)

# Consecutive-failure counts that get a loud report, at a 5-minute cadence:
# the first failure, one hour in, one day in, and daily after that. Everything
# between is logged at debug level so a broken target can't drown the log.
DDNS_FAILURE_ALERTS = (1, 12, 288)

# --status flags a target whose last success is older than this. At a 5-minute
# cadence anything past an hour means the cron job itself stopped running —
# a case that otherwise renders as a reassuring green line forever.
DDNS_STALE_SUCCESS_SECONDS = 3600

DDNS_CRON_LINE = (
    f'*/5 * * * * root /usr/bin/python3 {PERMANENT_SCRIPT_PATH} --ddns-update '
    f'>> {LOG_FILE} 2>&1\n'
)


class DdnsError(Exception):
    """A DDNS operation failed. Message is user-facing and should say why.

    `status` carries the HTTP status when the failure came from a response,
    so callers can distinguish "this zone isn't yours" (404) from "your token
    is bad" (401) without string-matching the message.
    """

    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


@dataclass
class DdnsZone:
    """A resolved zone plus the provider handle used to edit records in it.

    `ref` is what the provider's record endpoints want — the zone *name* for
    DigitalOcean, the zone *id* for Cloudflare — while `name` stays
    human-readable for messages and FQDN reconstruction.
    """
    name: str
    ref: str
    host: str       # label within the zone; '@' for the apex
    provider: str

    @property
    def fqdn(self) -> str:
        return self.name if self.host == '@' else f'{self.host}.{self.name}'


@dataclass
class DdnsSettings:
    """Resolved DDNS configuration: what to update, where, with which token."""
    targets: list
    provider: str
    credentials: str


def _ddns_api_base(provider: str) -> str:
    """API root for a DDNS-capable provider."""
    try:
        return DDNS_API_BASES[provider]
    except KeyError:
        raise DdnsError(
            f'DDNS does not support DNS provider {provider!r} '
            f'(supported: {", ".join(DDNS_PROVIDERS)}).'
        )


def _ddns_error_detail(raw: bytes) -> str:
    """Pull a human message out of a provider error body.

    Cloudflare returns {"success": false, "errors": [{"code", "message"}]};
    DigitalOcean returns {"id", "message"}. Surfacing that beats swallowing
    it — "Invalid API Token" from an IP-allowlisted token reads identically
    to a revoked one unless you can see the body.
    """
    try:
        payload = json.loads((raw or b'').decode('utf-8', 'replace'))
    except ValueError:
        return (raw or b'').decode('utf-8', 'replace').strip()[:200]
    if isinstance(payload, dict):
        errors = payload.get('errors')
        if isinstance(errors, list) and errors:
            return '; '.join(
                str(e.get('message', e)) if isinstance(e, dict) else str(e)
                for e in errors
            )
        if payload.get('message'):
            return str(payload['message'])
        # A well-formed object that simply carries no error text. Return
        # nothing so the caller's own description wins — echoing the raw dict
        # back at the user explains less than the sentence it would replace.
        return ''
    return str(payload)[:200]


def _ddns_request(method: str, url: str, token: str,
                   body: Optional[dict] = None,
                   provider: str = 'digitalocean') -> Any:
    """Issue a provider API request and return the decoded payload.

    Cloudflare wraps every response in {"success", "result", "errors"}; that
    envelope is unwrapped here so callers see the same bare shape DigitalOcean
    returns. Raises DdnsError — with the provider's own error text where it
    supplied one — on transport failure, non-2xx, bad JSON, or any response
    that isn't a well-formed Cloudflare success envelope.

    The Cloudflare check is deliberately allowlist-shaped (success must be
    exactly True, and the envelope must be a dict carrying 'result'). Treating
    an empty or unrecognized body as success is how a write that never
    happened gets logged as one — the exact failure mode this module exists
    to eliminate.
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

    try:
        with urllib.request.urlopen(req, timeout=DDNS_TIMEOUT) as resp:
            status = getattr(resp, 'status', None) or resp.getcode()
            raw = resp.read()
    except urllib.error.HTTPError as e:
        try:
            detail = _ddns_error_detail(e.read())
        except Exception:
            detail = ''
        raise DdnsError(f'{method} {url}: HTTP {e.code}'
                        + (f' — {detail}' if detail else ''), status=e.code)
    except (urllib.error.URLError, OSError) as e:
        raise DdnsError(f'{method} {url}: {e}')

    if status >= 300:
        raise DdnsError(f'{method} {url}: HTTP {status}', status=status)

    if provider == 'cloudflare':
        if not raw:
            raise DdnsError(f'{method} {url}: empty response body — expected a '
                            'Cloudflare success envelope', status=status)
    elif not raw:
        return {}

    try:
        payload = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeDecodeError) as e:
        raise DdnsError(f'{method} {url}: malformed JSON response ({e})',
                        status=status)

    if provider == 'cloudflare':
        if not isinstance(payload, dict):
            raise DdnsError(f'{method} {url}: expected a Cloudflare envelope '
                            f'object, got {type(payload).__name__}', status=status)
        if payload.get('success') is not True:
            raise DdnsError(f'{method} {url}: '
                            f'{_ddns_error_detail(raw) or "request failed"}',
                            status=status)
        if 'result' not in payload:
            raise DdnsError(f'{method} {url}: Cloudflare envelope reported '
                            'success but carried no result', status=status)
        return payload['result']
    return payload


def _ddns_read_creds_field(creds_path: str, field_name: str) -> Optional[str]:
    """Read one `key = value` field out of a certbot credentials INI."""
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


def _ddns_extract_token(creds_path: str, provider: str = 'digitalocean') -> Optional[str]:
    """Extract the provider's API token from a certbot credentials INI."""
    field_name = DNS_PROVIDERS.get(provider, {}).get('field')
    if not field_name:
        return None
    return _ddns_read_creds_field(creds_path, field_name)


def _ddns_token(settings: 'DdnsSettings') -> str:
    """Load the API token for `settings`, or raise with a pointed diagnosis."""
    token = _ddns_extract_token(settings.credentials, settings.provider)
    if token:
        return token

    field = DNS_PROVIDERS.get(settings.provider, {}).get('field', 'the API token')
    hint = ''
    if settings.provider == 'cloudflare' and _ddns_read_creds_field(
        settings.credentials, 'dns_cloudflare_api_key'
    ):
        # The legacy global key grants full account access and only works with
        # X-Auth-Email/X-Auth-Key headers, not bearer auth. Refuse rather than
        # support it — a scoped token is both safer and what certbot wants now.
        hint = (' That file holds a legacy global API key (dns_cloudflare_api_key). '
                'DDNS needs a scoped API token instead: create one under My Profile '
                '→ API Tokens with Zone:DNS:Edit + Zone:Zone:Read, and store it as '
                'dns_cloudflare_api_token.')
    raise DdnsError(f'Could not read {field} from {settings.credentials}.{hint}')


def _ddns_zone_candidates(domain: str) -> list:
    """Parent zones `domain` could live in, longest (most specific) first.

    'home.jdlien.ca' → ['home.jdlien.ca', 'jdlien.ca']. Any leading wildcard
    label is dropped, and the bare TLD is never a candidate. Probing these in
    order gives correct longest-suffix semantics — and correct handling of
    multi-part TLDs like co.uk — without a public-suffix list.
    """
    labels = [l for l in domain.split('.') if l and l != '*']
    return ['.'.join(labels[i:]) for i in range(max(len(labels) - 1, 0))]


def _ddns_lookup_zone(token: str, provider: str, candidate: str) -> Optional[str]:
    """Return the provider ref for `candidate` if the token owns it, else None.

    Exact single-zone lookups rather than a paged listing: a listing walk has
    to stop somewhere, and stopping early reports a zone you *do* own as
    unowned — a false negative dressed up as a configuration error.
    """
    base = _ddns_api_base(provider)
    name = urllib.parse.quote(candidate, safe='')

    if provider == 'cloudflare':
        rows = _ddns_request('GET', f'{base}/zones?name={name}', token,
                             provider='cloudflare')
        for z in (rows if isinstance(rows, list) else []):
            if str(z.get('name', '')).lower() == candidate.lower() and z.get('id'):
                return z['id']
        return None

    try:
        data = _ddns_request('GET', f'{base}/domains/{name}', token)
    except DdnsError as e:
        if e.status == 404:
            return None
        raise
    zone = data.get('domain') if isinstance(data, dict) else None
    if isinstance(zone, dict) and zone.get('name'):
        return zone['name']
    return None


def _ddns_visible_zones(token: str, provider: str) -> list:
    """Sample of zone names the token can see. Diagnostics only.

    Deliberately capped and only ever used to enrich an error message — never
    to decide whether a zone exists, which is what _ddns_lookup_zone is for.
    """
    base = _ddns_api_base(provider)
    try:
        if provider == 'cloudflare':
            rows = _ddns_request(
                'GET', f'{base}/zones?per_page={DDNS_ZONE_PAGE_SIZE}', token,
                provider='cloudflare')
            return sorted(str(z.get('name')) for z in (rows if isinstance(rows, list) else [])
                          if z.get('name'))
        data = _ddns_request('GET', f'{base}/domains?per_page={DDNS_DO_PER_PAGE}', token)
        return sorted(str(d.get('name'))
                      for d in (data.get('domains', []) if isinstance(data, dict) else [])
                      if d.get('name'))
    except DdnsError:
        return []


def _ddns_resolve_zone(token: str, domain: str,
                        provider: str = 'digitalocean') -> DdnsZone:
    """Find the zone that owns `domain`, most specific first.

    On a miss the error names what the token *can* see, because a token scoped
    to the wrong zone and a genuinely missing zone are otherwise identical.
    """
    _ddns_api_base(provider)  # reject non-DDNS providers before any request
    name = None
    ref = None
    for candidate in _ddns_zone_candidates(domain):
        ref = _ddns_lookup_zone(token, provider, candidate)
        if ref:
            name = candidate
            break

    if not name:
        visible = _ddns_visible_zones(token, provider)
        seen = ', '.join(visible[:8]) + ('…' if len(visible) > 8 else '')
        raise DdnsError(
            f'No {provider} zone owns {domain}. '
            f'This token sees: {seen or "no zones at all"}.'
        )
    host = '@' if domain == name else domain[:-(len(name) + 1)]
    return DdnsZone(name=name, ref=ref, host=host, provider=provider)


def _ddns_record_fqdn(zone: DdnsZone, raw_name: str) -> str:
    """Normalize a provider's record name to a comparable FQDN.

    DigitalOcean returns the relative label ('beehive', or '@' for the apex);
    Cloudflare returns the full name. Both collapse to the same string here so
    the caller can compare against what it asked for.
    """
    name = (raw_name or '').strip().rstrip('.').lower()
    if zone.provider == 'cloudflare':
        return name
    if name in ('', '@'):
        return zone.name.lower()
    return f'{name}.{zone.name}'.lower()


def _ddns_list_records(token: str, zone: DdnsZone, rtype: str = 'A') -> list:
    """Return [{'id', 'value'}] for records of `rtype` at zone.fqdn.

    The name is URL-encoded because wildcard targets ('*.home.jdlien.ca') are
    a legitimate and common case — the wildcard carries the same duplicate
    exposure as the bare record and needs updating alongside it.

    Every row is re-checked against the name and type we asked for, and rows
    without an id are dropped. We only ever address records by id for writes,
    so a mismatched row that slipped through the server-side filter would mean
    editing the wrong hostname's A record — "never create" would still hold
    while the actual safety property did not.
    """
    base = _ddns_api_base(zone.provider)
    name = urllib.parse.quote(zone.fqdn, safe='')
    want = zone.fqdn.lower()

    if zone.provider == 'cloudflare':
        result = _ddns_request(
            'GET', f'{base}/zones/{zone.ref}/dns_records?type={rtype}&name={name}',
            token, provider='cloudflare',
        )
        rows = result if isinstance(result, list) else []
        value_key = 'content'
    else:
        data = _ddns_request(
            'GET', f'{base}/domains/{zone.ref}/records?type={rtype}&name={name}', token)
        rows = data.get('domain_records', []) if isinstance(data, dict) else []
        value_key = 'data'

    records = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        record_id = row.get('id')
        if record_id in (None, ''):
            ui.debug(f'Ignoring {rtype} row without an id at {zone.fqdn}: {row}')
            continue
        row_type = str(row.get('type', rtype)).upper()
        row_fqdn = _ddns_record_fqdn(zone, str(row.get('name', '')))
        if row_type != rtype.upper() or row_fqdn != want:
            ui.debug(f'Ignoring {row_type} record for {row_fqdn} returned by a '
                     f'{rtype}/{want} query')
            continue
        records.append({'id': record_id, 'value': row.get(value_key)})
    return records


def _ddns_missing_record_message(token: str, zone: DdnsZone) -> str:
    """Explain a missing A record, naming the CNAME when that's the cause.

    A CNAME at the DDNS target is *the* failure this tool kept hitting, and
    "No A record found" alone gives no hint that the fix is to point
    ddns_domain one hop further down the chain.
    """
    base = (f'No A record found for {zone.fqdn} in the {zone.provider} '
            f'zone {zone.name}.')
    try:
        cnames = _ddns_list_records(token, zone, 'CNAME')
    except Exception as e:
        # Best-effort diagnostic only. Whatever goes wrong probing for the
        # CNAME, the caller still needs the missing-A-record error intact —
        # never let the nicety replace the finding.
        ui.debug(f'CNAME probe for {zone.fqdn} failed: {e}')
        cnames = []
    if cnames:
        target = str(cnames[0].get('value') or '').rstrip('.') or '(unknown target)'
        advice = (f'{base} It is a CNAME → {target}, and a CNAME cannot carry an '
                  f'IP. Set ddns_domain = {target} in {PROVISIONING_CONFIG} so '
                  'DDNS updates the A record at the end of the chain.')
        if target != '(unknown target)' and not (
            target == zone.name or target.endswith('.' + zone.name)
        ):
            # The Beehive shape: the CNAME hops into a zone at another
            # provider. Repointing ddns_domain alone would just move the
            # failure, so name the other two keys as well.
            advice += (f' {target} is outside the {zone.provider} zone '
                       f'{zone.name}, so set ddns_provider and ddns_credentials '
                       'for whichever provider hosts it.')
        return advice
    return (f'{base} Create it once at your DNS provider — this tool edits '
            'existing records by ID and never creates them, so it can never '
            'duplicate one.')


def _ddns_get_a_record(token: str, zone: DdnsZone) -> tuple:
    """Return (record_id, current_ip, record_count) for the A record at zone.fqdn.

    Raises DdnsError when no A record exists. Warns — loudly, every run — when
    more than one exists: that's the exact fingerprint of inadyn's duplicate
    bug, and it degrades connectivity intermittently rather than visibly.
    """
    records = _ddns_list_records(token, zone, 'A')
    if not records:
        raise DdnsError(_ddns_missing_record_message(token, zone))
    if len(records) > 1:
        values = ', '.join(str(r.get('value')) for r in records)
        ui.warning(
            f'{zone.fqdn} has {len(records)} A records ({values}). Only the first '
            'is updated. Clients round-robin between them, so every request that '
            'lands on a stale IP stalls until it times out — delete the extras '
            'at your DNS provider.'
        )
    return records[0].get('id'), records[0].get('value'), len(records)


def _ddns_put_a_record(token: str, zone: DdnsZone, record_id, new_ip: str) -> None:
    """Point an existing A record at `new_ip`, addressing it by ID.

    Never creates. Raises DdnsError on failure.
    """
    base = _ddns_api_base(zone.provider)
    if zone.provider == 'cloudflare':
        _ddns_request('PATCH', f'{base}/zones/{zone.ref}/dns_records/{record_id}',
                      token, body={'content': new_ip}, provider='cloudflare')
    else:
        _ddns_request('PUT', f'{base}/domains/{zone.ref}/records/{record_id}',
                      token, body={'data': new_ip})


# -----------------------------------------------------------------------------
# DDNS state — last success, failure streaks, duplicate counts
# -----------------------------------------------------------------------------

def _ddns_load_state() -> dict:
    """Read DDNS_STATE_FILE. Returns {'targets': {}} when absent or corrupt."""
    try:
        with open(DDNS_STATE_FILE, 'r', encoding='utf-8') as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        return {'targets': {}}
    if not isinstance(state, dict) or not isinstance(state.get('targets'), dict):
        return {'targets': {}}
    return state


def _ddns_save_state(state: dict) -> None:
    """Write DDNS_STATE_FILE atomically. Best-effort — never fails a run."""
    try:
        os.makedirs(UNIFI_CERT_ROOT, mode=0o755, exist_ok=True)
        tmp = f'{DDNS_STATE_FILE}.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(state, fh, indent=2, sort_keys=True)
        os.replace(tmp, DDNS_STATE_FILE)
    except OSError as e:
        ui.debug(f'Could not write {DDNS_STATE_FILE}: {e}')


def _ddns_forget(*targets: str) -> None:
    """Drop state entries entirely.

    Used for the synthetic '(configuration)' / '(public-ip)' keys once the
    condition they recorded has cleared, and for targets no longer configured.
    Without this a transient failure stays red in --status forever, and a
    permanently-red report is one nobody reads.
    """
    state = _ddns_load_state()
    removed = [t for t in targets if t in state['targets']]
    if not removed:
        return
    for target in removed:
        del state['targets'][target]
    _ddns_save_state(state)


def _ddns_prune_state(configured: list) -> None:
    """Forget targets that are no longer configured."""
    keep = set(configured) | set(DDNS_SYNTHETIC_TARGETS)
    stale = [t for t in _ddns_load_state()['targets'] if t not in keep]
    if stale:
        _ddns_forget(*stale)


def _ddns_note_success(target: str, provider: str, ip: str,
                        record_count: int) -> None:
    """Record a successful update and clear the failure streak."""
    state = _ddns_load_state()
    now = datetime.now().isoformat(timespec='seconds')
    entry = state['targets'].get(target, {})
    previous_failures = entry.get('consecutive_failures', 0)
    entry.update({
        'provider': provider,
        'last_attempt': now,
        'last_success': now,
        'last_ip': ip,
        'record_count': record_count,
        'consecutive_failures': 0,
        'last_error': None,
    })
    state['targets'][target] = entry
    _ddns_save_state(state)
    if previous_failures:
        ui.success(f'{target} recovered after {previous_failures} failed attempt(s).')


def _ddns_note_failure(target: str, provider: str, message: str) -> None:
    """Record a failure and report it on an escalating schedule.

    Reports the first failure, a new failure *mode* whenever the message
    changes, then hourly and daily milestones. Silence between those is
    deliberate: 6,295 identical error lines is what hid this outage for
    months, and --status carries the running count regardless.
    """
    state = _ddns_load_state()
    now = datetime.now().isoformat(timespec='seconds')
    entry = state['targets'].get(target, {})
    previous_error = entry.get('last_error')
    count = entry.get('consecutive_failures', 0) + 1
    entry.update({
        'provider': provider,
        'last_attempt': now,
        'consecutive_failures': count,
        'last_error': message,
    })
    state['targets'][target] = entry
    _ddns_save_state(state)

    changed = message != previous_error
    milestone = count in DDNS_FAILURE_ALERTS or (
        count > DDNS_FAILURE_ALERTS[-1] and count % DDNS_FAILURE_ALERTS[-1] == 0
    )
    if not (changed or milestone):
        ui.debug(f'DDNS {target}: {message} (failure #{count})')
        return

    ui.error(f'DDNS update failed for {target}: {message}')
    if count > 1:
        last_success = entry.get('last_success')
        since = f'nothing has updated it since {last_success}' if last_success \
            else 'it has never updated successfully'
        ui.error(f'  {count} consecutive failures (~{count * 5 // 60}h) — {since}.')


# -----------------------------------------------------------------------------
# DDNS orchestration
# -----------------------------------------------------------------------------

def _ddns_settings(cfg: dict, domain: Optional[str] = None,
                    provider: Optional[str] = None,
                    credentials: Optional[str] = None) -> DdnsSettings:
    """Resolve DDNS targets / provider / credentials from flags + config.

    Each ddns_* key falls back to its cert equivalent so single-record
    installs need no extra configuration. ddns_domain accepts a comma- or
    space-separated list, because a wildcard ('*.home.jdlien.ca') needs the
    same maintenance as the record it shadows.
    """
    raw = domain or cfg.get('ddns_domain') or cfg.get('domain')
    targets = [t.strip() for t in (raw or '').replace(' ', ',').split(',') if t.strip()]
    if not targets:
        raise DdnsError(
            'No DDNS target configured. Pass --ddns-domain, or set ddns_domain '
            f'(falling back to domain) in {PROVISIONING_CONFIG}.'
        )

    cert_provider = cfg.get('dns_provider') or 'digitalocean'
    ddns_provider = (provider or cfg.get('ddns_provider')
                     or cert_provider)
    if ddns_provider not in DDNS_API_BASES:
        raise DdnsError(
            f'DDNS does not support DNS provider {ddns_provider!r} '
            f'(supported: {", ".join(DDNS_PROVIDERS)}). Set ddns_provider in '
            f'{PROVISIONING_CONFIG} if your DDNS zone lives elsewhere than '
            'your ACME zone.'
        )

    creds = credentials or cfg.get('ddns_credentials')
    if not creds:
        fallback = cfg.get('dns_credentials')
        # The credentials fall back to the cert's only when that file can
        # actually authenticate the DDNS provider — either because it's the
        # same provider, or because one file holds both tokens. Handing a
        # DigitalOcean token to Cloudflare's API would fail as an opaque 401,
        # which is precisely the class of silent misconfiguration this path
        # exists to prevent.
        field = DNS_PROVIDERS.get(ddns_provider, {}).get('field')
        usable = ddns_provider == cert_provider or (
            fallback and field and _ddns_read_creds_field(fallback, field)
        )
        if fallback and not usable:
            raise DdnsError(
                f'ddns_provider is {ddns_provider} but the certificate provider '
                f'is {cert_provider}, and ddns_credentials is unset — '
                f'{fallback} holds no {field}, so falling back to it would '
                f'authenticate against the wrong API. Set ddns_credentials in '
                f'{PROVISIONING_CONFIG}.'
            )
        creds = fallback
    if not creds:
        raise DdnsError(
            'No DNS credentials configured for DDNS. Pass --ddns-credentials, '
            f'or set ddns_credentials / dns_credentials in {PROVISIONING_CONFIG}.'
        )
    if not os.path.exists(creds):
        raise DdnsError(f'DNS credentials file not found: {creds}')

    return DdnsSettings(targets=targets, provider=ddns_provider, credentials=creds)


def _ddns_update_target(token: str, provider: str, target: str,
                         public_ip: str, force: bool = False) -> None:
    """Bring one target's A record in line with `public_ip`. Raises DdnsError."""
    zone = _ddns_resolve_zone(token, target, provider)
    record_id, current_ip, count = _ddns_get_a_record(token, zone)

    if current_ip == public_ip and not force:
        ui.debug(f'A record {zone.fqdn} already up to date: {public_ip}')
        _ddns_note_success(target, provider, public_ip, count)
        return

    _ddns_put_a_record(token, zone, record_id, public_ip)
    ui.success(f'Updated {zone.fqdn} A → {public_ip} (was {current_ip})')
    _ddns_note_success(target, provider, public_ip, count)


def ddns_validate(cfg: Optional[dict] = None) -> tuple:
    """Read-only check that the configured DDNS target is actually updatable.

    Resolves the zone and looks the A record up without writing anything, so
    a CNAME target — or a token that can't see the zone — is caught at
    provisioning time instead of failing silently every five minutes for
    months. Returns (ok, message).
    """
    if cfg is None:
        cfg = load_provisioning_config()
    if not ddns_is_enabled(cfg):
        return True, 'DDNS is disabled (ddns_enabled = false); nothing to validate.'
    try:
        settings = _ddns_settings(cfg)
        token = _ddns_token(settings)
    except DdnsError as e:
        return False, str(e)

    problems = []
    for target in settings.targets:
        try:
            zone = _ddns_resolve_zone(token, target, settings.provider)
            _ddns_get_a_record(token, zone)
        except DdnsError as e:
            problems.append(f'{target}: {e}')
    if problems:
        return False, ' '.join(problems)
    return True, (f'DDNS target(s) {", ".join(settings.targets)} resolve to '
                  f'editable A records at {settings.provider}.')


def ddns_update(domain: Optional[str] = None,
                credentials: Optional[str] = None,
                provider: Optional[str] = None,
                force: bool = False) -> bool:
    """Refresh every configured DDNS target's A record to the current public IP.

    Reads provisioning config for anything not passed (the cron-fired case).
    Idempotent — a matching IP is a no-op logged at debug level. Pass
    force=True to write even when the record already matches. Returns True
    only when every target succeeded.
    """
    cfg = load_provisioning_config()
    try:
        settings = _ddns_settings(cfg, domain=domain, provider=provider,
                                  credentials=credentials)
        token = _ddns_token(settings)
    except DdnsError as e:
        # Track config errors too: a misconfigured install fires every five
        # minutes just like a broken one, and deserves the same escalation.
        _ddns_note_failure(DDNS_CONFIG_TARGET,
                           provider or cfg.get('ddns_provider')
                           or cfg.get('dns_provider') or '(unset)', str(e))
        return False

    # Config resolved, so any recorded config failure is history.
    _ddns_forget(DDNS_CONFIG_TARGET)

    # Forget targets that are no longer configured — state that can only
    # accumulate failures ends up permanently red and therefore ignored. Only
    # when the target set came from the config, though: a one-shot
    # --ddns-domain override is not a reconfiguration, and must not discard
    # the tracked history of what cron actually maintains.
    if not domain:
        _ddns_prune_state(settings.targets)

    public_ip = get_public_ip(timeout=5)
    if not public_ip:
        _ddns_note_failure(DDNS_PUBLIC_IP_TARGET, settings.provider,
                           'Could not determine public IP from any provider.')
        return False
    _ddns_forget(DDNS_PUBLIC_IP_TARGET)

    all_ok = True
    for target in settings.targets:
        try:
            _ddns_update_target(token, settings.provider, target, public_ip,
                                force=force)
        except DdnsError as e:
            _ddns_note_failure(target, settings.provider, str(e))
            all_ok = False
    return all_ok


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


def _ddns_success_age(last_success: Optional[str]) -> Optional[float]:
    """Seconds since an ISO last-success stamp, or None if absent/unparseable."""
    if not last_success:
        return None
    try:
        return (datetime.now() - datetime.fromisoformat(last_success)).total_seconds()
    except (ValueError, TypeError):
        return None


def _print_ddns_section(cfg: dict) -> None:
    """DDNS configuration + last-run outcome.

    Reads DDNS_STATE_FILE rather than probing the provider, so --status stays
    offline and side-effect free. That makes it a report of the last run, not
    a live check — but a stale last-success timestamp is precisely the signal
    that went unnoticed for months, so it's the number worth showing.
    """
    enabled = ddns_is_enabled(cfg)
    try:
        settings = _ddns_settings(cfg)
    except DdnsError as e:
        ui.warning(f'DDNS not configured: {e}')
        settings = None

    if settings:
        ui.table([
            ('Enabled', 'yes' if enabled else 'no (ddns_enabled = false)'),
            ('Targets', ', '.join(settings.targets)),
            ('Provider', settings.provider),
            ('Credentials', settings.credentials),
        ])
    if not enabled:
        ui.info('DDNS cron line is not installed; nothing here is being refreshed.')

    targets = _ddns_load_state().get('targets', {})
    if not targets:
        ui.info(f'No DDNS run recorded yet ({DDNS_STATE_FILE} absent).')
        return

    for target, entry in sorted(targets.items()):
        failures = entry.get('consecutive_failures', 0)
        last_success = entry.get('last_success') or 'never'
        if failures:
            ui.error(f'{target}: {failures} consecutive failure(s), '
                     f'last success {last_success}')
            ui.info(f'  last error: {entry.get("last_error") or "(none recorded)"}')
        else:
            stale = _ddns_success_age(entry.get('last_success'))
            if enabled and stale is not None and stale > DDNS_STALE_SUCCESS_SECONDS:
                # A zero-failure entry that stopped updating means cron isn't
                # firing at all. Rendering that as a green line is worse than
                # useless — it is the reassurance that hides the outage.
                ui.warning(f'{target} → {entry.get("last_ip") or "(unknown)"} but '
                           f'last success was {int(stale // 3600)}h ago '
                           f'({last_success}); the 5-minute job looks stopped.')
            else:
                ui.success(f'{target} → {entry.get("last_ip") or "(unknown)"} '
                           f'(last success {last_success})')
        if (entry.get('record_count') or 0) > 1:
            ui.warning(f'  {target} had {entry["record_count"]} A records at the '
                       'last check — duplicates stall connections intermittently.')


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

    ui.header('DDNS')
    _print_ddns_section(cfg)

    ui.header('GlennR residue')
    _print_glennr_section()

    ui.header('Log tail')
    _print_log_tail_section()

    return 0


# =============================================================================
# REMOTE SSH OPERATIONS
# =============================================================================

def _ssh_multiplex_args() -> list[str]:
    """Return SSH multiplex flags so dispatch_remote_verb's 2-4 sessions
    per call collapse into one TCP+TLS connection from the wire's POV.

    Without this, IDS signatures like "ET SCAN Potential SSH Scan"
    (Suricata SID 2001219, fires on rapid-fire SSH from a single source)
    flag a verb dispatch as a port-scan and silently drop the packets,
    making the box appear unreachable. UniFi's CyberSecure / Threat
    Management ships these signatures enabled by default. Multiplexing
    the connection pre-empts the trigger entirely without touching the
    IDS config.

    %r/%h/%p expand to remote-user / host / port; ControlPersist=60s
    keeps the master alive long enough for the back-to-back sub-commands
    inside ensure_remote_script() and the verb-execution call.
    """
    home = os.path.expanduser('~')
    sock = os.path.join(home, '.ssh', 'cm-%r@%h:%p')
    return [
        '-o', 'ControlMaster=auto',
        '-o', f'ControlPath={sock}',
        '-o', 'ControlPersist=60s',
    ]


def run_remote(host: str, command: str, timeout: int = 30) -> tuple[bool, str]:
    """Run a command on a remote host via SSH."""
    try:
        result = subprocess.run(
            ['ssh', '-o', 'ConnectTimeout=5', '-o', 'BatchMode=yes',
             *_ssh_multiplex_args(),
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
            ['scp', '-q', *_ssh_multiplex_args(),
             local_path, f'root@{host}:{remote_path}'],
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
        ('--ddns-domain', getattr(args, 'ddns_domain', None)),
        ('--ddns-provider', getattr(args, 'ddns_provider', None)),
        ('--ddns-credentials', getattr(args, 'ddns_credentials', None)),
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
                       help='Refresh the DDNS target A record(s) at the DNS '
                            'provider to the current public IP. Never creates '
                            'records — edits existing ones by ID.')

    # DDNS target overrides. Each falls back to its cert equivalent, so these
    # are only needed when the DDNS anchor differs from the certificate CN
    # (e.g. the CN is a CNAME pointing at a record in another provider's zone).
    parser.add_argument('--ddns-domain',
                       help='DDNS target hostname(s), comma-separated. '
                            'Defaults to ddns_domain, then domain, from the '
                            'provisioning config.')
    parser.add_argument('--ddns-provider',
                       choices=list(DDNS_PROVIDERS),
                       help='DNS provider hosting the DDNS target zone '
                            '(defaults to --dns-provider)')
    parser.add_argument('--ddns-credentials',
                       help='Credentials file for the DDNS provider '
                            '(defaults to --dns-credentials)')
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
    default_creds = default_credentials_path(config['dns_provider'])
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
    """`--ddns-update`: refresh DDNS target A record(s) to current public IP.

    --ddns-* wins over the cert flags, which in turn win over the provisioning
    config. -d stays honoured so the pre-decoupling invocation still works.
    """
    rotate_log()
    provider = args.ddns_provider or args.dns_provider
    if provider and provider not in DDNS_API_BASES:
        # --dns-provider covers every ACME plugin; only some have a DDNS
        # backend. Ignore an inherited one rather than failing the run, so
        # `--ddns-update --dns-provider route53` still consults the config.
        provider = args.ddns_provider
    ok = ddns_update(domain=args.ddns_domain or args.domain,
                     credentials=args.ddns_credentials or args.dns_credentials,
                     provider=provider,
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
        # Prefer --host (workstation flow), fall back to args.domain (cert CN
        # — the device's actual public hostname). "localhost" is meaningless
        # on a headless UniFi device — the user visits from another machine.
        verify_host = args.host or args.domain
        if verify_host:
            ui.info(f'Verify by visiting https://{verify_host}')
        else:
            ui.info("Verify by visiting your UniFi device's hostname or IP over HTTPS")
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
        default_creds = default_credentials_path(args.dns_provider)
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
        # Save provisioning before installing cron: the cron writer reads
        # ddns_enabled from it, and --renew depends on it existing at all.
        if not save_provisioning_config(
            domain=args.domain,
            email=args.email,
            dns_provider=args.dns_provider,
            dns_credentials=args.dns_credentials,
            ddns_domain=args.ddns_domain,
            ddns_provider=args.ddns_provider,
            ddns_credentials=args.ddns_credentials,
        ):
            ui.warning(f'Could not write {PROVISIONING_CONFIG}. Cron-fired '
                       '--renew has nothing to self-configure from; fix the '
                       'path and re-run.')
        if not install_cron_schedule():
            ui.warning('Cron schedule not installed — renewals and DDNS will '
                       'not run on their own. Re-run --self-heal once the '
                       'cause is fixed.')

        # Validate the DDNS target now rather than discovering months later
        # that a CNAME made every five-minute run a no-op. Never fatal: the
        # certificate is already installed, and DDNS is a separate concern.
        ddns_ok, ddns_message = ddns_validate()
        if ddns_ok:
            ui.success(ddns_message)
        else:
            ui.warning(f'DDNS target is not updatable: {ddns_message}')
            ui.info('The certificate is installed and renewals are scheduled; '
                    'only the A-record refresh is affected.')

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
