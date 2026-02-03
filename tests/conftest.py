"""Shared pytest fixtures for UniFi Certificate Manager tests."""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add parent directory to path so we can import unifi-cert
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def sample_cert_content():
    """Sample certificate PEM content."""
    return """-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIUB5JGf1QzXxsZz7oGvjBKl1J8+4IwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAx
MDEwMDAwMDBaMEUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQDf0TJq+Q==
-----END CERTIFICATE-----
"""


@pytest.fixture
def sample_key_content():
    """Sample private key PEM content."""
    return """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDf0TJq+QAAAQ==
-----END PRIVATE KEY-----
"""


@pytest.fixture
def sample_cert_file(temp_dir, sample_cert_content):
    """Create a sample certificate file."""
    cert_path = os.path.join(temp_dir, "test.crt")
    with open(cert_path, 'w') as f:
        f.write(sample_cert_content)
    return cert_path


@pytest.fixture
def sample_key_file(temp_dir, sample_key_content):
    """Create a sample private key file."""
    key_path = os.path.join(temp_dir, "test.key")
    with open(key_path, 'w') as f:
        f.write(sample_key_content)
    return key_path


@pytest.fixture
def sample_credentials_file(temp_dir):
    """Create a sample DNS credentials file with correct permissions."""
    creds_path = os.path.join(temp_dir, "digitalocean.ini")
    with open(creds_path, 'w') as f:
        f.write("# Certbot DNS DigitalOcean credentials\n")
        f.write("dns_digitalocean_token = dop_v1_test_token_12345\n")
    os.chmod(creds_path, 0o600)
    return creds_path


@pytest.fixture
def mock_openssl_output():
    """Mock output from various openssl commands."""
    return {
        'subject': 'subject=CN = example.com',
        'issuer': 'issuer=C = US, O = Let\'s Encrypt, CN = R3',
        'ext': 'X509v3 Subject Alternative Name:\n    DNS:example.com, DNS:www.example.com',
        'startdate': 'notBefore=Jan  1 00:00:00 2024 GMT',
        'enddate': 'notAfter=Apr  1 00:00:00 2024 GMT',
        'serial': 'serial=0A1B2C3D4E5F6789',
        'fingerprint': 'SHA1 Fingerprint=AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD',
    }


@pytest.fixture
def mock_subprocess_run(mock_openssl_output):
    """Mock subprocess.run for openssl commands."""
    def _mock_run(cmd, *args, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""

        if 'openssl' in cmd:
            if '-subject' in cmd:
                result.stdout = mock_openssl_output['subject']
            elif '-issuer' in cmd:
                result.stdout = mock_openssl_output['issuer']
            elif '-ext' in cmd:
                result.stdout = mock_openssl_output['ext']
            elif '-startdate' in cmd:
                result.stdout = mock_openssl_output['startdate']
            elif '-enddate' in cmd:
                result.stdout = mock_openssl_output['enddate']
            elif '-serial' in cmd:
                result.stdout = mock_openssl_output['serial']
            elif '-fingerprint' in cmd:
                result.stdout = mock_openssl_output['fingerprint']
        elif 'dpkg-query' in cmd:
            result.stdout = "4.0.6"
        elif 'psql' in cmd:
            result.stdout = "UPDATE 1"
        elif 'ssh' in cmd:
            if 'true' in ' '.join(cmd):
                result.stdout = ""
            elif 'grep' in ' '.join(cmd):
                result.stdout = "test-uuid-1234"
            elif 'test -d' in ' '.join(cmd):
                result.returncode = 0
            elif 'which psql' in ' '.join(cmd):
                result.stdout = "/usr/bin/psql"
        elif 'scp' in cmd:
            result.returncode = 0
        elif 'systemctl' in cmd:
            result.returncode = 0
        elif 'certbot' in cmd:
            result.returncode = 0
            result.stdout = "Congratulations!"

        return result

    return _mock_run


@pytest.fixture
def mock_ui():
    """Create a mock UI that doesn't print anything."""
    ui = MagicMock()
    ui.color = False
    ui.verbose = False
    return ui


@pytest.fixture
def mock_platform():
    """Create a mock UnifiPlatform."""
    from importlib import import_module
    # Import the module dynamically since it has a hyphen
    spec = __import__('unifi-cert')

    return spec.UnifiPlatform(
        device_type='UDM',
        core_version='4.0.6',
        has_eus_certs=True,
        has_postgres=True,
        active_cert_id='existing-cert-uuid-1234',
    )
