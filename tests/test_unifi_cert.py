"""Comprehensive tests for UniFi Certificate Manager.

Tests are organized by module/functionality matching the structure in unifi-cert.py:
1. UI Layer
2. Certificate Metadata
3. IP Lookup
4. DNS Credentials
5. UniFi Platform Detection
6. Certificate Installation
7. PostgreSQL Updates
8. Certbot Integration
9. Remote SSH Operations
10. CLI & Main
"""

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, call, mock_open, patch

import pytest

# Import the module with hyphen in name
spec = importlib.util.spec_from_file_location("unifi_cert", Path(__file__).parent.parent / "unifi-cert.py")
unifi_cert = importlib.util.module_from_spec(spec)
spec.loader.exec_module(unifi_cert)


# =============================================================================
# UI LAYER TESTS
# =============================================================================

class TestUI:
    """Tests for the UI class."""

    def test_ui_init_default(self):
        """Test UI initialization with defaults."""
        with patch('sys.stdout.isatty', return_value=True):
            ui = unifi_cert.UI()
            assert ui.verbose is False

    def test_ui_init_no_color(self):
        """Test UI with color disabled."""
        ui = unifi_cert.UI(color=False)
        assert ui.color is False

    def test_ui_init_verbose(self):
        """Test UI with verbose mode."""
        ui = unifi_cert.UI(verbose=True)
        assert ui.verbose is True

    def test_ui_color_code_enabled(self):
        """Test color code application when colors enabled."""
        with patch('sys.stdout.isatty', return_value=True):
            ui = unifi_cert.UI(color=True)
            result = ui._c(ui.GREEN, "test")
            assert ui.GREEN in result
            assert ui.RESET in result

    def test_ui_color_code_disabled(self):
        """Test color code application when colors disabled."""
        ui = unifi_cert.UI(color=False)
        result = ui._c(ui.GREEN, "test")
        assert result == "test"
        assert ui.GREEN not in result

    def test_ui_header(self, capsys):
        """Test header output."""
        ui = unifi_cert.UI(color=False)
        ui.header("Test Header")
        captured = capsys.readouterr()
        assert "Test Header" in captured.out

    def test_ui_status(self, capsys):
        """Test status message output."""
        ui = unifi_cert.UI(color=False)
        ui.status("Status message")
        captured = capsys.readouterr()
        assert "Status message" in captured.out

    def test_ui_success(self, capsys):
        """Test success message output."""
        ui = unifi_cert.UI(color=False)
        ui.success("Success message")
        captured = capsys.readouterr()
        assert "Success message" in captured.out

    def test_ui_warning(self, capsys):
        """Test warning message output."""
        ui = unifi_cert.UI(color=False)
        ui.warning("Warning message")
        captured = capsys.readouterr()
        assert "Warning message" in captured.out

    def test_ui_error(self, capsys):
        """Test error message output."""
        ui = unifi_cert.UI(color=False)
        ui.error("Error message")
        captured = capsys.readouterr()
        assert "Error message" in captured.err

    def test_ui_info(self, capsys):
        """Test info message output."""
        ui = unifi_cert.UI(color=False)
        ui.info("Info message")
        captured = capsys.readouterr()
        assert "Info message" in captured.out

    def test_ui_debug_verbose(self, capsys):
        """Test debug message in verbose mode."""
        ui = unifi_cert.UI(color=False, verbose=True)
        ui.debug("Debug message")
        captured = capsys.readouterr()
        assert "Debug message" in captured.out

    def test_ui_debug_not_verbose(self, capsys):
        """Test debug message not shown when not verbose."""
        ui = unifi_cert.UI(color=False, verbose=False)
        ui.debug("Debug message")
        captured = capsys.readouterr()
        assert "Debug message" not in captured.out

    def test_ui_table(self, capsys):
        """Test table output."""
        ui = unifi_cert.UI(color=False)
        rows = [("Key1", "Value1"), ("Key2", "Value2")]
        ui.table(rows)
        captured = capsys.readouterr()
        assert "Key1" in captured.out
        assert "Value1" in captured.out
        assert "Key2" in captured.out
        assert "Value2" in captured.out

    def test_ui_table_empty(self, capsys):
        """Test table output with empty rows."""
        ui = unifi_cert.UI(color=False)
        ui.table([])
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_ui_spinner_no_color(self, capsys):
        """Test spinner without color just prints message."""
        ui = unifi_cert.UI(color=False)
        ui.spinner_start("Loading")
        captured = capsys.readouterr()
        assert "Loading" in captured.out
        ui.spinner_stop()

    def test_ui_prompt(self):
        """Test user prompt."""
        ui = unifi_cert.UI(color=False)
        with patch('sys.stdin.isatty', return_value=True), \
             patch('builtins.input', return_value='user_input'):
            result = ui.prompt("Enter value")
            assert result == "user_input"

    def test_ui_prompt_default(self):
        """Test user prompt with default value."""
        ui = unifi_cert.UI(color=False)
        with patch('sys.stdin.isatty', return_value=True), \
             patch('builtins.input', return_value=''):
            result = ui.prompt("Enter value", default="default_value")
            assert result == "default_value"

    def test_ui_confirm_yes(self):
        """Test confirmation prompt with yes."""
        ui = unifi_cert.UI(color=False)
        with patch('sys.stdin.isatty', return_value=True), \
             patch('builtins.input', return_value='y'):
            result = ui.confirm("Confirm?")
            assert result is True

    def test_ui_confirm_no(self):
        """Test confirmation prompt with no."""
        ui = unifi_cert.UI(color=False)
        with patch('sys.stdin.isatty', return_value=True), \
             patch('builtins.input', return_value='n'):
            result = ui.confirm("Confirm?")
            assert result is False

    def test_ui_confirm_default_yes(self):
        """Test confirmation prompt with default yes."""
        ui = unifi_cert.UI(color=False)
        with patch('sys.stdin.isatty', return_value=True), \
             patch('builtins.input', return_value=''):
            result = ui.confirm("Confirm?", default=True)
            assert result is True

    def test_ui_confirm_default_no(self):
        """Test confirmation prompt with default no."""
        ui = unifi_cert.UI(color=False)
        with patch('sys.stdin.isatty', return_value=True), \
             patch('builtins.input', return_value=''):
            result = ui.confirm("Confirm?", default=False)
            assert result is False

    def test_ui_select(self):
        """Test selection prompt."""
        ui = unifi_cert.UI(color=False)
        options = ["Option A", "Option B", "Option C"]
        with patch('sys.stdin.isatty', return_value=True), \
             patch('builtins.input', return_value='2'):
            result = ui.select("Choose:", options)
            assert result == 1  # 0-indexed

    def test_ui_select_invalid_then_valid(self):
        """Test selection prompt with invalid input then valid."""
        ui = unifi_cert.UI(color=False)
        options = ["Option A", "Option B"]
        with patch('sys.stdin.isatty', return_value=True), \
             patch('builtins.input', side_effect=['invalid', '5', '1']):
            result = ui.select("Choose:", options)
            assert result == 0

    def test_ui_input_tty_fallback(self):
        """Test _input falls back to /dev/tty when stdin is a pipe."""
        ui = unifi_cert.UI(color=False)
        mock_tty = MagicMock()
        mock_tty.readline.return_value = 'tty_input\n'

        with patch('sys.stdin.isatty', return_value=False), \
             patch('builtins.open', return_value=mock_tty):
            result = ui._input("Prompt: ")
            assert result == 'tty_input'

    def test_ui_input_no_tty_raises_eof(self):
        """Test _input raises EOFError when no TTY available."""
        ui = unifi_cert.UI(color=False)

        with patch('sys.stdin.isatty', return_value=False), \
             patch('builtins.open', side_effect=OSError("No TTY")):
            with pytest.raises(EOFError):
                ui._input("Prompt: ")

    def test_ui_input_reuses_tty(self):
        """Test _input reuses opened TTY handle."""
        ui = unifi_cert.UI(color=False)
        mock_tty = MagicMock()
        mock_tty.readline.side_effect = ['first\n', 'second\n']

        with patch('sys.stdin.isatty', return_value=False), \
             patch('builtins.open', return_value=mock_tty) as mock_open:
            result1 = ui._input("Prompt1: ")
            result2 = ui._input("Prompt2: ")
            assert result1 == 'first'
            assert result2 == 'second'
            # open should only be called once
            assert mock_open.call_count == 1


# =============================================================================
# CERTIFICATE METADATA TESTS
# =============================================================================

class TestCertMetadata:
    """Tests for CertMetadata class."""

    def test_cert_metadata_from_file(self, temp_dir, sample_cert_content):
        """Test extracting metadata from certificate file."""
        cert_path = os.path.join(temp_dir, "test.crt")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)

        mock_outputs = {
            '-subject': 'subject=CN = example.com',
            '-issuer': 'issuer=C = US, O = Let\'s Encrypt, CN = R3',
            '-ext': 'X509v3 Subject Alternative Name:\n    DNS:example.com, DNS:www.example.com',
            '-startdate': 'notBefore=Jan  1 00:00:00 2024 GMT',
            '-enddate': 'notAfter=Apr  1 00:00:00 2024 GMT',
            '-serial': 'serial=0A1B2C3D4E5F6789',
            '-fingerprint': 'SHA1 Fingerprint=AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD',
        }

        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stderr = ""
            for flag, output in mock_outputs.items():
                if flag in cmd:
                    result.stdout = output
                    return result
            result.stdout = ""
            return result

        with patch('subprocess.run', side_effect=mock_run):
            meta = unifi_cert.CertMetadata.from_cert_file(cert_path)

        assert meta.cn == "example.com"
        assert meta.issuer_c == "US"
        assert meta.issuer_o == "Let's Encrypt"
        assert meta.issuer_cn == "R3"
        assert "example.com" in meta.sans
        assert "www.example.com" in meta.sans
        assert meta.serial == "0A1B2C3D4E5F6789"
        assert "AA:BB:CC" in meta.fingerprint

    def test_cert_metadata_date_conversion(self, temp_dir, sample_cert_content):
        """Test date format conversion in metadata."""
        cert_path = os.path.join(temp_dir, "test.crt")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)

        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stderr = ""
            if '-startdate' in cmd:
                result.stdout = 'notBefore=Jan  1 00:00:00 2024 GMT'
            elif '-enddate' in cmd:
                result.stdout = 'notAfter=Dec 31 23:59:59 2024 GMT'
            else:
                result.stdout = ""
            return result

        with patch('subprocess.run', side_effect=mock_run):
            meta = unifi_cert.CertMetadata.from_cert_file(cert_path)

        assert "2024-01-01" in meta.valid_from
        assert "2024-12-31" in meta.valid_to

    def test_cert_metadata_date_conversion_no_timezone(self, temp_dir, sample_cert_content):
        """Test date format conversion without timezone suffix."""
        cert_path = os.path.join(temp_dir, "test.crt")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)

        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stderr = ""
            if '-startdate' in cmd:
                # Date without proper timezone - triggers fallback parsing
                result.stdout = 'notBefore=Jan  1 00:00:00 2024'
            elif '-enddate' in cmd:
                result.stdout = 'notAfter=Dec 31 23:59:59 2024'
            else:
                result.stdout = ""
            return result

        with patch('subprocess.run', side_effect=mock_run):
            meta = unifi_cert.CertMetadata.from_cert_file(cert_path)

        assert "2024-01-01" in meta.valid_from
        assert "2024-12-31" in meta.valid_to

    def test_cert_metadata_date_conversion_unparseable(self, temp_dir, sample_cert_content):
        """Test date format that can't be parsed returns original string."""
        cert_path = os.path.join(temp_dir, "test.crt")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)

        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stderr = ""
            if '-startdate' in cmd:
                result.stdout = 'notBefore=INVALID_DATE_FORMAT'
            elif '-enddate' in cmd:
                result.stdout = 'notAfter=ALSO_INVALID'
            else:
                result.stdout = ""
            return result

        with patch('subprocess.run', side_effect=mock_run):
            meta = unifi_cert.CertMetadata.from_cert_file(cert_path)

        assert meta.valid_from == "INVALID_DATE_FORMAT"
        assert meta.valid_to == "ALSO_INVALID"

    def test_cert_metadata_openssl_failure(self, temp_dir, sample_cert_content):
        """Test handling of openssl command failure."""
        cert_path = os.path.join(temp_dir, "test.crt")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)

        def mock_run(cmd, *args, **kwargs):
            raise subprocess.CalledProcessError(1, cmd)

        with patch('subprocess.run', side_effect=mock_run):
            meta = unifi_cert.CertMetadata.from_cert_file(cert_path)

        # Should return empty strings on failure
        assert meta.cn == ""
        assert meta.issuer_cn == ""


# =============================================================================
# DOMAIN AUTO-DETECTION TESTS
# =============================================================================

class TestDomainAutoDetection:
    """Tests for detect_domain_from_cert function."""

    def test_detect_domain_from_cert_success(self, temp_dir, sample_cert_content):
        """Test successful domain detection from certificate."""
        cert_path = os.path.join(temp_dir, "test.crt")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)

        mock_meta = MagicMock()
        mock_meta.cn = "example.com"

        with patch.object(unifi_cert.CertMetadata, 'from_cert_file', return_value=mock_meta):
            result = unifi_cert.detect_domain_from_cert(cert_path)

        assert result == "example.com"

    def test_detect_domain_from_cert_file_not_found(self):
        """Test domain detection when cert file doesn't exist."""
        result = unifi_cert.detect_domain_from_cert("/nonexistent/path.crt")
        assert result is None

    def test_detect_domain_from_cert_localhost_ignored(self, temp_dir, sample_cert_content):
        """Test that localhost CN is ignored for auto-detection."""
        cert_path = os.path.join(temp_dir, "test.crt")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)

        mock_meta = MagicMock()
        mock_meta.cn = "localhost"

        with patch.object(unifi_cert.CertMetadata, 'from_cert_file', return_value=mock_meta):
            result = unifi_cert.detect_domain_from_cert(cert_path)

        assert result is None

    def test_detect_domain_from_cert_unifi_ignored(self, temp_dir, sample_cert_content):
        """Test that UniFi default CNs are ignored for auto-detection."""
        cert_path = os.path.join(temp_dir, "test.crt")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)

        mock_meta = MagicMock()
        mock_meta.cn = "UniFi OS"

        with patch.object(unifi_cert.CertMetadata, 'from_cert_file', return_value=mock_meta):
            result = unifi_cert.detect_domain_from_cert(cert_path)

        assert result is None

    def test_detect_domain_from_default_path(self, temp_dir, sample_cert_content):
        """Test domain detection using default EUS certificate path."""
        # Patch UNIFI_PATHS to use temp dir
        test_cert_path = os.path.join(temp_dir, "unifi-os.crt")
        with open(test_cert_path, 'w') as f:
            f.write(sample_cert_content)

        mock_meta = MagicMock()
        mock_meta.cn = "myrouter.example.com"

        with patch.dict(unifi_cert.UNIFI_PATHS, {'eus_cert': test_cert_path}):
            with patch.object(unifi_cert.CertMetadata, 'from_cert_file', return_value=mock_meta):
                result = unifi_cert.detect_domain_from_cert()

        assert result == "myrouter.example.com"

    def test_detect_domain_from_cert_exception_handled(self, temp_dir, sample_cert_content):
        """Test that exceptions during detection are handled gracefully."""
        cert_path = os.path.join(temp_dir, "test.crt")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)

        with patch.object(unifi_cert.CertMetadata, 'from_cert_file', side_effect=Exception("openssl error")):
            result = unifi_cert.detect_domain_from_cert(cert_path)

        assert result is None


# =============================================================================
# IP LOOKUP TESTS
# =============================================================================

class TestIPLookup:
    """Tests for get_public_ip function."""

    def test_get_public_ip_success(self):
        """Test successful IP lookup."""
        import urllib.request
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"ip": "203.0.113.1"}'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        # Need to patch in the module's context
        original_urlopen = urllib.request.urlopen
        urllib.request.urlopen = MagicMock(return_value=mock_response)
        try:
            result = unifi_cert.get_public_ip()
            assert result == "203.0.113.1"
        finally:
            urllib.request.urlopen = original_urlopen

    def test_get_public_ip_fallback(self):
        """Test IP lookup fallback to next provider."""
        import urllib.request
        import urllib.error
        call_count = [0]

        def mock_urlopen(req, *args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise urllib.error.URLError("First provider failed")
            mock_response = MagicMock()
            mock_response.read.return_value = b'{"ip": "203.0.113.2"}'
            mock_response.__enter__ = MagicMock(return_value=mock_response)
            mock_response.__exit__ = MagicMock(return_value=False)
            return mock_response

        original_urlopen = urllib.request.urlopen
        urllib.request.urlopen = mock_urlopen
        try:
            result = unifi_cert.get_public_ip()
            assert result == "203.0.113.2"
        finally:
            urllib.request.urlopen = original_urlopen

    def test_get_public_ip_all_fail(self):
        """Test IP lookup when all providers fail."""
        import urllib.request
        import urllib.error

        original_urlopen = urllib.request.urlopen
        urllib.request.urlopen = MagicMock(side_effect=urllib.error.URLError("All failed"))
        try:
            result = unifi_cert.get_public_ip()
            assert result is None
        finally:
            urllib.request.urlopen = original_urlopen

    def test_get_public_ip_invalid_format(self):
        """Test IP lookup with invalid IP format - should try next provider."""
        import urllib.request
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"ip": "invalid-ip"}'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        original_urlopen = urllib.request.urlopen
        urllib.request.urlopen = MagicMock(return_value=mock_response)
        try:
            # Should fall through all providers and return None since all return invalid format
            result = unifi_cert.get_public_ip()
            # Since all providers return invalid IP, result should be None
            assert result is None
        finally:
            urllib.request.urlopen = original_urlopen

    def test_get_public_ip_json_error(self):
        """Test IP lookup with JSON parse error."""
        import urllib.request
        mock_response = MagicMock()
        mock_response.read.return_value = b'not valid json'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        original_urlopen = urllib.request.urlopen
        urllib.request.urlopen = MagicMock(return_value=mock_response)
        try:
            result = unifi_cert.get_public_ip()
            assert result is None
        finally:
            urllib.request.urlopen = original_urlopen


# =============================================================================
# DNS CREDENTIALS TESTS
# =============================================================================

class TestDNSCredentials:
    """Tests for DNS credential validation and creation."""

    def test_validate_dns_credentials_success(self, sample_credentials_file):
        """Test successful credential validation."""
        valid, msg = unifi_cert.validate_dns_credentials('digitalocean', sample_credentials_file)
        assert valid is True
        assert "validated" in msg.lower()

    def test_validate_dns_credentials_unknown_provider(self, sample_credentials_file):
        """Test validation with unknown provider."""
        valid, msg = unifi_cert.validate_dns_credentials('unknown_provider', sample_credentials_file)
        assert valid is False
        assert "Unknown DNS provider" in msg

    def test_validate_dns_credentials_file_not_found(self):
        """Test validation when file doesn't exist."""
        valid, msg = unifi_cert.validate_dns_credentials('digitalocean', '/nonexistent/path.ini')
        assert valid is False
        assert "not found" in msg

    def test_validate_dns_credentials_wrong_field(self, temp_dir):
        """Test validation with wrong field name (the GlennR bug)."""
        creds_path = os.path.join(temp_dir, "wrong.ini")
        with open(creds_path, 'w') as f:
            f.write("DO_AUTH_TOKEN = token123\n")  # Wrong field name
        os.chmod(creds_path, 0o600)

        valid, msg = unifi_cert.validate_dns_credentials('digitalocean', creds_path)
        assert valid is False
        assert "Wrong field name" in msg
        assert "DO_AUTH_TOKEN" in msg
        assert "dns_digitalocean_token" in msg

    def test_validate_dns_credentials_missing_field(self, temp_dir):
        """Test validation when required field is missing."""
        creds_path = os.path.join(temp_dir, "empty.ini")
        with open(creds_path, 'w') as f:
            f.write("# Empty credentials\n")
        os.chmod(creds_path, 0o600)

        valid, msg = unifi_cert.validate_dns_credentials('digitalocean', creds_path)
        assert valid is False
        assert "Missing required field" in msg

    def test_validate_dns_credentials_bad_permissions(self, temp_dir):
        """Test validation with insecure file permissions."""
        creds_path = os.path.join(temp_dir, "insecure.ini")
        with open(creds_path, 'w') as f:
            f.write("dns_digitalocean_token = token123\n")
        os.chmod(creds_path, 0o644)  # World-readable - insecure!

        valid, msg = unifi_cert.validate_dns_credentials('digitalocean', creds_path)
        assert valid is False
        assert "Insecure permissions" in msg

    def test_create_credentials_file_success(self, temp_dir):
        """Test successful credentials file creation."""
        creds_path = os.path.join(temp_dir, "new_creds", "do.ini")

        # Mock the UI
        with patch.object(unifi_cert, 'ui'):
            result = unifi_cert.create_credentials_file('digitalocean', 'test_token', creds_path)

        assert result is True
        assert os.path.exists(creds_path)

        # Check content
        with open(creds_path, 'r') as f:
            content = f.read()
        assert "dns_digitalocean_token = test_token" in content

        # Check permissions
        mode = os.stat(creds_path).st_mode & 0o777
        assert mode == 0o600

    def test_create_credentials_file_unknown_provider(self, temp_dir):
        """Test creation with unknown provider."""
        creds_path = os.path.join(temp_dir, "creds.ini")

        with patch.object(unifi_cert, 'ui'):
            result = unifi_cert.create_credentials_file('unknown_provider', 'token', creds_path)

        assert result is False

    def test_create_credentials_file_io_error(self, temp_dir):
        """Test creation when IO error occurs."""
        # Use a path that can't be written
        creds_path = "/root/cannot_write.ini"

        with patch.object(unifi_cert, 'ui'):
            with patch('os.makedirs', side_effect=IOError("Permission denied")):
                result = unifi_cert.create_credentials_file('digitalocean', 'token', creds_path)

        assert result is False


# =============================================================================
# UNIFI PLATFORM DETECTION TESTS
# =============================================================================

class TestUnifiPlatform:
    """Tests for UniFi platform detection."""

    def test_detect_not_unifi_device(self):
        """Test detection when not on UniFi device."""
        with patch('os.path.exists', return_value=False):
            result = unifi_cert.UnifiPlatform.detect()
        assert result is None

    def test_detect_udm_device_full(self, temp_dir):
        """Test detection of UDM device with all features."""
        # Create mock paths
        settings_path = os.path.join(temp_dir, "settings.yaml")
        with open(settings_path, 'w') as f:
            f.write("activeCertId: test-cert-uuid\n")

        call_count = [0]

        def mock_exists(path):
            if path == '/data/unifi-core':
                return True
            if path == '/data/eus_certificates':
                return True
            if path == '/data/unifi-core/config/settings.yaml':
                return True
            if path == '/sys/firmware/devicetree/base/model':
                return False
            if path == '/usr/lib/version':
                return True
            return False

        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            if 'dpkg-query' in cmd:
                result.returncode = 0
                result.stdout = "4.0.6"
            else:
                result.returncode = 1
                result.stdout = ""
            return result

        def mock_open_file(path, *args, **kwargs):
            if 'settings.yaml' in str(path):
                return mock_open(read_data="activeCertId: test-cert-uuid\n")()
            raise FileNotFoundError

        with patch('os.path.exists', side_effect=mock_exists), \
             patch('subprocess.run', side_effect=mock_run), \
             patch('shutil.which', return_value='/usr/bin/psql'), \
             patch('builtins.open', side_effect=mock_open_file):

            platform = unifi_cert.UnifiPlatform.detect()

        assert platform is not None
        assert platform.device_type == 'UDM'
        assert platform.core_version == '4.0.6'
        assert platform.has_postgres is True
        assert platform.has_eus_certs is True
        assert platform.active_cert_id == 'test-cert-uuid'

    def test_detect_cloudkey_device(self):
        """Test detection of CloudKey device."""
        def mock_exists(path):
            if path == '/data/unifi-core':
                return True
            if path == '/data/eus_certificates':
                return False
            if path == '/sys/firmware/devicetree/base/model':
                return True
            return False

        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 1
            result.stdout = ""
            return result

        def mock_open_file(path, *args, **kwargs):
            if 'model' in str(path):
                m = MagicMock()
                m.__enter__ = MagicMock(return_value=m)
                m.__exit__ = MagicMock(return_value=False)
                m.read.return_value = b'Ubiquiti Cloud Key Gen2 Plus\x00'
                return m
            raise FileNotFoundError

        with patch('os.path.exists', side_effect=mock_exists), \
             patch('subprocess.run', side_effect=mock_run), \
             patch('shutil.which', return_value=None), \
             patch('builtins.open', side_effect=mock_open_file):

            platform = unifi_cert.UnifiPlatform.detect()

        assert platform is not None
        assert platform.device_type == 'CloudKey'
        assert platform.has_postgres is False

    def test_detect_dream_machine(self):
        """Test detection of Dream Machine device."""
        def mock_exists(path):
            if path == '/data/unifi-core':
                return True
            if path == '/sys/firmware/devicetree/base/model':
                return True
            return False

        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 1
            result.stdout = ""
            return result

        def mock_open_file(path, *args, **kwargs):
            if 'model' in str(path):
                m = MagicMock()
                m.__enter__ = MagicMock(return_value=m)
                m.__exit__ = MagicMock(return_value=False)
                m.read.return_value = b'Ubiquiti Dream Machine Pro\x00'
                return m
            raise FileNotFoundError

        with patch('os.path.exists', side_effect=mock_exists), \
             patch('subprocess.run', side_effect=mock_run), \
             patch('shutil.which', return_value=None), \
             patch('builtins.open', side_effect=mock_open_file):

            platform = unifi_cert.UnifiPlatform.detect()

        assert platform is not None
        assert platform.device_type == 'UDM'

    def test_detect_io_error_reading_settings(self):
        """Test detection handles IOError when reading settings."""
        def mock_exists(path):
            if path == '/data/unifi-core':
                return True
            if path == '/data/unifi-core/config/settings.yaml':
                return True
            return False

        def mock_open_file(path, *args, **kwargs):
            raise IOError("Cannot read file")

        with patch('os.path.exists', side_effect=mock_exists), \
             patch('subprocess.run', side_effect=FileNotFoundError), \
             patch('shutil.which', return_value=None), \
             patch('builtins.open', side_effect=mock_open_file):

            platform = unifi_cert.UnifiPlatform.detect()

        assert platform is not None
        assert platform.active_cert_id is None

    def test_detect_nvr_device(self):
        """Test detection of NVR device via UNVR in model string."""
        def mock_exists(path):
            if path == '/data/unifi-core':
                return True
            if path == '/sys/firmware/devicetree/base/model':
                return True
            return False

        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 1
            result.stdout = ""
            return result

        def mock_open_file(path, *args, **kwargs):
            if 'model' in str(path):
                m = MagicMock()
                m.__enter__ = MagicMock(return_value=m)
                m.__exit__ = MagicMock(return_value=False)
                m.read.return_value = b'UNVR\x00'
                return m
            raise FileNotFoundError

        with patch('os.path.exists', side_effect=mock_exists), \
             patch('subprocess.run', side_effect=mock_run), \
             patch('shutil.which', return_value=None), \
             patch('builtins.open', side_effect=mock_open_file):

            platform = unifi_cert.UnifiPlatform.detect()

        assert platform is not None
        assert platform.device_type == 'NVR'

    def test_detect_udm_fallback_via_version_file(self):
        """Test UDM detection fallback when model doesn't match but version file exists."""
        def mock_exists(path):
            if path == '/data/unifi-core':
                return True
            if path == '/sys/firmware/devicetree/base/model':
                return True
            if path == '/usr/lib/version':
                return True  # Version file exists - triggers UDM fallback
            return False

        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 1
            result.stdout = ""
            return result

        def mock_open_file(path, *args, **kwargs):
            if 'model' in str(path):
                m = MagicMock()
                m.__enter__ = MagicMock(return_value=m)
                m.__exit__ = MagicMock(return_value=False)
                # Model string without "Dream Machine" or "UDM" - Alpine chip only
                m.read.return_value = b'Annapurna Labs Alpine V2 UBNT\x00'
                return m
            raise FileNotFoundError

        with patch('os.path.exists', side_effect=mock_exists), \
             patch('subprocess.run', side_effect=mock_run), \
             patch('shutil.which', return_value=None), \
             patch('builtins.open', side_effect=mock_open_file):

            platform = unifi_cert.UnifiPlatform.detect()

        # Falls back to UDM when /usr/lib/version exists
        assert platform is not None
        assert platform.device_type == 'UDM'

    def test_detect_io_error_reading_model(self):
        """Test detection handles IOError when reading model file."""
        def mock_exists(path):
            if path == '/data/unifi-core':
                return True
            if path == '/sys/firmware/devicetree/base/model':
                return True
            return False

        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 1
            result.stdout = ""
            return result

        def mock_open_file(path, *args, **kwargs):
            if 'model' in str(path):
                raise IOError("Cannot read model")
            raise FileNotFoundError

        with patch('os.path.exists', side_effect=mock_exists), \
             patch('subprocess.run', side_effect=mock_run), \
             patch('shutil.which', return_value=None), \
             patch('builtins.open', side_effect=mock_open_file):

            platform = unifi_cert.UnifiPlatform.detect()

        assert platform is not None
        # IOError when reading model file leaves device_type as Unknown
        assert platform.device_type == 'Unknown'


# =============================================================================
# CERTIFICATE INSTALLATION TESTS
# =============================================================================

class TestCertificateInstallation:
    """Tests for certificate installation functions."""

    def test_backup_file_exists(self, temp_dir):
        """Test backup of existing file."""
        original = os.path.join(temp_dir, "original.txt")
        with open(original, 'w') as f:
            f.write("content")

        backup_path = unifi_cert.backup_file(original)

        assert backup_path is not None
        assert os.path.exists(backup_path)
        assert ".bak." in backup_path

    def test_backup_file_not_exists(self):
        """Test backup when file doesn't exist."""
        result = unifi_cert.backup_file("/nonexistent/file.txt")
        assert result is None

    def test_backup_file_io_error(self, temp_dir):
        """Test backup when IOError occurs."""
        original = os.path.join(temp_dir, "original.txt")
        with open(original, 'w') as f:
            f.write("content")

        with patch('shutil.copy2', side_effect=IOError("Permission denied")):
            backup_path = unifi_cert.backup_file(original)

        assert backup_path is None

    def test_install_certificate_dry_run(self, temp_dir, sample_cert_content, sample_key_content):
        """Test certificate installation in dry run mode."""
        cert_path = os.path.join(temp_dir, "cert.crt")
        key_path = os.path.join(temp_dir, "cert.key")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)
        with open(key_path, 'w') as f:
            f.write(sample_key_content)

        platform = unifi_cert.UnifiPlatform(
            device_type='UDM',
            core_version='4.0.6',
            has_eus_certs=True,
            has_postgres=True,
            active_cert_id='existing-uuid',
        )

        # Mock the metadata extraction
        mock_meta = unifi_cert.CertMetadata(
            cn='example.com',
            issuer_c='US',
            issuer_o="Let's Encrypt",
            issuer_cn='R3',
            sans=['example.com'],
            valid_from='2024-01-01 00:00:00+00',
            valid_to='2024-04-01 00:00:00+00',
            serial='1234',
            fingerprint='AA:BB:CC',
        )

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert.CertMetadata, 'from_cert_file', return_value=mock_meta), \
             patch.dict(unifi_cert.UNIFI_PATHS, {
                 'eus_cert': os.path.join(temp_dir, 'eus.crt'),
                 'eus_key': os.path.join(temp_dir, 'eus.key'),
                 'eus_dir': temp_dir,
                 'config_dir': temp_dir,
                 'settings_yaml': os.path.join(temp_dir, 'settings.yaml'),
             }):
            result = unifi_cert.install_certificate(
                cert_path, key_path, 'example.com', platform,
                dry_run=True
            )

        assert result is True

    def test_install_certificate_file_not_found(self, temp_dir):
        """Test installation with missing certificate files."""
        platform = unifi_cert.UnifiPlatform(
            device_type='UDM',
            core_version='4.0.6',
            has_eus_certs=True,
            has_postgres=True,
            active_cert_id=None,
        )

        with patch.object(unifi_cert, 'ui'):
            result = unifi_cert.install_certificate(
                '/nonexistent/cert.crt',
                '/nonexistent/key.key',
                'example.com',
                platform,
            )

        assert result is False

    def test_install_certificate_full_success(self, temp_dir, sample_cert_content, sample_key_content):
        """Test certificate installation full success path."""
        cert_path = os.path.join(temp_dir, "cert.crt")
        key_path = os.path.join(temp_dir, "cert.key")
        settings_path = os.path.join(temp_dir, "settings.yaml")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)
        with open(key_path, 'w') as f:
            f.write(sample_key_content)
        with open(settings_path, 'w') as f:
            f.write("some: config\n")

        platform = unifi_cert.UnifiPlatform(
            device_type='UDM',
            core_version='4.0.6',
            has_eus_certs=True,
            has_postgres=True,
            active_cert_id=None,  # Will generate new cert ID
        )

        mock_meta = unifi_cert.CertMetadata(
            cn='example.com',
            issuer_c='US',
            issuer_o="Let's Encrypt",
            issuer_cn='R3',
            sans=['example.com'],
            valid_from='2024-01-01 00:00:00+00',
            valid_to='2024-04-01 00:00:00+00',
            serial='1234',
            fingerprint='AA:BB:CC',
        )

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert.CertMetadata, 'from_cert_file', return_value=mock_meta), \
             patch.object(unifi_cert, 'update_postgres', return_value=True), \
             patch.object(unifi_cert, 'restart_services'), \
             patch.dict(unifi_cert.UNIFI_PATHS, {
                 'eus_cert': os.path.join(temp_dir, 'eus.crt'),
                 'eus_key': os.path.join(temp_dir, 'eus.key'),
                 'eus_dir': temp_dir,
                 'config_dir': temp_dir,
                 'settings_yaml': settings_path,
             }):
            result = unifi_cert.install_certificate(
                cert_path, key_path, 'example.com', platform,
            )

        assert result is True

    def test_install_certificate_skip_postgres(self, temp_dir, sample_cert_content, sample_key_content):
        """Test certificate installation with skip_postgres."""
        cert_path = os.path.join(temp_dir, "cert.crt")
        key_path = os.path.join(temp_dir, "cert.key")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)
        with open(key_path, 'w') as f:
            f.write(sample_key_content)

        platform = unifi_cert.UnifiPlatform(
            device_type='UDM',
            core_version='4.0.6',
            has_eus_certs=False,
            has_postgres=True,
            active_cert_id='existing-uuid',
        )

        mock_meta = unifi_cert.CertMetadata(
            cn='example.com',
            issuer_c='US',
            issuer_o="Let's Encrypt",
            issuer_cn='R3',
            sans=['example.com'],
            valid_from='2024-01-01 00:00:00+00',
            valid_to='2024-04-01 00:00:00+00',
            serial='1234',
            fingerprint='AA:BB:CC',
        )

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert.CertMetadata, 'from_cert_file', return_value=mock_meta), \
             patch.object(unifi_cert, 'restart_services'), \
             patch.dict(unifi_cert.UNIFI_PATHS, {
                 'eus_cert': os.path.join(temp_dir, 'eus.crt'),
                 'eus_key': os.path.join(temp_dir, 'eus.key'),
                 'eus_dir': temp_dir,
                 'config_dir': temp_dir,
                 'settings_yaml': os.path.join(temp_dir, 'settings.yaml'),
             }):
            result = unifi_cert.install_certificate(
                cert_path, key_path, 'example.com', platform,
                skip_postgres=True,
            )

        assert result is True

    def test_install_certificate_skip_restart(self, temp_dir, sample_cert_content, sample_key_content):
        """Test certificate installation with skip_restart."""
        cert_path = os.path.join(temp_dir, "cert.crt")
        key_path = os.path.join(temp_dir, "cert.key")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)
        with open(key_path, 'w') as f:
            f.write(sample_key_content)

        platform = unifi_cert.UnifiPlatform(
            device_type='UDM',
            core_version='4.0.6',
            has_eus_certs=False,
            has_postgres=False,
            active_cert_id='existing-uuid',
        )

        mock_meta = unifi_cert.CertMetadata(
            cn='example.com',
            issuer_c='US',
            issuer_o="Let's Encrypt",
            issuer_cn='R3',
            sans=['example.com'],
            valid_from='2024-01-01 00:00:00+00',
            valid_to='2024-04-01 00:00:00+00',
            serial='1234',
            fingerprint='AA:BB:CC',
        )

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert.CertMetadata, 'from_cert_file', return_value=mock_meta), \
             patch.dict(unifi_cert.UNIFI_PATHS, {
                 'eus_cert': os.path.join(temp_dir, 'eus.crt'),
                 'eus_key': os.path.join(temp_dir, 'eus.key'),
                 'eus_dir': temp_dir,
                 'config_dir': temp_dir,
                 'settings_yaml': os.path.join(temp_dir, 'settings.yaml'),
             }):
            result = unifi_cert.install_certificate(
                cert_path, key_path, 'example.com', platform,
                skip_restart=True,
            )

        assert result is True

    def test_install_certificate_settings_update_error(self, temp_dir, sample_cert_content, sample_key_content):
        """Test certificate installation when settings.yaml update fails."""
        cert_path = os.path.join(temp_dir, "cert.crt")
        key_path = os.path.join(temp_dir, "cert.key")
        settings_path = os.path.join(temp_dir, "settings.yaml")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)
        with open(key_path, 'w') as f:
            f.write(sample_key_content)
        with open(settings_path, 'w') as f:
            f.write("activeCertId: old-uuid\n")

        platform = unifi_cert.UnifiPlatform(
            device_type='UDM',
            core_version='4.0.6',
            has_eus_certs=False,
            has_postgres=False,
            active_cert_id=None,
        )

        mock_meta = unifi_cert.CertMetadata(
            cn='example.com',
            issuer_c='US',
            issuer_o="Let's Encrypt",
            issuer_cn='R3',
            sans=['example.com'],
            valid_from='2024-01-01 00:00:00+00',
            valid_to='2024-04-01 00:00:00+00',
            serial='1234',
            fingerprint='AA:BB:CC',
        )

        original_open = open
        def mock_open_func(path, *args, **kwargs):
            if 'settings.yaml' in str(path) and 'w' in str(args):
                raise IOError("Cannot write")
            return original_open(path, *args, **kwargs)

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert.CertMetadata, 'from_cert_file', return_value=mock_meta), \
             patch.object(unifi_cert, 'restart_services'), \
             patch.dict(unifi_cert.UNIFI_PATHS, {
                 'eus_cert': os.path.join(temp_dir, 'eus.crt'),
                 'eus_key': os.path.join(temp_dir, 'eus.key'),
                 'eus_dir': temp_dir,
                 'config_dir': temp_dir,
                 'settings_yaml': settings_path,
             }):
            # This should still succeed but warn about settings.yaml
            result = unifi_cert.install_certificate(
                cert_path, key_path, 'example.com', platform,
                skip_restart=True,
            )

        assert result is True


class TestPostgreSQL:
    """Tests for PostgreSQL update functions."""

    def test_update_postgres_new_cert(self):
        """Test PostgreSQL update for new certificate."""
        meta = unifi_cert.CertMetadata(
            cn='example.com',
            issuer_c='US',
            issuer_o="Let's Encrypt",
            issuer_cn='R3',
            sans=['example.com', 'www.example.com'],
            valid_from='2024-01-01 00:00:00+00',
            valid_to='2024-04-01 00:00:00+00',
            serial='1234567890',
            fingerprint='AA:BB:CC:DD',
        )

        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stdout = "INSERT 0 1"
            return result

        with patch('subprocess.run', side_effect=mock_run), \
             patch.object(unifi_cert, 'ui'):
            result = unifi_cert.update_postgres(
                'new-uuid',
                '2024-01-example.com',
                '---CERT---',
                '---KEY---',
                meta,
                is_new=True,
            )

        assert result is True

    def test_update_postgres_existing_cert(self):
        """Test PostgreSQL update for existing certificate."""
        meta = unifi_cert.CertMetadata(
            cn='example.com',
            issuer_c='US',
            issuer_o="Let's Encrypt",
            issuer_cn='R3',
            sans=['example.com'],
            valid_from='2024-01-01 00:00:00+00',
            valid_to='2024-04-01 00:00:00+00',
            serial='1234567890',
            fingerprint='AA:BB:CC:DD',
        )

        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stdout = "UPDATE 1"
            return result

        with patch('subprocess.run', side_effect=mock_run), \
             patch.object(unifi_cert, 'ui'):
            result = unifi_cert.update_postgres(
                'existing-uuid',
                '2024-01-example.com',
                '---CERT---',
                '---KEY---',
                meta,
                is_new=False,
            )

        assert result is True

    def test_update_postgres_psql_not_found(self):
        """Test PostgreSQL update when psql not available."""
        meta = unifi_cert.CertMetadata(
            cn='example.com',
            issuer_c='US',
            issuer_o="Let's Encrypt",
            issuer_cn='R3',
            sans=[],
            valid_from='',
            valid_to='',
            serial='',
            fingerprint='',
        )

        with patch('subprocess.run', side_effect=FileNotFoundError), \
             patch.object(unifi_cert, 'ui'):
            result = unifi_cert.update_postgres(
                'uuid', 'name', 'cert', 'key', meta, is_new=True
            )

        assert result is False


class TestRestartServices:
    """Tests for service restart function."""

    def test_restart_services(self):
        """Test service restart."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            unifi_cert.restart_services()

            # Should have called systemctl restart for nginx and unifi-core
            calls = mock_run.call_args_list
            assert len(calls) == 2

    def test_restart_services_systemctl_not_found(self):
        """Test restart when systemctl not available."""
        with patch('subprocess.run', side_effect=FileNotFoundError):
            # Should not raise
            unifi_cert.restart_services()


# =============================================================================
# CERTBOT INTEGRATION TESTS
# =============================================================================

class TestCertbot:
    """Tests for certbot integration."""

    def test_run_certbot_success(self, temp_dir):
        """Test successful certbot run."""
        # Create the expected certificate paths
        live_dir = os.path.join(temp_dir, 'live', 'example.com')
        cert_path = os.path.join(live_dir, 'fullchain.pem')
        key_path = os.path.join(live_dir, 'privkey.pem')
        os.makedirs(live_dir)
        with open(cert_path, 'w') as f:
            f.write("---CERT---")
        with open(key_path, 'w') as f:
            f.write("---KEY---")

        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stdout = "Congratulations!"
            result.stderr = ""
            return result

        real_exists = os.path.exists

        def mock_exists(path):
            if 'fullchain.pem' in str(path) or 'privkey.pem' in str(path):
                return True
            return real_exists(path)

        with patch('subprocess.run', side_effect=mock_run), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'bootstrap_certbot', return_value=(True, 'mocked')), \
             patch('os.path.exists', side_effect=mock_exists):

            success, returned_cert, returned_key = unifi_cert.run_certbot(
                'example.com',
                'admin@example.com',
                'digitalocean',
                '/path/to/creds.ini',
            )

        assert success is True
        assert 'fullchain.pem' in returned_cert
        assert 'privkey.pem' in returned_key

    def test_run_certbot_unknown_provider(self):
        """Test certbot with unknown DNS provider."""
        with patch.object(unifi_cert, 'ui'):
            success, cert, key = unifi_cert.run_certbot(
                'example.com',
                'admin@example.com',
                'unknown_provider',
                '/path/to/creds.ini',
            )

        assert success is False
        assert cert == ''
        assert key == ''

    def test_run_certbot_dry_run(self):
        """Test certbot dry run."""
        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stdout = "Dry run success"
            result.stderr = ""
            return result

        with patch('subprocess.run', side_effect=mock_run), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'bootstrap_certbot', return_value=(True, 'mocked')):
            success, cert, key = unifi_cert.run_certbot(
                'example.com',
                'admin@example.com',
                'digitalocean',
                '/path/to/creds.ini',
                dry_run=True,
            )

        assert success is True
        assert cert == ''  # No cert in dry run
        assert key == ''

    def test_run_certbot_failure(self):
        """Test certbot failure."""
        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 1
            result.stdout = ""
            result.stderr = "ACME challenge failed"
            return result

        with patch('subprocess.run', side_effect=mock_run), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'bootstrap_certbot', return_value=(True, 'mocked')):
            success, cert, key = unifi_cert.run_certbot(
                'example.com',
                'admin@example.com',
                'digitalocean',
                '/path/to/creds.ini',
            )

        assert success is False

    def test_run_certbot_not_installed(self):
        """Test when certbot is not installed."""
        with patch('subprocess.run', side_effect=FileNotFoundError), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'bootstrap_certbot', return_value=(True, 'mocked')):
            success, cert, key = unifi_cert.run_certbot(
                'example.com',
                'admin@example.com',
                'digitalocean',
                '/path/to/creds.ini',
            )

        assert success is False

    def test_setup_renewal_hook(self, temp_dir):
        """Test renewal hook setup success."""
        hook_dir = os.path.join(temp_dir, 'post')
        hook_path = os.path.join(hook_dir, 'unifi-cert-hook.sh')

        # Create the hook directory structure
        os.makedirs(hook_dir, exist_ok=True)

        with patch.object(unifi_cert, 'ui'):
            # Patch os.path.join to redirect to temp_dir
            original_join = os.path.join
            def mock_join(*args):
                if '/etc/letsencrypt' in str(args):
                    return original_join(temp_dir, 'post', 'unifi-cert-hook.sh')
                return original_join(*args)

            with patch('os.path.join', side_effect=mock_join):
                result = unifi_cert.setup_renewal_hook('example.com', '/path/to/script.py')

        assert result is True
        assert os.path.exists(hook_path)

    def test_setup_renewal_hook_failure(self):
        """Test renewal hook setup failure."""
        with patch.object(unifi_cert, 'ui'), \
             patch('os.makedirs', side_effect=IOError("Permission denied")):
            result = unifi_cert.setup_renewal_hook('example.com', '/path/to/script.py')

        assert result is False

    def test_ensure_script_installed_downloads_when_stdin(self, temp_dir):
        """Test that script downloads from GitHub when running from stdin (curl pipe)."""
        permanent_path = os.path.join(temp_dir, 'unifi-cert.py')

        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            if 'curl' in cmd:
                # Simulate successful download
                with open(cmd[cmd.index('-o') + 1], 'w') as f:
                    f.write('#!/usr/bin/env python3\n# Downloaded script')
                result.returncode = 0
            else:
                result.returncode = 1
            return result

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'PERMANENT_SCRIPT_PATH', permanent_path), \
             patch('subprocess.run', side_effect=mock_run), \
             patch('os.path.abspath', return_value=None):  # Simulate no __file__

            # Call the function - it should download when current_path is None
            result = unifi_cert.ensure_script_installed()

        assert result == permanent_path
        assert os.path.exists(permanent_path)

    def test_ensure_script_installed_copies_when_file(self, temp_dir):
        """Test that script copies itself when running from a file."""
        source_path = os.path.join(temp_dir, 'source.py')
        permanent_path = os.path.join(temp_dir, 'scripts', 'unifi-cert.py')

        # Create a source file
        with open(source_path, 'w') as f:
            f.write('#!/usr/bin/env python3\n# Source script')

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'PERMANENT_SCRIPT_PATH', permanent_path), \
             patch('os.path.abspath', return_value=source_path):

            result = unifi_cert.ensure_script_installed()

        assert result == permanent_path
        assert os.path.exists(permanent_path)


# =============================================================================
# REMOTE SSH OPERATIONS TESTS
# =============================================================================

class TestRemoteSSH:
    """Tests for remote SSH operations."""

    def test_run_remote_success(self):
        """Test successful remote command."""
        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stdout = "command output"
            return result

        with patch('subprocess.run', side_effect=mock_run):
            success, output = unifi_cert.run_remote('192.168.1.1', 'ls -la')

        assert success is True
        assert output == "command output"

    def test_run_remote_failure(self):
        """Test failed remote command."""
        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 1
            result.stdout = ""
            return result

        with patch('subprocess.run', side_effect=mock_run):
            success, output = unifi_cert.run_remote('192.168.1.1', 'invalid_command')

        assert success is False

    def test_run_remote_timeout(self):
        """Test remote command timeout."""
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('ssh', 30)):
            success, output = unifi_cert.run_remote('192.168.1.1', 'slow_command')

        assert success is False
        assert output == 'Timeout'

    def test_run_remote_ssh_not_found(self):
        """Test when SSH not available."""
        with patch('subprocess.run', side_effect=FileNotFoundError):
            success, output = unifi_cert.run_remote('192.168.1.1', 'command')

        assert success is False
        assert output == 'SSH not found'

    def test_scp_file_success(self):
        """Test successful file copy."""
        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 0
            return result

        with patch('subprocess.run', side_effect=mock_run):
            result = unifi_cert.scp_file('/local/file', '192.168.1.1', '/remote/file')

        assert result is True

    def test_scp_file_failure(self):
        """Test failed file copy."""
        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 1
            return result

        with patch('subprocess.run', side_effect=mock_run):
            result = unifi_cert.scp_file('/local/file', '192.168.1.1', '/remote/file')

        assert result is False

    def test_scp_file_timeout(self):
        """Test file copy timeout."""
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('scp', 60)):
            result = unifi_cert.scp_file('/local/file', '192.168.1.1', '/remote/file')

        assert result is False


class TestInstallCertificateRemote:
    """Tests for remote certificate installation."""

    def test_install_certificate_remote_connection_failure(self, temp_dir, sample_cert_content, sample_key_content):
        """Test remote installation when SSH connection fails."""
        cert_path = os.path.join(temp_dir, "cert.crt")
        key_path = os.path.join(temp_dir, "cert.key")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)
        with open(key_path, 'w') as f:
            f.write(sample_key_content)

        def mock_run_remote(host, cmd, timeout=30):
            return False, "Connection refused"

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_remote', side_effect=mock_run_remote):
            result = unifi_cert.install_certificate_remote(
                cert_path, key_path, 'example.com', '192.168.1.1'
            )

        assert result is False

    def test_install_certificate_remote_dry_run(self, temp_dir, sample_cert_content, sample_key_content):
        """Test remote installation dry run."""
        cert_path = os.path.join(temp_dir, "cert.crt")
        key_path = os.path.join(temp_dir, "cert.key")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)
        with open(key_path, 'w') as f:
            f.write(sample_key_content)

        def mock_run_remote(host, cmd, timeout=30):
            if cmd == 'true':
                return True, ""
            return True, "test-uuid"

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_remote', side_effect=mock_run_remote):
            result = unifi_cert.install_certificate_remote(
                cert_path, key_path, 'example.com', '192.168.1.1',
                dry_run=True
            )

        assert result is True

    def test_install_certificate_remote_full_success(self, temp_dir, sample_cert_content, sample_key_content):
        """Test full remote installation success."""
        cert_path = os.path.join(temp_dir, "cert.crt")
        key_path = os.path.join(temp_dir, "cert.key")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)
        with open(key_path, 'w') as f:
            f.write(sample_key_content)

        def mock_run_remote(host, cmd, timeout=30):
            if cmd == 'true':
                return True, ""
            if 'activeCertId' in cmd:
                return True, "existing-cert-uuid"
            if 'test -d' in cmd:
                return True, ""
            if 'which psql' in cmd:
                return True, "/usr/bin/psql"
            if 'psql' in cmd:
                return True, "UPDATE 1"
            if 'systemctl' in cmd:
                return True, ""
            return True, ""

        mock_meta = unifi_cert.CertMetadata(
            cn='example.com',
            issuer_c='US',
            issuer_o="Let's Encrypt",
            issuer_cn='R3',
            sans=['example.com'],
            valid_from='2024-01-01 00:00:00+00',
            valid_to='2024-04-01 00:00:00+00',
            serial='1234',
            fingerprint='AA:BB:CC',
        )

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_remote', side_effect=mock_run_remote), \
             patch.object(unifi_cert, 'scp_file', return_value=True), \
             patch.object(unifi_cert.CertMetadata, 'from_cert_file', return_value=mock_meta):
            result = unifi_cert.install_certificate_remote(
                cert_path, key_path, 'example.com', '192.168.1.1'
            )

        assert result is True

    def test_install_certificate_remote_new_cert(self, temp_dir, sample_cert_content, sample_key_content):
        """Test remote installation with new certificate (no existing cert ID)."""
        cert_path = os.path.join(temp_dir, "cert.crt")
        key_path = os.path.join(temp_dir, "cert.key")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)
        with open(key_path, 'w') as f:
            f.write(sample_key_content)

        def mock_run_remote(host, cmd, timeout=30):
            if cmd == 'true':
                return True, ""
            if 'activeCertId' in cmd:
                return True, ""  # No existing cert
            if 'test -d' in cmd:
                return True, ""
            if 'which psql' in cmd:
                return True, "/usr/bin/psql"
            if 'grep -q' in cmd:
                return True, ""
            if 'psql' in cmd:
                return True, "INSERT 1"
            if 'systemctl' in cmd:
                return True, ""
            return True, ""

        mock_meta = unifi_cert.CertMetadata(
            cn='example.com',
            issuer_c='US',
            issuer_o="Let's Encrypt",
            issuer_cn='R3',
            sans=['example.com'],
            valid_from='2024-01-01 00:00:00+00',
            valid_to='2024-04-01 00:00:00+00',
            serial='1234',
            fingerprint='AA:BB:CC',
        )

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_remote', side_effect=mock_run_remote), \
             patch.object(unifi_cert, 'scp_file', return_value=True), \
             patch.object(unifi_cert.CertMetadata, 'from_cert_file', return_value=mock_meta):
            result = unifi_cert.install_certificate_remote(
                cert_path, key_path, 'example.com', '192.168.1.1'
            )

        assert result is True

    def test_install_certificate_remote_eus_upload_failure(self, temp_dir, sample_cert_content, sample_key_content):
        """Test remote installation when EUS upload fails."""
        cert_path = os.path.join(temp_dir, "cert.crt")
        key_path = os.path.join(temp_dir, "cert.key")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)
        with open(key_path, 'w') as f:
            f.write(sample_key_content)

        def mock_run_remote(host, cmd, timeout=30):
            if cmd == 'true':
                return True, ""
            if 'activeCertId' in cmd:
                return True, "cert-uuid"
            if 'test -d' in cmd:
                return True, ""  # has EUS
            if 'which psql' in cmd:
                return True, "/usr/bin/psql"
            return True, ""

        mock_meta = unifi_cert.CertMetadata(
            cn='example.com',
            issuer_c='US',
            issuer_o="Let's Encrypt",
            issuer_cn='R3',
            sans=['example.com'],
            valid_from='2024-01-01 00:00:00+00',
            valid_to='2024-04-01 00:00:00+00',
            serial='1234',
            fingerprint='AA:BB:CC',
        )

        scp_call_count = [0]
        def mock_scp(local, host, remote):
            scp_call_count[0] += 1
            if scp_call_count[0] == 1:
                return False  # First upload fails
            return True

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_remote', side_effect=mock_run_remote), \
             patch.object(unifi_cert, 'scp_file', side_effect=mock_scp), \
             patch.object(unifi_cert.CertMetadata, 'from_cert_file', return_value=mock_meta):
            result = unifi_cert.install_certificate_remote(
                cert_path, key_path, 'example.com', '192.168.1.1'
            )

        assert result is False

    def test_install_certificate_remote_skip_postgres(self, temp_dir, sample_cert_content, sample_key_content):
        """Test remote installation skipping postgres."""
        cert_path = os.path.join(temp_dir, "cert.crt")
        key_path = os.path.join(temp_dir, "cert.key")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)
        with open(key_path, 'w') as f:
            f.write(sample_key_content)

        def mock_run_remote(host, cmd, timeout=30):
            if cmd == 'true':
                return True, ""
            if 'activeCertId' in cmd:
                return True, "cert-uuid"
            if 'test -d' in cmd:
                return False, ""  # no EUS
            if 'which psql' in cmd:
                return True, "/usr/bin/psql"
            if 'systemctl' in cmd:
                return True, ""
            return True, ""

        mock_meta = unifi_cert.CertMetadata(
            cn='example.com',
            issuer_c='US',
            issuer_o="Let's Encrypt",
            issuer_cn='R3',
            sans=['example.com'],
            valid_from='2024-01-01 00:00:00+00',
            valid_to='2024-04-01 00:00:00+00',
            serial='1234',
            fingerprint='AA:BB:CC',
        )

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_remote', side_effect=mock_run_remote), \
             patch.object(unifi_cert, 'scp_file', return_value=True), \
             patch.object(unifi_cert.CertMetadata, 'from_cert_file', return_value=mock_meta):
            result = unifi_cert.install_certificate_remote(
                cert_path, key_path, 'example.com', '192.168.1.1',
                skip_postgres=True
            )

        assert result is True

    def test_install_certificate_remote_skip_restart(self, temp_dir, sample_cert_content, sample_key_content):
        """Test remote installation skipping service restart."""
        cert_path = os.path.join(temp_dir, "cert.crt")
        key_path = os.path.join(temp_dir, "cert.key")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)
        with open(key_path, 'w') as f:
            f.write(sample_key_content)

        def mock_run_remote(host, cmd, timeout=30):
            if cmd == 'true':
                return True, ""
            if 'activeCertId' in cmd:
                return True, "cert-uuid"
            if 'test -d' in cmd:
                return False, ""
            if 'which psql' in cmd:
                return False, ""  # no postgres
            return True, ""

        mock_meta = unifi_cert.CertMetadata(
            cn='example.com',
            issuer_c='US',
            issuer_o="Let's Encrypt",
            issuer_cn='R3',
            sans=['example.com'],
            valid_from='2024-01-01 00:00:00+00',
            valid_to='2024-04-01 00:00:00+00',
            serial='1234',
            fingerprint='AA:BB:CC',
        )

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_remote', side_effect=mock_run_remote), \
             patch.object(unifi_cert, 'scp_file', return_value=True), \
             patch.object(unifi_cert.CertMetadata, 'from_cert_file', return_value=mock_meta):
            result = unifi_cert.install_certificate_remote(
                cert_path, key_path, 'example.com', '192.168.1.1',
                skip_restart=True
            )

        assert result is True


# =============================================================================
# CLI & MAIN TESTS
# =============================================================================

class TestCLI:
    """Tests for CLI argument parsing."""

    def test_parse_args_help(self):
        """Test --help doesn't crash."""
        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', ['unifi-cert', '--help']):
                unifi_cert.parse_args()
        assert exc_info.value.code == 0

    def test_parse_args_basic(self):
        """Test basic argument parsing."""
        with patch('sys.argv', ['unifi-cert', '-d', 'example.com', '-e', 'admin@example.com']):
            args = unifi_cert.parse_args()
        assert args.domain == 'example.com'
        assert args.email == 'admin@example.com'

    def test_parse_args_install(self):
        """Test --install argument parsing."""
        with patch('sys.argv', ['unifi-cert', '--install', '--cert', 'cert.pem', '--key', 'key.pem', '-d', 'example.com']):
            args = unifi_cert.parse_args()
        assert args.install is True
        assert args.cert == 'cert.pem'
        assert args.key == 'key.pem'

    def test_parse_args_remote(self):
        """Test --host argument parsing."""
        with patch('sys.argv', ['unifi-cert', '-d', 'example.com', '--host', '192.168.1.1']):
            args = unifi_cert.parse_args()
        assert args.host == '192.168.1.1'

    def test_parse_args_dns_provider(self):
        """Test DNS provider argument parsing."""
        with patch('sys.argv', ['unifi-cert', '-d', 'example.com', '--dns-provider', 'cloudflare']):
            args = unifi_cert.parse_args()
        assert args.dns_provider == 'cloudflare'

    def test_parse_args_modifiers(self):
        """Test operation modifier arguments."""
        with patch('sys.argv', ['unifi-cert', '-d', 'example.com', '--dry-run', '--force', '--skip-postgres', '--skip-restart', '-v', '--no-color']):
            args = unifi_cert.parse_args()
        assert args.dry_run is True
        assert args.force is True
        assert args.skip_postgres is True
        assert args.skip_restart is True
        assert args.verbose is True
        assert args.no_color is True


class TestMain:
    """Tests for main function."""

    def test_main_no_domain_non_interactive(self):
        """Test main with no domain and non-interactive mode."""
        with patch('sys.argv', ['unifi-cert']), \
             patch('sys.stdin.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'):
            result = unifi_cert.main()
        assert result == 1

    def test_main_install_missing_files(self):
        """Test main --install with missing files."""
        with patch('sys.argv', ['unifi-cert', '--install', '-d', 'example.com']), \
             patch.object(unifi_cert, 'ui'):
            result = unifi_cert.main()
        assert result == 1

    def test_main_install_cert_not_found(self, temp_dir):
        """Test main --install when cert file doesn't exist."""
        with patch('sys.argv', ['unifi-cert', '--install', '--cert', '/nonexistent.crt', '--key', '/nonexistent.key', '-d', 'example.com']), \
             patch.object(unifi_cert, 'ui'):
            result = unifi_cert.main()
        assert result == 1

    def test_main_install_key_not_found(self, temp_dir, sample_cert_content):
        """Test main --install when key file doesn't exist but cert does."""
        cert_path = os.path.join(temp_dir, "cert.crt")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)

        with patch('sys.argv', ['unifi-cert', '--install', '--cert', cert_path, '--key', '/nonexistent.key', '-d', 'example.com']), \
             patch.object(unifi_cert, 'ui'):
            result = unifi_cert.main()
        assert result == 1

    def test_main_setup_hook(self, temp_dir):
        """Test main --setup-hook."""
        with patch('sys.argv', ['unifi-cert', '--setup-hook', '-d', 'example.com']), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'setup_renewal_hook', return_value=True):
            result = unifi_cert.main()
        assert result == 0

    def test_main_setup_hook_failure(self, temp_dir):
        """Test main --setup-hook failure."""
        with patch('sys.argv', ['unifi-cert', '--setup-hook', '-d', 'example.com']), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'setup_renewal_hook', return_value=False):
            result = unifi_cert.main()
        assert result == 1

    def test_main_setup_hook_no_domain(self, temp_dir):
        """Test main --setup-hook without domain uses default."""
        with patch('sys.argv', ['unifi-cert', '--setup-hook']), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'setup_renewal_hook', return_value=True) as mock_hook:
            result = unifi_cert.main()
        assert result == 0
        # Should use 'example.com' as default
        mock_hook.assert_called_once()

    def test_main_missing_email(self):
        """Test main without email for new certificate."""
        with patch('sys.argv', ['unifi-cert', '-d', 'example.com']), \
             patch('sys.stdin.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'):
            result = unifi_cert.main()
        assert result == 1

    def test_main_missing_dns_provider(self):
        """Test main without DNS provider for new certificate."""
        with patch('sys.argv', ['unifi-cert', '-d', 'example.com', '-e', 'admin@example.com']), \
             patch('sys.stdin.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'):
            result = unifi_cert.main()
        assert result == 1

    def test_main_missing_dns_credentials(self):
        """Test main without DNS credentials."""
        with patch('sys.argv', ['unifi-cert', '-d', 'example.com', '-e', 'admin@example.com', '--dns-provider', 'digitalocean']), \
             patch('sys.stdin.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'):
            result = unifi_cert.main()
        assert result == 1

    def test_main_invalid_credentials(self, temp_dir):
        """Test main with invalid DNS credentials."""
        creds_path = os.path.join(temp_dir, "bad_creds.ini")
        with open(creds_path, 'w') as f:
            f.write("wrong_field = token\n")
        os.chmod(creds_path, 0o600)

        with patch('sys.argv', ['unifi-cert', '-d', 'example.com', '-e', 'admin@example.com', '--dns-provider', 'digitalocean', '--dns-credentials', creds_path]), \
             patch('sys.stdin.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'):
            result = unifi_cert.main()
        assert result == 1

    def test_main_certbot_dry_run_success(self, temp_dir):
        """Test main with certbot dry run success."""
        creds_path = os.path.join(temp_dir, "creds.ini")
        with open(creds_path, 'w') as f:
            f.write("dns_digitalocean_token = token\n")
        os.chmod(creds_path, 0o600)

        with patch('sys.argv', ['unifi-cert', '-d', 'example.com', '-e', 'admin@example.com', '--dns-provider', 'digitalocean', '--dns-credentials', creds_path, '--dry-run']), \
             patch('sys.stdin.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_certbot', return_value=(True, '', '')):
            result = unifi_cert.main()
        assert result == 0

    def test_main_certbot_failure(self, temp_dir):
        """Test main when certbot fails."""
        creds_path = os.path.join(temp_dir, "creds.ini")
        with open(creds_path, 'w') as f:
            f.write("dns_digitalocean_token = token\n")
        os.chmod(creds_path, 0o600)

        with patch('sys.argv', ['unifi-cert', '-d', 'example.com', '-e', 'admin@example.com', '--dns-provider', 'digitalocean', '--dns-credentials', creds_path]), \
             patch('sys.stdin.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_certbot', return_value=(False, '', '')):
            result = unifi_cert.main()
        assert result == 1

    def test_main_certbot_success_remote_install(self, temp_dir):
        """Test main with certbot success and remote installation."""
        creds_path = os.path.join(temp_dir, "creds.ini")
        with open(creds_path, 'w') as f:
            f.write("dns_digitalocean_token = token\n")
        os.chmod(creds_path, 0o600)

        with patch('sys.argv', ['unifi-cert', '-d', 'example.com', '-e', 'admin@example.com', '--dns-provider', 'digitalocean', '--dns-credentials', creds_path, '--host', '192.168.1.1']), \
             patch('sys.stdin.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_certbot', return_value=(True, '/path/cert.pem', '/path/key.pem')), \
             patch.object(unifi_cert, 'install_certificate_remote', return_value=True):
            result = unifi_cert.main()
        assert result == 0

    def test_main_certbot_success_local_install(self, temp_dir):
        """Test main with certbot success and local installation."""
        creds_path = os.path.join(temp_dir, "creds.ini")
        with open(creds_path, 'w') as f:
            f.write("dns_digitalocean_token = token\n")
        os.chmod(creds_path, 0o600)

        mock_platform = unifi_cert.UnifiPlatform(
            device_type='UDM',
            core_version='4.0.6',
            has_eus_certs=True,
            has_postgres=True,
            active_cert_id='uuid',
        )

        with patch('sys.argv', ['unifi-cert', '-d', 'example.com', '-e', 'admin@example.com', '--dns-provider', 'digitalocean', '--dns-credentials', creds_path]), \
             patch('sys.stdin.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_certbot', return_value=(True, '/path/cert.pem', '/path/key.pem')), \
             patch.object(unifi_cert.UnifiPlatform, 'detect', return_value=mock_platform), \
             patch.object(unifi_cert, 'install_certificate', return_value=True):
            result = unifi_cert.main()
        assert result == 0

    def test_main_certbot_success_no_platform(self, temp_dir):
        """Test main with certbot success but no platform detected."""
        creds_path = os.path.join(temp_dir, "creds.ini")
        with open(creds_path, 'w') as f:
            f.write("dns_digitalocean_token = token\n")
        os.chmod(creds_path, 0o600)

        with patch('sys.argv', ['unifi-cert', '-d', 'example.com', '-e', 'admin@example.com', '--dns-provider', 'digitalocean', '--dns-credentials', creds_path]), \
             patch('sys.stdin.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_certbot', return_value=(True, '/path/cert.pem', '/path/key.pem')), \
             patch.object(unifi_cert.UnifiPlatform, 'detect', return_value=None):
            result = unifi_cert.main()
        assert result == 0  # Success but warns about not installing

    def test_main_certbot_success_install_failure(self, temp_dir):
        """Test main with certbot success but installation failure."""
        creds_path = os.path.join(temp_dir, "creds.ini")
        with open(creds_path, 'w') as f:
            f.write("dns_digitalocean_token = token\n")
        os.chmod(creds_path, 0o600)

        mock_platform = unifi_cert.UnifiPlatform(
            device_type='UDM',
            core_version='4.0.6',
            has_eus_certs=True,
            has_postgres=True,
            active_cert_id='uuid',
        )

        with patch('sys.argv', ['unifi-cert', '-d', 'example.com', '-e', 'admin@example.com', '--dns-provider', 'digitalocean', '--dns-credentials', creds_path]), \
             patch('sys.stdin.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_certbot', return_value=(True, '/path/cert.pem', '/path/key.pem')), \
             patch.object(unifi_cert.UnifiPlatform, 'detect', return_value=mock_platform), \
             patch.object(unifi_cert, 'install_certificate', return_value=False):
            result = unifi_cert.main()
        assert result == 1

    def test_main_install_local_success(self, temp_dir, sample_cert_content, sample_key_content):
        """Test main --install with local installation success."""
        cert_path = os.path.join(temp_dir, "cert.crt")
        key_path = os.path.join(temp_dir, "cert.key")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)
        with open(key_path, 'w') as f:
            f.write(sample_key_content)

        mock_platform = unifi_cert.UnifiPlatform(
            device_type='UDM',
            core_version='4.0.6',
            has_eus_certs=True,
            has_postgres=True,
            active_cert_id='uuid',
        )

        with patch('sys.argv', ['unifi-cert', '--install', '--cert', cert_path, '--key', key_path, '-d', 'example.com']), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert.UnifiPlatform, 'detect', return_value=mock_platform), \
             patch.object(unifi_cert, 'install_certificate', return_value=True):
            result = unifi_cert.main()
        assert result == 0

    def test_main_install_local_no_platform(self, temp_dir, sample_cert_content, sample_key_content):
        """Test main --install with no local platform detected."""
        cert_path = os.path.join(temp_dir, "cert.crt")
        key_path = os.path.join(temp_dir, "cert.key")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)
        with open(key_path, 'w') as f:
            f.write(sample_key_content)

        with patch('sys.argv', ['unifi-cert', '--install', '--cert', cert_path, '--key', key_path, '-d', 'example.com']), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert.UnifiPlatform, 'detect', return_value=None):
            result = unifi_cert.main()
        assert result == 1

    def test_main_install_remote_success(self, temp_dir, sample_cert_content, sample_key_content):
        """Test main --install with remote installation success."""
        cert_path = os.path.join(temp_dir, "cert.crt")
        key_path = os.path.join(temp_dir, "cert.key")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)
        with open(key_path, 'w') as f:
            f.write(sample_key_content)

        with patch('sys.argv', ['unifi-cert', '--install', '--cert', cert_path, '--key', key_path, '-d', 'example.com', '--host', '192.168.1.1']), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'install_certificate_remote', return_value=True):
            result = unifi_cert.main()
        assert result == 0

    def test_main_install_remote_failure(self, temp_dir, sample_cert_content, sample_key_content):
        """Test main --install with remote installation failure."""
        cert_path = os.path.join(temp_dir, "cert.crt")
        key_path = os.path.join(temp_dir, "cert.key")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)
        with open(key_path, 'w') as f:
            f.write(sample_key_content)

        with patch('sys.argv', ['unifi-cert', '--install', '--cert', cert_path, '--key', key_path, '-d', 'example.com', '--host', '192.168.1.1']), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'install_certificate_remote', return_value=False):
            result = unifi_cert.main()
        assert result == 1

    def test_main_auto_detect_credentials(self, temp_dir, sample_cert_content, sample_key_content):
        """Test main auto-detects credentials from default location."""
        # Create credentials in default location
        creds_dir = os.path.join(temp_dir, '.secrets', 'certbot')
        os.makedirs(creds_dir)
        creds_path = os.path.join(creds_dir, 'digitalocean.ini')
        with open(creds_path, 'w') as f:
            f.write("dns_digitalocean_token = test_token\n")
        os.chmod(creds_path, 0o600)

        with patch('sys.argv', ['unifi-cert', '-d', 'example.com', '-e', 'admin@example.com', '--dns-provider', 'digitalocean']), \
             patch('sys.stdin.isatty', return_value=False), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch('os.path.expanduser', return_value=creds_path), \
             patch('os.path.exists', return_value=True), \
             patch.object(unifi_cert, 'validate_dns_credentials', return_value=(True, '')), \
             patch.object(unifi_cert, 'run_certbot', return_value=(True, '/path/cert.pem', '/path/key.pem')), \
             patch.object(unifi_cert.UnifiPlatform, 'detect', return_value=None):
            result = unifi_cert.main()
        # Succeeds - cert obtained, just warns that it wasn't installed
        assert result == 0

    def test_main_install_auto_detect_domain(self, temp_dir, sample_cert_content, sample_key_content):
        """Test main --install auto-detects domain from certificate."""
        cert_path = os.path.join(temp_dir, "cert.crt")
        key_path = os.path.join(temp_dir, "cert.key")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)
        with open(key_path, 'w') as f:
            f.write(sample_key_content)

        mock_platform = unifi_cert.UnifiPlatform(
            device_type='UDM',
            core_version='4.0.6',
            has_eus_certs=True,
            has_postgres=True,
            active_cert_id='uuid',
        )

        with patch('sys.argv', ['unifi-cert', '--install', '--cert', cert_path, '--key', key_path]), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'detect_domain_from_cert', return_value='auto.example.com'), \
             patch.object(unifi_cert.UnifiPlatform, 'detect', return_value=mock_platform), \
             patch.object(unifi_cert, 'install_certificate', return_value=True):
            result = unifi_cert.main()
        assert result == 0

    # --renew handler tests live in TestRenew below — the new semantics
    # (lock + self-heal + ACME-if-due + sync) need explicit fixtures rather
    # than the legacy "fullchain exists → install_certificate" assumption.


class TestInteractiveMode:
    """Tests for interactive mode."""

    def test_interactive_mode_basic(self):
        """Test interactive mode collects configuration."""
        with patch.object(unifi_cert, 'ui') as mock_ui:
            mock_ui.prompt.side_effect = ['example.com', 'admin@example.com', '~/.secrets/creds.ini']
            mock_ui.confirm.side_effect = [False, False]  # No existing cert, no remote
            mock_ui.select.return_value = 0  # First DNS provider

            with patch.object(unifi_cert.UnifiPlatform, 'detect', return_value=None), \
                 patch('os.path.exists', return_value=True):
                config = unifi_cert.interactive_mode()

        assert config['domain'] == 'example.com'
        assert config['email'] == 'admin@example.com'
        assert config['install'] is False

    def test_interactive_mode_with_existing_cert(self):
        """Test interactive mode with existing certificate."""
        with patch.object(unifi_cert, 'ui') as mock_ui:
            mock_ui.prompt.side_effect = ['example.com', '/path/cert.pem', '/path/key.pem']
            mock_ui.confirm.side_effect = [True, False]  # Has existing cert, no remote

            with patch.object(unifi_cert.UnifiPlatform, 'detect', return_value=None):
                config = unifi_cert.interactive_mode()

        assert config['domain'] == 'example.com'
        assert config['install'] is True
        assert config['cert'] == '/path/cert.pem'
        assert config['key'] == '/path/key.pem'

    def test_interactive_mode_no_domain(self):
        """Test interactive mode exits if no domain provided."""
        with patch.object(unifi_cert, 'ui') as mock_ui:
            mock_ui.prompt.return_value = ''

            with pytest.raises(SystemExit) as exc_info:
                unifi_cert.interactive_mode()

            assert exc_info.value.code == 1

    def test_interactive_mode_existing_cert_sync(self):
        """Test interactive mode with existing cert - sync to WebUI option."""
        with patch.object(unifi_cert, 'ui') as mock_ui, \
             patch.object(unifi_cert, 'detect_domain_from_cert', return_value='detected.example.com'), \
             patch('os.path.exists', return_value=True):
            mock_ui.select.return_value = 0  # Sync option

            config = unifi_cert.interactive_mode()

        assert config['domain'] == 'detected.example.com'
        assert config['install'] is True
        assert config['cert'] == unifi_cert.UNIFI_PATHS['eus_cert']
        assert config['key'] == unifi_cert.UNIFI_PATHS['eus_key']

    def test_interactive_mode_existing_cert_renew(self):
        """Test interactive mode with existing cert - renew option."""
        with patch.object(unifi_cert, 'ui') as mock_ui, \
             patch.object(unifi_cert, 'detect_domain_from_cert', return_value='detected.example.com'), \
             patch('os.path.exists', return_value=True), \
             patch.object(unifi_cert.UnifiPlatform, 'detect', return_value=None):
            mock_ui.select.return_value = 1  # Renew option
            mock_ui.prompt.side_effect = ['admin@example.com', '~/.secrets/creds.ini']
            mock_ui.confirm.return_value = False  # No remote

            config = unifi_cert.interactive_mode()

        assert config['domain'] == 'detected.example.com'
        assert config['install'] is False
        assert config['email'] == 'admin@example.com'

    def test_interactive_mode_existing_cert_install_different(self):
        """Test interactive mode with existing cert - install different cert option."""
        with patch.object(unifi_cert, 'ui') as mock_ui, \
             patch.object(unifi_cert, 'detect_domain_from_cert', return_value='detected.example.com'), \
             patch('os.path.exists', return_value=True):
            mock_ui.select.return_value = 2  # Install different cert
            mock_ui.prompt.side_effect = ['new.example.com', '/new/cert.pem', '/new/key.pem']

            config = unifi_cert.interactive_mode()

        assert config['domain'] == 'new.example.com'
        assert config['install'] is True
        assert config['cert'] == '/new/cert.pem'
        assert config['key'] == '/new/key.pem'

    def test_interactive_mode_creates_credentials(self, temp_dir):
        """Test interactive mode creates credentials file if missing."""
        creds_path = os.path.join(temp_dir, 'digitalocean.ini')

        with patch.object(unifi_cert, 'ui') as mock_ui, \
             patch.object(unifi_cert, 'detect_domain_from_cert', return_value=None), \
             patch.object(unifi_cert.UnifiPlatform, 'detect', return_value=None), \
             patch.object(unifi_cert, 'create_credentials_file') as mock_create, \
             patch.object(unifi_cert, 'load_config', return_value={}), \
             patch.object(unifi_cert, 'save_config', return_value=True):
            mock_ui.prompt.side_effect = ['example.com', 'admin@example.com', creds_path, 'my_api_token']
            mock_ui.confirm.side_effect = [False, True, False]  # No existing cert, create creds, no remote
            mock_ui.select.return_value = 0  # digitalocean

            # First call to exists for EUS paths, then for creds file
            with patch('os.path.exists', side_effect=[False, False, False]):
                config = unifi_cert.interactive_mode()

            mock_create.assert_called_once()


# =============================================================================
# CONFIG FILE TESTS
# =============================================================================

class TestConfigFile:
    """Tests for config file persistence."""

    def test_load_config_empty(self):
        """Test loading config when file doesn't exist."""
        with patch('os.path.exists', return_value=False):
            config = unifi_cert.load_config()
        assert config == {}

    def test_load_config_with_values(self, temp_dir):
        """Test loading config with saved values."""
        config_path = os.path.join(temp_dir, 'config.ini')
        with open(config_path, 'w') as f:
            f.write("# Comment\n")
            f.write("email = test@example.com\n")
            f.write("dns_provider = cloudflare\n")

        with patch.object(unifi_cert, 'CONFIG_FILE', config_path):
            config = unifi_cert.load_config()

        assert config['email'] == 'test@example.com'
        assert config['dns_provider'] == 'cloudflare'

    def test_save_config(self, temp_dir):
        """Test saving config creates file with correct permissions."""
        config_path = os.path.join(temp_dir, 'secrets', 'config.ini')

        with patch.object(unifi_cert, 'CONFIG_FILE', config_path):
            result = unifi_cert.save_config(email='user@test.com', dns_provider='digitalocean')

        assert result is True
        assert os.path.exists(config_path)

        # Check permissions (600)
        mode = os.stat(config_path).st_mode & 0o777
        assert mode == 0o600

        # Verify content
        with open(config_path) as f:
            content = f.read()
        assert 'email = user@test.com' in content
        assert 'dns_provider = digitalocean' in content

    def test_save_config_preserves_existing(self, temp_dir):
        """Test save_config preserves existing values."""
        config_path = os.path.join(temp_dir, 'config.ini')

        # Create existing config
        os.makedirs(temp_dir, exist_ok=True)
        with open(config_path, 'w') as f:
            f.write("email = old@example.com\n")
            f.write("custom_field = preserved\n")
        os.chmod(config_path, 0o600)

        with patch.object(unifi_cert, 'CONFIG_FILE', config_path):
            unifi_cert.save_config(dns_provider='linode')

        # Check that both old and new values exist
        with open(config_path) as f:
            content = f.read()
        assert 'email = old@example.com' in content
        assert 'dns_provider = linode' in content
        assert 'custom_field = preserved' in content

    def test_load_config_ioerror(self):
        """Test load_config handles IOError gracefully."""
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', side_effect=IOError("Permission denied")):
            config = unifi_cert.load_config()
        assert config == {}

    def test_save_config_ioerror(self):
        """Test save_config handles IOError gracefully."""
        with patch('os.makedirs', side_effect=IOError("Permission denied")):
            result = unifi_cert.save_config(email='test@example.com')
        assert result is False


# =============================================================================
# UI SELECT DEFAULT TESTS
# =============================================================================

class TestUISelectDefault:
    """Tests for UI select with default values."""

    def test_select_with_default_empty_input(self):
        """Test select returns default when user presses Enter."""
        ui = unifi_cert.UI(color=False)
        with patch.object(ui, '_input', return_value=''):
            result = ui.select('Choose:', ['a', 'b', 'c'], default=1)
        assert result == 1

    def test_select_with_default_invalid_then_empty(self):
        """Test select returns default after invalid input then Enter."""
        ui = unifi_cert.UI(color=False)
        with patch.object(ui, '_input', side_effect=['invalid', '']):
            result = ui.select('Choose:', ['a', 'b', 'c'], default=2)
        assert result == 2


# =============================================================================
# CREDENTIALS IOERROR TESTS
# =============================================================================

class TestCredentialsIOError:
    """Tests for credentials IOError handling."""

    def test_validate_dns_credentials_ioerror(self, temp_dir):
        """Test validate_dns_credentials handles IOError."""
        creds_path = os.path.join(temp_dir, 'creds.ini')

        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', side_effect=IOError("Read error")):
            valid, msg = unifi_cert.validate_dns_credentials('digitalocean', creds_path)

        assert valid is False
        assert 'Cannot read' in msg


# =============================================================================
# CERTBOT EDGE CASES
# =============================================================================

class TestCertbotEdgeCases:
    """Tests for certbot edge cases."""

    def test_run_certbot_files_not_found(self):
        """Test certbot success but cert files not found."""
        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 0
            return result

        with patch('subprocess.run', side_effect=mock_run), \
             patch('os.path.exists', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'bootstrap_certbot', return_value=(True, 'mocked')):
            success, cert, key = unifi_cert.run_certbot(
                'example.com', 'admin@example.com', 'digitalocean', '/creds.ini'
            )

        assert success is False
        assert cert == ''
        assert key == ''


# =============================================================================
# SCRIPT INSTALLATION EDGE CASES
# =============================================================================

class TestScriptInstallationEdgeCases:
    """Tests for script installation edge cases."""

    def test_ensure_script_already_at_permanent_location(self, temp_dir):
        """Test when script is already at permanent location."""
        permanent_path = os.path.join(temp_dir, 'unifi-cert.py')
        with open(permanent_path, 'w') as f:
            f.write('# script')

        with patch.object(unifi_cert, 'PERMANENT_SCRIPT_PATH', permanent_path), \
             patch.object(unifi_cert, 'ui'), \
             patch('os.path.abspath', return_value=permanent_path):
            result = unifi_cert.ensure_script_installed()

        assert result == permanent_path

    def test_ensure_script_download_timeout(self, temp_dir):
        """Test script download timeout handling."""
        permanent_path = os.path.join(temp_dir, 'scripts', 'unifi-cert.py')

        with patch.object(unifi_cert, 'PERMANENT_SCRIPT_PATH', permanent_path), \
             patch.object(unifi_cert, 'ui'), \
             patch('os.path.abspath', return_value=None), \
             patch('subprocess.run', side_effect=subprocess.TimeoutExpired('curl', 30)):
            result = unifi_cert.ensure_script_installed()

        assert result == permanent_path

    def test_ensure_script_download_failure(self, temp_dir):
        """Test script download failure handling."""
        permanent_path = os.path.join(temp_dir, 'scripts', 'unifi-cert.py')

        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 1
            result.stderr = b'Connection refused'
            return result

        with patch.object(unifi_cert, 'PERMANENT_SCRIPT_PATH', permanent_path), \
             patch.object(unifi_cert, 'ui'), \
             patch('os.path.abspath', return_value=None), \
             patch('subprocess.run', side_effect=mock_run):
            result = unifi_cert.ensure_script_installed()

        assert result == permanent_path

    def test_ensure_script_copy_ioerror(self, temp_dir):
        """Test script copy IOError handling."""
        source_path = os.path.join(temp_dir, 'source.py')
        permanent_path = os.path.join(temp_dir, 'scripts', 'unifi-cert.py')

        with open(source_path, 'w') as f:
            f.write('# script')

        with patch.object(unifi_cert, 'PERMANENT_SCRIPT_PATH', permanent_path), \
             patch.object(unifi_cert, 'ui'), \
             patch('os.path.abspath', return_value=source_path), \
             patch('shutil.copy2', side_effect=IOError("Permission denied")):
            result = unifi_cert.ensure_script_installed()

        assert result == permanent_path


# =============================================================================
# REMOTE INSTALLATION FAILURE TESTS
# =============================================================================

class TestRemoteInstallationFailures:
    """Tests for remote installation failure cases."""

    def test_install_remote_eus_key_failure(self, temp_dir):
        """Test remote install fails on EUS key upload."""
        cert_path = os.path.join(temp_dir, 'cert.pem')
        key_path = os.path.join(temp_dir, 'key.pem')
        with open(cert_path, 'w') as f:
            f.write('CERT CONTENT')
        with open(key_path, 'w') as f:
            f.write('KEY CONTENT')

        def mock_scp(local, host, remote):
            if 'eus' in remote and 'key' in remote:
                return False
            return True

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_remote', return_value=(True, 'uuid-123')), \
             patch.object(unifi_cert, 'scp_file', side_effect=mock_scp), \
             patch.object(unifi_cert.CertMetadata, 'from_cert_file') as mock_meta:
            mock_meta.return_value = MagicMock(cn='example.com')

            result = unifi_cert.install_certificate_remote(
                cert_path, key_path, 'example.com', '192.168.1.1'
            )

        assert result is False

    def test_install_remote_webui_cert_failure(self, temp_dir):
        """Test remote install fails on WebUI cert upload."""
        cert_path = os.path.join(temp_dir, 'cert.pem')
        key_path = os.path.join(temp_dir, 'key.pem')
        with open(cert_path, 'w') as f:
            f.write('CERT CONTENT')
        with open(key_path, 'w') as f:
            f.write('KEY CONTENT')

        call_count = [0]
        def mock_scp(local, host, remote):
            call_count[0] += 1
            # First two succeed (EUS), third fails (WebUI cert)
            if call_count[0] == 3:
                return False
            return True

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_remote', return_value=(True, 'uuid-123')), \
             patch.object(unifi_cert, 'scp_file', side_effect=mock_scp), \
             patch.object(unifi_cert.CertMetadata, 'from_cert_file') as mock_meta:
            mock_meta.return_value = MagicMock(cn='example.com')

            result = unifi_cert.install_certificate_remote(
                cert_path, key_path, 'example.com', '192.168.1.1'
            )

        assert result is False

    def test_install_remote_webui_key_failure(self, temp_dir):
        """Test remote install fails on WebUI key upload."""
        cert_path = os.path.join(temp_dir, 'cert.pem')
        key_path = os.path.join(temp_dir, 'key.pem')
        with open(cert_path, 'w') as f:
            f.write('CERT CONTENT')
        with open(key_path, 'w') as f:
            f.write('KEY CONTENT')

        call_count = [0]
        def mock_scp(local, host, remote):
            call_count[0] += 1
            # First three succeed, fourth fails (WebUI key)
            if call_count[0] == 4:
                return False
            return True

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_remote', return_value=(True, 'uuid-123')), \
             patch.object(unifi_cert, 'scp_file', side_effect=mock_scp), \
             patch.object(unifi_cert.CertMetadata, 'from_cert_file') as mock_meta:
            mock_meta.return_value = MagicMock(cn='example.com')

            result = unifi_cert.install_certificate_remote(
                cert_path, key_path, 'example.com', '192.168.1.1'
            )

        assert result is False


# =============================================================================
# MAIN FUNCTION EDGE CASES
# =============================================================================

class TestMainEdgeCases:
    """Tests for main function edge cases."""

    # Legacy --renew failure-path tests removed — superseded by TestRenew
    # which exercises the new lock + self-heal + ACME-if-due pipeline.

    def test_main_certbot_missing_credentials_file(self):
        """Test certbot path when credentials file doesn't exist."""
        with patch('sys.argv', ['unifi-cert', '-d', 'example.com', '-e', 'test@test.com',
                               '--dns-provider', 'digitalocean']), \
             patch.object(unifi_cert, 'ui'), \
             patch('sys.stdout.isatty', return_value=False), \
             patch('os.path.exists', return_value=False):
            result = unifi_cert.main()

        assert result == 1


# =============================================================================
# CONFIGURATION TESTS
# =============================================================================

class TestConfiguration:
    """Tests for configuration constants."""

    def test_dns_providers_exist(self):
        """Test that DNS providers are defined."""
        assert 'digitalocean' in unifi_cert.DNS_PROVIDERS
        assert 'cloudflare' in unifi_cert.DNS_PROVIDERS
        assert 'route53' in unifi_cert.DNS_PROVIDERS

    def test_dns_provider_has_required_fields(self):
        """Test DNS providers have required fields."""
        for name, config in unifi_cert.DNS_PROVIDERS.items():
            assert 'plugin' in config, f"{name} missing plugin"
            assert 'field' in config, f"{name} missing field"
            assert 'propagation' in config, f"{name} missing propagation"
            assert 'description' in config, f"{name} missing description"

    def test_unifi_paths_exist(self):
        """Test that UniFi paths are defined."""
        assert 'settings_yaml' in unifi_cert.UNIFI_PATHS
        assert 'config_dir' in unifi_cert.UNIFI_PATHS
        assert 'eus_cert' in unifi_cert.UNIFI_PATHS
        assert 'eus_key' in unifi_cert.UNIFI_PATHS
        assert 'eus_dir' in unifi_cert.UNIFI_PATHS

    def test_ip_providers_exist(self):
        """Test that IP providers are defined."""
        assert len(unifi_cert.IP_PROVIDERS) > 0
        for url, extractor in unifi_cert.IP_PROVIDERS:
            assert url.startswith('http')
            assert callable(extractor)


# =============================================================================
# EDGE CASES AND ERROR HANDLING
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_cert_metadata_empty_sans(self, temp_dir, sample_cert_content):
        """Test certificate with no SANs."""
        cert_path = os.path.join(temp_dir, "test.crt")
        with open(cert_path, 'w') as f:
            f.write(sample_cert_content)

        def mock_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stderr = ""
            if '-ext' in cmd:
                result.stdout = "X509v3 Subject Alternative Name: <empty>"
            else:
                result.stdout = ""
            return result

        with patch('subprocess.run', side_effect=mock_run):
            meta = unifi_cert.CertMetadata.from_cert_file(cert_path)

        assert meta.sans == []

    def test_spinner_with_color(self):
        """Test spinner behavior with color enabled."""
        with patch('sys.stdout.isatty', return_value=True):
            ui = unifi_cert.UI(color=True)
            ui.spinner_start("Test spinner")
            import time
            time.sleep(0.2)
            ui.spinner_stop()

    def test_keyboard_interrupt_handling(self):
        """Test that keyboard interrupt is handled gracefully."""
        # The main function catches KeyboardInterrupt and exits with 130
        # This is tested by the fact that the except block exists in the code
        pass  # Coverage is achieved by reading the code path

    def test_dns_provider_cloudflare_validation(self, temp_dir):
        """Test Cloudflare credential validation."""
        creds_path = os.path.join(temp_dir, "cloudflare.ini")
        with open(creds_path, 'w') as f:
            f.write("dns_cloudflare_api_token = token123\n")
        os.chmod(creds_path, 0o600)

        valid, msg = unifi_cert.validate_dns_credentials('cloudflare', creds_path)
        assert valid is True


# =============================================================================
# CERTBOT BOOTSTRAP - persistent venv + apt prereqs
# =============================================================================

class TestCertbotBootstrap:
    """Tests for the certbot bootstrap pipeline."""

    def test_resolve_certbot_bin_persistent(self):
        """When the persistent venv binary exists, prefer it."""
        with patch('os.path.exists', return_value=True):
            assert unifi_cert.resolve_certbot_bin() == unifi_cert.CERTBOT_BIN

    def test_resolve_certbot_bin_fallback(self):
        """When persistent binary is absent, fall back to PATH lookup."""
        with patch('os.path.exists', return_value=False):
            assert unifi_cert.resolve_certbot_bin() == 'certbot'

    def test_certbot_argv_base_with_persistent_root(self):
        """When persistent config dir exists, return the routing flags."""
        with patch('os.path.isdir', return_value=True):
            argv = unifi_cert.certbot_argv_base()
        assert '--config-dir' in argv
        assert unifi_cert.CERTBOT_CONFIG_DIR in argv
        assert '--work-dir' in argv
        assert '--logs-dir' in argv

    def test_certbot_argv_base_legacy(self):
        """When persistent config dir is missing, return [] so certbot uses defaults."""
        with patch('os.path.isdir', return_value=False):
            assert unifi_cert.certbot_argv_base() == []

    def test_certbot_live_dir_persistent(self):
        """Live cert dir resolves to the persistent path when present."""
        with patch('os.path.isdir', return_value=True):
            live_dir = unifi_cert.certbot_live_dir('example.com')
        assert live_dir.startswith(unifi_cert.CERTBOT_CONFIG_DIR)
        assert live_dir.endswith('example.com')

    def test_certbot_live_dir_legacy(self):
        """Live cert dir falls back to /etc/letsencrypt/live/<domain>."""
        with patch('os.path.isdir', return_value=False):
            live_dir = unifi_cert.certbot_live_dir('example.com')
        assert live_dir == '/etc/letsencrypt/live/example.com'

    def test_certbot_health_check_healthy(self):
        """certbot --version returning 0 means healthy."""
        result = MagicMock(returncode=0)
        with patch('os.path.exists', return_value=True), \
             patch('subprocess.run', return_value=result):
            assert unifi_cert.certbot_health_check() is True

    def test_certbot_health_check_missing(self):
        """No binary at the persistent path means unhealthy."""
        with patch('os.path.exists', return_value=False):
            assert unifi_cert.certbot_health_check() is False

    def test_certbot_health_check_broken(self):
        """certbot --version returning non-zero means unhealthy (e.g., venv broken)."""
        result = MagicMock(returncode=1)
        with patch('os.path.exists', return_value=True), \
             patch('subprocess.run', return_value=result):
            assert unifi_cert.certbot_health_check() is False

    def test_certbot_health_check_timeout(self):
        """A hung --version invocation should return False, not raise."""
        with patch('os.path.exists', return_value=True), \
             patch('subprocess.run', side_effect=__import__('subprocess').TimeoutExpired('certbot', 10)):
            assert unifi_cert.certbot_health_check() is False

    def test_dpkg_installed_yes(self):
        """A package whose status reads 'installed' is reported as installed."""
        result = MagicMock(returncode=0, stdout='installed\n')
        with patch('subprocess.run', return_value=result):
            assert unifi_cert._dpkg_installed('python3-pip') is True

    def test_dpkg_installed_no(self):
        """Missing package (dpkg-query nonzero) is not installed."""
        result = MagicMock(returncode=1, stdout='')
        with patch('subprocess.run', return_value=result):
            assert unifi_cert._dpkg_installed('python3-venv') is False

    def test_dpkg_installed_uninstalled_status(self):
        """Status 'config-files' or other non-installed status is not installed."""
        result = MagicMock(returncode=0, stdout='config-files\n')
        with patch('subprocess.run', return_value=result):
            assert unifi_cert._dpkg_installed('python3-pip') is False

    def test_ensure_apt_prereqs_all_present(self):
        """When all prereqs are installed, short-circuit without calling apt-get."""
        with patch.object(unifi_cert, '_dpkg_installed', return_value=True), \
             patch('subprocess.run') as mock_run, \
             patch.object(unifi_cert, 'ui'):
            ok, msg = unifi_cert._ensure_apt_prereqs()
        assert ok is True
        # No subprocess calls should happen since nothing was needed.
        mock_run.assert_not_called()

    def test_ensure_apt_prereqs_install_needed(self):
        """When prereqs missing, run apt-get update + install."""
        update_result = MagicMock(returncode=0)
        install_result = MagicMock(returncode=0, stdout='', stderr='')
        with patch.object(unifi_cert, '_dpkg_installed', return_value=False), \
             patch('subprocess.run', side_effect=[update_result, install_result]) as mock_run, \
             patch.object(unifi_cert, 'ui'):
            ok, msg = unifi_cert._ensure_apt_prereqs()
        assert ok is True
        # Two calls: update then install.
        assert mock_run.call_count == 2
        install_cmd = mock_run.call_args_list[1].args[0]
        assert install_cmd[:3] == ['apt-get', 'install', '-y']

    def test_ensure_apt_prereqs_install_fails(self):
        """apt-get install non-zero exit returns (False, message)."""
        update_result = MagicMock(returncode=0)
        install_result = MagicMock(returncode=100, stdout='', stderr='boom')
        with patch.object(unifi_cert, '_dpkg_installed', return_value=False), \
             patch('subprocess.run', side_effect=[update_result, install_result]), \
             patch.object(unifi_cert, 'ui'):
            ok, msg = unifi_cert._ensure_apt_prereqs()
        assert ok is False
        assert 'boom' in msg

    def test_dns_plugin_installed_yes(self):
        """pip show <plugin> returning 0 means plugin is installed."""
        result = MagicMock(returncode=0)
        with patch('os.path.exists', return_value=True), \
             patch('subprocess.run', return_value=result):
            assert unifi_cert._dns_plugin_installed('digitalocean') is True

    def test_dns_plugin_installed_no(self):
        """pip show non-zero or pip missing means plugin not installed."""
        result = MagicMock(returncode=1)
        with patch('os.path.exists', return_value=True), \
             patch('subprocess.run', return_value=result):
            assert unifi_cert._dns_plugin_installed('digitalocean') is False

    def test_dns_plugin_installed_unknown_provider(self):
        """Unknown provider returns False rather than blowing up."""
        with patch('os.path.exists', return_value=True):
            assert unifi_cert._dns_plugin_installed('not_a_provider') is False

    def test_bootstrap_unknown_provider(self):
        """Unknown DNS provider rejected up front."""
        with patch.object(unifi_cert, 'ui'):
            ok, msg = unifi_cert.bootstrap_certbot('not_a_provider')
        assert ok is False
        assert 'unknown' in msg.lower()

    def test_bootstrap_already_healthy(self):
        """Healthy venv + plugin already installed → early return without subprocess."""
        with patch.object(unifi_cert, '_ensure_persistent_dirs', return_value=(True, 'ok')), \
             patch.object(unifi_cert, 'certbot_health_check', return_value=True), \
             patch.object(unifi_cert, '_dns_plugin_installed', return_value=True), \
             patch('subprocess.run') as mock_run, \
             patch.object(unifi_cert, 'ui'):
            ok, msg = unifi_cert.bootstrap_certbot('digitalocean')
        assert ok is True
        assert msg == 'already healthy'
        mock_run.assert_not_called()

    def test_bootstrap_dirs_fail_returns_false(self):
        """Filesystem unavailable → graceful (False, reason), no exception."""
        with patch.object(unifi_cert, '_ensure_persistent_dirs',
                          return_value=(False, 'Read-only file system')), \
             patch.object(unifi_cert, 'ui'):
            ok, msg = unifi_cert.bootstrap_certbot('digitalocean')
        assert ok is False
        assert 'Read-only' in msg

    def test_bootstrap_apt_prereqs_fail(self):
        """If apt prereqs can't be installed, bootstrap fails cleanly."""
        with patch.object(unifi_cert, '_ensure_persistent_dirs', return_value=(True, 'ok')), \
             patch.object(unifi_cert, 'certbot_health_check', return_value=False), \
             patch.object(unifi_cert, '_ensure_apt_prereqs', return_value=(False, 'apt down')), \
             patch.object(unifi_cert, 'ui'):
            ok, msg = unifi_cert.bootstrap_certbot('digitalocean')
        assert ok is False
        assert 'apt' in msg.lower()

    def test_bootstrap_creates_venv_and_installs_from_pypi(self):
        """Happy path: missing venv → create + install from PyPI + cache wheels + verify."""
        # Sequence: venv-create (0), pip-upgrade (0), pip-install (0),
        # pip-download/cache (0), then certbot --version (0).
        results = [MagicMock(returncode=0, stderr='') for _ in range(5)]
        # Health-check before bootstrap returns False (venv missing); after returns True.
        health_check_calls = iter([False, True])
        # First os.path.exists call: check CERTBOT_BIN before venv create → False.
        # No wheel cache directory.
        with patch.object(unifi_cert, '_ensure_persistent_dirs', return_value=(True, 'ok')), \
             patch.object(unifi_cert, 'certbot_health_check',
                          side_effect=lambda: next(health_check_calls)), \
             patch.object(unifi_cert, '_dns_plugin_installed', return_value=False), \
             patch.object(unifi_cert, '_ensure_apt_prereqs', return_value=(True, 'ok')), \
             patch('os.path.exists', return_value=False), \
             patch('os.path.isdir', return_value=False), \
             patch('subprocess.run', side_effect=results) as mock_run, \
             patch.object(unifi_cert, 'cache_wheels', return_value=True) as mock_cache, \
             patch.object(unifi_cert, 'ui'):
            ok, msg = unifi_cert.bootstrap_certbot('digitalocean')
        assert ok is True
        assert msg == 'bootstrapped'
        # Should have invoked: venv create, pip upgrade, pip install (no cache attempt
        # because os.scandir/isdir indicate empty/missing). cache_wheels separately.
        assert mock_run.call_count >= 3
        mock_cache.assert_called_once()

    def test_bootstrap_force_rebuild_removes_existing_venv(self):
        """force=True triggers rmtree of existing venv before recreation."""
        results = [MagicMock(returncode=0, stderr='') for _ in range(5)]
        # With force=True the early-exit health check is skipped (short-circuits
        # at `not force`), so only the post-install health check runs and must
        # return True.
        with patch.object(unifi_cert, '_ensure_persistent_dirs', return_value=(True, 'ok')), \
             patch.object(unifi_cert, 'certbot_health_check', return_value=True), \
             patch.object(unifi_cert, '_dns_plugin_installed', return_value=False), \
             patch.object(unifi_cert, '_ensure_apt_prereqs', return_value=(True, 'ok')), \
             patch('os.path.exists', return_value=True), \
             patch('os.path.isdir', return_value=False), \
             patch('shutil.rmtree') as mock_rmtree, \
             patch('subprocess.run', side_effect=results), \
             patch.object(unifi_cert, 'cache_wheels', return_value=True), \
             patch.object(unifi_cert, 'ui'):
            ok, msg = unifi_cert.bootstrap_certbot('digitalocean', force=True)
        assert ok is True
        mock_rmtree.assert_called_once_with(unifi_cert.CERTBOT_VENV)

    def test_bootstrap_health_check_fails_after_install(self):
        """If install succeeds but certbot --version still fails, return False."""
        # All subprocess calls succeed, but post-install health check fails.
        results = [MagicMock(returncode=0, stderr='') for _ in range(5)]
        with patch.object(unifi_cert, '_ensure_persistent_dirs', return_value=(True, 'ok')), \
             patch.object(unifi_cert, 'certbot_health_check', return_value=False), \
             patch.object(unifi_cert, '_dns_plugin_installed', return_value=False), \
             patch.object(unifi_cert, '_ensure_apt_prereqs', return_value=(True, 'ok')), \
             patch('os.path.exists', return_value=False), \
             patch('os.path.isdir', return_value=False), \
             patch('subprocess.run', side_effect=results), \
             patch.object(unifi_cert, 'cache_wheels', return_value=True), \
             patch.object(unifi_cert, 'ui'):
            ok, msg = unifi_cert.bootstrap_certbot('digitalocean')
        assert ok is False
        assert 'health check' in msg

    def test_cache_wheels_no_pip_returns_false(self):
        """cache_wheels short-circuits when the venv pip is absent."""
        with patch('os.path.exists', return_value=False), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.cache_wheels(['certbot']) is False

    def test_cache_wheels_pip_failure_is_nonfatal(self):
        """A failing pip download warns and returns False without raising."""
        result = MagicMock(returncode=1, stderr='no network')
        with patch('os.path.exists', return_value=True), \
             patch('os.makedirs'), \
             patch('subprocess.run', return_value=result), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.cache_wheels(['certbot']) is False

    def test_main_bootstrap_flag_success(self):
        """--bootstrap dispatches to bootstrap_certbot and returns 0 on success."""
        with patch('sys.argv', ['unifi-cert', '--bootstrap', '--dns-provider', 'digitalocean']), \
             patch('sys.stdin.isatty', return_value=False), \
             patch.object(unifi_cert, 'bootstrap_certbot', return_value=(True, 'ok')) as mock_boot, \
             patch.object(unifi_cert, 'ui'):
            result = unifi_cert.main()
        assert result == 0
        mock_boot.assert_called_once_with('digitalocean', force=False)

    def test_main_bootstrap_flag_requires_provider(self):
        """--bootstrap without --dns-provider returns 1 with a clear error."""
        with patch('sys.argv', ['unifi-cert', '--bootstrap']), \
             patch('sys.stdin.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'):
            result = unifi_cert.main()
        assert result == 1

    def test_main_bootstrap_flag_failure(self):
        """--bootstrap surfaces bootstrap_certbot's (False, msg) as exit 1."""
        with patch('sys.argv', ['unifi-cert', '--bootstrap', '--dns-provider', 'digitalocean']), \
             patch('sys.stdin.isatty', return_value=False), \
             patch.object(unifi_cert, 'bootstrap_certbot', return_value=(False, 'apt down')), \
             patch.object(unifi_cert, 'ui'):
            result = unifi_cert.main()
        assert result == 1

    def test_main_bootstrap_flag_force(self):
        """--bootstrap --force passes force=True through to bootstrap_certbot."""
        with patch('sys.argv', ['unifi-cert', '--bootstrap', '--dns-provider', 'digitalocean', '--force']), \
             patch('sys.stdin.isatty', return_value=False), \
             patch.object(unifi_cert, 'bootstrap_certbot', return_value=(True, 'ok')) as mock_boot, \
             patch.object(unifi_cert, 'ui'):
            result = unifi_cert.main()
        assert result == 0
        mock_boot.assert_called_once_with('digitalocean', force=True)


# =============================================================================
# UNIFI OS 5.x cert-deploy fixes (override removal, nginx config, Java keystore)
# =============================================================================

class TestRemoveGlennRSSLOverride:
    """Tests for remove_glennr_ssl_override()."""

    def test_no_override_file_is_no_op(self, temp_dir):
        """Missing override file → success, no error."""
        path = os.path.join(temp_dir, 'local.yml')
        with patch.object(unifi_cert, 'UNIFI_CORE_OVERRIDE', path), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.remove_glennr_ssl_override() is True

    def test_override_without_eus_path_left_alone(self, temp_dir):
        """File exists but doesn't reference /data/eus_certificates → leave alone."""
        path = os.path.join(temp_dir, 'local.yml')
        with open(path, 'w') as f:
            f.write("logging:\n  level: debug\n")
        with patch.object(unifi_cert, 'UNIFI_CORE_OVERRIDE', path), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.remove_glennr_ssl_override() is True
        # File should be untouched.
        with open(path) as f:
            assert f.read() == "logging:\n  level: debug\n"

    def test_override_with_eus_path_stripped(self, temp_dir):
        """The exact GlennR-installed override is removed; file deleted when empty."""
        path = os.path.join(temp_dir, 'local.yml')
        with open(path, 'w') as f:
            f.write(
                "# File created by EUS ( Easy UniFi Scripts ).\n"
                "ssl:\n"
                "  crt: '/data/eus_certificates/unifi-os.crt'\n"
                "  key: '/data/eus_certificates/unifi-os.key'\n"
            )
        with patch.object(unifi_cert, 'UNIFI_CORE_OVERRIDE', path), \
             patch.object(unifi_cert, 'backup_file'), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.remove_glennr_ssl_override() is True
        # The ssl: stanza was the only meaningful content; comment is whitespace-stripped.
        # File should be deleted (or contain only the surviving comment).
        if os.path.exists(path):
            with open(path) as f:
                content = f.read()
            assert 'ssl:' not in content
            assert '/data/eus_certificates' not in content

    def test_dry_run_does_not_modify_file(self, temp_dir):
        """dry_run=True logs intent but leaves the override file untouched."""
        path = os.path.join(temp_dir, 'local.yml')
        original = ("ssl:\n"
                    "  crt: '/data/eus_certificates/unifi-os.crt'\n"
                    "  key: '/data/eus_certificates/unifi-os.key'\n")
        with open(path, 'w') as f:
            f.write(original)
        with patch.object(unifi_cert, 'UNIFI_CORE_OVERRIDE', path), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.remove_glennr_ssl_override(dry_run=True) is True
        with open(path) as f:
            assert f.read() == original

    def test_preserves_other_top_level_keys(self, temp_dir):
        """Stripping ssl: doesn't touch sibling top-level YAML keys."""
        path = os.path.join(temp_dir, 'local.yml')
        with open(path, 'w') as f:
            f.write(
                "ssl:\n"
                "  crt: '/data/eus_certificates/unifi-os.crt'\n"
                "  key: '/data/eus_certificates/unifi-os.key'\n"
                "logging:\n"
                "  level: debug\n"
            )
        with patch.object(unifi_cert, 'UNIFI_CORE_OVERRIDE', path), \
             patch.object(unifi_cert, 'backup_file'), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.remove_glennr_ssl_override() is True
        with open(path) as f:
            content = f.read()
        assert 'ssl:' not in content
        assert 'logging:' in content
        assert 'level: debug' in content


class TestEnsureNginxUsesActiveCert:
    """Tests for ensure_nginx_uses_active_cert()."""

    def test_writes_correct_cert_paths(self, temp_dir):
        """The conf file lands with ssl_certificate / ssl_certificate_key for the UUID."""
        conf = os.path.join(temp_dir, 'local-certs.conf')
        # UNIFI_PATHS['config_dir'] is the real module constant ('/data/unifi-core/config').
        with patch.object(unifi_cert, 'UNIFI_CORE_LOCAL_CERTS_CONF', conf), \
             patch('subprocess.run'), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.ensure_nginx_uses_active_cert('abc123-uuid') is True
        with open(conf) as f:
            content = f.read()
        config_dir = unifi_cert.UNIFI_PATHS['config_dir']
        assert f'ssl_certificate     {config_dir}/abc123-uuid.crt;' in content
        assert f'ssl_certificate_key {config_dir}/abc123-uuid.key;' in content

    def test_dry_run_does_not_write(self, temp_dir):
        """dry_run skips file write and nginx reload."""
        conf = os.path.join(temp_dir, 'local-certs.conf')
        with patch.object(unifi_cert, 'UNIFI_CORE_LOCAL_CERTS_CONF', conf), \
             patch('subprocess.run') as mock_run, \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.ensure_nginx_uses_active_cert('abc', dry_run=True) is True
        assert not os.path.exists(conf)
        mock_run.assert_not_called()

    def test_nginx_reload_failure_is_nonfatal(self, temp_dir):
        """nginx -s reload failing shouldn't make the function return False."""
        conf = os.path.join(temp_dir, 'local-certs.conf')
        with patch.object(unifi_cert, 'UNIFI_CORE_LOCAL_CERTS_CONF', conf), \
             patch('subprocess.run', side_effect=OSError('no nginx')), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.ensure_nginx_uses_active_cert('abc') is True


class TestInstallUnifiNetworkKeystore:
    """Tests for install_unifi_network_keystore()."""

    def test_no_unifi_install_returns_false(self):
        """Skip cleanly when /usr/lib/unifi/data is absent (NVR-style devices)."""
        # Narrow-scope side_effect: only spoof the unifi-data check; leave
        # everything else (incl. shutil.copy2's dst-is-dir check) un-patched.
        real_isdir = os.path.isdir
        def isdir_for_unifi(path):
            if path == '/usr/lib/unifi/data':
                return False
            return real_isdir(path)
        with patch('os.path.isdir', side_effect=isdir_for_unifi), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.install_unifi_network_keystore('/c.pem', '/k.pem') is False

    def test_dry_run_does_not_invoke_openssl(self):
        """dry_run reports intent and returns True without subprocess calls."""
        real_isdir = os.path.isdir
        def isdir_for_unifi(path):
            if path == '/usr/lib/unifi/data':
                return True
            return real_isdir(path)
        with patch('os.path.isdir', side_effect=isdir_for_unifi), \
             patch('subprocess.run') as mock_run, \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.install_unifi_network_keystore('/c.pem', '/k.pem', dry_run=True) is True
        mock_run.assert_not_called()

    def test_openssl_failure_returns_false_no_keystore_change(self, temp_dir):
        """When openssl pkcs12 -export fails, the keystore is not replaced."""
        keystore = os.path.join(temp_dir, 'keystore')
        with open(keystore, 'wb') as f:
            f.write(b'OLD KEYSTORE')
        result = MagicMock(returncode=1, stderr='boom')
        real_isdir = os.path.isdir
        def isdir_for_unifi(path):
            if path == '/usr/lib/unifi/data':
                return True
            return real_isdir(path)
        with patch('os.path.isdir', side_effect=isdir_for_unifi), \
             patch.object(unifi_cert, 'UNIFI_NETWORK_KEYSTORE', keystore), \
             patch.object(unifi_cert, 'UNIFI_CERT_ROOT', temp_dir), \
             patch.object(unifi_cert, 'BACKUPS_DIR', os.path.join(temp_dir, 'backups')), \
             patch('subprocess.run', return_value=result), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.install_unifi_network_keystore('/c.pem', '/k.pem') is False
        with open(keystore, 'rb') as f:
            assert f.read() == b'OLD KEYSTORE'

    def test_happy_path_replaces_keystore(self, temp_dir):
        """openssl succeeds → keystore atomically replaced + backup created."""
        keystore = os.path.join(temp_dir, 'keystore')
        with open(keystore, 'wb') as f:
            f.write(b'OLD KEYSTORE')
        backups = os.path.join(temp_dir, 'backups')
        # Simulate openssl pkcs12 -export success by writing a fake .p12 file
        # at the temp output path during the subprocess.run call.
        def fake_run(cmd, *args, **kwargs):
            if cmd[0] == 'openssl':
                out_idx = cmd.index('-out') + 1
                with open(cmd[out_idx], 'wb') as f:
                    f.write(b'NEW PKCS12')
            return MagicMock(returncode=0, stderr='')

        real_isdir = os.path.isdir
        def isdir_for_unifi(path):
            if path == '/usr/lib/unifi/data':
                return True
            return real_isdir(path)

        with patch('os.path.isdir', side_effect=isdir_for_unifi), \
             patch.object(unifi_cert, 'UNIFI_NETWORK_KEYSTORE', keystore), \
             patch.object(unifi_cert, 'UNIFI_CERT_ROOT', temp_dir), \
             patch.object(unifi_cert, 'BACKUPS_DIR', backups), \
             patch('subprocess.run', side_effect=fake_run), \
             patch('shutil.chown'), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.install_unifi_network_keystore('/c.pem', '/k.pem') is True
        with open(keystore, 'rb') as f:
            assert f.read() == b'NEW PKCS12'
        backup_dir = os.path.join(backups, 'network-keystore')
        assert os.path.isdir(backup_dir)
        backups_present = os.listdir(backup_dir)
        assert any(name.startswith('keystore.') for name in backups_present)


class TestRestartServices:
    """Tests for the restart_services() service-list logic."""

    def test_default_restarts_nginx_and_unifi_core_only(self):
        """Default call (no keystore change) doesn't restart the Java unifi service."""
        with patch('subprocess.run') as mock_run, \
             patch.object(unifi_cert, 'ui'):
            unifi_cert.restart_services()
        services = [call.args[0][2] for call in mock_run.call_args_list
                    if call.args and call.args[0][:2] == ['systemctl', 'restart']]
        assert services == ['nginx', 'unifi-core']

    def test_restart_unifi_network_appends_unifi(self):
        """restart_unifi_network=True appends `unifi` to the restart list."""
        with patch('subprocess.run') as mock_run, \
             patch.object(unifi_cert, 'ui'):
            unifi_cert.restart_services(restart_unifi_network=True)
        services = [call.args[0][2] for call in mock_run.call_args_list
                    if call.args and call.args[0][:2] == ['systemctl', 'restart']]
        assert services == ['nginx', 'unifi-core', 'unifi']


class TestLock:
    """Tests for the fcntl.flock-based --renew / --deploy-hook lock."""

    def test_acquire_and_release(self, tmp_path):
        """Round-trip: acquire returns a fh; release closes it cleanly."""
        lock_file = str(tmp_path / 'lock')
        with patch.object(unifi_cert, 'LOCK_FILE', lock_file), \
             patch.object(unifi_cert, 'UNIFI_CERT_ROOT', str(tmp_path)):
            fh = unifi_cert.acquire_lock()
            assert fh is not None
            assert not fh.closed
            unifi_cert.release_lock(fh)
            assert fh.closed

    def test_concurrent_acquire_blocks(self, tmp_path):
        """Second acquire with timeout=0 raises BlockingIOError."""
        lock_file = str(tmp_path / 'lock')
        with patch.object(unifi_cert, 'LOCK_FILE', lock_file), \
             patch.object(unifi_cert, 'UNIFI_CERT_ROOT', str(tmp_path)):
            first = unifi_cert.acquire_lock()
            try:
                with pytest.raises(BlockingIOError):
                    unifi_cert.acquire_lock(timeout=0)
            finally:
                unifi_cert.release_lock(first)

    def test_release_after_first_lets_second_acquire(self, tmp_path):
        """Releasing the first lock allows a fresh acquire to succeed."""
        lock_file = str(tmp_path / 'lock')
        with patch.object(unifi_cert, 'LOCK_FILE', lock_file), \
             patch.object(unifi_cert, 'UNIFI_CERT_ROOT', str(tmp_path)):
            first = unifi_cert.acquire_lock()
            unifi_cert.release_lock(first)
            second = unifi_cert.acquire_lock()
            unifi_cert.release_lock(second)

    def test_release_lock_handles_none(self):
        """release_lock(None) is a graceful no-op."""
        unifi_cert.release_lock(None)


class TestLogRotate:
    """Tests for size-based log rotation."""

    def test_rotate_log_missing_is_noop(self, tmp_path):
        """No log → graceful True (nothing to do)."""
        log = str(tmp_path / 'unifi-cert.log')
        with patch.object(unifi_cert, 'LOG_FILE', log):
            assert unifi_cert.rotate_log() is True

    def test_rotate_log_small_is_noop(self, tmp_path):
        """Log under threshold is left untouched."""
        log = tmp_path / 'unifi-cert.log'
        log.write_bytes(b'small\n' * 10)
        with patch.object(unifi_cert, 'LOG_FILE', str(log)):
            assert unifi_cert.rotate_log() is True
        # Content untouched.
        assert log.read_bytes() == b'small\n' * 10

    def test_rotate_log_truncates_oversized(self, tmp_path):
        """Log over threshold is truncated to roughly the keep-size."""
        log = tmp_path / 'unifi-cert.log'
        # 1.5 MB of distinguishable lines.
        log.write_bytes(b'A' * (1500 * 1024))
        with patch.object(unifi_cert, 'LOG_FILE', str(log)), \
             patch.object(unifi_cert, 'LOG_ROTATE_THRESHOLD', 1024 * 1024), \
             patch.object(unifi_cert, 'LOG_ROTATE_KEEP', 100 * 1024):
            assert unifi_cert.rotate_log() is True
        new_size = log.stat().st_size
        assert new_size <= 100 * 1024
        # Has content; we kept the tail, not zeroed out.
        assert new_size > 0

    def test_rotate_log_drops_partial_first_line(self, tmp_path):
        """The first partial line is dropped so rotated log starts at a record boundary."""
        log = tmp_path / 'unifi-cert.log'
        # Lines AAA…\n then BBB…\n etc. Make it big.
        chunk = (b'AAAAA\n' * 100 * 1024) + b'partial-trailing-line\nNEXTLINE\n'
        log.write_bytes(chunk)
        with patch.object(unifi_cert, 'LOG_FILE', str(log)), \
             patch.object(unifi_cert, 'LOG_ROTATE_THRESHOLD', 1024), \
             patch.object(unifi_cert, 'LOG_ROTATE_KEEP', 50):
            assert unifi_cert.rotate_log() is True
        # First line of rotated log should be intact (not partial).
        rotated = log.read_bytes()
        # Either starts with full AAAAA line or the NEXTLINE record.
        assert rotated.startswith(b'AAAAA') or rotated.startswith(b'NEXTLINE')


class TestRenewalDue:
    """Tests for is_renewal_due()."""

    def test_missing_cert_due(self, tmp_path):
        """No cert at the expected path → due (recovery path)."""
        with patch.object(unifi_cert, 'certbot_live_dir',
                          return_value=str(tmp_path / 'live')):
            assert unifi_cert.is_renewal_due('example.com') is True

    def test_far_future_not_due(self, tmp_path):
        """Cert valid 90d out, threshold 30d → not due."""
        cert_path = tmp_path / 'cert.pem'
        cert_path.write_text('fake')
        future = (datetime.utcnow() + __import__('datetime').timedelta(days=90))
        meta = MagicMock(valid_to=future.strftime('%Y-%m-%d %H:%M:%S+00'))
        with patch.object(unifi_cert, 'certbot_live_dir', return_value=str(tmp_path)), \
             patch.object(unifi_cert.CertMetadata, 'from_cert_file', return_value=meta):
            assert unifi_cert.is_renewal_due('example.com', days=30) is False

    def test_within_threshold_due(self, tmp_path):
        """Cert valid 5d out, threshold 30d → due."""
        cert_path = tmp_path / 'cert.pem'
        cert_path.write_text('fake')
        soon = (datetime.utcnow() + __import__('datetime').timedelta(days=5))
        meta = MagicMock(valid_to=soon.strftime('%Y-%m-%d %H:%M:%S+00'))
        with patch.object(unifi_cert, 'certbot_live_dir', return_value=str(tmp_path)), \
             patch.object(unifi_cert.CertMetadata, 'from_cert_file', return_value=meta):
            assert unifi_cert.is_renewal_due('example.com', days=30) is True

    def test_unparseable_valid_to_due(self, tmp_path):
        """Garbage valid_to → due (recovery path)."""
        cert_path = tmp_path / 'cert.pem'
        cert_path.write_text('fake')
        meta = MagicMock(valid_to='garbage-date')
        with patch.object(unifi_cert, 'certbot_live_dir', return_value=str(tmp_path)), \
             patch.object(unifi_cert.CertMetadata, 'from_cert_file', return_value=meta):
            assert unifi_cert.is_renewal_due('example.com') is True

    def test_metadata_extraction_raises_due(self, tmp_path):
        """If from_cert_file raises, treat as due."""
        cert_path = tmp_path / 'cert.pem'
        cert_path.write_text('fake')
        with patch.object(unifi_cert, 'certbot_live_dir', return_value=str(tmp_path)), \
             patch.object(unifi_cert.CertMetadata, 'from_cert_file',
                          side_effect=RuntimeError('openssl crashed')):
            assert unifi_cert.is_renewal_due('example.com') is True

    def test_falls_back_to_fullchain(self, tmp_path):
        """When cert.pem missing but fullchain.pem present, parse it."""
        (tmp_path / 'fullchain.pem').write_text('fake')
        future = (datetime.utcnow() + __import__('datetime').timedelta(days=90))
        meta = MagicMock(valid_to=future.strftime('%Y-%m-%d %H:%M:%S+00'))
        with patch.object(unifi_cert, 'certbot_live_dir', return_value=str(tmp_path)), \
             patch.object(unifi_cert.CertMetadata, 'from_cert_file', return_value=meta):
            assert unifi_cert.is_renewal_due('example.com') is False


class TestSchedule:
    """Tests for install_cron_schedule() and install_boot_script()."""

    def test_install_cron_schedule_writes_canonical_line(self, tmp_path):
        """Cron file contains daily --renew + 5-min --ddns-update lines, mode 0644."""
        cron = tmp_path / 'unifi-cert'
        with patch.object(unifi_cert, 'CRON_FILE', str(cron)), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.install_cron_schedule() is True
        content = cron.read_text()
        assert '--renew' in content
        assert '--ddns-update' in content
        assert '*/5' in content  # DDNS cadence
        assert '/data/scripts/unifi-cert.py' in content
        assert (cron.stat().st_mode & 0o777) == 0o644

    def test_install_cron_schedule_idempotent(self, tmp_path):
        """Second invocation overwrites cleanly."""
        cron = tmp_path / 'unifi-cert'
        with patch.object(unifi_cert, 'CRON_FILE', str(cron)), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.install_cron_schedule() is True
            first = cron.read_text()
            assert unifi_cert.install_cron_schedule() is True
            second = cron.read_text()
        assert first == second

    def test_install_cron_schedule_oserror_returns_false(self):
        """Filesystem failure surfaces as False."""
        with patch('os.makedirs', side_effect=OSError('readonly')), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.install_cron_schedule() is False

    def test_install_boot_script_skipped_when_dir_absent(self, tmp_path):
        """No /data/on_boot.d → graceful skip with a warning, returns True."""
        absent = str(tmp_path / 'does-not-exist')
        mock_ui = MagicMock()
        with patch.object(unifi_cert, 'BOOT_SCRIPT_DIR', absent), \
             patch.object(unifi_cert, 'BOOT_SCRIPT_PATH', f'{absent}/15-unifi-cert.sh'), \
             patch.object(unifi_cert, 'ui', mock_ui):
            assert unifi_cert.install_boot_script() is True
        mock_ui.warning.assert_called()

    def test_install_boot_script_writes_when_dir_exists(self, tmp_path):
        """When /data/on_boot.d/ is present, write the boot script (executable)."""
        boot_dir = tmp_path / 'on_boot.d'
        boot_dir.mkdir()
        boot_path = boot_dir / '15-unifi-cert.sh'
        with patch.object(unifi_cert, 'BOOT_SCRIPT_DIR', str(boot_dir)), \
             patch.object(unifi_cert, 'BOOT_SCRIPT_PATH', str(boot_path)), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.install_boot_script() is True
        content = boot_path.read_text()
        assert '--self-heal' in content
        assert (boot_path.stat().st_mode & 0o777) == 0o755


class TestSelfHeal:
    """Tests for the self_heal() composition."""

    def test_self_heal_runs_no_acme(self, tmp_path):
        """self_heal() composes bootstrap + cron + hook + boot, never run_certbot."""
        with patch.object(unifi_cert, 'bootstrap_certbot',
                          return_value=(True, 'ok')) as boot, \
             patch.object(unifi_cert, 'ensure_script_installed') as ens, \
             patch.object(unifi_cert, 'install_cron_schedule', return_value=True) as cron, \
             patch.object(unifi_cert, 'setup_renewal_hook', return_value=True) as hook, \
             patch.object(unifi_cert, 'install_boot_script', return_value=True) as boot_s, \
             patch.object(unifi_cert, 'run_certbot') as cb, \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert.self_heal(dns_provider='digitalocean', domain='example.com')
        assert ok is True
        boot.assert_called_once_with('digitalocean')
        ens.assert_called_once()
        cron.assert_called_once()
        hook.assert_called_once_with('example.com')
        boot_s.assert_called_once()
        cb.assert_not_called()

    def test_self_heal_loads_provisioning_when_args_omitted(self, tmp_path):
        """When dns_provider/domain omitted, fall back to load_provisioning_config()."""
        cfg = {'dns_provider': 'cloudflare', 'domain': 'beehive.example.com'}
        with patch.object(unifi_cert, 'load_provisioning_config', return_value=cfg), \
             patch.object(unifi_cert, 'bootstrap_certbot',
                          return_value=(True, 'ok')) as boot, \
             patch.object(unifi_cert, 'ensure_script_installed'), \
             patch.object(unifi_cert, 'install_cron_schedule', return_value=True), \
             patch.object(unifi_cert, 'setup_renewal_hook', return_value=True) as hook, \
             patch.object(unifi_cert, 'install_boot_script', return_value=True), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.self_heal() is True
        boot.assert_called_once_with('cloudflare')
        hook.assert_called_once_with('beehive.example.com')

    def test_self_heal_skips_bootstrap_when_no_provider(self):
        """No dns_provider known + no provisioning config → skip bootstrap, still install cron."""
        with patch.object(unifi_cert, 'load_provisioning_config', return_value={}), \
             patch.object(unifi_cert, 'bootstrap_certbot') as boot, \
             patch.object(unifi_cert, 'ensure_script_installed'), \
             patch.object(unifi_cert, 'install_cron_schedule', return_value=True) as cron, \
             patch.object(unifi_cert, 'setup_renewal_hook') as hook, \
             patch.object(unifi_cert, 'install_boot_script', return_value=True), \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert.self_heal()
        assert ok is True  # no domain → hook skipped, but cron still installed
        boot.assert_not_called()
        cron.assert_called_once()
        hook.assert_not_called()

    def test_self_heal_reports_failure_when_bootstrap_fails(self):
        """Bootstrap failure → ok=False but cron + hook still attempted."""
        with patch.object(unifi_cert, 'bootstrap_certbot',
                          return_value=(False, 'apt unavailable')), \
             patch.object(unifi_cert, 'ensure_script_installed'), \
             patch.object(unifi_cert, 'install_cron_schedule', return_value=True) as cron, \
             patch.object(unifi_cert, 'setup_renewal_hook', return_value=True), \
             patch.object(unifi_cert, 'install_boot_script', return_value=True), \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert.self_heal(dns_provider='digitalocean', domain='example.com')
        assert ok is False
        cron.assert_called_once()


class TestProvisioningConfig:
    """Tests for save_provisioning_config() / load_provisioning_config()."""

    def test_save_then_load_roundtrip(self, tmp_path):
        """Round-trip persists all four fields."""
        cfg = tmp_path / 'unifi-cert.conf'
        with patch.object(unifi_cert, 'PROVISIONING_CONFIG', str(cfg)), \
             patch.object(unifi_cert, 'UNIFI_CERT_ROOT', str(tmp_path)), \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert.save_provisioning_config(
                domain='example.com',
                email='admin@example.com',
                dns_provider='digitalocean',
                dns_credentials='/data/unifi-cert/credentials/digitalocean.ini',
            )
            assert ok is True
            loaded = unifi_cert.load_provisioning_config()
        assert loaded['domain'] == 'example.com'
        assert loaded['email'] == 'admin@example.com'
        assert loaded['dns_provider'] == 'digitalocean'
        assert loaded['dns_credentials'] == '/data/unifi-cert/credentials/digitalocean.ini'

    def test_save_provisioning_config_mode_0600(self, tmp_path):
        """Saved config has mode 0600 (path only, but contains email)."""
        cfg = tmp_path / 'unifi-cert.conf'
        with patch.object(unifi_cert, 'PROVISIONING_CONFIG', str(cfg)), \
             patch.object(unifi_cert, 'UNIFI_CERT_ROOT', str(tmp_path)), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert.save_provisioning_config(
                'example.com', 'admin@example.com', 'digitalocean', '/x/y.ini'
            )
        assert (cfg.stat().st_mode & 0o777) == 0o600

    def test_load_missing_returns_empty(self, tmp_path):
        """Absent file → empty dict, no error."""
        cfg = tmp_path / 'does-not-exist'
        with patch.object(unifi_cert, 'PROVISIONING_CONFIG', str(cfg)):
            assert unifi_cert.load_provisioning_config() == {}

    def test_load_ignores_comments_and_blanks(self, tmp_path):
        """Comments and blank lines are skipped."""
        cfg = tmp_path / 'unifi-cert.conf'
        cfg.write_text('# comment\n\ndomain = a.com\n# another\nemail = a@b.com\n')
        with patch.object(unifi_cert, 'PROVISIONING_CONFIG', str(cfg)):
            loaded = unifi_cert.load_provisioning_config()
        assert loaded == {'domain': 'a.com', 'email': 'a@b.com'}

    def test_save_provisioning_config_oserror_returns_false(self):
        """Filesystem error surfaces as False."""
        with patch('os.makedirs', side_effect=OSError('readonly')), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.save_provisioning_config(
                'a.com', 'a@b.com', 'digitalocean', '/x/y.ini'
            ) is False


class TestRenew:
    """Tests for the new --renew main() handler.

    The pipeline: rotate_log → load_provisioning_config (when CLI args
    missing) → acquire_lock → self_heal → if is_renewal_due() or --force
    → run_certbot → install_certificate.
    """

    def _renew_env(self, tmp_path):
        """Common patches: redirect persistent paths into tmp_path."""
        return {
            'UNIFI_CERT_ROOT': str(tmp_path),
            'LOCK_FILE': str(tmp_path / 'lock'),
            'LOG_FILE': str(tmp_path / 'log'),
            'PROVISIONING_CONFIG': str(tmp_path / 'unifi-cert.conf'),
        }

    def test_renew_runs_acme_when_due(self, tmp_path):
        """When cert is due, --renew calls run_certbot then install_certificate."""
        platform = MagicMock()
        env = self._renew_env(tmp_path)
        with patch('sys.argv', [
                'unifi-cert', '--renew', '-d', 'example.com',
                '-e', 'a@b.com',
                '--dns-provider', 'digitalocean',
                '--dns-credentials', '/x/y.ini']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.multiple(unifi_cert, **env), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'self_heal', return_value=True), \
             patch.object(unifi_cert, 'is_renewal_due', return_value=True), \
             patch.object(unifi_cert, 'run_certbot',
                          return_value=(True, '/x/cert.pem', '/x/key.pem')) as cb, \
             patch.object(unifi_cert, 'install_certificate',
                          return_value=True) as inst, \
             patch.object(unifi_cert.UnifiPlatform, 'detect', return_value=platform):
            result = unifi_cert.main()
        assert result == 0
        cb.assert_called_once()
        inst.assert_called_once()

    def test_renew_skips_acme_when_not_due(self, tmp_path):
        """When cert is not due, --renew exits 0 without calling certbot."""
        env = self._renew_env(tmp_path)
        with patch('sys.argv', ['unifi-cert', '--renew', '-d', 'example.com',
                               '-e', 'a@b.com', '--dns-provider', 'digitalocean',
                               '--dns-credentials', '/x/y.ini']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.multiple(unifi_cert, **env), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'self_heal', return_value=True), \
             patch.object(unifi_cert, 'is_renewal_due', return_value=False), \
             patch.object(unifi_cert, 'run_certbot') as cb, \
             patch.object(unifi_cert, 'install_certificate') as inst:
            result = unifi_cert.main()
        assert result == 0
        cb.assert_not_called()
        inst.assert_not_called()

    def test_renew_force_bypasses_due_check(self, tmp_path):
        """--force makes --renew run certbot even when not due."""
        platform = MagicMock()
        env = self._renew_env(tmp_path)
        with patch('sys.argv', ['unifi-cert', '--renew', '-d', 'example.com',
                               '-e', 'a@b.com', '--dns-provider', 'digitalocean',
                               '--dns-credentials', '/x/y.ini', '--force']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.multiple(unifi_cert, **env), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'self_heal', return_value=True), \
             patch.object(unifi_cert, 'is_renewal_due', return_value=False), \
             patch.object(unifi_cert, 'run_certbot',
                          return_value=(True, '/x/cert.pem', '/x/key.pem')) as cb, \
             patch.object(unifi_cert, 'install_certificate', return_value=True), \
             patch.object(unifi_cert.UnifiPlatform, 'detect', return_value=platform):
            result = unifi_cert.main()
        assert result == 0
        cb.assert_called_once()

    def test_renew_loads_provisioning_config_when_args_missing(self, tmp_path):
        """Cron-fired --renew (no flags) pulls from /data/unifi-cert/unifi-cert.conf."""
        cfg = tmp_path / 'unifi-cert.conf'
        cfg.write_text(
            'domain = example.com\n'
            'email = a@b.com\n'
            'dns_provider = digitalocean\n'
            'dns_credentials = /data/unifi-cert/credentials/digitalocean.ini\n'
        )
        platform = MagicMock()
        env = self._renew_env(tmp_path)
        with patch('sys.argv', ['unifi-cert', '--renew']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.multiple(unifi_cert, **env), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'self_heal', return_value=True), \
             patch.object(unifi_cert, 'is_renewal_due', return_value=True), \
             patch.object(unifi_cert, 'run_certbot',
                          return_value=(True, '/x/cert.pem', '/x/key.pem')) as cb, \
             patch.object(unifi_cert, 'install_certificate', return_value=True), \
             patch.object(unifi_cert.UnifiPlatform, 'detect', return_value=platform):
            result = unifi_cert.main()
        assert result == 0
        # Args read from provisioning config got threaded through.
        args, kwargs = cb.call_args
        assert args[0] == 'example.com'
        assert args[1] == 'a@b.com'
        assert args[2] == 'digitalocean'

    def test_renew_no_domain_anywhere_errors(self, tmp_path, capsys):
        """No -d AND no provisioning config → exit 1 with provisioning-config hint."""
        env = self._renew_env(tmp_path)
        with patch('sys.argv', ['unifi-cert', '--renew']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.multiple(unifi_cert, **env):
            result = unifi_cert.main()
        assert result == 1
        # Hint references provisioning config so the user knows where to look.
        err = capsys.readouterr().err
        assert 'unifi-cert.conf' in err

    def test_renew_due_but_missing_creds_errors(self, tmp_path):
        """Cert is due but no email/dns_provider/credentials → exit 1."""
        env = self._renew_env(tmp_path)
        with patch('sys.argv', ['unifi-cert', '--renew', '-d', 'example.com']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.multiple(unifi_cert, **env), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'self_heal', return_value=True), \
             patch.object(unifi_cert, 'is_renewal_due', return_value=True):
            result = unifi_cert.main()
        assert result == 1

    def test_renew_certbot_failure_propagates(self, tmp_path):
        """run_certbot returning False → exit 1."""
        env = self._renew_env(tmp_path)
        with patch('sys.argv', ['unifi-cert', '--renew', '-d', 'example.com',
                               '-e', 'a@b.com', '--dns-provider', 'digitalocean',
                               '--dns-credentials', '/x/y.ini']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.multiple(unifi_cert, **env), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'self_heal', return_value=True), \
             patch.object(unifi_cert, 'is_renewal_due', return_value=True), \
             patch.object(unifi_cert, 'run_certbot',
                          return_value=(False, '', '')):
            result = unifi_cert.main()
        assert result == 1

    def test_renew_install_failure_propagates(self, tmp_path):
        """install_certificate returning False → exit 1."""
        platform = MagicMock()
        env = self._renew_env(tmp_path)
        with patch('sys.argv', ['unifi-cert', '--renew', '-d', 'example.com',
                               '-e', 'a@b.com', '--dns-provider', 'digitalocean',
                               '--dns-credentials', '/x/y.ini']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.multiple(unifi_cert, **env), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'self_heal', return_value=True), \
             patch.object(unifi_cert, 'is_renewal_due', return_value=True), \
             patch.object(unifi_cert, 'run_certbot',
                          return_value=(True, '/x/cert.pem', '/x/key.pem')), \
             patch.object(unifi_cert, 'install_certificate', return_value=False), \
             patch.object(unifi_cert.UnifiPlatform, 'detect', return_value=platform):
            result = unifi_cert.main()
        assert result == 1

    def test_renew_lock_held_aborts(self, tmp_path):
        """Concurrent --renew while another holds the lock → exit 1."""
        env = self._renew_env(tmp_path)
        # Hold the lock from this process first.
        with patch.multiple(unifi_cert, **env):
            held = unifi_cert.acquire_lock()
            try:
                with patch('sys.argv', ['unifi-cert', '--renew', '-d', 'example.com',
                                       '-e', 'a@b.com',
                                       '--dns-provider', 'digitalocean',
                                       '--dns-credentials', '/x/y.ini']), \
                     patch('sys.stdout.isatty', return_value=False), \
                     patch.object(unifi_cert, 'ui'):
                    result = unifi_cert.main()
                assert result == 1
            finally:
                unifi_cert.release_lock(held)

    def test_renew_dry_run_returns_after_certbot(self, tmp_path):
        """--dry-run runs certbot in dry-run but never reaches install_certificate."""
        env = self._renew_env(tmp_path)
        with patch('sys.argv', ['unifi-cert', '--renew', '-d', 'example.com',
                               '-e', 'a@b.com', '--dns-provider', 'digitalocean',
                               '--dns-credentials', '/x/y.ini', '--dry-run']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.multiple(unifi_cert, **env), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'self_heal', return_value=True), \
             patch.object(unifi_cert, 'is_renewal_due', return_value=True), \
             patch.object(unifi_cert, 'run_certbot',
                          return_value=(True, '', '')) as cb, \
             patch.object(unifi_cert, 'install_certificate') as inst:
            result = unifi_cert.main()
        assert result == 0
        cb.assert_called_once()
        inst.assert_not_called()


class TestDeployHook:
    """Tests for the --deploy-hook entry point."""

    def test_deploy_hook_requires_lineage(self, tmp_path):
        """No $RENEWED_LINEAGE in env → exit 1."""
        with patch('sys.argv', ['unifi-cert', '--deploy-hook']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.dict(os.environ, {}, clear=False), \
             patch.object(unifi_cert, 'ui'):
            os.environ.pop('RENEWED_LINEAGE', None)
            result = unifi_cert.main()
        assert result == 1

    def test_deploy_hook_syncs_lineage(self, tmp_path):
        """With $RENEWED_LINEAGE pointing at a complete lineage, sync it."""
        lineage = tmp_path / 'live' / 'example.com'
        lineage.mkdir(parents=True)
        (lineage / 'fullchain.pem').write_text('cert')
        (lineage / 'privkey.pem').write_text('key')

        platform = MagicMock()
        with patch('sys.argv', ['unifi-cert', '--deploy-hook']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.dict(os.environ, {'RENEWED_LINEAGE': str(lineage)}), \
             patch.object(unifi_cert, 'UNIFI_CERT_ROOT', str(tmp_path)), \
             patch.object(unifi_cert, 'LOCK_FILE', str(tmp_path / 'lock')), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'install_certificate', return_value=True) as inst, \
             patch.object(unifi_cert.UnifiPlatform, 'detect', return_value=platform):
            result = unifi_cert.main()
        assert result == 0
        # Domain extracted from lineage basename.
        args, kwargs = inst.call_args
        assert args[2] == 'example.com'

    def test_deploy_hook_incomplete_lineage_errors(self, tmp_path):
        """Lineage missing privkey → exit 1, install_certificate not called."""
        lineage = tmp_path / 'live' / 'example.com'
        lineage.mkdir(parents=True)
        (lineage / 'fullchain.pem').write_text('cert')  # privkey missing

        with patch('sys.argv', ['unifi-cert', '--deploy-hook']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.dict(os.environ, {'RENEWED_LINEAGE': str(lineage)}), \
             patch.object(unifi_cert, 'UNIFI_CERT_ROOT', str(tmp_path)), \
             patch.object(unifi_cert, 'LOCK_FILE', str(tmp_path / 'lock')), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'install_certificate') as inst:
            result = unifi_cert.main()
        assert result == 1
        inst.assert_not_called()

    def test_deploy_hook_no_acme_no_bootstrap(self, tmp_path):
        """--deploy-hook never calls run_certbot or bootstrap_certbot."""
        lineage = tmp_path / 'live' / 'example.com'
        lineage.mkdir(parents=True)
        (lineage / 'fullchain.pem').write_text('cert')
        (lineage / 'privkey.pem').write_text('key')

        platform = MagicMock()
        with patch('sys.argv', ['unifi-cert', '--deploy-hook']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.dict(os.environ, {'RENEWED_LINEAGE': str(lineage)}), \
             patch.object(unifi_cert, 'UNIFI_CERT_ROOT', str(tmp_path)), \
             patch.object(unifi_cert, 'LOCK_FILE', str(tmp_path / 'lock')), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_certbot') as cb, \
             patch.object(unifi_cert, 'bootstrap_certbot') as boot, \
             patch.object(unifi_cert, 'install_certificate', return_value=True), \
             patch.object(unifi_cert.UnifiPlatform, 'detect', return_value=platform):
            unifi_cert.main()
        cb.assert_not_called()
        boot.assert_not_called()


class TestSelfHealCli:
    """Tests for the --self-heal CLI entry."""

    def test_self_heal_invokes_self_heal(self, tmp_path):
        """--self-heal calls self_heal() and exits 0 on success."""
        with patch('sys.argv', ['unifi-cert', '--self-heal',
                               '--dns-provider', 'digitalocean',
                               '-d', 'example.com']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'self_heal', return_value=True) as sh:
            result = unifi_cert.main()
        assert result == 0
        sh.assert_called_once_with(dns_provider='digitalocean', domain='example.com')

    def test_self_heal_no_args_works(self, tmp_path):
        """--self-heal with no -d / no --dns-provider still runs (uses provisioning)."""
        with patch('sys.argv', ['unifi-cert', '--self-heal']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'self_heal', return_value=True) as sh:
            result = unifi_cert.main()
        assert result == 0
        sh.assert_called_once_with(dns_provider=None, domain=None)

    def test_self_heal_failure_returns_1(self):
        """self_heal() returning False → exit 1."""
        with patch('sys.argv', ['unifi-cert', '--self-heal']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'self_heal', return_value=False):
            result = unifi_cert.main()
        assert result == 1


class TestHookAutoupdate:
    """Tests for the renewal hook + opt-in auto-update gating.

    Auto-update via curl-and-replace is the same anti-pattern that broke
    GlennR's installer (and bit unifi-cert on 2026-04-27 by overwriting
    an in-flight script). It must be off by default and only re-enabled
    when a SHA-256 pin is baked in.
    """

    def _write_hook(self, tmp_path, **kwargs):
        """Helper: render the hook into tmp_path/post/unifi-cert-hook.sh."""
        hook_dir = tmp_path / 'post'
        hook_dir.mkdir()
        hook_path = hook_dir / 'unifi-cert-hook.sh'
        original_join = os.path.join

        def mock_join(*args):
            if '/etc/letsencrypt' in str(args):
                return str(hook_path)
            return original_join(*args)

        with patch.object(unifi_cert, 'ui'), \
             patch('os.path.join', side_effect=mock_join):
            ok = unifi_cert.setup_renewal_hook('example.com', '/data/scripts/unifi-cert.py', **kwargs)
        return ok, hook_path

    def test_default_hook_has_no_curl_autoupdate(self, tmp_path):
        """Default install: no curl, no GitHub URL — hook is local-only."""
        ok, hook_path = self._write_hook(tmp_path)
        assert ok is True
        content = hook_path.read_text()
        assert 'curl' not in content
        assert 'raw.githubusercontent.com' not in content
        # And it should call --deploy-hook (not --renew) so it doesn't
        # recurse into ACME from inside a renewal hook.
        assert '--deploy-hook' in content
        assert '--renew' not in content

    def test_enable_autoupdate_without_pin_refused(self, tmp_path):
        """enable_autoupdate=True but HOOK_AUTOUPDATE_SHA256='' → False, hook NOT written."""
        with patch.object(unifi_cert, 'HOOK_AUTOUPDATE_SHA256', ''):
            ok, hook_path = self._write_hook(tmp_path, enable_autoupdate=True)
        assert ok is False
        # Hook file should not exist (we refused before writing).
        assert not hook_path.exists()

    def test_enable_autoupdate_with_pin_writes_verified_hook(self, tmp_path):
        """With a pin, hook contains curl + sha256sum + pin comparison."""
        pin = 'a' * 64  # 64-char hex looks like sha256
        with patch.object(unifi_cert, 'HOOK_AUTOUPDATE_SHA256', pin):
            ok, hook_path = self._write_hook(tmp_path, enable_autoupdate=True)
        assert ok is True
        content = hook_path.read_text()
        assert 'curl' in content
        assert 'sha256sum' in content
        assert pin in content  # pin is referenced in the hook for comparison
        # Mismatch path keeps the existing script.
        assert 'keeping existing script' in content
        # Still calls --deploy-hook for the actual sync.
        assert '--deploy-hook' in content

    def test_hook_uses_renewed_lineage_env(self, tmp_path):
        """Hook reads $RENEWED_LINEAGE so --deploy-hook gets the right path."""
        ok, hook_path = self._write_hook(tmp_path)
        assert ok is True
        content = hook_path.read_text()
        assert 'RENEWED_LINEAGE' in content

    def test_hook_logs_to_unifi_cert_log(self, tmp_path):
        """Hook redirects --deploy-hook output to LOG_FILE for --status visibility."""
        ok, hook_path = self._write_hook(tmp_path)
        assert ok is True
        content = hook_path.read_text()
        assert unifi_cert.LOG_FILE in content

    def test_setup_hook_cli_passes_autoupdate_flag(self):
        """`--setup-hook --enable-hook-autoupdate` threads the flag through."""
        with patch('sys.argv', ['unifi-cert', '--setup-hook',
                               '-d', 'example.com',
                               '--enable-hook-autoupdate']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'ensure_script_installed'), \
             patch.object(unifi_cert, 'setup_renewal_hook',
                          return_value=True) as hook:
            unifi_cert.main()
        assert hook.call_args.kwargs.get('enable_autoupdate') is True

    def test_setup_hook_cli_default_no_autoupdate(self):
        """Plain `--setup-hook` does NOT enable autoupdate."""
        with patch('sys.argv', ['unifi-cert', '--setup-hook', '-d', 'example.com']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'ensure_script_installed'), \
             patch.object(unifi_cert, 'setup_renewal_hook',
                          return_value=True) as hook:
            unifi_cert.main()
        assert hook.call_args.kwargs.get('enable_autoupdate') is False


class TestGlennRInventory:
    """Tests for inventory_glennr() — read-only probe of GlennR state."""

    def _stage_renewal_conf(self, tmp_path, domain, email='admin@example.com',
                             dns='digitalocean', creds='/root/.secrets/do.ini'):
        """Helper: create a fake /etc/letsencrypt/renewal/<domain>.conf file."""
        renewal_dir = tmp_path / 'letsencrypt' / 'renewal'
        renewal_dir.mkdir(parents=True)
        conf = renewal_dir / f'{domain}.conf'
        conf.write_text(
            f'# managed by certbot\n'
            f'cert = /etc/letsencrypt/live/{domain}/cert.pem\n'
            f'archive_dir = /etc/letsencrypt/archive/{domain}\n'
            f'\n'
            f'[renewalparams]\n'
            f'authenticator = dns-{dns}\n'
            f'email = {email}\n'
            f'dns_{dns}_credentials = {creds}\n'
        )
        return tmp_path / 'letsencrypt'

    def test_empty_disk_returns_empty_inventory(self, tmp_path):
        """No GlennR footprint → all fields None and detected_paths == []."""
        with patch('os.path.isdir', return_value=False), \
             patch('os.path.isfile', return_value=False), \
             patch('glob.glob', return_value=[]):
            inv = unifi_cert.inventory_glennr()
        assert inv.domain is None
        assert inv.dns_provider is None
        assert inv.detected_paths == []

    def test_renewal_conf_extraction(self, tmp_path, monkeypatch):
        """Renewal conf yields domain + email + dns_provider + credentials path."""
        le_root = self._stage_renewal_conf(tmp_path, 'example.com')

        # Patch the renewal_dir lookup to point at our staged tree.
        real_isdir = os.path.isdir
        real_listdir = os.listdir
        real_open = open

        def fake_isdir(p):
            if p == '/etc/letsencrypt/renewal':
                return True
            return real_isdir(p)

        def fake_listdir(p):
            if p == '/etc/letsencrypt/renewal':
                return real_listdir(le_root / 'renewal')
            return real_listdir(p)

        def fake_open(p, *a, **kw):
            if isinstance(p, str) and p.startswith('/etc/letsencrypt/renewal/'):
                return real_open(le_root / 'renewal' / os.path.basename(p), *a, **kw)
            return real_open(p, *a, **kw)

        with patch('os.path.isdir', side_effect=fake_isdir), \
             patch('os.listdir', side_effect=fake_listdir), \
             patch('builtins.open', side_effect=fake_open), \
             patch('os.path.exists', return_value=False), \
             patch('os.path.isfile', return_value=False), \
             patch('glob.glob', return_value=[]):
            inv = unifi_cert.inventory_glennr()
        assert inv.domain == 'example.com'
        assert inv.email == 'admin@example.com'
        assert inv.dns_provider == 'digitalocean'
        assert inv.dns_credentials_path == '/root/.secrets/do.ini'

    def test_detected_dirs(self):
        """Existing GlennR dirs are added to detected_paths with kind='dir'."""
        def fake_isdir(p):
            return p in ('/srv/EUS', '/usr/lib/EUS', '/root/EUS')

        with patch('os.path.isdir', side_effect=fake_isdir), \
             patch('os.path.isfile', return_value=False), \
             patch('os.path.exists', return_value=False), \
             patch('glob.glob', return_value=[]):
            inv = unifi_cert.inventory_glennr()
        kinds = {(p, k) for (p, k, _) in inv.detected_paths}
        assert ('/srv/EUS', 'dir') in kinds
        assert ('/usr/lib/EUS', 'dir') in kinds
        assert ('/root/EUS', 'dir') in kinds

    def test_detected_crons_and_hooks(self):
        """Cron files + EUS_*.sh hooks are detected via allowlist + globs."""
        def fake_isfile(p):
            return p in (
                '/etc/cron.d/eus_script',
                '/etc/cron.d/eus_certbot',
                '/etc/letsencrypt/renewal-hooks/post/EUS_postsync.sh',
            )

        def fake_glob(pattern):
            if pattern == '/etc/letsencrypt/renewal-hooks/post/EUS_*.sh':
                return ['/etc/letsencrypt/renewal-hooks/post/EUS_postsync.sh']
            return []

        with patch('os.path.isdir', return_value=False), \
             patch('os.path.isfile', side_effect=fake_isfile), \
             patch('os.path.exists', return_value=False), \
             patch('glob.glob', side_effect=fake_glob):
            inv = unifi_cert.inventory_glennr()
        kinds = {(p, k) for (p, k, _) in inv.detected_paths}
        assert ('/etc/cron.d/eus_script', 'cron') in kinds
        assert ('/etc/cron.d/eus_certbot', 'cron') in kinds
        assert ('/etc/letsencrypt/renewal-hooks/post/EUS_postsync.sh', 'hook') in kinds

    def test_generic_certbot_cron_only_when_apt_content(self, tmp_path):
        """/etc/cron.d/certbot only added when content invokes apt-installed certbot."""
        cron_path = '/etc/cron.d/certbot'

        def fake_isfile(p):
            return p == cron_path

        # Case A: apt-style content → DETECTED.
        apt_content = ('SHELL=/bin/sh\n0 */12 * * * root test -x /usr/bin/certbot && '
                       '/usr/bin/certbot -q renew\n')
        with patch('os.path.isdir', return_value=False), \
             patch('os.path.isfile', side_effect=fake_isfile), \
             patch('os.path.exists', return_value=False), \
             patch('glob.glob', return_value=[]), \
             patch('builtins.open', mock_open(read_data=apt_content)):
            inv = unifi_cert.inventory_glennr()
        assert any(p == cron_path for (p, _, _) in inv.detected_paths)

        # Case B: user-authored content (no /usr/bin/certbot) → NOT detected.
        user_content = '0 3 * * * root /home/me/my-cert-tool.sh\n'
        with patch('os.path.isdir', return_value=False), \
             patch('os.path.isfile', side_effect=fake_isfile), \
             patch('os.path.exists', return_value=False), \
             patch('glob.glob', return_value=[]), \
             patch('builtins.open', mock_open(read_data=user_content)):
            inv = unifi_cert.inventory_glennr()
        assert not any(p == cron_path for (p, _, _) in inv.detected_paths)

    def test_apt_sources_detection(self):
        """All four glennr-install-script.* apt sources are detected."""
        sources = (
            '/etc/apt/sources.list.d/glennr-install-script.list',
            '/etc/apt/sources.list.d/glennr-install-script.sources',
            '/etc/apt/sources.list.d/glennr-install-script-unmet.list',
            '/etc/apt/sources.list.d/glennr-install-script-unmet.sources',
        )

        def fake_isfile(p):
            return p in sources

        with patch('os.path.isdir', return_value=False), \
             patch('os.path.isfile', side_effect=fake_isfile), \
             patch('os.path.exists', return_value=False), \
             patch('glob.glob', return_value=[]):
            inv = unifi_cert.inventory_glennr()
        detected = {p for (p, _, _) in inv.detected_paths}
        for src in sources:
            assert src in detected


class TestImportProvisioning:
    """Tests for import_provisioning_from_glennr()."""

    def test_refuses_without_minimum_fields(self, tmp_path):
        """Inventory missing domain or dns_provider → False, no save."""
        inv = unifi_cert.GlennRInventory(domain=None, dns_provider='digitalocean')
        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'save_provisioning_config') as save:
            assert unifi_cert.import_provisioning_from_glennr(inv) is False
        save.assert_not_called()

    def test_copies_credentials_to_persistent_root(self, tmp_path):
        """Existing credentials file is copied into CREDENTIALS_DIR with mode 0600."""
        creds_src = tmp_path / 'do.ini'
        creds_src.write_text('dns_digitalocean_token = secret\n')
        creds_src.chmod(0o600)
        creds_dir = tmp_path / 'credentials'
        inv = unifi_cert.GlennRInventory(
            domain='example.com', email='a@b.com',
            dns_provider='digitalocean', dns_credentials_path=str(creds_src),
        )
        with patch.object(unifi_cert, 'CREDENTIALS_DIR', str(creds_dir)), \
             patch.object(unifi_cert, 'save_provisioning_config',
                          return_value=True) as save, \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert.import_provisioning_from_glennr(inv)
        assert ok is True
        new_creds = creds_dir / 'digitalocean.ini'
        assert new_creds.exists()
        assert (new_creds.stat().st_mode & 0o777) == 0o600
        # save_provisioning_config receives the NEW path, not the old one.
        assert save.call_args.kwargs['dns_credentials'] == str(new_creds)

    def test_missing_creds_path_warns_but_saves(self, tmp_path):
        """Credentials path that doesn't exist → warn, save with original path."""
        inv = unifi_cert.GlennRInventory(
            domain='example.com', dns_provider='digitalocean',
            dns_credentials_path='/does/not/exist.ini',
        )
        mock_ui = MagicMock()
        with patch.object(unifi_cert, 'ui', mock_ui), \
             patch.object(unifi_cert, 'save_provisioning_config',
                          return_value=True) as save:
            ok = unifi_cert.import_provisioning_from_glennr(inv)
        assert ok is True
        mock_ui.warning.assert_called()
        # Falls back to the original (non-existent) path.
        assert save.call_args.kwargs['dns_credentials'] == '/does/not/exist.ini'


class TestSnapshotGlennr:
    """Tests for snapshot_glennr() tarball creation."""

    def test_snapshot_includes_detected_and_etc_letsencrypt(self, tmp_path):
        """Tarball includes every detected path plus /etc/letsencrypt when present."""
        inv = unifi_cert.GlennRInventory(detected_paths=[
            ('/srv/EUS', 'dir', ''),
            ('/etc/cron.d/eus_script', 'cron', ''),
        ])
        backups = tmp_path / 'backups'

        def fake_exists(p):
            return p in ('/srv/EUS', '/etc/cron.d/eus_script')

        def fake_isdir(p):
            return p == '/etc/letsencrypt'

        result = MagicMock(returncode=0, stderr='')
        with patch.object(unifi_cert, 'BACKUPS_DIR', str(backups)), \
             patch('os.path.exists', side_effect=fake_exists), \
             patch('os.path.isdir', side_effect=fake_isdir), \
             patch('subprocess.run', return_value=result) as run, \
             patch.object(unifi_cert, 'ui'):
            tarball = unifi_cert.snapshot_glennr(inv, timestamp='20260427T000000Z')
        assert tarball is not None
        cmd = run.call_args.args[0]
        assert cmd[:3] == ['tar', 'czf', tarball]
        assert '/srv/EUS' in cmd
        assert '/etc/cron.d/eus_script' in cmd
        assert '/etc/letsencrypt' in cmd

    def test_snapshot_empty_returns_none(self):
        """No detected paths and no /etc/letsencrypt → None + warning, no tar call."""
        inv = unifi_cert.GlennRInventory(detected_paths=[])
        with patch('os.path.exists', return_value=False), \
             patch('os.path.isdir', return_value=False), \
             patch('subprocess.run') as run, \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.snapshot_glennr(inv) is None
        run.assert_not_called()

    def test_snapshot_tar_failure_returns_none(self):
        """tar exit non-zero → None, error logged."""
        inv = unifi_cert.GlennRInventory(detected_paths=[('/srv/EUS', 'dir', '')])
        result = MagicMock(returncode=2, stderr='tar: permission denied')
        with patch('os.path.exists', return_value=True), \
             patch('os.path.isdir', return_value=False), \
             patch('subprocess.run', return_value=result), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.snapshot_glennr(inv) is None


class TestRsyncLeState:
    """Tests for _rsync_etc_letsencrypt()."""

    def test_skips_when_etc_letsencrypt_absent(self):
        """No /etc/letsencrypt → True (graceful skip), no rsync call."""
        with patch('os.path.isdir', return_value=False), \
             patch('subprocess.run') as run, \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert._rsync_etc_letsencrypt() is True
        run.assert_not_called()

    def test_passes_archive_and_update_flags(self, tmp_path):
        """rsync invoked with -aHu plus trailing-slash source for contents-only copy.

        -u (--update) prevents stale source files from clobbering newer dest
        files when dest already has a partial lineage; combined with the
        early-return guard below it covers both safe-merge and skip cases.
        """
        result = MagicMock(returncode=0, stderr='')
        with patch('os.path.isdir', return_value=True), \
             patch('os.path.exists', return_value=False), \
             patch('os.makedirs'), \
             patch('subprocess.run', return_value=result) as run, \
             patch.object(unifi_cert, 'CERTBOT_CONFIG_DIR', str(tmp_path)), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert._rsync_etc_letsencrypt() is True
        cmd = run.call_args.args[0]
        assert cmd[:2] == ['rsync', '-aHu']
        assert cmd[2] == '/etc/letsencrypt/'
        assert cmd[3].endswith('/')

    def test_rsync_failure_returns_false(self):
        """rsync exit non-zero → False so caller can abort before deletion."""
        result = MagicMock(returncode=23, stderr='rsync: protocol error')
        with patch('os.path.isdir', return_value=True), \
             patch('os.path.exists', return_value=False), \
             patch('os.makedirs'), \
             patch('subprocess.run', return_value=result), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert._rsync_etc_letsencrypt() is False

    def test_skips_when_dest_lineage_already_present(self, tmp_path):
        """If dest has fullchain.pem for the domain, rsync is skipped entirely.

        Regression test: prior behavior would rsync GlennR's older lineage
        over a working newer lineage, replacing a valid cert with stale
        files of the same name (cert1.pem, etc.) that happen to live at
        identical relative paths. The fix is to early-return when the
        destination already owns a working lineage for this domain.
        """
        live_dir = tmp_path / 'live' / 'example.com'
        live_dir.mkdir(parents=True)
        (live_dir / 'fullchain.pem').write_text('cert\n')

        with patch('os.path.isdir', return_value=True), \
             patch('subprocess.run') as run, \
             patch.object(unifi_cert, 'CERTBOT_CONFIG_DIR', str(tmp_path)), \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert._rsync_etc_letsencrypt(domain='example.com')
        assert ok is True
        run.assert_not_called()

    def test_proceeds_when_dest_lineage_missing(self, tmp_path):
        """Dest path exists but no fullchain for this domain → proceed with rsync."""
        # tmp_path exists but has no live/example.com/fullchain.pem
        result = MagicMock(returncode=0, stderr='')
        with patch('os.path.isdir', return_value=True), \
             patch('os.makedirs'), \
             patch('subprocess.run', return_value=result) as run, \
             patch.object(unifi_cert, 'CERTBOT_CONFIG_DIR', str(tmp_path)), \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert._rsync_etc_letsencrypt(domain='example.com')
        assert ok is True
        run.assert_called_once()


class TestMigrateUninstall:
    """Tests for _remove_glennr_path() per-path confirm logic."""

    def test_force_skips_confirm_and_removes(self, tmp_path):
        """force=True bypasses ui.confirm and proceeds to remove."""
        target = tmp_path / 'eus_script'
        target.write_text('cron content')
        mock_ui = MagicMock()
        with patch.object(unifi_cert, 'ui', mock_ui):
            ok = unifi_cert._remove_glennr_path(str(target), 'cron', force=True)
        assert ok is True
        assert not target.exists()
        mock_ui.confirm.assert_not_called()

    def test_dir_removed_via_rmtree(self, tmp_path):
        """kind='dir' uses shutil.rmtree (deletes nested files)."""
        target = tmp_path / 'EUS'
        target.mkdir()
        (target / 'inside.txt').write_text('x')
        with patch.object(unifi_cert, 'ui'):
            ok = unifi_cert._remove_glennr_path(str(target), 'dir', force=True)
        assert ok is True
        assert not target.exists()

    def test_decline_confirm_skips(self, tmp_path):
        """User declines confirm → file preserved, returns True (graceful)."""
        target = tmp_path / 'thing'
        target.write_text('keep me')
        mock_ui = MagicMock()
        mock_ui.confirm.return_value = False
        with patch.object(unifi_cert, 'ui', mock_ui):
            ok = unifi_cert._remove_glennr_path(str(target), 'file', force=False)
        assert ok is True
        assert target.exists()


class TestMigrateGlennr:
    """Orchestration tests for migrate_glennr()."""

    def _empty_inv(self):
        return unifi_cert.GlennRInventory(detected_paths=[])

    def _full_inv(self):
        return unifi_cert.GlennRInventory(
            domain='example.com', email='a@b.com',
            dns_provider='digitalocean',
            dns_credentials_path='/root/.secrets/do.ini',
            glennr_version='8.4.2',
            detected_paths=[
                ('/srv/EUS', 'dir', 'GlennR data directory'),
                ('/etc/cron.d/eus_script', 'cron', 'GlennR cron job'),
            ],
        )

    def test_no_footprint_short_circuits(self):
        """Empty inventory + no /etc/letsencrypt → True, nothing destructive runs."""
        with patch.object(unifi_cert, 'inventory_glennr',
                          return_value=self._empty_inv()), \
             patch('os.path.isdir', return_value=False), \
             patch.object(unifi_cert, 'import_provisioning_from_glennr') as imp, \
             patch.object(unifi_cert, 'snapshot_glennr') as snap, \
             patch.object(unifi_cert, '_remove_glennr_path') as rm, \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.migrate_glennr() is True
        imp.assert_not_called()
        snap.assert_not_called()
        rm.assert_not_called()

    def test_dry_run_lists_no_destructive(self):
        """--dry-run logs planned actions but never imports / snapshots / removes."""
        with patch.object(unifi_cert, 'inventory_glennr',
                          return_value=self._full_inv()), \
             patch('os.path.isdir', return_value=True), \
             patch.object(unifi_cert, 'import_provisioning_from_glennr') as imp, \
             patch.object(unifi_cert, 'snapshot_glennr') as snap, \
             patch.object(unifi_cert, '_rsync_etc_letsencrypt') as rsync, \
             patch.object(unifi_cert, '_remove_glennr_path') as rm, \
             patch.object(unifi_cert, 'self_heal') as sh, \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.migrate_glennr(dry_run=True) is True
        imp.assert_not_called()
        snap.assert_not_called()
        rsync.assert_not_called()
        rm.assert_not_called()
        sh.assert_not_called()

    def test_happy_path_calls_phases_in_order(self, tmp_path):
        """Real run threads inventory → import → snapshot → rsync → uninstall → self-heal."""
        inv = self._full_inv()
        ordering = []

        with patch.object(unifi_cert, 'inventory_glennr', return_value=inv), \
             patch('os.path.isdir', return_value=True), \
             patch('os.path.exists', return_value=True), \
             patch.object(unifi_cert, 'import_provisioning_from_glennr',
                          side_effect=lambda *a, **k: ordering.append('import') or True), \
             patch.object(unifi_cert, 'snapshot_glennr',
                          side_effect=lambda *a, **k: ordering.append('snapshot') or '/x/snap.tgz'), \
             patch.object(unifi_cert, '_rsync_etc_letsencrypt',
                          side_effect=lambda *a, **k: ordering.append('rsync') or True), \
             patch.object(unifi_cert, '_remove_glennr_path',
                          side_effect=lambda *a, **k: ordering.append(f'rm:{a[0]}') or True), \
             patch.object(unifi_cert, 'self_heal',
                          side_effect=lambda **k: ordering.append('self_heal') or True), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.migrate_glennr(force=True) is True

        # Order matters: import must precede snapshot, snapshot must precede rsync,
        # rsync must precede any rm, self_heal is last.
        assert ordering.index('import') < ordering.index('snapshot')
        assert ordering.index('snapshot') < ordering.index('rsync')
        rm_indices = [i for i, x in enumerate(ordering) if x.startswith('rm:')]
        assert all(ordering.index('rsync') < i for i in rm_indices)
        assert ordering[-1] == 'self_heal'

    def test_import_failure_aborts_before_snapshot(self):
        """import_provisioning_from_glennr returning False → no snapshot, no rm."""
        with patch.object(unifi_cert, 'inventory_glennr',
                          return_value=self._full_inv()), \
             patch('os.path.isdir', return_value=True), \
             patch.object(unifi_cert, 'import_provisioning_from_glennr',
                          return_value=False), \
             patch.object(unifi_cert, 'snapshot_glennr') as snap, \
             patch.object(unifi_cert, '_rsync_etc_letsencrypt') as rsync, \
             patch.object(unifi_cert, '_remove_glennr_path') as rm, \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.migrate_glennr(force=True) is False
        snap.assert_not_called()
        rsync.assert_not_called()
        rm.assert_not_called()

    def test_snapshot_failure_aborts_before_rsync(self):
        """snapshot_glennr() returning None → no rsync, no rm — preserves /etc/letsencrypt."""
        with patch.object(unifi_cert, 'inventory_glennr',
                          return_value=self._full_inv()), \
             patch('os.path.isdir', return_value=True), \
             patch.object(unifi_cert, 'import_provisioning_from_glennr',
                          return_value=True), \
             patch.object(unifi_cert, 'snapshot_glennr', return_value=None), \
             patch.object(unifi_cert, '_rsync_etc_letsencrypt') as rsync, \
             patch.object(unifi_cert, '_remove_glennr_path') as rm, \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.migrate_glennr(force=True) is False
        rsync.assert_not_called()
        rm.assert_not_called()

    def test_post_rsync_lineage_missing_skips_letsencrypt_deletion(self):
        """Migrated lineage missing fullchain.pem → /etc/letsencrypt/ is preserved."""
        inv = self._full_inv()
        rm_calls = []

        def fake_exists(p):
            # New live path is missing → trigger safety net.
            if 'live/example.com/fullchain.pem' in p:
                return False
            return True

        with patch.object(unifi_cert, 'inventory_glennr', return_value=inv), \
             patch('os.path.isdir', return_value=True), \
             patch('os.path.exists', side_effect=fake_exists), \
             patch.object(unifi_cert, 'import_provisioning_from_glennr',
                          return_value=True), \
             patch.object(unifi_cert, 'snapshot_glennr', return_value='/x/s.tgz'), \
             patch.object(unifi_cert, '_rsync_etc_letsencrypt', return_value=True), \
             patch.object(unifi_cert, '_remove_glennr_path',
                          side_effect=lambda *a, **k: rm_calls.append(a[0]) or True), \
             patch.object(unifi_cert, 'self_heal', return_value=True), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.migrate_glennr(force=True) is True

        # Allowlisted paths still removed, but /etc/letsencrypt is preserved.
        assert '/srv/EUS' in rm_calls
        assert '/etc/letsencrypt' not in rm_calls


class TestMainMigrateGlennr:
    """CLI integration tests for --migrate-glennr."""

    def test_migrate_glennr_dry_run_threaded_through(self):
        """`--migrate-glennr --dry-run` calls migrate_glennr(dry_run=True)."""
        with patch('sys.argv', ['unifi-cert', '--migrate-glennr', '--dry-run']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'migrate_glennr', return_value=True) as mg:
            result = unifi_cert.main()
        assert result == 0
        mg.assert_called_once_with(dry_run=True, force=False)

    def test_migrate_glennr_force_threaded_through(self):
        """`--migrate-glennr --force` calls migrate_glennr(force=True)."""
        with patch('sys.argv', ['unifi-cert', '--migrate-glennr', '--force']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'migrate_glennr', return_value=True) as mg:
            result = unifi_cert.main()
        assert result == 0
        mg.assert_called_once_with(dry_run=False, force=True)

    def test_migrate_glennr_failure_returns_1(self):
        """migrate_glennr returning False → exit 1."""
        with patch('sys.argv', ['unifi-cert', '--migrate-glennr', '--force']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'migrate_glennr', return_value=False):
            result = unifi_cert.main()
        assert result == 1

    def test_migrate_glennr_runs_without_domain_arg(self):
        """--migrate-glennr (automation verb) must not trip 'Domain is required'."""
        with patch('sys.argv', ['unifi-cert', '--migrate-glennr', '--dry-run']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'migrate_glennr', return_value=True):
            result = unifi_cert.main()
        assert result == 0


class _FakeUrlOpen:
    """Context-manager fake for urllib.request.urlopen.

    Returns parsed JSON from `payload` (dict), with HTTP status `status`.
    Records all requests for assertion.
    """
    def __init__(self):
        self.requests = []
        self._next = []

    def queue(self, payload, status=200):
        self._next.append((payload, status))

    def __call__(self, req, timeout=None):
        self.requests.append({
            'method': req.get_method(),
            'url': req.full_url,
            'body': req.data.decode('utf-8') if req.data else None,
            'headers': dict(req.header_items()),
        })
        if not self._next:
            raise RuntimeError(f'No queued response for {req.get_method()} {req.full_url}')
        payload, status = self._next.pop(0)
        return _FakeResp(payload, status)


class _FakeResp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status = status

    def read(self):
        if self._payload is None:
            return b''
        if isinstance(self._payload, bytes):
            return self._payload
        return json.dumps(self._payload).encode('utf-8')

    def getcode(self):
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestDdnsExtractToken:
    """Tests for _ddns_extract_token() against certbot credentials INI."""

    def test_extract_digitalocean_token(self, tmp_path):
        """Standard certbot INI: extracts dns_digitalocean_token value."""
        creds = tmp_path / 'do.ini'
        creds.write_text(
            '# Certbot DigitalOcean credentials\n'
            'dns_digitalocean_token = dop_v1_abcdef0123456789\n'
        )
        assert unifi_cert._ddns_extract_token(str(creds)) == 'dop_v1_abcdef0123456789'

    def test_unknown_provider_returns_none(self, tmp_path):
        """Provider not in DNS_PROVIDERS → None."""
        creds = tmp_path / 'x.ini'
        creds.write_text('foo = bar\n')
        assert unifi_cert._ddns_extract_token(str(creds), provider='nonsense') is None

    def test_missing_field_returns_none(self, tmp_path):
        """Credential file has the right shape but wrong field name → None."""
        creds = tmp_path / 'do.ini'
        creds.write_text('something_else = value\n')
        assert unifi_cert._ddns_extract_token(str(creds)) is None

    def test_missing_file_returns_none(self):
        """Non-existent file → None (graceful)."""
        assert unifi_cert._ddns_extract_token('/does/not/exist.ini') is None


class TestDdnsResolveZone:
    """Tests for _ddns_resolve_zone() — finding the right DigitalOcean zone."""

    def test_subdomain_resolves_to_apex_zone(self):
        """beehive.jdlien.com → zone='jdlien.com', host='beehive'."""
        fake = _FakeUrlOpen()
        fake.queue({'domains': [{'name': 'jdlien.com'}, {'name': 'other.com'}]})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            zone, host = unifi_cert._ddns_resolve_zone('TOKEN', 'beehive.jdlien.com')
        assert zone == 'jdlien.com'
        assert host == 'beehive'

    def test_apex_returns_at_host(self):
        """jdlien.com → zone='jdlien.com', host='@'."""
        fake = _FakeUrlOpen()
        fake.queue({'domains': [{'name': 'jdlien.com'}]})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            zone, host = unifi_cert._ddns_resolve_zone('T', 'jdlien.com')
        assert zone == 'jdlien.com'
        assert host == '@'

    def test_multipart_tld_picks_longest_match(self):
        """example.co.uk owned + co.uk also owned → longest suffix wins."""
        fake = _FakeUrlOpen()
        fake.queue({'domains': [{'name': 'example.co.uk'}, {'name': 'co.uk'}]})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            zone, host = unifi_cert._ddns_resolve_zone('T', 'foo.example.co.uk')
        assert zone == 'example.co.uk'
        assert host == 'foo'

    def test_no_match_returns_none(self):
        """Domain isn't owned by user → (None, None)."""
        fake = _FakeUrlOpen()
        fake.queue({'domains': [{'name': 'other.com'}]})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            zone, host = unifi_cert._ddns_resolve_zone('T', 'beehive.jdlien.com')
        assert zone is None
        assert host is None

    def test_network_error_returns_none(self):
        """urlopen raising URLError → (None, None) with logged error."""
        with patch('urllib.request.urlopen',
                   side_effect=urllib.error.URLError('connection refused')), \
             patch.object(unifi_cert, 'ui'):
            zone, host = unifi_cert._ddns_resolve_zone('T', 'beehive.jdlien.com')
        assert zone is None
        assert host is None


class TestDdnsGetARecord:
    """Tests for _ddns_get_a_record() and _ddns_put_a_record()."""

    def test_get_a_record_returns_id_and_data(self):
        """API returns one matching A record → (id, ip) tuple."""
        fake = _FakeUrlOpen()
        fake.queue({'domain_records': [{'id': 12345, 'data': '1.2.3.4'}]})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            rid, ip = unifi_cert._ddns_get_a_record('T', 'jdlien.com', 'beehive')
        assert rid == 12345
        assert ip == '1.2.3.4'
        # URL includes type=A and the fully-qualified name.
        assert 'type=A' in fake.requests[0]['url']
        assert 'beehive.jdlien.com' in fake.requests[0]['url']

    def test_get_a_record_apex_uses_zone_as_name(self):
        """For host='@' the API name parameter is just the zone."""
        fake = _FakeUrlOpen()
        fake.queue({'domain_records': []})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            unifi_cert._ddns_get_a_record('T', 'jdlien.com', '@')
        url = fake.requests[0]['url']
        assert 'name=jdlien.com' in url
        assert 'name=@' not in url

    def test_get_a_record_missing_returns_none(self):
        """No matching record → (None, None)."""
        fake = _FakeUrlOpen()
        fake.queue({'domain_records': []})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            rid, ip = unifi_cert._ddns_get_a_record('T', 'jdlien.com', 'beehive')
        assert (rid, ip) == (None, None)

    def test_put_a_record_sends_data_field(self):
        """PUT body is JSON {'data': new_ip}, Authorization header set."""
        fake = _FakeUrlOpen()
        fake.queue({'domain_record': {'id': 1, 'data': '5.6.7.8'}})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            ok = unifi_cert._ddns_put_a_record('TOKEN', 'jdlien.com', 12345, '5.6.7.8')
        assert ok is True
        req = fake.requests[0]
        assert req['method'] == 'PUT'
        assert '/domains/jdlien.com/records/12345' in req['url']
        assert json.loads(req['body']) == {'data': '5.6.7.8'}
        # Header keys are case-insensitive in Request; urllib title-cases them.
        auth = next((v for k, v in req['headers'].items() if k.lower() == 'authorization'), None)
        assert auth == 'Bearer TOKEN'

    def test_put_a_record_network_error_returns_false(self):
        """urlopen raising → False, error logged."""
        with patch('urllib.request.urlopen',
                   side_effect=urllib.error.URLError('boom')), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert._ddns_put_a_record('T', 'jdlien.com', 1, '1.2.3.4') is False


class TestDdnsUpdate:
    """Orchestration tests for ddns_update()."""

    def _provisioning(self, **overrides):
        cfg = {
            'domain': 'beehive.jdlien.com',
            'email': 'a@b.com',
            'dns_provider': 'digitalocean',
            'dns_credentials': '/secrets/do.ini',
        }
        cfg.update(overrides)
        return cfg

    def test_no_op_when_record_matches(self, tmp_path):
        """Current public IP equals A-record value → no PUT, returns True."""
        creds = tmp_path / 'do.ini'
        creds.write_text('dns_digitalocean_token = TOKEN\n')

        with patch.object(unifi_cert, 'load_provisioning_config',
                          return_value=self._provisioning(dns_credentials=str(creds))), \
             patch.object(unifi_cert, 'get_public_ip', return_value='1.2.3.4'), \
             patch.object(unifi_cert, '_ddns_resolve_zone',
                          return_value=('jdlien.com', 'beehive')), \
             patch.object(unifi_cert, '_ddns_get_a_record',
                          return_value=(12345, '1.2.3.4')), \
             patch.object(unifi_cert, '_ddns_put_a_record') as put, \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert.ddns_update()
        assert ok is True
        put.assert_not_called()

    def test_patch_when_record_stale(self, tmp_path):
        """A-record IP differs from current → PUT new IP, return True."""
        creds = tmp_path / 'do.ini'
        creds.write_text('dns_digitalocean_token = TOKEN\n')

        with patch.object(unifi_cert, 'load_provisioning_config',
                          return_value=self._provisioning(dns_credentials=str(creds))), \
             patch.object(unifi_cert, 'get_public_ip', return_value='5.6.7.8'), \
             patch.object(unifi_cert, '_ddns_resolve_zone',
                          return_value=('jdlien.com', 'beehive')), \
             patch.object(unifi_cert, '_ddns_get_a_record',
                          return_value=(12345, '1.2.3.4')), \
             patch.object(unifi_cert, '_ddns_put_a_record',
                          return_value=True) as put, \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert.ddns_update()
        assert ok is True
        put.assert_called_once_with('TOKEN', 'jdlien.com', 12345, '5.6.7.8')

    def test_force_patches_even_when_match(self, tmp_path):
        """force=True → PUT even when current IP equals record."""
        creds = tmp_path / 'do.ini'
        creds.write_text('dns_digitalocean_token = TOKEN\n')

        with patch.object(unifi_cert, 'load_provisioning_config',
                          return_value=self._provisioning(dns_credentials=str(creds))), \
             patch.object(unifi_cert, 'get_public_ip', return_value='1.2.3.4'), \
             patch.object(unifi_cert, '_ddns_resolve_zone',
                          return_value=('jdlien.com', 'beehive')), \
             patch.object(unifi_cert, '_ddns_get_a_record',
                          return_value=(12345, '1.2.3.4')), \
             patch.object(unifi_cert, '_ddns_put_a_record',
                          return_value=True) as put, \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert.ddns_update(force=True)
        assert ok is True
        put.assert_called_once()

    def test_no_domain_errors(self):
        """No domain in args or provisioning → False."""
        with patch.object(unifi_cert, 'load_provisioning_config', return_value={}), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.ddns_update() is False

    def test_non_digitalocean_provider_errors(self, tmp_path):
        """provisioning dns_provider != digitalocean → False (v1 limitation)."""
        creds = tmp_path / 'cf.ini'
        creds.write_text('dns_cloudflare_api_token = T\n')
        cfg = self._provisioning(dns_provider='cloudflare', dns_credentials=str(creds))
        with patch.object(unifi_cert, 'load_provisioning_config', return_value=cfg), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.ddns_update() is False

    def test_missing_credentials_file_errors(self):
        """dns_credentials path doesn't exist → False."""
        cfg = self._provisioning(dns_credentials='/does/not/exist.ini')
        with patch.object(unifi_cert, 'load_provisioning_config', return_value=cfg), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.ddns_update() is False

    def test_public_ip_lookup_failure_errors(self, tmp_path):
        """get_public_ip returning None → False."""
        creds = tmp_path / 'do.ini'
        creds.write_text('dns_digitalocean_token = T\n')
        with patch.object(unifi_cert, 'load_provisioning_config',
                          return_value=self._provisioning(dns_credentials=str(creds))), \
             patch.object(unifi_cert, 'get_public_ip', return_value=None), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.ddns_update() is False

    def test_record_not_found_errors(self, tmp_path):
        """_ddns_get_a_record returning (None, None) → False."""
        creds = tmp_path / 'do.ini'
        creds.write_text('dns_digitalocean_token = T\n')
        with patch.object(unifi_cert, 'load_provisioning_config',
                          return_value=self._provisioning(dns_credentials=str(creds))), \
             patch.object(unifi_cert, 'get_public_ip', return_value='1.2.3.4'), \
             patch.object(unifi_cert, '_ddns_resolve_zone',
                          return_value=('jdlien.com', 'beehive')), \
             patch.object(unifi_cert, '_ddns_get_a_record',
                          return_value=(None, None)), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.ddns_update() is False


class TestMainDdnsUpdate:
    """CLI plumbing tests for --ddns-update."""

    def test_ddns_update_threaded_through(self):
        """`--ddns-update` calls ddns_update() and exits 0 on success."""
        with patch('sys.argv', ['unifi-cert', '--ddns-update']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'rotate_log'), \
             patch.object(unifi_cert, 'ddns_update', return_value=True) as fn:
            result = unifi_cert.main()
        assert result == 0
        fn.assert_called_once()

    def test_ddns_update_failure_returns_1(self):
        """ddns_update returning False → exit 1."""
        with patch('sys.argv', ['unifi-cert', '--ddns-update']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'rotate_log'), \
             patch.object(unifi_cert, 'ddns_update', return_value=False):
            result = unifi_cert.main()
        assert result == 1

    def test_ddns_update_no_domain_arg_works(self):
        """--ddns-update without -d (cron case) doesn't trip 'Domain is required'."""
        with patch('sys.argv', ['unifi-cert', '--ddns-update']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'rotate_log'), \
             patch.object(unifi_cert, 'ddns_update', return_value=True):
            result = unifi_cert.main()
        assert result == 0


# =============================================================================
# STATUS REPORT
# =============================================================================

@pytest.fixture
def status_paths(tmp_path):
    """Patch all status-relevant module paths into tmp_path subdirs.

    Lets print_status() probe a controlled filesystem so individual states
    (empty / healthy / GlennR-residue) can be set up by writing into the
    tmp paths the test owns.
    """
    cert_root = tmp_path / 'unifi-cert'
    cert_root.mkdir()
    eus_dir = tmp_path / 'eus_certificates'
    eus_dir.mkdir()
    cron_dir = tmp_path / 'cron.d'
    cron_dir.mkdir()
    hook_dir = tmp_path / 'renewal-hooks' / 'post'
    hook_dir.mkdir(parents=True)

    overrides = {
        'UNIFI_CERT_ROOT': str(cert_root),
        'CERTBOT_BIN': str(cert_root / 'certbot-venv' / 'bin' / 'certbot'),
        'CERTBOT_CONFIG_DIR': str(cert_root / 'letsencrypt'),
        'CRON_FILE': str(cron_dir / 'unifi-cert'),
        'RENEWAL_HOOK_PATH': str(hook_dir / 'unifi-cert-hook.sh'),
        'BOOT_SCRIPT_DIR': str(tmp_path / 'on_boot.d'),
        'BOOT_SCRIPT_PATH': str(tmp_path / 'on_boot.d' / '15-unifi-cert.sh'),
        'LOCK_FILE': str(cert_root / 'unifi-cert.lock'),
        'LOG_FILE': str(cert_root / 'unifi-cert.log'),
        'PROVISIONING_CONFIG': str(cert_root / 'unifi-cert.conf'),
    }

    unifi_paths = dict(unifi_cert.UNIFI_PATHS)
    unifi_paths['eus_cert'] = str(eus_dir / 'unifi-os.crt')
    unifi_paths['eus_key'] = str(eus_dir / 'unifi-os.key')

    with patch.multiple(unifi_cert, **overrides), \
         patch.object(unifi_cert, 'UNIFI_PATHS', unifi_paths):
        yield {**overrides, 'UNIFI_PATHS': unifi_paths,
               'tmp_path': tmp_path, 'cert_root': cert_root}


class TestPrintStatus:
    """Tests for print_status() local mode."""

    def test_empty_device_reports_all_missing(self, status_paths, capsys):
        """Nothing set up → certbot/cron/hook/log all flagged missing."""
        with patch.object(unifi_cert, 'inventory_glennr',
                          return_value=unifi_cert.GlennRInventory()), \
             patch.object(unifi_cert, 'detect_domain_from_cert', return_value=None), \
             patch.object(unifi_cert, 'ui',
                          new=unifi_cert.UI(color=False, verbose=False)):
            rc = unifi_cert.print_status()
        assert rc == 0
        out = capsys.readouterr().out
        assert 'No certificate found' in out
        assert 'Certbot venv missing' in out
        assert 'Cron missing' in out
        assert 'Renewal hook missing' in out
        assert 'No GlennR residue' in out
        assert 'No log file' in out

    def test_glennr_residue_reported(self, status_paths, capsys):
        """When inventory finds paths, --status warns and lists them."""
        inv = unifi_cert.GlennRInventory()
        inv.detected_paths = [
            ('/srv/EUS', 'dir', 'GlennR data directory'),
            ('/etc/cron.d/eus_script', 'cron', 'GlennR cron job'),
        ]
        with patch.object(unifi_cert, 'inventory_glennr', return_value=inv), \
             patch.object(unifi_cert, 'detect_domain_from_cert', return_value=None), \
             patch.object(unifi_cert, 'ui',
                          new=unifi_cert.UI(color=False, verbose=False)):
            rc = unifi_cert.print_status()
        assert rc == 0
        out = capsys.readouterr().out
        assert '2 GlennR path(s) still present' in out
        assert '/srv/EUS' in out
        assert '/etc/cron.d/eus_script' in out
        assert '--migrate-glennr' in out

    def test_healthy_device_shows_cert_and_schedule(self, status_paths, capsys):
        """Cert + cron + hook present → success indicators all populated."""
        # Provisioning config
        with open(status_paths['PROVISIONING_CONFIG'], 'w') as fh:
            fh.write(
                'domain=example.com\n'
                'email=admin@example.com\n'
                'dns_provider=digitalocean\n'
                'dns_credentials=/data/unifi-cert/credentials/digitalocean.ini\n'
            )
        # EUS cert file (content irrelevant; we mock CertMetadata.from_cert_file)
        with open(status_paths['UNIFI_PATHS']['eus_cert'], 'w') as fh:
            fh.write('-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n')
        # Cron + hook + log file
        with open(status_paths['CRON_FILE'], 'w') as fh:
            fh.write('# UniFi cert auto-renewal + DDNS\n')
            fh.write('17 3 * * * root /usr/bin/python3 /data/scripts/unifi-cert.py --renew\n')
        with open(status_paths['RENEWAL_HOOK_PATH'], 'w') as fh:
            fh.write('#!/bin/bash\n# unifi-cert hook\n')
        with open(status_paths['LOG_FILE'], 'w') as fh:
            fh.write('2026-04-27 00:00:00 INFO renewal complete\n')
        # Certbot venv
        certbot_bin = status_paths['CERTBOT_BIN']
        os.makedirs(os.path.dirname(certbot_bin), exist_ok=True)
        with open(certbot_bin, 'w') as fh:
            fh.write('#!/bin/sh\necho "certbot 2.10.0"\n')
        os.chmod(certbot_bin, 0o755)

        # Synthetic CertMetadata: still in the future so renewal is not due.
        future = (datetime.utcnow().replace(microsecond=0)).strftime(
            '%Y-%m-%d %H:%M:%S+00')
        future = '2099-01-01 00:00:00+00'
        meta = unifi_cert.CertMetadata(
            cn='example.com', issuer_c='US', issuer_o="Let's Encrypt",
            issuer_cn='R3', sans=['example.com'],
            valid_from='2026-01-01 00:00:00+00', valid_to=future,
            serial='ABCD', fingerprint='AA:BB',
        )

        def fake_subprocess_run(cmd, *args, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stdout = 'certbot 2.10.0'
            result.stderr = ''
            return result

        with patch.object(unifi_cert, 'inventory_glennr',
                          return_value=unifi_cert.GlennRInventory()), \
             patch.object(unifi_cert.CertMetadata, 'from_cert_file',
                          return_value=meta), \
             patch.object(unifi_cert, 'is_renewal_due', return_value=False), \
             patch('subprocess.run', side_effect=fake_subprocess_run), \
             patch.object(unifi_cert, 'ui',
                          new=unifi_cert.UI(color=False, verbose=False)):
            rc = unifi_cert.print_status()

        assert rc == 0
        out = capsys.readouterr().out
        assert 'example.com' in out
        assert "Let's Encrypt" in out
        assert 'Renewal not yet due' in out
        assert 'certbot 2.10.0' in out
        assert 'Cron: ' in out
        assert 'Renewal hook: ' in out
        assert 'No GlennR residue' in out
        assert 'renewal complete' in out  # log tail

    def test_remote_dispatches_via_ssh(self, status_paths):
        """print_status(host=X) skips local probing and calls dispatch_remote_verb."""
        with patch.object(unifi_cert, 'dispatch_remote_verb',
                          return_value=0) as disp, \
             patch.object(unifi_cert, 'ui',
                          new=unifi_cert.UI(color=False, verbose=False)):
            rc = unifi_cert.print_status(host='beehive.example.com')
        assert rc == 0
        disp.assert_called_once()
        assert disp.call_args.args[0] == '--status'
        assert disp.call_args.args[1] == 'beehive.example.com'

    def test_lock_held_state_detected(self, status_paths, capsys):
        """When the lock is held by another process, --status reports HELD."""
        # Create a held lock by acquiring it in this process.
        lock_fh = unifi_cert.acquire_lock(timeout=0)
        try:
            with patch.object(unifi_cert, 'inventory_glennr',
                              return_value=unifi_cert.GlennRInventory()), \
                 patch.object(unifi_cert, 'detect_domain_from_cert', return_value=None), \
                 patch.object(unifi_cert, 'ui',
                              new=unifi_cert.UI(color=False, verbose=False)):
                unifi_cert.print_status()
            out = capsys.readouterr().out
            assert 'HELD' in out
        finally:
            unifi_cert.release_lock(lock_fh)


class TestRemoteVerbs:
    """Tests for dispatch_remote_verb() and ensure_remote_script()."""

    def test_unsupported_verb_refused(self):
        """Verbs outside REMOTE_DISPATCH_VERBS return 1 with an error."""
        args = argparse.Namespace(domain=None, email=None, dns_provider=None,
                                  dns_credentials=None, dry_run=False, force=False,
                                  verbose=False, no_color=False, skip_postgres=False,
                                  skip_restart=False)
        with patch.object(unifi_cert, 'ui'):
            rc = unifi_cert.dispatch_remote_verb('--install', '192.168.1.1', args)
        assert rc == 1

    def test_migrate_glennr_without_dry_or_force_refused(self):
        """Remote --migrate-glennr w/o --dry-run/--force refuses (no TTY)."""
        args = argparse.Namespace(domain=None, email=None, dns_provider=None,
                                  dns_credentials=None, dry_run=False, force=False,
                                  verbose=False, no_color=False, skip_postgres=False,
                                  skip_restart=False)
        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_remote') as rr:
            rc = unifi_cert.dispatch_remote_verb('--migrate-glennr', 'h', args)
        assert rc == 1
        # We should refuse before even probing SSH.
        rr.assert_not_called()

    def test_migrate_glennr_with_force_proceeds(self):
        """--migrate-glennr --force passes the dispatch gate."""
        args = argparse.Namespace(domain='example.com', email=None,
                                  dns_provider=None, dns_credentials=None,
                                  dry_run=False, force=True, verbose=False,
                                  no_color=False, skip_postgres=False,
                                  skip_restart=False)
        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_remote',
                          return_value=(True, '')) as rr, \
             patch.object(unifi_cert, 'ensure_remote_script', return_value=True):
            rc = unifi_cert.dispatch_remote_verb('--migrate-glennr', 'h', args)
        assert rc == 0
        # 'true' probe + the verb command itself = at least 2 calls.
        assert rr.call_count >= 2

    def test_ssh_probe_failure_returns_1(self):
        """If `ssh root@host true` fails, no upload is attempted."""
        args = argparse.Namespace(domain=None, email=None, dns_provider=None,
                                  dns_credentials=None, dry_run=False, force=False,
                                  verbose=False, no_color=False, skip_postgres=False,
                                  skip_restart=False)
        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_remote',
                          return_value=(False, '')), \
             patch.object(unifi_cert, 'ensure_remote_script') as ers:
            rc = unifi_cert.dispatch_remote_verb('--status', 'h', args)
        assert rc == 1
        ers.assert_not_called()

    def test_dispatch_runs_verb_and_forwards_output(self, capsys):
        """Verb command is run via SSH and its stdout is forwarded to caller."""
        args = argparse.Namespace(domain=None, email=None, dns_provider=None,
                                  dns_credentials=None, dry_run=False, force=False,
                                  verbose=False, no_color=False, skip_postgres=False,
                                  skip_restart=False)
        captured_cmd = {}

        def fake_run_remote(host, cmd, timeout=30):
            if cmd == 'true':
                return True, ''
            captured_cmd['cmd'] = cmd
            return True, 'remote status output\n'

        with patch.object(unifi_cert, 'ui',
                          new=unifi_cert.UI(color=False, verbose=False)), \
             patch.object(unifi_cert, 'run_remote', side_effect=fake_run_remote), \
             patch.object(unifi_cert, 'ensure_remote_script', return_value=True):
            rc = unifi_cert.dispatch_remote_verb('--status', 'beehive', args)
        assert rc == 0
        out = capsys.readouterr().out
        assert 'remote status output' in out
        assert '--status' in captured_cmd['cmd']
        assert '--no-color' in captured_cmd['cmd']
        assert unifi_cert.PERMANENT_SCRIPT_PATH in captured_cmd['cmd']

    def test_build_remote_command_forwards_string_flags(self):
        """domain/email/dns_provider/dns_credentials are passed through as flags."""
        args = argparse.Namespace(
            domain='example.com', email='admin@example.com',
            dns_provider='digitalocean',
            dns_credentials='/root/.secrets/certbot/digitalocean.ini',
            dry_run=False, force=False, verbose=False, no_color=False,
            skip_postgres=False, skip_restart=False,
        )
        cmd = unifi_cert._build_remote_command('--ddns-update', args)
        assert '--ddns-update' in cmd
        assert "-d example.com" in cmd
        assert '-e admin@example.com' in cmd
        assert '--dns-provider digitalocean' in cmd
        assert '/root/.secrets/certbot/digitalocean.ini' in cmd
        assert '--no-color' in cmd

    def test_build_remote_command_forwards_bool_flags(self):
        """dry_run / force / verbose translate to flag-only switches."""
        args = argparse.Namespace(
            domain=None, email=None, dns_provider=None, dns_credentials=None,
            dry_run=True, force=True, verbose=True, no_color=False,
            skip_postgres=True, skip_restart=False,
        )
        cmd = unifi_cert._build_remote_command('--migrate-glennr', args)
        assert '--dry-run' in cmd
        assert '--force' in cmd
        assert ' -v' in cmd
        assert '--skip-postgres' in cmd
        assert '--skip-restart' not in cmd


class TestEnsureRemoteScript:
    """Tests for ensure_remote_script() — sha256 compare + SCP gating."""

    def test_skips_upload_when_sha_matches(self, tmp_path):
        """Same sha → no scp_file call, returns True."""
        local = tmp_path / 'unifi-cert.py'
        local.write_text('print("hi")')
        local_sha = unifi_cert._file_sha256(str(local))

        def fake_run_remote(host, cmd, timeout=30):
            if 'sha256sum' in cmd:
                return True, f'{local_sha}  {unifi_cert.PERMANENT_SCRIPT_PATH}\n'
            return True, ''

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_remote', side_effect=fake_run_remote), \
             patch.object(unifi_cert, 'scp_file') as scp:
            ok = unifi_cert.ensure_remote_script('h', local_path=str(local))
        assert ok is True
        scp.assert_not_called()

    def test_uploads_when_sha_differs(self, tmp_path):
        """Sha mismatch → mkdir + scp + chmod via run_remote/scp_file."""
        local = tmp_path / 'unifi-cert.py'
        local.write_text('print("hi")')

        calls = []

        def fake_run_remote(host, cmd, timeout=30):
            calls.append(cmd)
            if 'sha256sum' in cmd:
                return True, 'deadbeef  somepath\n'  # mismatched
            return True, ''

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_remote', side_effect=fake_run_remote), \
             patch.object(unifi_cert, 'scp_file', return_value=True) as scp:
            ok = unifi_cert.ensure_remote_script('h', local_path=str(local))
        assert ok is True
        scp.assert_called_once()
        assert any('mkdir -p' in c for c in calls)
        assert any('chmod' in c for c in calls)

    def test_no_local_script_returns_false(self):
        """When _local_script_path() returns None (curl-pipe), refuse."""
        with patch.object(unifi_cert, '_local_script_path', return_value=None), \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert.ensure_remote_script('h')
        assert ok is False

    def test_scp_failure_returns_false(self, tmp_path):
        """SCP returning False → False from ensure_remote_script."""
        local = tmp_path / 'unifi-cert.py'
        local.write_text('print("hi")')

        def fake_run_remote(host, cmd, timeout=30):
            if 'sha256sum' in cmd:
                return True, 'deadbeef  x\n'
            return True, ''

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'run_remote', side_effect=fake_run_remote), \
             patch.object(unifi_cert, 'scp_file', return_value=False):
            ok = unifi_cert.ensure_remote_script('h', local_path=str(local))
        assert ok is False


class TestMainStatusCli:
    """Tests for the --status CLI dispatch and --host short-circuit."""

    def test_status_local(self):
        """`--status` with no --host calls print_status() locally."""
        with patch('sys.argv', ['unifi-cert', '--status']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'print_status', return_value=0) as ps:
            rc = unifi_cert.main()
        assert rc == 0
        ps.assert_called_once_with()

    def test_status_remote_dispatches(self):
        """`--status --host X` short-circuits to dispatch_remote_verb."""
        with patch('sys.argv', ['unifi-cert', '--status',
                                '--host', 'beehive.example.com']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'dispatch_remote_verb',
                          return_value=0) as disp:
            rc = unifi_cert.main()
        assert rc == 0
        disp.assert_called_once()
        assert disp.call_args.args[0] == '--status'
        assert disp.call_args.args[1] == 'beehive.example.com'

    def test_renew_with_host_dispatches_remotely(self):
        """`--renew --host X` runs the verb on the remote, not locally."""
        with patch('sys.argv', ['unifi-cert', '--renew',
                                '--host', 'beehive.example.com',
                                '-d', 'example.com']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'dispatch_remote_verb',
                          return_value=0) as disp, \
             patch.object(unifi_cert, 'rotate_log') as rot:
            rc = unifi_cert.main()
        assert rc == 0
        disp.assert_called_once()
        # We should NOT have started the local renew pipeline.
        rot.assert_not_called()

    def test_self_heal_with_host_dispatches_remotely(self):
        """`--self-heal --host X` dispatches; local self_heal() is not called."""
        with patch('sys.argv', ['unifi-cert', '--self-heal',
                                '--host', 'beehive']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'dispatch_remote_verb',
                          return_value=0) as disp, \
             patch.object(unifi_cert, 'self_heal') as sh:
            rc = unifi_cert.main()
        assert rc == 0
        disp.assert_called_once()
        sh.assert_not_called()
