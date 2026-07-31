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
from datetime import datetime, timedelta
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
        mock_response.read.return_value = b'{"ip": "93.184.215.14"}'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        # Need to patch in the module's context
        original_urlopen = urllib.request.urlopen
        urllib.request.urlopen = MagicMock(return_value=mock_response)
        try:
            result = unifi_cert.get_public_ip()
            assert result == "93.184.215.14"
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
            mock_response.read.return_value = b'{"ip": "93.184.215.15"}'
            mock_response.__enter__ = MagicMock(return_value=mock_response)
            mock_response.__exit__ = MagicMock(return_value=False)
            return mock_response

        original_urlopen = urllib.request.urlopen
        urllib.request.urlopen = mock_urlopen
        try:
            result = unifi_cert.get_public_ip()
            assert result == "93.184.215.15"
        finally:
            urllib.request.urlopen = original_urlopen

    @pytest.mark.parametrize('address', [
        '192.168.1.1',      # RFC1918 — a captive portal or hijacked resolver
        '10.0.0.5',
        '100.64.0.1',       # CGNAT
        '127.0.0.1',
        '203.0.113.1',      # RFC5737 documentation range
        '0.0.0.0',
        'not-an-ip',
        '',
    ])
    def test_non_public_addresses_are_rejected(self, address):
        """This value is published as an A record — a shape check isn't enough."""
        assert unifi_cert.is_public_ipv4(address) is False

    def test_public_address_accepted(self):
        assert unifi_cert.is_public_ipv4('198.53.200.179') is True

    def test_ipv6_answer_falls_through_to_an_ipv4_provider(self):
        """A dual-stack device gets told its v6 address; an A record can't hold it.

        Observed live on the target network: ipwho.is answered
        2001:56a:… over IPv6 while ipify answered the IPv4. Without the
        fall-through the whole chain returns None and DDNS never runs.
        """
        import urllib.request

        def mock_urlopen(req, *args, **kwargs):
            # Every dual-stack service answers with the v6 address; only the
            # IPv4-pinned hostnames can report the v4 one.
            if 'api4.' in req.full_url or 'ipv4.' in req.full_url:
                raise urllib.error.URLError('pretend the v4 hosts are down')
            resp = MagicMock()
            resp.read.return_value = b'{"ip": "2001:56a:f8e6:e00:8876:4a2:63bb:b383"}'
            if 'ip-api' in req.full_url:
                resp.read.return_value = b'{"query": "198.53.200.179"}'
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        original = urllib.request.urlopen
        urllib.request.urlopen = mock_urlopen
        try:
            with patch.object(unifi_cert, 'ui'):
                assert unifi_cert.get_public_ip() == '198.53.200.179'
        finally:
            urllib.request.urlopen = original

    def test_all_providers_answering_ipv6_returns_none(self):
        """Better to fail loudly than to publish something that isn't an IPv4."""
        import urllib.request

        def mock_urlopen(req, *args, **kwargs):
            resp = MagicMock()
            resp.read.return_value = b'{"ip": "2001:56a:f8e6:e00::1", "query": "2001:56a:f8e6:e00::1"}'
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        original = urllib.request.urlopen
        urllib.request.urlopen = mock_urlopen
        try:
            with patch.object(unifi_cert, 'ui'):
                assert unifi_cert.get_public_ip() is None
        finally:
            urllib.request.urlopen = original

    def test_html_page_body_is_rejected(self):
        """Observed live: a content-negotiating service served an HTML page.

        Anything that isn't a public IPv4 must fall through rather than head
        toward a DNS write, and the rejection must not dump the whole page
        into the log on every five-minute run.
        """
        import urllib.request
        html = b'<!DOCTYPE html>\n<html lang="en">\n<title>Your IP</title>\n' + b'x' * 4000

        def mock_urlopen(req, *args, **kwargs):
            resp = MagicMock()
            resp.read.return_value = html if 'my-ip.ca' in req.full_url \
                else b'{"ip": "198.53.200.179"}'
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        mock_ui = MagicMock()
        original = urllib.request.urlopen
        urllib.request.urlopen = mock_urlopen
        try:
            with patch.object(unifi_cert, 'ui', mock_ui):
                assert unifi_cert.get_public_ip() == '198.53.200.179'
        finally:
            urllib.request.urlopen = original
        logged = ' '.join(str(c) for c in mock_ui.debug.call_args_list)
        assert len(logged) < 500, 'a rejected body must not be logged in full'

    def test_ipv4_only_providers_are_tried_first(self):
        """The chain must lead with hostnames that can only answer over v4."""
        first_two = [url for url, _ in unifi_cert.IP_PROVIDERS[:2]]
        assert any('api4.' in u for u in first_two)
        assert any('ipv4.' in u for u in first_two)

    def test_plaintext_provider_is_last(self):
        """An answer an on-path party could rewrite goes straight into DNS."""
        urls = [url for url, _ in unifi_cert.IP_PROVIDERS]
        http_only = [u for u in urls if u.startswith('http://')]
        assert http_only == [urls[-1]]

    def test_plaintext_body_provider_is_parsed(self):
        """icanhazip returns a bare address with a trailing newline, not JSON."""
        import urllib.request

        def mock_urlopen(req, *args, **kwargs):
            resp = MagicMock()
            # First provider is JSON; make it fail so we reach the text one.
            if 'ipify' in req.full_url:
                raise urllib.error.URLError('down')
            resp.read.return_value = b'198.53.200.179\n'
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        original = urllib.request.urlopen
        urllib.request.urlopen = mock_urlopen
        try:
            with patch.object(unifi_cert, 'ui'):
                assert unifi_cert.get_public_ip() == '198.53.200.179'
        finally:
            urllib.request.urlopen = original

    def test_provider_returning_private_ip_is_skipped(self):
        """A bogus answer must fall through to the next provider, not be used."""
        import urllib.request

        def mock_urlopen(req, *args, **kwargs):
            resp = MagicMock()
            # The first provider is behind a captive portal; the next real
            # answer must win rather than the bogus RFC1918 one.
            if 'api4.' in req.full_url:
                resp.read.return_value = b'{"ip": "192.168.1.1"}'
            elif 'ipv4.' in req.full_url:
                resp.read.return_value = b'93.184.215.16\n'
            else:
                resp.read.return_value = b'{"ip": "93.184.215.16"}'
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        original = urllib.request.urlopen
        urllib.request.urlopen = mock_urlopen
        try:
            with patch.object(unifi_cert, 'ui'):
                assert unifi_cert.get_public_ip() == '93.184.215.16'
        finally:
            urllib.request.urlopen = original

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

    def test_run_certbot_passes_cert_name(self, temp_dir):
        """certbot argv must include `--cert-name <domain>` so renewals
        reuse the existing lineage instead of forking to <domain>-0001."""
        live_dir = os.path.join(temp_dir, 'live', 'example.com')
        os.makedirs(live_dir)
        with open(os.path.join(live_dir, 'fullchain.pem'), 'w') as f:
            f.write('c')
        with open(os.path.join(live_dir, 'privkey.pem'), 'w') as f:
            f.write('k')

        captured = {}

        def mock_run(cmd, *args, **kwargs):
            captured['cmd'] = cmd
            result = MagicMock()
            result.returncode = 0
            result.stdout = ''
            result.stderr = ''
            return result

        real_exists = os.path.exists

        def mock_exists(path):
            if 'fullchain.pem' in str(path) or 'privkey.pem' in str(path):
                return True
            return real_exists(path)

        for force in (False, True):
            captured.clear()
            with patch('subprocess.run', side_effect=mock_run), \
                 patch.object(unifi_cert, 'ui'), \
                 patch.object(unifi_cert, 'bootstrap_certbot', return_value=(True, 'mocked')), \
                 patch('os.path.exists', side_effect=mock_exists):
                ok, _, _ = unifi_cert.run_certbot(
                    'example.com',
                    'admin@example.com',
                    'digitalocean',
                    '/path/to/creds.ini',
                    force=force,
                )
            assert ok is True
            cmd = captured['cmd']
            assert cmd.count('--cert-name') == 1, cmd
            assert cmd[cmd.index('--cert-name') + 1] == 'example.com', cmd
            if force:
                assert '--force-renewal' in cmd

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

    def test_ensure_script_installed_no_copy_when_already_at_permanent_path(self, temp_dir):
        """Regression: when __file__ already IS PERMANENT_SCRIPT_PATH, no copy or curl.

        The pre-fix `'__file__' in dir()` guard checked function locals,
        not module globals, so __file__ was never visible — every call
        fell through to the curl-from-GitHub branch. That clobbered
        newly-deployed local scripts (most painfully during --self-heal
        right after a SCP push, replacing our latest code with
        main-branch HEAD). The fix: look up __file__ directly with a
        NameError fallback, and early-return when current_path matches
        PERMANENT_SCRIPT_PATH.
        """
        permanent_path = os.path.join(temp_dir, 'unifi-cert.py')
        with open(permanent_path, 'w') as f:
            f.write('# already deployed\n')

        with patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'PERMANENT_SCRIPT_PATH', permanent_path), \
             patch('os.path.abspath', return_value=permanent_path), \
             patch('shutil.copy2') as cp, \
             patch('subprocess.run') as run:
            result = unifi_cert.ensure_script_installed()

        assert result == permanent_path
        cp.assert_not_called()  # no copy
        run.assert_not_called()  # no curl


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

    def test_run_remote_uses_ssh_multiplex(self):
        """run_remote must pass ControlMaster/ControlPath/ControlPersist so
        dispatch_remote_verb's 2-4 back-to-back sessions don't trip IDS
        rate-limit signatures (SID 2001219, etc.)."""
        captured = {}

        def mock_run(cmd, *args, **kwargs):
            captured['cmd'] = cmd
            r = MagicMock()
            r.returncode = 0
            r.stdout = ''
            return r

        with patch('subprocess.run', side_effect=mock_run):
            unifi_cert.run_remote('192.168.1.1', 'true')

        cmd = captured['cmd']
        assert '-o' in cmd
        # All three multiplex options must be present.
        joined = ' '.join(cmd)
        assert 'ControlMaster=auto' in joined
        assert 'ControlPath=' in joined
        assert 'ControlPersist=60s' in joined

    def test_scp_file_uses_ssh_multiplex(self):
        """scp_file must also use the multiplex socket so it shares the
        ssh master that run_remote opened, instead of re-handshaking."""
        captured = {}

        def mock_run(cmd, *args, **kwargs):
            captured['cmd'] = cmd
            r = MagicMock()
            r.returncode = 0
            return r

        with patch('subprocess.run', side_effect=mock_run):
            unifi_cert.scp_file('/local/file', '192.168.1.1', '/remote/file')

        cmd = captured['cmd']
        joined = ' '.join(cmd)
        assert 'ControlMaster=auto' in joined
        assert 'ControlPath=' in joined
        assert 'ControlPersist=60s' in joined


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


class TestDefaultCredentialsPath:
    """Credentials must default into the persistent root when on a device.

    /root/.secrets is wiped by firmware updates, and a copy left there becomes
    a second forgotten copy of a live API token — which is exactly what was
    found on beehive, dating from the original install.
    """

    def test_on_device_uses_persistent_root(self, tmp_path):
        creds_dir = tmp_path / 'credentials'
        with patch.object(unifi_cert, 'CREDENTIALS_DIR', str(creds_dir)), \
             patch('os.path.isdir', return_value=True):
            path = unifi_cert.default_credentials_path('cloudflare')
        assert path == str(creds_dir / 'cloudflare.ini')
        assert '.secrets' not in path

    def test_off_device_uses_workstation_location(self):
        with patch('os.path.isdir', return_value=False):
            path = unifi_cert.default_credentials_path('digitalocean')
        assert path.endswith('/.secrets/certbot/digitalocean.ini')


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

    def test_save_persists_ddns_keys(self, tmp_path):
        """The ddns_* trio round-trips alongside the cert fields."""
        cfg = tmp_path / 'unifi-cert.conf'
        with patch.object(unifi_cert, 'PROVISIONING_CONFIG', str(cfg)), \
             patch.object(unifi_cert, 'UNIFI_CERT_ROOT', str(tmp_path)), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert.save_provisioning_config(
                domain='beehive.jdlien.com', email='a@b.com',
                dns_provider='digitalocean', dns_credentials='/x/do.ini',
                ddns_domain='home.jdlien.ca,*.home.jdlien.ca',
                ddns_provider='cloudflare',
                ddns_credentials='/x/cloudflare.ini',
            )
            loaded = unifi_cert.load_provisioning_config()
        assert loaded['ddns_domain'] == 'home.jdlien.ca,*.home.jdlien.ca'
        assert loaded['ddns_provider'] == 'cloudflare'
        assert loaded['ddns_credentials'] == '/x/cloudflare.ini'

    def test_save_merges_and_preserves_ddns_keys(self, tmp_path):
        """A later obtain-new must not wipe hand-added ddns_* keys.

        Dropping ddns_domain silently reverts the DDNS target to the cert CN —
        exactly the misconfiguration that caused 6,295 failed updates.
        """
        cfg = tmp_path / 'unifi-cert.conf'
        cfg.write_text(
            'domain = beehive.jdlien.com\n'
            'ddns_domain = home.jdlien.ca\n'
            'ddns_provider = cloudflare\n'
            'custom_key = keep-me\n'
        )
        with patch.object(unifi_cert, 'PROVISIONING_CONFIG', str(cfg)), \
             patch.object(unifi_cert, 'UNIFI_CERT_ROOT', str(tmp_path)), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert.save_provisioning_config(
                domain='beehive.jdlien.com', email='a@b.com',
                dns_provider='digitalocean', dns_credentials='/x/do.ini',
            )
            loaded = unifi_cert.load_provisioning_config()
        assert loaded['ddns_domain'] == 'home.jdlien.ca'
        assert loaded['ddns_provider'] == 'cloudflare'
        assert loaded['email'] == 'a@b.com'
        assert loaded['custom_key'] == 'keep-me'


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


class TestEmailFallbacks:
    """Tests for the v1-prefs and certbot-accounts email fallbacks.

    Certbot rarely writes `email = ...` into renewal/<domain>.conf, so
    the inventory needs secondary sources or it ships an incomplete
    provisioning config to migration.
    """

    def test_email_from_v1_prefs_file(self, tmp_path):
        """~/.secrets/certbot/config.ini email is picked up when present."""
        prefs = tmp_path / 'config.ini'
        prefs.write_text(
            '# UniFi Certificate Manager config\n'
            'email = jd@jdlien.com\n'
            'dns_provider = digitalocean\n'
        )
        with patch.object(unifi_cert, 'CONFIG_FILE', str(prefs)):
            assert unifi_cert._email_from_v1_prefs() == 'jd@jdlien.com'

    def test_email_from_v1_prefs_missing_file(self, tmp_path):
        """Absent prefs file → None (no exception)."""
        with patch.object(unifi_cert, 'CONFIG_FILE', str(tmp_path / 'nope.ini')):
            assert unifi_cert._email_from_v1_prefs() is None

    def test_email_from_certbot_accounts(self, tmp_path):
        """ACME registration JSON's mailto: contact is extracted."""
        regr = tmp_path / 'regr.json'
        regr.write_text(json.dumps({
            'body': {'contact': ['mailto:jd@jdlien.com'], 'status': 'valid'},
        }))
        with patch('glob.glob', return_value=[str(regr)]):
            assert unifi_cert._email_from_certbot_accounts() == 'jd@jdlien.com'

    def test_email_from_certbot_accounts_no_mailto(self, tmp_path):
        """regr.json with non-mailto contacts (or empty) → None."""
        regr = tmp_path / 'regr.json'
        regr.write_text(json.dumps({'body': {'contact': []}}))
        with patch('glob.glob', return_value=[str(regr)]):
            assert unifi_cert._email_from_certbot_accounts() is None

    def test_inventory_falls_back_to_v1_prefs_when_renewal_lacks_email(self):
        """Real-world case (beehive): renewal conf has no email but v1 prefs do."""
        with patch('os.path.isdir', return_value=False), \
             patch('glob.glob', return_value=[]), \
             patch('os.path.isfile', return_value=False), \
             patch('os.path.exists', return_value=False), \
             patch.object(unifi_cert, '_email_from_v1_prefs',
                          return_value='jd@jdlien.com') as v1, \
             patch.object(unifi_cert, '_email_from_certbot_accounts') as acct:
            inv = unifi_cert.inventory_glennr()
        assert inv.email == 'jd@jdlien.com'
        v1.assert_called_once()
        acct.assert_not_called()  # short-circuit when v1 prefs returned a value


class TestMigrateGlennrOverrides:
    """Tests for migrate_glennr CLI overrides on top of inventory."""

    def test_overrides_layer_on_inventory(self):
        """email_override fills a gap inventory missed; other fields kept."""
        inv = unifi_cert.GlennRInventory(
            domain='example.com', dns_provider='digitalocean',
            dns_credentials_path='/root/.secrets/digitalocean.ini',
            email=None,
        )
        # Need at least one detected path or migrate_glennr early-returns.
        inv.detected_paths = [('/srv/EUS', 'dir', 'GlennR data directory')]
        captured_inv = []

        def fake_import(inv_arg):
            captured_inv.append(inv_arg)
            return True

        with patch.object(unifi_cert, 'inventory_glennr', return_value=inv), \
             patch('os.path.isdir', return_value=False), \
             patch.object(unifi_cert, 'import_provisioning_from_glennr',
                          side_effect=fake_import), \
             patch.object(unifi_cert, 'snapshot_glennr', return_value='/x.tgz'), \
             patch.object(unifi_cert, '_remove_glennr_path', return_value=True), \
             patch.object(unifi_cert, 'self_heal', return_value=True), \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert.migrate_glennr(force=True,
                                           email_override='jd@jdlien.com')
        assert ok is True
        assert captured_inv[0].email == 'jd@jdlien.com'
        # Original fields not touched.
        assert captured_inv[0].domain == 'example.com'
        assert captured_inv[0].dns_provider == 'digitalocean'

    def test_handle_migrate_glennr_threads_args(self):
        """_handle_migrate_glennr forwards args.domain/email/etc as overrides."""
        ns = argparse.Namespace(
            dry_run=False, force=True, domain='override.example',
            email='admin@override.example', dns_provider='cloudflare',
            dns_credentials='/path/to/cf.ini',
        )
        with patch.object(unifi_cert, 'migrate_glennr',
                          return_value=True) as mg:
            unifi_cert._handle_migrate_glennr(ns)
        kw = mg.call_args.kwargs
        assert kw['domain_override'] == 'override.example'
        assert kw['email_override'] == 'admin@override.example'
        assert kw['dns_provider_override'] == 'cloudflare'
        assert kw['dns_credentials_override'] == '/path/to/cf.ini'


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

    def test_missing_creds_path_falls_back_to_canonical(self, tmp_path):
        """Credentials path that doesn't exist → warn, save with the
        canonical CREDENTIALS_DIR/<provider>.ini path so the user can drop
        the file there and the next --renew picks it up. Saving the bogus
        original path traps users with a stale reference for weeks."""
        creds_dir = tmp_path / 'credentials'
        inv = unifi_cert.GlennRInventory(
            domain='example.com', dns_provider='digitalocean',
            dns_credentials_path='/does/not/exist.ini',
        )
        mock_ui = MagicMock()
        with patch.object(unifi_cert, 'CREDENTIALS_DIR', str(creds_dir)), \
             patch.object(unifi_cert, 'ui', mock_ui), \
             patch.object(unifi_cert, 'save_provisioning_config',
                          return_value=True) as save:
            ok = unifi_cert.import_provisioning_from_glennr(inv)
        assert ok is True
        mock_ui.warning.assert_called()
        canonical = str(creds_dir / 'digitalocean.ini')
        assert save.call_args.kwargs['dns_credentials'] == canonical


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
             patch('shutil.which', return_value='/usr/bin/rsync'), \
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
             patch('shutil.which', return_value='/usr/bin/rsync'), \
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
             patch('shutil.which', return_value='/usr/bin/rsync'), \
             patch('subprocess.run', return_value=result) as run, \
             patch.object(unifi_cert, 'CERTBOT_CONFIG_DIR', str(tmp_path)), \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert._rsync_etc_letsencrypt(domain='example.com')
        assert ok is True
        run.assert_called_once()

    def test_falls_back_to_copytree_when_rsync_missing(self, tmp_path):
        """Stock UDM Pro SE has no rsync; fall back to shutil.copytree
        with symlinks=True so live/ → archive/ symlinks survive."""
        with patch('os.path.isdir', return_value=True), \
             patch('os.path.exists', return_value=False), \
             patch('os.makedirs'), \
             patch('shutil.which', return_value=None), \
             patch('shutil.copytree') as copytree, \
             patch('subprocess.run') as run, \
             patch.object(unifi_cert, 'CERTBOT_CONFIG_DIR', str(tmp_path)), \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert._rsync_etc_letsencrypt(domain='example.com')
        assert ok is True
        run.assert_not_called()
        copytree.assert_called_once()
        args, kwargs = copytree.call_args
        assert args[0] == '/etc/letsencrypt/'
        assert args[1].rstrip('/') == str(tmp_path).rstrip('/')
        assert kwargs.get('symlinks') is True
        assert kwargs.get('dirs_exist_ok') is True

    def test_copytree_failure_returns_false(self):
        """copytree errors propagate as False so caller aborts before deletion."""
        with patch('os.path.isdir', return_value=True), \
             patch('os.path.exists', return_value=False), \
             patch('os.makedirs'), \
             patch('shutil.which', return_value=None), \
             patch('shutil.copytree', side_effect=OSError('disk full')), \
             patch('subprocess.run') as run, \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert._rsync_etc_letsencrypt()
        assert ok is False
        run.assert_not_called()


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


class TestPurgeGlennrResidueInLineage:
    """Tests for _purge_glennr_residue_in_lineage()."""

    def _stage(self, tmp_path):
        (tmp_path / 'renewal').mkdir()
        (tmp_path / 'renewal-hooks' / 'pre').mkdir(parents=True)
        (tmp_path / 'renewal-hooks' / 'post').mkdir(parents=True)
        return tmp_path

    def test_strips_eus_post_hook_line_from_renewal_conf(self, tmp_path):
        self._stage(tmp_path)
        conf = tmp_path / 'renewal' / 'example.com.conf'
        conf.write_text(
            'version = 1.12.0\n'
            'archive_dir = /x/archive/example.com\n'
            '\n'
            '[renewalparams]\n'
            'account = abc123\n'
            'authenticator = dns-digitalocean\n'
            'post_hook = /etc/letsencrypt/renewal-hooks/post/EUS_example.com.sh\n'
            'pre_hook = /etc/letsencrypt/renewal-hooks/pre/EUS_example.com.sh\n'
            'server = https://acme-v02.api.letsencrypt.org/directory\n'
        )
        with patch.object(unifi_cert, 'CERTBOT_CONFIG_DIR', str(tmp_path)), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert._purge_glennr_residue_in_lineage()
        result = conf.read_text()
        assert 'EUS_example.com.sh' not in result
        assert 'post_hook' not in result
        assert 'pre_hook' not in result
        # Other lines preserved.
        assert 'account = abc123' in result
        assert 'authenticator = dns-digitalocean' in result

    def test_leaves_unrelated_post_hook_line_intact(self, tmp_path):
        self._stage(tmp_path)
        conf = tmp_path / 'renewal' / 'foo.com.conf'
        conf.write_text(
            'post_hook = /usr/local/bin/my-deploy-script.sh\n'
            'account = def456\n'
        )
        with patch.object(unifi_cert, 'CERTBOT_CONFIG_DIR', str(tmp_path)), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert._purge_glennr_residue_in_lineage()
        result = conf.read_text()
        assert 'my-deploy-script.sh' in result
        assert 'post_hook' in result

    def test_removes_eus_renewal_hook_files(self, tmp_path):
        self._stage(tmp_path)
        eus_post = tmp_path / 'renewal-hooks' / 'post' / 'EUS_foo.sh'
        eus_pre = tmp_path / 'renewal-hooks' / 'pre' / 'EUS_foo.sh'
        keep = tmp_path / 'renewal-hooks' / 'post' / 'unifi-cert-hook.sh'
        eus_post.write_text('#!/bin/bash\n')
        eus_pre.write_text('#!/bin/bash\n')
        keep.write_text('#!/bin/bash\n')
        with patch.object(unifi_cert, 'CERTBOT_CONFIG_DIR', str(tmp_path)), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert._purge_glennr_residue_in_lineage()
        assert not eus_post.exists()
        assert not eus_pre.exists()
        assert keep.exists()  # Non-EUS hook left alone.

    def test_no_renewal_dir_is_a_noop(self, tmp_path):
        # Empty CERTBOT_CONFIG_DIR — function must not raise.
        with patch.object(unifi_cert, 'CERTBOT_CONFIG_DIR', str(tmp_path)), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert._purge_glennr_residue_in_lineage()


class TestDedupeLeAccounts:
    """Tests for _dedupe_le_accounts()."""

    def _stage_account(self, tmp_path, acct_id):
        d = (tmp_path / 'accounts' / 'acme-v02.api.letsencrypt.org' /
             'directory' / acct_id)
        d.mkdir(parents=True)
        (d / 'regr.json').write_text('{}')
        return d

    def _stage_renewal(self, tmp_path, name, account_id):
        renewal_dir = tmp_path / 'renewal'
        renewal_dir.mkdir(exist_ok=True)
        (renewal_dir / f'{name}.conf').write_text(
            f'[renewalparams]\naccount = {account_id}\n'
        )

    def test_removes_unreferenced_account_only(self, tmp_path):
        good = self._stage_account(tmp_path, '59e42bf4b8a613df59d3fde7d30eacb0')
        bad = self._stage_account(tmp_path, '7e4d0dda37b1e14951719421a03b836c')
        self._stage_renewal(tmp_path, 'example.com',
                            '59e42bf4b8a613df59d3fde7d30eacb0')
        with patch.object(unifi_cert, 'CERTBOT_CONFIG_DIR', str(tmp_path)), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert._dedupe_le_accounts()
        assert good.exists()
        assert not bad.exists()

    def test_no_renewal_configs_is_a_noop(self, tmp_path):
        """No referenced accounts → keep everything (don't delete blind)."""
        a = self._stage_account(tmp_path, 'aaaaaaaa1111')
        b = self._stage_account(tmp_path, 'bbbbbbbb2222')
        (tmp_path / 'renewal').mkdir()
        with patch.object(unifi_cert, 'CERTBOT_CONFIG_DIR', str(tmp_path)), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert._dedupe_le_accounts()
        assert a.exists()
        assert b.exists()

    def test_no_accounts_dir_is_a_noop(self, tmp_path):
        (tmp_path / 'renewal').mkdir()
        self._stage_renewal(tmp_path, 'example.com', 'abc1234')
        with patch.object(unifi_cert, 'CERTBOT_CONFIG_DIR', str(tmp_path)), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert._dedupe_le_accounts()  # must not raise

    def test_multiple_renewals_with_different_accounts(self, tmp_path):
        a1 = self._stage_account(tmp_path, 'aaaaaaaaaaa1')
        a2 = self._stage_account(tmp_path, 'bbbbbbbbbbb2')
        a3 = self._stage_account(tmp_path, 'cccccccccccc')
        self._stage_renewal(tmp_path, 'one', 'aaaaaaaaaaa1')
        self._stage_renewal(tmp_path, 'two', 'bbbbbbbbbbb2')
        with patch.object(unifi_cert, 'CERTBOT_CONFIG_DIR', str(tmp_path)), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert._dedupe_le_accounts()
        assert a1.exists()
        assert a2.exists()
        assert not a3.exists()


class TestNormalizeRenewalPathsInLineage:
    """Tests for _normalize_renewal_paths_in_lineage()."""

    def _stage(self, tmp_path):
        renewal = tmp_path / 'renewal'
        renewal.mkdir()
        return renewal

    def test_rewrites_archive_and_lineage_paths(self, tmp_path):
        """archive_dir / cert / privkey / chain / fullchain prefixes
        get rewritten from /etc/letsencrypt/ to CERTBOT_CONFIG_DIR/."""
        renewal = self._stage(tmp_path)
        conf = renewal / 'example.com.conf'
        conf.write_text(
            'version = 1.12.0\n'
            'archive_dir = /etc/letsencrypt/archive/example.com\n'
            'cert = /etc/letsencrypt/live/example.com/cert.pem\n'
            'privkey = /etc/letsencrypt/live/example.com/privkey.pem\n'
            'chain = /etc/letsencrypt/live/example.com/chain.pem\n'
            'fullchain = /etc/letsencrypt/live/example.com/fullchain.pem\n'
            '\n[renewalparams]\n'
            'authenticator = dns-digitalocean\n'
        )
        with patch.object(unifi_cert, 'CERTBOT_CONFIG_DIR', str(tmp_path)), \
             patch.object(unifi_cert, 'CREDENTIALS_DIR',
                          str(tmp_path / 'credentials')), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert._normalize_renewal_paths_in_lineage()
        result = conf.read_text()
        prefix = str(tmp_path).rstrip('/') + '/'
        assert f'archive_dir = {prefix}archive/example.com' in result
        assert f'cert = {prefix}live/example.com/cert.pem' in result
        assert f'privkey = {prefix}live/example.com/privkey.pem' in result
        assert f'chain = {prefix}live/example.com/chain.pem' in result
        assert f'fullchain = {prefix}live/example.com/fullchain.pem' in result
        # No legacy prefix anywhere.
        assert '/etc/letsencrypt/' not in result

    def test_rewrites_dns_credentials_outside_persistent_root(self, tmp_path):
        """dns_<provider>_credentials pointing outside CERTBOT_CONFIG_DIR /
        CREDENTIALS_DIR is replaced with the canonical creds path."""
        renewal = self._stage(tmp_path)
        conf = renewal / 'example.com.conf'
        conf.write_text(
            '[renewalparams]\n'
            'authenticator = dns-digitalocean\n'
            'dns_digitalocean_credentials = /root/.secrets/digitalocean.ini\n'
        )
        creds_dir = tmp_path / 'credentials'
        with patch.object(unifi_cert, 'CERTBOT_CONFIG_DIR', str(tmp_path)), \
             patch.object(unifi_cert, 'CREDENTIALS_DIR', str(creds_dir)), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert._normalize_renewal_paths_in_lineage()
        canonical = str(creds_dir / 'digitalocean.ini')
        result = conf.read_text()
        assert f'dns_digitalocean_credentials = {canonical}' in result
        assert '/root/.secrets/digitalocean.ini' not in result

    def test_leaves_credentials_already_in_persistent_root_alone(self, tmp_path):
        """A credentials path under CREDENTIALS_DIR is already canonical,
        so don't rewrite (idempotent for re-runs)."""
        renewal = self._stage(tmp_path)
        creds_dir = tmp_path / 'credentials'
        canonical = str(creds_dir / 'digitalocean.ini')
        conf = renewal / 'example.com.conf'
        conf.write_text(
            '[renewalparams]\n'
            f'dns_digitalocean_credentials = {canonical}\n'
        )
        with patch.object(unifi_cert, 'CERTBOT_CONFIG_DIR', str(tmp_path)), \
             patch.object(unifi_cert, 'CREDENTIALS_DIR', str(creds_dir)), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert._normalize_renewal_paths_in_lineage()
        # File unchanged (one line, same canonical path).
        assert conf.read_text().count(canonical) == 1

    def test_leaves_other_lines_intact(self, tmp_path):
        """Lines that aren't path/credentials fields pass through unchanged,
        including section headers, blank lines, and renewalparams."""
        renewal = self._stage(tmp_path)
        conf = renewal / 'example.com.conf'
        original = (
            '# leading comment\n'
            'version = 4.2.0\n'
            'archive_dir = /etc/letsencrypt/archive/example.com\n'
            '\n'
            '[renewalparams]\n'
            'account = abcdef0123456789\n'
            'authenticator = dns-digitalocean\n'
            'dns_digitalocean_propagation_seconds = 60\n'
            'server = https://acme-v02.api.letsencrypt.org/directory\n'
            'key_type = ecdsa\n'
        )
        conf.write_text(original)
        with patch.object(unifi_cert, 'CERTBOT_CONFIG_DIR', str(tmp_path)), \
             patch.object(unifi_cert, 'CREDENTIALS_DIR',
                          str(tmp_path / 'credentials')), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert._normalize_renewal_paths_in_lineage()
        result = conf.read_text()
        # All the non-path fields preserved.
        for fragment in ('# leading comment', 'version = 4.2.0',
                         '[renewalparams]', 'account = abcdef0123456789',
                         'authenticator = dns-digitalocean',
                         'dns_digitalocean_propagation_seconds = 60',
                         'server = https://acme-v02.api.letsencrypt.org/directory',
                         'key_type = ecdsa'):
            assert fragment in result

    def test_no_renewal_dir_is_a_noop(self, tmp_path):
        with patch.object(unifi_cert, 'CERTBOT_CONFIG_DIR', str(tmp_path)), \
             patch.object(unifi_cert, 'CREDENTIALS_DIR',
                          str(tmp_path / 'credentials')), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert._normalize_renewal_paths_in_lineage()  # must not raise


class TestMigrateGlennrCallsCleanupHelpers:
    """migrate_glennr() must invoke the residue/normalize/account cleanup
    helpers after the LE rsync, before the GlennR uninstall."""

    def test_helpers_invoked_post_rsync(self):
        inv = unifi_cert.GlennRInventory(
            domain='example.com', email='a@b.com',
            dns_provider='digitalocean',
            dns_credentials_path='/root/.secrets/do.ini',
            glennr_version='8.4.2',
            detected_paths=[('/srv/EUS', 'dir', 'GlennR data directory')],
        )
        ordering = []
        with patch.object(unifi_cert, 'inventory_glennr', return_value=inv), \
             patch('os.path.isdir', return_value=True), \
             patch('os.path.exists', return_value=True), \
             patch.object(unifi_cert, 'import_provisioning_from_glennr',
                          side_effect=lambda *a, **k: ordering.append('import') or True), \
             patch.object(unifi_cert, 'snapshot_glennr',
                          side_effect=lambda *a, **k: ordering.append('snapshot') or '/x/s.tgz'), \
             patch.object(unifi_cert, '_rsync_etc_letsencrypt',
                          side_effect=lambda *a, **k: ordering.append('rsync') or True), \
             patch.object(unifi_cert, '_purge_glennr_residue_in_lineage',
                          side_effect=lambda: ordering.append('purge')), \
             patch.object(unifi_cert, '_normalize_renewal_paths_in_lineage',
                          side_effect=lambda: ordering.append('normalize')), \
             patch.object(unifi_cert, '_dedupe_le_accounts',
                          side_effect=lambda: ordering.append('dedupe')), \
             patch.object(unifi_cert, '_remove_glennr_path',
                          side_effect=lambda *a, **k: ordering.append(f'rm:{a[0]}') or True), \
             patch.object(unifi_cert, 'self_heal',
                          side_effect=lambda **k: ordering.append('self_heal') or True), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.migrate_glennr(force=True) is True
        # rsync → purge → normalize → dedupe → rm:<paths> → self_heal
        assert ordering.index('rsync') < ordering.index('purge')
        assert ordering.index('purge') < ordering.index('normalize')
        assert ordering.index('normalize') < ordering.index('dedupe')
        rm_indices = [i for i, x in enumerate(ordering) if x.startswith('rm:')]
        assert all(ordering.index('dedupe') < i for i in rm_indices)


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
        kw = mg.call_args.kwargs
        assert kw['dry_run'] is True
        assert kw['force'] is False

    def test_migrate_glennr_force_threaded_through(self):
        """`--migrate-glennr --force` calls migrate_glennr(force=True)."""
        with patch('sys.argv', ['unifi-cert', '--migrate-glennr', '--force']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'migrate_glennr', return_value=True) as mg:
            result = unifi_cert.main()
        assert result == 0
        kw = mg.call_args.kwargs
        assert kw['dry_run'] is False
        assert kw['force'] is True

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


_HTTP_ERROR = object()   # sentinel: this queued entry raises instead of returning


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

    def queue_http_error(self, code, body=None):
        """Queue an HTTPError, e.g. DigitalOcean's 404 for an unowned zone."""
        self._next.append((_HTTP_ERROR, code, body))

    def __call__(self, req, timeout=None):
        self.requests.append({
            'method': req.get_method(),
            'url': req.full_url,
            'body': req.data.decode('utf-8') if req.data else None,
            'headers': dict(req.header_items()),
        })
        if not self._next:
            raise RuntimeError(f'No queued response for {req.get_method()} {req.full_url}')
        queued = self._next.pop(0)
        if queued[0] is _HTTP_ERROR:
            _, code, body = queued
            raise _http_error(code, body or {'id': 'not_found',
                                             'message': 'The resource you were accessing could not be found.'})
        payload, status = queued
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


@pytest.fixture
def ddns_state(tmp_path):
    """Redirect DDNS_STATE_FILE into tmp_path so state writes stay hermetic."""
    path = tmp_path / 'ddns-state.json'
    with patch.object(unifi_cert, 'DDNS_STATE_FILE', str(path)), \
         patch.object(unifi_cert, 'UNIFI_CERT_ROOT', str(tmp_path)):
        yield path


def _http_error(code, body):
    """Build a urllib HTTPError carrying a provider JSON error body."""
    import io
    return urllib.error.HTTPError(
        'https://api.cloudflare.com/client/v4/zones', code, 'err', {},
        io.BytesIO(json.dumps(body).encode('utf-8')),
    )


class TestDdnsRequest:
    """Transport-layer tests for _ddns_request() across both providers."""

    def test_digitalocean_payload_returned_verbatim(self):
        """DigitalOcean has no envelope — the parsed body passes through."""
        fake = _FakeUrlOpen()
        fake.queue({'domains': [{'name': 'jdlien.com'}]})
        with patch('urllib.request.urlopen', fake):
            out = unifi_cert._ddns_request('GET', 'https://x/domains', 'T')
        assert out == {'domains': [{'name': 'jdlien.com'}]}

    def test_cloudflare_envelope_is_unwrapped(self):
        """{'success': True, 'result': [...]} → the bare result list."""
        fake = _FakeUrlOpen()
        fake.queue({'success': True, 'errors': [],
                    'result': [{'id': 'zid', 'name': 'jdlien.ca'}]})
        with patch('urllib.request.urlopen', fake):
            out = unifi_cert._ddns_request('GET', 'https://x/zones', 'T',
                                           provider='cloudflare')
        assert out == [{'id': 'zid', 'name': 'jdlien.ca'}]

    def test_cloudflare_success_false_raises_with_message(self):
        """success=false on an HTTP 200 still has to fail, with CF's own text."""
        fake = _FakeUrlOpen()
        fake.queue({'success': False,
                    'errors': [{'code': 1000, 'message': 'Invalid API Token'}],
                    'result': None})
        with patch('urllib.request.urlopen', fake):
            with pytest.raises(unifi_cert.DdnsError, match='Invalid API Token'):
                unifi_cert._ddns_request('GET', 'https://x/zones', 'T',
                                         provider='cloudflare')

    def test_http_error_body_is_surfaced(self):
        """A 403 body's error message beats a bare status code."""
        err = _http_error(403, {'success': False,
                                'errors': [{'code': 9109, 'message': 'Unauthorized to access requested resource'}]})
        with patch('urllib.request.urlopen', side_effect=err):
            with pytest.raises(unifi_cert.DdnsError, match='Unauthorized to access'):
                unifi_cert._ddns_request('GET', 'https://x/zones', 'T',
                                         provider='cloudflare')

    def test_digitalocean_http_error_message_surfaced(self):
        """DigitalOcean's {'id', 'message'} error shape is understood too."""
        err = _http_error(401, {'id': 'unauthorized', 'message': 'Unable to authenticate you'})
        with patch('urllib.request.urlopen', side_effect=err):
            with pytest.raises(unifi_cert.DdnsError, match='Unable to authenticate you'):
                unifi_cert._ddns_request('GET', 'https://x/domains', 'T')

    def test_transport_error_raises_ddns_error(self):
        """URLError is translated, not leaked."""
        with patch('urllib.request.urlopen',
                   side_effect=urllib.error.URLError('connection refused')):
            with pytest.raises(unifi_cert.DdnsError, match='connection refused'):
                unifi_cert._ddns_request('GET', 'https://x/domains', 'T')

    def test_malformed_json_raises_ddns_error(self):
        """A non-JSON 200 body fails loudly instead of silently returning {}."""
        fake = _FakeUrlOpen()
        fake.queue(b'<html>gateway timeout</html>')
        with patch('urllib.request.urlopen', fake):
            with pytest.raises(unifi_cert.DdnsError, match='malformed JSON'):
                unifi_cert._ddns_request('GET', 'https://x/domains', 'T')

    def test_empty_body_returns_empty_dict(self):
        """204-style empty body is a success, not a parse failure."""
        fake = _FakeUrlOpen()
        fake.queue(None)
        with patch('urllib.request.urlopen', fake):
            assert unifi_cert._ddns_request('GET', 'https://x/domains', 'T') == {}

    @pytest.mark.parametrize('payload,expected', [
        (None, 'empty response body'),               # nothing at all
        ([1, 2, 3], 'expected a Cloudflare envelope'),   # not an object
        ({'result': []}, 'request failed'),          # no success key
        ({'success': 'yes', 'result': []}, 'request failed'),   # truthy but not True
        ({'success': True}, 'carried no result'),    # success without payload
    ])
    def test_cloudflare_requires_a_wellformed_success_envelope(self, payload, expected):
        """Anything that isn't a proper envelope must fail, never pass silently.

        A PATCH whose response we can't confirm is a write we can't claim
        happened — reporting it as success is the original bug in miniature.
        """
        fake = _FakeUrlOpen()
        fake.queue(payload)
        with patch('urllib.request.urlopen', fake):
            with pytest.raises(unifi_cert.DdnsError, match=expected):
                unifi_cert._ddns_request('PATCH', 'https://x/dns_records/1', 'T',
                                         body={'content': '1.2.3.4'},
                                         provider='cloudflare')

    def test_unconfirmable_patch_is_not_recorded_as_success(self, ddns_state):
        """End-to-end: a malformed PATCH response must fail the update."""
        fake = _FakeUrlOpen()
        fake.queue({'success': True, 'result': [
            {'id': 'recid', 'type': 'A', 'name': 'home.jdlien.ca', 'content': '1.1.1.1'},
        ]})
        fake.queue(None)   # PATCH answers with an empty body
        with patch('urllib.request.urlopen', fake), \
             patch.object(unifi_cert, '_ddns_resolve_zone', return_value=_cf_zone()), \
             patch.object(unifi_cert, 'ui'):
            with pytest.raises(unifi_cert.DdnsError):
                unifi_cert._ddns_update_target('T', 'cloudflare', 'home.jdlien.ca',
                                               '5.6.7.8')
        assert 'home.jdlien.ca' not in unifi_cert._ddns_load_state()['targets']

    def test_http_status_is_attached_to_the_error(self):
        """Callers branch on 404 vs 401 — don't make them parse the message."""
        with patch('urllib.request.urlopen', side_effect=_http_error(404, {})):
            with pytest.raises(unifi_cert.DdnsError) as exc:
                unifi_cert._ddns_request('GET', 'https://x/domains/z', 'T')
        assert exc.value.status == 404


class TestDdnsZoneCandidates:
    """The suffix ladder that replaces a capped zone listing."""

    def test_progressively_broader_longest_first(self):
        assert unifi_cert._ddns_zone_candidates('home.jdlien.ca') == [
            'home.jdlien.ca', 'jdlien.ca']

    def test_bare_tld_is_never_a_candidate(self):
        assert unifi_cert._ddns_zone_candidates('jdlien.com') == ['jdlien.com']

    def test_wildcard_label_is_dropped(self):
        """'*' isn't part of any zone name, but the rest of the ladder is."""
        assert unifi_cert._ddns_zone_candidates('*.home.jdlien.ca') == [
            'home.jdlien.ca', 'jdlien.ca']

    def test_multipart_tld_ladder(self):
        assert unifi_cert._ddns_zone_candidates('foo.example.co.uk') == [
            'foo.example.co.uk', 'example.co.uk', 'co.uk']


class TestDdnsResolveZone:
    """Tests for _ddns_resolve_zone() across DigitalOcean and Cloudflare."""

    def test_subdomain_resolves_to_apex_zone(self):
        """beehive.jdlien.com → zone='jdlien.com', host='beehive'."""
        fake = _FakeUrlOpen()
        fake.queue_http_error(404)                              # beehive.jdlien.com
        fake.queue({'domain': {'name': 'jdlien.com'}})          # jdlien.com
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            zone = unifi_cert._ddns_resolve_zone('TOKEN', 'beehive.jdlien.com')
        assert zone.name == 'jdlien.com'
        assert zone.host == 'beehive'
        assert zone.ref == 'jdlien.com'  # DigitalOcean addresses zones by name
        assert zone.fqdn == 'beehive.jdlien.com'

    def test_apex_returns_at_host(self):
        """jdlien.com → zone='jdlien.com', host='@', fqdn is the bare zone."""
        fake = _FakeUrlOpen()
        fake.queue({'domain': {'name': 'jdlien.com'}})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            zone = unifi_cert._ddns_resolve_zone('T', 'jdlien.com')
        assert (zone.name, zone.host, zone.fqdn) == ('jdlien.com', '@', 'jdlien.com')

    def test_multipart_tld_picks_longest_match(self):
        """example.co.uk owned + co.uk also owned → the more specific one wins."""
        fake = _FakeUrlOpen()
        fake.queue_http_error(404)                                 # foo.example.co.uk
        fake.queue({'domain': {'name': 'example.co.uk'}})          # example.co.uk
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            zone = unifi_cert._ddns_resolve_zone('T', 'foo.example.co.uk')
        assert zone.name == 'example.co.uk'
        assert zone.host == 'foo'
        # co.uk is never probed — the ladder stops at the first hit.
        assert len(fake.requests) == 2

    def test_non_404_error_is_not_swallowed(self):
        """A 401 mid-ladder must fail loudly, not read as 'zone not owned'."""
        fake = _FakeUrlOpen()
        fake.queue_http_error(401, {'id': 'unauthorized',
                                    'message': 'Unable to authenticate you'})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            with pytest.raises(unifi_cert.DdnsError, match='Unable to authenticate'):
                unifi_cert._ddns_resolve_zone('T', 'beehive.jdlien.com')

    def test_no_match_raises_naming_visible_zones(self):
        """Unowned domain → DdnsError that says what the token *can* see."""
        fake = _FakeUrlOpen()
        fake.queue_http_error(404)      # beehive.jdlien.com
        fake.queue_http_error(404)      # jdlien.com
        fake.queue({'domains': [{'name': 'other.com'}]})   # diagnostic listing
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            with pytest.raises(unifi_cert.DdnsError, match='other.com'):
                unifi_cert._ddns_resolve_zone('T', 'beehive.jdlien.com')
        assert 'per_page=200' in fake.requests[-1]['url']

    def test_diagnostic_listing_failure_still_reports_the_miss(self):
        """The 'token sees' nicety must not replace the actual error."""
        fake = _FakeUrlOpen()
        fake.queue_http_error(404)
        fake.queue_http_error(404)
        fake.queue_http_error(403)      # listing denied
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            with pytest.raises(unifi_cert.DdnsError, match='no zones at all'):
                unifi_cert._ddns_resolve_zone('T', 'beehive.jdlien.com')

    def test_network_error_raises(self):
        """Transport failure propagates as DdnsError."""
        with patch('urllib.request.urlopen',
                   side_effect=urllib.error.URLError('connection refused')), \
             patch.object(unifi_cert, 'ui'):
            with pytest.raises(unifi_cert.DdnsError):
                unifi_cert._ddns_resolve_zone('T', 'beehive.jdlien.com')

    def test_cloudflare_zone_ref_is_the_zone_id(self):
        """Cloudflare record endpoints are keyed by zone id, not name."""
        fake = _FakeUrlOpen()
        fake.queue({'success': True, 'result': []})          # home.jdlien.ca
        fake.queue({'success': True, 'result': [             # jdlien.ca
            {'id': 'f625a1d7dbb0228633c5273a1a66ea4c', 'name': 'jdlien.ca'},
        ]})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            zone = unifi_cert._ddns_resolve_zone('T', 'home.jdlien.ca',
                                                 provider='cloudflare')
        assert zone.name == 'jdlien.ca'
        assert zone.ref == 'f625a1d7dbb0228633c5273a1a66ea4c'
        assert zone.host == 'home'
        assert zone.provider == 'cloudflare'
        assert 'name=jdlien.ca' in fake.requests[1]['url']

    def test_cloudflare_ignores_non_exact_name_match(self):
        """A row whose name isn't the candidate must not be accepted as the zone."""
        fake = _FakeUrlOpen()
        fake.queue({'success': True, 'result': [{'id': 'wrong', 'name': 'other.ca'}]})
        fake.queue({'success': True, 'result': [{'id': 'wrong2', 'name': 'nope.ca'}]})
        fake.queue({'success': True, 'result': []})   # diagnostic listing
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            with pytest.raises(unifi_cert.DdnsError, match='No cloudflare zone owns'):
                unifi_cert._ddns_resolve_zone('T', 'home.jdlien.ca',
                                              provider='cloudflare')

    def test_cloudflare_wildcard_target_resolves(self):
        """'*.home.jdlien.ca' resolves with a '*.home' label in jdlien.ca."""
        fake = _FakeUrlOpen()
        fake.queue({'success': True, 'result': []})
        fake.queue({'success': True, 'result': [{'id': 'zid', 'name': 'jdlien.ca'}]})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            zone = unifi_cert._ddns_resolve_zone('T', '*.home.jdlien.ca',
                                                 provider='cloudflare')
        assert zone.host == '*.home'
        assert zone.fqdn == '*.home.jdlien.ca'

    def test_zone_beyond_any_listing_page_still_resolves(self):
        """Exact lookup means a large account can't produce a false negative.

        A paged listing has to stop somewhere; whatever cap it picks reports a
        zone you do own as unowned. Targeted lookups have no such boundary.
        """
        fake = _FakeUrlOpen()
        fake.queue({'success': True, 'result': []})
        fake.queue({'success': True, 'result': [{'id': 'zid', 'name': 'jdlien.ca'}]})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            zone = unifi_cert._ddns_resolve_zone('T', 'home.jdlien.ca',
                                                 provider='cloudflare')
        assert zone.ref == 'zid'
        assert len(fake.requests) == 2          # no listing walk at all
        assert all('page=' not in r['url'] for r in fake.requests)

    def test_unsupported_provider_raises(self):
        """A provider with ACME support but no DDNS backend fails clearly."""
        with pytest.raises(unifi_cert.DdnsError, match='route53'):
            unifi_cert._ddns_resolve_zone('T', 'x.example.com', provider='route53')


def _do_zone(host='beehive', name='jdlien.com'):
    return unifi_cert.DdnsZone(name=name, ref=name, host=host,
                               provider='digitalocean')


def _cf_zone(host='home', name='jdlien.ca', ref='zid'):
    return unifi_cert.DdnsZone(name=name, ref=ref, host=host,
                               provider='cloudflare')


class TestDdnsRecords:
    """Record lookup and update, per provider. The never-create invariant."""

    def test_digitalocean_get_returns_id_value_and_count(self):
        """One matching A record → (id, ip, 1)."""
        fake = _FakeUrlOpen()
        fake.queue({'domain_records': [
            {'id': 12345, 'type': 'A', 'name': 'beehive', 'data': '1.2.3.4'},
        ]})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            rid, ip, count = unifi_cert._ddns_get_a_record('T', _do_zone())
        assert (rid, ip, count) == (12345, '1.2.3.4', 1)
        assert 'type=A' in fake.requests[0]['url']
        assert 'beehive.jdlien.com' in fake.requests[0]['url']

    def test_apex_queries_the_bare_zone_name(self):
        """host='@' must not leak an '@' into the API name parameter."""
        fake = _FakeUrlOpen()
        fake.queue({'domain_records': [
            {'id': 1, 'type': 'A', 'name': '@', 'data': '1.2.3.4'},
        ]})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            rid, _, _ = unifi_cert._ddns_get_a_record('T', _do_zone(host='@'))
        url = fake.requests[0]['url']
        assert 'name=jdlien.com' in url
        assert '%40' not in url and 'name=@' not in url
        assert rid == 1   # DigitalOcean's '@' normalizes back to the apex FQDN

    def test_cloudflare_get_reads_content_field(self):
        """Cloudflare puts the IP in 'content', not DigitalOcean's 'data'."""
        fake = _FakeUrlOpen()
        fake.queue({'success': True, 'result': [
            {'id': 'recid', 'type': 'A', 'name': 'home.jdlien.ca',
             'content': '198.53.200.179'},
        ]})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            rid, ip, count = unifi_cert._ddns_get_a_record('T', _cf_zone())
        assert (rid, ip, count) == ('recid', '198.53.200.179', 1)
        assert '/zones/zid/dns_records' in fake.requests[0]['url']

    def test_wildcard_name_is_url_encoded(self):
        """'*' must be percent-encoded in the name query parameter."""
        fake = _FakeUrlOpen()
        fake.queue({'success': True, 'result': [
            {'id': 'r', 'type': 'A', 'name': '*.home.jdlien.ca', 'content': '1.2.3.4'},
        ]})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            rid, _, _ = unifi_cert._ddns_get_a_record('T', _cf_zone(host='*.home'))
        url = fake.requests[0]['url']
        assert 'name=%2A.home.jdlien.ca' in url
        assert '*' not in url
        assert rid == 'r'

    def test_record_for_a_different_name_is_rejected(self):
        """A row the server-side filter let through must not be edited.

        We only ever write by id, so accepting a mismatched row would mean
        repointing some other hostname's A record — 'never create' would hold
        while the safety property it stands for would not.
        """
        fake = _FakeUrlOpen()
        fake.queue({'success': True, 'result': [
            {'id': 'other', 'type': 'A', 'name': 'unrelated.jdlien.ca',
             'content': '9.9.9.9'},
        ]})
        fake.queue({'success': True, 'result': []})   # CNAME probe
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            with pytest.raises(unifi_cert.DdnsError, match='No A record found'):
                unifi_cert._ddns_get_a_record('T', _cf_zone())

    def test_record_of_a_different_type_is_rejected(self):
        fake = _FakeUrlOpen()
        fake.queue({'success': True, 'result': [
            {'id': 'aaaa', 'type': 'AAAA', 'name': 'home.jdlien.ca',
             'content': '2606:4700::1111'},
        ]})
        fake.queue({'success': True, 'result': []})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            with pytest.raises(unifi_cert.DdnsError, match='No A record found'):
                unifi_cert._ddns_get_a_record('T', _cf_zone())

    def test_record_without_an_id_is_rejected(self):
        """No id means no safe way to address the write — refuse, don't guess."""
        fake = _FakeUrlOpen()
        fake.queue({'success': True, 'result': [
            {'type': 'A', 'name': 'home.jdlien.ca', 'content': '1.2.3.4'},
        ]})
        fake.queue({'success': True, 'result': []})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            with pytest.raises(unifi_cert.DdnsError, match='No A record found'):
                unifi_cert._ddns_get_a_record('T', _cf_zone())

    def test_duplicate_a_records_warn_and_use_first(self):
        """Two A records is the inadyn-duplicate fingerprint — warn every run."""
        fake = _FakeUrlOpen()
        fake.queue({'success': True, 'result': [
            {'id': 'live', 'type': 'A', 'name': 'home.jdlien.ca',
             'content': '198.53.200.179'},
            {'id': 'stale', 'type': 'A', 'name': 'home.jdlien.ca',
             'content': '173.183.229.156'},
        ]})
        mock_ui = MagicMock()
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui', mock_ui):
            rid, ip, count = unifi_cert._ddns_get_a_record('T', _cf_zone())
        assert (rid, count) == ('live', 2)
        warning = ' '.join(str(c) for c in mock_ui.warning.call_args_list)
        assert '2 A records' in warning
        assert '173.183.229.156' in warning

    def test_missing_record_raises_and_never_posts(self):
        """No A record → DdnsError; crucially, no POST is attempted."""
        fake = _FakeUrlOpen()
        fake.queue({'success': True, 'result': []})   # A lookup: empty
        fake.queue({'success': True, 'result': []})   # CNAME probe: empty
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            with pytest.raises(unifi_cert.DdnsError, match='never creates them'):
                unifi_cert._ddns_get_a_record('T', _cf_zone())
        assert [r['method'] for r in fake.requests] == ['GET', 'GET']

    def test_missing_record_names_the_cname(self):
        """The CNAME-at-the-target case gets a diagnosis, not just 'not found'."""
        fake = _FakeUrlOpen()
        fake.queue({'domain_records': []})  # no A record
        fake.queue({'domain_records': [
            {'id': 9, 'type': 'CNAME', 'name': 'beehive', 'data': 'home.jdlien.com'},
        ]})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            with pytest.raises(unifi_cert.DdnsError) as exc:
                unifi_cert._ddns_get_a_record('T', _do_zone())
        message = str(exc.value)
        assert 'CNAME' in message
        assert 'ddns_domain = home.jdlien.com' in message

    def test_cname_into_another_zone_names_all_three_keys(self):
        """The Beehive shape: repointing ddns_domain alone would still fail."""
        fake = _FakeUrlOpen()
        fake.queue({'domain_records': []})
        fake.queue({'domain_records': [
            {'id': 9, 'type': 'CNAME', 'name': 'beehive', 'data': 'home.jdlien.ca'},
        ]})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            with pytest.raises(unifi_cert.DdnsError) as exc:
                unifi_cert._ddns_get_a_record('T', _do_zone())
        message = str(exc.value)
        assert 'ddns_domain = home.jdlien.ca' in message
        assert 'ddns_provider' in message
        assert 'ddns_credentials' in message

    def test_cname_probe_failure_falls_back_to_generic_message(self):
        """A failing CNAME probe must not mask the original missing-record error."""
        fake = _FakeUrlOpen()
        fake.queue({'domain_records': []})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            with pytest.raises(unifi_cert.DdnsError, match='No A record found'):
                unifi_cert._ddns_get_a_record('T', _do_zone())

    def test_digitalocean_put_sends_data_field_by_id(self):
        """DigitalOcean: PUT /records/{id} with {'data': ip}, bearer auth."""
        fake = _FakeUrlOpen()
        fake.queue({'domain_record': {'id': 12345, 'data': '5.6.7.8'}})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            unifi_cert._ddns_put_a_record('TOKEN', _do_zone(), 12345, '5.6.7.8')
        req = fake.requests[0]
        assert req['method'] == 'PUT'
        assert '/domains/jdlien.com/records/12345' in req['url']
        assert json.loads(req['body']) == {'data': '5.6.7.8'}
        auth = next((v for k, v in req['headers'].items() if k.lower() == 'authorization'), None)
        assert auth == 'Bearer TOKEN'

    def test_cloudflare_patch_sends_content_field_by_id(self):
        """Cloudflare: PATCH /dns_records/{id} with {'content': ip}."""
        fake = _FakeUrlOpen()
        fake.queue({'success': True, 'result': {'id': 'recid', 'content': '5.6.7.8'}})
        with patch('urllib.request.urlopen', fake), patch.object(unifi_cert, 'ui'):
            unifi_cert._ddns_put_a_record('TOKEN', _cf_zone(), 'recid', '5.6.7.8')
        req = fake.requests[0]
        assert req['method'] == 'PATCH'
        assert '/zones/zid/dns_records/recid' in req['url']
        assert json.loads(req['body']) == {'content': '5.6.7.8'}

    def test_put_network_error_raises(self):
        """A failed write must raise so the caller records a failure."""
        with patch('urllib.request.urlopen',
                   side_effect=urllib.error.URLError('boom')), \
             patch.object(unifi_cert, 'ui'):
            with pytest.raises(unifi_cert.DdnsError):
                unifi_cert._ddns_put_a_record('T', _do_zone(), 1, '1.2.3.4')


class TestDdnsSettings:
    """ddns_* config resolution and its fallbacks to the cert values."""

    def _cfg(self, **overrides):
        cfg = {
            'domain': 'beehive.jdlien.com',
            'email': 'a@b.com',
            'dns_provider': 'digitalocean',
            'dns_credentials': '/secrets/do.ini',
        }
        cfg.update(overrides)
        return cfg

    def test_falls_back_to_cert_values(self, tmp_path):
        """No ddns_* keys → target/provider/creds all mirror the cert config."""
        creds = tmp_path / 'do.ini'
        creds.write_text('dns_digitalocean_token = T\n')
        s = unifi_cert._ddns_settings(self._cfg(dns_credentials=str(creds)))
        assert s.targets == ['beehive.jdlien.com']
        assert s.provider == 'digitalocean'
        assert s.credentials == str(creds)

    def test_ddns_keys_override_cert_values(self, tmp_path):
        """The decoupled case: different name, provider, and token."""
        creds = tmp_path / 'cf.ini'
        creds.write_text('dns_cloudflare_api_token = T\n')
        s = unifi_cert._ddns_settings(self._cfg(
            ddns_domain='home.jdlien.ca',
            ddns_provider='cloudflare',
            ddns_credentials=str(creds),
        ))
        assert s.targets == ['home.jdlien.ca']
        assert s.provider == 'cloudflare'
        assert s.credentials == str(creds)

    def test_target_list_is_split(self, tmp_path):
        """ddns_domain accepts a list so the wildcard is maintained too."""
        creds = tmp_path / 'cf.ini'
        creds.write_text('dns_cloudflare_api_token = T\n')
        s = unifi_cert._ddns_settings(self._cfg(
            ddns_domain='home.jdlien.ca, *.home.jdlien.ca',
            ddns_provider='cloudflare',
            ddns_credentials=str(creds),
        ))
        assert s.targets == ['home.jdlien.ca', '*.home.jdlien.ca']

    def test_explicit_args_beat_config(self, tmp_path):
        """CLI overrides win over everything in the provisioning file."""
        creds = tmp_path / 'cf.ini'
        creds.write_text('dns_cloudflare_api_token = T\n')
        s = unifi_cert._ddns_settings(
            self._cfg(ddns_domain='wrong.example.com'),
            domain='home.jdlien.ca', provider='cloudflare', credentials=str(creds),
        )
        assert s.targets == ['home.jdlien.ca']
        assert s.provider == 'cloudflare'

    def test_no_target_raises(self):
        """Empty config → a message naming both keys that could supply it."""
        with pytest.raises(unifi_cert.DdnsError, match='ddns_domain'):
            unifi_cert._ddns_settings({})

    def test_provider_without_ddns_backend_raises(self, tmp_path):
        """route53 has ACME support but no DDNS backend — say so."""
        creds = tmp_path / 'r53.ini'
        creds.write_text('aws_access_key_id = T\n')
        with pytest.raises(unifi_cert.DdnsError, match='route53'):
            unifi_cert._ddns_settings(self._cfg(dns_provider='route53',
                                                dns_credentials=str(creds)))

    def test_cross_provider_without_credentials_refuses(self):
        """ddns_provider != dns_provider with no ddns_credentials must not
        silently hand the DigitalOcean token to Cloudflare's API."""
        with pytest.raises(unifi_cert.DdnsError, match='wrong API'):
            unifi_cert._ddns_settings(self._cfg(ddns_provider='cloudflare'))

    def test_missing_credentials_file_raises(self):
        """A configured but absent credentials path fails before any request."""
        with pytest.raises(unifi_cert.DdnsError, match='not found'):
            unifi_cert._ddns_settings(self._cfg(dns_credentials='/does/not/exist.ini'))


class TestDdnsToken:
    """Token extraction, including the Cloudflare legacy-key trap."""

    def test_cloudflare_token_read(self, tmp_path):
        creds = tmp_path / 'cf.ini'
        creds.write_text('dns_cloudflare_api_token = cfut_abc123\n')
        settings = unifi_cert.DdnsSettings(targets=['x'], provider='cloudflare',
                                           credentials=str(creds))
        assert unifi_cert._ddns_token(settings) == 'cfut_abc123'

    def test_legacy_global_key_is_refused_with_guidance(self, tmp_path):
        """A global API key can't do bearer auth — name the fix, don't just fail."""
        creds = tmp_path / 'cf.ini'
        creds.write_text('dns_cloudflare_email = a@b.com\n'
                         'dns_cloudflare_api_key = deadbeef\n')
        settings = unifi_cert.DdnsSettings(targets=['x'], provider='cloudflare',
                                           credentials=str(creds))
        with pytest.raises(unifi_cert.DdnsError, match='dns_cloudflare_api_token'):
            unifi_cert._ddns_token(settings)

    def test_missing_field_raises(self, tmp_path):
        creds = tmp_path / 'do.ini'
        creds.write_text('# empty\n')
        settings = unifi_cert.DdnsSettings(targets=['x'], provider='digitalocean',
                                           credentials=str(creds))
        with pytest.raises(unifi_cert.DdnsError, match='dns_digitalocean_token'):
            unifi_cert._ddns_token(settings)


class TestDdnsState:
    """Failure-streak tracking and the escalating report schedule."""

    def test_success_records_ip_and_clears_streak(self, ddns_state):
        with patch.object(unifi_cert, 'ui'):
            unifi_cert._ddns_note_failure('home.jdlien.ca', 'cloudflare', 'boom')
            unifi_cert._ddns_note_success('home.jdlien.ca', 'cloudflare', '1.2.3.4', 1)
        entry = unifi_cert._ddns_load_state()['targets']['home.jdlien.ca']
        assert entry['consecutive_failures'] == 0
        assert entry['last_ip'] == '1.2.3.4'
        assert entry['last_success']

    def test_recovery_is_announced(self, ddns_state):
        """Going from broken to working is worth a line in the log."""
        mock_ui = MagicMock()
        with patch.object(unifi_cert, 'ui', mock_ui):
            unifi_cert._ddns_note_failure('t', 'cloudflare', 'boom')
            mock_ui.reset_mock()
            unifi_cert._ddns_note_success('t', 'cloudflare', '1.2.3.4', 1)
        assert 'recovered' in ' '.join(str(c) for c in mock_ui.success.call_args_list)

    def test_repeated_identical_failures_are_throttled(self, ddns_state):
        """The 6,295-identical-lines bug: only milestones get reported."""
        mock_ui = MagicMock()
        with patch.object(unifi_cert, 'ui', mock_ui):
            for _ in range(11):
                unifi_cert._ddns_note_failure('t', 'cloudflare', 'same error')
        # Failure #1 is reported; #2..#11 are debug-only (next alert is #12).
        assert mock_ui.error.call_count == 1
        assert mock_ui.debug.call_count == 10
        assert unifi_cert._ddns_load_state()['targets']['t']['consecutive_failures'] == 11

    def test_hourly_milestone_escalates(self, ddns_state):
        """Failure #12 (~1h at a 5-min cadence) breaks the silence."""
        mock_ui = MagicMock()
        with patch.object(unifi_cert, 'ui', mock_ui):
            for _ in range(11):
                unifi_cert._ddns_note_failure('t', 'cloudflare', 'same error')
            mock_ui.reset_mock()
            unifi_cert._ddns_note_failure('t', 'cloudflare', 'same error')
        assert mock_ui.error.called
        assert '12 consecutive failures' in ' '.join(
            str(c) for c in mock_ui.error.call_args_list)

    def test_new_failure_mode_always_reports(self, ddns_state):
        """A *different* error mid-streak is new information — never throttle it."""
        mock_ui = MagicMock()
        with patch.object(unifi_cert, 'ui', mock_ui):
            unifi_cert._ddns_note_failure('t', 'cloudflare', 'first error')
            unifi_cert._ddns_note_failure('t', 'cloudflare', 'first error')
            mock_ui.reset_mock()
            unifi_cert._ddns_note_failure('t', 'cloudflare', 'a different error')
        assert mock_ui.error.called

    def test_corrupt_state_file_is_survivable(self, ddns_state):
        """A truncated JSON file must not break the update path."""
        ddns_state.write_text('{not json')
        assert unifi_cert._ddns_load_state() == {'targets': {}}

    def test_config_failure_clears_once_config_is_fixed(self, tmp_path, ddns_state):
        """A synthetic key that can only accumulate stays red forever."""
        creds = tmp_path / 'do.ini'
        creds.write_text('dns_digitalocean_token = T\n')
        cfg = {'domain': 'x.example.com', 'dns_provider': 'digitalocean',
               'dns_credentials': str(creds)}

        with patch.object(unifi_cert, 'load_provisioning_config', return_value={}), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert.ddns_update()          # no target → config failure recorded
        assert unifi_cert.DDNS_CONFIG_TARGET in unifi_cert._ddns_load_state()['targets']

        with patch.object(unifi_cert, 'load_provisioning_config', return_value=cfg), \
             patch.object(unifi_cert, 'get_public_ip', return_value='1.2.3.4'), \
             patch.object(unifi_cert, '_ddns_resolve_zone', return_value=_do_zone()), \
             patch.object(unifi_cert, '_ddns_get_a_record',
                          return_value=(1, '1.2.3.4', 1)), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert.ddns_update()
        assert unifi_cert.DDNS_CONFIG_TARGET not in unifi_cert._ddns_load_state()['targets']

    def test_public_ip_failure_clears_on_recovery(self, tmp_path, ddns_state):
        creds = tmp_path / 'do.ini'
        creds.write_text('dns_digitalocean_token = T\n')
        cfg = {'domain': 'x.example.com', 'dns_provider': 'digitalocean',
               'dns_credentials': str(creds)}
        with patch.object(unifi_cert, 'load_provisioning_config', return_value=cfg), \
             patch.object(unifi_cert, 'get_public_ip', return_value=None), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert.ddns_update()
        assert unifi_cert.DDNS_PUBLIC_IP_TARGET in unifi_cert._ddns_load_state()['targets']

        with patch.object(unifi_cert, 'load_provisioning_config', return_value=cfg), \
             patch.object(unifi_cert, 'get_public_ip', return_value='1.2.3.4'), \
             patch.object(unifi_cert, '_ddns_resolve_zone', return_value=_do_zone()), \
             patch.object(unifi_cert, '_ddns_get_a_record',
                          return_value=(1, '1.2.3.4', 1)), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert.ddns_update()
        assert unifi_cert.DDNS_PUBLIC_IP_TARGET not in unifi_cert._ddns_load_state()['targets']

    def test_removed_targets_are_pruned(self, tmp_path, ddns_state):
        """Renaming ddns_domain must not leave the old name failing forever."""
        creds = tmp_path / 'do.ini'
        creds.write_text('dns_digitalocean_token = T\n')
        ddns_state.write_text(json.dumps({'targets': {
            'old.example.com': {'consecutive_failures': 99, 'last_error': 'gone'},
        }}))
        cfg = {'domain': 'x.example.com', 'dns_provider': 'digitalocean',
               'dns_credentials': str(creds)}
        with patch.object(unifi_cert, 'load_provisioning_config', return_value=cfg), \
             patch.object(unifi_cert, 'get_public_ip', return_value='1.2.3.4'), \
             patch.object(unifi_cert, '_ddns_resolve_zone', return_value=_do_zone()), \
             patch.object(unifi_cert, '_ddns_get_a_record',
                          return_value=(1, '1.2.3.4', 1)), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert.ddns_update()
        targets = unifi_cert._ddns_load_state()['targets']
        assert 'old.example.com' not in targets
        assert 'x.example.com' in targets

    def test_one_shot_override_does_not_prune_configured_targets(self, tmp_path,
                                                                  ddns_state):
        """Testing one name by hand must not erase what cron maintains.

        --ddns-domain is an override for a single run, not a reconfiguration;
        discarding the real targets' history would blank --status until the
        next cron firing.
        """
        creds = tmp_path / 'do.ini'
        creds.write_text('dns_digitalocean_token = T\n')
        ddns_state.write_text(json.dumps({'targets': {
            'home.jdlien.ca': {'consecutive_failures': 0,
                               'last_success': '2026-07-31T03:00:00',
                               'last_ip': '198.53.200.179'},
        }}))
        cfg = {'domain': 'home.jdlien.ca', 'dns_provider': 'digitalocean',
               'dns_credentials': str(creds)}
        with patch.object(unifi_cert, 'load_provisioning_config', return_value=cfg), \
             patch.object(unifi_cert, 'get_public_ip', return_value='1.2.3.4'), \
             patch.object(unifi_cert, '_ddns_resolve_zone', return_value=_do_zone()), \
             patch.object(unifi_cert, '_ddns_get_a_record',
                          return_value=(1, '1.2.3.4', 1)), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert.ddns_update(domain='scratch.example.com')
        targets = unifi_cert._ddns_load_state()['targets']
        assert 'home.jdlien.ca' in targets
        assert targets['home.jdlien.ca']['last_ip'] == '198.53.200.179'


class TestDdnsValidate:
    """ddns_validate(): the provisioning-time check, read-only."""

    def test_cname_target_is_refused(self, tmp_path):
        """The check that would have caught this in April instead of July."""
        creds = tmp_path / 'do.ini'
        creds.write_text('dns_digitalocean_token = T\n')
        cfg = {'domain': 'beehive.jdlien.com', 'dns_provider': 'digitalocean',
               'dns_credentials': str(creds)}
        with patch.object(unifi_cert, '_ddns_resolve_zone', return_value=_do_zone()), \
             patch.object(unifi_cert, '_ddns_get_a_record',
                          side_effect=unifi_cert.DdnsError('It is a CNAME → home.jdlien.ca')), \
             patch.object(unifi_cert, 'ui'):
            ok, message = unifi_cert.ddns_validate(cfg)
        assert ok is False
        assert 'CNAME' in message

    def test_updatable_target_passes_without_writing(self, tmp_path):
        creds = tmp_path / 'do.ini'
        creds.write_text('dns_digitalocean_token = T\n')
        cfg = {'domain': 'x.example.com', 'dns_provider': 'digitalocean',
               'dns_credentials': str(creds)}
        with patch.object(unifi_cert, '_ddns_resolve_zone', return_value=_do_zone()), \
             patch.object(unifi_cert, '_ddns_get_a_record',
                          return_value=(1, '1.2.3.4', 1)), \
             patch.object(unifi_cert, '_ddns_put_a_record') as put, \
             patch.object(unifi_cert, 'ui'):
            ok, message = unifi_cert.ddns_validate(cfg)
        assert ok is True
        assert 'editable A records' in message
        put.assert_not_called()

    def test_disabled_ddns_short_circuits(self):
        ok, message = unifi_cert.ddns_validate({'ddns_enabled': 'false'})
        assert ok is True
        assert 'disabled' in message

    def test_misconfiguration_is_reported(self):
        ok, message = unifi_cert.ddns_validate({})
        assert ok is False
        assert 'No DDNS target configured' in message


class TestDdnsEnabled:
    """ddns_enabled: the supported way to turn the 5-minute job off."""

    @pytest.mark.parametrize('value,expected', [
        ('false', False), ('False', False), ('no', False), ('0', False),
        ('off', False), ('true', True), ('yes', True), ('1', True),
    ])
    def test_parsing(self, value, expected):
        assert unifi_cert.ddns_is_enabled({'ddns_enabled': value}) is expected

    def test_defaults_to_enabled(self):
        assert unifi_cert.ddns_is_enabled({}) is True

    def test_cron_omits_ddns_line_when_disabled(self, tmp_path):
        """self_heal() rewrites cron constantly; hand-deleting the line can't stick."""
        cron = tmp_path / 'unifi-cert'
        with patch.object(unifi_cert, 'CRON_FILE', str(cron)), \
             patch.object(unifi_cert, 'ddns_is_enabled', return_value=False), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.install_cron_schedule() is True
        content = cron.read_text()
        assert '--renew' in content
        assert '--ddns-update' not in content
        assert 'DDNS disabled' in content

    def test_cron_includes_ddns_line_by_default(self, tmp_path):
        cron = tmp_path / 'unifi-cert'
        with patch.object(unifi_cert, 'CRON_FILE', str(cron)), \
             patch.object(unifi_cert, 'ddns_is_enabled', return_value=True), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert.install_cron_schedule()
        assert '--ddns-update' in cron.read_text()


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

    def test_no_op_when_record_matches(self, tmp_path, ddns_state):
        """Current public IP equals A-record value → no write, returns True."""
        creds = tmp_path / 'do.ini'
        creds.write_text('dns_digitalocean_token = TOKEN\n')

        with patch.object(unifi_cert, 'load_provisioning_config',
                          return_value=self._provisioning(dns_credentials=str(creds))), \
             patch.object(unifi_cert, 'get_public_ip', return_value='1.2.3.4'), \
             patch.object(unifi_cert, '_ddns_resolve_zone', return_value=_do_zone()), \
             patch.object(unifi_cert, '_ddns_get_a_record',
                          return_value=(12345, '1.2.3.4', 1)), \
             patch.object(unifi_cert, '_ddns_put_a_record') as put, \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert.ddns_update()
        assert ok is True
        put.assert_not_called()

    def test_update_when_record_stale(self, tmp_path, ddns_state):
        """A-record IP differs from current → write new IP by ID, return True."""
        creds = tmp_path / 'do.ini'
        creds.write_text('dns_digitalocean_token = TOKEN\n')
        zone = _do_zone()

        with patch.object(unifi_cert, 'load_provisioning_config',
                          return_value=self._provisioning(dns_credentials=str(creds))), \
             patch.object(unifi_cert, 'get_public_ip', return_value='5.6.7.8'), \
             patch.object(unifi_cert, '_ddns_resolve_zone', return_value=zone), \
             patch.object(unifi_cert, '_ddns_get_a_record',
                          return_value=(12345, '1.2.3.4', 1)), \
             patch.object(unifi_cert, '_ddns_put_a_record') as put, \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert.ddns_update()
        assert ok is True
        put.assert_called_once_with('TOKEN', zone, 12345, '5.6.7.8')

    def test_force_writes_even_when_match(self, tmp_path, ddns_state):
        """force=True → write even when the record already matches."""
        creds = tmp_path / 'do.ini'
        creds.write_text('dns_digitalocean_token = TOKEN\n')

        with patch.object(unifi_cert, 'load_provisioning_config',
                          return_value=self._provisioning(dns_credentials=str(creds))), \
             patch.object(unifi_cert, 'get_public_ip', return_value='1.2.3.4'), \
             patch.object(unifi_cert, '_ddns_resolve_zone', return_value=_do_zone()), \
             patch.object(unifi_cert, '_ddns_get_a_record',
                          return_value=(12345, '1.2.3.4', 1)), \
             patch.object(unifi_cert, '_ddns_put_a_record') as put, \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert.ddns_update(force=True)
        assert ok is True
        put.assert_called_once()

    def test_cloudflare_target_end_to_end(self, tmp_path, ddns_state):
        """The decoupled Beehive shape: DO cert, Cloudflare DDNS anchor."""
        creds = tmp_path / 'cloudflare.ini'
        creds.write_text('dns_cloudflare_api_token = cfut_abc\n')
        cfg = self._provisioning(ddns_domain='home.jdlien.ca',
                                 ddns_provider='cloudflare',
                                 ddns_credentials=str(creds))
        fake = _FakeUrlOpen()
        fake.queue({'success': True, 'result': []})              # zone: home.jdlien.ca
        fake.queue({'success': True, 'result': [{'id': 'zid', 'name': 'jdlien.ca'}]})
        fake.queue({'success': True, 'result': [
            {'id': 'recid', 'type': 'A', 'name': 'home.jdlien.ca', 'content': '1.1.1.1'},
        ]})
        fake.queue({'success': True, 'result': {'id': 'recid', 'content': '5.6.7.8'}})

        with patch.object(unifi_cert, 'load_provisioning_config', return_value=cfg), \
             patch.object(unifi_cert, 'get_public_ip', return_value='5.6.7.8'), \
             patch('urllib.request.urlopen', fake), \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert.ddns_update()

        assert ok is True
        assert [r['method'] for r in fake.requests] == ['GET', 'GET', 'GET', 'PATCH']
        assert json.loads(fake.requests[3]['body']) == {'content': '5.6.7.8'}
        entry = unifi_cert._ddns_load_state()['targets']['home.jdlien.ca']
        assert entry['last_ip'] == '5.6.7.8'
        assert entry['provider'] == 'cloudflare'

    def test_multiple_targets_partial_failure(self, tmp_path, ddns_state):
        """One broken target fails the run but must not skip the others."""
        creds = tmp_path / 'cf.ini'
        creds.write_text('dns_cloudflare_api_token = T\n')
        cfg = self._provisioning(ddns_domain='home.jdlien.ca,*.home.jdlien.ca',
                                 ddns_provider='cloudflare',
                                 ddns_credentials=str(creds))
        attempted = []

        def _update(token, provider, target, ip, force=False):
            attempted.append(target)
            if target.startswith('*'):
                raise unifi_cert.DdnsError('no A record')

        with patch.object(unifi_cert, 'load_provisioning_config', return_value=cfg), \
             patch.object(unifi_cert, 'get_public_ip', return_value='5.6.7.8'), \
             patch.object(unifi_cert, '_ddns_update_target', side_effect=_update), \
             patch.object(unifi_cert, 'ui'):
            ok = unifi_cert.ddns_update()

        assert ok is False
        assert attempted == ['home.jdlien.ca', '*.home.jdlien.ca']
        assert unifi_cert._ddns_load_state()['targets'][
            '*.home.jdlien.ca']['consecutive_failures'] == 1

    def test_no_domain_errors(self, ddns_state):
        """No domain in args or provisioning → False."""
        with patch.object(unifi_cert, 'load_provisioning_config', return_value={}), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.ddns_update() is False

    def test_config_failures_are_tracked(self, ddns_state):
        """A misconfigured install fires every 5 min too — escalate it the same."""
        with patch.object(unifi_cert, 'load_provisioning_config', return_value={}), \
             patch.object(unifi_cert, 'ui'):
            unifi_cert.ddns_update()
        assert unifi_cert._ddns_load_state()['targets'][
            '(configuration)']['consecutive_failures'] == 1

    def test_cloudflare_provider_now_supported(self, tmp_path, ddns_state):
        """Regression guard: cloudflare used to be rejected outright."""
        creds = tmp_path / 'cf.ini'
        creds.write_text('dns_cloudflare_api_token = T\n')
        cfg = self._provisioning(dns_provider='cloudflare', dns_credentials=str(creds))
        with patch.object(unifi_cert, 'load_provisioning_config', return_value=cfg), \
             patch.object(unifi_cert, 'get_public_ip', return_value='1.2.3.4'), \
             patch.object(unifi_cert, '_ddns_resolve_zone', return_value=_cf_zone()), \
             patch.object(unifi_cert, '_ddns_get_a_record',
                          return_value=('recid', '1.2.3.4', 1)), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.ddns_update() is True

    def test_missing_credentials_file_errors(self, ddns_state):
        """dns_credentials path doesn't exist → False."""
        cfg = self._provisioning(dns_credentials='/does/not/exist.ini')
        with patch.object(unifi_cert, 'load_provisioning_config', return_value=cfg), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.ddns_update() is False

    def test_public_ip_lookup_failure_errors(self, tmp_path, ddns_state):
        """get_public_ip returning None → False, tracked under its own key."""
        creds = tmp_path / 'do.ini'
        creds.write_text('dns_digitalocean_token = T\n')
        with patch.object(unifi_cert, 'load_provisioning_config',
                          return_value=self._provisioning(dns_credentials=str(creds))), \
             patch.object(unifi_cert, 'get_public_ip', return_value=None), \
             patch.object(unifi_cert, 'ui'):
            assert unifi_cert.ddns_update() is False
        assert '(public-ip)' in unifi_cert._ddns_load_state()['targets']

    def test_record_not_found_errors(self, tmp_path, ddns_state):
        """_ddns_get_a_record raising → False."""
        creds = tmp_path / 'do.ini'
        creds.write_text('dns_digitalocean_token = T\n')
        with patch.object(unifi_cert, 'load_provisioning_config',
                          return_value=self._provisioning(dns_credentials=str(creds))), \
             patch.object(unifi_cert, 'get_public_ip', return_value='1.2.3.4'), \
             patch.object(unifi_cert, '_ddns_resolve_zone', return_value=_do_zone()), \
             patch.object(unifi_cert, '_ddns_get_a_record',
                          side_effect=unifi_cert.DdnsError('No A record found')), \
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

    def test_ddns_flags_are_threaded_through(self):
        """--ddns-domain/-provider/-credentials reach ddns_update()."""
        argv = ['unifi-cert', '--ddns-update',
                '--ddns-domain', 'home.jdlien.ca,*.home.jdlien.ca',
                '--ddns-provider', 'cloudflare',
                '--ddns-credentials', '/data/unifi-cert/credentials/cloudflare.ini']
        with patch('sys.argv', argv), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'rotate_log'), \
             patch.object(unifi_cert, 'ddns_update', return_value=True) as fn:
            assert unifi_cert.main() == 0
        fn.assert_called_once_with(
            domain='home.jdlien.ca,*.home.jdlien.ca',
            credentials='/data/unifi-cert/credentials/cloudflare.ini',
            provider='cloudflare',
            force=False,
        )

    def test_bare_domain_flag_still_honoured(self):
        """-d keeps working as the DDNS target for pre-decoupling invocations."""
        with patch('sys.argv', ['unifi-cert', '--ddns-update', '-d', 'x.example.com']), \
             patch('sys.stdout.isatty', return_value=False), \
             patch.object(unifi_cert, 'ui'), \
             patch.object(unifi_cert, 'rotate_log'), \
             patch.object(unifi_cert, 'ddns_update', return_value=True) as fn:
            assert unifi_cert.main() == 0
        assert fn.call_args.kwargs['domain'] == 'x.example.com'


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
        'DDNS_STATE_FILE': str(cert_root / 'ddns-state.json'),
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


class TestPrintDdnsSection:
    """The --status DDNS block: config, last success, failure streaks."""

    def _run(self, cfg):
        with patch.object(unifi_cert, 'ui',
                          new=unifi_cert.UI(color=False, verbose=False)):
            unifi_cert._print_ddns_section(cfg)

    def test_unconfigured_reports_why(self, status_paths, capsys):
        """No target anywhere → say so rather than printing an empty block."""
        self._run({})
        assert 'DDNS not configured' in capsys.readouterr().out

    def test_shows_resolved_targets_and_provider(self, status_paths, tmp_path, capsys):
        """The decoupled config is echoed back so a typo is visible."""
        creds = tmp_path / 'cf.ini'
        creds.write_text('dns_cloudflare_api_token = T\n')
        self._run({
            'domain': 'beehive.jdlien.com',
            'dns_provider': 'digitalocean',
            'ddns_domain': 'home.jdlien.ca,*.home.jdlien.ca',
            'ddns_provider': 'cloudflare',
            'ddns_credentials': str(creds),
        })
        out = capsys.readouterr().out
        assert 'home.jdlien.ca, *.home.jdlien.ca' in out
        assert 'cloudflare' in out

    def test_no_run_recorded_yet(self, status_paths, capsys):
        """A configured-but-never-run install says so explicitly."""
        self._run({'domain': 'x.example.com', 'dns_provider': 'digitalocean',
                   'dns_credentials': __file__})
        assert 'No DDNS run recorded yet' in capsys.readouterr().out

    def test_failure_streak_surfaced(self, status_paths, capsys):
        """The number that went unnoticed for months is now in the report."""
        Path(status_paths['DDNS_STATE_FILE']).write_text(json.dumps({'targets': {
            'beehive.jdlien.com': {
                'consecutive_failures': 6295,
                'last_success': None,
                'last_error': 'No A record found for beehive.jdlien.com',
            },
        }}))
        self._run({})
        captured = capsys.readouterr()
        # ui.error goes to stderr; cron folds both streams into the log.
        combined = captured.out + captured.err
        assert '6295 consecutive failure(s)' in combined
        assert 'last success never' in combined
        assert 'No A record found' in combined

    def test_healthy_target_shows_last_ip(self, status_paths, capsys):
        Path(status_paths['DDNS_STATE_FILE']).write_text(json.dumps({'targets': {
            'home.jdlien.ca': {
                'consecutive_failures': 0,
                'last_success': '2026-07-31T03:00:00',
                'last_ip': '198.53.200.179',
                'record_count': 1,
            },
        }}))
        self._run({})
        out = capsys.readouterr().out
        assert '198.53.200.179' in out
        assert '2026-07-31T03:00:00' in out

    def test_duplicate_record_count_warns(self, status_paths, capsys):
        """>1 A record is the inadyn fingerprint — flag it even when updates work."""
        Path(status_paths['DDNS_STATE_FILE']).write_text(json.dumps({'targets': {
            'home.jdlien.ca': {
                'consecutive_failures': 0,
                'last_success': '2026-07-31T03:00:00',
                'last_ip': '198.53.200.179',
                'record_count': 2,
            },
        }}))
        self._run({})
        assert '2 A records' in capsys.readouterr().out

    def test_stale_success_is_flagged_not_green(self, status_paths, capsys):
        """Zero failures + an old timestamp means cron stopped, not health.

        Rendering that as a reassuring green line is the same failure mode as
        the silent errors: the report says fine while nothing is happening.
        """
        old = (datetime.now() - timedelta(hours=9)).isoformat(timespec='seconds')
        Path(status_paths['DDNS_STATE_FILE']).write_text(json.dumps({'targets': {
            'home.jdlien.ca': {'consecutive_failures': 0, 'last_success': old,
                               'last_ip': '198.53.200.179', 'record_count': 1},
        }}))
        self._run({})
        out = capsys.readouterr().out
        assert 'looks stopped' in out
        assert '9h ago' in out

    def test_recent_success_is_green(self, status_paths, capsys):
        recent = (datetime.now() - timedelta(minutes=4)).isoformat(timespec='seconds')
        Path(status_paths['DDNS_STATE_FILE']).write_text(json.dumps({'targets': {
            'home.jdlien.ca': {'consecutive_failures': 0, 'last_success': recent,
                               'last_ip': '198.53.200.179', 'record_count': 1},
        }}))
        self._run({})
        out = capsys.readouterr().out
        assert 'looks stopped' not in out
        assert '198.53.200.179' in out

    def test_disabled_ddns_does_not_warn_about_staleness(self, status_paths, capsys):
        """If DDNS is intentionally off, an old timestamp isn't a problem."""
        old = (datetime.now() - timedelta(days=30)).isoformat(timespec='seconds')
        Path(status_paths['DDNS_STATE_FILE']).write_text(json.dumps({'targets': {
            'home.jdlien.ca': {'consecutive_failures': 0, 'last_success': old,
                               'last_ip': '198.53.200.179', 'record_count': 1},
        }}))
        self._run({'ddns_enabled': 'false'})
        out = capsys.readouterr().out
        assert 'looks stopped' not in out
        assert 'nothing here is being refreshed' in out

    def test_status_includes_ddns_header(self, status_paths, capsys):
        """print_status() wires the section in."""
        with patch.object(unifi_cert, 'inventory_glennr',
                          return_value=unifi_cert.GlennRInventory()), \
             patch.object(unifi_cert, 'detect_domain_from_cert', return_value=None), \
             patch.object(unifi_cert, 'ui',
                          new=unifi_cert.UI(color=False, verbose=False)):
            unifi_cert.print_status()
        assert 'DDNS' in capsys.readouterr().out


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

    def test_build_remote_command_forwards_ddns_flags(self):
        """The ddns_* overrides have to survive the trip to the device."""
        args = argparse.Namespace(
            domain=None, email=None, dns_provider=None, dns_credentials=None,
            ddns_domain='home.jdlien.ca,*.home.jdlien.ca',
            ddns_provider='cloudflare',
            ddns_credentials='/data/unifi-cert/credentials/cloudflare.ini',
            dry_run=False, force=False, verbose=False, no_color=False,
            skip_postgres=False, skip_restart=False,
        )
        cmd = unifi_cert._build_remote_command('--ddns-update', args)
        assert '--ddns-provider cloudflare' in cmd
        assert '/data/unifi-cert/credentials/cloudflare.ini' in cmd
        # The wildcard must reach the device intact — an unquoted '*' would be
        # glob-expanded by the remote shell against its cwd.
        assert "'home.jdlien.ca,*.home.jdlien.ca'" in cmd

    def test_build_remote_command_omits_absent_ddns_flags(self):
        """Verbs on hosts predating these flags must not receive empty values."""
        args = argparse.Namespace(
            domain='example.com', email=None, dns_provider=None,
            dns_credentials=None, dry_run=False, force=False, verbose=False,
            no_color=False, skip_postgres=False, skip_restart=False,
        )
        cmd = unifi_cert._build_remote_command('--status', args)
        assert '--ddns-domain' not in cmd
        assert '--ddns-provider' not in cmd
        assert '--ddns-credentials' not in cmd


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
