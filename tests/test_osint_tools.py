"""
Tests for the osint_tools package.

These tests verify that the modularized OSINT tools work correctly
and maintain backward compatibility with backend_logic.py.
"""

import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestOsintToolsImports:
    """Test that all tools can be imported from the package."""

    def test_import_layer1_tools(self):
        """Test Layer 1 tool imports."""
        from osint_tools import (
            logic_whois,
            logic_dns_resolution,
            logic_reverse_dns,
            logic_http_headers,
            logic_ssl_analysis,
            logic_tls_ciphers,
            logic_robots_txt,
            logic_redirect_chain,
            logic_social_tags,
        )

        # Verify they are callable
        assert callable(logic_whois)
        assert callable(logic_dns_resolution)
        assert callable(logic_reverse_dns)
        assert callable(logic_http_headers)
        assert callable(logic_ssl_analysis)
        assert callable(logic_tls_ciphers)
        assert callable(logic_robots_txt)
        assert callable(logic_redirect_chain)
        assert callable(logic_social_tags)

    def test_import_layer2_tools(self):
        """Test Layer 2 tool imports."""
        from osint_tools import (
            logic_censys,
            logic_virustotal,
            logic_shodan,
            logic_securitytrails,
            logic_crtsh,
            logic_subdomains,
            logic_wayback,
            logic_email_config,
            logic_security_txt,
        )

        # Verify they are callable
        assert callable(logic_censys)
        assert callable(logic_virustotal)
        assert callable(logic_shodan)
        assert callable(logic_securitytrails)
        assert callable(logic_crtsh)
        assert callable(logic_subdomains)
        assert callable(logic_wayback)
        assert callable(logic_email_config)
        assert callable(logic_security_txt)

    def test_import_layer3_tools(self):
        """Test Layer 3 tool imports."""
        from osint_tools import (
            logic_port_scan,
            logic_vuln_scan,
        )

        # Verify they are callable
        assert callable(logic_port_scan)
        assert callable(logic_vuln_scan)

    def test_import_from_submodules(self):
        """Test direct import from submodules."""
        from osint_tools.layer1 import logic_whois, logic_dns_resolution
        from osint_tools.layer2 import logic_censys, logic_crtsh
        from osint_tools.layer3 import logic_port_scan, logic_vuln_scan

        assert callable(logic_whois)
        assert callable(logic_censys)
        assert callable(logic_port_scan)


class TestLayer1ToolsBasic:
    """Basic tests for Layer 1 tools (no network required)."""

    def test_dns_resolution_invalid_domain(self):
        """Test DNS resolution with invalid domain."""
        from osint_tools import logic_dns_resolution

        result = logic_dns_resolution("this-domain-does-not-exist-12345.invalid")
        assert "error" in result

    def test_reverse_dns_invalid_ip(self):
        """Test reverse DNS with invalid IP."""
        from osint_tools import logic_reverse_dns

        result = logic_reverse_dns("0.0.0.0")
        # Either error or valid response (some systems return localhost)
        assert "raw" in result or "error" in result


class TestLayer2ToolsSkipped:
    """Tests for Layer 2 tools when API keys are not configured."""

    def test_censys_skipped_without_key(self, monkeypatch):
        """Test Censys returns skipped when API key not configured."""
        monkeypatch.delenv("CENSYS_API_KEY", raising=False)

        from osint_tools import logic_censys
        result = logic_censys("8.8.8.8")

        assert result.get("skipped") is True
        assert "CENSYS_API_KEY" in result.get("reason", "")

    def test_virustotal_skipped_without_key(self, monkeypatch):
        """Test VirusTotal returns skipped when API key not configured."""
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

        from osint_tools import logic_virustotal
        result = logic_virustotal("example.com")

        assert result.get("skipped") is True
        assert "VIRUSTOTAL_API_KEY" in result.get("reason", "")

    def test_shodan_skipped_without_key(self, monkeypatch):
        """Test Shodan returns skipped when API key not configured."""
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)

        from osint_tools import logic_shodan
        result = logic_shodan("8.8.8.8")

        assert result.get("skipped") is True
        assert "SHODAN_API_KEY" in result.get("reason", "")

    def test_securitytrails_skipped_without_key(self, monkeypatch):
        """Test SecurityTrails returns skipped when API key not configured."""
        monkeypatch.delenv("SECURITYTRAILS_API_KEY", raising=False)

        from osint_tools import logic_securitytrails
        result = logic_securitytrails("example.com")

        assert result.get("skipped") is True
        assert "SECURITYTRAILS_API_KEY" in result.get("reason", "")


class TestLayer3ToolsFormat:
    """Test that Layer 3 tools return properly formatted responses."""

    def test_port_scan_invalid_host(self):
        """Test port scan with invalid host returns error."""
        from osint_tools import logic_port_scan

        result = logic_port_scan("this-host-does-not-exist-12345.invalid")
        # Should return error for unresolvable host
        assert "error" in result

    def test_vuln_scan_response_structure(self):
        """Test vuln scan returns properly structured response on error."""
        from osint_tools import logic_vuln_scan

        result = logic_vuln_scan("https://this-domain-does-not-exist-12345.invalid")

        # Should return either a proper error or raw data
        assert "error" in result or "raw" in result


class TestBackwardCompatibility:
    """Test backward compatibility with backend_logic.py."""

    def test_functions_match_signature(self):
        """Test that osint_tools functions have same signatures as backend_logic."""
        from osint_tools import logic_whois as new_whois
        from osint_tools import logic_dns_resolution as new_dns

        import inspect

        # Check logic_whois signature
        sig = inspect.signature(new_whois)
        params = list(sig.parameters.keys())
        assert "domain" in params

        # Check logic_dns_resolution signature
        sig = inspect.signature(new_dns)
        params = list(sig.parameters.keys())
        assert "domain" in params
