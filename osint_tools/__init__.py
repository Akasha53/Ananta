"""
OSINT Tools Package - Modular OSINT tool implementations.

This package contains all OSINT tools organized by layer:
- Layer 1: Fundamental tools (passive, safe, automatic)
- Layer 2: Specialized tools (conditional, logged)
- Layer 3: Sensitive tools (user approval required)

Usage:
    from osint_tools import logic_whois, logic_dns_resolution, logic_censys
    # or
    from osint_tools.layer1 import logic_whois
    from osint_tools.layer2 import logic_censys

Migration Note:
    These functions were extracted from backend_logic.py to reduce file size
    and improve maintainability. The original functions in backend_logic.py
    now import from this package for backward compatibility.
"""

# Layer 1 - Fundamental tools
from osint_tools.layer1 import (
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

# Layer 2 - Specialized tools
from osint_tools.layer2 import (
    logic_censys,
    logic_virustotal,
    logic_shodan,
    logic_securitytrails,
    logic_crtsh,
    logic_subdomains,
    logic_wayback,
    logic_email_config,
    logic_security_txt,
    logic_web_enrichment,
)

# Layer 3 - Sensitive tools (require user approval)
from osint_tools.layer3 import (
    logic_port_scan,
    logic_vuln_scan,
)

__all__ = [
    # Layer 1
    "logic_whois",
    "logic_dns_resolution",
    "logic_reverse_dns",
    "logic_http_headers",
    "logic_ssl_analysis",
    "logic_tls_ciphers",
    "logic_robots_txt",
    "logic_redirect_chain",
    "logic_social_tags",
    # Layer 2
    "logic_censys",
    "logic_virustotal",
    "logic_shodan",
    "logic_securitytrails",
    "logic_crtsh",
    "logic_subdomains",
    "logic_wayback",
    "logic_email_config",
    "logic_security_txt",
    "logic_web_enrichment",
    # Layer 3
    "logic_port_scan",
    "logic_vuln_scan",
]
