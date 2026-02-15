"""
Layer 1 - Fundamental OSINT Tools

Passive, safe, automatic tools that can be executed without special approval.
Legal risk level: LOW
"""

import os
import re
import socket
import ssl
import logging
import requests
import whois
from urllib.parse import urlparse
from typing import Dict, Any

logger = logging.getLogger(__name__)


def logic_whois(domain: str) -> Dict[str, Any]:
    """
    WHOIS lookup for domain registration information.

    Args:
        domain: Domain name to query

    Returns:
        Dict with raw WHOIS data or error
    """
    try:
        w = whois.whois(domain)
        data = (
            {k: str(v) for k, v in w.items()}
            if isinstance(w, dict)
            else {k: str(v) for k, v in w.__dict__.items() if not k.startswith("_")}
        )
        return {"raw": data}
    except Exception as e:
        return {"error": str(e)}


def logic_dns_resolution(domain: str) -> Dict[str, Any]:
    """
    DNS resolution (domain → IP address).

    Args:
        domain: Domain name to resolve

    Returns:
        Dict with IP address or error
    """
    try:
        ip = socket.gethostbyname(domain)
        return {"raw": ip}
    except Exception as e:
        return {"error": str(e)}


def logic_reverse_dns(ip: str) -> Dict[str, Any]:
    """
    Reverse DNS lookup (IP → hostname).

    Args:
        ip: IP address to resolve

    Returns:
        Dict with hostname or error
    """
    try:
        host = socket.gethostbyaddr(ip)[0]
        return {"raw": host}
    except Exception as e:
        return {"error": str(e)}


def logic_ssl_analysis(domain: str) -> Dict[str, Any]:
    """
    SSL/TLS certificate analysis for a domain.

    Args:
        domain: Domain name to analyze

    Returns:
        Dict with certificate information or error
    """
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                # Extract important information
                subject = dict(x[0] for x in cert.get('subject', ()))
                issuer = dict(x[0] for x in cert.get('issuer', ()))

                return {
                    "raw": {
                        "subject": subject,
                        "issuer": issuer,
                        "version": cert.get("version"),
                        "serial_number": cert.get("serialNumber"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "subject_alt_names": [x[1] for x in cert.get("subjectAltName", [])],
                        "ssl_version": ssock.version()
                    }
                }
    except Exception as e:
        return {"error": str(e)}


def logic_tls_ciphers(domain: str) -> Dict[str, Any]:
    """
    Analyze TLS cipher suites for a domain.

    Args:
        domain: Domain name to analyze

    Returns:
        Dict with cipher information or error
    """
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cipher = ssock.cipher()

                return {
                    "raw": {
                        "current_cipher": {
                            "name": cipher[0],
                            "version": cipher[1],
                            "bits": cipher[2]
                        },
                        "protocol_version": ssock.version(),
                    }
                }
    except Exception as e:
        return {"error": str(e)}


def logic_http_headers(target: str) -> Dict[str, Any]:
    """
    HTTP headers analysis for technology detection and security assessment.

    Args:
        target: URL or domain to analyze

    Returns:
        Dict with headers information or error
    """
    try:
        # Ensure URL has protocol
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        response = requests.head(target, timeout=5, allow_redirects=True)
        headers = dict(response.headers)

        # Detect technologies via headers
        technologies = []

        if "Server" in headers:
            technologies.append(f"Serveur: {headers['Server']}")

        if "X-Powered-By" in headers:
            technologies.append(f"Backend: {headers['X-Powered-By']}")

        if "X-AspNet-Version" in headers:
            technologies.append(f"ASP.NET: {headers['X-AspNet-Version']}")

        if "X-Generator" in headers:
            technologies.append(f"Générateur: {headers['X-Generator']}")

        # CDN detection
        cdn_headers = {
            "cf-ray": "Cloudflare",
            "x-amz-cf-id": "AWS CloudFront",
            "x-cdn": "CDN détecté",
            "x-fastly-request-id": "Fastly"
        }

        for header, cdn in cdn_headers.items():
            if header in headers:
                technologies.append(f"CDN: {cdn}")
                break

        return {
            "raw": {
                "status_code": response.status_code,
                "headers": headers,
                "technologies_detected": technologies,
                "security_headers": {
                    "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Non présent"),
                    "X-Frame-Options": headers.get("X-Frame-Options", "Non présent"),
                    "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Non présent"),
                    "Content-Security-Policy": headers.get("Content-Security-Policy", "Non présent")
                }
            }
        }
    except Exception as e:
        return {"error": str(e)}


def logic_robots_txt(target: str) -> Dict[str, Any]:
    """
    Fetch and parse robots.txt file.

    Args:
        target: URL or domain to check

    Returns:
        Dict with robots.txt content and parsed directives or error
    """
    try:
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        # Ensure URL ends with /robots.txt
        parsed = urlparse(target)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

        response = requests.get(robots_url, timeout=5)

        if response.status_code == 404:
            return {"raw": {"exists": False, "content": None}}

        if response.status_code != 200:
            return {"error": f"HTTP {response.status_code}"}

        content = response.text
        lines = content.split('\n')

        # Parse important directives
        disallowed_paths = []
        sitemaps = []
        user_agents = []

        for line in lines:
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    disallowed_paths.append(path)
            elif line.lower().startswith("sitemap:"):
                sitemap = line.split(":", 1)[1].strip()
                sitemaps.append(sitemap)
            elif line.lower().startswith("user-agent:"):
                ua = line.split(":", 1)[1].strip()
                user_agents.append(ua)

        return {
            "raw": {
                "exists": True,
                "url": robots_url,
                "size_bytes": len(content),
                "disallowed_paths": disallowed_paths[:20],
                "sitemaps": sitemaps,
                "user_agents": list(set(user_agents)),
                "full_content": content[:2000]
            }
        }
    except Exception as e:
        return {"error": str(e)}


def logic_redirect_chain(target: str) -> Dict[str, Any]:
    """
    Trace HTTP redirect chain.

    Args:
        target: URL or domain to trace

    Returns:
        Dict with redirect chain information or error
    """
    try:
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        chain = []
        current_url = target
        max_redirects = 10

        for i in range(max_redirects):
            response = requests.get(current_url, allow_redirects=False, timeout=5)

            chain.append({
                "url": current_url,
                "status_code": response.status_code,
                "location": response.headers.get("Location"),
                "is_redirect": response.is_redirect
            })

            if not response.is_redirect:
                break

            # Follow redirect
            location = response.headers.get("Location")
            if not location:
                break

            # Handle relative redirects
            if location.startswith("/"):
                parsed = urlparse(current_url)
                location = f"{parsed.scheme}://{parsed.netloc}{location}"
            elif not location.startswith("http"):
                parsed = urlparse(current_url)
                location = f"{parsed.scheme}://{parsed.netloc}/{location}"

            current_url = location

        return {
            "raw": {
                "chain_length": len(chain),
                "final_url": chain[-1]["url"] if chain else target,
                "chain": chain
            }
        }
    except Exception as e:
        return {"error": str(e)}


def logic_social_tags(target: str) -> Dict[str, Any]:
    """
    Extract social media meta tags (Open Graph, Twitter Cards).

    Args:
        target: URL or domain to analyze

    Returns:
        Dict with social tags or error
    """
    try:
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        response = requests.get(target, timeout=5)

        if response.status_code != 200:
            return {"error": f"HTTP {response.status_code}"}

        html = response.text

        og_tags = {}
        twitter_tags = {}

        # Extract Open Graph meta tags
        og_pattern = r'<meta\s+property=["\']og:([^"\']+)["\']\s+content=["\']([^"\']+)["\']'
        for match in re.finditer(og_pattern, html, re.IGNORECASE):
            og_tags[match.group(1)] = match.group(2)

        # Extract Twitter meta tags
        twitter_pattern = r'<meta\s+name=["\']twitter:([^"\']+)["\']\s+content=["\']([^"\']+)["\']'
        for match in re.finditer(twitter_pattern, html, re.IGNORECASE):
            twitter_tags[match.group(1)] = match.group(2)

        return {
            "raw": {
                "open_graph": og_tags,
                "twitter_cards": twitter_tags,
                "has_og": len(og_tags) > 0,
                "has_twitter": len(twitter_tags) > 0
            }
        }
    except Exception as e:
        return {"error": str(e)}
