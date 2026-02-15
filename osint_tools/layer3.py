"""
Layer 3 - Sensitive OSINT Tools

Tools that REQUIRE EXPLICIT USER APPROVAL before execution.
Legal risk level: HIGH to CRITICAL

⚠️ WARNING: These tools may be considered intrusive in some jurisdictions.
Only use with explicit written authorization.
"""

import os
import re
import socket
import ssl
import logging
import datetime
import requests
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# CVE Database for common server versions
CVE_DATABASE = {
    # Apache
    "Apache/2.4.49": [{"cve": "CVE-2021-41773", "severity": "CRITICAL", "desc": "Path Traversal + RCE"}],
    "Apache/2.4.50": [{"cve": "CVE-2021-42013", "severity": "CRITICAL", "desc": "Path Traversal bypass"}],
    "Apache/2.4.": [{"cve": "CVE-2021-44790", "severity": "HIGH", "desc": "mod_lua buffer overflow (< 2.4.52)"}],
    "Apache/2.2.": [{"cve": "CVE-2017-3167", "severity": "HIGH", "desc": "Authentication bypass (EOL)"}],
    # Nginx
    "nginx/1.16.": [{"cve": "CVE-2019-20372", "severity": "MEDIUM", "desc": "HTTP request smuggling"}],
    "nginx/1.14.": [{"cve": "CVE-2018-16845", "severity": "MEDIUM", "desc": "Denial of Service"}],
    # IIS
    "Microsoft-IIS/7.": [{"cve": "CVE-2017-7269", "severity": "CRITICAL", "desc": "WebDAV RCE (Buffer Overflow)"}],
    "Microsoft-IIS/6.": [{"cve": "CVE-2017-7269", "severity": "CRITICAL", "desc": "WebDAV RCE (EOL)"}],
    # PHP
    "PHP/5.": [{"cve": "CVE-2019-11043", "severity": "CRITICAL", "desc": "PHP-FPM RCE (PHP 5.x EOL)"}],
    "PHP/7.0": [{"cve": "CVE-2019-11043", "severity": "CRITICAL", "desc": "PHP-FPM RCE (7.0 EOL)"}],
    "PHP/7.1": [{"cve": "CVE-2019-11043", "severity": "CRITICAL", "desc": "PHP-FPM RCE (7.1 EOL)"}],
    "PHP/7.2": [{"cve": "CVE-2019-11043", "severity": "HIGH", "desc": "PHP-FPM RCE (7.2 EOL)"}],
    # OpenSSL
    "OpenSSL/1.0.1": [{"cve": "CVE-2014-0160", "severity": "CRITICAL", "desc": "Heartbleed"}],
    "OpenSSL/1.0.2": [{"cve": "CVE-2016-2107", "severity": "HIGH", "desc": "Padding Oracle (< 1.0.2h)"}],
    # WordPress
    "WordPress/4.": [{"cve": "Multiple", "severity": "HIGH", "desc": "WordPress 4.x - Multiple CVEs (EOL)"}],
    "WordPress/5.0": [{"cve": "CVE-2019-8942", "severity": "HIGH", "desc": "Authenticated RCE via upload"}],
}

# Sensitive file paths to check
SENSITIVE_PATHS = [
    ("/.env", "Environment file with credentials"),
    ("/.git/config", "Git repository exposed"),
    ("/wp-config.php.bak", "WordPress config backup"),
    ("/config.php.bak", "Config backup file"),
    ("/backup.sql", "SQL backup file"),
    ("/phpinfo.php", "PHP info page"),
    ("/.htpasswd", "Apache password file"),
    ("/server-status", "Apache server status"),
    ("/web.config", "IIS config file"),
    ("/.DS_Store", "macOS metadata file"),
    ("/robots.txt", "Robots file (info disclosure)"),
    ("/sitemap.xml", "Sitemap (structure disclosure)"),
    ("/.well-known/security.txt", "Security contact info"),
]


def logic_port_scan(target: str) -> Dict[str, Any]:
    """
    Layer 3 Tool: TCP port scan for common ports.
    
    ⚠️ REQUIRES EXPLICIT USER APPROVAL.
    
    Scans the most common ports to identify exposed services.
    WARNING: May be considered intrusive. Use only with authorization.

    Args:
        target: IP or domain to scan

    Returns:
        Dict with list of open ports and their probable services
    """
    try:
        # Top common ports (limited to avoid being too intrusive)
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5900, 8080, 8443, 8888
        ]

        open_ports = []
        timeout = 1.0  # Short timeout per port

        logger.warning(f"[PORT SCAN] Starting scan on {target} - TOOL LAYER 3")

        # Resolve domain to IP if needed
        ip_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
        if not ip_pattern.match(target):
            try:
                target_ip = socket.gethostbyname(target)
            except socket.gaierror:
                return {"error": f"Cannot resolve hostname: {target}"}
        else:
            target_ip = target

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target_ip, port))

                if result == 0:
                    # Port is open
                    try:
                        service = socket.getservbyport(port, 'tcp')
                    except OSError:
                        service = f"service-{port}"
                    
                    open_ports.append({
                        "port": port,
                        "state": "open",
                        "service": service
                    })
                    logger.info(f"[PORT SCAN] Port {port}/tcp OPEN ({service})")

                sock.close()

            except socket.gaierror:
                return {"error": f"Cannot resolve hostname: {target}"}
            except socket.error:
                pass  # Port closed or filtered

        if not open_ports:
            logger.info(f"[PORT SCAN] No open ports found on {target}")

        return {
            "raw": {
                "target": target,
                "target_ip": target_ip,
                "scan_type": "TCP Connect",
                "ports_scanned": len(common_ports),
                "ports_open": len(open_ports),
                "open_ports": open_ports,
                "warning": "This scan may have been detected by IDS/IPS systems"
            }
        }

    except Exception as e:
        logger.error(f"[PORT SCAN] Error: {e}")
        return {"error": str(e)}


def logic_vuln_scan(target: str) -> Dict[str, Any]:
    """
    Layer 3 Tool: Enhanced vulnerability scan with CVE detection.
    
    🚨 REQUIRES EXPLICIT USER APPROVAL + LEGAL CONTEXT.

    Performs tests to detect:
    - Server versions with known CVEs
    - Weak HTTP configurations
    - Missing security headers
    - SSL/TLS vulnerabilities
    - Exposed sensitive files
    - Framework versions with known CVEs

    WARNING: May trigger IDS/IPS alerts. USE ONLY WITH WRITTEN AUTHORIZATION.

    Args:
        target: URL or domain to scan

    Returns:
        Dict with detected vulnerabilities
    """
    try:
        vulnerabilities = []
        security_headers = []
        cve_findings = []
        detected_frameworks = []

        logger.warning(f"[VULN SCAN] Starting enhanced scan on {target} - TOOL LAYER 3 CRITICAL")

        # Normalize URL
        if not target.startswith(('http://', 'https://')):
            test_url = f"https://{target}"
            domain = target
        else:
            test_url = target
            domain = target.replace('https://', '').replace('http://', '').split('/')[0]

        try:
            # Test 1: HTTP headers analysis
            response = requests.get(test_url, timeout=10, allow_redirects=True, verify=False)

            # Check missing security headers
            security_checks = {
                "Strict-Transport-Security": ("HSTS - force HTTPS", "LOW", True),
                "Content-Security-Policy": ("CSP - XSS/injection protection", "LOW", True),
                "X-Frame-Options": ("Clickjacking protection", "LOW", True),
                "X-Content-Type-Options": ("MIME sniffing protection", "INFO", True),
                "Referrer-Policy": ("Referrer control", "INFO", True),
                "Permissions-Policy": ("Browser permissions control", "INFO", True),
            }

            for header, (description, severity, recommended) in security_checks.items():
                if header not in response.headers:
                    vulnerabilities.append({
                        "severity": severity,
                        "type": "Missing Security Header",
                        "description": f"Header '{header}' missing ({description})",
                        "remediation": f"Add header {header}" if recommended else "Optional header",
                        "note": "Security best practice, not directly exploitable"
                    })
                else:
                    security_headers.append(header)

            # Test 2: Server version and CVE check
            server_header = response.headers.get('Server', '')
            x_powered_by = response.headers.get('X-Powered-By', '')

            # Detect CDN (version exposed = CDN, not real target)
            cdn_indicators = ['cloudflare', 'akamai', 'fastly', 'cloudfront', 'azure', 'sucuri', 'incapsula', 'imperva']
            is_cdn_version = any(cdn in server_header.lower() for cdn in cdn_indicators)

            for version_info in [server_header, x_powered_by]:
                if version_info:
                    if is_cdn_version:
                        vulnerabilities.append({
                            "severity": "INFO",
                            "type": "CDN Version Exposed",
                            "description": f"CDN version exposed: {version_info} (protection infrastructure, not target)",
                            "remediation": "Informational - this version concerns the CDN, not your server",
                            "note": "Infrastructure info concerns the CDN, not the real target"
                        })
                    else:
                        vulnerabilities.append({
                            "severity": "LOW",
                            "type": "Information Disclosure",
                            "description": f"Version exposed: {version_info}",
                            "remediation": "Hide or generalize this header to reduce fingerprinting"
                        })

                    # CVE lookup
                    for pattern, cves in CVE_DATABASE.items():
                        if pattern in version_info:
                            for cve in cves:
                                cve_findings.append({
                                    "cve_id": cve["cve"],
                                    "severity": cve["severity"],
                                    "affected_component": version_info,
                                    "description": cve["desc"],
                                    "remediation": "Update to latest stable version"
                                })

            # Test 3: Check dangerous HTTP methods
            try:
                options_response = requests.options(test_url, timeout=5, verify=False)
                allowed_methods = options_response.headers.get('Allow', '').split(',')
                dangerous_methods = ['TRACE', 'DELETE', 'PUT', 'CONNECT']

                for method in dangerous_methods:
                    if method.strip() in [m.strip() for m in allowed_methods]:
                        vulnerabilities.append({
                            "severity": "MEDIUM" if method in ['TRACE', 'CONNECT'] else "HIGH",
                            "type": "Dangerous HTTP Method",
                            "description": f"HTTP method {method} enabled",
                            "remediation": f"Disable method {method}"
                        })
            except:
                pass

            # Test 4: Check exposed sensitive files
            logger.info("[VULN SCAN] Checking sensitive files...")
            for path, desc in SENSITIVE_PATHS:
                try:
                    check_url = f"https://{domain}{path}"
                    check_resp = requests.head(check_url, timeout=3, verify=False, allow_redirects=False)
                    if check_resp.status_code == 200:
                        severity = "HIGH" if any(s in path for s in ['.env', '.git', 'config', 'backup', '.htpasswd']) else "MEDIUM"
                        vulnerabilities.append({
                            "severity": severity,
                            "type": "Sensitive File Exposed",
                            "description": f"Sensitive file accessible: {path} ({desc})",
                            "remediation": f"Block access to {path} via server configuration"
                        })
                except:
                    pass

            # Test 5: SSL/TLS verification
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        ssl_version = ssock.version()

                        # Check obsolete protocols
                        if ssl_version in ['TLSv1', 'TLSv1.0', 'TLSv1.1', 'SSLv3', 'SSLv2']:
                            vulnerabilities.append({
                                "severity": "HIGH",
                                "type": "Weak SSL/TLS Protocol",
                                "description": f"Obsolete protocol: {ssl_version}",
                                "remediation": "Use TLS 1.2 or higher only"
                            })

                        # Check certificate expiration
                        if cert:
                            not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            days_until_expiry = (not_after - datetime.datetime.utcnow()).days
                            if days_until_expiry < 0:
                                vulnerabilities.append({
                                    "severity": "CRITICAL",
                                    "type": "Expired SSL Certificate",
                                    "description": f"SSL certificate expired {abs(days_until_expiry)} days ago",
                                    "remediation": "Renew SSL certificate immediately"
                                })
                            elif days_until_expiry < 30:
                                vulnerabilities.append({
                                    "severity": "MEDIUM",
                                    "type": "SSL Certificate Expiring Soon",
                                    "description": f"SSL certificate expires in {days_until_expiry} days",
                                    "remediation": "Plan certificate renewal"
                                })
            except ssl.SSLError as e:
                vulnerabilities.append({
                    "severity": "HIGH",
                    "type": "SSL/TLS Issue",
                    "description": f"SSL error: {str(e)}",
                    "remediation": "Verify SSL/TLS configuration"
                })
            except Exception as e:
                logger.debug(f"[VULN SCAN] SSL check skipped: {e}")

            # Test 6: Framework/CMS detection
            body = response.text[:50000]
            framework_patterns = {
                r'wp-content|wp-includes': ("WordPress", "CMS"),
                r'Drupal|drupal\.js': ("Drupal", "CMS"),
                r'Joomla|joomla': ("Joomla", "CMS"),
                r'laravel|Laravel': ("Laravel", "Framework"),
                r'django|Django': ("Django", "Framework"),
                r'express|Express': ("Express.js", "Framework"),
                r'react|React': ("React", "Frontend"),
                r'angular|Angular': ("Angular", "Frontend"),
                r'vue\.js|Vue': ("Vue.js", "Frontend"),
            }

            for pattern, (name, category) in framework_patterns.items():
                if re.search(pattern, body, re.I):
                    detected_frameworks.append({"name": name, "category": category})

        except requests.exceptions.SSLError:
            vulnerabilities.append({
                "severity": "HIGH",
                "type": "SSL/TLS Issue",
                "description": "Invalid or untrusted SSL certificate",
                "remediation": "Install a valid SSL certificate"
            })

        except requests.exceptions.ConnectionError:
            return {"error": f"Cannot connect to {target}"}

        # Calculate risk score
        severity_scores = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        total_score = sum(severity_scores.get(v.get("severity", "LOW"), 1) for v in vulnerabilities)
        total_score += sum(severity_scores.get(c.get("severity", "MEDIUM"), 2) for c in cve_findings)

        if total_score >= 15:
            risk_level = "CRITICAL"
        elif total_score >= 10:
            risk_level = "HIGH"
        elif total_score >= 5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        logger.info(f"[VULN SCAN] {len(vulnerabilities)} vulnerabilities, {len(cve_findings)} CVE, Risk: {risk_level}")

        return {
            "raw": {
                "target": target,
                "scan_type": "Enhanced Vulnerability Scan with CVE Detection",
                "risk_level": risk_level,
                "risk_score": total_score,
                "vulnerabilities_found": len(vulnerabilities),
                "cve_found": len(cve_findings),
                "vulnerabilities": vulnerabilities,
                "cve_findings": cve_findings,
                "security_headers_present": security_headers,
                "detected_frameworks": detected_frameworks,
                "warning": "This scan may have triggered security alerts",
                "disclaimer": "Semi-automated scan. For a complete audit, use professional tools (Nuclei, Nessus, etc.)"
            }
        }

    except Exception as e:
        logger.error(f"[VULN SCAN] Error: {e}")
        return {"error": str(e)}
