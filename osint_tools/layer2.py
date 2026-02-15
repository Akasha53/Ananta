"""
Layer 2 - Specialized OSINT Tools

Conditional, logged tools that are automatically executed but require logging.
Legal risk level: LOW to MEDIUM
"""

import os
import re
import socket
import logging
import requests
import concurrent.futures
from typing import Dict, Any, List, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def logic_censys(target: str) -> Dict[str, Any]:
    """
    Query Censys Platform API v3 for host/IP information.

    Args:
        target: IP address or domain to query

    Returns:
        Dict with Censys data or error/skipped
    """
    api_key = os.getenv("CENSYS_API_KEY")
    if not api_key:
        logger.info(f"[CENSYS] Skipped - CENSYS_API_KEY not configured")
        return {"skipped": True, "reason": "CENSYS_API_KEY not configured"}

    try:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/vnd.censys.api.v3.host.v1+json"
        }

        r = requests.get(
            f"https://api.platform.censys.io/v3/global/asset/host/{target}",
            headers=headers,
            timeout=10
        )

        if r.status_code == 401:
            return {"error": "Invalid API Key or unauthorized"}
        elif r.status_code == 404:
            return {"error": f"Host {target} not found in Censys database"}
        elif r.status_code != 200:
            return {"error": f"HTTP {r.status_code}: {r.text[:200]}"}

        data = r.json()
        return {"raw": data}

    except requests.exceptions.Timeout:
        return {"error": "Request timeout (>10s)"}
    except Exception as e:
        return {"error": str(e)}


def logic_virustotal(target: str) -> Dict[str, Any]:
    """
    Reputation analysis via VirusTotal API v3.
    Supports domains, IPs, and URLs.

    Args:
        target: Domain, IP, or URL to analyze

    Returns:
        Dict with reputation data or error/skipped
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        logger.info(f"[VIRUSTOTAL] Skipped - VIRUSTOTAL_API_KEY not configured")
        return {"skipped": True, "reason": "VIRUSTOTAL_API_KEY not configured"}

    try:
        import base64
        headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }

        # Determine target type
        ip_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

        if ip_pattern.match(target):
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            target_type = "ip"
        elif target.startswith("http://") or target.startswith("https://"):
            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            target_type = "url"
        else:
            endpoint = f"https://www.virustotal.com/api/v3/domains/{target}"
            target_type = "domain"

        r = requests.get(endpoint, headers=headers, timeout=10)

        if r.status_code == 401:
            return {"error": "Invalid VirusTotal API key"}
        elif r.status_code == 404:
            return {"error": f"Target '{target}' not found in VirusTotal database"}
        elif r.status_code == 429:
            return {"error": "VirusTotal rate limit exceeded (4 req/min on free tier)"}
        elif r.status_code != 200:
            return {"error": f"VirusTotal API error: HTTP {r.status_code}"}

        data = r.json()
        attributes = data.get("data", {}).get("attributes", {})

        last_analysis_stats = attributes.get("last_analysis_stats", {})
        reputation = attributes.get("reputation", 0)

        malicious = last_analysis_stats.get("malicious", 0)
        suspicious = last_analysis_stats.get("suspicious", 0)
        harmless = last_analysis_stats.get("harmless", 0)
        undetected = last_analysis_stats.get("undetected", 0)
        total_engines = malicious + suspicious + harmless + undetected

        summary = {
            "target": target,
            "target_type": target_type,
            "reputation_score": reputation,
            "detection_stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_engines": total_engines
            },
            "risk_level": "HIGH" if malicious > 5 else "MEDIUM" if malicious > 0 or suspicious > 2 else "LOW",
            "last_analysis_date": attributes.get("last_analysis_date"),
            "categories": attributes.get("categories", {}),
            "tags": attributes.get("tags", [])
        }

        if target_type == "domain":
            summary["registrar"] = attributes.get("registrar")
            summary["creation_date"] = attributes.get("creation_date")
            summary["whois"] = attributes.get("whois", "")[:500]
        elif target_type == "ip":
            summary["asn"] = attributes.get("asn")
            summary["as_owner"] = attributes.get("as_owner")
            summary["country"] = attributes.get("country")
            summary["network"] = attributes.get("network")

        return {
            "raw": summary,
            "full_response": data
        }

    except requests.exceptions.Timeout:
        return {"error": "VirusTotal request timeout (>10s)"}
    except Exception as e:
        logger.error(f"[VIRUSTOTAL] Error analyzing {target}: {e}")
        return {"error": str(e)}


def logic_shodan(target: str) -> Dict[str, Any]:
    """
    Host/IP information lookup via Shodan API.

    Args:
        target: IP or domain to analyze

    Returns:
        Dict with Shodan data or error/skipped
    """
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        logger.info(f"[SHODAN] Skipped - SHODAN_API_KEY not configured")
        return {"skipped": True, "reason": "SHODAN_API_KEY not configured"}

    try:
        ip_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

        # Resolve domain to IP if needed
        if not ip_pattern.match(target):
            try:
                target_ip = socket.gethostbyname(target)
                logger.info(f"[SHODAN] Resolved {target} to {target_ip}")
            except socket.gaierror:
                return {"error": f"Cannot resolve domain '{target}' to IP"}
        else:
            target_ip = target

        endpoint = f"https://api.shodan.io/shodan/host/{target_ip}?key={api_key}"
        r = requests.get(endpoint, timeout=10)

        if r.status_code == 401:
            return {"error": "Invalid Shodan API key"}
        elif r.status_code == 404:
            return {"error": f"No Shodan data found for {target_ip}"}
        elif r.status_code == 429:
            return {"error": "Shodan rate limit exceeded"}
        elif r.status_code != 200:
            return {"error": f"Shodan API error: HTTP {r.status_code}"}

        data = r.json()

        summary = {
            "ip": data.get("ip_str"),
            "original_target": target,
            "organization": data.get("org"),
            "asn": data.get("asn"),
            "isp": data.get("isp"),
            "country": data.get("country_name"),
            "city": data.get("city"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "hostnames": data.get("hostnames", []),
            "domains": data.get("domains", []),
            "open_ports": data.get("ports", []),
            "vulns": list(data.get("vulns", {}).keys()) if data.get("vulns") else [],
            "tags": data.get("tags", []),
            "last_update": data.get("last_update"),
        }

        services = []
        for item in data.get("data", [])[:10]:
            service = {
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "version": item.get("version"),
                "banner": item.get("data", "")[:200],
            }
            if item.get("ssl"):
                service["ssl_cert_issuer"] = item.get("ssl", {}).get("cert", {}).get("issuer", {}).get("CN")
            services.append(service)

        summary["services"] = services
        summary["total_services"] = len(data.get("data", []))

        # Risk assessment
        risk_indicators = []
        if summary["vulns"]:
            risk_indicators.append(f"{len(summary['vulns'])} known vulnerabilities")
        if 22 in summary["open_ports"]:
            risk_indicators.append("SSH exposed")
        if 3389 in summary["open_ports"]:
            risk_indicators.append("RDP exposed")
        if 23 in summary["open_ports"]:
            risk_indicators.append("Telnet exposed (insecure)")

        summary["risk_indicators"] = risk_indicators
        summary["risk_level"] = "HIGH" if len(risk_indicators) > 2 else "MEDIUM" if risk_indicators else "LOW"

        return {
            "raw": summary,
            "full_response": data
        }

    except requests.exceptions.Timeout:
        return {"error": "Shodan request timeout (>10s)"}
    except Exception as e:
        logger.error(f"[SHODAN] Error analyzing {target}: {e}")
        return {"error": str(e)}


def logic_securitytrails(target: str) -> Dict[str, Any]:
    """
    DNS history and subdomain discovery via SecurityTrails API.

    Args:
        target: Domain to analyze

    Returns:
        Dict with SecurityTrails data or error/skipped
    """
    api_key = os.getenv("SECURITYTRAILS_API_KEY")
    if not api_key:
        logger.info(f"[SECURITYTRAILS] Skipped - SECURITYTRAILS_API_KEY not configured")
        return {"skipped": True, "reason": "SECURITYTRAILS_API_KEY not configured"}

    try:
        headers = {
            "APIKEY": api_key,
            "Accept": "application/json"
        }

        # Get domain info
        domain_url = f"https://api.securitytrails.com/v1/domain/{target}"
        r = requests.get(domain_url, headers=headers, timeout=10)

        if r.status_code == 401:
            return {"error": "Invalid SecurityTrails API key"}
        elif r.status_code == 404:
            return {"error": f"Domain '{target}' not found"}
        elif r.status_code == 429:
            return {"error": "SecurityTrails rate limit exceeded"}
        elif r.status_code != 200:
            return {"error": f"SecurityTrails API error: HTTP {r.status_code}"}

        domain_data = r.json()

        # Get subdomain count
        subdomain_url = f"https://api.securitytrails.com/v1/domain/{target}/subdomains"
        subdomain_data = {}
        try:
            r2 = requests.get(subdomain_url, headers=headers, timeout=10)
            if r2.status_code == 200:
                subdomain_data = r2.json()
        except:
            pass

        summary = {
            "domain": target,
            "alexa_rank": domain_data.get("alexa_rank"),
            "apex_domain": domain_data.get("apex_domain"),
            "current_dns": domain_data.get("current_dns", {}),
            "subdomain_count": subdomain_data.get("subdomain_count", 0),
            "subdomains": subdomain_data.get("subdomains", [])[:50],
        }

        return {
            "raw": summary,
            "full_response": {"domain": domain_data, "subdomains": subdomain_data}
        }

    except requests.exceptions.Timeout:
        return {"error": "SecurityTrails request timeout (>10s)"}
    except Exception as e:
        logger.error(f"[SECURITYTRAILS] Error analyzing {target}: {e}")
        return {"error": str(e)}


def logic_crtsh(domain: str) -> Dict[str, Any]:
    """
    Subdomain discovery via crt.sh (Certificate Transparency).

    Args:
        domain: Domain to query

    Returns:
        Dict with subdomain list or error
    """
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return {"error": f"HTTP {response.status_code}"}

        data = response.json()

        # Extract unique subdomains
        subdomains = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for subdomain in name_value.split("\n"):
                subdomain = subdomain.strip().lower()
                if subdomain and not subdomain.startswith("*"):
                    subdomains.add(subdomain)

        return {
            "raw": {
                "total_certificates": len(data),
                "subdomains_found": len(subdomains),
                "subdomains": sorted(list(subdomains))[:50]
            }
        }
    except Exception as e:
        return {"error": str(e)}


def logic_subdomains(domain: str) -> Dict[str, Any]:
    """
    Comprehensive subdomain enumeration via multiple sources.

    Sources:
    - crt.sh (Certificate Transparency)
    - HackerTarget API
    - DNS brute-force (common subdomains)

    Args:
        domain: Domain to enumerate

    Returns:
        Dict with all discovered subdomains
    """
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
        "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "blog",
        "server", "cpanel", "autodiscover", "autoconfig", "admin",
        "portal", "dev", "staging", "test", "api", "app", "cdn", "cloud",
        "git", "gitlab", "jenkins", "ci", "monitor", "status", "support",
        "shop", "store", "secure", "vpn", "ssh", "backup", "db", "database",
        "mysql", "postgres", "redis", "elastic", "kibana", "grafana", "docs",
        "wiki", "forum", "intranet", "internal", "mobile", "m", "img",
        "images", "static", "assets", "media", "files", "download", "upload"
    ]

    results = {
        "domain": domain,
        "sources": {},
        "all_subdomains": set(),
        "resolved": {},
        "statistics": {}
    }

    # 1. crt.sh
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            crt_subdomains = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for subdomain in name_value.split("\n"):
                    subdomain = subdomain.strip().lower()
                    if subdomain and not subdomain.startswith("*"):
                        crt_subdomains.add(subdomain)
            results["sources"]["crt.sh"] = {
                "count": len(crt_subdomains),
                "subdomains": sorted(list(crt_subdomains))[:100]
            }
            results["all_subdomains"].update(crt_subdomains)
    except Exception as e:
        results["sources"]["crt.sh"] = {"error": str(e)}

    # 2. HackerTarget API
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200 and "error" not in response.text.lower():
            ht_subdomains = set()
            for line in response.text.strip().split("\n"):
                if "," in line:
                    subdomain = line.split(",")[0].strip().lower()
                    if subdomain:
                        ht_subdomains.add(subdomain)
            results["sources"]["hackertarget"] = {
                "count": len(ht_subdomains),
                "subdomains": sorted(list(ht_subdomains))[:100]
            }
            results["all_subdomains"].update(ht_subdomains)
    except Exception as e:
        results["sources"]["hackertarget"] = {"error": str(e)}

    # 3. DNS brute-force
    def resolve_subdomain(subdomain_prefix):
        full_domain = f"{subdomain_prefix}.{domain}"
        try:
            socket.gethostbyname(full_domain)
            return full_domain
        except socket.gaierror:
            return None

    try:
        dns_found = set()
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(resolve_subdomain, sub): sub for sub in COMMON_SUBDOMAINS}
            for future in concurrent.futures.as_completed(futures, timeout=30):
                result = future.result()
                if result:
                    dns_found.add(result)

        results["sources"]["dns_bruteforce"] = {
            "count": len(dns_found),
            "subdomains": sorted(list(dns_found))
        }
        results["all_subdomains"].update(dns_found)
    except Exception as e:
        results["sources"]["dns_bruteforce"] = {"error": str(e)}

    # 4. Resolve all found subdomains to IPs
    all_subs = list(results["all_subdomains"])[:200]

    def resolve_to_ip(subdomain):
        try:
            ip = socket.gethostbyname(subdomain)
            return (subdomain, ip)
        except socket.gaierror:
            return (subdomain, None)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(resolve_to_ip, sub) for sub in all_subs]
            for future in concurrent.futures.as_completed(futures, timeout=60):
                subdomain, ip = future.result()
                if ip:
                    results["resolved"][subdomain] = ip
    except Exception as e:
        logger.warning(f"[SUBDOMAINS] Resolution error: {e}")

    # Statistics
    results["statistics"] = {
        "total_unique": len(results["all_subdomains"]),
        "resolved_count": len(results["resolved"]),
        "unique_ips": len(set(results["resolved"].values())),
        "sources_used": len([s for s in results["sources"].values() if "error" not in s])
    }

    results["all_subdomains"] = sorted(list(results["all_subdomains"]))[:200]

    logger.info(f"[SUBDOMAINS] {domain}: {results['statistics']['total_unique']} found, {results['statistics']['resolved_count']} resolved")

    return {"raw": results}


def logic_wayback(domain: str) -> Dict[str, Any]:
    """
    Fetch site history via Wayback Machine (Internet Archive).

    Args:
        domain: Domain to query

    Returns:
        Dict with historical snapshots or error
    """
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url={domain}&output=json&fl=timestamp,original,statuscode&collapse=timestamp:8"
        response = requests.get(url, timeout=5)

        if response.status_code != 200:
            return {"error": f"HTTP {response.status_code}"}

        data = response.json()

        if len(data) <= 1:
            return {"raw": {"snapshots_count": 0, "first_seen": None, "last_seen": None}}

        snapshots = data[1:]
        first_snapshot = snapshots[0]
        last_snapshot = snapshots[-1]

        def format_timestamp(ts):
            try:
                return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}"
            except:
                return ts

        return {
            "raw": {
                "snapshots_count": len(snapshots),
                "first_seen": format_timestamp(first_snapshot[0]),
                "last_seen": format_timestamp(last_snapshot[0]),
                "recent_snapshots": [
                    {
                        "date": format_timestamp(s[0]),
                        "url": s[1],
                        "status": s[2]
                    } for s in snapshots[-5:]
                ]
            }
        }
    except Exception as e:
        return {"error": str(e)}


def logic_email_config(domain: str) -> Dict[str, Any]:
    """
    Email configuration analysis (SPF, DMARC, MX records).

    Args:
        domain: Domain to analyze

    Returns:
        Dict with email security configuration or error
    """
    try:
        import dns.resolver

        results = {
            "spf": None,
            "dmarc": None,
            "mx_records": []
        }

        # SPF (TXT record)
        try:
            spf_records = dns.resolver.resolve(domain, 'TXT')
            for record in spf_records:
                txt = str(record).strip('"')
                if txt.startswith("v=spf1"):
                    results["spf"] = txt
                    break
        except:
            results["spf"] = "Non configuré"

        # DMARC (TXT record on _dmarc.domain)
        try:
            dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for record in dmarc_records:
                txt = str(record).strip('"')
                if txt.startswith("v=DMARC1"):
                    results["dmarc"] = txt
                    break
        except:
            results["dmarc"] = "Non configuré"

        # MX Records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            for mx in mx_records:
                results["mx_records"].append({
                    "priority": mx.preference,
                    "server": str(mx.exchange).rstrip('.')
                })
        except:
            pass

        return {"raw": results}
    except ImportError:
        return {"error": "Module dnspython not installed (pip install dnspython)"}
    except Exception as e:
        return {"error": str(e)}


def logic_security_txt(target: str) -> Dict[str, Any]:
    """
    Fetch security.txt file (RFC 9116).

    Args:
        target: URL or domain to check

    Returns:
        Dict with security.txt content or error
    """
    try:
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        locations = [
            f"{base_url}/.well-known/security.txt",
            f"{base_url}/security.txt"
        ]

        for url in locations:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    content = response.text

                    fields = {}
                    for line in content.split('\n'):
                        line = line.strip()
                        if ':' in line and not line.startswith('#'):
                            key, value = line.split(':', 1)
                            fields[key.strip()] = value.strip()

                    return {
                        "raw": {
                            "exists": True,
                            "location": url,
                            "contact": fields.get("Contact"),
                            "expires": fields.get("Expires"),
                            "encryption": fields.get("Encryption"),
                            "policy": fields.get("Policy"),
                            "all_fields": fields,
                            "full_content": content[:1000]
                        }
                    }
            except:
                continue

        return {"raw": {"exists": False}}
    except Exception as e:
        return {"error": str(e)}


def logic_web_enrichment(query: str) -> Dict[str, Any]:
    """
    Web search and enrichment for context gathering.

    Note: This is a placeholder that returns a skipped status.
    The full implementation requires the scrapy worker and additional dependencies.
    Import the full version from backend_logic if needed.

    Args:
        query: Search query

    Returns:
        Dict with web search results or skipped status
    """
    # This function requires scrapy worker - return skipped for now
    # The full implementation is in backend_logic.py
    logger.info(f"[WEB_ENRICHMENT] Placeholder - use backend_logic.logic_web_enrichment for full functionality")
    return {
        "skipped": True,
        "reason": "Web enrichment requires scrapy worker - use backend_logic.logic_web_enrichment"
    }
