import pytest

from backend_logic import (
    summarize_tool_output,
    postprocess_structured_findings,
    append_spiderfoot_summary_to_report,
)


def test_summarize_tool_output_vuln_scan_is_compact():
    data = {
        "vulnerabilities_found": 7,
        "risk_level": "HIGH",
        "cve_findings": ["CVE-2024-0001", "CVE-2023-9999"],
        "vulnerabilities": [{"severity": "LOW"}] * 7,
    }
    s = summarize_tool_output("vuln_scan", data)
    assert "Vuln scan" in s
    assert "7" in s
    assert "CVE=2" in s
    assert len(s) <= 200


def test_summarize_tool_output_web_enrichment_includes_org_intel_counts():
    data = {
        "text": "x" * 1000,
        "sources": [{"title": "t", "url": "https://example.com", "summary": "..."}] * 3,
        "people": [{"name": "Jane Doe", "role": "CEO", "email": "jane@example.com", "source_url": "https://example.com/team"}],
        "public_emails": ["contact@example.com"],
        "social_links": ["https://www.linkedin.com/company/example"],
    }
    s = summarize_tool_output("web_enrichment", data)
    assert "Web intel" in s
    assert "people=" in s
    assert "emails=" in s
    assert "socials=" in s
    assert len(s) <= 200


def test_postprocess_structured_findings_dedupes_similar_claims():
    structured = {
        "executive_summary": "test",
        "top_findings": [
            {
                "id": "F-001",
                "category": "VULN",
                "title": "Headers manquants",
                "claim": "Header HSTS manquant sur example.com",
                "severity": "LOW",
                "confidence": "MEDIUM",
                "evidence": ["Missing security headers: 2"],
                "impact": "Downgrade possible",
                "remediation": "Ajouter HSTS",
                "sources": [{"tool": "http_headers", "reference": "HTTP 200"}],
            },
            {
                "id": "F-002",
                "category": "VULN",
                "title": "HSTS absent",
                "claim": "Le header HSTS est manquant sur example.com",
                "severity": "LOW",
                "confidence": "LOW",
                "evidence": ["Missing security headers: 2"],
                "impact": "Downgrade HTTPS",
                "remediation": "Ajouter Strict-Transport-Security",
                "sources": [{"tool": "http_headers", "reference": "security_headers"}],
            },
        ],
        "limitations": [],
        "sources_used": ["http_headers"],
    }

    out = postprocess_structured_findings(structured)
    assert isinstance(out["top_findings"], list)
    assert len(out["top_findings"]) == 1
    f = out["top_findings"][0]
    assert f["id"] == "F-001"
    assert f["category"] == "VULN"
    assert len(f["evidence"]) >= 1


def test_postprocess_structured_findings_caps_sizes():
    structured = {
        "executive_summary": "x" * 2000,
        "top_findings": [
            {
                "claim": "y" * 2000,
                "evidence": ["z" * 2000] * 20,
                "severity": "HIGH",
                "category": "OSINT",
            }
        ] * 50,
        "limitations": ["l" * 2000] * 50,
        "sources_used": ["tool" * 100] * 100,
    }

    out = postprocess_structured_findings(structured)
    assert len(out["top_findings"]) <= 25
    assert len(out["executive_summary"]) <= 400
    assert len(out["top_findings"][0]["claim"]) <= 400
    assert len(out["top_findings"][0]["evidence"]) <= 6
    assert all(len(x) <= 180 for x in out["top_findings"][0]["evidence"])
    assert len(out["limitations"]) <= 12
    assert len(out["sources_used"]) <= 40


def test_spiderfoot_summary_is_compact_and_appended():
    data = {
        "events_count": 42,
        "high_confidence_findings": 3,
        "entities": {"domains": 5, "ips": 4, "emails": 2},
        "risk_level": "MEDIUM",
    }
    s = summarize_tool_output("spiderfoot", data)
    assert "SpiderFoot" in s
    assert "events=42" in s
    assert "risk=MEDIUM" in s

    report = "# Rapport\n\nContenu principal."
    raw = {"tools": {"spiderfoot": {"status": "ok", "data": data}}}
    with_section = append_spiderfoot_summary_to_report(report, raw, language="fr")
    assert "Résumé SpiderFoot" in with_section
