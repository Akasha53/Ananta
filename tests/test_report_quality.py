import pytest

from backend_logic import summarize_tool_output, postprocess_structured_findings


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
