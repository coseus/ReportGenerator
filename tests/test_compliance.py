import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from util.compliance import map_findings, coverage_summary, category_for


def test_maps_known_categories():
    rows = map_findings([
        {"title": "SMBv1 EternalBlue MS17-010", "severity": "Critical", "host": "10.0.0.9"},
        {"title": "Default credentials on switch", "severity": "High", "host": "10.0.0.2"},
        {"title": "Weak TLS ciphers SWEET32", "severity": "Low", "host": "10.0.0.3"},
    ])
    cats = [r["category"] for r in rows]
    assert cats[0] == "SMB / legacy Windows exposure"
    assert cats[1] == "Default credentials"
    assert cats[2] == "Weak TLS / cryptography"
    assert all("21(2)" in r["nis2"] for r in rows)


def test_unmatched_uses_fallback():
    rows = map_findings([{"title": "Some odd thing", "severity": "Moderate"}])
    assert rows[0]["category"] == "General security finding"


def test_manual_override_category():
    entry = category_for({"title": "x", "compliance_category": "Default credentials"})
    assert entry["category"] == "Default credentials"


def test_coverage_expands_nis2_letters():
    rows = map_findings([{"title": "SMBv1 MS17-010", "severity": "Critical"}])
    cov = coverage_summary(rows)
    # 21(2)(e),(i) must expand to two distinct article references
    assert "art.21(2)(e)" in cov["nis2_articles"]
    assert "art.21(2)(i)" in cov["nis2_articles"]
    assert cov["total"] == 1


def test_empty_findings():
    assert map_findings([]) == []
    assert coverage_summary([])["total"] == 0
