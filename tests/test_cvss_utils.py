# tests/test_cvss_utils.py
"""Unit tests for CVSS 3.1 calculator and utilities."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from util.cvss_utils import (
    calculate_cvss31,
    normalize_vector,
    severity_from_score,
    suggest_vectors_for_score,
    auto_fill_finding_cvss,
)


def test_severity_from_score():
    assert severity_from_score(0.0) == "Informational"
    assert severity_from_score(1.0) == "Low"
    assert severity_from_score(3.9) == "Low"
    assert severity_from_score(4.0) == "Moderate"
    assert severity_from_score(6.9) == "Moderate"
    assert severity_from_score(7.0) == "High"
    assert severity_from_score(8.9) == "High"
    assert severity_from_score(9.0) == "Critical"
    assert severity_from_score(10.0) == "Critical"


def test_severity_from_score_invalid():
    assert severity_from_score("not_a_number") == "Informational"
    assert severity_from_score(None) == "Informational"


def test_normalize_vector_with_prefix():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert normalize_vector(v) == v


def test_normalize_vector_bare():
    bare = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    normalized = normalize_vector(bare)
    assert normalized.startswith("CVSS:3.1/")


def test_calculate_cvss31_known_value():
    # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
    score, severity = calculate_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score == 9.8
    assert severity == "Critical"


def test_calculate_cvss31_low():
    # Low-impact vector
    score, severity = calculate_cvss31("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
    assert score <= 2.0
    assert severity == "Low"


def test_auto_fill_finding_cvss():
    finding = {
        "title": "Test",
        "severity": "Informational",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }
    result = auto_fill_finding_cvss(finding)
    assert result["cvss"] == "9.8"
    assert result["severity"] == "Critical"
    assert result["cvss_auto_ok"] is True


def test_auto_fill_finding_cvss_no_vector():
    finding = {"title": "Test", "severity": "High"}
    result = auto_fill_finding_cvss(finding)
    assert result["severity"] == "High"  # Unchanged


def test_suggest_vectors_returns_list():
    results = suggest_vectors_for_score(7.5, limit=5)
    assert isinstance(results, list)
    assert len(results) <= 5
    for r in results:
        assert r["score"] == "7.5"
        assert r["severity"] == "High"


def test_suggest_vectors_cached():
    """Calling twice should return same result (lru_cache)."""
    r1 = suggest_vectors_for_score(5.0, limit=3)
    r2 = suggest_vectors_for_score(5.0, limit=3)
    assert r1 == r2
