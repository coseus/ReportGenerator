# tests/test_severity.py
"""Unit tests for centralized severity normalization."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from util.severity import normalize_severity


def test_canonical_values_passthrough():
    for sev in ("Critical", "High", "Moderate", "Low", "Informational"):
        assert normalize_severity(sev) == sev


def test_case_insensitive():
    assert normalize_severity("CRITICAL") == "Critical"
    assert normalize_severity("high") == "High"
    assert normalize_severity("LOW") == "Low"


def test_aliases():
    assert normalize_severity("medium") == "Moderate"
    assert normalize_severity("med") == "Moderate"
    assert normalize_severity("info") == "Informational"
    assert normalize_severity("crit") == "Critical"
    assert normalize_severity("none") == "Informational"
    assert normalize_severity("log") == "Informational"


def test_nessus_numeric_severity():
    assert normalize_severity("0") == "Informational"
    assert normalize_severity("1") == "Low"
    assert normalize_severity("2") == "Moderate"
    assert normalize_severity("3") == "High"
    assert normalize_severity("4") == "Critical"


def test_unknown_defaults_to_informational():
    assert normalize_severity("xyz") == "Informational"
    assert normalize_severity("") == "Informational"
    assert normalize_severity(None) == "Informational"
    assert normalize_severity(999) == "Informational"
