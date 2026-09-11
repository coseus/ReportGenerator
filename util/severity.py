# util/severity.py
"""
Centralized severity normalization.
Eliminates duplicated _norm_severity / _normalize_severity logic
that previously existed in parsers.py, json_utils.py, and findings_tab.py.
"""

from __future__ import annotations
from typing import Any

VALID_SEVERITIES = ("Critical", "High", "Moderate", "Low", "Informational")

_SEVERITY_MAP: dict[str, str] = {
    "critical":      "Critical",
    "crit":          "Critical",
    "high":          "High",
    "medium":        "Moderate",
    "moderate":      "Moderate",
    "med":           "Moderate",
    "low":           "Low",
    "info":          "Informational",
    "informational": "Informational",
    "information":   "Informational",
    "none":          "Informational",
    "log":           "Informational",
    "0":             "Informational",
    "1":             "Low",
    "2":             "Moderate",
    "3":             "High",
    "4":             "Critical",
}


def normalize_severity(value: Any) -> str:
    """
    Normalize any severity representation to one of the five canonical values.
    Returns 'Informational' as safe default for unrecognized inputs.
    """
    if value is None:
        return "Informational"
    raw = str(value).strip().lower()
    return _SEVERITY_MAP.get(raw, "Informational")
