# util/compliance.py
"""
Maps penetration-test findings to compliance framework controls:
  - NIS2 Directive art. 21(2)
  - IEC 62443-3-3 (System Requirements)
  - NIST SP 800-53 / 800-82r3
  - ISO/IEC 27001:2022 (Annex A)

Matching is keyword-based over each finding's title/description/recommendation/CVE.
A finding may set "compliance_category" to force a category, and the whole report
may provide "compliance_rows" to bypass auto-mapping entirely.

Derived from the framework mapping the team already uses in the OT toolkit,
extended with common IT/AD/web categories.
"""
from __future__ import annotations
from typing import Any

# Ordered most-specific first; first keyword hit wins.
# This is the built-in fallback; the live mapping is loaded from data/compliance_mapping.csv
# (created from these defaults on first run) so it can be edited as a separate file / from the web.
_DEFAULT_MAP: list[dict[str, Any]] = [
    {"category": "Default credentials",
     "keywords": ["default cred", "default password", "admin/admin", "factory default", "hardcoded credential", "default account"],
     "iec62443": "SR 1.1 / SR 1.5", "nist": "IA-5 Authenticator Mgmt", "nis2": "21(2)(i)", "iso27001": "A.5.17, A.8.5"},
    {"category": "Default / weak SNMP",
     "keywords": ["snmp community", "snmp public", "snmp private", "snmp default", "snmpv1", "snmpv2"],
     "iec62443": "SR 1.2 / SR 1.5", "nist": "IA-5, CM-6", "nis2": "21(2)(i)", "iso27001": "A.8.5, A.8.9"},
    {"category": "Insecure remote access (Telnet/VNC/RDP)",
     "keywords": ["telnet", "vnc", "rdp", "remote desktop", "exposed management"],
     "iec62443": "SR 2.6 Remote session termination", "nist": "AC-17 Remote Access", "nis2": "21(2)(j)", "iso27001": "A.6.7, A.8.20"},
    {"category": "Missing MFA on remote access",
     "keywords": ["mfa", "2fa", "multi-factor", "multifactor", "without mfa", "no mfa"],
     "iec62443": "SR 1.1 / SR 2.1", "nist": "IA-2(1), AC-17", "nis2": "21(2)(j)", "iso27001": "A.8.5"},
    {"category": "Weak passwords / no policy",
     "keywords": ["weak password", "password policy", "kerberoast", "as-rep", "asrep", "brute force", "password spray", "spn"],
     "iec62443": "SR 1.7 Password strength", "nist": "IA-5(1)", "nis2": "21(2)(i)", "iso27001": "A.5.17"},
    {"category": "Shared / stale accounts",
     "keywords": ["shared account", "inactive account", "stale account", "orphaned account", "dormant account"],
     "iec62443": "SR 1.3 Account management", "nist": "AC-2 Account Mgmt", "nis2": "21(2)(i)", "iso27001": "A.5.16, A.5.18"},
    {"category": "SMB / legacy Windows exposure",
     "keywords": ["smbv1", "smb signing", "null session", "llmnr", "nbt-ns", "netbios", "ms17-010", "eternalblue"],
     "iec62443": "SR 1.1 / SR 3.1", "nist": "CM-7, SC-7", "nis2": "21(2)(e),(i)", "iso27001": "A.8.8, A.8.20"},
    {"category": "Weak IT/OT segmentation",
     "keywords": ["segmentation", "vlan", "flat network", "zone", "dmz", "purdue"],
     "iec62443": "SR 5.1 Network segmentation", "nist": "AC-4, SC-7 Boundary Protection", "nis2": "21(2)(a),(d)", "iso27001": "A.8.22"},
    {"category": "Unfiltered IT-OT interconnection",
     "keywords": ["interconnection", "dual-homed", "dual homed", "pivot", "bridge", "unfiltered path"],
     "iec62443": "SR 5.1 / SR 5.2 Zone boundary", "nist": "SC-7 Boundary Protection", "nis2": "21(2)(a)", "iso27001": "A.8.22, A.8.20"},
    {"category": "Cleartext / industrial protocol in the clear",
     "keywords": ["cleartext", "plaintext", "plain text", "unencrypted", "modbus", "s7comm", "s7 ", "dnp3", "iec-104", "iec104", "profinet", "ftp", "http "],
     "iec62443": "SR 4.1 Information confidentiality", "nist": "SC-8 Transmission Confidentiality", "nis2": "21(2)(h)", "iso27001": "A.8.24, A.8.20"},
    {"category": "Weak TLS / cryptography",
     "keywords": ["tls", "ssl", "weak cipher", "self-signed", "certificate", "sslv3", "rc4", "sweet32", "poodle", "beast"],
     "iec62443": "SR 4.3 Use of cryptography", "nist": "SC-8, SC-13", "nis2": "21(2)(h)", "iso27001": "A.8.24"},
    {"category": "Missing visibility / detection",
     "keywords": ["logging", "no logging", "monitoring", "siem", "detection", "audit trail", "no visibility"],
     "iec62443": "SR 6.1 / SR 6.2 Audit", "nist": "AU-6, SI-4 Monitoring", "nis2": "21(2)(b)", "iso27001": "A.8.15, A.8.16"},
    {"category": "Unpatched / outdated software",
     "keywords": ["cve-", "outdated", "unpatched", "missing patch", "end of life", "end-of-life", "eol", "obsolete", "vulnerable version", "old firmware", "firmware"],
     "iec62443": "SR 3.4 / SR 7.6 Patching", "nist": "RA-5, SI-2 Flaw Remediation", "nis2": "21(2)(e)", "iso27001": "A.8.8"},
]

# Applied when nothing else matches.
FALLBACK = {"category": "General security finding",
            "iec62443": "SR 3.1 / SR 7.x", "nist": "RA-5 Vulnerability Scanning", "nis2": "21(2)(a),(e)", "iso27001": "A.8.8"}


import os as _os
import csv as _csv

_MAPPING_CSV = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "data", "compliance_mapping.csv")
_FIELDS = ["category", "keywords", "nis2", "iec62443", "nist", "iso27001"]
_cache = {"mtime": None, "map": None}


def _row_to_entry(row: dict) -> dict:
    kw = str(row.get("keywords") or "")
    keywords = [k.strip().lower() for k in kw.replace("|", ";").split(";") if k.strip()]
    return {
        "category": str(row.get("category") or "").strip(),
        "keywords": keywords,
        "nis2": str(row.get("nis2") or "").strip(),
        "iec62443": str(row.get("iec62443") or "").strip(),
        "nist": str(row.get("nist") or "").strip(),
        "iso27001": str(row.get("iso27001") or "").strip(),
    }


def _entry_to_row(entry: dict) -> dict:
    return {
        "category": entry.get("category", ""),
        "keywords": "; ".join(entry.get("keywords", []) or []),
        "nis2": entry.get("nis2", ""),
        "iec62443": entry.get("iec62443", ""),
        "nist": entry.get("nist", ""),
        "iso27001": entry.get("iso27001", ""),
    }


def _write_csv(path: str, entries: list[dict]) -> None:
    _os.makedirs(_os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = _csv.DictWriter(f, fieldnames=_FIELDS)
        w.writeheader()
        for e in entries:
            w.writerow(_entry_to_row(e))


def ensure_mapping_file() -> str:
    """Create data/compliance_mapping.csv from the built-in defaults if it does not exist."""
    if not _os.path.exists(_MAPPING_CSV):
        try:
            _write_csv(_MAPPING_CSV, _DEFAULT_MAP)
        except Exception:
            pass
    return _MAPPING_CSV


def get_mapping() -> list[dict]:
    """Live mapping: loaded from the CSV (auto-created from defaults), fresh on file change."""
    try:
        ensure_mapping_file()
        mtime = _os.path.getmtime(_MAPPING_CSV)
        if _cache["map"] is not None and _cache["mtime"] == mtime:
            return _cache["map"]
        with open(_MAPPING_CSV, newline="", encoding="utf-8") as f:
            entries = [_row_to_entry(r) for r in _csv.DictReader(f) if (r.get("category") or "").strip()]
        if not entries:
            entries = list(_DEFAULT_MAP)
        _cache["map"] = entries
        _cache["mtime"] = mtime
        return entries
    except Exception:
        return list(_DEFAULT_MAP)


def save_mapping(entries: list[dict]) -> None:
    """Persist an edited mapping (list of entry dicts) back to the CSV."""
    _write_csv(_MAPPING_CSV, entries)
    _cache["mtime"] = None  # force reload


# Backwards-compatible module-level name (a snapshot; prefer get_mapping()).
COMPLIANCE_MAP = get_mapping()


def _text_of(finding: dict) -> str:
    parts = [finding.get(k, "") for k in ("title", "description", "impact", "recommendation", "cve", "protocol")]
    if isinstance(finding.get("cves"), list):
        parts.append(" ".join(finding.get("cves")))
    return " ".join(str(p) for p in parts if p).lower()


def category_for(finding: dict) -> dict:
    mapping = get_mapping()
    forced = str(finding.get("compliance_category") or "").strip()
    if forced:
        for entry in mapping:
            if entry["category"].lower() == forced.lower():
                return entry
        return {**FALLBACK, "category": forced}
    text = _text_of(finding)
    for entry in mapping:
        if entry.get("keywords") and any(kw in text for kw in entry["keywords"]):
            return entry
    return FALLBACK


def map_findings(findings: list[dict]) -> list[dict]:
    """One row per finding: severity, title, host(s), category + framework controls."""
    rows = []
    for f in findings or []:
        entry = category_for(f)
        host = f.get("host") or ""
        if not host and isinstance(f.get("hosts"), list) and f["hosts"]:
            host = ", ".join(str(h) for h in f["hosts"])
        rows.append({
            "title": f.get("title") or "Untitled finding",
            "severity": f.get("severity") or "Informational",
            "host": host,
            "category": entry["category"],
            "iec62443": entry["iec62443"],
            "nist": entry["nist"],
            "nis2": entry["nis2"],
            "iso27001": entry.get("iso27001", ""),
        })
    return rows


import re as _re


def _expand_nis2(value: str) -> list[str]:
    """'21(2)(e),(i)' -> ['art.21(2)(e)', 'art.21(2)(i)']."""
    value = str(value).replace(" ", "")
    m = _re.match(r"^(\d+\(\d+\))", value)
    base = m.group(1) if m else "21(2)"
    letters = _re.findall(r"\(([a-z])\)", value)
    return [f"art.{base}({ltr})" for ltr in letters] or ([f"art.{value}"] if value else [])


def coverage_summary(rows: list[dict]) -> dict:
    """Distinct frameworks touched, for a short intro line."""
    nis2, iec, cats = set(), set(), set()
    for r in rows:
        cats.add(r["category"])
        for art in _expand_nis2(r["nis2"]):
            nis2.add(art)
        iec.add(str(r["iec62443"]).split("/")[0].strip())
    return {
        "categories": sorted(cats),
        "nis2_articles": sorted(nis2),
        "iec_requirements": sorted(x for x in iec if x),
        "total": len(rows),
    }


# Framework columns for the compliance table. key -> (i18n header key, row field, display name).
FRAMEWORKS = [
    ("nis2", "compliance_col_nis2", "nis2", "NIS2 art.21(2)"),
    ("iec", "compliance_col_iec", "iec62443", "IEC 62443-3-3"),
    ("nist", "compliance_col_nist", "nist", "NIST SP 800-53/82"),
    ("iso27001", "compliance_col_iso", "iso27001", "ISO/IEC 27001"),
]
ALL_FRAMEWORKS = [f[0] for f in FRAMEWORKS]


def selected_frameworks(report: dict) -> list[str]:
    """Framework keys chosen for export; defaults to all when unset."""
    sel = report.get("compliance_frameworks")
    if not sel:
        return list(ALL_FRAMEWORKS)
    return [k for k in ALL_FRAMEWORKS if k in sel]


def framework_columns(report: dict):
    """Yield (header_i18n_key, row_field, display_name) for the selected frameworks."""
    sel = set(selected_frameworks(report))
    return [(hk, field, name) for key, hk, field, name in FRAMEWORKS if key in sel]
