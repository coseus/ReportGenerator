from __future__ import annotations

import copy
import json
import logging
from pathlib import Path
from typing import Any

from util.cvss_utils import auto_fill_finding_cvss, severity_from_score
from util.severity import normalize_severity as _normalize_severity

logger = logging.getLogger(__name__)

VALID_SEVERITIES = ("Critical", "High", "Moderate", "Low", "Informational")
VALID_LANGUAGES = ("en", "ro")

DEFAULT_TEMPLATE = {
    "client": "",
    "project": "",
    "tester": "",
    "contact": "",
    "date": "",
    "version": "1.0",
    "theme_hex": "#ED863D",
    "watermark_enabled": False,
    "logo_b64": "",
    "report_language": "en",
    "include_charts": True,
    "executive_summary": "",
    "assessment_overview": "",
    "assessment_details": "",
    "scope": "",
    "scope_exclusions": "",
    "client_allowances": "",
    "section_1_0_confidentiality_and_legal": "",
    "section_1_1_confidentiality_statement": "",
    "section_1_2_disclaimer": "",
    "section_1_3_contact_information": "",
    "sections": {},
    "contacts": [],
    "findings": [],
    "overall_risk": "Informational",
    "attack_path": [],
    "additional_reports": [],
    "detailed_walkthrough": [],
    "remediation_short": [],
    "remediation_medium": [],
    "remediation_long": [],
    "vuln_summary_counts": {},
    "vuln_summary_total": 0,
    "vuln_by_host": {},
}


def _json_default(obj: Any) -> str:
    return str(obj)


def _safe_text(value: Any) -> str:
    return "" if value is None else str(value)


def _ensure_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _ensure_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _normalize_language(value: Any) -> str:
    lang = _safe_text(value).strip().lower()
    return lang if lang in VALID_LANGUAGES else "en"


def _normalize_theme_hex(value: Any) -> str:
    text = _safe_text(value).strip()
    if len(text) == 7 and text.startswith("#"):
        hex_part = text[1:]
        if all(ch in "0123456789abcdefABCDEF" for ch in hex_part):
            return text.upper()
    return "#ED863D"


def _normalize_image_item(item: Any, default_name: str = "") -> dict | None:
    if isinstance(item, dict):
        data = _safe_text(item.get("data")).strip()
        if not data:
            return None
        return {
            "data": data,
            "name": _safe_text(item.get("name")).strip() or default_name,
        }

    if isinstance(item, str):
        data = item.strip()
        if not data:
            return None
        return {
            "data": data,
            "name": default_name,
        }

    return None


def _normalize_images(images: Any, default_prefix: str = "Image") -> list[dict]:
    normalized = []
    for idx, item in enumerate(_ensure_list(images), start=1):
        image = _normalize_image_item(item, default_name=f"{default_prefix} {idx}")
        if image:
            normalized.append(image)
    return normalized


def _normalize_string_list(items: Any) -> list[str]:
    result = []
    for item in _ensure_list(items):
        text = _safe_text(item).strip()
        if text:
            result.append(text)
    return result


def _coerce_single_to_multi(item: dict, single_key: str, multi_key: str) -> None:
    single_value = _safe_text(item.get(single_key)).strip()
    multi_value = item.get(multi_key)

    if isinstance(multi_value, list):
        cleaned = [v for v in (_safe_text(x).strip() for x in multi_value) if v]
        item[multi_key] = cleaned
    else:
        item[multi_key] = []

    if single_value and single_value not in item[multi_key]:
        item[multi_key].insert(0, single_value)

    item[single_key] = item[multi_key][0] if item[multi_key] else ""


def _normalize_contacts(contacts: Any) -> list[dict]:
    normalized = []
    for item in _ensure_list(contacts):
        if not isinstance(item, dict):
            continue
        role = _safe_text(item.get("role")).strip()
        if role.lower() in ("client",):
            role = "Client"
        elif role.lower() in ("tester", "evaluator", "provider", "furnizor"):
            role = "Tester"
        else:
            role = role or "Tester"
        normalized.append(
            {
                "name": _safe_text(item.get("name")).strip(),
                "title": _safe_text(item.get("title")).strip(),
                "contact": _safe_text(item.get("contact")).strip(),
                "role": role,
            }
        )
    return normalized


def _normalize_sections(report: dict) -> None:
    sections = _ensure_dict(report.get("sections"))
    report["sections"] = sections

    for key in (
        "section_1_0_confidentiality_and_legal",
        "section_1_1_confidentiality_statement",
        "section_1_2_disclaimer",
        "section_1_3_contact_information",
    ):
        top_level = _safe_text(report.get(key)).strip()
        section_value = sections.get(key)

        if isinstance(section_value, dict):
            section_value = (
                _safe_text(section_value.get("content")).strip()
                or _safe_text(section_value.get("text")).strip()
                or _safe_text(section_value.get("value")).strip()
            )
        else:
            section_value = _safe_text(section_value).strip()

        final_value = top_level or section_value
        if final_value:
            report[key] = final_value
            sections[key] = final_value
        else:
            report[key] = ""


def _normalize_finding(finding: Any, index: int) -> dict:
    if not isinstance(finding, dict):
        finding = {}

    f = dict(finding)

    f["title"] = _safe_text(f.get("title") or f.get("name") or f"Finding {index}").strip()
    f["name"] = f["title"]
    f["severity"] = _normalize_severity(f.get("severity"))
    f["cvss"] = _safe_text(f.get("cvss")).strip()
    f["cvss_vector"] = _safe_text(f.get("cvss_vector")).strip()

    for key in (
        "description",
        "likelihood",
        "impact",
        "tools_used",
        "recommendation",
        "references",
        "protocol",
        "code",
    ):
        f[key] = _safe_text(f.get(key)).strip()

    _coerce_single_to_multi(f, "host", "hosts")
    _coerce_single_to_multi(f, "port", "ports")
    _coerce_single_to_multi(f, "cve", "cves")
    _coerce_single_to_multi(f, "cwe", "cwes")

    f["affected_hosts"] = _normalize_string_list(f.get("affected_hosts"))
    f["images"] = _normalize_images(f.get("images"), default_prefix=f["title"])

    # Auto-fill CVSS where possible
    f = auto_fill_finding_cvss(f)

    # Final safety normalization
    f["severity"] = _normalize_severity(f.get("severity"))
    if f.get("cvss"):
        try:
            f["severity"] = severity_from_score(float(f["cvss"]))
        except Exception:
            pass

    return f


def _normalize_walkthrough_item(item: Any, index: int) -> dict:
    if not isinstance(item, dict):
        item = {}

    title = _safe_text(item.get("name") or item.get("title") or f"Step {index}").strip()

    return {
        "name": title,
        "title": title,
        "description": _safe_text(item.get("description")).strip(),
        "code": _safe_text(item.get("code")).strip(),
        "images": _normalize_images(item.get("images"), default_prefix=title),
    }


def _normalize_additional_report(item: Any, index: int) -> dict:
    if not isinstance(item, dict):
        item = {}

    title = _safe_text(item.get("name") or item.get("title") or f"Additional Report {index}").strip()

    return {
        "name": title,
        "title": title,
        "description": _safe_text(item.get("description")).strip(),
        "code": _safe_text(item.get("code")).strip(),
        "images": _normalize_images(item.get("images"), default_prefix=title),
    }


def normalize_report(report: dict | None) -> dict:
    raw = copy.deepcopy(report or {})
    normalized = copy.deepcopy(DEFAULT_TEMPLATE)
    normalized.update(raw)

    normalized["client"] = _safe_text(normalized.get("client")).strip()
    normalized["project"] = _safe_text(normalized.get("project")).strip()
    normalized["tester"] = _safe_text(normalized.get("tester")).strip()
    normalized["contact"] = _safe_text(normalized.get("contact")).strip()
    normalized["date"] = _safe_text(normalized.get("date")).strip()
    normalized["version"] = _safe_text(normalized.get("version") or "1.0").strip()

    normalized["theme_hex"] = _normalize_theme_hex(normalized.get("theme_hex"))
    normalized["watermark_enabled"] = bool(normalized.get("watermark_enabled", False))
    normalized["logo_b64"] = _safe_text(normalized.get("logo_b64")).strip()
    normalized["report_language"] = _normalize_language(normalized.get("report_language"))
    normalized["include_charts"] = bool(normalized.get("include_charts", True))

    for key in (
        "executive_summary",
        "assessment_overview",
        "assessment_details",
        "scope",
        "scope_exclusions",
        "client_allowances",
    ):
        normalized[key] = _safe_text(normalized.get(key)).strip()

    _normalize_sections(normalized)

    normalized["contacts"] = _normalize_contacts(normalized.get("contacts"))
    normalized["attack_path"] = _normalize_string_list(normalized.get("attack_path"))

    normalized["remediation_short"] = _normalize_string_list(normalized.get("remediation_short"))
    normalized["remediation_medium"] = _normalize_string_list(normalized.get("remediation_medium"))
    normalized["remediation_long"] = _normalize_string_list(normalized.get("remediation_long"))

    normalized["findings"] = [
        _normalize_finding(item, idx)
        for idx, item in enumerate(_ensure_list(normalized.get("findings")), start=1)
    ]

    normalized["detailed_walkthrough"] = [
        _normalize_walkthrough_item(item, idx)
        for idx, item in enumerate(_ensure_list(normalized.get("detailed_walkthrough")), start=1)
    ]

    normalized["additional_reports"] = [
        _normalize_additional_report(item, idx)
        for idx, item in enumerate(_ensure_list(normalized.get("additional_reports")), start=1)
    ]

    normalized["overall_risk"] = _normalize_severity(normalized.get("overall_risk"))
    normalized["vuln_summary_counts"] = _ensure_dict(normalized.get("vuln_summary_counts"))
    normalized["vuln_summary_total"] = int(normalized.get("vuln_summary_total") or 0)
    normalized["vuln_by_host"] = _ensure_dict(normalized.get("vuln_by_host"))

    return normalized


def validate_report(report: dict) -> list[str]:
    errors: list[str] = []

    if not isinstance(report, dict):
        return ["Report must be a dictionary."]

    if not _safe_text(report.get("client")).strip():
        errors.append("Missing client.")
    if not _safe_text(report.get("project")).strip():
        errors.append("Missing project.")
    if not _safe_text(report.get("tester")).strip():
        errors.append("Missing tester.")

    for idx, finding in enumerate(_ensure_list(report.get("findings")), start=1):
        if not isinstance(finding, dict):
            errors.append(f"Finding {idx} is not a dictionary.")
            continue

        if not _safe_text(finding.get("title")).strip():
            errors.append(f"Finding {idx} is missing title.")

        severity = _normalize_severity(finding.get("severity"))
        if severity not in VALID_SEVERITIES:
            errors.append(f"Finding {idx} has invalid severity.")

        for img_idx, image in enumerate(_ensure_list(finding.get("images")), start=1):
            if isinstance(image, dict):
                if not _safe_text(image.get("data")).strip():
                    errors.append(f"Finding {idx} image {img_idx} is missing data.")
            elif not _safe_text(image).strip():
                errors.append(f"Finding {idx} image {img_idx} is empty.")

    lang = _normalize_language(report.get("report_language"))
    if lang not in VALID_LANGUAGES:
        errors.append("Invalid report_language.")

    return errors


def load_json_file(path: str | Path) -> dict:
    path = Path(path)
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return normalize_report(data)


def save_json_file(path: str | Path, report: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    normalized = normalize_report(report)
    with path.open("w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2, ensure_ascii=False, default=_json_default)


def load_json_bytes(file_bytes: bytes) -> dict:
    data = json.loads(file_bytes.decode("utf-8"))
    return normalize_report(data)


def dump_json_bytes(report: dict) -> bytes:
    normalized = normalize_report(report)
    return json.dumps(
        normalized,
        indent=2,
        ensure_ascii=False,
        default=_json_default,
    ).encode("utf-8")
