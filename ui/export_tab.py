from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import streamlit as st

from report import docx_generator, pdf_generator
from util.helpers import normalize_images


SAVE_FILE = Path("data/saved_report.json")
VALID_REPORT_VARIANTS = ("technical", "executive", "combined")
VALID_SEVERITIES = ("Critical", "High", "Moderate", "Low", "Informational")

DEFAULT_TEMPLATE = {
    "client": "",
    "project": "",
    "tester": "",
    "contact": "",
    "contacts": [],
    "date": "",
    "version": "1.0",
    "theme_hex": "#ED863D",
    "watermark_enabled": False,
    "logo_b64": "",
    "executive_summary": "",
    "assessment_overview": "",
    "assessment_details": "",
    "scope": "",
    "scope_exclusions": "",
    "client_allowances": "",
    "findings": [],
    "overall_risk": "Critical",
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


def _safe_json_default(obj: Any):
    return str(obj)


def _slugify_filename(value: str, fallback: str = "Client") -> str:
    text = (value or "").strip() or fallback
    text = re.sub(r"[^\w\s\-.]", "", text, flags=re.UNICODE)
    text = re.sub(r"\s+", "_", text).strip("._")
    return text or fallback


def _json_dumps_bytes(data: dict) -> bytes:
    return json.dumps(data, indent=2, ensure_ascii=False, default=_safe_json_default).encode("utf-8")


def _compute_file_hash(file_bytes: bytes) -> str:
    return hashlib.md5(file_bytes).hexdigest()


def _ensure_parent_dir(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)


def save_json_file(report: dict) -> bool:
    try:
        _ensure_parent_dir(SAVE_FILE)
        with SAVE_FILE.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=_safe_json_default)
        return True
    except Exception as exc:
        st.error(f"Failed to save JSON: {exc}")
        return False


def _load_json_from_disk() -> dict | None:
    try:
        if not SAVE_FILE.exists():
            st.warning("No local saved JSON file was found.")
            return None
        with SAVE_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        st.error(f"Failed to load JSON: {exc}")
        return None


def _generate_pdf(report: dict, report_variant: str = "technical") -> bytes:
    return pdf_generator.generate_pdf_bytes(report, report_variant=report_variant)


def _generate_docx(report: dict, report_variant: str = "technical") -> bytes:
    return docx_generator.generate_docx_bytes(report, report_variant=report_variant)


def _repair_text(text: Any) -> Any:
    if not isinstance(text, str):
        return text
    replacements = {
        "â€“": "-",
        "â€”": "-",
        "â€˜": "'",
        "â€™": "'",
        'â€œ': '"',
        'â€': '"',
        "â€¢": "-",
        "Â": "",
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    return text


def _repair_structure(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _repair_structure(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_repair_structure(v) for v in obj]
    if isinstance(obj, str):
        return _repair_text(obj)
    return obj


def _normalize_severity(value: Any) -> str:
    if not isinstance(value, str):
        return "Informational"
    raw = value.strip().lower()
    mapping = {
        "critical": "Critical",
        "crit": "Critical",
        "high": "High",
        "medium": "Moderate",
        "moderate": "Moderate",
        "med": "Moderate",
        "low": "Low",
        "info": "Informational",
        "informational": "Informational",
    }
    return mapping.get(raw, "Informational")


def _ensure_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _ensure_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _normalize_theme_hex(value: Any) -> str:
    if isinstance(value, str) and re.fullmatch(r"#[0-9A-Fa-f]{6}", value.strip()):
        return value.strip()
    return "#ED863D"


def _normalize_findings(findings: Any) -> list[dict]:
    normalized = []
    for item in _ensure_list(findings):
        if not isinstance(item, dict):
            continue
        fixed = dict(item)
        fixed["title"] = fixed.get("title") or fixed.get("name") or "Untitled Finding"
        fixed["name"] = fixed.get("name") or fixed["title"]
        fixed["severity"] = _normalize_severity(fixed.get("severity"))
        fixed["images"] = normalize_images(fixed.get("images"), default_prefix=fixed["title"])
        normalized.append(fixed)
    return normalized


def _normalize_walkthrough(steps: Any) -> list[dict]:
    normalized = []
    for item in _ensure_list(steps):
        if not isinstance(item, dict):
            continue
        fixed = dict(item)
        fixed["name"] = fixed.get("name") or fixed.get("title") or "Untitled Step"
        fixed["images"] = normalize_images(fixed.get("images"), default_prefix=fixed["name"])
        normalized.append(fixed)
    return normalized


def _normalize_additional_reports(reports: Any) -> list[dict]:
    normalized = []
    for item in _ensure_list(reports):
        if not isinstance(item, dict):
            continue
        fixed = dict(item)
        fixed["title"] = fixed.get("title") or fixed.get("name") or "Additional Report"
        fixed["name"] = fixed.get("name") or fixed["title"]
        fixed["images"] = normalize_images(fixed.get("images"), default_prefix=fixed["name"])
        normalized.append(fixed)
    return normalized


def _normalize_remediation_list(items: Any) -> list[str]:
    return [str(item).strip() for item in _ensure_list(items) if str(item).strip()]


def _merge_with_template(data: dict) -> dict:
    merged = copy.deepcopy(DEFAULT_TEMPLATE)
    merged.update(data)
    return merged


def _normalize_report_data(data: dict) -> dict:
    data = _merge_with_template(_repair_structure(data))
    data["theme_hex"] = _normalize_theme_hex(data.get("theme_hex"))
    data["watermark_enabled"] = bool(data.get("watermark_enabled", False))
    data["contacts"] = _ensure_list(data.get("contacts"))
    data["findings"] = _normalize_findings(data.get("findings"))
    data["additional_reports"] = _normalize_additional_reports(data.get("additional_reports"))
    data["detailed_walkthrough"] = _normalize_walkthrough(data.get("detailed_walkthrough"))
    data["overall_risk"] = _normalize_severity(data.get("overall_risk"))
    data["attack_path"] = _ensure_list(data.get("attack_path"))
    data["remediation_short"] = _normalize_remediation_list(data.get("remediation_short"))
    data["remediation_medium"] = _normalize_remediation_list(data.get("remediation_medium"))
    data["remediation_long"] = _normalize_remediation_list(data.get("remediation_long"))
    data["vuln_summary_counts"] = _ensure_dict(data.get("vuln_summary_counts"))
    data["vuln_by_host"] = _ensure_dict(data.get("vuln_by_host"))
    try:
        data["vuln_summary_total"] = int(data.get("vuln_summary_total") or 0)
    except Exception:
        data["vuln_summary_total"] = 0
    return data


def _store_generated_file(kind: str, variant: str, content: bytes):
    st.session_state[f"generated_{kind}_{variant}"] = content


def _get_generated_file(kind: str, variant: str) -> bytes | None:
    return st.session_state.get(f"generated_{kind}_{variant}")


def _clear_import_state():
    for key in ("json_import_last_hash", "json_import_processed"):
        st.session_state.pop(key, None)


def _calculate_severity_counts(report_data: dict) -> dict[str, int]:
    counts = {sev: 0 for sev in VALID_SEVERITIES}
    for finding in report_data.get("findings", []):
        counts[_normalize_severity(finding.get("severity"))] += 1
    return counts


def _count_evidence_items(report_data: dict) -> int:
    total = 0
    for section in ("findings", "detailed_walkthrough", "additional_reports"):
        for item in report_data.get(section, []):
            total += len(item.get("images", []) or [])
            total += 1 if str(item.get("code", "")).strip() else 0
    return total


def render_export_tab(report_data: dict):
    st.header("Export Final Report")

    report_data["theme_hex"] = st.color_picker(
        "Accent Color",
        value=_normalize_theme_hex(report_data.get("theme_hex")),
        key="theme_hex_picker",
    )
    report_data["watermark_enabled"] = st.checkbox(
        "Add watermark (CONFIDENTIAL)",
        value=bool(report_data.get("watermark_enabled", False)),
        key="watermark_enabled_toggle",
    )

    st.markdown("---")

    report_variant = st.radio(
        "Report Profile",
        options=list(VALID_REPORT_VARIANTS),
        format_func=lambda x: {
            "technical": "Technical Report",
            "executive": "Executive Report",
            "combined": "Combined Executive + Technical Report",
        }[x],
        horizontal=True,
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("Generate PDF", use_container_width=True):
            with st.spinner("Generating PDF report..."):
                try:
                    _store_generated_file("pdf", report_variant, _generate_pdf(report_data, report_variant=report_variant))
                    st.success(f"{report_variant.title()} PDF generated successfully.")
                except Exception as exc:
                    st.error(f"Error generating PDF: {exc}")
    with col2:
        if st.button("Generate DOCX", use_container_width=True):
            with st.spinner("Generating DOCX report..."):
                try:
                    _store_generated_file("docx", report_variant, _generate_docx(report_data, report_variant=report_variant))
                    st.success(f"{report_variant.title()} DOCX generated successfully.")
                except Exception as exc:
                    st.error(f"Error generating DOCX: {exc}")
    with col3:
        if st.button("Generate Both", use_container_width=True):
            with st.spinner("Generating PDF and DOCX..."):
                try:
                    _store_generated_file("pdf", report_variant, _generate_pdf(report_data, report_variant=report_variant))
                    _store_generated_file("docx", report_variant, _generate_docx(report_data, report_variant=report_variant))
                    st.success(f"{report_variant.title()} PDF and DOCX generated successfully.")
                except Exception as exc:
                    st.error(f"Error generating exports: {exc}")

    st.markdown("---")

    pdf_data = _get_generated_file("pdf", report_variant)
    docx_data = _get_generated_file("docx", report_variant)
    if pdf_data or docx_data:
        st.subheader("Download Files")
        safe_client = _slugify_filename(str(report_data.get("client", "Client")))
        variant_label = {"technical": "Technical", "executive": "Executive", "combined": "Combined"}[report_variant]
        filename_base = f"Pentest_{variant_label}_{safe_client}_{datetime.now().strftime('%Y%m%d')}"
        if pdf_data:
            st.download_button("Download PDF", pdf_data, f"{filename_base}.pdf", "application/pdf", use_container_width=True)
        if docx_data:
            st.download_button(
                "Download DOCX",
                docx_data,
                f"{filename_base}.docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                use_container_width=True,
            )
    else:
        st.info("Generate a PDF or DOCX first to enable downloads.")

    st.markdown("---")
    st.subheader("JSON Save / Load")
    save_col, load_col = st.columns(2)
    with save_col:
        if st.button("Save JSON to Server", use_container_width=True):
            if save_json_file(report_data):
                st.success("JSON saved to server.")
    with load_col:
        if st.button("Load JSON from Server", use_container_width=True):
            loaded = _load_json_from_disk()
            if loaded is not None:
                st.session_state["report_data"] = _normalize_report_data(loaded)
                st.success("Local JSON loaded successfully. Reloading interface...")
                st.rerun()

    st.download_button(
        "Download JSON",
        data=_json_dumps_bytes(report_data),
        file_name=f"Pentest_Report_{_slugify_filename(str(report_data.get('client', 'Client')))}.json",
        mime="application/json",
        use_container_width=True,
    )

    st.markdown("---")
    st.subheader("Import JSON Report")
    uploaded_json = st.file_uploader("Choose JSON file", type=["json"], key="json_importer")
    info_col, reset_col = st.columns([3, 1])
    with reset_col:
        if st.button("Reset Import", use_container_width=True):
            _clear_import_state()
            st.info("Import state cleared.")
    if uploaded_json is not None:
        try:
            file_bytes = uploaded_json.read()
            current_hash = _compute_file_hash(file_bytes)
            already_processed = st.session_state.get("json_import_last_hash") == current_hash and st.session_state.get("json_import_processed") is True
            with info_col:
                st.caption(f"Selected file: {uploaded_json.name} ({len(file_bytes):,} bytes)")
            if not already_processed:
                parsed = json.loads(file_bytes.decode("utf-8"))
                normalized = _normalize_report_data(parsed)
                st.session_state["report_data"] = normalized
                st.session_state["json_import_last_hash"] = current_hash
                st.session_state["json_import_processed"] = True
                st.success("JSON imported successfully. Reloading interface...")
                st.rerun()
            else:
                st.info("This JSON file is already loaded.")
        except Exception as exc:
            st.error(f"JSON import error: {exc}")

    st.markdown("---")
    st.subheader("Export Summary")
    sev_counts = _calculate_severity_counts(report_data)
    remediation_total = sum(len(report_data.get(k, [])) for k in ("remediation_short", "remediation_medium", "remediation_long"))
    st.text(f"Client: {report_data.get('client', 'N/A')}")
    st.text(f"Project: {report_data.get('project', 'N/A')}")
    st.text(f"Tester: {report_data.get('tester', 'N/A')}")
    st.text(f"Report Profile: {report_variant.title()}")
    st.text(f"Contacts: {len(report_data.get('contacts', []))}")
    st.text(f"Findings: {len(report_data.get('findings', []))}")
    st.text(f"Additional Reports: {len(report_data.get('additional_reports', []))}")
    st.text(f"Detailed Walkthrough Steps: {len(report_data.get('detailed_walkthrough', []))}")
    st.text(f"Remediation Items: {remediation_total}")
    st.text(f"Date: {report_data.get('date', '')}")
    st.text("Severity Distribution: " + ", ".join(f"{severity}={count}" for severity, count in sev_counts.items()))
    st.text(f"Evidence Annex Items: {_count_evidence_items(report_data)}")
    st.caption("JSON import keeps unknown keys, normalizes image metadata, and avoids rerun loops on repeated uploads.")
    return report_data
