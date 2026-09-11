from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import streamlit as st

from report import docx_generator, html_generator, pdf_generator
from util.json_utils import (
    dump_json_bytes,
    load_json_bytes,
    load_json_file,
    normalize_report,
    save_json_file as save_report_json_file,
    validate_report,
)
from util.i18n import TRANSLATIONS, t, get_language
from util.helpers import normalize_images
from util.charting import png_bytes_to_b64, risk_trend_png, severity_distribution_png

SAVE_FILE = Path("data/saved_report.json")
VALID_REPORT_VARIANTS = ("technical", "executive", "combined")
VALID_SEVERITIES = ("Critical", "High", "Moderate", "Low", "Informational")


def _generate_pdf(report, report_variant="technical"):
    report = normalize_report(report)
    return pdf_generator.generate_pdf_bytes(report, report_variant=report_variant)


def _generate_docx(report, report_variant="technical"):
    report = normalize_report(report)
    return docx_generator.generate_docx_bytes(report, report_variant=report_variant)


def _generate_html(report, report_variant="technical"):
    report = normalize_report(report)
    return html_generator.generate_html_bytes(report, report_variant=report_variant)


def _slugify_filename(value: str, fallback: str = "Client") -> str:
    import re

    text = (value or "").strip()
    if not text:
        text = fallback
    text = re.sub(r"[^\w\s\-\.]", "", text, flags=re.UNICODE)
    text = re.sub(r"\s+", "_", text)
    text = text.strip("._")
    return text or fallback


def _compute_file_hash(file_bytes: bytes) -> str:
    import hashlib

    return hashlib.md5(file_bytes).hexdigest()


def _store_generated_file(kind: str, variant: str, content: bytes):
    st.session_state[f"generated_{kind}_{variant}"] = content


def _get_generated_file(kind: str, variant: str) -> bytes | None:
    return st.session_state.get(f"generated_{kind}_{variant}")

def _calculate_severity_counts(report_data: dict) -> dict[str, int]:
    counts = {sev: 0 for sev in VALID_SEVERITIES}
    for finding in report_data.get("findings", []):
        counts[_normalize_severity(finding.get("severity"))] += 1
    return counts

def _clear_import_state():
    for key in (
        "json_import_last_hash",
        "json_import_filename",
        "json_import_processed",
    ):
        st.session_state.pop(key, None)


# Widget-state keys that mirror report_data fields. They must be cleared when a
# report is loaded/imported, otherwise a keyed widget keeps its old value and
# overwrites the freshly imported data (Streamlit keeps widget state by key).
_FIELD_WIDGET_KEYS = (
    "client", "provider", "project", "tester", "contact", "date", "version",
    "executive_summary", "wm_toggle", "watermark_enabled_toggle",
    "include_charts_toggle", "theme_hex_picker", "logo_upload",
    "assessment_overview", "assessment_details", "scope",
    "scope_exclusions", "client_allowances",
    "global_language_selector", "report_language_selector",
    "findings_filter_sev", "section_1_3_contact_information",
    "registration_number", "test_type", "security_posture",
    "contact_name", "contact_title", "contact_info", "contact_role",
    "include_compliance_toggle_ct", "compliance_frameworks_ms", "control_frameworks_ms",
)


def _apply_loaded_report(report):
    """Install a loaded/imported report and drop stale widget state so every
    field re-initialises from the new data."""
    for key in list(st.session_state.keys()):
        if key in _FIELD_WIDGET_KEYS or key.startswith("contact_role_") or key.startswith("del_contact_") or key.startswith("comp_cat_") or key.startswith("ctrl_") or key.startswith("finding_"):
            st.session_state.pop(key, None)
    st.session_state["report_data"] = report
        
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

def _render_chart_preview(report_data: dict):
    if not report_data.get("include_charts", True):
        return
    st.subheader("Chart Preview")
    sev_counts = _calculate_severity_counts(report_data)
    col1, col2 = st.columns(2)
    with col1:
        st.image(severity_distribution_png(sev_counts), caption="Severity Distribution", width="stretch")
    with col2:
        st.image(risk_trend_png(report_data.get("findings", [])), caption="Risk Trend", width="stretch")

def render_export_tab(report_data: dict):
    report_data = normalize_report(report_data)

    st.header("Export Final Report")

    report_data["theme_hex"] = st.color_picker(
        "Accent Color",
        value=report_data.get("theme_hex", "#ED863D"),
        key="theme_hex_picker",
    )

    report_data["watermark_enabled"] = st.checkbox(
        t(get_language(report_data), "export_watermark"),
        value=bool(report_data.get("watermark_enabled", False)),
        key="watermark_enabled_toggle",
    )

    _lang = get_language(report_data)
    st.caption(f"{t(_lang, 'export_language_label')}: "
               + {"en": "English", "ro": "Română"}.get(_lang, "English")
               + "  ·  " + t(_lang, "ui_note_language"))

    report_data["include_charts"] = st.checkbox(
        t(get_language(report_data), "export_include_charts"),
        value=bool(report_data.get("include_charts", True)),
        key="include_charts_toggle",
    )

    st.markdown("---")

    report_variant = st.radio(
        "Report Profile",
        options=["technical", "executive", "combined"],
        format_func=lambda x: {
            "technical": "Technical Report",
            "executive": "Executive Report",
            "combined": "Combined Executive + Technical Report",
        }[x],
        horizontal=True,
    )

    errors = validate_report(report_data)
    if errors:
        with st.expander("Validation Warnings", expanded=False):
            for err in errors:
                st.warning(err)

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        if st.button("Generate PDF", width="stretch"):
            with st.spinner("Generating PDF report..."):
                try:
                    pdf_bytes = _generate_pdf(report_data, report_variant=report_variant)
                    _store_generated_file("pdf", report_variant, pdf_bytes)
                    st.success(f"{report_variant.title()} PDF generated successfully.")
                except Exception as exc:
                    st.error(f"Error generating PDF: {exc}")

    with col2:
        if st.button("Generate DOCX", width="stretch"):
            with st.spinner("Generating DOCX report..."):
                try:
                    docx_bytes = _generate_docx(report_data, report_variant=report_variant)
                    _store_generated_file("docx", report_variant, docx_bytes)
                    st.success(f"{report_variant.title()} DOCX generated successfully.")
                except Exception as exc:
                    st.error(f"Error generating DOCX: {exc}")

    with col3:
        if st.button("Generate HTML", width="stretch"):
            with st.spinner("Generating HTML report..."):
                try:
                    html_bytes = _generate_html(report_data, report_variant=report_variant)
                    _store_generated_file("html", report_variant, html_bytes)
                    st.success(f"{report_variant.title()} HTML generated successfully.")
                except Exception as exc:
                    st.error(f"Error generating HTML: {exc}")

    with col4:
        if st.button("Generate All", width="stretch"):
            with st.spinner("Generating all export formats..."):
                try:
                    _store_generated_file(
                        "pdf",
                        report_variant,
                        _generate_pdf(report_data, report_variant=report_variant),
                    )
                    _store_generated_file(
                        "docx",
                        report_variant,
                        _generate_docx(report_data, report_variant=report_variant),
                    )
                    _store_generated_file(
                        "html",
                        report_variant,
                        _generate_html(report_data, report_variant=report_variant),
                    )
                    st.success(f"{report_variant.title()} exports generated successfully.")
                except Exception as exc:
                    st.error(f"Error generating exports: {exc}")

    st.markdown("---")

    pdf_data = _get_generated_file("pdf", report_variant)
    docx_data = _get_generated_file("docx", report_variant)
    html_data = _get_generated_file("html", report_variant)

    if pdf_data or docx_data or html_data:
        st.subheader("Download Files")

        safe_client = _slugify_filename(str(report_data.get("client", "Client")), fallback="Client")
        date_part = datetime.now().strftime("%Y%m%d")
        variant_label = {
            "technical": "Technical",
            "executive": "Executive",
            "combined": "Combined",
        }[report_variant]
        filename_base = f"Pentest_{variant_label}_{safe_client}_{date_part}"

        if pdf_data:
            st.download_button(
                label="Download PDF",
                data=pdf_data,
                file_name=f"{filename_base}.pdf",
                mime="application/pdf",
                width="stretch",
            )

        if docx_data:
            st.download_button(
                label="Download DOCX",
                data=docx_data,
                file_name=f"{filename_base}.docx",
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                width="stretch",
            )

        if html_data:
            st.download_button(
                label="Download HTML",
                data=html_data,
                file_name=f"{filename_base}.html",
                mime="text/html",
                width="stretch",
            )
    else:
        st.info("Generate a report first to enable downloads.")

    st.markdown("---")
    _render_chart_preview(report_data)
    
    st.markdown("---")

    st.subheader("JSON Save / Load")

    save_col, load_col = st.columns(2)

    with save_col:
        if st.button("Save JSON to Server", width="stretch"):
            try:
                save_report_json_file(SAVE_FILE, report_data)
                st.success("JSON saved to server.")
            except Exception as exc:
                st.error(f"Failed to save JSON: {exc}")

    with load_col:
        if st.button("Load JSON from Server", width="stretch"):
            try:
                loaded = load_json_file(SAVE_FILE)
                _apply_loaded_report(loaded)
                st.success("Local JSON loaded successfully. Reloading interface...")
                st.rerun()
            except Exception as exc:
                st.error(f"Failed to load JSON: {exc}")

    json_bytes = dump_json_bytes(report_data)
    safe_client = _slugify_filename(str(report_data.get("client", "Client")), fallback="Client")

    st.download_button(
        "Download JSON",
        data=json_bytes,
        file_name=f"Pentest_Report_{safe_client}.json",
        mime="application/json",
        width="stretch",
    )

    st.markdown("---")

    st.subheader("Import JSON Report")

    uploaded_json = st.file_uploader(
        "Choose JSON file",
        type=["json"],
        key="json_importer",
    )

    import_col1, import_col2 = st.columns([3, 1])

    with import_col2:
        if st.button("Reset Import", width="stretch"):
            _clear_import_state()
            st.info("Import state cleared. You can upload the file again.")

    if uploaded_json is not None:
        try:
            file_bytes = uploaded_json.read()
            current_hash = _compute_file_hash(file_bytes)

            already_processed = (
                st.session_state.get("json_import_last_hash") == current_hash
                and st.session_state.get("json_import_processed") is True
            )

            with import_col1:
                st.caption(f"Selected file: {uploaded_json.name} ({len(file_bytes):,} bytes)")

            if not already_processed:
                parsed = load_json_bytes(file_bytes)
                _apply_loaded_report(parsed)
                st.session_state["json_import_last_hash"] = current_hash
                st.session_state["json_import_filename"] = uploaded_json.name
                st.session_state["json_import_processed"] = True
                st.success("JSON imported successfully. Reloading interface...")
                st.rerun()
            else:
                st.info("This JSON file is already loaded.")
        except UnicodeDecodeError:
            st.error("Import failed: the file is not valid UTF-8 JSON.")
        except json.JSONDecodeError as exc:
            st.error(f"Import failed: invalid JSON format. {exc}")
        except Exception as exc:
            st.error(f"JSON import error: {exc}")

    st.markdown("---")

    st.subheader("Export Summary")

    findings = report_data.get("findings", [])
    sev_counts = {
        sev: sum(1 for f in findings if (f.get("severity") or "Informational") == sev)
        for sev in ["Critical", "High", "Moderate", "Low", "Informational"]
    }

    remediation_total = (
        len(report_data.get("remediation_short", []))
        + len(report_data.get("remediation_medium", []))
        + len(report_data.get("remediation_long", []))
    )

    evidence_total = 0
    for section_name in ("findings", "detailed_walkthrough", "additional_reports"):
        for item in report_data.get(section_name, []):
            evidence_total += len(item.get("images", []))
            evidence_total += 1 if str(item.get("code", "")).strip() else 0

    st.text(f"Client: {report_data.get('client', 'N/A')}")
    st.text(f"Project: {report_data.get('project', 'N/A')}")
    st.text(f"Tester: {report_data.get('tester', 'N/A')}")
    st.text(f"Language: {report_data.get('report_language', 'en')}")
    st.text(f"Include Charts: {report_data.get('include_charts', True)}")
    st.text(f"Report Profile: {report_variant.title()}")
    st.text(f"Findings: {len(findings)}")
    st.text(f"Additional Reports: {len(report_data.get('additional_reports', []))}")
    st.text(f"Detailed Walkthrough Steps: {len(report_data.get('detailed_walkthrough', []))}")
    st.text(f"Remediation Items: {remediation_total}")
    st.text(f"Date: {report_data.get('date', '')}")
    st.text(
        "Severity Distribution: "
        + ", ".join(f"{severity}={count}" for severity, count in sev_counts.items())
    )
    st.text(f"Evidence Items: {evidence_total}")

    return report_data
