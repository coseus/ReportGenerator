# app.py

from __future__ import annotations

import hashlib
import json
import logging
import os

import streamlit as st

import setup_paths

from report.data_model import empty_report
from ui.reset import render_global_reset_button
from ui.general_info import render_general_info
from ui.scope_tab import render_scope_tab
from ui.findings_tab import render_findings_tab
from ui.additional_reports import render_additional_reports
from ui.executive_summary_tab import render_executive_summary_tab
from ui.export_tab import render_export_tab
from ui.detailed_walkthrough_tab import render_detailed_walkthrough_tab
from ui.remediation_summary_tab import render_remediation_summary_tab
from util.control_mapper import render_controls_tab
from util.i18n import t, get_language

# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

SAVE_FILE = "data/saved_report.json"

# ---------------------------------------------------------------------------
# DEFAULT REPORT STRUCTURE — sourced from a single canonical location
# ---------------------------------------------------------------------------
# FIX: Previously DEFAULT_REPORT_DATA was duplicated here AND in data_model.py
# with slightly different values (overall_risk differed). Now we use one source.
_UI_EXTRAS: dict = {
    "contacts": [],
    "theme_hex": "#ED863D",
    "watermark_enabled": False,
    "logo_b64": "",
    "report_language": "en",
    "include_charts": True,
    "section_1_0_confidentiality_and_legal": "",
    "section_1_1_confidentiality_statement": "",
    "section_1_2_disclaimer": "",
    "section_1_3_contact_information": "",
    "sections": {},
    "vuln_summary_counts": {},
    "vuln_summary_total": 0,
    "vuln_by_host": {},
    "attack_path": [],
}

DEFAULT_REPORT_DATA: dict = {**_UI_EXTRAS, **empty_report()}


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
def _merge_defaults(data: dict | None) -> dict:
    merged = DEFAULT_REPORT_DATA.copy()
    if isinstance(data, dict):
        merged.update(data)
    return merged


def _report_hash(data: dict) -> str:
    """Stable hash of report data for change detection (ignores key ordering)."""
    try:
        serialized = json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.md5(serialized.encode()).hexdigest()
    except Exception:
        return ""


def load_saved_report() -> dict:
    if os.path.exists(SAVE_FILE):
        try:
            with open(SAVE_FILE, "r", encoding="utf-8") as f:
                raw = f.read().strip()
                if not raw or raw == "{}":
                    return DEFAULT_REPORT_DATA.copy()
                data = json.loads(raw)
                return _merge_defaults(data)
        except Exception as exc:
            logger.warning("Failed to load saved report: %s", exc)
            return DEFAULT_REPORT_DATA.copy()
    return DEFAULT_REPORT_DATA.copy()


def save_report_data():
    """
    FIX: Previously saved on every render regardless of changes.
    Now compares hash against last saved state to avoid unnecessary disk writes.
    Particularly important for large reports with many B64 images.
    """
    current_hash = _report_hash(st.session_state["report_data"])
    last_hash = st.session_state.get("_last_saved_hash", "")

    if current_hash == last_hash:
        return  # Nothing changed, skip write

    try:
        os.makedirs("data", exist_ok=True)
        with open(SAVE_FILE, "w", encoding="utf-8") as f:
            json.dump(
                st.session_state["report_data"],
                f,
                indent=2,
                ensure_ascii=False,
                default=str,
            )
        st.session_state["_last_saved_hash"] = current_hash
    except Exception as exc:
        logger.error("Save failed: %s", exc)
        st.error(f"Save failed: {exc}")


def reset_all():
    st.session_state["report_data"] = DEFAULT_REPORT_DATA.copy()
    st.session_state["_last_saved_hash"] = ""
    if os.path.exists(SAVE_FILE):
        try:
            os.remove(SAVE_FILE)
        except Exception as exc:
            logger.warning("Could not remove save file: %s", exc)
    st.success("All data cleared.")
    st.rerun()


def _safe_run_tab(render_func, report_data: dict) -> dict:
    """
    Runs a tab renderer safely.
    - If renderer returns a dict, use it.
    - If renderer returns None, keep existing report_data.
    - Always keep session_state synced.
    - Logs exceptions rather than swallowing them silently.
    """
    try:
        result = render_func(report_data)
        if isinstance(result, dict):
            report_data = result
    except Exception as exc:
        logger.exception("Tab render error in %s: %s", render_func.__name__, exc)
        st.error(f"Tab error in {render_func.__name__}: {exc}")
    st.session_state["report_data"] = report_data
    return report_data


# ---------------------------------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="PenTest Report Generator",
    page_icon="util/coseus.ico",
    layout="wide",
)

# ---------------------------------------------------------------------------
# INITIALIZE SESSION
# ---------------------------------------------------------------------------
if "report_data" not in st.session_state or not isinstance(st.session_state["report_data"], dict):
    st.session_state["report_data"] = load_saved_report()
else:
    st.session_state["report_data"] = _merge_defaults(st.session_state["report_data"])


# ---------------------------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------------------------
with st.sidebar:
    render_global_reset_button()
    _lang_current = get_language(st.session_state["report_data"])
    _lang = st.radio(
        t(_lang_current, "sidebar_language"),
        options=["en", "ro"],
        index=0 if _lang_current == "en" else 1,
        format_func=lambda x: {"en": "English", "ro": "Română"}[x],
        horizontal=True,
        key="global_language_selector",
    )
    st.session_state["report_data"]["report_language"] = _lang
    st.caption(t(_lang, "ui_note_language"))


# ---------------------------------------------------------------------------
# MAIN UI HEADER
# ---------------------------------------------------------------------------
report_data = st.session_state["report_data"]
LANG = get_language(report_data)

col_logo, col_titlu = st.columns([1, 4])

with col_logo:
    st.image("util/coseus_logo_slim.png", width=150)

with col_titlu:
    st.markdown(
        f"<h3 style='margin: 12px 0 0 0;'>{t(LANG, 'app_title')}</h3>",
        unsafe_allow_html=True,
    )

st.markdown("---")


# ---------------------------------------------------------------------------
# TABS
# ---------------------------------------------------------------------------
tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9 = st.tabs(
    [
        t(LANG, "tab_general"),
        t(LANG, "tab_scope"),
        t(LANG, "tab_findings"),
        t(LANG, "tab_additional"),
        t(LANG, "tab_walkthrough"),
        t(LANG, "tab_exec"),
        t(LANG, "tab_remediation"),
        t(LANG, "tab_compliance"),
        t(LANG, "tab_export"),
    ]
)

with tab1:
    report_data = _safe_run_tab(render_general_info, report_data)

with tab2:
    report_data = _safe_run_tab(render_scope_tab, report_data)

with tab3:
    report_data = _safe_run_tab(render_findings_tab, report_data)

with tab4:
    report_data = _safe_run_tab(render_additional_reports, report_data)

with tab5:
    report_data = _safe_run_tab(render_detailed_walkthrough_tab, report_data)

with tab6:
    report_data = _safe_run_tab(render_executive_summary_tab, report_data)

with tab7:
    report_data = _safe_run_tab(render_remediation_summary_tab, report_data)

with tab8:
    report_data = _safe_run_tab(render_controls_tab, report_data)

with tab9:
    report_data = _safe_run_tab(render_export_tab, report_data)


# ---------------------------------------------------------------------------
# FINAL SAVE (conditional — only writes if data changed)
# ---------------------------------------------------------------------------
st.session_state["report_data"] = report_data
save_report_data()
