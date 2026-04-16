# app.py (FIXED — stable sync version)

import os
import json
import streamlit as st
from datetime import datetime

import setup_paths

from ui.reset import render_global_reset_button
from ui.general_info import render_general_info
from ui.scope_tab import render_scope_tab
from ui.findings_tab import render_findings_tab
from ui.additional_reports import render_additional_reports
from ui.executive_summary_tab import render_executive_summary_tab
from ui.export_tab import render_export_tab
from ui.detailed_walkthrough_tab import render_detailed_walkthrough_tab
from ui.remediation_summary_tab import render_remediation_summary_tab

SAVE_FILE = "data/saved_report.json"

st.set_page_config(
    page_title="PenTest Report Generator",
    page_icon="util/coseus.ico",
    layout="wide"
)

# ---------------------------------------------------------
# Load JSON into session_state
# ---------------------------------------------------------
def load_saved_report():
    if os.path.exists(SAVE_FILE):
        try:
            with open(SAVE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_report_data():
    """Save session_state report_data to file."""
    try:
        os.makedirs("data", exist_ok=True)
        with open(SAVE_FILE, "w", encoding="utf-8") as f:
            json.dump(st.session_state["report_data"], f, indent=2, ensure_ascii=False)
    except Exception as e:
        st.error(f"Save failed: {e}")


def reset_all():
    st.session_state["report_data"] = {}
    if os.path.exists(SAVE_FILE):
        os.remove(SAVE_FILE)
    st.success("All data cleared.")
    st.rerun()

# ---------------------------------------------------------
# Initialize session_state
# ---------------------------------------------------------
if "report_data" not in st.session_state:
    st.session_state["report_data"] = load_saved_report()


# ---------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------
# Sidebar
# app.py → în sidebar
with st.sidebar:
     render_global_reset_button()

# ---------------------------------------------------------
# MAIN TABS
# ---------------------------------------------------------
report_data = st.session_state["report_data"]

col_logo, col_titlu = st.columns([1, 4])

with col_logo:
    st.image("util/coseus_logo_slim.png", width=150)

with col_titlu:
    st.markdown(
        "<h3 style='margin: 12px 0 0 0;'>Pentest Report Generator</h3>",
        unsafe_allow_html=True
    )

st.markdown("---")   # linie subtire de separare (optional)

tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
    "General Info",
    "Scope & Details",
    "Findings",
    "Additional Reports",
    "Detailed Walkthrough",
    "Executive Summary",
    "Remediation Summary",
    "Export",
])

with tab1:
    render_general_info(report_data)

with tab2:
    render_scope_tab(report_data)

with tab3:
    render_findings_tab(report_data)

with tab4:
    render_additional_reports(report_data)

with tab5:
    report_data = render_detailed_walkthrough_tab(report_data)

with tab6:
    report_data = render_executive_summary_tab(report_data)

with tab7:
    report_data = render_remediation_summary_tab(report_data)

with tab8:
    report_data = render_export_tab(report_data)

# Save at end
save_report_data()





















