# ui/executive_summary_tab.py
import streamlit as st
import plotly.express as px
import pandas as pd

def render_executive_summary_tab(report_data):
    st.header("Executive Summary")

    findings = report_data.get("findings", [])
    if not findings:
        st.warning("No findings yet. Add some in the Findings tab.")
        report_data["executive_summary"] = st.text_area(
            "Custom Executive Summary", "", height=200
        )
        return report_data

    df = pd.DataFrame(findings)
    sev_order = ["Critical", "High", "Moderate", "Low", "Informational"]
    sev_count = df["severity"].value_counts().reindex(sev_order, fill_value=0)

    col1, col2 = st.columns([1, 2])
    with col1:
        st.metric("Total Findings", len(findings))
        st.metric("Critical", sev_count["Critical"])
        st.metric("High", sev_count["High"])

    with col2:
        fig = px.pie(
            names=sev_count.index,
            values=sev_count.values,
            color=sev_count.index,
            color_discrete_map={
                "Critical": "#e74c3c", "High": "#e67e22", "Moderate": "#f1c40f",
                "Low": "#27ae60", "Informational": "#95a5a6"
            },
            hole=0.4
        )
        fig.update_layout(title="Vulnerability Severity Distribution")
        st.plotly_chart(fig, width="stretch")

    default_summary = (
        f"During the penetration test of {report_data.get('project','the target')}, "
        f"a total of {len(findings)} vulnerabilities were identified. "
        f"{sev_count['Critical']} were rated Critical."
    )

    report_data["executive_summary"] = st.text_area(
        "Custom Executive Summary (optional)",
        report_data.get("executive_summary", default_summary),
        height=200
    )

    return report_data
