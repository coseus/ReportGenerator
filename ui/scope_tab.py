# ui/scope_tab.py
import streamlit as st

def render_scope_tab(data: dict) -> dict:
    """
    Scope & Details tab.
    Note: Engagement Status and Testing Phase removed as requested.
    """
    if not isinstance(data, dict):
        data = {}

    st.header("📄 Scope & Details")

    # Assessment Overview and Details
    st.subheader("Assessment Overview")
    data["assessment_overview"] = st.text_area(
        "Assessment Overview (this will be included in the report)",
        value=data.get("assessment_overview", ""),
        height=120,
        key="assessment_overview"
    )

    st.subheader("Assessment Details")
    data["assessment_details"] = st.text_area(
        "Assessment Details (phases, goals, tools used)",
        value=data.get("assessment_details", ""),
        height=120,
        key="assessment_details"
    )

    st.subheader("Scope")
    data["scope"] = st.text_area(
        "Scope — list of in-scope targets / ranges",
        value=data.get("scope", ""),
        height=100,
        key="scope"
    )

    st.subheader("Scope Exclusions")
    data["scope_exclusions"] = st.text_area(
        "Scope exclusions (if any)",
        value=data.get("scope_exclusions", ""),
        height=80,
        key="scope_exclusions"
    )

    st.subheader("Client Allowances")
    data["client_allowances"] = st.text_area(
        "Client allowances (what's permitted during testing)",
        value=data.get("client_allowances", ""),
        height=80,
        key="client_allowances"
    )

    return data
