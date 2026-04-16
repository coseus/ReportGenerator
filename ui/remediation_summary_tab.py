import streamlit as st


def render_remediation_summary_tab(report_data: dict):
    if "remediation_short" not in report_data:
        report_data["remediation_short"] = []
    if "remediation_medium" not in report_data:
        report_data["remediation_medium"] = []
    if "remediation_long" not in report_data:
        report_data["remediation_long"] = []

    st.header("Remediation Roadmap")

    st.subheader("Short Term")
    _rem_list_ui(report_data["remediation_short"], "short")

    st.subheader("Medium Term")
    _rem_list_ui(report_data["remediation_medium"], "medium")

    st.subheader("Long Term")
    _rem_list_ui(report_data["remediation_long"], "long")

    return report_data


def _rem_list_ui(list_ref, prefix):
    add = st.text_input(f"Add {prefix} remediation item", key=f"add_{prefix}")
    if st.button(f"Add {prefix}", key=f"add_btn_{prefix}"):
        if add.strip():
            list_ref.append(add.strip())
            st.rerun()

    st.write("")

    for idx, item in enumerate(list_ref):
        col1, col2 = st.columns([6, 1])
        col1.write(f"- {item}")
        if col2.button("Delete", key=f"del_{prefix}_{idx}"):
            del list_ref[idx]
            st.rerun()
