# ui/general_info.py
import streamlit as st
import base64
from datetime import date, datetime

def render_general_info(data: dict) -> dict:
    """
    Render General Info tab.
    Ensures contacts list exists and provides logo upload + executive summary.
    """
    if not isinstance(data, dict):
        data = {}

    st.header("📋 General Information")

    col1, col2 = st.columns(2)

    with col1:
        data["client"] = st.text_input("Client", data.get("client", ""), key="client")
        data["project"] = st.text_input("Project", data.get("project", ""), key="project")
        data["tester"] = st.text_input("Tester", data.get("tester", ""), key="tester")

    with col2:
        data["contact"] = st.text_input("Primary Contact (email/phone)", data.get("contact", ""), key="contact")
        # store date as ISO string for JSON compatibility
        current_date = data.get("date")
        if current_date:
            try:
                current_date = datetime.fromisoformat(str(current_date)).date()
            except Exception:
                current_date = date.today()
        else:
            current_date = date.today()
        picked = st.date_input("Date", value=current_date, key="date")
        data["date"] = picked.isoformat()
        data["version"] = st.text_input("Version", data.get("version", "1.0"), key="version")

    st.markdown("---")

    # Contacts (table-like)
    st.subheader("Contacts")
    if "contacts" not in data or not isinstance(data["contacts"], list):
        data["contacts"] = data.get("contacts", [])

    # Add contact form
    with st.expander("Add contact", expanded=False):
        c_name = st.text_input("Name", key="contact_name")
        c_title = st.text_input("Title", key="contact_title")
        c_info = st.text_input("Contact information (email / phone)", key="contact_info")
        if st.button("➕ Add contact", key="add_contact"):
            if c_name.strip():
                data["contacts"].append({"name": c_name.strip(), "title": c_title.strip(), "contact": c_info.strip()})
                st.success("Contact added")
                # clear inputs by rerender
                st.rerun()
            else:
                st.error("Name is required")

    # Show contacts
    if data["contacts"]:
        for i, c in enumerate(data["contacts"]):
            cols = st.columns([3,3,3,1])
            cols[0].write(c.get("name",""))
            cols[1].write(c.get("title",""))
            cols[2].write(c.get("contact",""))
            if cols[3].button("🗑️", key=f"del_contact_{i}"):
                data["contacts"].pop(i)
                st.rerun()

    st.markdown("---")

    # Logo upload
    st.subheader("Logo (optional)")
    uploaded_logo = st.file_uploader("Upload company logo (PNG/JPG)", type=["png","jpg","jpeg"], key="logo_upload")
    if uploaded_logo:
        data["logo_b64"] = base64.b64encode(uploaded_logo.read()).decode("utf-8")
        st.image(uploaded_logo, caption="Logo preview", width=160)
    elif data.get("logo_b64"):
        try:
            st.image(base64.b64decode(data["logo_b64"]), width=160)
        except Exception:
            pass

    st.markdown("---")

    # Executive summary quick edit (shows in export)
    st.subheader("Executive Summary (pre-filled text will appear in report)")
    data["executive_summary"] = st.text_area(
        "Executive Summary (this text is prefilled into section 6.0)",
        value=data.get("executive_summary", ""),
        height=200,
        key="executive_summary"
    )

    # Watermark toggle
    data["watermark_enabled"] = st.checkbox("Add CONFIDENTIAL watermark to PDF", value=data.get("watermark_enabled", False), key="wm_toggle")

    return data
