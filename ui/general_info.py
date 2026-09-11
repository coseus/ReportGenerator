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
        data["provider"] = st.text_input("Furnizor / Provider (compania ta)", data.get("provider", ""), key="provider")
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
        data["registration_number"] = st.text_input(
            "Nr. înregistrare / Registration no.", data.get("registration_number", ""), key="registration_number")

    st.markdown("---")
    st.subheader("Raport NIS / NIS report")
    from util.i18n import get_language, t
    from util import report_meta as RM
    _lang = get_language(data)
    _n1, _n2 = st.columns(2)
    with _n1:
        _tt = ["Black Box", "Grey Box", "White Box"]
        _cur_tt = data.get("test_type") or "Black Box"
        data["test_type"] = st.selectbox(t(_lang, "test_type_label"), _tt,
            index=_tt.index(_cur_tt) if _cur_tt in _tt else 0, key="test_type")
    with _n2:
        _pk = [""] + RM.POSTURE_KEYS
        _cur_p = data.get("security_posture") or ""
        data["security_posture"] = st.selectbox(t(_lang, "security_posture_label"), _pk,
            index=_pk.index(_cur_p) if _cur_p in _pk else 0,
            format_func=lambda k: "—" if not k else RM.POSTURE_LABELS.get(_lang, {}).get(k, k),
            key="security_posture")

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
        c_role = st.selectbox("Type", ["Tester", "Client"], key="contact_role",
                              help="Tester = echipa de evaluare / furnizor. Client = persoana de contact din partea clientului.")
        if st.button("➕ Add contact", key="add_contact"):
            if c_name.strip():
                data["contacts"].append({"name": c_name.strip(), "title": c_title.strip(), "contact": c_info.strip(), "role": c_role})
                st.success("Contact added")
                # clear inputs by rerender
                st.rerun()
            else:
                st.error("Name is required")

    # Show contacts
    if data["contacts"]:
        head = st.columns([3,3,3,2,1])
        head[0].caption("Name"); head[1].caption("Title"); head[2].caption("Contact"); head[3].caption("Type")
        for i, c in enumerate(data["contacts"]):
            cols = st.columns([3,3,3,2,1])
            cols[0].write(c.get("name",""))
            cols[1].write(c.get("title",""))
            cols[2].write(c.get("contact",""))
            role_val = c.get("role") or "Tester"
            c["role"] = cols[3].selectbox(
                "Type", ["Tester", "Client"],
                index=0 if role_val == "Tester" else 1,
                key=f"contact_role_{i}", label_visibility="collapsed",
            )
            if cols[4].button("🗑️", key=f"del_contact_{i}"):
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

    # (Executive Summary is edited on its own dedicated tab — single source of truth.)

    # Watermark toggle
    data["watermark_enabled"] = st.checkbox("Add CONFIDENTIAL watermark to PDF", value=data.get("watermark_enabled", False), key="wm_toggle")

    return data
