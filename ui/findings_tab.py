import streamlit as st
import base64
from io import BytesIO
from PIL import Image as PILImage

from util.helpers import normalize_images, resize_image_b64
from report.parsers import auto_parse_findings
from report.numbering import renumber_findings, next_finding_id


SEVERITY_OPTIONS = ["Critical", "High", "Moderate", "Low", "Informational"]

SEVERITY_COLORS = {
    "Critical": "#e74c3c",
    "High": "#e67e22",
    "Moderate": "#f1c40f",
    "Low": "#3498db",
    "Informational": "#95a5a6",
}


# ============================================================
# IMAGE HELPERS
# ============================================================
def _is_valid_b64_image(b64_str: str) -> bool:
    try:
        raw = base64.b64decode(b64_str)
        img = PILImage.open(BytesIO(raw))
        img.verify()
        return True
    except Exception:
        return False


def _clean_images(images):
    clean = []
    for item in normalize_images(images, default_prefix="Evidence"):
        if _is_valid_b64_image(item["data"]):
            clean.append(item)
    return clean


def _show_b64_image(image_item: dict, caption: str = ""):
    try:
        raw = base64.b64decode(image_item["data"])
        st.image(raw, caption=caption or image_item.get("name", ""), width="stretch")
        return True
    except Exception:
        st.warning("Invalid image skipped")
        return False


def _uploaded_image_entries(files, key_prefix: str):
    entries = []
    for i, file in enumerate(files or [], start=1):
        default_name = file.name.rsplit('.', 1)[0] or f"Evidence {i}"
        name = st.text_input(
            f"Image name for {file.name}",
            value=default_name,
            key=f"{key_prefix}_img_name_{i}",
        )
        raw = file.read()
        b64 = base64.b64encode(raw).decode("utf-8")
        b64 = resize_image_b64(b64)
        if _is_valid_b64_image(b64):
            entries.append({"data": b64, "name": name.strip() or default_name})
    return entries


# ============================================================
# FINDING EDITOR
# ============================================================
def _edit_finding_modal(finding: dict, idx: int) -> bool:
    st.subheader(f"Editing Finding #{finding.get('id')}")

    # ---------- CLEAN INVALID / DUPLICATE IMAGES ----------
    finding["images"] = _clean_images(finding.get("images", []))
    existing_images = finding["images"]

    # ---------- FIELDS ----------
    finding["title"] = st.text_input(
        "Title",
        finding.get("title", ""),
        key=f"edit_title_{idx}",
    )

    current_sev = finding.get("severity", "Informational")
    if current_sev not in SEVERITY_OPTIONS:
        current_sev = "Informational"

    finding["severity"] = st.selectbox(
        "Severity",
        SEVERITY_OPTIONS,
        index=SEVERITY_OPTIONS.index(current_sev),
        key=f"edit_severity_{idx}",
    )

    finding["host"] = st.text_input(
        "Host",
        finding.get("host", ""),
        key=f"edit_host_{idx}",
    )
    finding["port"] = st.text_input(
        "Port",
        finding.get("port", ""),
        key=f"edit_port_{idx}",
    )
    finding["protocol"] = st.text_input(
        "Protocol",
        finding.get("protocol", ""),
        key=f"edit_protocol_{idx}",
    )

    finding["cvss"] = st.text_input(
        "CVSS",
        finding.get("cvss", ""),
        key=f"edit_cvss_{idx}",
    )
    finding["cve"] = st.text_input(
        "CVE",
        finding.get("cve", ""),
        key=f"edit_cve_{idx}",
    )
    finding["cwe"] = st.text_input(
        "CWE",
        finding.get("cwe", ""),
        key=f"edit_cwe_{idx}",
    )
    finding["cvss_vector"] = st.text_input(
        "CVSS Vector",
        finding.get("cvss_vector", ""),
        key=f"edit_cvss_vector_{idx}",
    )

    finding["description"] = st.text_area(
        "Description",
        finding.get("description", ""),
        height=120,
        key=f"edit_desc_{idx}",
    )
    finding["likelihood"] = st.text_area(
        "Likelihood",
        finding.get("likelihood", ""),
        height=90,
        key=f"edit_likelihood_{idx}",
    )
    finding["impact"] = st.text_area(
        "Impact",
        finding.get("impact", ""),
        height=120,
        key=f"edit_imp_{idx}",
    )
    finding["tools_used"] = st.text_area(
        "Tools Used",
        finding.get("tools_used", ""),
        height=70,
        key=f"edit_tools_{idx}",
    )
    finding["references"] = st.text_area(
        "References",
        finding.get("references", ""),
        height=90,
        key=f"edit_refs_{idx}",
    )
    finding["recommendation"] = st.text_area(
        "Recommendation",
        finding.get("recommendation", ""),
        height=120,
        key=f"edit_rec_{idx}",
    )
    finding["code"] = st.text_area(
        "Code / Output",
        finding.get("code", ""),
        height=200,
        key=f"edit_code_{idx}",
    )

    # ---------- EXISTING IMAGES ----------
    st.markdown("### Existing Evidence Images")

    if not existing_images:
        st.info("No evidence images yet.")
    else:
        cols = st.columns(4)
        delete_index = None

        for i, img_item in enumerate(existing_images):
            with cols[i % 4]:
                img_item["name"] = st.text_input(
                    "Image name",
                    value=img_item.get("name", f"Evidence {i+1}"),
                    key=f"existing_img_name_{idx}_{i}",
                )
                shown = _show_b64_image(img_item, caption=img_item.get("name", f"Evidence {i+1}"))
                if shown and st.button(f"Delete {i+1}", key=f"del_img_{idx}_{i}"):
                    delete_index = i

        if delete_index is not None:
            existing_images.pop(delete_index)
            finding["images"] = existing_images
            st.rerun()

    st.markdown("---")
    st.markdown("### Upload New Evidence Images")

    new_imgs = st.file_uploader(
        "Add more images",
        type=["png", "jpg", "jpeg"],
        accept_multiple_files=True,
        key=f"new_upload_{idx}",
    )
    new_entries = _uploaded_image_entries(new_imgs, f"new_upload_{idx}")

    if st.button("Attach New Images", key=f"attach_new_imgs_{idx}"):
        if new_entries:
            existing_images.extend(new_entries)
            finding["images"] = _clean_images(existing_images)
            st.success("Images added.")
            st.rerun()

    # ---------- SAVE ----------
    if st.button("Save Finding", key=f"save_find_{idx}"):
        finding["images"] = _clean_images(existing_images)
        return True

    return False


# ============================================================
# ADD FINDING MANUALLY
# ============================================================
def _add_manual_finding(findings):
    st.subheader("Add New Finding")

    title = st.text_input("Title", key="new_find_title")
    severity = st.selectbox("Severity", SEVERITY_OPTIONS, key="new_find_sev")
    host = st.text_input("Host", key="new_find_host")
    port = st.text_input("Port", key="new_find_port")
    protocol = st.text_input("Protocol", key="new_find_proto")

    cvss = st.text_input("CVSS", key="new_find_cvss")
    cve = st.text_input("CVE", key="new_find_cve")
    cwe = st.text_input("CWE", key="new_find_cwe")
    cvss_vector = st.text_input("CVSS Vector", key="new_find_cvss_vector")

    description = st.text_area("Description", height=120, key="new_find_desc")
    likelihood = st.text_area("Likelihood", height=90, key="new_find_likelihood")
    impact = st.text_area("Impact", height=120, key="new_find_imp")
    tools_used = st.text_area("Tools Used", height=70, key="new_find_tools")
    references = st.text_area("References", height=90, key="new_find_refs")
    recommendation = st.text_area("Recommendation", height=120, key="new_find_rec")
    code = st.text_area("Code / Output", height=200, key="new_find_code")

    new_imgs = st.file_uploader(
        "Upload Evidence Images",
        type=["png", "jpg", "jpeg"],
        accept_multiple_files=True,
        key="new_find_images",
    )
    images = _uploaded_image_entries(new_imgs, "new_find")

    if st.button("Add Finding", key="add_finding_btn"):

        fid = next_finding_id(findings)
        findings.append(
            {
                "id": fid,
                "title": title.strip() or "Untitled Finding",
                "severity": severity,
                "host": host,
                "port": port,
                "protocol": protocol,
                "description": description,
                "likelihood": likelihood,
                "impact": impact,
                "tools_used": tools_used,
                "references": references,
                "recommendation": recommendation,
                "cvss": cvss,
                "cve": cve,
                "cwe": cwe,
                "cvss_vector": cvss_vector,
                "code": code,
                "images": _clean_images(images),
            }
        )
        return True

    return False


# ============================================================
# IMPORT SECTION
# ============================================================
def _render_import_section(findings):
    st.subheader("Import Findings")

    uploaded = st.file_uploader(
        "Upload Nessus / Nmap / OpenVAS / CSV / JSON",
        type=["nessus", "xml", "csv", "json", "nmap"],
        key="findings_import_file",
    )

    if not uploaded:
        return

    try:
        imported = auto_parse_findings(uploaded.read(), uploaded.name)
    except Exception as e:
        st.error(f"Parser error: {e}")
        return

    st.success(f"Detected {len(imported)} findings.")

    # normalize preview values
    for f in imported:
        if f.get("severity") not in SEVERITY_OPTIONS:
            f["severity"] = "Informational"
        f.setdefault("images", [])

    # severity stats
    counts = {s: 0 for s in SEVERITY_OPTIONS}
    for f in imported:
        counts[f.get("severity", "Informational")] += 1

    cols = st.columns(len(SEVERITY_OPTIONS) + 1)
    cols[0].metric("Total", len(imported))
    for i, sev in enumerate(SEVERITY_OPTIONS, start=1):
        cols[i].metric(sev, counts[sev])

    st.write("Preview (first 10):")
    for f in imported[:10]:
        st.write(f"**{f.get('title', 'Untitled')}** – {f.get('severity')}")

    severity_sel = st.multiselect(
        "Import only severities:",
        SEVERITY_OPTIONS,
        default=SEVERITY_OPTIONS,
        key="findings_import_sev",
    )
    severity_sel = set(severity_sel)

    if st.button("Import Findings Now", key="import_findings_now"):
        added = 0
        for f in imported:
            if f.get("severity") not in severity_sel:
                continue

            f["id"] = next_finding_id(findings)
            f["images"] = _clean_images(f.get("images", []))
            findings.append(f)
            added += 1

        renumber_findings(findings)
        st.success(f"Import complete. Added {added} findings.")
        st.rerun()


# ============================================================
# FINDINGS TAB – MAIN FUNCTION
# ============================================================
def render_findings_tab(report_data: dict):
    st.header("Findings")

    if "findings" not in report_data or not isinstance(report_data["findings"], list):
        report_data["findings"] = []

    findings = report_data["findings"]

    # =======================================
    # IMPORT SECTION
    # =======================================
    _render_import_section(findings)

    st.markdown("---")

    # =======================================
    # ADD MANUAL FINDING
    # =======================================
    if _add_manual_finding(findings):
        renumber_findings(findings)
        st.success("Finding added.")
        st.rerun()

    st.markdown("---")

    # =======================================
    # FILTER BY SEVERITY
    # =======================================
    st.subheader("Filter & List Findings")

    sev_filter = st.multiselect(
        "Show only severities:",
        SEVERITY_OPTIONS,
        default=SEVERITY_OPTIONS,
        key="findings_filter_sev",
    )

    filtered = [f for f in findings if f.get("severity") in sev_filter]

    if not filtered:
        st.info("No findings match the selected filters.")
        return report_data

    # =======================================
    # LIST FINDINGS
    # =======================================
    for idx, f in enumerate(filtered):
        sev = f.get("severity", "Informational")

        box = st.container(border=True)
        with box:
            st.markdown(
                f"""
                <div style="padding:8px 10px;
                            border-radius:8px;
                            margin-top:8px;
                            background:{SEVERITY_COLORS.get(sev, '#999')};
                            color:white;">
                    <b>{f.get("id", "-")}. [{sev}]</b> — {f.get("title", "Untitled Finding")}
                </div>
                """,
                unsafe_allow_html=True,
            )

            meta_parts = []
            if f.get("host"):
                meta_parts.append(f"Host: {f.get('host')}")
            if f.get("port"):
                meta_parts.append(f"Port: {f.get('port')}")
            if f.get("protocol"):
                meta_parts.append(f"Protocol: {f.get('protocol')}")
            if meta_parts:
                st.caption(" | ".join(meta_parts))

            col1, col2 = st.columns([1, 1])
            with col1:
                if st.button("Edit", key=f"edit_{f.get('id', idx)}"):
                    # store real index from original findings list
                    try:
                        real_index = findings.index(f)
                        st.session_state["edit_index"] = real_index
                    except ValueError:
                        st.session_state["edit_index"] = None
                    st.rerun()

            with col2:
                if st.button("Delete", key=f"del_{f.get('id', idx)}"):
                    try:
                        real_index = findings.index(f)
                        findings.pop(real_index)
                        renumber_findings(findings)
                        st.success("Deleted.")
                        st.rerun()
                    except ValueError:
                        st.warning("Could not delete finding.")

    # =======================================
    # EDIT SELECTED FINDING
    # =======================================
    edit_index = st.session_state.get("edit_index")
    if edit_index is not None and 0 <= edit_index < len(findings):
        st.markdown("---")
        st.markdown("## Edit Finding")

        if _edit_finding_modal(findings[edit_index], edit_index):
            renumber_findings(findings)
            st.session_state["edit_index"] = None
            st.success("Saved.")
            st.rerun()

        if st.button("Cancel Edit", key="cancel_edit_finding"):
            st.session_state["edit_index"] = None
            st.rerun()

    return report_data
