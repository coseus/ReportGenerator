import base64

import streamlit as st

from util.helpers import normalize_images, resize_image_b64


def _build_uploaded_images(uploaded_files, key_prefix: str, default_prefix: str = "Image"):
    entries = []
    for idx, file in enumerate(uploaded_files or [], start=1):
        default_name = file.name.rsplit('.', 1)[0] or f"{default_prefix} {idx}"
        caption = st.text_input(
            f"Image name for {file.name}",
            value=default_name,
            key=f"{key_prefix}_caption_{idx}",
        )
        entries.append({
            "data": resize_image_b64(file.read()),
            "name": caption.strip() or default_name,
        })
    return entries


def render_additional_reports_tab(report_data: dict):
    st.header("Additional Reports")
    if "additional_reports" not in report_data or not isinstance(report_data["additional_reports"], list):
        report_data["additional_reports"] = []

    items = report_data["additional_reports"]

    with st.expander("Add Additional Report", expanded=False):
        name = st.text_input("Title / Name", key="add_rep_name")
        desc = st.text_area("Description", key="add_rep_desc")
        code = st.text_area("Code / Output", key="add_rep_code")
        imgs = st.file_uploader("Attach images", type=["png", "jpg", "jpeg"], accept_multiple_files=True, key="add_rep_imgs")
        uploaded_entries = _build_uploaded_images(imgs, "add_report")

        if st.button("Add Report", key="btn_add_rep"):
            items.append({
                "name": name.strip() or "Additional Report",
                "title": name.strip() or "Additional Report",
                "description": desc,
                "code": code,
                "images": normalize_images(uploaded_entries, default_prefix=name.strip() or "Additional Report"),
            })
            st.success("Additional report added.")
            st.rerun()

    st.markdown("---")
    st.subheader("Existing Additional Reports")

    if not items:
        st.info("No additional reports added yet.")
        return report_data

    for idx, item in enumerate(items):
        item["images"] = normalize_images(item.get("images"), default_prefix=item.get("name") or f"Report {idx+1}")
        with st.container(border=True):
            st.markdown(f"### {item.get('name', 'Additional Report')}")
            if item.get("description"):
                st.markdown(item["description"].replace("\n", "<br>"), unsafe_allow_html=True)
            if item.get("code"):
                st.code(item["code"], language="bash")
            if item.get("images"):
                st.markdown("**Images**")
                cols = st.columns(2)
                delete_index = None
                for img_idx, image in enumerate(item["images"]):
                    with cols[img_idx % 2]:
                        try:
                            st.image(base64.b64decode(image["data"]), caption=image.get("name") or f"Image {img_idx+1}", width="stretch")
                        except Exception:
                            st.warning("Invalid image skipped.")
                        image["name"] = st.text_input("Image name", value=image.get("name", f"Image {img_idx+1}"), key=f"additional_img_name_{idx}_{img_idx}")
                        if st.button(f"Delete Image {img_idx+1}", key=f"del_add_img_{idx}_{img_idx}"):
                            delete_index = img_idx
                if delete_index is not None:
                    del item["images"][delete_index]
                    st.rerun()

            c1, c2 = st.columns(2)
            with c1:
                if st.button("Edit", key=f"edit_add_{idx}"):
                    st.session_state["edit_additional_idx"] = idx
                    st.rerun()
            with c2:
                if st.button("Delete", key=f"del_add_{idx}"):
                    items.pop(idx)
                    st.success("Additional report removed.")
                    st.rerun()

            if st.session_state.get("edit_additional_idx") == idx:
                st.markdown("---")
                st.markdown("### Edit Additional Report")
                new_name = st.text_input("Title / Name", item.get("name", ""), key=f"edit_name_{idx}")
                new_desc = st.text_area("Description", item.get("description", ""), height=120, key=f"edit_desc_{idx}")
                new_code = st.text_area("Code / Output", item.get("code", ""), height=120, key=f"edit_code_{idx}")
                new_imgs = st.file_uploader("Attach more images", type=["png", "jpg", "jpeg"], accept_multiple_files=True, key=f"edit_add_imgs_{idx}")
                uploaded_entries = _build_uploaded_images(new_imgs, f"edit_add_{idx}", default_prefix=new_name or "Additional Report")
                ca, cb = st.columns(2)
                with ca:
                    if st.button("Save Changes", key=f"save_add_{idx}"):
                        item["name"] = new_name.strip() or "Additional Report"
                        item["title"] = item["name"]
                        item["description"] = new_desc
                        item["code"] = new_code
                        item["images"].extend(uploaded_entries)
                        item["images"] = normalize_images(item["images"], default_prefix=item["name"])
                        st.session_state["edit_additional_idx"] = None
                        st.success("Changes saved.")
                        st.rerun()
                with cb:
                    if st.button("Cancel", key=f"cancel_add_{idx}"):
                        st.session_state["edit_additional_idx"] = None
                        st.rerun()
    return report_data



# Backward-compatible alias expected by app.py
def render_additional_reports(report_data: dict):
    return render_additional_reports_tab(report_data)
