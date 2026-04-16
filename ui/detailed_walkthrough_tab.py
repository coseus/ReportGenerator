import base64

import streamlit as st

from util.helpers import normalize_images, resize_image_b64


def _build_uploaded_images(uploaded_files, key_prefix: str, default_prefix: str = "Screenshot"):
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


def render_detailed_walkthrough_tab(report_data: dict):
    st.header("Detailed Walkthrough")
    st.caption("Add detailed attack chains, exploit steps, lateral movement, screenshots, and code samples.")

    if "detailed_walkthrough" not in report_data or not isinstance(report_data["detailed_walkthrough"], list):
        report_data["detailed_walkthrough"] = []

    walkthrough = report_data["detailed_walkthrough"]

    with st.expander("Add Walkthrough Step", expanded=False):
        title = st.text_input("Title", key="dw_new_title")
        description = st.text_area("Description (multiline)", key="dw_new_desc")
        code = st.text_area("Code Block (optional)", key="dw_new_code")
        images_upload = st.file_uploader(
            "Upload screenshots",
            accept_multiple_files=True,
            type=["png", "jpg", "jpeg"],
            key="dw_new_images",
        )
        uploaded_entries = _build_uploaded_images(images_upload, "dw_new")

        if st.button("Add Walkthrough Step", key="dw_add_btn"):
            walkthrough.append({
                "name": title.strip() or "Untitled Step",
                "description": description,
                "code": code,
                "images": normalize_images(uploaded_entries, default_prefix=title.strip() or "Step"),
            })
            st.success("Step added.")
            st.rerun()

    st.markdown("---")
    st.subheader("Existing Walkthrough Steps")

    if not walkthrough:
        st.info("No steps added yet.")
        return report_data

    for idx, step in enumerate(walkthrough):
        step["images"] = normalize_images(step.get("images"), default_prefix=step.get("name") or f"Step {idx+1}")
        with st.container(border=True):
            st.markdown(f"### 8.{idx + 1} - {step.get('name', 'Untitled Step')}")
            if step.get("description"):
                st.markdown(step["description"].replace("\n", "<br>"), unsafe_allow_html=True)
            if step.get("code"):
                st.code(step["code"], language="bash")
            if step.get("images"):
                st.markdown("**Images:**")
                cols = st.columns(2)
                delete_index = None
                for img_idx, image in enumerate(step["images"]):
                    with cols[img_idx % 2]:
                        try:
                            st.image(base64.b64decode(image["data"]), caption=image.get("name") or f"Image {img_idx+1}", width="stretch")
                        except Exception:
                            st.warning("Invalid image skipped.")
                        image["name"] = st.text_input("Image name", value=image.get("name", f"Image {img_idx+1}"), key=f"dw_img_name_{idx}_{img_idx}")
                        if st.button(f"Delete Image {img_idx + 1}", key=f"dw_del_img_{idx}_{img_idx}"):
                            delete_index = img_idx
                if delete_index is not None:
                    del step["images"][delete_index]
                    st.rerun()

            col1, col2 = st.columns(2)
            with col1:
                if st.button("Edit", key=f"dw_edit_btn_{idx}"):
                    st.session_state["dw_edit_index"] = idx
                    st.rerun()
            with col2:
                if st.button("Delete", key=f"dw_del_btn_{idx}"):
                    del walkthrough[idx]
                    st.success("Deleted.")
                    st.rerun()
        st.markdown("---")

    if st.session_state.get("dw_edit_index") is not None:
        idx = st.session_state["dw_edit_index"]
        if idx < 0 or idx >= len(walkthrough):
            st.session_state["dw_edit_index"] = None
            return report_data

        step = walkthrough[idx]
        with st.container(border=True):
            st.markdown(f"## Edit Walkthrough Step 8.{idx + 1}")
            step["name"] = st.text_input("Title", step.get("name", ""), key=f"dw_edit_title_{idx}")
            step["description"] = st.text_area("Description", step.get("description", ""), height=150, key=f"dw_edit_desc_{idx}")
            step["code"] = st.text_area("Code Block (optional)", step.get("code", ""), height=120, key=f"dw_edit_code_{idx}")

            st.markdown("### Add More Images")
            new_imgs = st.file_uploader(
                "Upload screenshots",
                accept_multiple_files=True,
                type=["png", "jpg", "jpeg"],
                key=f"dw_edit_new_images_{idx}",
            )
            uploaded_entries = _build_uploaded_images(new_imgs, f"dw_edit_{idx}", default_prefix=step.get("name") or "Step")

            col_a, col_b = st.columns(2)
            with col_a:
                if st.button("Save Changes", key=f"dw_save_{idx}"):
                    step["images"] = normalize_images((step.get("images") or []) + uploaded_entries, default_prefix=step.get("name") or "Step")
                    st.session_state["dw_edit_index"] = None
                    st.success("Updated.")
                    st.rerun()
            with col_b:
                if st.button("Cancel", key=f"dw_cancel_{idx}"):
                    st.session_state["dw_edit_index"] = None
                    st.rerun()

    return report_data
