from __future__ import annotations

import base64
from io import BytesIO
from typing import Any

import streamlit as st
from PIL import Image as PILImage

from report.parsers import auto_parse_findings
from util.cvss_utils import auto_fill_finding_cvss, suggest_vectors_for_score
from util.helpers import normalize_images, resize_image_b64
from util.json_utils import normalize_report
from util.severity import normalize_severity
from util.i18n import get_language, t
from util import report_meta as RM


SEVERITY_OPTIONS = ["Critical", "High", "Moderate", "Low", "Informational"]

SEVERITY_COLORS = {
    "Critical": "#e74c3c",
    "High": "#e67e22",
    "Moderate": "#f1c40f",
    "Low": "#3498db",
    "Informational": "#95a5a6",
}


def _safe_text(value: Any) -> str:
    return "" if value is None else str(value)


def _ensure_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _normalize_string_list(values: Any) -> list[str]:
    result = []
    for item in _ensure_list(values):
        text = _safe_text(item).strip()
        if text:
            result.append(text)
    return result


def _seed_multi_from_finding(finding: dict, single_key: str, multi_key: str) -> list[str]:
    values = _normalize_string_list(finding.get(multi_key))
    single = _safe_text(finding.get(single_key)).strip()
    if single and single not in values:
        values.insert(0, single)
    return values or [""]


def _ensure_widget_state(key: str, default: Any):
    if key not in st.session_state:
        st.session_state[key] = default


def _normalize_images_for_editor(images: Any, default_prefix: str = "Image") -> list[dict]:
    normalized = []
    for idx, item in enumerate(_ensure_list(images), start=1):
        if isinstance(item, dict):
            data = _safe_text(item.get("data")).strip()
            if not data:
                continue
            normalized.append(
                {
                    "data": data,
                    "name": _safe_text(item.get("name")).strip() or f"{default_prefix} {idx}",
                }
            )
        elif isinstance(item, str):
            data = item.strip()
            if not data:
                continue
            normalized.append({"data": data, "name": f"{default_prefix} {idx}"})
    return normalized


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


def _uploaded_image_entries(files, key_prefix: str):
    entries = []
    for i, file in enumerate(files or [], start=1):
        default_name = file.name.rsplit(".", 1)[0] or f"Evidence {i}"
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


def _next_finding_id(findings: list[dict]) -> int:
    ids = []
    for f in findings:
        try:
            ids.append(int(f.get("id")))
        except Exception:
            continue
    return max(ids, default=0) + 1


def _renumber_findings(findings: list[dict]):
    for idx, finding in enumerate(findings, start=1):
        finding["id"] = idx


def _init_editor_state(prefix: str, finding: dict | None = None):
    if finding is None:
        finding = {}

    title = _safe_text(finding.get("title") or finding.get("name"))
    severity = _safe_text(finding.get("severity") or "Informational")
    if severity not in SEVERITY_OPTIONS:
        severity = "Informational"

    _ensure_widget_state(f"{prefix}_title", title)
    _ensure_widget_state(f"{prefix}_severity", severity)
    _ensure_widget_state(f"{prefix}_cvss", _safe_text(finding.get("cvss")))
    _ensure_widget_state(f"{prefix}_cvss_vector", _safe_text(finding.get("cvss_vector")))
    _status = _safe_text(finding.get("status")) or "present"
    if _status not in RM.STATUS_KEYS:
        _status = "present"
    _expl = _safe_text(finding.get("exploitability")) or "medium"
    if _expl not in RM.EXPLOIT_KEYS:
        _expl = "medium"
    _ensure_widget_state(f"{prefix}_status", _status)
    _ensure_widget_state(f"{prefix}_exploitability", _expl)
    _ensure_widget_state(f"{prefix}_status_note", _safe_text(finding.get("status_note")))
    _ensure_widget_state(f"{prefix}_status_date", _safe_text(finding.get("status_date")))
    _ensure_widget_state(f"{prefix}_protocol", _safe_text(finding.get("protocol")))
    _ensure_widget_state(f"{prefix}_description", _safe_text(finding.get("description")))
    _ensure_widget_state(f"{prefix}_likelihood", _safe_text(finding.get("likelihood")))
    _ensure_widget_state(f"{prefix}_impact", _safe_text(finding.get("impact")))
    _ensure_widget_state(f"{prefix}_tools_used", _safe_text(finding.get("tools_used")))
    _ensure_widget_state(f"{prefix}_recommendation", _safe_text(finding.get("recommendation")))
    _ensure_widget_state(f"{prefix}_references", _safe_text(finding.get("references")))
    _ensure_widget_state(f"{prefix}_code", _safe_text(finding.get("code")))

    _ensure_widget_state(f"{prefix}_hosts", _seed_multi_from_finding(finding, "host", "hosts"))
    _ensure_widget_state(f"{prefix}_ports", _seed_multi_from_finding(finding, "port", "ports"))
    _ensure_widget_state(f"{prefix}_cves", _seed_multi_from_finding(finding, "cve", "cves"))
    _ensure_widget_state(f"{prefix}_cwes", _seed_multi_from_finding(finding, "cwe", "cwes"))

    images = _normalize_images_for_editor(
        finding.get("images"),
        default_prefix=title or "Finding",
    )
    _ensure_widget_state(f"{prefix}_images", images)
    _ensure_widget_state(f"{prefix}_cvss_suggestions", [])


def _cleanup_editor_state(prefix: str):
    keys = [
        f"{prefix}_title",
        f"{prefix}_severity",
        f"{prefix}_cvss",
        f"{prefix}_cvss_vector",
        f"{prefix}_status",
        f"{prefix}_exploitability",
        f"{prefix}_status_note",
        f"{prefix}_status_date",
        f"{prefix}_protocol",
        f"{prefix}_description",
        f"{prefix}_likelihood",
        f"{prefix}_impact",
        f"{prefix}_tools_used",
        f"{prefix}_recommendation",
        f"{prefix}_references",
        f"{prefix}_code",
        f"{prefix}_hosts",
        f"{prefix}_ports",
        f"{prefix}_cves",
        f"{prefix}_cwes",
        f"{prefix}_images",
        f"{prefix}_cvss_suggestions",
        f"{prefix}_suggested_vector_select",
        f"{prefix}_pending_cvss_vector",
        f"{prefix}_pending_uploaded_images",
    ]
    for key in list(st.session_state.keys()):
        if key.startswith(f"{prefix}_upload_name_"):
            st.session_state.pop(key, None)


def _apply_pending_cvss_vector(prefix: str):
    pending_key = f"{prefix}_pending_cvss_vector"
    widget_key = f"{prefix}_cvss_vector"
    if pending_key in st.session_state:
        st.session_state[widget_key] = st.session_state.pop(pending_key)


def _render_dynamic_text_list(label: str, state_key: str, input_prefix: str):
    st.markdown(f"**{label}**")
    values = st.session_state.get(state_key, [""])
    new_values: list[str] = []

    for idx, value in enumerate(values):
        col1, col2 = st.columns([6, 1])
        with col1:
            current_value = st.text_input(
                f"{label} {idx + 1}",
                value=value,
                key=f"{input_prefix}_{idx}",
                label_visibility="collapsed",
            )
            new_values.append(current_value)
        with col2:
            if st.button("Delete", key=f"{input_prefix}_del_{idx}", width="stretch"):
                if len(values) > 1:
                    values.pop(idx)
                else:
                    values[0] = ""
                st.session_state[state_key] = values
                st.rerun()

    st.session_state[state_key] = new_values

    add_label = label[:-1] if label.endswith("s") else label
    if st.button(f"Add {add_label}", key=f"{input_prefix}_add", width="stretch"):
        st.session_state[state_key] = st.session_state.get(state_key, [""]) + [""]
        st.rerun()


def _read_dynamic_list(state_key: str) -> list[str]:
    values = st.session_state.get(state_key, [])
    return [v.strip() for v in values if _safe_text(v).strip()]


def _render_image_preview_block(images: list[dict], prefix: str) -> list[dict]:
    if not images:
        st.info("No images attached.")
        return images

    updated_images = images.copy()

    for idx, image in enumerate(images):
        with st.container(border=True):
            try:
                st.image(base64.b64decode(image["data"]), width="stretch")
            except Exception:
                st.warning("Could not render image preview.")

            image_name = st.text_input(
                f"Image name {idx + 1}",
                value=_safe_text(image.get("name")),
                key=f"{prefix}_img_name_{idx}",
            )
            updated_images[idx]["name"] = image_name.strip()

            if st.button(f"Delete Image {idx + 1}", key=f"{prefix}_img_del_{idx}", width="stretch"):
                updated_images.pop(idx)
                st.session_state[f"{prefix}_images"] = updated_images
                st.rerun()

    return updated_images


def _upload_new_images(prefix: str, existing_images: list[dict], default_prefix: str) -> list[dict]:
    uploaded = st.file_uploader(
        "Upload images",
        type=["png", "jpg", "jpeg"],
        accept_multiple_files=True,
        key=f"{prefix}_uploader",
    )

    pending_key = f"{prefix}_pending_uploaded_images"
    if pending_key not in st.session_state:
        st.session_state[pending_key] = []

    pending_entries = []
    for i, file in enumerate(uploaded or [], start=1):
        default_name = file.name.rsplit(".", 1)[0] or f"{default_prefix} {i}"
        img_name = st.text_input(
            f"Image name for {file.name}",
            value=default_name,
            key=f"{prefix}_upload_name_{i}",
        )

        raw = file.read()
        b64 = base64.b64encode(raw).decode("utf-8")
        b64 = resize_image_b64(b64)

        if _is_valid_b64_image(b64):
            pending_entries.append(
                {
                    "data": b64,
                    "name": img_name.strip() or default_name,
                }
            )

    if pending_entries:
        st.session_state[pending_key] = pending_entries

        if st.button("Attach Uploaded Images", key=f"{prefix}_attach_uploaded", width="stretch"):
            # dedupe by image data
            existing_data = {img.get("data") for img in existing_images}
            for item in st.session_state[pending_key]:
                if item.get("data") not in existing_data:
                    existing_images.append(item)

            st.session_state[pending_key] = []
            st.success("Images attached.")
            st.rerun()

    return existing_images


def _render_cvss_suggestions(prefix: str):
    cvss_value = _safe_text(st.session_state.get(f"{prefix}_cvss")).strip()

    if st.button("Suggest CVSS Vector", key=f"{prefix}_suggest_vector", width="stretch"):
        suggestions = suggest_vectors_for_score(cvss_value, limit=5)
        st.session_state[f"{prefix}_cvss_suggestions"] = suggestions

    suggestions = st.session_state.get(f"{prefix}_cvss_suggestions", [])
    if suggestions:
        option_map = {
            f"{item['vector']}  |  Score: {item['score']}  |  Severity: {item['severity']}": item["vector"]
            for item in suggestions
        }

        selected_label = st.selectbox(
            "Suggested vectors",
            options=list(option_map.keys()),
            key=f"{prefix}_suggested_vector_select",
        )

        if st.button("Use Selected Vector", key=f"{prefix}_use_suggested_vector", width="stretch"):
            st.session_state[f"{prefix}_pending_cvss_vector"] = option_map[selected_label]
            st.rerun()


def _render_cvss_preview(prefix: str):
    preview_finding = auto_fill_finding_cvss(
        {
            "cvss_vector": _safe_text(st.session_state.get(f"{prefix}_cvss_vector")),
            "cvss": _safe_text(st.session_state.get(f"{prefix}_cvss")),
            "severity": _safe_text(st.session_state.get(f"{prefix}_severity")),
        }
    )

    current_vector = _safe_text(st.session_state.get(f"{prefix}_cvss_vector")).strip()
    if current_vector:
        if preview_finding.get("cvss_auto_ok"):
            st.info(
                f"Auto CVSS: {preview_finding.get('cvss_auto_score', '')} | "
                f"Severity: {preview_finding.get('cvss_auto_severity', '')}"
            )
        else:
            st.warning(preview_finding.get("cvss_auto_error", "Invalid CVSS vector"))


def _build_finding_from_state(prefix: str) -> dict:
    title = _safe_text(st.session_state.get(f"{prefix}_title")).strip()
    severity = _safe_text(st.session_state.get(f"{prefix}_severity")).strip() or "Informational"
    cvss = _safe_text(st.session_state.get(f"{prefix}_cvss")).strip()
    cvss_vector = _safe_text(st.session_state.get(f"{prefix}_cvss_vector")).strip()
    protocol = _safe_text(st.session_state.get(f"{prefix}_protocol")).strip()
    description = _safe_text(st.session_state.get(f"{prefix}_description"))
    likelihood = _safe_text(st.session_state.get(f"{prefix}_likelihood"))
    impact = _safe_text(st.session_state.get(f"{prefix}_impact"))
    tools_used = _safe_text(st.session_state.get(f"{prefix}_tools_used"))
    recommendation = _safe_text(st.session_state.get(f"{prefix}_recommendation"))
    references = _safe_text(st.session_state.get(f"{prefix}_references"))
    code = _safe_text(st.session_state.get(f"{prefix}_code"))

    hosts = _read_dynamic_list(f"{prefix}_hosts")
    ports = _read_dynamic_list(f"{prefix}_ports")
    cves = _read_dynamic_list(f"{prefix}_cves")
    cwes = _read_dynamic_list(f"{prefix}_cwes")
    images = _clean_images(st.session_state.get(f"{prefix}_images", []))

    finding = {
        "title": title or "Untitled Finding",
        "name": title or "Untitled Finding",
        "severity": severity,
        "cvss": cvss,
        "cvss_vector": cvss_vector,
        "description": description,
        "likelihood": likelihood,
        "impact": impact,
        "tools_used": tools_used,
        "recommendation": recommendation,
        "references": references,
        "protocol": protocol,
        "code": code,
        "images": images,
        "hosts": hosts,
        "ports": ports,
        "cves": cves,
        "cwes": cwes,
        "host": hosts[0] if hosts else "",
        "port": ports[0] if ports else "",
        "cve": cves[0] if cves else "",
        "cwe": cwes[0] if cwes else "",
    }

    finding = auto_fill_finding_cvss(finding)
    finding = normalize_report({"findings": [finding]}).get("findings", [finding])[0]
    finding["status"] = _safe_text(st.session_state.get(f"{prefix}_status")).strip() or "present"
    finding["exploitability"] = _safe_text(st.session_state.get(f"{prefix}_exploitability")).strip() or "medium"
    finding["status_note"] = _safe_text(st.session_state.get(f"{prefix}_status_note")).strip()
    finding["status_date"] = _safe_text(st.session_state.get(f"{prefix}_status_date")).strip()
    return finding


def _render_editor(prefix: str, initial_title: str = "Finding"):
    _apply_pending_cvss_vector(prefix)

    st.text_input("Title", key=f"{prefix}_title")
    st.selectbox("Severity", SEVERITY_OPTIONS, key=f"{prefix}_severity")
    st.text_input("CVSS", key=f"{prefix}_cvss")
    st.text_input("CVSS Vector", key=f"{prefix}_cvss_vector")
    st.text_input("Protocol", key=f"{prefix}_protocol")

    _render_cvss_preview(prefix)
    _render_cvss_suggestions(prefix)
    _lang = get_language(st.session_state.get("report_data") or {})
    _sc1, _sc2 = st.columns(2)
    with _sc1:
        st.selectbox(t(_lang, "lbl_status"), RM.STATUS_KEYS,
                     format_func=lambda k: RM.STATUS_LABELS.get(_lang, {}).get(k, k),
                     key=f"{prefix}_status")
    with _sc2:
        st.selectbox(t(_lang, "lbl_exploitability"), RM.EXPLOIT_KEYS,
                     format_func=lambda k: RM.EXPLOIT_LABELS.get(_lang, {}).get(k, k),
                     key=f"{prefix}_exploitability")
    _nc1, _nc2 = st.columns(2)
    with _nc1:
        st.text_input(t(_lang, "col_comments"), key=f"{prefix}_status_note")
    with _nc2:
        st.text_input(t(_lang, "col_updated"), key=f"{prefix}_status_date")

    _render_dynamic_text_list("Hosts", f"{prefix}_hosts", f"{prefix}_host")
    _render_dynamic_text_list("Ports", f"{prefix}_ports", f"{prefix}_port")
    _render_dynamic_text_list("CVEs", f"{prefix}_cves", f"{prefix}_cve")
    _render_dynamic_text_list("CWEs", f"{prefix}_cwes", f"{prefix}_cwe")

    st.text_area("Description", height=140, key=f"{prefix}_description")
    st.text_area("Likelihood", height=100, key=f"{prefix}_likelihood")
    st.text_area("Impact", height=120, key=f"{prefix}_impact")
    st.text_area("Tools Used", height=80, key=f"{prefix}_tools_used")
    st.text_area("References", height=100, key=f"{prefix}_references")
    st.text_area("Recommendation", height=120, key=f"{prefix}_recommendation")
    st.text_area("Code / Output", height=180, key=f"{prefix}_code")

    st.markdown("### Images")
    current_images = st.session_state.get(f"{prefix}_images", [])
    current_title = _safe_text(st.session_state.get(f"{prefix}_title")).strip() or initial_title
    current_images = _upload_new_images(prefix, current_images, default_prefix=current_title)
    current_images = _render_image_preview_block(current_images, prefix)
    st.session_state[f"{prefix}_images"] = current_images


def _render_import_section(findings, report_data: dict):
    st.subheader("Import Findings")

    uploaded = st.file_uploader(
        "Upload Nessus / Nmap / OpenVAS / CSV / JSON",
        type=["nessus", "xml", "csv", "json", "nmap"],
        key="findings_import_file",
    )

    if not uploaded:
        return

    try:
        file_bytes = uploaded.read()
        if not file_bytes:
            st.error("Fișierul uploadat este gol.")
            return
        imported = auto_parse_findings(file_bytes, uploaded.name)
    except Exception as e:
        st.error(f"Parser error: {e}")
        return

    if not imported:
        st.warning(
            "Nu s-au detectat findings în fișierul uploadat. "
            "Verifică formatul fișierului (Nessus, OpenVAS, Nmap XML, CSV, JSON)."
        )
        return

    st.success(f"Detected {len(imported)} findings.")

    for f in imported:
        if f.get("severity") not in SEVERITY_OPTIONS:
            f["severity"] = "Informational"
        f.setdefault("images", [])
        f = auto_fill_finding_cvss(f)

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

            f["id"] = _next_finding_id(findings)
            f["images"] = _clean_images(f.get("images", []))
            findings.append(normalize_report({"findings": [f]}).get("findings", [f])[0])
            added += 1

        _renumber_findings(findings)
        report_data["findings"] = findings
        st.session_state["report_data"] = report_data
        st.success(f"Import complete. Added {added} findings.")
        st.rerun()


def render_findings_tab(report_data: dict):
    report_data = normalize_report(report_data)

    st.header("Findings")

    if "findings" not in report_data or not isinstance(report_data["findings"], list):
        report_data["findings"] = []

    findings = report_data["findings"]

    _render_import_section(findings, report_data)

    st.markdown("---")

    with st.expander("Add New Finding", expanded=False):
        new_prefix = "finding_new"
        _init_editor_state(new_prefix, {})
        _render_editor(new_prefix, initial_title="Finding")

        if st.button("Add Finding", key=f"{new_prefix}_save", width="stretch"):
            new_finding = _build_finding_from_state(new_prefix)
            new_finding["id"] = _next_finding_id(findings)
            findings.append(new_finding)
            _renumber_findings(findings)
            report_data["findings"] = findings
            st.session_state["report_data"] = report_data
            _cleanup_editor_state(new_prefix)
            st.success("Finding added.")
            st.rerun()

    st.markdown("---")

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

    for idx, f in enumerate(filtered):
        sev = f.get("severity", "Informational")

        with st.container(border=True):
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

            hosts = _normalize_string_list(f.get("hosts")) or (
                [_safe_text(f.get("host")).strip()] if _safe_text(f.get("host")).strip() else []
            )
            ports = _normalize_string_list(f.get("ports")) or (
                [_safe_text(f.get("port")).strip()] if _safe_text(f.get("port")).strip() else []
            )
            cves = _normalize_string_list(f.get("cves")) or (
                [_safe_text(f.get("cve")).strip()] if _safe_text(f.get("cve")).strip() else []
            )
            cwes = _normalize_string_list(f.get("cwes")) or (
                [_safe_text(f.get("cwe")).strip()] if _safe_text(f.get("cwe")).strip() else []
            )

            meta_parts = []
            if hosts:
                meta_parts.append(f"Hosts: {', '.join(hosts)}")
            if ports:
                meta_parts.append(f"Ports: {', '.join(ports)}")
            if f.get("protocol"):
                meta_parts.append(f"Protocol: {f.get('protocol')}")
            if cves:
                meta_parts.append(f"CVEs: {', '.join(cves)}")
            if cwes:
                meta_parts.append(f"CWEs: {', '.join(cwes)}")
            if f.get("cvss"):
                meta_parts.append(f"CVSS: {f.get('cvss')}")
            if meta_parts:
                st.caption(" | ".join(meta_parts))

            col1, col2 = st.columns([1, 1])

            with col1:
                if st.button("Edit", key=f"finding_edit_btn_{f.get('id', idx)}", width="stretch"):
                    try:
                        real_index = findings.index(f)
                        st.session_state["editing_finding_index"] = real_index
                    except ValueError:
                        st.session_state["editing_finding_index"] = None
                    st.rerun()

            with col2:
                if st.button("Delete", key=f"finding_delete_btn_{f.get('id', idx)}", width="stretch"):
                    try:
                        real_index = findings.index(f)
                        findings.pop(real_index)
                        _renumber_findings(findings)
                        report_data["findings"] = findings
                        st.session_state["report_data"] = report_data
                        st.success("Deleted.")
                        st.rerun()
                    except ValueError:
                        st.warning("Could not delete finding.")

    edit_idx = st.session_state.get("editing_finding_index")
    if edit_idx is not None and 0 <= edit_idx < len(findings):
        st.markdown("---")
        st.subheader(f"Edit Finding {findings[edit_idx].get('id', edit_idx + 1)}")

        edit_prefix = f"finding_edit_{edit_idx}"
        _init_editor_state(edit_prefix, findings[edit_idx])
        _render_editor(edit_prefix, initial_title=_safe_text(findings[edit_idx].get("title")) or "Finding")

        col_a, col_b = st.columns(2)

        with col_a:
            if st.button("Save Changes", key=f"{edit_prefix}_save", width="stretch"):
                updated = _build_finding_from_state(edit_prefix)
                updated["id"] = findings[edit_idx].get("id", edit_idx + 1)
                findings[edit_idx] = updated
                _renumber_findings(findings)
                report_data["findings"] = findings
                st.session_state["report_data"] = report_data
                _cleanup_editor_state(edit_prefix)
                st.session_state["editing_finding_index"] = None
                st.success("Saved.")
                st.rerun()

        with col_b:
            if st.button("Cancel Edit", key=f"{edit_prefix}_cancel", width="stretch"):
                _cleanup_editor_state(edit_prefix)
                st.session_state["editing_finding_index"] = None
                st.rerun()

    return report_data
