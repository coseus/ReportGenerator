# ui/compliance_tab.py
import os
import streamlit as st
import pandas as pd

from util.compliance import (
    map_findings,
    get_mapping,
    save_mapping,
    ensure_mapping_file,
    FRAMEWORKS,
    ALL_FRAMEWORKS,
    selected_frameworks,
    _MAPPING_CSV,
)
from util.i18n import get_language, t

FRAMEWORK_LABELS = {
    "nis2": "NIS2 art.21(2)",
    "iec": "IEC 62443-3-3",
    "nist": "NIST SP 800-53/82r3",
    "iso27001": "ISO/IEC 27001",
}
_AUTO = "(Auto)"
_MAP_COLS = ["category", "keywords", "nis2", "iec62443", "nist", "iso27001"]


def render_compliance_tab(report_data: dict):
    get_language(report_data)
    st.header("Mapare de conformitate")
    st.caption(
        "Cum functioneaza: fiecare constatare este mapata automat pe o CATEGORIE (dupa cuvinte cheie), "
        "iar categoria are asociate controale NIS2 / IEC 62443-3-3 / NIST / ISO 27001. "
        "Maparea categorie -> controale este intr-un fisier separat, editabil si din web mai jos: "
        f"data/compliance_mapping.csv. Poti forta manual categoria per constatare."
    )

    report_data.setdefault("include_compliance", True)
    report_data.setdefault("compliance_frameworks", list(ALL_FRAMEWORKS))

    report_data["include_compliance"] = st.checkbox(
        "Include maparea de conformitate in raportul exportat",
        value=bool(report_data.get("include_compliance", True)),
        key="include_compliance_toggle_ct",
    )
    if not report_data["include_compliance"]:
        st.info("Sectiunea de conformitate NU va aparea in export.")
        return report_data

    # --- choose frameworks to export ---
    st.subheader("Cadre de conformitate de inclus in export")
    sel = st.multiselect(
        "Alege ce cadre apar in tabelul de conformitate",
        options=list(ALL_FRAMEWORKS),
        default=selected_frameworks(report_data),
        format_func=lambda k: FRAMEWORK_LABELS.get(k, k),
        key="compliance_frameworks_ms",
    )
    report_data["compliance_frameworks"] = sel or list(ALL_FRAMEWORKS)

    # --- editable mapping table (separate file) ---
    with st.expander("Editeaza maparea categorie -> controale (fisier separat)", expanded=False):
        st.caption(f"Fisier: {_MAPPING_CSV}")
        ensure_mapping_file()
        mapping = get_mapping()
        df_map = pd.DataFrame(
            [{
                "category": e.get("category", ""),
                "keywords": "; ".join(e.get("keywords", []) or []),
                "nis2": e.get("nis2", ""),
                "iec62443": e.get("iec62443", ""),
                "nist": e.get("nist", ""),
                "iso27001": e.get("iso27001", ""),
            } for e in mapping],
            columns=_MAP_COLS,
        )
        edited = st.data_editor(
            df_map, num_rows="dynamic", width="stretch", key="mapping_editor",
            column_config={
                "category": st.column_config.TextColumn("Categorie", width="medium"),
                "keywords": st.column_config.TextColumn("Cuvinte cheie (separate prin ;)", width="large"),
                "nis2": "NIS2 art.21(2)",
                "iec62443": "IEC 62443-3-3",
                "nist": "NIST",
                "iso27001": "ISO/IEC 27001",
            },
        )
        col_a, col_b = st.columns([1, 3])
        if col_a.button("💾 Salveaza maparea", key="save_mapping_btn"):
            entries = []
            for _, row in edited.iterrows():
                cat = str(row.get("category") or "").strip()
                if not cat:
                    continue
                kw = str(row.get("keywords") or "")
                entries.append({
                    "category": cat,
                    "keywords": [k.strip().lower() for k in kw.replace("|", ";").split(";") if k.strip()],
                    "nis2": str(row.get("nis2") or "").strip(),
                    "iec62443": str(row.get("iec62443") or "").strip(),
                    "nist": str(row.get("nist") or "").strip(),
                    "iso27001": str(row.get("iso27001") or "").strip(),
                })
            try:
                save_mapping(entries)
                col_b.success("Maparea a fost salvata in data/compliance_mapping.csv.")
            except Exception as exc:
                col_b.error(f"Nu am putut salva: {exc}")

    findings = report_data.get("findings", []) or []
    if not findings:
        st.warning("Nu exista constatari inca. Adauga-le in tab-ul Findings.")
        return report_data

    # --- per-finding category override (map findings from the web) ---
    st.subheader("Mapeaza constatarile (categorie per constatare)")
    st.caption("(Auto) = detectare automata dupa cuvinte cheie. Poti forta manual o categorie.")
    categories = [_AUTO] + [e["category"] for e in get_mapping()]
    for i, f in enumerate(findings):
        cur = f.get("compliance_category") or ""
        idx = categories.index(cur) if cur in categories else 0
        c1, c2 = st.columns([5, 4])
        c1.markdown(f"**{f.get('title', '(fara titlu)')}**  ·  {f.get('severity', '')}")
        choice = c2.selectbox(
            "Categorie", categories, index=idx,
            key=f"comp_cat_{i}", label_visibility="collapsed",
        )
        f["compliance_category"] = "" if choice == _AUTO else choice

    # --- live preview of the exported table ---
    st.subheader("Previzualizare (exact ce se exporta)")
    rows = map_findings(findings)
    active = report_data["compliance_frameworks"]
    columns = {"title": "Constatare", "severity": "Severitate", "category": "Categorie"}
    for key, _hk, field, name in FRAMEWORKS:
        if key in active:
            columns[field] = name
    df = pd.DataFrame([{columns[c]: r.get(c, "") for c in columns} for r in rows])
    st.dataframe(df, width="stretch", hide_index=True)

    return report_data
