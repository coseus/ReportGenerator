# report/data_model.py

def empty_report():
    return {
        # --- General Info ---
        "client": "",
        "project": "",
        "tester": "",
        "contact": "",
        "date": "",
        "version": "1.0",

        # --- Executive Summary ---
        "executive_summary": "",

        # --- Assessment (5.x) ---
        "assessment_overview": "",
        "assessment_details": "",
        "scope": "",
        "scope_exclusions": "",
        "client_allowances": "",

        # --- Findings (6.x) ---
        "findings": [],

        # --- Optional high-fidelity metadata ---
        "overall_risk": "Critical",
        "attack_path": [],

        # --- Remediation Summary (7.x) ---
        "remediation_short": [],
        "remediation_medium": [],
        "remediation_long": [],

        # --- Detailed Walkthrough (8.x) ---
        "detailed_walkthrough": [],

        # --- Additional Reports (9.x) ---
        "additional_reports": [],

        # --- Vulnerability Summary (auto-calculat) ---
        "vuln_summary_counts": {},
        "vuln_summary_total": 0,
        "vuln_by_host": {},

        # --- PDF Options ---
        "watermark_enabled": False,
        "theme_hex": "#2E3B4E",

        # --- Logo ---
        "logo_b64": "",
    }
