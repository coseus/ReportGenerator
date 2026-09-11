# report/numbering.py
"""
Handles automatic numbering for findings and additional reports.

Used by findings_tab.py and pdf/docx generators.

Numbering rules (Corporate Extended):
- Findings = 8.1, 8.2, 8.3 ...
- Additional Reports = 9.1, 9.2 ...

This module ensures consistent ordering even after editing / deleting.
"""

def next_finding_id(findings: list) -> str:
    """
    Returns next available ID in section 8.x
    Example: if findings = [{id:"8.1"}, {id:"8.2"}] -> returns "8.3"
    """
    if not findings:
        return "8.1"

    used = []
    for f in findings:
        fid = f.get("id")
        if not fid:
            continue
        try:
            if fid.startswith("8."):
                used.append(float(fid.replace("8.", "")))
        except Exception:
            continue

    if not used:
        return "8.1"

    next_num = max(used) + 1
    return f"8.{int(next_num)}"


def renumber_findings(findings: list) -> list:
    """
    Reassigns all findings to 8.1, 8.2, 8.3... in current order.
    Called after delete or manual reorder.
    """
    new_list = []
    counter = 1

    for f in findings:
        new_f = dict(f)
        new_f["id"] = f"8.{counter}"
        new_list.append(new_f)
        counter += 1

    return new_list


def next_additional_id(additional_reports: list) -> str:
    """
    Returns next available ID in section 9.x
    """
    if not additional_reports:
        return "9.1"

    used = []
    for r in additional_reports:
        rid = r.get("id")
        if not rid:
            continue
        try:
            if rid.startswith("9."):
                used.append(float(rid.replace("9.", "")))
        except Exception:
            continue

    if not used:
        return "9.1"

    next_num = max(used) + 1
    return f"9.{int(next_num)}"


def renumber_additional_reports(additional_reports: list) -> list:
    """
    Forces numbering: 9.1, 9.2, 9.3...
    """
    new_list = []
    counter = 1

    for r in additional_reports:
        new_r = dict(r)
        new_r["id"] = f"9.{counter}"
        new_list.append(new_r)
        counter += 1

    return new_list
