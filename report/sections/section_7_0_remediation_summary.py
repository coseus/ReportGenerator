# report/sections/section_7_0_remediation_summary.py
from reportlab.platypus import Paragraph, Spacer
from reportlab.lib.units import mm

def _default_block(title, items: list[str]) -> str:
    if not items:
        return ""
    bullet_lines = "".join([f"• {line}<br/>" for line in items])
    return f"<b>{title}</b><br/>{bullet_lines}"

def build_section(elements, styles, report):
    """
    7.0 Remediation Summary
    Uses (if provided in report dict):
      remediation_short_term
      remediation_medium_term
      remediation_long_term
    Else, falls back to example text.
    """
    elements.append(Paragraph("7.0 Remediation Summary", styles["HeadingModern"]))
    elements.append(Spacer(1, 4))

    short_txt = report.get("remediation_short_term", "").strip()
    medium_txt = report.get("remediation_medium_term", "").strip()
    long_txt = report.get("remediation_long_term", "").strip()

    if not (short_txt or medium_txt or long_txt):
        # Fallback: template with your example
        short_block = _default_block("Short Term", [
            "[Finding 2] – Set strong (24+ character) passwords on all SPN accounts",
            "[Finding 5] – Change the default admin credentials for the Tomcat Manager",
            "[Finding 7] – Disable Directory Listing on the affected web server",
        ])
        medium_block = _default_block("Medium Term", [
            "[Finding 1] – Disable LLMNR and NBT-NS wherever possible",
            "[Finding 2] – Transition from SPNs to Group Managed Service Accounts (gMSA) wherever possible",
            "[Finding 3] – Implement a solution such as the Microsoft Local Administrator Password Solution (LAPS)",
            "[Finding 4] – Enhance the domain password policy",
        ])
        long_block = _default_block("Long Term", [
            "Perform ongoing internal network vulnerability assessments and domain password audits",
            "Perform periodic Active Directory security assessments",
            "Educate systems and network administrators and developers on security hardening best practices",
            "Enhance network segmentation to isolate critical hosts and limit the effects of an internal compromise",
        ])

        html = "<br/>".join([short_block, "<br/>", medium_block, "<br/>", long_block])
        elements.append(Paragraph(html, styles["NormalHelv"]))
        elements.append(Spacer(1, 10))
        return

    # If custom text provided in UI / JSON, use it instead (kept as-is, with line breaks)
    def as_html_block(title, txt):
        txt = txt.replace("\n", "<br/>")
        return f"<b>{title}</b><br/>{txt}"

    blocks = []
    if short_txt:
        blocks.append(as_html_block("Short Term", short_txt))
    if medium_txt:
        blocks.append(as_html_block("Medium Term", medium_txt))
    if long_txt:
        blocks.append(as_html_block("Long Term", long_txt))

    html = "<br/><br/>".join(blocks)
    elements.append(Paragraph(html, styles["NormalHelv"]))
    elements.append(Spacer(1, 10))


def build_section_docx(doc, report):
    doc.add_heading("7.0 Remediation Summary", level=1)

    short_txt = report.get("remediation_short_term", "").strip()
    medium_txt = report.get("remediation_medium_term", "").strip()
    long_txt = report.get("remediation_long_term", "").strip()

    if not (short_txt or medium_txt or long_txt):
        doc.add_paragraph("Short Term", style="Heading 2")
        doc.add_paragraph("[Finding 2] – Set strong (24+ character) passwords on all SPN accounts", style="List Bullet")
        doc.add_paragraph("[Finding 5] – Change the default admin credentials for the Tomcat Manager", style="List Bullet")
        doc.add_paragraph("[Finding 7] – Disable Directory Listing on the affected web server", style="List Bullet")

        doc.add_paragraph("Medium Term", style="Heading 2")
        doc.add_paragraph("[Finding 1] – Disable LLMNR and NBT-NS wherever possible", style="List Bullet")
        doc.add_paragraph("[Finding 2] – Transition from SPNs to Group Managed Service Accounts (gMSA) wherever possible", style="List Bullet")
        doc.add_paragraph("[Finding 3] – Implement a solution such as Microsoft LAPS", style="List Bullet")
        doc.add_paragraph("[Finding 4] – Enhance the domain password policy", style="List Bullet")

        doc.add_paragraph("Long Term", style="Heading 2")
        doc.add_paragraph("Perform ongoing internal network vulnerability assessments and domain password audits", style="List Bullet")
        doc.add_paragraph("Perform periodic Active Directory security assessments", style="List Bullet")
        doc.add_paragraph("Educate systems and network administrators and developers on security hardening best practices", style="List Bullet")
        doc.add_paragraph("Enhance network segmentation to isolate critical hosts and limit the effects of an internal compromise", style="List Bullet")
        return

    if short_txt:
        doc.add_paragraph("Short Term", style="Heading 2")
        for line in short_txt.splitlines():
            if line.strip():
                doc.add_paragraph(line.strip(), style="List Bullet")

    if medium_txt:
        doc.add_paragraph("Medium Term", style="Heading 2")
        for line in medium_txt.splitlines():
            if line.strip():
                doc.add_paragraph(line.strip(), style="List Bullet")

    if long_txt:
        doc.add_paragraph("Long Term", style="Heading 2")
        for line in long_txt.splitlines():
            if line.strip():
                doc.add_paragraph(line.strip(), style="List Bullet")
