# report/sections/section_4_0_technical_findings.py
from reportlab.platypus import Paragraph, Spacer, Preformatted, Image as RLImage
from report.numbering import renumber_findings
from util.helpers import format_multiline, preformat, pdf_safe_image
from reportlab.lib.units import mm

SEVERITY_COLORS = {
    "Critical": "#e74c3c",
    "High": "#e67e22",
    "Moderate": "#f1c40f",
    "Low": "#3498db",
    "Informational": "#95a5a6",
}

def build_section(elements, styles, report):
    findings = report.get("findings", [])
    if not findings:
        return

    findings = sorted(
        findings,
        key=lambda f: ["Critical","High","Moderate","Low","Informational"].index(f.get("severity","Informational"))
    )

    elements.append(Paragraph("6.0 Technical Findings", styles["HeadingModern"]))
    elements.append(Spacer(1, 10))

    for f in findings:
        fid = f.get("id")
        sev = f.get("severity", "Informational")
        color = SEVERITY_COLORS.get(sev, "#95a5a6")

        # Finding header
        elements.append(Paragraph(
            f'<font color="{color}"><b>6.{fid} – {sev}</b></font><br/>{f.get("title","Untitled Finding")}',
            styles["SubHeading"]
        ))
        elements.append(Spacer(1, 6))

        # Meta
        meta = []
        if f.get("host"): meta.append(f"Host: {f['host']}")
        if f.get("port"): meta.append(f"Port: {f['port']}")
        if f.get("protocol"): meta.append(f"Protocol: {f['protocol']}")
        if f.get("cvss"): meta.append(f"CVSS: {f['cvss']}")
        if f.get("cve"): meta.append(f"CVE: {f['cve']}")

        if meta:
            elements.append(Paragraph(" | ".join(meta), styles["MetaSmall"]))
            elements.append(Spacer(1, 8))

        # Description
        if f.get("description"):
            elements.append(Paragraph("<b>Description</b>", styles["NormalHelv"]))
            elements.append(Preformatted(preformat(f.get("description","")), styles["PreText"]))
            elements.append(Spacer(1, 8))

        # Impact
        if f.get("impact"):
            elements.append(Paragraph("<b>Impact</b>", styles["NormalHelv"]))
            elements.append(Preformatted(preformat(f.get("impact","")), styles["PreText"]))
            elements.append(Spacer(1, 8))

        # Recommendation
        if f.get("recommendation"):
            elements.append(Paragraph("<b>Recommendation</b>", styles["NormalHelv"]))
            elements.append(Preformatted(preformat(f.get("recommendation","")), styles["PreText"]))
            elements.append(Spacer(1, 12))

        # Code / Output
        if f.get("code"):
            elements.append(Paragraph("<b>Code / Output</b>", styles["NormalHelv"]))
            elements.append(Preformatted(preformat(f.get("code","")), styles["PreText"]))
            elements.append(Spacer(1, 10))

        # Images
        imgs = pdf_safe_image(f.get("images", []))
        if imgs:
            elements.append(Paragraph("<b>Evidence Images</b>", styles["NormalHelv"]))
            elements.append(Spacer(1, 6))
            for im in imgs:
                elements.append(im)
                elements.append(Spacer(1, 10))

        elements.append(Spacer(1, 18))
