# report/sections/section_5_0_executive_summary.py
from reportlab.platypus import Paragraph, Spacer, Preformatted
from reportlab.lib.styles import ParagraphStyle
from util.helpers import format_multiline

def build_section(elements, styles, report):

    elements.append(Paragraph("3.0 Executive Summary", styles["HeadingModern"]))
    elements.append(Spacer(1, 6))

    text = report.get("executive_summary", "").strip()

    if not text:
        elements.append(Paragraph("No executive summary provided.", styles["NormalHelv"]))
        elements.append(Spacer(1, 10))
        return

    safe = format_multiline(text)

    elements.append(
        Paragraph(
            safe,
            ParagraphStyle(
                "ExecSummaryWrap",
                parent=styles["NormalHelv"],
                leading=14,
                splitLongWords=True,
                wordWrap="LTR",
                allowWidows=1,
                allowOrphans=1,
                spaceAfter=8,
            ),
        )
    )
    elements.append(Spacer(1, 12))
