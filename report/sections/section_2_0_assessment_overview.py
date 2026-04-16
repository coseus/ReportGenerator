# report/sections/section_2_0_assessment_overview.py
from util.helpers import format_multiline, preformat
from reportlab.platypus import Paragraph, Spacer
from reportlab.lib.units import mm

def build_section(elements, styles, report):
    elements.append(Paragraph("5.0 Assessment Overview", styles["HeadingModern"]))

    text = report.get("assessment_overview", "")
    formatted = format_multiline(text)

    elements.append(Paragraph(formatted, styles["NormalHelv"]))
    elements.append(Spacer(1, 14))
