# report/sections/section_2_3_scope_exclusions.py
from util.helpers import format_multiline, preformat
from reportlab.platypus import Paragraph, Spacer
from reportlab.lib.units import mm

def build_section(elements, styles, report):
    elements.append(Paragraph("5.3 Scope Exclusions", styles["HeadingModern"]))

    text = report.get("scope_exclusions", "")
    formatted = format_multiline(text)

    elements.append(Paragraph(formatted, styles["NormalHelv"]))
    elements.append(Spacer(1, 12))
