# report/sections/section_2_2_scope.py
from util.helpers import format_multiline, preformat
from reportlab.platypus import Paragraph, Spacer
from reportlab.lib.units import mm

def build_section(elements, styles, report):
    elements.append(Paragraph("5.2 Scope", styles["HeadingModern"]))

    text = report.get("scope", "")
    formatted = format_multiline(text)

    elements.append(Paragraph(formatted, styles["NormalHelv"]))
    elements.append(Spacer(1, 12))
