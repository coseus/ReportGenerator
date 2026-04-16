# report/sections/section_1_0_confidentiality_and_legal.py
from reportlab.platypus import Paragraph, Spacer
from util.helpers import format_multiline, preformat
from reportlab.lib.units import mm

def build_section(elements, styles, report):
    elements.append(Paragraph("1.0 Confidentiality and Legal", styles["HeadingModern"]))

    text = (
        "This penetration testing report contains confidential information intended solely "
        "for the client organization. Unauthorized access, distribution, disclosure, or copying "
        "of this document or any information contained herein is strictly prohibited. "
        "All findings, methodologies, and artifacts are the intellectual property of the "
        "security testing provider unless otherwise stated."
    )

    elements.append(Paragraph(format_multiline(text), styles["NormalHelv"]))
    elements.append(Spacer(1, 14))
