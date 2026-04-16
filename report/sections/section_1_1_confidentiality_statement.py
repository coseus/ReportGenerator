# report/sections/section_1_1_confidentiality_statement.py
from reportlab.platypus import Paragraph, Spacer
from util.helpers import format_multiline, preformat
from reportlab.lib.units import mm

def build_section(elements, styles, report):
    elements.append(Paragraph("1.0 Confidentiality and Legal", styles["HeadingModern"]))

    text = (
        "Findings are provided for informational purposes only and represent the system state at the time of testing only."
        "The client is solely responsible for implementing and verifying any remediation actions."
        "The testing team disclaims all liability for any damages resulting from the use of this report or the authorized testing activities."
    )

    elements.append(Paragraph(format_multiline(text), styles["NormalHelv"]))
    elements.append(Spacer(1, 14))
