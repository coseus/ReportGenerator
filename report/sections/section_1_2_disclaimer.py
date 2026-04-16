# report/sections/section_1_2_disclaimer.py
from reportlab.platypus import Paragraph, Spacer
from util.helpers import format_multiline, preformat
from reportlab.lib.units import mm

def build_section(elements, styles, report):
    elements.append(Paragraph("1.0 Confidentiality and Legal", styles["HeadingModern"]))

    text = (
            "This penetration test was conducted exclusively in accordance with the Rules of Engagement and Statement of Work signed by the Client."
            "No warranties of any kind, express or implied, are provided." 
            "The Testing Team and its personnel shall not be held liable for any direct, indirect, incidental, "
            "consequential, or punitive damages arising from the use or misuse of this report, its findings, or any actions taken as a result thereof."
            "The report is delivered “as is”."
    )

    elements.append(Paragraph(format_multiline(text), styles["NormalHelv"]))
    elements.append(Spacer(1, 14))
