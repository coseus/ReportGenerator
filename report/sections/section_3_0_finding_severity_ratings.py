# report/sections/section_3_0_finding_severity_ratings.py
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from util.helpers import format_multiline, preformat
from reportlab.lib.units import mm

def build_section(elements, styles, report):
    elements.append(Paragraph("1.4 Finding Severity Ratings", styles["HeadingModern"]))

    table_data = [
        ["Severity", "CVSS Range", "Definition"],
        ["Critical", "9.0 – 10.0", "Immediate risk of full compromise."],
        ["High", "7.0 – 8.9", "High probability of exploitation; privileged impact."],
        ["Moderate", "4.0 – 6.9", "Requires conditions or chaining to exploit."],
        ["Low", "0.1 – 3.9", "Low probability; limited security impact."],
        ["Informational", "N/A", "No vulnerability; useful informational data only."]
    ]

    table = Table(table_data, colWidths=[30*mm, 30*mm, None])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.lightgrey),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("FONTSIZE", (0,0), (-1,-1), 9),
    ]))

    elements.append(table)
    elements.append(Spacer(1, 14))
