# report/sections/section_1_3_contact_information.py
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import mm

def build_section(elements, styles, report):
    elements.append(Paragraph("1.3 Contact Information", styles["HeadingModern"]))
    contacts = report.get("contacts", [])
    if not contacts:
        elements.append(Paragraph("No contact information provided.", styles["NormalHelv"]))
        elements.append(Spacer(1,6))
        return
    # render as a simple 3-column table
    table_data = [["Name", "Title", "Contact"]]
    for c in contacts:
        table_data.append([c.get("name",""), c.get("title",""), c.get("contact","")])
    t = Table(table_data, colWidths=[120, 150, 150])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.lightgrey),
        ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
    ]))
    elements.append(t)
    elements.append(Spacer(1,6))
