# report/sections/section_8_0_detailed_walkthrough.py
from reportlab.platypus import Paragraph, Spacer, Image as RLImage
from reportlab.lib.units import mm
import base64
from io import BytesIO
from PIL import Image

def build_section(elements, styles, report):
    elements.append(Paragraph("8.0 Detailed Walkthrough", styles["HeadingModern"]))
    elements.append(Spacer(1, 4))

    steps = report.get("detailed_walkthrough", [])

    if not steps:
        elements.append(Paragraph("No walkthrough steps provided.", styles["NormalHelv"]))
        elements.append(Spacer(1, 10))
        return

    for idx, step in enumerate(steps, start=1):
        elements.append(Paragraph(f"<b>8.{idx} – {step.get('title','Untitled Step')}</b>", styles["SubHeading"]))

        # Description
        desc_html = step.get("description", "").replace("\n", "<br/>")
        elements.append(Paragraph(desc_html, styles["NormalHelv"]))
        elements.append(Spacer(1, 4))

        # Code block
        if step.get("code"):
            code_html = step["code"].replace(" ", "&nbsp;").replace("\n", "<br/>")
            elements.append(Paragraph(f"<font face='Courier'>{code_html}</font>", styles["CodeBlock"]))
            elements.append(Spacer(1, 4))

        # Images
        for img_b64 in step.get("images", []):
            try:
                img_data = base64.b64decode(img_b64)
                img = Image.open(BytesIO(img_data))

                w, h = img.size
                max_w = 150 * mm
                scale = min(max_w / w, 1)
                new_w = w * scale
                new_h = h * scale

                bio = BytesIO()
                img.save(bio, format="PNG")
                bio.seek(0)

                elements.append(RLImage(bio, width=new_w, height=new_h))
                elements.append(Spacer(1, 6))
            except:
                continue

        elements.append(Spacer(1, 10))


def build_section_docx(doc, report):
    doc.add_heading("8.0 Detailed Walkthrough", level=1)

    steps = report.get("detailed_walkthrough", [])
    if not steps:
        doc.add_paragraph("No walkthrough steps provided.")
        return

    for idx, step in enumerate(steps, start=1):
        doc.add_heading(f"8.{idx} – {step.get('title','Untitled Step')}", level=2)
        for line in step.get("description","").splitlines():
            doc.add_paragraph(line)

        if step.get("code"):
            doc.add_paragraph(step["code"], style="Code")

        for img_b64 in step.get("images", []):
            try:
                img_data = base64.b64decode(img_b64)
                doc.add_picture(BytesIO(img_data), width=5000000)
            except:
                pass
