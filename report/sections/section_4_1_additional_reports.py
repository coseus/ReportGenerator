# report/sections/section_4_1_additional_reports.py
from io import BytesIO
from reportlab.platypus import Paragraph, Spacer, Image as RLImage
from reportlab.lib.units import mm
from util.helpers import safe_b64decode, image_resize


def build_section(elements, styles, report):
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("9.0 Additional Reports & Scans", styles["HeadingModern"]))
    elements.append(Spacer(1, 8))

    reports = report.get("additional_reports", []) or []

    if not reports:
        elements.append(
            Paragraph("No additional reports or informational scans were provided.", styles["NormalHelv"])
        )
        return

    for idx, r in enumerate(reports, start=1):
        title = r.get("name", f"Item {idx}")
        desc = r.get("description", "")
        code = r.get("code", "")
        images = r.get("images", []) or []

        # 7.x Title
        elements.append(Paragraph(f"9.{idx} {title}", styles["SubHeading"]))
        elements.append(Spacer(1, 4))

        # Description
        if desc:
            elements.append(
                Paragraph(desc.replace("\n", "<br/>"), styles["NormalHelv"])
            )
            elements.append(Spacer(1, 4))

        # Code / output
        if code:
            elements.append(Paragraph("<b>Code / Output:</b>", styles["NormalHelv"]))
            safe = (
                code.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\n", "<br/>")
            )
            elements.append(
                Paragraph(f"<font face='Courier'>{safe}</font>", styles["NormalHelv"])
            )
            elements.append(Spacer(1, 4))

        # Images (una sub alta, sub text)
        if images:
            elements.append(Paragraph("<b>Evidence Images:</b>", styles["NormalHelv"]))
            elements.append(Spacer(1, 2))

            for b64 in images:
                try:
                    raw = safe_b64decode(b64)
                    resized = image_resize(raw, max_size=800)  # bytes sau base64
                    if isinstance(resized, str):
                        # dacă helper-ul întoarce base64, decodăm la bytes
                        img_bytes = safe_b64decode(resized)
                    else:
                        img_bytes = resized

                    bio = BytesIO(img_bytes)
                    img = RLImage(bio, width=140 * mm, preserveAspectRatio=True)
                    elements.append(img)
                    elements.append(Spacer(1, 6))
                except Exception:
                    continue

        elements.append(Spacer(1, 10))
