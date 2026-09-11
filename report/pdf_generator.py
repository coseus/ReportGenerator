from __future__ import annotations

import base64
import os
import re
from collections import Counter, defaultdict
from io import BytesIO
from typing import Iterable

from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image as RLImage,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from util.charting import risk_trend_png, severity_distribution_png
from util.helpers import normalize_images
from util.i18n import t, get_language

from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

_FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "util", "fonts")
_FONTS_OK = False
try:
    pdfmetrics.registerFont(TTFont("DejaVuSans", os.path.join(_FONT_DIR, "DejaVuSans.ttf")))
    pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", os.path.join(_FONT_DIR, "DejaVuSans-Bold.ttf")))
    pdfmetrics.registerFont(TTFont("DejaVuSans-Oblique", os.path.join(_FONT_DIR, "DejaVuSans-Oblique.ttf")))
    pdfmetrics.registerFont(TTFont("DejaVuSansMono", os.path.join(_FONT_DIR, "DejaVuSansMono.ttf")))
    pdfmetrics.registerFontFamily(
        "DejaVuSans", normal="DejaVuSans", bold="DejaVuSans-Bold",
        italic="DejaVuSans-Oblique", boldItalic="DejaVuSans-Bold",
    )
    _FONTS_OK = True
except Exception:
    _FONTS_OK = False

# Unicode fonts (Romanian diacritics) with graceful fallback to the PDF base fonts.
if _FONTS_OK:
    F_REG, F_BOLD, F_OBL, F_MONO = "DejaVuSans", "DejaVuSans-Bold", "DejaVuSans-Oblique", "DejaVuSansMono"
else:
    F_REG, F_BOLD, F_OBL, F_MONO = F_REG, F_BOLD, F_OBL, F_MONO

from util import control_mapper as CM
from util import methodology as MM
from util import attack_chain as AC
from util import report_meta as RM
from util.narrative import executive_narrative


SEVERITIES_ORDER = ["Critical", "High", "Moderate", "Low", "Informational"]
SEVERITY_COLORS = {
    "Critical": "#A61B1B",
    "High": "#D35400",
    "Moderate": "#B9770E",
    "Low": "#1F618D",
    "Informational": "#5D6D7E",
}
SEVERITY_SHORT = {
    "Critical": "CRIT",
    "High": "HIGH",
    "Moderate": "MED",
    "Low": "LOW",
    "Informational": "INFO",
}
from util.legal_sections import section_default


def _section_value(report: dict, key: str, default: str = "") -> str:
    value = report.get(key)
    if not value:
        sections = report.get("sections") or {}
        value = sections.get(key)
    if isinstance(value, dict):
        value = value.get("content") or value.get("text") or value.get("value") or ""
    return str(value or default or "").strip()


def _header_label(report: dict) -> str:
    provider = str(report.get("provider") or "").strip()
    who = provider or str(report.get("client") or "Client").strip()
    project = str(report.get("project") or "").strip()
    return f"{who} · {project}" if project else who


class PentestDocTemplate(BaseDocTemplate):
    def __init__(self, filename, report, report_variant, accent_color, watermark_enabled=False, **kwargs):
        super().__init__(filename, **kwargs)
        self.report = report
        self.report_variant = report_variant
        self.accent_color = accent_color
        self.watermark_enabled = watermark_enabled
        self.heading_log: list[tuple[int, str, int]] = []
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="normal")
        self.addPageTemplates(
            [
                PageTemplate(id="Cover", frames=[frame], onPage=self._draw_cover_page),
                PageTemplate(id="Body", frames=[frame], onPage=self._draw_body_page),
            ]
        )

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and getattr(flowable, "_is_heading", False):
            self.heading_log.append((flowable._heading_level, flowable._heading_text, self.page))

    def _draw_cover_page(self, canvas, doc):
        w, h = A4
        canvas.saveState()
        accent = self.accent_color
        deep = _mix_color(accent, 0.58)
        pale = _mix_color(accent, 0.10)
        canvas.setFillColor(colors.white)
        canvas.rect(0, 0, w, h, fill=1, stroke=0)
        canvas.setFillColor(deep)
        canvas.rect(0, h - 42 * mm, w, 42 * mm, fill=1, stroke=0)
        canvas.setFillColor(pale)
        canvas.rect(0, 0, w, 18 * mm, fill=1, stroke=0)
        canvas.setStrokeColor(_mix_color(accent, 0.35))
        canvas.setLineWidth(1.4)
        canvas.line(18 * mm, 28 * mm, 78 * mm, 28 * mm)
        if self.watermark_enabled:
            _draw_watermark(canvas)
        canvas.restoreState()

    def _draw_body_page(self, canvas, doc):
        w, h = A4
        canvas.saveState()
        accent = self.accent_color
        deep = _mix_color(accent, 0.58)
        if self.watermark_enabled:
            _draw_watermark(canvas)
        canvas.setFillColor(deep)
        canvas.rect(doc.leftMargin, h - 16 * mm, doc.width, 4, fill=1, stroke=0)
        canvas.setFont(F_BOLD, 9)
        canvas.setFillColor(_mix_color(accent, 0.50))
        canvas.drawString(doc.leftMargin, h - 10 * mm, _header_label(self.report))
        canvas.setFont(F_REG, 8)
        canvas.setFillColor(colors.HexColor("#6B7280"))
        canvas.drawRightString(w - doc.rightMargin, 10 * mm, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()


def _draw_watermark(canvas, text="CONFIDENTIAL"):
    canvas.saveState()
    canvas.setFillGray(0.9, 0.16)
    canvas.setFont(F_BOLD, 58)
    w, h = A4
    canvas.translate(w / 2, h / 2)
    canvas.rotate(35)
    canvas.drawCentredString(0, 0, text)
    canvas.restoreState()


def _hex_to_color(value: str) -> colors.Color:
    try:
        return colors.HexColor(value)
    except Exception:
        return colors.HexColor("#ED863D")


def _mix_color(color: colors.Color, ratio: float) -> colors.Color:
    ratio = max(0.0, min(1.0, ratio))
    return colors.Color(
        1 - (1 - color.red) * ratio,
        1 - (1 - color.green) * ratio,
        1 - (1 - color.blue) * ratio,
    )


def _safe_text(text) -> str:
    text = "" if text is None else str(text)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _risk_rank(value: str) -> int:
    try:
        return SEVERITIES_ORDER.index(value)
    except ValueError:
        return len(SEVERITIES_ORDER)


def _findings_sorted(report: dict) -> list[dict]:
    return sorted(
        report.get("findings", []) or [],
        key=lambda f: (_risk_rank(f.get("severity", "Informational")), (f.get("title") or "").lower()),
    )


def _listish(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value).strip()
    return [text] if text else []


def _meta_values(finding: dict, plural_key: str, singular_key: str):
    vals = _listish(finding.get(plural_key))
    if vals:
        return vals
    return _listish(finding.get(singular_key))


def _compute_summary(report: dict) -> dict:
    findings = _findings_sorted(report)
    counts = Counter()
    hosts = Counter()
    evidence_items = 0

    for finding in findings:
        sev = finding.get("severity", "Informational")
        if sev not in SEVERITIES_ORDER:
            sev = "Informational"
        counts[sev] += 1

        host_values = _meta_values(finding, "hosts", "host")
        if host_values:
            for host in host_values:
                hosts[host] += 1
        else:
            hosts["Unknown"] += 1

        evidence_items += len(finding.get("images", []) or []) + (1 if finding.get("code") else 0)

    for item in report.get("detailed_walkthrough", []) or []:
        evidence_items += len(item.get("images", []) or []) + (1 if item.get("code") else 0)

    for item in report.get("additional_reports", []) or []:
        evidence_items += len(item.get("images", []) or []) + (1 if item.get("code") else 0)

    return {
        "findings": findings,
        "counts": {s: counts.get(s, 0) for s in SEVERITIES_ORDER},
        "total": sum(counts.values()),
        "top_host": hosts.most_common(1)[0][0] if hosts else "N/A",
        "highest_severity": next((s for s in SEVERITIES_ORDER if counts[s] > 0), "Informational"),
        "evidence_items": evidence_items,
    }


def _image_from_b64(b64_str: str, max_width_mm=150, max_height_mm=120):
    try:
        raw = base64.b64decode(b64_str)
        return _image_from_bytes(raw, max_width_mm=max_width_mm, max_height_mm=max_height_mm)
    except Exception:
        return None


def _image_from_bytes(raw: bytes, max_width_mm=150, max_height_mm=120):
    try:
        img = PILImage.open(BytesIO(raw))
        # Preserve transparency (e.g. a logo PNG with a transparent background).
        # Converting straight to RGB fills transparent pixels with black, and JPEG
        # has no alpha channel, so a transparent logo turned into a black box.
        has_alpha = img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info)
        if has_alpha:
            img = img.convert("RGBA")
        elif img.mode != "RGB":
            img = img.convert("RGB")
        max_w_px = int(max_width_mm * 3.78)
        max_h_px = int(max_height_mm * 3.78)
        ratio = min(max_w_px / img.width, max_h_px / img.height, 1.0)
        new_w = max(1, int(img.width * ratio))
        new_h = max(1, int(img.height * ratio))
        if ratio < 1.0:
            img = img.resize((new_w, new_h), PILImage.LANCZOS)
        bio = BytesIO()
        if has_alpha:
            img.save(bio, format="PNG")            # keep alpha -> transparent background
        else:
            img.save(bio, format="JPEG", quality=90)
        bio.seek(0)
        out = RLImage(bio, width=(new_w / 3.78) * mm, height=(new_h / 3.78) * mm)
        out.hAlign = "CENTER"
        return out
    except Exception:
        return None


def _build_styles(theme_hex: str):
    accent = _hex_to_color(theme_hex)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CoverKicker", fontName=F_BOLD, fontSize=11, textColor=colors.white, alignment=TA_CENTER, spaceAfter=6))
    styles.add(ParagraphStyle(name="CoverTitle", fontName=F_BOLD, fontSize=26, leading=30, textColor=colors.HexColor("#111827"), alignment=TA_CENTER, spaceAfter=12))
    styles.add(ParagraphStyle(name="Body", fontName=F_REG, fontSize=10, leading=14, textColor=colors.HexColor("#1F2937"), alignment=TA_JUSTIFY, spaceAfter=4))
    styles.add(ParagraphStyle(name="BodySmall", fontName=F_REG, fontSize=9, leading=12, textColor=colors.HexColor("#4B5563"), spaceAfter=4))
    styles.add(ParagraphStyle(name="Meta", fontName=F_REG, fontSize=8.4, leading=10.5, textColor=colors.HexColor("#6B7280"), spaceAfter=4))
    styles.add(ParagraphStyle(name="Caption", fontName=F_OBL, fontSize=9, leading=11.2, textColor=colors.HexColor("#4B5563"), alignment=TA_CENTER, spaceBefore=4, spaceAfter=10))
    styles.add(ParagraphStyle(name="Heading1Custom", fontName=F_BOLD, fontSize=17, leading=21, textColor=_mix_color(accent, 0.42), spaceBefore=6, spaceAfter=10))
    styles.add(ParagraphStyle(name="Heading2Custom", fontName=F_BOLD, fontSize=12.2, leading=15, textColor=colors.HexColor("#111827"), spaceBefore=5, spaceAfter=6))
    styles.add(ParagraphStyle(name="Badge", fontName=F_BOLD, fontSize=8.5, leading=10, alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="CodeBlockCustom", fontName=F_MONO, fontSize=8.3, leading=10.2, textColor=colors.HexColor("#111827"), backColor=colors.HexColor("#F3F4F6"), borderPadding=6, borderColor=colors.HexColor("#E5E7EB"), borderWidth=0.5, spaceBefore=0, spaceAfter=0))
    styles.add(ParagraphStyle(name="EndingTitle", fontName=F_BOLD, fontSize=20, leading=24, textColor=colors.HexColor("#111827"), alignment=TA_CENTER, spaceAfter=10))
    return styles


def _heading(text: str, styles, level: int):
    style = styles["Heading1Custom"] if level == 0 else styles["Heading2Custom"]
    p = Paragraph(text, style)
    p._is_heading = True
    p._heading_level = level
    p._heading_text = text
    return p


def _badge_paragraph(severity: str, styles):
    sev = severity if severity in SEVERITY_COLORS else "Informational"
    return Paragraph(
        f"<font color='white' backcolor='{SEVERITY_COLORS[sev]}'><b>&nbsp;{SEVERITY_SHORT[sev]}&nbsp;</b></font>",
        styles["Badge"],
    )


def _draw_logo_story(report, max_w_mm=24):
    img = _image_from_b64(report.get("logo_b64", ""), max_width_mm=max_w_mm, max_height_mm=max_w_mm) if report.get("logo_b64") else None
    return [img, Spacer(1, 8)] if img else []

def _cover_logo_flowable(report, target_w_mm=174, max_h_mm=42):
    """Provider logo as a wide banner on the cover (aspect preserved, ~725x130)."""
    b64 = report.get("logo_b64", "")
    if not b64:
        return None
    try:
        raw = base64.b64decode(b64)
        img = PILImage.open(BytesIO(raw))
        has_alpha = img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info)
        img = img.convert("RGBA") if has_alpha else (img if img.mode == "RGB" else img.convert("RGB"))
        iw, ih = img.width, img.height
        w_mm = float(target_w_mm)
        h_mm = w_mm * ih / iw
        if h_mm > max_h_mm:
            h_mm = float(max_h_mm)
            w_mm = h_mm * iw / ih
        bio = BytesIO()
        img.save(bio, format="PNG") if has_alpha else img.save(bio, format="JPEG", quality=92)
        bio.seek(0)
        out = RLImage(bio, width=w_mm * mm, height=h_mm * mm)
        out.hAlign = "CENTER"
        return out
    except Exception:
        return None


def _normalize_text(text: str) -> str:
    text = "" if text is None else str(text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("•", "\n- ")
    text = re.sub(r"(?<=[:.])\s+n\s+(?=[A-Z0-9])", "\n- ", text)
    text = re.sub(r"\s+n\s+(?=[A-Z0-9][^\n]{0,60}(?:\n|$))", "\n- ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _paragraph_blocks(text: str):
    text = _normalize_text(text)
    if not text:
        return []
    return [block.strip() for block in re.split(r"\n\s*\n", text) if block.strip()]


def _rich_text_flowables(text: str, styles, style_name="Body"):
    flows = []
    for block in _paragraph_blocks(text):
        lines = [ln.strip() for ln in block.split("\n") if ln.strip()]
        bullet_lines = [ln[2:].strip() for ln in lines if ln.startswith("- ")]
        if bullet_lines and len(bullet_lines) == len(lines):
            for item in bullet_lines:
                flows.append(Paragraph(f"• {_safe_text(item)}", styles[style_name]))
        else:
            safe = "<br/>".join(_safe_text(ln) for ln in lines)
            flows.append(Paragraph(safe, styles[style_name]))
    return flows


def _cover_story(report, styles, summary, report_variant):
    story = [Spacer(1, 20 * mm)]
    _cover_logo = _cover_logo_flowable(report)
    if _cover_logo is not None:
        story += [_cover_logo, Spacer(1, 8 * mm)]
    else:
        story.append(Spacer(1, 8 * mm))
    cover_key = f"cover_kicker_{report_variant if report_variant in {'executive','technical'} else 'combined'}"
    story.append(Paragraph(t(report, cover_key), styles["CoverKicker"]))
    story.append(Paragraph(t(report, "report_title"), styles["CoverTitle"]))

    meta_rows = [
        [Paragraph(f"<b>{t(report,'client')}</b>", styles["BodySmall"]), Paragraph(_safe_text(report.get("client", "N/A")), styles["Body"])],
        [Paragraph(f"<b>{t(report,'project')}</b>", styles["BodySmall"]), Paragraph(_safe_text(report.get("project", "N/A")), styles["Body"])],
        [Paragraph(f"<b>{t(report,'assessment_date')}</b>", styles["BodySmall"]), Paragraph(_safe_text(report.get("date", "N/A")), styles["Body"])],
        [Paragraph(f"<b>{t(report,'version')}</b>", styles["BodySmall"]), Paragraph(_safe_text(report.get("version", "1.0")), styles["Body"])],
        [Paragraph(f"<b>{t(report,'lead_tester')}</b>", styles["BodySmall"]), Paragraph(_safe_text(report.get("tester", "N/A")), styles["Body"])],
    ]
    meta = Table(meta_rows, colWidths=[35 * mm, 95 * mm])
    meta.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#E5E7EB")),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(meta)
    story.append(Spacer(1, 12 * mm))

    snapshot = Table(
        [
            [
                Paragraph("<b>Total Findings</b>", styles["BodySmall"]),
                Paragraph(str(summary["total"]), styles["Heading2Custom"]),
                Paragraph("<b>Highest Severity</b>", styles["BodySmall"]),
                Paragraph(summary["highest_severity"], styles["Heading2Custom"]),
            ],
            [
                Paragraph("<b>Primary Risk Host</b>", styles["BodySmall"]),
                Paragraph(_safe_text(summary["top_host"]), styles["Body"]),
                Paragraph("<b>Evidence Items</b>", styles["BodySmall"]),
                Paragraph(str(summary["evidence_items"]), styles["Body"]),
            ],
        ],
        colWidths=[32 * mm, 38 * mm, 35 * mm, 38 * mm],
    )
    snapshot.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#D1D5DB")),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E5E7EB")),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(snapshot)
    story.append(Spacer(1, 14))
    story.append(Paragraph(t(report, "confidential_note"), styles["Meta"]))
    story.append(NextPageTemplate("Body"))
    story.append(PageBreak())
    return story


def _initial_toc_entries(variant: str, report: dict):
    base = [
        (0, t(report, "legal"), "—"),
        (1, t(report, "conf_statement"), "—"),
        (1, t(report, "disclaimer"), "—"),
        (1, t(report, "contact_info"), "—"),
        (0, t(report, "exec_overview") if variant in {"executive", "combined"} else t(report, "engagement_overview"), "—"),
        (1, t(report, "assessment_details"), "—"),
        (0, t(report, "findings_summary"), "—"),
    ]

    if report.get("include_charts", True):
        base.append((1, t(report, "risk_charts"), "—"))

    base.append((0, t(report, "vuln_by_host", n="4"), "—"))

    if variant == "executive":
        base += [
            (0, t(report, "key_findings"), "—"),
            (0, t(report, "remediation", n="6"), "—"),
        ]
        if report.get("include_compliance", True):
            base.append((0, t(report, "compliance_mapping", n="7"), "—"))
    elif variant in ("combined", "technical") and variant != "executive":
        base.append((0, t(report, "technical_findings", n="5"), "—"))
        base.append((0, t(report, "remediation", n="6"), "—"))
        seq = 6
        if report.get("detailed_walkthrough"):
            seq += 1
            base.append((0, t(report, "walkthrough", n=str(seq)), "—"))
        if report.get("additional_reports"):
            seq += 1
            base.append((0, t(report, "additional_reports", n=str(seq)), "—"))
        if report.get("include_compliance", True):
            seq += 1
            base.append((0, t(report, "compliance_mapping", n=str(seq)), "—"))
    return base


def _toc_leader_style(styles):
    # A single-line dotted leader (no wrap) for the table of contents.
    return ParagraphStyle(
        name="TOCLeader", parent=styles["Meta"],
        wordWrap=None, splitLongWords=False, allowWidows=1, allowOrphans=1,
    )


def _table_of_contents(styles, entries, report):
    rows = []
    for idx, (level, text, page) in enumerate(entries):
        base_style = styles["BodySmall"] if level else styles["Body"]
        toc_style = ParagraphStyle(
            name=f"TOC_{level}_{idx}",
            parent=base_style,
            leftIndent=12 * mm if level else 0,
            spaceAfter=0,
        )
        rows.append([
            Paragraph(_safe_text(text), toc_style),
            Paragraph("." * 28, _toc_leader_style(styles)),
            Paragraph(str(page), styles["BodySmall"]),
        ])
    tbl = Table(rows, colWidths=[126 * mm, 36 * mm, 12 * mm], repeatRows=0)
    tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("ALIGN", (2, 0), (2, -1), "RIGHT"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return [
        _heading(t(report, "table_of_contents"), styles, 0),
        Paragraph(t(report, "toc_note"), styles["Meta"]),
        Spacer(1, 4),
        tbl,
        PageBreak(),
    ]


def _build_risk_matrix(styles, summary, report):
    pr = {
        "Critical": t(report, "priority_critical"),
        "High": t(report, "priority_high"),
        "Moderate": t(report, "priority_moderate"),
        "Low": t(report, "priority_low"),
        "Informational": t(report, "priority_info"),
    }
    rows = [[
        Paragraph(f"<b>{t(report,'severity')}</b>", styles["BodySmall"]),
        Paragraph(f"<b>{t(report,'count')}</b>", styles["BodySmall"]),
        Paragraph(f"<b>{t(report,'priority')}</b>", styles["BodySmall"]),
    ]]
    for sev in SEVERITIES_ORDER:
        rows.append([
            Paragraph(f"<font color='{SEVERITY_COLORS[sev]}'><b>{sev}</b></font>", styles["Body"]),
            Paragraph(str(summary["counts"][sev]), styles["Body"]),
            Paragraph(pr[sev], styles["BodySmall"]),
        ])
    tbl = Table(rows, colWidths=[40 * mm, 20 * mm, 75 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF2F7")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#E2E8F0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("ALIGN", (1, 1), (1, -1), "CENTER"),
    ]))
    return tbl


def _charts_section(report, styles, summary):
    if not report.get("include_charts", True):
        return []

    flows = [_heading(t(report, "risk_charts"), styles, 1)]

    lang = get_language(report)
    sev = _image_from_bytes(severity_distribution_png(summary["counts"], lang), max_width_mm=155, max_height_mm=85)

    if sev:
        flows += [sev, Spacer(1, 4), Paragraph(t(report, "severity_distribution"), styles["Caption"]), Spacer(1, 8)]
    return flows


def _contact_block(report, styles):
    """Structured 1.3 contact block built once from provider/client + role-tagged contacts."""
    contacts = report.get("contacts", []) or []
    provider = str(report.get("provider") or "").strip()
    client = str(report.get("client") or "").strip()
    testers = [c for c in contacts if (c.get("role") or "Tester") != "Client"]
    clients = [c for c in contacts if (c.get("role") or "Tester") == "Client"]

    def person_line(c):
        name = _safe_text(c.get("name", ""))
        title = _safe_text(c.get("title", ""))
        contact = _safe_text(c.get("contact", ""))
        bits = [name]
        if title:
            bits.append(f"({title})")
        if contact:
            bits.append(f"&ndash; {contact}")
        return "&nbsp;&nbsp;&bull; " + " ".join(b for b in bits if b)

    flows = []
    if provider or testers:
        head = f"<b>{t(report,'contact_provider_label')}:</b>"
        if provider:
            head += f" {_safe_text(provider)}"
        flows.append(Paragraph(head, styles["Body"]))
        for c in testers:
            flows.append(Paragraph(person_line(c), styles["BodySmall"]))
        flows.append(Spacer(1, 4))
    if client or clients:
        head = f"<b>{t(report,'contact_client_label')}:</b>"
        if client:
            head += f" {_safe_text(client)}"
        flows.append(Paragraph(head, styles["Body"]))
        for c in clients:
            flows.append(Paragraph(person_line(c), styles["BodySmall"]))
        flows.append(Spacer(1, 4))
    return flows


def _legal_section(report, styles):
    flows = [_heading(t(report, "legal"), styles, 0)]
    sec_10 = _section_value(report, "section_1_0_confidentiality_and_legal", section_default("section_1_0_confidentiality_and_legal", get_language(report)))
    sec_11 = _section_value(report, "section_1_1_confidentiality_statement", section_default("section_1_1_confidentiality_statement", get_language(report)))
    sec_12 = _section_value(report, "section_1_2_disclaimer", section_default("section_1_2_disclaimer", get_language(report)))
    sec_13 = _section_value(report, "section_1_3_contact_information", "")

    flows += _rich_text_flowables(sec_10, styles)
    flows += [Spacer(1, 6), _heading(t(report, "conf_statement"), styles, 1)]
    flows += _rich_text_flowables(sec_11, styles)
    flows += [Spacer(1, 6), _heading(t(report, "disclaimer"), styles, 1)]
    flows += _rich_text_flowables(sec_12, styles)
    flows += [Spacer(1, 6), _heading(t(report, "contact_info"), styles, 1)]

    flows += _contact_block(report, styles)

    if not (report.get("provider") or report.get("client") or (report.get("contacts") or [])):
        flows.append(Paragraph(t(report, "no_contacts"), styles["Body"]))

    flows.append(PageBreak())
    return flows


def _posture_box(report, styles):
    key = RM.posture_key(report)
    if not key:
        return []
    lang = get_language(report)
    label = RM.posture_label(report, lang)
    desc = RM.POSTURE_DESC.get(lang, RM.POSTURE_DESC["en"]).get(key, "")
    bar = _color_bar(f"{t(report,'security_posture_label')}: {label}", RM.posture_color(report), styles)
    flows = [bar, Spacer(1, 3)]
    if desc:
        flows.append(Paragraph(_safe_text(desc), styles["BodySmall"]))
    flows.append(Spacer(1, 8))
    return flows


def _attack_chain_block(report, styles, sub_number="2.2"):
    lang = get_language(report)
    flows = [_heading(f"{sub_number} {t(report, 'attack_path')}", styles, 1)]
    for _para in AC.intro(lang):
        flows += _rich_text_flowables(_para, styles)
    flows.append(Paragraph(f"<b>{_safe_text(AC.stages_title(lang))}</b>", styles["BodySmall"]))
    for _label, _desc in AC.stages(lang):
        flows.append(Paragraph(f"<b>{_safe_text(_label)}:</b> {_safe_text(_desc)}", styles["Body"]))
    flows.append(Paragraph(f"<b>{_safe_text(AC.limitation_title(lang))}</b>", styles["BodySmall"]))
    for _para in AC.limitation(lang):
        flows += _rich_text_flowables(_para, styles)
    return flows


def _methodology_block(report, styles, sub_number="2.2"):
    lang = get_language(report)
    test_type = _safe_text(report.get("test_type") or "Black Box")
    _meth_name = t(report, "sec_methodology", n="2").split(".0", 1)[-1].strip() or "Methodology"
    flows = [_heading(f"{sub_number} {_meth_name}", styles, 1)]
    # intro paragraphs (report override or default)
    for _para in MM.intro(report, lang):
        flows += _rich_text_flowables(_para, styles)
    # legal framework
    flows.append(Paragraph(f"<b>{t(report,'legal_framework')}</b>", styles["BodySmall"]))
    flows += _rich_text_flowables(MM.legal(lang, test_type), styles)
    # standards
    flows.append(Paragraph(f"<b>{t(report,'methodology_standards')}</b>", styles["BodySmall"]))
    flows.append(Paragraph(_safe_text(MM.standards_lead(lang)), styles["BodySmall"]))
    for std in MM.standards(lang):
        flows.append(Paragraph(f"&bull; {_safe_text(std)}", styles["Meta"]))
    # tools
    flows.append(Spacer(1, 3))
    flows.append(Paragraph(f"<b>{t(report,'methodology_tools')}</b>", styles["BodySmall"]))
    for cat, lst in MM.tools(lang):
        flows.append(Paragraph(f"<b>{_safe_text(cat)}:</b> {_safe_text(lst)}", styles["Meta"]))
    # NIS impact scale
    flows.append(Spacer(1, 4))
    flows.append(Paragraph(f"<b>{t(report,'nis_impact_scale')}</b>", styles["BodySmall"]))
    scale = [("Critic", "Risc critic - necesita corectie imediata sau oprirea serviciului."),
             ("Major", "Risc major - necesita corectie pe termen scurt."),
             ("Mediu", "Risc moderat - necesita corectie pe termen mediu."),
             ("Scazut", "Risc scazut - poate necesita corectie.")]
    band = {"Critic": "#A61B1B", "Major": "#D35400", "Mediu": "#B9770E", "Scazut": "#1F618D"}
    rows = [[Paragraph(f"<font color='white'><b>{lvl}</b></font>", styles["Body"]),
             Paragraph(_safe_text(desc), styles["Body"])] for lvl, desc in scale]
    tbl = Table(rows, colWidths=[32 * mm, 124 * mm])
    style_cmds = [("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                  ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
                  ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E7EB")),
                  ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                  ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]
    for i, (lvl, _) in enumerate(scale):
        style_cmds.append(("BACKGROUND", (0, i), (0, i), colors.HexColor(band[lvl])))
    tbl.setStyle(TableStyle(style_cmds))
    flows.extend([tbl, Spacer(1, 8)])
    return flows


def _status_overview_table(report, styles):
    findings = _findings_sorted(report)
    if not findings:
        return []
    lang = get_language(report)
    flows = [_heading("3.1 " + t(report, "status_table_title"), styles, 1)]
    header = [Paragraph(f"<b>{t(report,'col_num')}</b>", styles["BodySmall"]),
              Paragraph(f"<b>{t(report,'compliance_col_finding')}</b>", styles["BodySmall"]),
              Paragraph(f"<b>{t(report,'col_location')}</b>", styles["BodySmall"]),
              Paragraph(f"<b>{t(report,'col_state')}</b>", styles["BodySmall"]),
              Paragraph(f"<b>{t(report,'col_comments')}</b>", styles["BodySmall"]),
              Paragraph(f"<b>{t(report,'col_updated')}</b>", styles["BodySmall"])]
    data = [header]
    for idx, f in enumerate(findings, start=1):
        locs = _meta_values(f, "hosts", "host")
        state = RM.status_label(f, lang)
        state_col = RM.status_color(f)
        data.append([
            Paragraph(str(idx), styles["Meta"]),
            Paragraph(_safe_text(f.get("title") or "-"), styles["Meta"]),
            Paragraph(_safe_text(", ".join(locs)), styles["Meta"]),
            Paragraph(f"<font color='{state_col}'><b>{_safe_text(state)}</b></font>", styles["Meta"]),
            Paragraph(_safe_text(f.get("status_note") or ""), styles["Meta"]),
            Paragraph(_safe_text(f.get("status_date") or ""), styles["Meta"]),
        ])
    tbl = Table(data, colWidths=[8 * mm, 58 * mm, 34 * mm, 24 * mm, 20 * mm, 22 * mm], repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF2F7")),
        ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E7EB")),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    flows.extend([tbl, Spacer(1, 10)])
    return flows


def _overview_section(report, styles, summary, variant):
    title = t(report, "exec_overview") if variant in {"executive", "combined"} else t(report, "engagement_overview")
    flows = [_heading(title, styles, 0)]
    overview_text = (report.get("executive_summary") or report.get("assessment_overview")
                     or executive_narrative(report, summary["findings"], get_language(report)))
    flows += _rich_text_flowables(overview_text, styles)
    flows += _posture_box(report, styles)
    flows.extend([
        Spacer(1, 4),
        _build_risk_matrix(styles, summary, report),
        Spacer(1, 8),
        _heading(t(report, "assessment_details"), styles, 1),
    ])
    for label, key in [
        (t(report, "label_assessment_overview"), "assessment_overview"),
        (t(report, "label_assessment_details"), "assessment_details"),
        (t(report, "label_scope"), "scope"),
        (t(report, "label_scope_exclusions"), "scope_exclusions"),
        (t(report, "label_client_allowances"), "client_allowances"),
    ]:
        value = report.get(key, "")
        if value:
            flows.append(Paragraph(f"<b>{_safe_text(label)}</b>", styles["BodySmall"]))
            flows += _rich_text_flowables(value, styles)

    flows += _attack_chain_block(report, styles, "2.2")
    flows += _methodology_block(report, styles, "2.3")
    return flows


def _findings_summary_section(styles, summary, report):
    grouped = {sev: [] for sev in SEVERITIES_ORDER}
    for item in summary["findings"]:
        sev = item.get("severity", "Informational")
        if sev not in grouped:
            sev = "Informational"
        grouped[sev].append(item.get("title") or "Untitled finding")

    rows = [[
        Paragraph(f"<b>{t(report,'severity')}</b>", styles["BodySmall"]),
        Paragraph(f"<b>{t(report,'count')}</b>", styles["BodySmall"]),
        Paragraph(f"<b>{t(report,'col_themes')}</b>", styles["BodySmall"]),
    ]]
    for sev in SEVERITIES_ORDER:
        rows.append([
            Paragraph(f"<font color='{SEVERITY_COLORS[sev]}'><b>{sev}</b></font>", styles["Body"]),
            Paragraph(str(summary["counts"][sev]), styles["Body"]),
            Paragraph(_safe_text("; ".join(grouped[sev][:2]) or "—"), styles["BodySmall"]),
        ])
    tbl = Table(rows, colWidths=[34 * mm, 18 * mm, 83 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF2F7")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#E2E8F0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("ALIGN", (1, 1), (1, -1), "CENTER"),
    ]))
    flows = [_heading(t(report, "findings_summary"), styles, 0), tbl, Spacer(1, 8)]
    flows += _status_overview_table(report, styles)
    return flows


def _vulnerabilities_by_host_section(report, styles, section_number="4"):
    findings = _findings_sorted(report)
    grouped: dict[str, list[dict]] = defaultdict(list)

    for finding in findings:
        hosts = _meta_values(finding, "hosts", "host")
        if not hosts:
            hosts = ["Unknown"]
        for host in hosts:
            grouped[host].append(finding)

    flows = [_heading(t(report, "vuln_by_host", n=section_number), styles, 0)]

    if not grouped:
        flows.append(Paragraph(t(report, "no_host_data"), styles["Body"]))
        return flows

    for idx, host in enumerate(sorted(grouped.keys()), start=1):
        flows.append(_heading(f"{section_number}.{idx} {host}", styles, 1))

        rows = [[
            Paragraph(f"<b>{t(report,'col_title')}</b>", styles["BodySmall"]),
            Paragraph(f"<b>{t(report,'severity')}</b>", styles["BodySmall"]),
            Paragraph(f"<b>{t(report,'col_ports')}</b>", styles["BodySmall"]),
            Paragraph("<b>CVSS</b>", styles["BodySmall"]),
        ]]

        for finding in grouped[host]:
            ports = _meta_values(finding, "ports", "port")
            rows.append([
                Paragraph(_safe_text(finding.get("title") or "Untitled finding"), styles["Body"]),
                Paragraph(_safe_text(finding.get("severity") or "Informational"), styles["Body"]),
                Paragraph(_safe_text(", ".join(ports) if ports else "—"), styles["Body"]),
                Paragraph(_safe_text(finding.get("cvss") or "—"), styles["Body"]),
            ])

        tbl = Table(rows, colWidths=[88 * mm, 24 * mm, 34 * mm, 18 * mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF2F7")),
            ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
            ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E7EB")),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        flows.extend([tbl, Spacer(1, 8)])

    return flows


def _color_bar(text, hexcolor, styles):
    p = Paragraph(f"<font color='white'><b>{text}</b></font>", styles["BodySmall"])
    tbl = Table([[p]], colWidths=[130 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(hexcolor)),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return tbl


def _finding_card(finding: dict, styles, report):
    sev = finding.get("severity", "Informational")
    if sev not in SEVERITY_COLORS:
        sev = "Informational"

    badge_tbl = Table(
        [[_badge_paragraph(sev, styles), Paragraph(f"<b>{_safe_text(sev)} severity</b>", styles["BodySmall"])]],
        colWidths=[18 * mm, 46 * mm],
    )
    badge_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#E5E7EB")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))

    content = [badge_tbl, Spacer(1, 4)]
    lang = get_language(report)

    # --- NIS coloured bars: Impact x Exploitability = Risk, Status ---
    expl = RM.exploit_label(finding, lang)
    if expl:
        content.append(Paragraph(f"<b>{t(report, 'lbl_impact_nis')}</b>", styles["BodySmall"]))
        content.append(_color_bar(f"{sev} &times; {_safe_text(expl)} = {sev}", SEVERITY_COLORS[sev], styles))
        content.append(Spacer(1, 3))
    content.append(Paragraph(f"<b>{t(report, 'lbl_status')}</b>", styles["BodySmall"]))
    _st_extra = _safe_text(finding.get("status_note") or finding.get("status_date") or "")
    content.append(_color_bar(
        RM.status_label(finding, lang) + (f" &ndash; {_st_extra}" if _st_extra else ""),
        RM.status_color(finding), styles))
    content.append(Spacer(1, 3))

    # Severity + CVSS score + vector
    _sev_bits = []
    if finding.get("cvss"):
        _sev_bits.append(_safe_text(finding.get("cvss")))
    _sev_bits.append(_safe_text(sev))
    if finding.get("cvss_vector"):
        _sev_bits.append(_safe_text(finding.get("cvss_vector")))
    content.append(Paragraph(f"<b>{t(report, 'severity')}:</b> " + " - ".join(_sev_bits), styles["Meta"]))
    _locs = _meta_values(finding, "hosts", "host")
    if _locs:
        content.append(Paragraph(f"<b>{t(report, 'lbl_location')}:</b> " + _safe_text(", ".join(_locs)), styles["Meta"]))
    content.append(Spacer(1, 3))

    meta = []
    hosts = _meta_values(finding, "hosts", "host")
    ports = _meta_values(finding, "ports", "port")
    cves = _meta_values(finding, "cves", "cve")
    cwes = _meta_values(finding, "cwes", "cwe")

    if hosts:
        meta.append(f"<b>Hosts:</b> {_safe_text(', '.join(hosts))}")
    if ports:
        meta.append(f"<b>Ports:</b> {_safe_text(', '.join(ports))}")
    if cves:
        meta.append(f"<b>CVEs:</b> {_safe_text(', '.join(cves))}")
    if cwes:
        meta.append(f"<b>CWEs:</b> {_safe_text(', '.join(cwes))}")

    for label, key in [("Protocol", "protocol")]:
        if finding.get(key):
            meta.append(f"<b>{label}:</b> {_safe_text(finding.get(key))}")

    if meta:
        content.append(Paragraph(" | ".join(meta), styles["Meta"]))

    for label_key, key in [
        ("description", "description"),
        ("likelihood", "likelihood"),
        ("impact", "impact"),
        ("tools_used", "tools_used"),
        ("recommendation", "recommendation"),
        ("references", "references"),
    ]:
        if finding.get(key):
            content.append(Paragraph(f"<b>{t(report, label_key)}</b>", styles["BodySmall"]))
            content.extend(_rich_text_flowables(finding.get(key), styles))

    if finding.get("code"):
        code_lines = _normalize_text(finding.get("code")).split("\n")
        content.append(Paragraph(f"<b>{t(report, 'evidence_output')}</b>", styles["BodySmall"]))
        content.append(Spacer(1, 8))
        content.append(Paragraph("<br/>".join(_safe_text(line) for line in code_lines), styles["CodeBlockCustom"]))
        content.append(Spacer(1, 14))

    for image_item in normalize_images(finding.get("images"), default_prefix=finding.get("title") or "Finding"):
        img = _image_from_b64(image_item["data"])
        if img:
            content.append(img)
            if image_item.get("name"):
                content.append(Spacer(1, 7))
                content.append(Paragraph(_safe_text(image_item["name"]), styles["Caption"]))
            content.append(Spacer(1, 12))

    content.append(Spacer(1, 14))
    return content


def _key_findings_section(styles, summary, report, section_number="5"):
    flows = [_heading(t(report, "key_findings"), styles, 0)]
    for idx, finding in enumerate(summary["findings"][: min(6, len(summary["findings"]))], start=1):
        flows.append(_heading(f"{section_number}.{idx} {finding.get('title') or 'Untitled finding'}", styles, 1))
        flows.extend(_finding_card(finding, styles, report))
    return flows


def _technical_findings_section(styles, summary, report, section_number="5"):
    flows = [_heading(t(report, "technical_findings", n=section_number), styles, 0)]
    for idx, finding in enumerate(summary["findings"], start=1):
        flows.append(_heading(f"{section_number}.{idx} {finding.get('title') or 'Untitled finding'}", styles, 1))
        flows.extend(_finding_card(finding, styles, report))
    return flows


def _bullet_list(items, styles, report):
    return [Paragraph(f"• {_safe_text(item)}", styles["Body"]) for item in items] if items else [Paragraph(t(report, "no_items"), styles["Body"])]


def _remediation_section(report, styles, section_prefix="6"):
    flows = [_heading(t(report, "remediation", n=section_prefix), styles, 0)]
    for head, items in [
        (t(report, "short_term", n=section_prefix), report.get("remediation_short", [])),
        (t(report, "medium_term", n=section_prefix), report.get("remediation_medium", [])),
        (t(report, "long_term", n=section_prefix), report.get("remediation_long", [])),
    ]:
        flows.append(_heading(head, styles, 1))
        flows += _bullet_list(items, styles, report)
        flows.append(Spacer(1, 4))
    return flows


def _walkthrough_section(report, styles, section_prefix="7"):
    steps = report.get("detailed_walkthrough", []) or []
    if not steps:
        return []

    flows = [_heading(t(report, "walkthrough", n=section_prefix), styles, 0)]
    for idx, step in enumerate(steps, start=1):
        title = step.get("name") or step.get("title") or f"Step {idx}"
        flows.append(_heading(f"{section_prefix}.{idx} {title}", styles, 1))
        if step.get("description"):
            flows += [Paragraph(f"<b>{t(report,'description')}</b>", styles["BodySmall"])]
            flows.extend(_rich_text_flowables(step.get("description"), styles))
        if step.get("code"):
            flows += [
                Paragraph(f"<b>{t(report,'command_output')}</b>", styles["BodySmall"]),
                Spacer(1, 8),
                Paragraph("<br/>".join(_safe_text(line) for line in _normalize_text(step.get("code")).split("\n")), styles["CodeBlockCustom"]),
                Spacer(1, 14),
            ]
        for image_item in normalize_images(step.get("images"), default_prefix=title):
            img = _image_from_b64(image_item["data"])
            if img:
                flows.append(img)
                if image_item.get("name"):
                    flows += [Spacer(1, 7), Paragraph(_safe_text(image_item["name"]), styles["Caption"])]
                flows.append(Spacer(1, 12))
        flows.append(Spacer(1, 10))
    return flows


def _additional_reports_section(report, styles, section_prefix="8"):
    extras = report.get("additional_reports", []) or []
    if not extras:
        return []

    flows = [_heading(t(report, "additional_reports", n=section_prefix), styles, 0)]
    for idx, extra in enumerate(extras, start=1):
        title = extra.get("name") or extra.get("title") or f"Additional Report {idx}"
        flows.append(_heading(f"{section_prefix}.{idx} {title}", styles, 1))
        if extra.get("description"):
            flows.extend(_rich_text_flowables(extra.get("description"), styles))
        if extra.get("code"):
            flows += [
                Paragraph(f"<b>{t(report,'output')}</b>", styles["BodySmall"]),
                Spacer(1, 8),
                Paragraph("<br/>".join(_safe_text(line) for line in _normalize_text(extra.get("code")).split("\n")), styles["CodeBlockCustom"]),
                Spacer(1, 14),
            ]
        for image_item in normalize_images(extra.get("images"), default_prefix=title):
            img = _image_from_b64(image_item["data"])
            if img:
                flows.append(img)
                if image_item.get("name"):
                    flows += [Spacer(1, 7), Paragraph(_safe_text(image_item["name"]), styles["Caption"])]
                flows.append(Spacer(1, 12))
        flows.append(Spacer(1, 10))
    return flows


def _compliance_section(report, styles, summary, section_prefix="9"):
    if not report.get("include_compliance", True):
        return []
    fw = CM.report_frameworks(report)
    rows = CM.report_rows(report)
    heading = t(report, "compliance_mapping", n=section_prefix)
    if fw:
        heading += " (" + " / ".join(label for _, label in fw) + ")"
    flows = [_heading(heading, styles, 0)]
    flows.append(Paragraph(t(report, "compliance_intro"), styles["BodySmall"]))
    flows.append(Spacer(1, 6))
    if not rows or not fw:
        flows.append(Paragraph(t(report, "compliance_none"), styles["Body"]))
        return flows

    header = [
        Paragraph(f"<b>{t(report,'compliance_col_finding')}</b>", styles["BodySmall"]),
        Paragraph(f"<b>{t(report,'severity')}</b>", styles["BodySmall"]),
        Paragraph(f"<b>{t(report,'compliance_col_category')}</b>", styles["BodySmall"]),
    ] + [Paragraph(f"<b>{_safe_text(label)}</b>", styles["BodySmall"]) for _, label in fw]
    data = [header]
    for r in rows:
        sev = r["severity"] if r["severity"] in SEVERITY_COLORS else "Informational"
        data.append([
            Paragraph(_safe_text(r["title"]), styles["BodySmall"]),
            Paragraph(f"<font color='{SEVERITY_COLORS[sev]}'><b>{_safe_text(r['severity'])}</b></font>", styles["BodySmall"]),
            Paragraph(_safe_text(r["category"]), styles["BodySmall"]),
        ] + [Paragraph(_safe_text(r["controls"].get(k, "")), styles["BodySmall"]) for k, _ in fw])
    fixed = [30 * mm, 13 * mm, 26 * mm]
    each = (105 * mm) / max(1, len(fw))
    tbl = Table(data, colWidths=fixed + [each] * len(fw), repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF2F7")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E2E8F0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    flows.extend([tbl, Spacer(1, 10)])

    legend = CM.used_controls(report)
    if legend:
        flows.append(_heading(t(report, "control_legend"), styles, 1))
        for label, items in legend:
            flows.append(Paragraph(f"<b>{_safe_text(label)}</b>", styles["BodySmall"]))
            for cid, title in items:
                flows.append(Paragraph(f"{_safe_text(cid)} &mdash; {_safe_text(title)}", styles["Meta"]))
            flows.append(Spacer(1, 5))
    return flows

    sel = set(selected_frameworks(report))
    cov = coverage_summary(rows)
    if "nis2" in sel and cov["nis2_articles"]:
        flows.append(Paragraph(
            f"<b>{t(report,'compliance_coverage')}:</b> NIS2 " + ", ".join(cov["nis2_articles"]),
            styles["Meta"]))
        flows.append(Spacer(1, 6))

    header = [
        Paragraph(f"<b>{t(report,'compliance_col_finding')}</b>", styles["BodySmall"]),
        Paragraph(f"<b>{t(report,'severity')}</b>", styles["BodySmall"]),
        Paragraph(f"<b>{t(report,'compliance_col_category')}</b>", styles["BodySmall"]),
    ] + [Paragraph(f"<b>{t(report, hk)}</b>", styles["BodySmall"]) for hk, _, _ in fw_cols]
    data = [header]
    for r in rows:
        sev = r["severity"] if r["severity"] in SEVERITY_COLORS else "Informational"
        data.append([
            Paragraph(_safe_text(r["title"]), styles["Body"]),
            Paragraph(f"<font color='{SEVERITY_COLORS[sev]}'><b>{_safe_text(r['severity'])}</b></font>", styles["Body"]),
            Paragraph(_safe_text(r["category"]), styles["BodySmall"]),
        ] + [Paragraph(_safe_text(r.get(field, "")), styles["BodySmall"]) for _, field, _ in fw_cols])
    fixed = [40*mm, 16*mm, 34*mm]
    remaining = 84 * mm
    each = remaining / max(1, len(fw_cols))
    tbl = Table(data, colWidths=fixed + [each] * len(fw_cols), repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF2F7")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E2E8F0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    flows.extend([tbl, Spacer(1, 10)])
    return flows

    cov = coverage_summary(rows)
    if cov["nis2_articles"]:
        flows.append(Paragraph(
            f"<b>{t(report,'compliance_coverage')}:</b> NIS2 " + ", ".join(cov["nis2_articles"])
            + " &middot; IEC 62443-3-3 " + ", ".join(cov["iec_requirements"]),
            styles["Meta"]))
        flows.append(Spacer(1, 6))

    header = [
        Paragraph(f"<b>{t(report,'compliance_col_finding')}</b>", styles["BodySmall"]),
        Paragraph(f"<b>{t(report,'severity')}</b>", styles["BodySmall"]),
        Paragraph(f"<b>{t(report,'compliance_col_category')}</b>", styles["BodySmall"]),
        Paragraph(f"<b>{t(report,'compliance_col_nis2')}</b>", styles["BodySmall"]),
        Paragraph(f"<b>{t(report,'compliance_col_iec')}</b>", styles["BodySmall"]),
        Paragraph(f"<b>{t(report,'compliance_col_nist')}</b>", styles["BodySmall"]),
    ]
    data = [header]
    for r in rows:
        sev = r["severity"] if r["severity"] in SEVERITY_COLORS else "Informational"
        data.append([
            Paragraph(_safe_text(r["title"]), styles["Body"]),
            Paragraph(f"<font color='{SEVERITY_COLORS[sev]}'><b>{_safe_text(r['severity'])}</b></font>", styles["Body"]),
            Paragraph(_safe_text(r["category"]), styles["BodySmall"]),
            Paragraph(_safe_text(r["nis2"]), styles["BodySmall"]),
            Paragraph(_safe_text(r["iec62443"]), styles["BodySmall"]),
            Paragraph(_safe_text(r["nist"]), styles["BodySmall"]),
        ])
    tbl = Table(data, colWidths=[40*mm, 16*mm, 34*mm, 22*mm, 30*mm, 32*mm], repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF2F7")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E2E8F0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    flows.extend([tbl, Spacer(1, 10)])
    return flows


def _closing_page(report, styles):
    center_meta = ParagraphStyle(name="EndingMetaCenter", parent=styles["Meta"], alignment=TA_CENTER)
    center_body = ParagraphStyle(name="EndingBodyCenter", parent=styles["BodySmall"], alignment=TA_CENTER)
    story = [PageBreak(), Spacer(1, 78 * mm)]
    if report.get("logo_b64"):
        img = _image_from_b64(report.get("logo_b64"), max_width_mm=30, max_height_mm=30)
        if img:
            story += [img, Spacer(1, 8)]
    story.append(Paragraph(t(report, "end_of_report"), styles["EndingTitle"]))
    story.append(Paragraph(t(report, "last_page"), center_meta))
    story.append(Paragraph(t(report, "closing_text"), center_body))
    return story


def _story(report: dict, variant: str, toc_entries):
    summary = _compute_summary(report)
    styles = _build_styles(report.get("theme_hex", "#ED863D"))
    story = []

    story += _cover_story(report, styles, summary, variant)
    story += _table_of_contents(styles, toc_entries, report)
    story += _legal_section(report, styles)
    story += _overview_section(report, styles, summary, variant)
    story += _findings_summary_section(styles, summary, report)
    story += _charts_section(report, styles, summary)
    story += _vulnerabilities_by_host_section(report, styles, section_number="4")

    if variant in ("technical", "combined"):
        story += _technical_findings_section(styles, summary, report, section_number="5")
        story += _remediation_section(report, styles, section_prefix="6")
        seq = 6
        if report.get("detailed_walkthrough"):
            seq += 1
            story += _walkthrough_section(report, styles, section_prefix=str(seq))
        if report.get("additional_reports"):
            seq += 1
            story += _additional_reports_section(report, styles, section_prefix=str(seq))
        if report.get("include_compliance", True):
            seq += 1
            story += _compliance_section(report, styles, summary, section_prefix=str(seq))
    else:  # executive
        story += _key_findings_section(styles, summary, report, section_number="5")
        story += _remediation_section(report, styles, section_prefix="6")
        if report.get("include_compliance", True):
            story += _compliance_section(report, styles, summary, section_prefix="7")

    story += _closing_page(report, styles)
    return story


def _build_pdf(report: dict, variant: str, toc_entries):
    buffer = BytesIO()
    accent = _hex_to_color(report.get("theme_hex", "#ED863D"))
    doc = PentestDocTemplate(
        buffer,
        report=report,
        report_variant=variant,
        accent_color=accent,
        watermark_enabled=bool(report.get("watermark_enabled", False)),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=22 * mm,
        bottomMargin=16 * mm,
        title=f"{report.get('client','Client')} {variant.title()} Pentest Report",
        author=report.get("tester") or "Penetration Testing Team",
    )
    doc.build(_story(report, variant, toc_entries))
    return buffer.getvalue(), doc.heading_log


def _heading_entries_from_log(log):
    return [
        (level, text, page)
        for level, text, page in log
        if text != t("en", "table_of_contents") and text != t("ro", "table_of_contents")
    ]


def generate_pdf_bytes(report: dict, report_variant: str = "technical") -> bytes:
    variant = (report_variant or "technical").lower()
    if variant not in {"technical", "executive", "combined"}:
        variant = "technical"

    current = _initial_toc_entries(variant, report)
    final_pdf = b""

    for _ in range(4):
        final_pdf, heading_log = _build_pdf(report, variant, current)
        updated = _heading_entries_from_log(heading_log)
        if updated == current:
            break
        current = updated

    final_pdf, _ = _build_pdf(report, variant, current)
    return final_pdf