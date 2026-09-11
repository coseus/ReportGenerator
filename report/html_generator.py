from __future__ import annotations

from collections import Counter

from jinja2 import Template

from util.charting import png_bytes_to_b64, risk_trend_png, severity_distribution_png
from util.helpers import normalize_images
from util.i18n import get_language, t
from util import control_mapper as CM
from util import methodology as MM
from util import attack_chain as AC
from util import report_meta as RM
from util.narrative import executive_narrative

HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{{ title }}</title>
  <style>
    body{
      font-family: Arial, sans-serif;
      margin: 30px;
      color: #1f2937;
      line-height: 1.55;
    }
    h1,h2,h3,h4{
      color:#111827;
      margin-top: 24px;
      margin-bottom: 12px;
    }
    .meta{
      color:#6b7280;
      margin-bottom: 18px;
    }
    .card{
      border:1px solid #d1d5db;
      border-radius:8px;
      padding:14px;
      margin:14px 0;
      background:#fff;
    }
    .badge{
      display:inline-block;
      padding:4px 8px;
      border-radius:999px;
      color:white;
      font-weight:bold;
      font-size:12px;
      margin-bottom: 10px;
    }
    .imgcap{
      text-align:center;
      color:#4b5563;
      font-style:italic;
      margin-top:8px;
      margin-bottom:16px;
    }
    img{
      max-width:100%;
      height:auto;
      border:1px solid #e5e7eb;
      border-radius:6px;
      display:block;
      margin-top:10px;
      margin-bottom:0;
    }
    .grid{
      display:grid;
      grid-template-columns:1fr 1fr;
      gap:18px;
    }
    .toc{
      padding-left: 22px;
    }
    .toc li{
      margin:4px 0;
    }
    .section-text{
      white-space: pre-wrap;
    }
    .label{
      font-weight:bold;
    }
    .block-title{
      font-weight:bold;
      margin-top:12px;
      margin-bottom:6px;
    }
    .code{
      white-space: pre-wrap;
      background:#f3f4f6;
      border:1px solid #e5e7eb;
      border-radius:6px;
      padding:10px;
      font-family: Consolas, monospace;
      font-size: 12px;
      margin-top:8px;
      margin-bottom:16px;
    }
    .kv{
      margin:4px 0;
    }
    .list{
      margin: 8px 0 12px 20px;
    }
  </style>
</head>
<body>
  {% if logo_b64 %}
  <img src="data:image/png;base64,{{ logo_b64 }}" alt="logo" style="display:block;width:725px;max-width:100%;height:auto;margin:0 auto 18px">
  {% endif %}
  <h1>{{ report_title }}</h1>
  <p class="meta">{{ provider_or_client }} · {{ project }}</p>

  <div class="card">
    <div><span class="label">{{ t_client }}:</span> {{ client }}</div>
    <div><span class="label">{{ t_project }}:</span> {{ project }}</div>
    <div><span class="label">{{ t_date }}:</span> {{ date }}</div>
    <div><span class="label">{{ t_version }}:</span> {{ version }}</div>
    <div><span class="label">{{ t_tester }}:</span> {{ tester }}</div>
  </div>

  <h2>{{ toc }}</h2>
  <ol class="toc">
    {% for item in toc_items %}
      <li>{{ item }}</li>
    {% endfor %}
  </ol>

  <h2>{{ legal_title }}</h2>
  <div class="card section-text">{{ legal_text }}</div>

  <h3>{{ conf_statement_title }}</h3>
  <div class="card section-text">{{ conf_statement_text }}</div>

  <h3>{{ disclaimer_title }}</h3>
  <div class="card section-text">{{ disclaimer_text }}</div>

  <h3>{{ contact_info_title }}</h3>
  {% if provider_company or provider_people or client_company or client_people %}
    <div class="card">
      {% if provider_company or provider_people %}
        <div class="kv"><span class="label">{{ contact_provider_label }}:</span> {{ provider_company }}</div>
        {% for c in provider_people %}<div class="kv" style="margin-left:16px">• {{ c }}</div>{% endfor %}
      {% endif %}
      {% if client_company or client_people %}
        <div class="kv" style="margin-top:8px"><span class="label">{{ contact_client_label }}:</span> {{ client_company }}</div>
        {% for c in client_people %}<div class="kv" style="margin-left:16px">• {{ c }}</div>{% endfor %}
      {% endif %}
    </div>
  {% endif %}

  <h2>{{ overview_title }}</h2>
  <div class="card section-text">{{ executive_summary }}</div>
  {% if posture_label_val %}
    <div style="background:{{ posture_color_val }};color:#fff;font-weight:bold;padding:8px 12px;border-radius:6px;margin:10px 0">{{ security_posture_label_txt }}: {{ posture_label_val }}</div>
    {% if posture_desc_val %}<div class="meta">{{ posture_desc_val }}</div>{% endif %}
  {% endif %}

  <h3>{{ assessment_details_title }}</h3>
  <div class="card">
    {% if assessment_overview %}
      <div class="block-title">{{ label_assessment_overview }}</div>
      <div class="section-text">{{ assessment_overview }}</div>
    {% endif %}
    {% if assessment_details %}
      <div class="block-title">{{ label_assessment_details }}</div>
      <div class="section-text">{{ assessment_details }}</div>
    {% endif %}
    {% if scope %}
      <div class="block-title">{{ label_scope }}</div>
      <div class="section-text">{{ scope }}</div>
    {% endif %}
    {% if scope_exclusions %}
      <div class="block-title">{{ label_scope_exclusions }}</div>
      <div class="section-text">{{ scope_exclusions }}</div>
    {% endif %}
    {% if client_allowances %}
      <div class="block-title">{{ label_client_allowances }}</div>
      <div class="section-text">{{ client_allowances }}</div>
    {% endif %}
  </div>

  <h2>{{ attack_path_title }}</h2>
  <div class="card">
    {% for para in attack_intro %}<div class="section-text">{{ para }}</div>{% endfor %}
    <div class="block-title">{{ attack_stages_title }}</div>
    <ul class="list">{% for label, desc in attack_stages %}<li><b>{{ label }}:</b> {{ desc }}</li>{% endfor %}</ul>
    <div class="block-title">{{ attack_limitation_title }}</div>
    {% for para in attack_limitation %}<div class="section-text">{{ para }}</div>{% endfor %}
  </div>

  <h2>{{ methodology_title }}</h2>
  <div class="card">
    {% for para in methodology_intro %}<div class="section-text">{{ para }}</div>{% endfor %}
    <div class="block-title">{{ legal_framework_label }}</div>
    <div class="section-text">{{ methodology_legal }}</div>
    <div class="block-title">{{ methodology_standards_label }}</div>
    <div class="section-text">{{ methodology_standards_lead }}</div>
    <ul class="list">{% for s in methodology_standards %}<li>{{ s }}</li>{% endfor %}</ul>
    <div class="block-title">{{ methodology_tools_label }}</div>
    <ul class="list">{% for cat, lst in methodology_tools %}<li><b>{{ cat }}:</b> {{ lst }}</li>{% endfor %}</ul>
    <div class="block-title">{{ nis_impact_scale_label }}</div>
    <table style="border-collapse:collapse;font-size:15px;width:100%">
      {% for lvl, col, desc in nis_impact_scale %}
      <tr><td style="background:{{ col }};color:#fff;font-weight:bold;padding:9px 14px;white-space:nowrap">{{ lvl }}</td><td style="border:1px solid #e5e7eb;padding:9px 14px">{{ desc }}</td></tr>
      {% endfor %}
    </table>
  </div>

  <h2>{{ findings_summary }}</h2>
  <div class="card">
    {% for row in severity_rows %}
      <div class="kv"><span class="label">{{ row.severity }}:</span> {{ row.count }}</div>
    {% endfor %}
  </div>
  {% if status_rows %}
    <h3>{{ status_table_title }}</h3>
    <table style="border-collapse:collapse;width:100%;font-size:12px">
      <thead><tr style="background:#eef2f7">
        <th style="border:1px solid #cbd5e1;padding:6px">#</th>
        <th style="border:1px solid #cbd5e1;padding:6px;text-align:left">{{ t_col_finding }}</th>
        <th style="border:1px solid #cbd5e1;padding:6px;text-align:left">{{ t_col_location }}</th>
        <th style="border:1px solid #cbd5e1;padding:6px">{{ t_col_state }}</th>
        <th style="border:1px solid #cbd5e1;padding:6px;text-align:left">{{ t_col_comments }}</th>
        <th style="border:1px solid #cbd5e1;padding:6px">{{ t_col_updated }}</th>
      </tr></thead>
      <tbody>
        {% for r in status_rows %}
        <tr>
          <td style="border:1px solid #e5e7eb;padding:6px;text-align:center">{{ r.num }}</td>
          <td style="border:1px solid #e5e7eb;padding:6px">{{ r.title }}</td>
          <td style="border:1px solid #e5e7eb;padding:6px">{{ r.location }}</td>
          <td style="border:1px solid #e5e7eb;padding:6px;color:{{ r.state_color }};font-weight:bold;text-align:center">{{ r.state }}</td>
          <td style="border:1px solid #e5e7eb;padding:6px">{{ r.comments }}</td>
          <td style="border:1px solid #e5e7eb;padding:6px;text-align:center">{{ r.updated }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  {% endif %}

  {% if include_charts %}
    <h3>{{ risk_charts }}</h3>
    <div class="grid">
      <div class="card">
        <img src="data:image/png;base64,{{ severity_chart }}">
        <div class="imgcap">{{ severity_distribution }}</div>
      </div>
    </div>
  {% endif %}

  {% if technical_findings %}
    <h2>{{ technical_findings_title }}</h2>
    {% for finding in technical_findings %}
      <div class="card">
        <h3>{{ finding.number }} {{ finding.title }}</h3>
        <span class="badge" style="background:{{ finding.color }}">{{ finding.severity }}</span>
        {% if finding.exploit_label %}
          <div class="block-title">{{ lbl_impact_nis }}</div>
          <div style="background:{{ finding.color }};color:#fff;font-weight:bold;padding:5px 9px;border-radius:4px;margin:4px 0">{{ finding.severity }} × {{ finding.exploit_label }} = {{ finding.severity }}</div>
        {% endif %}
        <div class="block-title">{{ lbl_status }}</div>
        <div style="background:{{ finding.status_color }};color:#fff;font-weight:bold;padding:5px 9px;border-radius:4px;margin:4px 0">{{ finding.status_full }}</div>
        <div class="kv"><b>{{ t_severity }}:</b> {{ finding.sev_bits }}</div>
        {% if finding.locations %}<div class="kv"><b>{{ lbl_location }}:</b> {{ finding.locations }}</div>{% endif %}

        {% if finding.meta_lines %}
          {% for line in finding.meta_lines %}
            <div class="kv">{{ line }}</div>
          {% endfor %}
        {% endif %}

        {% if finding.description %}
          <div class="block-title">{{ desc }}</div>
          <div class="section-text">{{ finding.description }}</div>
        {% endif %}

        {% if finding.likelihood %}
          <div class="block-title">{{ likelihood }}</div>
          <div class="section-text">{{ finding.likelihood }}</div>
        {% endif %}

        {% if finding.impact %}
          <div class="block-title">{{ impact }}</div>
          <div class="section-text">{{ finding.impact }}</div>
        {% endif %}

        {% if finding.tools_used %}
          <div class="block-title">{{ tools_used }}</div>
          <div class="section-text">{{ finding.tools_used }}</div>
        {% endif %}

        {% if finding.recommendation %}
          <div class="block-title">{{ recommendation }}</div>
          <div class="section-text">{{ finding.recommendation }}</div>
        {% endif %}

        {% if finding.references %}
          <div class="block-title">{{ references }}</div>
          <div class="section-text">{{ finding.references }}</div>
        {% endif %}

        {% if finding.code %}
          <div class="block-title">{{ evidence_output }}</div>
          <div class="code">{{ finding.code }}</div>
        {% endif %}

        {% for img in finding.images %}
          <img src="data:image/png;base64,{{ img.data }}">
          {% if img.name %}
            <div class="imgcap">{{ img.name }}</div>
          {% endif %}
        {% endfor %}
      </div>
    {% endfor %}
  {% endif %}

  {% if walkthrough %}
    <h2>{{ walkthrough_title }}</h2>
    {% for step in walkthrough %}
      <div class="card">
        <h3>{{ step.number }} {{ step.title }}</h3>

        {% if step.description %}
          <div class="block-title">{{ desc }}</div>
          <div class="section-text">{{ step.description }}</div>
        {% endif %}

        {% if step.code %}
          <div class="block-title">{{ command_output }}</div>
          <div class="code">{{ step.code }}</div>
        {% endif %}

        {% for img in step.images %}
          <img src="data:image/png;base64,{{ img.data }}">
          {% if img.name %}
            <div class="imgcap">{{ img.name }}</div>
          {% endif %}
        {% endfor %}
      </div>
    {% endfor %}
  {% endif %}

  {% if additional_reports %}
    <h2>{{ additional_reports_title }}</h2>
    {% for extra in additional_reports %}
      <div class="card">
        <h3>{{ extra.number }} {{ extra.title }}</h3>

        {% if extra.description %}
          <div class="section-text">{{ extra.description }}</div>
        {% endif %}

        {% if extra.code %}
          <div class="block-title">{{ output }}</div>
          <div class="code">{{ extra.code }}</div>
        {% endif %}

        {% for img in extra.images %}
          <img src="data:image/png;base64,{{ img.data }}">
          {% if img.name %}
            <div class="imgcap">{{ img.name }}</div>
          {% endif %}
        {% endfor %}
      </div>
    {% endfor %}
  {% endif %}

  {% if compliance_rows %}
    <h2>{{ compliance_title }}</h2>
    <div class="card section-text">{{ compliance_intro }}</div>
    {% if compliance_coverage %}
      <p class="meta"><span class="label">{{ compliance_coverage_label }}:</span> {{ compliance_coverage }}</p>
    {% endif %}
    <table style="border-collapse:collapse;width:100%;font-size:12px">
      <thead>
        <tr style="background:#eef2f7">
          {% for h in compliance_headers %}
          <th style="border:1px solid #cbd5e1;padding:6px;text-align:left">{{ h }}</th>
          {% endfor %}
        </tr>
      </thead>
      <tbody>
        {% for r in compliance_rows %}
        <tr>
          <td style="border:1px solid #e5e7eb;padding:6px">{{ r.title }}</td>
          <td style="border:1px solid #e5e7eb;padding:6px;color:{{ r.color }};font-weight:bold">{{ r.severity }}</td>
          <td style="border:1px solid #e5e7eb;padding:6px">{{ r.category }}</td>
          {% for v in r.fw %}
          <td style="border:1px solid #e5e7eb;padding:6px">{{ v }}</td>
          {% endfor %}
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% if compliance_legend %}
      <h3>{{ control_legend_title }}</h3>
      {% for label, items in compliance_legend %}
        <div class="block-title">{{ label }}</div>
        <ul class="list">
          {% for cid, title in items %}<li>{{ cid }} — {{ title }}</li>{% endfor %}
        </ul>
      {% endfor %}
    {% endif %}
  {% endif %}
</body>
</html>
"""

SEV_COLORS = {
    "Critical": "#A61B1B",
    "High": "#D35400",
    "Moderate": "#B9770E",
    "Low": "#1F618D",
    "Informational": "#5D6D7E",
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


def _join_multi(finding: dict, plural_key: str, singular_key: str) -> str:
    values = finding.get(plural_key)
    if isinstance(values, list) and values:
        cleaned = [str(v).strip() for v in values if str(v).strip()]
        if cleaned:
            return ", ".join(cleaned)

    value = str(finding.get(singular_key) or "").strip()
    return value


def _build_finding_meta_lines(finding: dict) -> list[str]:
    lines = []

    hosts = _join_multi(finding, "hosts", "host")
    ports = _join_multi(finding, "ports", "port")
    cves = _join_multi(finding, "cves", "cve")
    cwes = _join_multi(finding, "cwes", "cwe")
    protocol = str(finding.get("protocol") or "").strip()
    cvss = str(finding.get("cvss") or "").strip()

    if hosts:
        lines.append(f"Hosts: {hosts}")
    if ports:
        lines.append(f"Ports: {ports}")
    if cves:
        lines.append(f"CVEs: {cves}")
    if cwes:
        lines.append(f"CWEs: {cwes}")
    if protocol:
        lines.append(f"Protocol: {protocol}")
    if cvss:
        lines.append(f"CVSS: {cvss}")

    return lines


def generate_html_bytes(report: dict, report_variant: str = "technical") -> bytes:
    lang = get_language(report)
    def _person_line(c):
        bits = [c.get("name", "")]
        if c.get("title"): bits.append(f"({c.get('title')})")
        if c.get("contact"): bits.append(f"– {c.get('contact')}")
        return " ".join(b for b in bits if b)
    _all_contacts = report.get("contacts") or []
    provider_people = [_person_line(c) for c in _all_contacts if (c.get("role") or "Tester") != "Client"]
    client_people = [_person_line(c) for c in _all_contacts if (c.get("role") or "Tester") == "Client"]
    findings = list(report.get("findings") or [])
    counts = Counter((f.get("severity") or "Informational") for f in findings)

    include_charts = bool(report.get("include_charts", True))
    sev_chart = png_bytes_to_b64(severity_distribution_png(counts, lang)) if include_charts else ""
    trend_chart = png_bytes_to_b64(risk_trend_png(findings, lang)) if include_charts else ""

    toc_items = [
        t(lang, "legal"),
        t(lang, "conf_statement"),
        t(lang, "disclaimer"),
        t(lang, "contact_info"),
        t(lang, "exec_overview") if report_variant in {"executive", "combined"} else t(lang, "engagement_overview"),
        t(lang, "assessment_details"),
        t(lang, "findings_summary"),
    ]

    if include_charts:
        toc_items.append(t(lang, "risk_charts"))

    include_compliance = bool(report.get("include_compliance", True))
    has_walk = bool(report.get("detailed_walkthrough"))
    has_add = bool(report.get("additional_reports"))

    # Consecutive numbers assigned only to trailing sections that actually render.
    technical_section_number = "6" if report_variant == "combined" else "4"
    seq = int(technical_section_number)
    walkthrough_section_number = additional_section_number = compliance_section_number = ""
    if has_walk:
        seq += 1
        walkthrough_section_number = str(seq)
    if has_add:
        seq += 1
        additional_section_number = str(seq)
    if include_compliance:
        seq += 1
        compliance_section_number = str(seq)

    toc_items.append(t(lang, "technical_findings", n=technical_section_number))
    if has_walk:
        toc_items.append(t(lang, "walkthrough", n=walkthrough_section_number))
    if has_add:
        toc_items.append(t(lang, "additional_reports", n=additional_section_number))
    if include_compliance:
        toc_items.append(t(lang, "compliance_mapping", n=compliance_section_number))
    _fw = CM.report_frameworks(report) if include_compliance else []
    compliance_headers = ([t(lang, "compliance_col_finding"), t(lang, "severity"), t(lang, "compliance_col_category")]
                          + [label for _, label in _fw])
    compliance_rows = []
    if include_compliance and _fw:
        for r in CM.report_rows(report):
            compliance_rows.append({
                "title": r["title"], "severity": r["severity"], "category": r["category"],
                "color": SEV_COLORS.get(r["severity"], "#5D6D7E"),
                "fw": [r["controls"].get(k, "") for k, _ in _fw],
            })
    _fw_names = " / ".join(label for _, label in _fw)
    compliance_cov_text = ""
    compliance_legend = CM.used_controls(report) if (include_compliance and _fw) else []

    # NIS extras: posture verdict, status table, methodology
    _pk = RM.posture_key(report)
    posture_label_val = RM.posture_label(report, lang)
    posture_color_val = RM.posture_color(report)
    posture_desc_val = RM.POSTURE_DESC.get(lang, RM.POSTURE_DESC["en"]).get(_pk, "") if _pk else ""
    _status_findings = sorted(findings, key=lambda f: ["Critical","High","Moderate","Low","Informational"].index(f.get("severity","Informational")) if f.get("severity") in ["Critical","High","Moderate","Low","Informational"] else 4)
    status_rows = []
    for _i, _f in enumerate(_status_findings, start=1):
        _locs = _f.get("hosts") if isinstance(_f.get("hosts"), list) and _f.get("hosts") else ([_f.get("host")] if _f.get("host") else [])
        status_rows.append({"num": _i, "title": _f.get("title") or "-",
                            "location": ", ".join(str(x) for x in _locs if x),
                            "state": RM.status_label(_f, lang), "state_color": RM.status_color(_f),
                            "comments": str(_f.get("status_note") or ""), "updated": str(_f.get("status_date") or "")})
    _test_type = report.get("test_type") or "Black Box"
    methodology_intro = MM.intro(report, lang)
    methodology_legal = MM.legal(lang, _test_type)
    methodology_standards_lead = MM.standards_lead(lang)
    methodology_standards = MM.standards(lang)
    methodology_tools = MM.tools(lang)
    _meth_name = t(lang, "sec_methodology", n="2").split(".0", 1)[-1].strip()
    _attack_path_title = "2.2 " + t(lang, "attack_path")
    _methodology_title = "2.3 " + _meth_name
    attack_intro = AC.intro(lang)
    attack_stages_title = AC.stages_title(lang)
    attack_stages = AC.stages(lang)
    attack_limitation_title = AC.limitation_title(lang)
    attack_limitation = AC.limitation(lang)
    nis_impact_scale = [("Critic", "#A61B1B", "Risc critic - corectie imediata sau oprirea serviciului."),
                        ("Major", "#D35400", "Risc major - corectie pe termen scurt."),
                        ("Mediu", "#B9770E", "Risc moderat - corectie pe termen mediu."),
                        ("Scazut", "#1F618D", "Risc scazut - poate necesita corectie.")]

    technical_findings = [
        {
            **f,
            "number": f"{technical_section_number}.{idx}",
            "color": SEV_COLORS.get(f.get("severity"), "#5D6D7E"),
            "status_full": RM.status_label(f, lang) + ((" – " + str(f.get("status_note") or f.get("status_date"))) if (f.get("status_note") or f.get("status_date")) else ""),
            "status_color": RM.status_color(f),
            "exploit_label": RM.exploit_label(f, lang),
            "sev_bits": " - ".join(str(x) for x in [f.get("cvss"), f.get("severity"), f.get("cvss_vector")] if x),
            "locations": ", ".join(str(x) for x in ((f.get("hosts") if isinstance(f.get("hosts"), list) and f.get("hosts") else ([f.get("host")] if f.get("host") else []))) if x),
            "meta_lines": _build_finding_meta_lines(f),
            "images": normalize_images(f.get("images"), default_prefix=f.get("title") or f"Finding {idx}"),
        }
        for idx, f in enumerate(findings, start=1)
    ]

    walkthrough = [
        {
            **step,
            "number": f"{walkthrough_section_number}.{idx}",
            "title": step.get("name") or step.get("title") or f"Step {idx}",
            "images": normalize_images(step.get("images"), default_prefix=step.get("name") or step.get("title") or f"Step {idx}"),
        }
        for idx, step in enumerate(report.get("detailed_walkthrough") or [], start=1)
    ]

    additional_reports = [
        {
            **extra,
            "number": f"{additional_section_number}.{idx}",
            "title": extra.get("name") or extra.get("title") or f"Additional Report {idx}",
            "images": normalize_images(extra.get("images"), default_prefix=extra.get("name") or extra.get("title") or f"Additional Report {idx}"),
        }
        for idx, extra in enumerate(report.get("additional_reports") or [], start=1)
    ]

    severity_rows = [
        {"severity": sev, "count": counts.get(sev, 0)}
        for sev in ["Critical", "High", "Moderate", "Low", "Informational"]
    ]

    template = Template(HTML_TEMPLATE)
    html = template.render(
        title=f"{report.get('client', 'Client')} {t(lang, 'generated_html')}",
        report_title=t(lang, "report_title"),
        client=report.get("client", "N/A"),
        logo_b64=report.get("logo_b64", ""),
        provider_or_client=(str(report.get("provider") or "").strip() or report.get("client", "N/A")),
        project=report.get("project", "N/A"),
        date=report.get("date", "N/A"),
        version=report.get("version", "1.0"),
        tester=report.get("tester", "N/A"),
        t_client=t(lang, "client"),
        t_project=t(lang, "project"),
        t_date=t(lang, "assessment_date"),
        t_version=t(lang, "version"),
        t_tester=t(lang, "lead_tester"),
        toc=t(lang, "table_of_contents"),
        toc_items=toc_items,
        legal_title=t(lang, "legal"),
        legal_text=_section_value(
            report,
            "section_1_0_confidentiality_and_legal",
            section_default("section_1_0_confidentiality_and_legal", lang),
        ),
        conf_statement_title=t(lang, "conf_statement"),
        conf_statement_text=_section_value(
            report,
            "section_1_1_confidentiality_statement",
            section_default("section_1_1_confidentiality_statement", lang),
        ),
        disclaimer_title=t(lang, "disclaimer"),
        disclaimer_text=_section_value(
            report,
            "section_1_2_disclaimer",
            section_default("section_1_2_disclaimer", lang),
        ),
        contact_info_title=t(lang, "contact_info"),
        contact_info_text=_section_value(report, "section_1_3_contact_information", ""),
        provider_company=report.get("provider", ""),
        client_company=report.get("client", ""),
        provider_people=provider_people,
        client_people=client_people,
        contact_provider_label=t(lang, "contact_provider_label"),
        contact_client_label=t(lang, "contact_client_label"),
        no_contacts=t(lang, "no_contacts"),
        overview_title=t(lang, "exec_overview") if report_variant in {"executive", "combined"} else t(lang, "engagement_overview"),
        executive_summary=report.get("executive_summary") or report.get("assessment_overview") or executive_narrative(report, findings, lang),
        assessment_details_title=t(lang, "assessment_details"),
        assessment_overview=report.get("assessment_overview", ""),
        assessment_details=report.get("assessment_details", ""),
        scope=report.get("scope", ""),
        scope_exclusions=report.get("scope_exclusions", ""),
        client_allowances=report.get("client_allowances", ""),
        attack_path_title=_attack_path_title,
        attack_intro=attack_intro,
        attack_stages_title=attack_stages_title,
        attack_stages=attack_stages,
        attack_limitation_title=attack_limitation_title,
        attack_limitation=attack_limitation,
        findings_summary=t(lang, "findings_summary"),
        severity_rows=severity_rows,
        include_charts=include_charts,
        risk_charts=t(lang, "risk_charts"),
        severity_chart=sev_chart,
        trend_chart=trend_chart,
        severity_distribution=t(lang, "severity_distribution"),
        risk_trend=t(lang, "risk_trend"),
        technical_findings_title=t(lang, "technical_findings", n=technical_section_number),
        technical_findings=technical_findings,
        walkthrough_title=t(lang, "walkthrough", n=walkthrough_section_number),
        walkthrough=walkthrough,
        additional_reports_title=t(lang, "additional_reports", n=additional_section_number),
        additional_reports=additional_reports,
        desc=t(lang, "description"),
        likelihood=t(lang, "likelihood"),
        impact=t(lang, "impact"),
        tools_used=t(lang, "tools_used"),
        recommendation=t(lang, "recommendation"),
        references=t(lang, "references"),
        evidence_output=t(lang, "evidence_output"),
        command_output=t(lang, "command_output"),
        output=t(lang, "output"),
        label_assessment_overview=t(lang, "label_assessment_overview"),
        label_assessment_details=t(lang, "label_assessment_details"),
        label_scope=t(lang, "label_scope"),
        label_scope_exclusions=t(lang, "label_scope_exclusions"),
        label_client_allowances=t(lang, "label_client_allowances"),
        compliance_rows=compliance_rows,
        compliance_title=(t(lang, "compliance_mapping", n=compliance_section_number) + (f" ({_fw_names})" if _fw_names else "")),
        compliance_intro=t(lang, "compliance_intro"),
        compliance_coverage_label=t(lang, "compliance_coverage"),
        compliance_coverage=compliance_cov_text,
        lbl_impact_nis=t(lang, "lbl_impact_nis"),
        lbl_status=t(lang, "lbl_status"),
        lbl_location=t(lang, "lbl_location"),
        t_severity=t(lang, "severity"),
        posture_label_val=posture_label_val, posture_color_val=posture_color_val,
        posture_desc_val=posture_desc_val, security_posture_label_txt=t(lang, "security_posture_label"),
        methodology_title=_methodology_title,
        legal_framework_label=t(lang, "legal_framework"), methodology_legal=methodology_legal,
        methodology_intro=methodology_intro,
        methodology_standards_lead=methodology_standards_lead,
        methodology_standards_label=t(lang, "methodology_standards"), methodology_standards=methodology_standards,
        methodology_tools_label=t(lang, "methodology_tools"), methodology_tools=methodology_tools,
        nis_impact_scale_label=t(lang, "nis_impact_scale"), nis_impact_scale=nis_impact_scale,
        status_table_title="3.1 " + t(lang, "status_table_title"), status_rows=status_rows,
        t_col_finding=t(lang, "compliance_col_finding"), t_col_location=t(lang, "col_location"),
        t_col_state=t(lang, "col_state"), t_col_comments=t(lang, "col_comments"), t_col_updated=t(lang, "col_updated"),
        compliance_headers=compliance_headers,
        compliance_legend=compliance_legend,
        control_legend_title=t(lang, "control_legend"),
    )

    return html.encode("utf-8")