# report/parsers.py
"""
Unified parser module for:
- Nessus .nessus / .xml
- OpenVAS XML
- Nmap XML / text
- CSV with flexible headers
- JSON structured inputs

All functions return LIST[DICT] with normalized structure
compatible with the current report generator project.
"""

from __future__ import annotations

import csv
import json
import logging
import xml.etree.ElementTree as ET
from io import StringIO

from util.cvss_utils import auto_fill_finding_cvss, severity_from_score
from util.severity import normalize_severity

logger = logging.getLogger(__name__)

SEVERITY_OPTIONS = {"Critical", "High", "Moderate", "Low", "Informational"}


def _norm(value):
    if value is None:
        return ""
    return str(value).strip()


# Alias for backward compatibility inside this module
_norm_severity = normalize_severity


def _split_multi(value: str) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in str(value).split(",") if item.strip()]


def _make_finding(
    title="Untitled Finding",
    severity="Informational",
    host="",
    port="",
    protocol="",
    description="",
    likelihood="",
    impact="",
    recommendation="",
    cvss="",
    cve="",
    cwe="",
    cvss_vector="",
    references="",
    tools_used="",
    code="",
):
    host = _norm(host)
    port = _norm(port)
    cve = _norm(cve)
    cwe = _norm(cwe)

    finding = {
        "severity": _norm_severity(severity),
        "title": _norm(title) or "Untitled Finding",
        "name": _norm(title) or "Untitled Finding",
        "host": host,
        "port": port,
        "protocol": _norm(protocol),
        "description": _norm(description),
        "likelihood": _norm(likelihood),
        "impact": _norm(impact),
        "recommendation": _norm(recommendation),
        "cvss": _norm(cvss),
        "cve": cve,
        "cwe": cwe,
        "cvss_vector": _norm(cvss_vector),
        "references": _norm(references),
        "tools_used": _norm(tools_used),
        "code": _norm(code),
        "images": [],
        "hosts": _split_multi(host),
        "ports": _split_multi(port),
        "cves": _split_multi(cve),
        "cwes": _split_multi(cwe),
    }

    finding = auto_fill_finding_cvss(finding)

    # Auto-classify the finding and propose controls (NIS2 / ISO 27001 / NIST CSF / NIST 800-53).
    try:
        from util.control_mapper import classify_finding, suggest_controls
        finding["categories"] = classify_finding(finding)
        finding["controls"] = suggest_controls(finding)
    except Exception:
        pass
    return finding


def _pick(row: dict, *names, default=""):
    for name in names:
        if name in row and row[name] is not None:
            value = str(row[name]).strip()
            if value:
                return value
    return default


# ---------------------------------------------------------------------------
# 1. OPENVAS XML
# ---------------------------------------------------------------------------
def parse_openvas_xml_bytes(file_bytes: bytes) -> list[dict]:
    findings = []
    root = ET.fromstring(file_bytes)

    for res in root.findall(".//result"):
        title = res.findtext("name") or "Untitled Finding"

        host = res.findtext("host") or ""
        if host:
            host = host.strip().split("\n")[0]

        port_text = res.findtext("port") or ""
        port = port_text
        protocol = port_text.split("/", 1)[1] if "/" in port_text else ""

        cvss = ""
        nvt = res.find("nvt")
        if nvt is not None:
            cvss = nvt.findtext("cvss_base") or ""

        sev = res.findtext("threat") or ""
        severity = _norm_severity(sev) if sev else "Informational"
        # Modern GVM exports may omit <threat>; derive the band from numeric severity/CVSS.
        if not sev or severity == "Informational":
            num = res.findtext("severity") or cvss
            try:
                score = float(num)
                if score > 0:
                    severity = severity_from_score(score)
            except (TypeError, ValueError):
                pass

        description = ""
        impact = ""
        recommendation = ""
        references = ""
        cves = []

        tags_text = ""
        if nvt is not None and nvt.find("tags") is not None:
            tags_text = (nvt.find("tags").text or "").strip()

        for part in tags_text.split("|"):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            key = key.strip().lower()
            value = value.strip()

            if key == "summary":
                description = value
            elif key == "impact":
                impact = value
            elif key == "solution":
                recommendation = value
            elif key in {"refs", "reference", "references"}:
                references = value

        for det in res.findall(".//detail"):
            name = det.findtext("name")
            val = det.findtext("value")
            if name and name.lower().startswith("cve") and val:
                cves.extend(v.strip() for v in val.split(",") if v.strip())

        findings.append(
            _make_finding(
                title=title,
                severity=severity,
                host=host,
                port=port,
                protocol=protocol,
                description=description,
                impact=impact,
                recommendation=recommendation,
                cvss=cvss,
                cve=", ".join(sorted(set(cves))),
                references=references,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# 2. NESSUS XML
# ---------------------------------------------------------------------------
def parse_nessus_xml_bytes(xml_bytes: bytes) -> list[dict]:
    findings = []

    try:
        root = ET.fromstring(xml_bytes)
    except Exception as e:
        raise ValueError(f"Nessus parsing error: {e}")

    severity_map = {
        "0": "Informational",
        "1": "Low",
        "2": "Moderate",
        "3": "High",
        "4": "Critical",
    }

    # In the .nessus format the host is the parent <ReportHost name="..."> element,
    # not a child of <ReportItem>. Iterate hosts first so every finding keeps its host.
    report_hosts = root.findall(".//ReportHost")
    host_items = [(_norm(rh.get("name")), rh.findall("ReportItem")) for rh in report_hosts]
    if not host_items:  # fallback for flat exports without ReportHost wrappers
        host_items = [("", root.findall(".//ReportItem"))]

    for report_host_name, report_items in host_items:
        for r in report_items:
            try:
                title = _norm(r.get("pluginName"))
                severity_num = _norm(r.get("severity"))
                severity = severity_map.get(severity_num, "Informational")

                host = report_host_name or _norm(r.findtext("Host")) or _norm(r.get("host"))
                port = _norm(r.get("port"))
                proto = _norm(r.get("protocol"))

                description = _norm(r.findtext("description"))
                likelihood = _norm(r.findtext("risk_factor"))
                impact = _norm(r.findtext("synopsis"))
                recommendation = _norm(r.findtext("solution"))
                cvss = _norm(r.findtext("cvss_base_score"))
                cvss_vector = _norm(r.findtext("cvss_vector"))
                references = _norm(r.findtext("see_also"))

                cves = r.findall("cve")
                cve = ", ".join(_norm(c.text) for c in cves if c.text)

                findings.append(
                    _make_finding(
                        title=title,
                        severity=severity,
                        host=host,
                        port=port,
                        protocol=proto,
                        description=description,
                        likelihood=likelihood,
                        impact=impact,
                        recommendation=recommendation,
                        cvss=cvss,
                        cve=cve,
                        cvss_vector=cvss_vector,
                        references=references,
                    )
                )
            except Exception as exc:
                logger.warning("Skipping Nessus ReportItem due to error: %s", exc)
                continue

    return findings


# ---------------------------------------------------------------------------
# 3. NMAP XML
# ---------------------------------------------------------------------------
def parse_nmap_xml_bytes(xml_bytes: bytes) -> list[dict]:
    findings = []
    try:
        root = ET.fromstring(xml_bytes)
    except Exception as e:
        raise ValueError(f"Nmap XML parsing error: {e}")

    for host in root.findall("host"):
        address = ""
        for addr_el in host.findall("address"):
            addr_type = addr_el.get("addrtype", "")
            if addr_type in ("ipv4", "ipv6"):
                address = _norm(addr_el.get("addr"))
                break
        if not address:  # fall back to whatever address is present
            addr_el = host.find("address")
            address = _norm(addr_el.get("addr")) if addr_el is not None else ""
        hostname_el = host.find(".//hostname")
        if hostname_el is not None and hostname_el.get("name"):
            hn = _norm(hostname_el.get("name"))
            if hn and hn != address:
                address = f"{address} ({hn})" if address else hn

        for port_el in host.findall(".//port"):
            try:
                port = port_el.get("portid", "")
                proto = port_el.get("protocol", "")

                state = port_el.find("state")
                service = port_el.find("service")

                svc_name = service.get("name", "service") if service is not None else "service"
                product = service.get("product", "") if service is not None else ""
                version = service.get("version", "") if service is not None else ""

                title = f"Nmap: {svc_name} on port {port}/{proto}"
                description = f"State: {state.get('state', 'unknown') if state is not None else 'unknown'}"
                if product or version:
                    description += f" | Product: {product} {version}".strip()

                findings.append(
                    _make_finding(
                        title=title,
                        severity="Informational",
                        host=address,
                        port=port,
                        protocol=proto,
                        description=description,
                    )
                )
            except Exception as exc:
                logger.warning("Skipping Nmap port entry due to error: %s", exc)
                continue

    return findings


# ---------------------------------------------------------------------------
# 4. NMAP TEXT
# ---------------------------------------------------------------------------
def parse_nmap_text(text_bytes: bytes) -> list[dict]:
    findings = []
    text = text_bytes.decode(errors="ignore")

    for line in text.splitlines():
        line = line.strip()
        if not line or ("tcp" not in line and "udp" not in line):
            continue

        if "/tcp" in line or "/udp" in line:
            try:
                parts = line.split()
                port_proto = parts[0]
                if "/" not in port_proto:
                    continue

                port, proto = port_proto.split("/", 1)
                state = parts[1] if len(parts) > 1 else ""
                service = parts[2] if len(parts) > 2 else "service"

                title = f"Nmap: {service} on port {port}/{proto}"
                description = " ".join(parts[1:])

                findings.append(
                    _make_finding(
                        title=title,
                        severity="Informational",
                        port=port,
                        protocol=proto,
                        description=description,
                        impact=f"Detected state: {state}" if state else "",
                    )
                )
            except Exception as exc:
                logger.warning("Skipping Nmap text line due to error: %s", exc)
                continue

    return findings


# ---------------------------------------------------------------------------
# 5. CSV
# ---------------------------------------------------------------------------
def parse_csv_bytes(csv_bytes: bytes) -> list[dict]:
    text = csv_bytes.decode(errors="ignore")

    try:
        dialect = csv.Sniffer().sniff(text[:2048])
    except Exception:
        dialect = csv.excel

    reader = csv.DictReader(StringIO(text), dialect=dialect)
    findings = []

    for row in reader:
        try:
            severity = _norm_severity(
                _pick(row, "severity", "Severity", "risk", "Risk", default="Informational")
            )

            title = _pick(row, "title", "Title", "name", "Name", default="Untitled Finding")
            host = _pick(row, "host", "Host", "hosts", "Hosts")
            port = _pick(row, "port", "Port", "ports", "Ports")
            protocol = _pick(row, "protocol", "Protocol")
            description = _pick(
                row,
                "description",
                "Description",
                "summary",
                "Summary",
                "Informational",  # support your CSV as uploaded
            )
            likelihood = _pick(row, "likelihood", "Likelihood")
            impact = _pick(row, "impact", "Impact")
            recommendation = _pick(row, "recommendation", "Recommendation", "solution", "Solution")
            cvss = _pick(row, "cvss", "CVSS")
            cve = _pick(row, "cve", "CVE", "cves", "CVEs")
            cwe = _pick(row, "cwe", "CWE", "cwes", "CWEs")
            cvss_vector = _pick(row, "cvss_vector", "CVSS Vector", "vector", "Vector")
            references = _pick(row, "references", "References", "reference", "Reference")
            tools_used = _pick(row, "tools_used", "Tools Used", "tools", "Tools")
            code = _pick(row, "code", "Code", "Evidence Output", "Output")

            findings.append(
                _make_finding(
                    title=title,
                    severity=severity,
                    host=host,
                    port=port,
                    protocol=protocol,
                    description=description,
                    likelihood=likelihood,
                    impact=impact,
                    recommendation=recommendation,
                    cvss=cvss,
                    cve=cve,
                    cwe=cwe,
                    cvss_vector=cvss_vector,
                    references=references,
                    tools_used=tools_used,
                    code=code,
                )
            )
        except Exception as exc:
            logger.warning("Skipping CSV row due to error: %s", exc)
            continue

    return findings


# ---------------------------------------------------------------------------
# 6. JSON
# ---------------------------------------------------------------------------
def parse_json_bytes(json_bytes: bytes) -> list[dict]:
    try:
        data = json.loads(json_bytes.decode(errors="ignore"))
    except Exception as e:
        raise ValueError(f"JSON parsing error: {e}")

    if isinstance(data, dict):
        data = data.get("findings", [])

    findings = []

    for entry in data:
        if not isinstance(entry, dict):
            continue

        host = _norm(entry.get("host"))
        if not host and isinstance(entry.get("hosts"), list):
            host = ", ".join(_norm(v) for v in entry.get("hosts", []) if _norm(v))

        port = _norm(entry.get("port"))
        if not port and isinstance(entry.get("ports"), list):
            port = ", ".join(_norm(v) for v in entry.get("ports", []) if _norm(v))

        cve = _norm(entry.get("cve"))
        if not cve and isinstance(entry.get("cves"), list):
            cve = ", ".join(_norm(v) for v in entry.get("cves", []) if _norm(v))

        cwe = _norm(entry.get("cwe"))
        if not cwe and isinstance(entry.get("cwes"), list):
            cwe = ", ".join(_norm(v) for v in entry.get("cwes", []) if _norm(v))

        findings.append(
            _make_finding(
                title=entry.get("title") or entry.get("name"),
                severity=entry.get("severity"),
                host=host,
                port=port,
                protocol=entry.get("protocol"),
                description=entry.get("description"),
                likelihood=entry.get("likelihood"),
                impact=entry.get("impact"),
                recommendation=entry.get("recommendation"),
                cvss=entry.get("cvss"),
                cve=cve,
                cwe=cwe,
                cvss_vector=entry.get("cvss_vector"),
                references=entry.get("references"),
                tools_used=entry.get("tools_used"),
                code=entry.get("code"),
            )
        )

    return findings


# ---------------------------------------------------------------------------
# AUTO-DETECT FORMAT
# ---------------------------------------------------------------------------
def auto_parse_findings(file_bytes: bytes, filename: str) -> list[dict]:
    fn = filename.lower()
    decoded = file_bytes.decode(errors="ignore")

    if fn.endswith(".nessus") or (fn.endswith(".xml") and "<NessusClientData_v" in decoded):
        return parse_nessus_xml_bytes(file_bytes)

    if fn.endswith(".xml") and "<report" in decoded:
        return parse_openvas_xml_bytes(file_bytes)

    if fn.endswith(".xml") and "<nmaprun" in decoded:
        return parse_nmap_xml_bytes(file_bytes)

    if fn.endswith(".csv"):
        return parse_csv_bytes(file_bytes)

    if fn.endswith(".json"):
        return parse_json_bytes(file_bytes)

    return parse_nmap_text(file_bytes)
