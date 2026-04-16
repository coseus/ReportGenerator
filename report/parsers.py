# report/parsers.py
"""
Advanced unified parser module for:
- Nessus .nessus / .xml
- OpenVAS XML
- Nmap XML / Grepable / Output
- CSV with auto-delimiter
- JSON structured inputs

All functions return LIST[DICT] with normalized structure.
"""

import csv
import json
import xml.etree.ElementTree as ET
from io import StringIO


# ---------------------------------------------------------------------------
# NORMALIZER (fail-safe)
# ---------------------------------------------------------------------------
def _norm(value):
    if value is None:
        return ""
    return str(value).strip()


# ---------------------------------------------------------------------------
# UNIFIED OUTPUT FORMAT for findings
# ---------------------------------------------------------------------------
def _make_finding(
    title="Untitled Finding",
    severity="Informational",
    host="",
    port="",
    protocol="",
    description="",
    impact="",
    recommendation="",
    cvss="",
    cve="",
):
    return {
        "severity": _norm(severity),
        "title": _norm(title),
        "host": _norm(host),
        "port": _norm(port),
        "protocol": _norm(protocol),
        "description": _norm(description),
        "impact": _norm(impact),
        "recommendation": _norm(recommendation),
        "cvss": _norm(cvss),
        "cve": _norm(cve),
        "code": "",
        "images": [],
    }


# ---------------------------------------------------------------------------
# 1. PARSER: OPENVAS XML (optimizat complet)
# ---------------------------------------------------------------------------
def parse_openvas_xml_bytes(file_bytes: bytes) -> list:
    import xml.etree.ElementTree as ET

    findings = []
    root = ET.fromstring(file_bytes)

    # All results under <results>...
    for res in root.findall(".//result"):
        f = {}

        # ID
        f["id"] = res.get("id")

        # Title
        title = res.findtext("name")
        f["title"] = title or "Untitled Finding"

        # Host
        host = res.findtext("host")
        if host:
            host = host.strip().split("\n")[0]
        f["host"] = host or ""

        # Port / Protocol
        port = res.findtext("port") or ""
        f["port"] = port
        if "/" in port:
            f["protocol"] = port.split("/", 1)[1]
        else:
            f["protocol"] = ""

        # SEVERITY (Greenbone uses <threat> High/Medium/etc)
        sev = res.findtext("threat") or "Info"
        mapping = {
            "Critical": "Critical",
            "High": "High",
            "Medium": "Moderate",
            "Low": "Low",
            "Log": "Informational",
            "None": "Informational",
            "Info": "Informational",
        }
        f["severity"] = mapping.get(sev, "Informational")

        # CVSS
        nvt = res.find("nvt")
        if nvt is not None:
            f["cvss"] = nvt.findtext("cvss_base") or ""

        # TAGS (summary, impact, solution, etc)
        f["description"] = ""
        f["impact"] = ""
        f["recommendation"] = ""

        tags_text = ""
        if nvt is not None and nvt.find("tags") is not None:
            tags_text = (nvt.find("tags").text or "").strip()

        # tags are like: "summary=...|impact=...|solution=...|vuldetect=..."
        tag_parts = tags_text.split("|")
        for part in tag_parts:
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            key = key.strip()
            value = value.strip()

            if key == "summary":
                f["description"] = value
            elif key == "impact":
                f["impact"] = value
            elif key == "solution":
                f["recommendation"] = value

        # CVEs in <detail> entries
        cves = []
        for det in res.findall(".//detail"):
            name = det.findtext("name")
            val = det.findtext("value")
            if name and name.lower().startswith("cve") and val:
                cves.extend(v.strip() for v in val.split(","))
        f["cve"] = ", ".join(sorted(set(cves)))

        # Code not provided by scanner
        f["code"] = ""
        f["images"] = []

        findings.append(f)

    return findings



# ---------------------------------------------------------------------------
# 2. PARSER: NESSUS (.nessus / .xml)
# ---------------------------------------------------------------------------
def parse_nessus_xml_bytes(xml_bytes):

    findings = []

    try:
        root = ET.fromstring(xml_bytes)
    except Exception as e:
        raise ValueError(f"Nessus parsing error: {e}")

    for r in root.findall(".//ReportItem"):
        try:
            title = _norm(r.get("pluginName"))
            severity_num = _norm(r.get("severity"))
            severity_map = {
                "0": "Informational",
                "1": "Low",
                "2": "Moderate",
                "3": "High",
                "4": "Critical",
            }
            severity = severity_map.get(severity_num, "Informational")

            host = _norm(r.findtext("Host"))
            port = _norm(r.get("port"))
            proto = _norm(r.get("protocol"))

            description = _norm(r.findtext("description"))
            impact = _norm(r.findtext("synopsis"))
            recommendation = _norm(r.findtext("solution"))

            # CVE list
            cve = ""
            cves = r.findall("cve")
            if cves:
                cve = ", ".join(_norm(c.text) for c in cves if c.text)

            cvss = _norm(r.findtext("cvss_base_score"))

            findings.append(
                _make_finding(
                    title=title,
                    severity=severity,
                    host=host,
                    port=port,
                    protocol=proto,
                    description=description,
                    impact=impact,
                    recommendation=recommendation,
                    cvss=cvss,
                    cve=cve,
                )
            )

        except:
            continue

    return findings


# ---------------------------------------------------------------------------
# 3. PARSER: NMAP XML
# ---------------------------------------------------------------------------
def parse_nmap_xml_bytes(xml_bytes):

    findings = []
    try:
        root = ET.fromstring(xml_bytes)
    except Exception as e:
        raise ValueError(f"Nmap XML parsing error: {e}")

    for host in root.findall("host"):
        address = _norm(host.findtext("address[@addrtype='ipv4']") or "")

        for port_el in host.findall(".//port"):
            try:
                port = port_el.get("portid", "")
                proto = port_el.get("protocol", "")

                state = port_el.find("state")
                service = port_el.find("service")

                title = f"Nmap: {service.get('name','service')} on port {port}/{proto}"

                description = f"State: {state.get('state','unknown')}"
                impact = ""
                recommendation = ""

                findings.append(
                    _make_finding(
                        title=title,
                        severity="Informational",
                        host=address,
                        port=port,
                        protocol=proto,
                        description=description,
                        impact=impact,
                        recommendation=recommendation,
                        cve="",
                        cvss="",
                    )
                )
            except:
                continue

    return findings


# ---------------------------------------------------------------------------
# 4. PARSER: NMAP GREPABLE (.nmap or text)
# ---------------------------------------------------------------------------
def parse_nmap_text(text_bytes):

    findings = []
    text = text_bytes.decode(errors="ignore")

    for line in text.splitlines():
        if "/tcp" in line or "/udp" in line:
            try:
                parts = line.split()
                host = ""
                if "Nmap scan report for" in line:
                    continue
                # format: 80/tcp open http Apache ...
                port_proto = parts[0]
                port, proto = port_proto.split("/")
                title = f"Nmap: {parts[2]} on port {port}/{proto}"
                description = " ".join(parts[2:])

                findings.append(
                    _make_finding(
                        title=title,
                        severity="Informational",
                        host=host,
                        port=port,
                        protocol=proto,
                        description=description,
                    )
                )
            except:
                continue

    return findings


# ---------------------------------------------------------------------------
# 5. PARSER: CSV auto-delimiter
# ---------------------------------------------------------------------------
def parse_csv_bytes(csv_bytes):
    text = csv_bytes.decode(errors="ignore")

    dialect = csv.Sniffer().sniff(text.splitlines()[0])
    reader = csv.DictReader(StringIO(text), dialect=dialect)

    findings = []

    for row in reader:
        try:
            findings.append(
                _make_finding(
                    title=row.get("title", ""),
                    severity=row.get("severity", "Informational"),
                    host=row.get("host", ""),
                    port=row.get("port", ""),
                    protocol=row.get("protocol", ""),
                    description=row.get("description", ""),
                    impact=row.get("impact", ""),
                    recommendation=row.get("recommendation", ""),
                    cvss=row.get("cvss", ""),
                    cve=row.get("cve", ""),
                )
            )
        except:
            continue

    return findings


# ---------------------------------------------------------------------------
# 6. PARSER: JSON (listă de dict-uri)
# ---------------------------------------------------------------------------
def parse_json_bytes(json_bytes):
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
        findings.append(
            _make_finding(
                title=entry.get("title"),
                severity=entry.get("severity"),
                host=entry.get("host"),
                port=entry.get("port"),
                protocol=entry.get("protocol"),
                description=entry.get("description"),
                impact=entry.get("impact"),
                recommendation=entry.get("recommendation"),
                cvss=entry.get("cvss"),
                cve=entry.get("cve"),
            )
        )

    return findings


# ---------------------------------------------------------------------------
# AUTO-DETECT FORMAT
# ---------------------------------------------------------------------------
def auto_parse_findings(file_bytes, filename):
    fn = filename.lower()

    if fn.endswith(".nessus") or fn.endswith(".xml") and "<NessusClientData_v" in file_bytes.decode(errors="ignore"):
        return parse_nessus_xml_bytes(file_bytes)

    if fn.endswith(".xml") and "<report" in file_bytes.decode(errors="ignore"):
        # prefer OpenVAS logic
        return parse_openvas_xml_bytes(file_bytes)

    if fn.endswith(".xml") and "<nmaprun" in file_bytes.decode(errors="ignore"):
        return parse_nmap_xml_bytes(file_bytes)

    if fn.endswith(".csv"):
        return parse_csv_bytes(file_bytes)

    if fn.endswith(".json"):
        return parse_json_bytes(file_bytes)

    # fallback → text Nmap
    return parse_nmap_text(file_bytes)
