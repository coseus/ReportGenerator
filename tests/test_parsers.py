# tests/test_parsers.py
"""Unit tests for the unified parser module."""

import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from report.parsers import (
    parse_csv_bytes,
    parse_json_bytes,
    parse_nessus_xml_bytes,
    parse_openvas_xml_bytes,
    parse_nmap_xml_bytes,
    auto_parse_findings,
)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------
def test_parse_csv_basic():
    csv_content = b"title,severity,host,description\nSQL Injection,Critical,10.0.0.1,Found in login form\n"
    findings = parse_csv_bytes(csv_content)
    assert len(findings) == 1
    f = findings[0]
    assert f["title"] == "SQL Injection"
    assert f["severity"] == "Critical"
    assert f["host"] == "10.0.0.1"


def test_parse_csv_empty_returns_empty():
    findings = parse_csv_bytes(b"title,severity\n")
    assert findings == []


def test_parse_csv_missing_columns_uses_defaults():
    csv_content = b"title\nMissing Headers Finding\n"
    findings = parse_csv_bytes(csv_content)
    assert len(findings) == 1
    assert findings[0]["severity"] == "Informational"


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def test_parse_json_basic():
    data = {
        "findings": [
            {
                "title": "XSS Reflected",
                "severity": "High",
                "host": "192.168.1.10",
                "description": "Reflected XSS in search param",
            }
        ]
    }
    findings = parse_json_bytes(json.dumps(data).encode())
    assert len(findings) == 1
    assert findings[0]["title"] == "XSS Reflected"
    assert findings[0]["severity"] == "High"


def test_parse_json_list_format():
    data = [{"title": "Open Redirect", "severity": "Low"}]
    findings = parse_json_bytes(json.dumps(data).encode())
    assert len(findings) == 1
    assert findings[0]["severity"] == "Low"


def test_parse_json_empty():
    findings = parse_json_bytes(json.dumps({"findings": []}).encode())
    assert findings == []


def test_parse_json_malformed_raises():
    try:
        parse_json_bytes(b"NOT JSON {{{{")
        assert False, "Expected ValueError"
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# Nessus XML
# ---------------------------------------------------------------------------
NESSUS_SAMPLE = b"""<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Test">
    <ReportHost name="10.0.0.5">
      <ReportItem port="443" severity="3" pluginName="SSL Certificate Expired"
                  protocol="tcp">
        <description>The SSL certificate has expired.</description>
        <solution>Renew the certificate.</solution>
        <cvss_base_score>7.5</cvss_base_score>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""


def test_parse_nessus_basic():
    findings = parse_nessus_xml_bytes(NESSUS_SAMPLE)
    assert len(findings) == 1
    f = findings[0]
    assert f["title"] == "SSL Certificate Expired"
    assert f["severity"] == "High"
    assert f["cvss"] == "7.5"


def test_parse_nessus_invalid_xml_raises():
    try:
        parse_nessus_xml_bytes(b"<not valid xml")
        assert False, "Expected ValueError"
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# Nmap XML
# ---------------------------------------------------------------------------
NMAP_XML_SAMPLE = b"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml_basic():
    findings = parse_nmap_xml_bytes(NMAP_XML_SAMPLE)
    assert len(findings) == 1
    f = findings[0]
    assert "22" in f["title"] or f["port"] == "22"
    assert f["host"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# auto_parse_findings routing
# ---------------------------------------------------------------------------
def test_auto_parse_routes_csv():
    csv_content = b"title,severity\nTest,High\n"
    findings = auto_parse_findings(csv_content, "results.csv")
    assert len(findings) == 1


def test_auto_parse_routes_json():
    data = [{"title": "Test", "severity": "Low"}]
    findings = auto_parse_findings(json.dumps(data).encode(), "export.json")
    assert len(findings) == 1


def test_auto_parse_routes_nessus():
    findings = auto_parse_findings(NESSUS_SAMPLE, "scan.nessus")
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Regression tests (added during code review – Sep 2026)
# ---------------------------------------------------------------------------
def test_nessus_host_from_reporthost_name():
    """Regression: host must come from parent <ReportHost name=...>, not a child element."""
    nessus = (
        b'<?xml version="1.0"?><NessusClientData_v2><Report name="t">'
        b'<ReportHost name="10.0.0.9">'
        b'<ReportItem port="445" protocol="tcp" severity="4" pluginName="MS17-010">'
        b'<description>EternalBlue</description><solution>Patch</solution>'
        b'<cvss_base_score>9.8</cvss_base_score><cve>CVE-2017-0144</cve>'
        b'</ReportItem></ReportHost></Report></NessusClientData_v2>'
    )
    findings = parse_nessus_xml_bytes(nessus)
    assert len(findings) == 1
    f = findings[0]
    assert f["host"] == "10.0.0.9"
    assert f["severity"] == "Critical"
    assert "CVE-2017-0144" in f["cve"]


def test_nessus_multiple_hosts_keep_their_own_host():
    nessus = (
        b'<?xml version="1.0"?><NessusClientData_v2><Report name="t">'
        b'<ReportHost name="10.0.0.1"><ReportItem severity="2" pluginName="A"/></ReportHost>'
        b'<ReportHost name="10.0.0.2"><ReportItem severity="3" pluginName="B"/></ReportHost>'
        b'</Report></NessusClientData_v2>'
    )
    findings = parse_nessus_xml_bytes(nessus)
    hosts = {f["title"]: f["host"] for f in findings}
    assert hosts == {"A": "10.0.0.1", "B": "10.0.0.2"}


def test_nmap_xml_prefers_ipv4_over_mac():
    nmap = (
        b'<?xml version="1.0"?><nmaprun><host>'
        b'<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>'
        b'<address addr="192.168.1.50" addrtype="ipv4"/>'
        b'<ports><port protocol="tcp" portid="80">'
        b'<state state="open"/><service name="http"/></port></ports>'
        b'</host></nmaprun>'
    )
    findings = parse_nmap_xml_bytes(nmap)
    assert len(findings) == 1
    assert "192.168.1.50" in findings[0]["host"]


def test_openvas_severity_from_numeric_when_threat_missing():
    openvas = (
        b'<?xml version="1.0"?><report><results><result>'
        b'<name>TLS weak</name><host>10.0.0.5</host><port>443/tcp</port>'
        b'<severity>9.1</severity>'
        b'<nvt oid="1"><cvss_base>9.1</cvss_base></nvt>'
        b'</result></results></report>'
    )
    findings = parse_openvas_xml_bytes(openvas)
    assert len(findings) == 1
    assert findings[0]["severity"] == "Critical"
