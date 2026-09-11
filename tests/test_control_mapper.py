import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from util import control_mapper as CM


def test_catalogs_nonempty_and_consistent():
    for fw in CM.FRAMEWORK_KEYS:
        assert CM.CATALOGS[fw], f"empty catalog {fw}"
    # every control referenced by a category exists in its catalog
    for cat, mp in CM.CATEGORY_CONTROLS.items():
        for fw, ids in mp.items():
            for cid in ids:
                assert cid in CM.CATALOGS[fw], f"{cat}/{fw}: {cid} missing from catalog"


def test_classify_known_findings():
    assert "Cryptography" in CM.classify_finding({"title": "Weak TLS ciphers SWEET32"})
    assert "Authentication" in CM.classify_finding({"title": "Default credentials admin/admin"})
    assert "Patch Management" in CM.classify_finding({"title": "SQL Server 2016 end of life"})
    assert "Network Security" in CM.classify_finding({"title": "RDP exposed to the internet"})


def test_unmatched_defaults_to_vuln_mgmt():
    assert CM.classify_finding({"title": "totally generic thing"}) == ["Vulnerability Management"]


def test_suggest_controls_covers_all_frameworks():
    s = CM.suggest_controls({"title": "SMBv1 EternalBlue MS17-010"})
    assert all(fw in s for fw in CM.FRAMEWORK_KEYS)
    assert s["nist_800_53"], "expected some 800-53 controls"
    assert all(c in CM.CATALOGS["iso27001"] for c in s["iso27001"])


def test_effective_controls_prefers_user_selection():
    f = {"title": "x", "controls": {"nis2": ["21(2)(h)"], "iso27001": [], "nist_csf": [], "nist_800_53": []}}
    assert CM.effective_controls(f)["nis2"] == ["21(2)(h)"]


def test_report_frameworks_subset():
    fw = CM.report_frameworks({"control_frameworks": ["nis2", "nist_csf"]})
    assert [k for k, _ in fw] == ["nis2", "nist_csf"]


def test_apply_auto_suggestions_fills_findings():
    findings = [{"title": "Weak TLS SWEET32"}]
    CM.apply_auto_suggestions(findings)
    assert findings[0]["categories"] == ["Cryptography"]
    assert findings[0]["controls"]["iso27001"]
