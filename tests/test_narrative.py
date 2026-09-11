import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from util.narrative import executive_narrative


def test_narrative_mentions_counts_en():
    fs = [{"title": "A", "severity": "Critical", "host": "10.0.0.1"},
          {"title": "B", "severity": "High", "host": "10.0.0.2"}]
    txt = executive_narrative({"client": "ACME"}, fs, "en")
    assert "2 findings" in txt
    assert "2 hosts" in txt
    assert "Critical" in txt


def test_narrative_ro():
    fs = [{"title": "A", "severity": "Critical", "host": "10.0.0.1"}]
    txt = executive_narrative({"client": "ACME"}, fs, "ro")
    assert "constatare" in txt  # singular
    assert "ACME" in txt


def test_narrative_empty():
    txt = executive_narrative({}, [], "en")
    assert "no vulnerabilities" in txt.lower()


def test_narrative_no_high_crit():
    fs = [{"title": "A", "severity": "Low", "host": "10.0.0.1"}]
    txt = executive_narrative({}, fs, "en")
    assert "hygiene" in txt.lower()
