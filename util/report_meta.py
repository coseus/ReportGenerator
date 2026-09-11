# util/report_meta.py
"""
Metadata vocabularies for NIS-qualified pentest reports: finding status,
exploitability, overall security posture. Canonical keys are stored in the
report data; labels are resolved per language and each has a colour for the
coloured bars used in the report. No Streamlit dependency.
"""
from __future__ import annotations

# --- Finding status (remediation state) ---
STATUS_KEYS = ["present", "resolved", "accepted", "open"]
STATUS_COLORS = {
    "present": "#D35400",    # orange - still present
    "resolved": "#1E8449",   # green - fixed
    "accepted": "#1F618D",   # blue - risk accepted
    "open": "#A61B1B",       # red - open / not remediated
}
STATUS_LABELS = {
    "en": {"present": "Present", "resolved": "Resolved", "accepted": "Risk accepted", "open": "Open"},
    "ro": {"present": "Prezent", "resolved": "Rezolvat", "accepted": "Risc acceptat", "open": "Neremediat"},
}

# --- Exploitability (ease of exploitation) ---
EXPLOIT_KEYS = ["easy", "medium", "hard"]
EXPLOIT_COLORS = {"easy": "#A61B1B", "medium": "#D35400", "hard": "#B9770E"}
EXPLOIT_LABELS = {
    "en": {"easy": "Easy", "medium": "Moderate", "hard": "Hard"},
    "ro": {"easy": "Ușor", "medium": "Mediu", "hard": "Dificil"},
}

# --- Overall security posture (matches the audited-firm scale) ---
POSTURE_KEYS = ["excellent", "good", "balanced", "weak", "inadequate"]
POSTURE_COLORS = {
    "excellent": "#1E8449", "good": "#27AE60", "balanced": "#B9770E",
    "weak": "#D35400", "inadequate": "#A61B1B",
}
POSTURE_LABELS = {
    "en": {"excellent": "Excellent", "good": "Good", "balanced": "Balanced",
           "weak": "Weak", "inadequate": "Inadequate"},
    "ro": {"excellent": "Excelent", "good": "Bun", "balanced": "Echilibrat",
           "weak": "Slab", "inadequate": "Inadecvat"},
}
POSTURE_DESC = {
    "en": {
        "excellent": "The current security posture exceeds industry best-practice standards; only a few low-risk findings.",
        "good": "The current security posture meets some industry best-practice standards; a few medium/low-risk findings.",
        "balanced": "Current controls protect some areas; limited changes are needed to meet best-practice standards.",
        "weak": "There is a significant gap versus best-practice standards; the identified exposure areas need immediate attention and major changes.",
        "inadequate": "Serious deficiencies were identified across most or all examined controls; improving security requires major resource allocation.",
    },
    "ro": {
        "excellent": "Starea actuală de securitate depășește standardele «celor mai bune practici din industrie»; doar câteva constatări cu risc scăzut.",
        "good": "Starea actuală de securitate îndeplinește unele standarde «ale celor mai bune practici»; câteva vulnerabilități cu risc mediu și scăzut.",
        "balanced": "Soluțiile de securitate actuale protejează anumite zone; sunt necesare modificări limitate pentru a atinge standardele «celor mai bune practici».",
        "weak": "Există un decalaj semnificativ față de standardul «Industry Best Practice»; este necesară atenție imediată și schimbări majore.",
        "inadequate": "Au fost identificate deficiențe grave în majoritatea sau în toate controalele examinate; îmbunătățirea securității necesită o alocare majoră de resurse.",
    },
}


def _norm(value, keys):
    v = str(value or "").strip().lower()
    return v if v in keys else ""


def status_key(finding: dict) -> str:
    """Normalized status; defaults to 'present' when unset."""
    return _norm(finding.get("status"), STATUS_KEYS) or "present"


def status_label(finding: dict, lang: str) -> str:
    return STATUS_LABELS.get(lang, STATUS_LABELS["en"])[status_key(finding)]


def status_color(finding: dict) -> str:
    return STATUS_COLORS[status_key(finding)]


def exploit_key(finding: dict) -> str:
    return _norm(finding.get("exploitability"), EXPLOIT_KEYS)


def exploit_label(finding: dict, lang: str) -> str:
    k = exploit_key(finding)
    return EXPLOIT_LABELS.get(lang, EXPLOIT_LABELS["en"]).get(k, "") if k else ""


def exploit_color(finding: dict) -> str:
    k = exploit_key(finding)
    return EXPLOIT_COLORS.get(k, "#5D6D7E")


def posture_key(report: dict) -> str:
    return _norm(report.get("security_posture"), POSTURE_KEYS)


def posture_label(report: dict, lang: str) -> str:
    k = posture_key(report)
    return POSTURE_LABELS.get(lang, POSTURE_LABELS["en"]).get(k, "") if k else ""


def posture_color(report: dict) -> str:
    return POSTURE_COLORS.get(posture_key(report), "#5D6D7E")


def label_options(kind: str, lang: str) -> list[tuple[str, str]]:
    """(key, label) options for a UI selectbox. kind in status/exploit/posture."""
    if kind == "status":
        return [(k, STATUS_LABELS.get(lang, STATUS_LABELS["en"])[k]) for k in STATUS_KEYS]
    if kind == "exploit":
        return [(k, EXPLOIT_LABELS.get(lang, EXPLOIT_LABELS["en"])[k]) for k in EXPLOIT_KEYS]
    if kind == "posture":
        return [(k, POSTURE_LABELS.get(lang, POSTURE_LABELS["en"])[k]) for k in POSTURE_KEYS]
    return []
