# -*- coding: utf-8 -*-
"""Default Methodology section content (intro, legal framing, standards, tools).

Single, editable source of truth imported by the PDF, DOCX and HTML generators,
so the methodology wording is changed in ONE place instead of being duplicated
in each generator.

Per-report override: if a report sets ``methodology_intro`` (non-empty) that
text replaces the default intro paragraphs below. The standards / tools lists
are taken from here.
"""

# --- Intro paragraphs (rendered as normal text) ---
INTRO = {
    "ro": [
        "Tehnicile și metodele utilizate pentru identificarea, validarea și evaluarea "
        "vulnerabilităților se bazează pe bune practici și metodologii recunoscute la nivel "
        "internațional în domeniul securității cibernetice.",
        "Evaluarea a fost realizată prin aplicarea unor metode specifice de testare, adaptate "
        "tipului de infrastructură și serviciilor analizate, urmărindu-se identificarea "
        "vulnerabilităților, evaluarea impactului potențial și determinarea nivelului de risc asociat.",
    ],
    "en": [
        "The techniques and methods used to identify, validate and assess vulnerabilities are "
        "based on internationally recognized good practices and methodologies in the field of "
        "cyber security.",
        "The assessment was carried out by applying specific testing methods, adapted to the type "
        "of infrastructure and the services under review, aiming to identify vulnerabilities, "
        "assess their potential impact and determine the associated risk level.",
    ],
}

# --- Legal framing (NIS); {test_type} is filled by the generator ---
LEGAL = {
    "ro": ("Test de tip {test_type}, conform cerințelor Legii 362/2018 (transpunerea Directivei NIS). "
           "Nivelul de impact al vulnerabilităților a fost evaluat conform ORDINULUI DNSC nr. 559 din "
           "22 martie 2021, iar severitatea tehnică conform CVSS."),
    "en": ("{test_type} assessment performed in accordance with Law 362/2018 (NIS Directive). "
           "Vulnerability impact was rated per DNSC Order no. 559/2021 and technical severity per CVSS."),
}

# --- Standards & good-practice guides ---
STANDARDS_LEAD = {
    "ro": "Metodologia de testare a avut la bază, după caz, următoarele standarde și ghiduri de bune practici:",
    "en": "The testing methodology was based, as applicable, on the following standards and good-practice guides:",
}

STANDARDS = {
    "ro": [
        "Penetration Testing Execution Standard (PTES)",
        "National Institute of Standards and Technology (NIST), inclusiv NIST SP 800-115 – Technical Guide to Information Security Testing and Assessment",
        "Open Source Security Testing Methodology Manual (OSSTMM)",
        "OWASP Testing Guide",
        "Penetration Testing Framework",
        "SANS – Conducting a Penetration Test on an Organization",
        "cerințele și recomandările aplicabile din cadrul legislativ național privind securitatea rețelelor și a sistemelor informatice",
    ],
    "en": [
        "Penetration Testing Execution Standard (PTES)",
        "National Institute of Standards and Technology (NIST), including NIST SP 800-115 – Technical Guide to Information Security Testing and Assessment",
        "Open Source Security Testing Methodology Manual (OSSTMM)",
        "OWASP Testing Guide",
        "Penetration Testing Framework",
        "SANS – Conducting a Penetration Test on an Organization",
        "applicable requirements and recommendations of the national legal framework on the security of networks and information systems",
    ],
}

# --- Example tools, grouped by activity: list of (category, tools) ---
TOOLS = {
    "ro": [
        ("Pentru descoperirea de informații și amprentare", "Nmap, smbmap, dnsenum, Hping, netcat"),
        ("Pentru testarea aplicațiilor web", "Burp Suite, Sqlmap, John the Ripper, Arachni, wpscan, joomscan"),
        ("Pentru testarea rețelelor și a infrastructurii", "Nessus, OpenVAS, Nmap, Wireshark, mimikatz, msfvenom, Metasploit Framework"),
        ("Alte instrumente", "Hydra, Hashcat, Metasploit Framework, theHarvester, TestSSL, Routersploit etc."),
    ],
    "en": [
        ("Information gathering and fingerprinting", "Nmap, smbmap, dnsenum, Hping, netcat"),
        ("Web application testing", "Burp Suite, Sqlmap, John the Ripper, Arachni, wpscan, joomscan"),
        ("Network and infrastructure testing", "Nessus, OpenVAS, Nmap, Wireshark, mimikatz, msfvenom, Metasploit Framework"),
        ("Other tools", "Hydra, Hashcat, Metasploit Framework, theHarvester, TestSSL, Routersploit, etc."),
    ],
}


def _pick(table, lang):
    return table.get(lang) or table["en"]


def intro(report, lang="en"):
    """Intro paragraphs: the report's methodology_intro override, else the default list."""
    custom = str((report or {}).get("methodology_intro") or "").strip()
    if custom:
        return [p.strip() for p in custom.replace("\r\n", "\n").split("\n\n") if p.strip()]
    return list(_pick(INTRO, lang))


def legal(lang="en", test_type="Black Box"):
    return _pick(LEGAL, lang).format(test_type=test_type or "Black Box")


def standards_lead(lang="en"):
    return _pick(STANDARDS_LEAD, lang)


def standards(lang="en"):
    return list(_pick(STANDARDS, lang))


def tools(lang="en"):
    return list(_pick(TOOLS, lang))
