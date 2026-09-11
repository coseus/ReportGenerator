# -*- coding: utf-8 -*-
"""Default Attack Chain (Lanț de atac) section content.

Fixed, generic boilerplate imported by the PDF, DOCX and HTML generators and
included automatically in section 2.2 of every report — it is NOT taken from
the report JSON. Edit the texts here to change the wording for all reports.
"""

INTRO = {
    "ro": [
        "Analiza lanțului de atac urmărește modul în care informațiile și vulnerabilitățile "
        "identificate în cadrul evaluării ar putea fi corelate de un atacator pentru a obține "
        "acces inițial, a-și consolida poziția și, ulterior, a extinde compromiterea către alte "
        "sisteme sau segmente ale infrastructurii.",
        "În cadrul prezentei evaluări, lanțul de atac reprezintă o analiză teoretică a posibilului "
        "traseu de compromitere, construită pe baza serviciilor și informațiilor identificate în "
        "timpul activităților de evaluare. Nu toate etapele prezentate au fost executate sau "
        "validate prin exploatare activă.",
    ],
    "en": [
        "The attack chain analysis describes how information and vulnerabilities identified during "
        "the assessment could potentially be combined by an attacker to obtain initial access, "
        "establish a foothold, and subsequently expand access to additional systems or network segments.",
        "For this assessment, the attack chain represents a theoretical attack path based on services, "
        "technologies, and information identified during the assessment activities. Not all stages "
        "described below were executed or validated through active exploitation.",
    ],
}

STAGES_TITLE = {
    "ro": "Etapele generale ale lanțului de atac",
    "en": "General Attack Chain Stages",
}

STAGES = {
    "ro": [
        ("Recunoaștere și identificarea suprafeței de atac",
         "identificarea adreselor IP publice, a serviciilor expuse, a protocoalelor, versiunilor de "
         "produse, certificatelor digitale, informațiilor despre sisteme și a altor metadate accesibile din Internet."),
        ("Identificarea punctelor de intrare",
         "evaluarea serviciilor expuse din perspectiva riscului de compromitere, cu accent pe serviciile "
         "de administrare, aplicațiile, bazele de date și componentele de infrastructură accesibile din Internet."),
        ("Compromiterea inițială",
         "în funcție de vulnerabilitățile identificate, un atacator ar putea încerca exploatarea unei "
         "vulnerabilități, utilizarea unor credențiale compromise sau efectuarea unor atacuri asupra "
         "mecanismelor de autentificare. În cadrul acestei evaluări nu au fost efectuate atacuri asupra "
         "credențialelor și nu a fost realizată exploatarea activă a vulnerabilităților."),
        ("Consolidarea accesului",
         "în cazul obținerii accesului la un sistem, un atacator ar putea încerca identificarea conturilor, "
         "serviciilor, configurațiilor și a altor informații care ar permite menținerea sau extinderea accesului."),
        ("Escaladarea privilegiilor",
         "accesul inițial ar putea fi utilizat pentru identificarea unor posibilități de obținere a unor "
         "privilegii suplimentare, inclusiv prin vulnerabilități locale, configurații necorespunzătoare sau "
         "expunerea unor servicii administrative."),
        ("Mișcare laterală",
         "informațiile despre domeniu, hosturi, rețele interne și servicii accesibile ar putea facilita "
         "identificarea și accesarea altor sisteme din infrastructură."),
        ("Impact potențial",
         "în funcție de nivelul privilegiilor obținute, compromiterea unui sistem expus poate reprezenta un "
         "punct de plecare pentru accesarea altor sisteme, modificarea configurațiilor de securitate, "
         "accesarea datelor sau afectarea disponibilității serviciilor."),
    ],
    "en": [
        ("Reconnaissance and attack surface identification",
         "identification of publicly accessible IP addresses, exposed services, protocols, product versions, "
         "digital certificates, system information, and other metadata available from the Internet."),
        ("Entry point identification",
         "assessment of exposed services from an attack perspective, with particular attention to administrative "
         "interfaces, applications, databases, and infrastructure components accessible from the Internet."),
        ("Initial compromise",
         "depending on the vulnerabilities identified, an attacker could attempt to exploit a vulnerability, use "
         "compromised credentials, or target authentication mechanisms. No credential attacks and no active "
         "exploitation of vulnerabilities were performed as part of this assessment."),
        ("Establishing a foothold",
         "following successful access to a system, an attacker could attempt to identify accounts, services, "
         "configurations, and other information that could facilitate persistence or further access."),
        ("Privilege escalation",
         "initial access could potentially be leveraged to obtain additional privileges through local "
         "vulnerabilities, insecure configurations, excessive permissions, or exposed administrative services."),
        ("Lateral movement",
         "information relating to domains, hosts, internal networks, and accessible services could facilitate "
         "the identification and targeting of additional systems within the environment."),
        ("Potential impact",
         "depending on the privileges obtained, compromise of an externally exposed system could provide a "
         "starting point for accessing additional systems, modifying security controls, accessing sensitive "
         "information, or affecting service availability."),
    ],
}

LIMITATION_TITLE = {
    "ro": "Limitarea analizei",
    "en": "Analysis Limitation",
}

LIMITATION = {
    "ro": [
        "Lanțul de atac prezentat are caracter analitic și ipotetic și nu trebuie interpretat ca o secvență "
        "de atac executată integral în cadrul acestei evaluări. Activitățile efectiv realizate sunt cele "
        "documentate în secțiunile de metodologie și rezultate ale raportului.",
        "Informațiile de recunoaștere și identificare a suprafeței de atac prezentate în raport sunt bazate pe "
        "observații efectiv obținute în timpul evaluării. În schimb, exploatarea activă, atacurile asupra "
        "credențialelor, escaladarea privilegiilor și mișcarea laterală nu au fost executate, dacă nu sunt "
        "menționate explicit în rezultatele testării.",
        "Validarea practică a unui astfel de lanț, inclusiv confirmarea impactului asupra sistemelor interne, "
        "necesită un Penetration Test autorizat, desfășurat în condiții și cu reguli de engagement definite în prealabil.",
    ],
    "en": [
        "The attack chain presented above is analytical and hypothetical and should not be interpreted as a "
        "fully executed attack sequence during this assessment. The activities actually performed are documented "
        "in the methodology and findings sections of the report.",
        "Reconnaissance and attack-surface information presented in the report is based on information actually "
        "obtained during the assessment. However, active exploitation, credential attacks, privilege escalation, "
        "and lateral movement were not performed unless explicitly documented as executed within the assessment results.",
        "Practical validation of such an attack chain, including confirmation of the potential impact on internal "
        "systems, requires an authorized Penetration Test performed under predefined Rules of Engagement.",
    ],
}


def _pick(table, lang):
    return table.get(lang) or table["en"]


def intro(lang="en"):
    return list(_pick(INTRO, lang))


def stages_title(lang="en"):
    return _pick(STAGES_TITLE, lang)


def stages(lang="en"):
    return list(_pick(STAGES, lang))


def limitation_title(lang="en"):
    return _pick(LIMITATION_TITLE, lang)


def limitation(lang="en"):
    return list(_pick(LIMITATION, lang))
