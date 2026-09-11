"""Default confidentiality & legal texts for report sections 1.0 - 1.2.

Single, editable source of truth. The PDF, DOCX and HTML generators import
these defaults instead of each keeping its own copy, so the default wording is
changed in ONE place. Per-report overrides saved in the report JSON (the same
``section_1_0_confidentiality_and_legal`` / ``_1_1_confidentiality_statement``
/ ``_1_2_disclaimer`` keys) still take precedence; the texts below are only the
fallback used when a report carries no custom wording.

To change a default, edit the string below. Keep the two languages in sync.
"""

SECTION_KEYS = (
    "section_1_0_confidentiality_and_legal",
    "section_1_1_confidentiality_statement",
    "section_1_2_disclaimer",
)

SECTION_DEFAULTS = {
    "en": {
        "section_1_0_confidentiality_and_legal": (
            "This penetration testing report contains confidential information intended solely for the client organization. "
            "Unauthorized access, distribution, disclosure, or copying of this document or any information contained herein is strictly prohibited. "
            "All findings, methodologies, and artifacts are the intellectual property of the security testing provider unless otherwise stated."
        ),
        "section_1_1_confidentiality_statement": (
            "Findings are provided for informational purposes only and represent the system state at the time of testing only. "
            "The client is solely responsible for implementing and verifying any remediation actions. "
            "The testing team disclaims all liability for any damages resulting from the use of this report or the authorized testing activities."
        ),
        "section_1_2_disclaimer": (
            "This penetration test was conducted exclusively in accordance with the Rules of Engagement and Statement of Work signed by the Client. "
            "No warranties of any kind, express or implied, are provided. The Testing Team and its personnel shall not be held liable for any direct, indirect, incidental, consequential, or punitive damages arising from the use or misuse of this report, its findings, or any actions taken as a result thereof. The report is delivered as is."
        ),
    },
    "ro": {
        "section_1_0_confidentiality_and_legal": (
            "Acest raport de testare de securitate conține informații confidențiale, destinate exclusiv organizației client. "
            "Accesul, distribuția, divulgarea sau copierea neautorizată a acestui document sau a oricărei informații conținute în el sunt strict interzise. "
            "Toate constatările, metodologiile și artefactele rămân proprietatea intelectuală a furnizorului de servicii de securitate, cu excepția cazurilor menționate explicit."
        ),
        "section_1_1_confidentiality_statement": (
            "Constatările sunt furnizate exclusiv în scop informativ și reflectă starea sistemelor la momentul testării. "
            "Clientul este singurul responsabil pentru implementarea și verificarea oricăror măsuri de remediere. "
            "Echipa de testare declină orice răspundere pentru eventualele daune rezultate din utilizarea acestui raport sau din activitățile de testare autorizate."
        ),
        "section_1_2_disclaimer": (
            "Testarea a fost efectuată exclusiv în conformitate cu regulile de angajament (Rules of Engagement) și cu documentul de definire a lucrărilor (Statement of Work) semnate de client. "
            "Nu se oferă nicio garanție, expresă sau implicită. Echipa de testare și personalul acesteia nu pot fi trași la răspundere pentru daune directe, indirecte, incidentale, subsecvente sau punitive care decurg din utilizarea sau utilizarea necorespunzătoare a acestui raport, a constatărilor sale sau a oricăror acțiuni întreprinse ca urmare a acestora. Raportul este furnizat ca atare, fără garanții."
        ),
    },
}


def section_default(key: str, lang: str = "en") -> str:
    """Return the default text for a section key in ``lang`` (falls back to EN)."""
    table = SECTION_DEFAULTS.get(lang) or SECTION_DEFAULTS["en"]
    return table.get(key) or SECTION_DEFAULTS["en"].get(key, "")
