# util/narrative.py
"""
Auto-drafts an executive-summary narrative from the findings data, used as a
starting point when the tester has not written one. Deterministic: it only
states counts, hosts and finding titles that are actually present – it never
invents facts. Bilingual (en / ro) following the report language.
"""
from __future__ import annotations
from collections import Counter

SEV_ORDER = ["Critical", "High", "Moderate", "Low", "Informational"]


def _host_count(findings: list[dict]) -> int:
    hosts = set()
    for f in findings or []:
        h = f.get("host")
        if h:
            hosts.add(str(h))
        for hh in f.get("hosts", []) or []:
            if hh:
                hosts.add(str(hh))
    return len(hosts)


def _top_titles(findings: list[dict], severities, limit=3) -> list[str]:
    out = []
    for f in findings or []:
        if f.get("severity") in severities and f.get("title"):
            out.append(str(f["title"]))
        if len(out) >= limit:
            break
    return out


def executive_narrative(report: dict, findings: list[dict], lang: str = "en") -> str:
    findings = findings or []
    counts = Counter((f.get("severity") or "Informational") for f in findings)
    total = sum(counts.values())
    n_hosts = _host_count(findings)
    client = str(report.get("client") or "").strip()
    project = str(report.get("project") or "").strip()
    crit, high = counts.get("Critical", 0), counts.get("High", 0)
    priority = crit + high
    top = _top_titles(findings, {"Critical", "High"}) or _top_titles(findings, set(SEV_ORDER))
    themes = "; ".join(top)
    ro = lang == "ro"

    if total == 0:
        if ro:
            return ("Această evaluare nu a identificat vulnerabilități în perimetrul testat. "
                    "Rezultatul reflectă starea sistemelor la momentul testării și nu garantează "
                    "absența unor probleme în afara scopului sau apărute ulterior.")
        return ("This assessment identified no vulnerabilities within the tested scope. "
                "The result reflects the state of the systems at the time of testing and does not "
                "guarantee the absence of issues outside scope or arising afterwards.")

    if ro:
        who = f" pentru {client}" if client else ""
        proj = f' („{project}")' if project else ""
        finding_word = "constatare" if total == 1 else "constatări"
        host_word = "gazdă" if n_hosts == 1 else "gazde"
        host_frag = f" pe {n_hosts} {host_word}" if n_hosts else ""
        p1 = (f"În cadrul angajamentului de testare a securității{who}{proj}, au fost evaluate "
              f"sistemele din scopul convenit. Evaluarea a identificat {total} {finding_word}{host_frag}.")
        if priority:
            crit_verb = "este" if crit == 1 else "sunt"
            p2 = (f"Dintre acestea, {crit} {crit_verb} de severitate Critică și {high} Ridicată, ceea ce "
                  "reprezintă un risc care necesită acțiune prioritară. Exploatarea acestor probleme ar "
                  "putea permite compromiterea sistemelor afectate sau accesul neautorizat la date și "
                  "procese sensibile.")
        else:
            p2 = ("Nu au fost identificate probleme de severitate Critică sau Ridicată; constatările "
                  "țin în principal de igiena de securitate și de reducerea suprafeței de atac.")
        p3 = (f"Temele principale includ: {themes}. " if themes else "")
        p3 += ("Recomandăm remedierea prioritizată în funcție de severitate și de expunerea reală, "
               "conform planului de remediere și mapării de conformitate din acest raport.")
        return "\n\n".join([p1, p2, p3])

    who = f" for {client}" if client else ""
    proj = f' ("{project}")' if project else ""
    finding_word = "finding" if total == 1 else "findings"
    host_word = "host" if n_hosts == 1 else "hosts"
    host_frag = f" across {n_hosts} {host_word}" if n_hosts else ""
    p1 = (f"During the security assessment{who}{proj}, the in-scope systems were evaluated. "
          f"The assessment identified {total} {finding_word}{host_frag}.")
    if priority:
        crit_verb = "is" if crit == 1 else "are"
        p2 = (f"Of these, {crit} {crit_verb} rated Critical and {high} High, representing risk that "
              "warrants priority action. Exploitation of these issues could allow compromise of the "
              "affected systems or unauthorized access to sensitive data and processes.")
    else:
        p2 = ("No Critical or High severity issues were identified; the findings relate mainly to "
              "security hygiene and attack-surface reduction.")
    p3 = (f"Key themes include: {themes}. " if themes else "")
    p3 += ("Remediation should be prioritised by severity and real-world exposure, following the "
           "remediation roadmap and the compliance mapping provided in this report.")
    return "\n\n".join([p1, p2, p3])
