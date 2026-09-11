# util/control_mapper.py
"""
Self-contained control library, classifier and auto-association engine for:

  * NIS2 Directive (art. 21(2) measures)
  * ISO/IEC 27001:2022 (Annex A, all 93 controls)
  * NIST Cybersecurity Framework 2.0 (all subcategories)
  * NIST SP 800-53 Rev. 5 (comprehensive control set, all families)
  * IEC 62443-3-3 (all 51 System Requirements) -- OT / ICS

Everything the feature needs lives in this one file: the control catalogs,
the finding classifier (keyword + category driven, incl. OT-specific
categories), the automatic association of relevant controls across all
frameworks, the Streamlit UI helpers and the report helpers.

Streamlit is imported lazily (only inside the render_* helpers) so the logic
part can be imported anywhere (parsers, report generators, tests) without a
hard Streamlit dependency.
"""
from __future__ import annotations
from typing import Any

# ---------------------------------------------------------------------------
# Frameworks
# ---------------------------------------------------------------------------
FRAMEWORK_KEYS = ["nis2", "iso27001", "nist_csf", "nist_800_53", "iec62443"]
FRAMEWORK_LABELS = {
    "nis2": "NIS2 art.21(2)",
    "iso27001": "ISO/IEC 27001:2022",
    "nist_csf": "NIST CSF 2.0",
    "nist_800_53": "NIST SP 800-53",
    "iec62443": "IEC 62443-3-3",
}
# Frameworks shown in the exported report by default (IEC is opt-in to keep the
# table readable; it is always available in the tab and in classification).
DEFAULT_REPORT_FRAMEWORKS = ["nis2", "iso27001", "nist_csf", "nist_800_53"]

# ---------------------------------------------------------------------------
# NIS2 -- art. 21(2) measures
# ---------------------------------------------------------------------------
NIS2_CONTROLS = {
    "21(2)(a)": "Risk analysis and information system security policies",
    "21(2)(b)": "Incident handling",
    "21(2)(c)": "Business continuity, backup management and disaster recovery, crisis management",
    "21(2)(d)": "Supply chain security",
    "21(2)(e)": "Security in acquisition, development and maintenance, incl. vulnerability handling and disclosure",
    "21(2)(f)": "Policies and procedures to assess the effectiveness of cyber risk-management measures",
    "21(2)(g)": "Basic cyber hygiene practices and cybersecurity training",
    "21(2)(h)": "Cryptography and, where appropriate, encryption",
    "21(2)(i)": "Human resources security, access control policies and asset management",
    "21(2)(j)": "Multi-factor authentication, secured communications and secured emergency communications",
}

# ---------------------------------------------------------------------------
# ISO/IEC 27001:2022 Annex A -- all 93 controls
# ---------------------------------------------------------------------------
ISO27001_CONTROLS = {
    "A.5.1": "Policies for information security",
    "A.5.2": "Information security roles and responsibilities",
    "A.5.3": "Segregation of duties",
    "A.5.4": "Management responsibilities",
    "A.5.5": "Contact with authorities",
    "A.5.6": "Contact with special interest groups",
    "A.5.7": "Threat intelligence",
    "A.5.8": "Information security in project management",
    "A.5.9": "Inventory of information and other associated assets",
    "A.5.10": "Acceptable use of information and other associated assets",
    "A.5.11": "Return of assets",
    "A.5.12": "Classification of information",
    "A.5.13": "Labelling of information",
    "A.5.14": "Information transfer",
    "A.5.15": "Access control",
    "A.5.16": "Identity management",
    "A.5.17": "Authentication information",
    "A.5.18": "Access rights",
    "A.5.19": "Information security in supplier relationships",
    "A.5.20": "Addressing information security within supplier agreements",
    "A.5.21": "Managing information security in the ICT supply chain",
    "A.5.22": "Monitoring, review and change management of supplier services",
    "A.5.23": "Information security for use of cloud services",
    "A.5.24": "Information security incident management planning and preparation",
    "A.5.25": "Assessment and decision on information security events",
    "A.5.26": "Response to information security incidents",
    "A.5.27": "Learning from information security incidents",
    "A.5.28": "Collection of evidence",
    "A.5.29": "Information security during disruption",
    "A.5.30": "ICT readiness for business continuity",
    "A.5.31": "Legal, statutory, regulatory and contractual requirements",
    "A.5.32": "Intellectual property rights",
    "A.5.33": "Protection of records",
    "A.5.34": "Privacy and protection of PII",
    "A.5.35": "Independent review of information security",
    "A.5.36": "Compliance with policies, rules and standards for information security",
    "A.5.37": "Documented operating procedures",
    "A.6.1": "Screening",
    "A.6.2": "Terms and conditions of employment",
    "A.6.3": "Information security awareness, education and training",
    "A.6.4": "Disciplinary process",
    "A.6.5": "Responsibilities after termination or change of employment",
    "A.6.6": "Confidentiality or non-disclosure agreements",
    "A.6.7": "Remote working",
    "A.6.8": "Information security event reporting",
    "A.7.1": "Physical security perimeters",
    "A.7.2": "Physical entry",
    "A.7.3": "Securing offices, rooms and facilities",
    "A.7.4": "Physical security monitoring",
    "A.7.5": "Protecting against physical and environmental threats",
    "A.7.6": "Working in secure areas",
    "A.7.7": "Clear desk and clear screen",
    "A.7.8": "Equipment siting and protection",
    "A.7.9": "Security of assets off-premises",
    "A.7.10": "Storage media",
    "A.7.11": "Supporting utilities",
    "A.7.12": "Cabling security",
    "A.7.13": "Equipment maintenance",
    "A.7.14": "Secure disposal or re-use of equipment",
    "A.8.1": "User endpoint devices",
    "A.8.2": "Privileged access rights",
    "A.8.3": "Information access restriction",
    "A.8.4": "Access to source code",
    "A.8.5": "Secure authentication",
    "A.8.6": "Capacity management",
    "A.8.7": "Protection against malware",
    "A.8.8": "Management of technical vulnerabilities",
    "A.8.9": "Configuration management",
    "A.8.10": "Information deletion",
    "A.8.11": "Data masking",
    "A.8.12": "Data leakage prevention",
    "A.8.13": "Information backup",
    "A.8.14": "Redundancy of information processing facilities",
    "A.8.15": "Logging",
    "A.8.16": "Monitoring activities",
    "A.8.17": "Clock synchronization",
    "A.8.18": "Use of privileged utility programs",
    "A.8.19": "Installation of software on operational systems",
    "A.8.20": "Networks security",
    "A.8.21": "Security of network services",
    "A.8.22": "Segregation of networks",
    "A.8.23": "Web filtering",
    "A.8.24": "Use of cryptography",
    "A.8.25": "Secure development life cycle",
    "A.8.26": "Application security requirements",
    "A.8.27": "Secure system architecture and engineering principles",
    "A.8.28": "Secure coding",
    "A.8.29": "Security testing in development and acceptance",
    "A.8.30": "Outsourced development",
    "A.8.31": "Separation of development, test and production environments",
    "A.8.32": "Change management",
    "A.8.33": "Test information",
    "A.8.34": "Protection of information systems during audit testing",
}

# ---------------------------------------------------------------------------
# NIST CSF 2.0 -- all subcategories
# ---------------------------------------------------------------------------
NIST_CSF_CONTROLS = {
    "GV.OC-01": "The organizational mission is understood and informs cyber risk management",
    "GV.OC-02": "Internal and external stakeholders are understood",
    "GV.OC-03": "Legal, regulatory and contractual requirements are understood and managed",
    "GV.OC-04": "Critical objectives, capabilities and services stakeholders depend on are understood",
    "GV.OC-05": "Outcomes, capabilities and services the organization depends on are understood",
    "GV.RM-01": "Risk management objectives are established and agreed by stakeholders",
    "GV.RM-02": "Risk appetite and risk tolerance statements are established and communicated",
    "GV.RM-03": "Cybersecurity risk management is integrated into enterprise risk management",
    "GV.RM-04": "Strategic direction describing risk response options is established",
    "GV.RM-05": "Lines of communication across the organization are established for cyber risks",
    "GV.RM-06": "A standardized method for calculating, documenting and prioritizing risk is established",
    "GV.RM-07": "Strategic opportunities (positive risks) are characterized and included",
    "GV.RR-01": "Organizational leadership is accountable for cybersecurity risk",
    "GV.RR-02": "Roles, responsibilities and authorities are established, communicated and enforced",
    "GV.RR-03": "Adequate resources are allocated commensurate with the risk strategy",
    "GV.RR-04": "Cybersecurity is included in human resources practices",
    "GV.PO-01": "Policy for managing cybersecurity risks is established and communicated",
    "GV.PO-02": "Policy is reviewed, updated, communicated and enforced",
    "GV.OV-01": "Cybersecurity risk management strategy outcomes are reviewed",
    "GV.OV-02": "The risk management strategy is reviewed and adjusted",
    "GV.OV-03": "Cybersecurity risk management performance is evaluated and reviewed",
    "GV.SC-01": "A cyber supply chain risk management program and strategy are established",
    "GV.SC-02": "Cyber roles and responsibilities for suppliers are established and coordinated",
    "GV.SC-03": "Supply chain risk management is integrated into cybersecurity and enterprise risk management",
    "GV.SC-04": "Suppliers are known and prioritized by criticality",
    "GV.SC-05": "Requirements to address cyber risks in supply chains are established in agreements",
    "GV.SC-06": "Planning and due diligence are performed before entering supplier relationships",
    "GV.SC-07": "Risks posed by suppliers and their products are understood and managed",
    "GV.SC-08": "Relevant suppliers are included in incident planning, response and recovery",
    "GV.SC-09": "Supply chain security practices are integrated into cybersecurity programs",
    "GV.SC-10": "Supply chain risk management plans include provisions for post-partnership activities",
    "ID.AM-01": "Inventories of hardware managed by the organization are maintained",
    "ID.AM-02": "Inventories of software, services and systems are maintained",
    "ID.AM-03": "Representations of network communication and internal/external data flows are maintained",
    "ID.AM-04": "Inventories of services provided by suppliers are maintained",
    "ID.AM-05": "Assets are prioritized based on classification, criticality, resources and impact",
    "ID.AM-07": "Inventories of data and corresponding metadata are maintained",
    "ID.AM-08": "Systems, hardware, software, services and data are managed through their life cycle",
    "ID.RA-01": "Vulnerabilities in assets are identified, validated and recorded",
    "ID.RA-02": "Cyber threat intelligence is received from information sharing sources",
    "ID.RA-03": "Internal and external threats to the organization are identified and recorded",
    "ID.RA-04": "Potential impacts and likelihoods of threats exploiting vulnerabilities are identified",
    "ID.RA-05": "Threats, vulnerabilities, likelihoods and impacts are used to understand inherent risk",
    "ID.RA-06": "Risk responses are chosen, prioritized, planned, tracked and communicated",
    "ID.RA-07": "Changes and exceptions are managed, assessed for impact, recorded and tracked",
    "ID.RA-08": "Processes for receiving, analyzing and responding to vulnerability disclosures are established",
    "ID.RA-09": "The authenticity and integrity of hardware and software are assessed before acquisition and use",
    "ID.RA-10": "Critical suppliers are assessed prior to acquisition",
    "ID.IM-01": "Improvements are identified from evaluations",
    "ID.IM-02": "Improvements are identified from security tests and exercises, incl. those with suppliers",
    "ID.IM-03": "Improvements are identified from operational processes, procedures and activities",
    "ID.IM-04": "Incident response plans and other cybersecurity plans are established, communicated and improved",
    "PR.AA-01": "Identities and credentials for authorized users, services and hardware are managed",
    "PR.AA-02": "Identities are proofed and bound to credentials based on the context of interactions",
    "PR.AA-03": "Users, services and hardware are authenticated",
    "PR.AA-04": "Identity assertions are protected, conveyed and verified",
    "PR.AA-05": "Access permissions, entitlements and authorizations follow least privilege and separation of duties",
    "PR.AA-06": "Physical access to assets is managed, monitored and enforced commensurate with risk",
    "PR.AT-01": "Personnel are provided with awareness and training to perform general tasks securely",
    "PR.AT-02": "Individuals in specialized roles are provided with awareness and training",
    "PR.DS-01": "The confidentiality, integrity and availability of data-at-rest are protected",
    "PR.DS-02": "The confidentiality, integrity and availability of data-in-transit are protected",
    "PR.DS-10": "The confidentiality, integrity and availability of data-in-use are protected",
    "PR.DS-11": "Backups of data are created, protected, maintained and tested",
    "PR.PS-01": "Configuration management practices are established and applied",
    "PR.PS-02": "Software is maintained, replaced and removed commensurate with risk",
    "PR.PS-03": "Hardware is maintained, replaced and removed commensurate with risk",
    "PR.PS-04": "Log records are generated and made available for continuous monitoring",
    "PR.PS-05": "Installation and execution of unauthorized software are prevented",
    "PR.PS-06": "Secure software development practices are integrated and monitored",
    "PR.IR-01": "Networks and environments are protected from unauthorized logical access and usage",
    "PR.IR-02": "The organization's technology assets are protected from environmental threats",
    "PR.IR-03": "Mechanisms are implemented to achieve resilience requirements in normal and adverse situations",
    "PR.IR-04": "Adequate resource capacity to ensure availability is maintained",
    "DE.CM-01": "Networks and network services are monitored to find potentially adverse events",
    "DE.CM-02": "The physical environment is monitored to find potentially adverse events",
    "DE.CM-03": "Personnel activity and technology usage are monitored",
    "DE.CM-06": "External service provider activities and services are monitored",
    "DE.CM-09": "Computing hardware and software, runtime environments and their data are monitored",
    "DE.AE-02": "Potentially adverse events are analyzed to better understand associated activities",
    "DE.AE-03": "Information is correlated from multiple sources",
    "DE.AE-04": "The estimated impact and scope of adverse events are understood",
    "DE.AE-06": "Information on adverse events is provided to authorized staff and tools",
    "DE.AE-07": "Cyber threat intelligence and other contextual information are integrated into the analysis",
    "DE.AE-08": "Incidents are declared when adverse events meet the defined incident criteria",
    "RS.MA-01": "The incident response plan is executed once an incident is declared",
    "RS.MA-02": "Incident reports are triaged and validated",
    "RS.MA-03": "Incidents are categorized and prioritized",
    "RS.MA-04": "Incidents are escalated or elevated as needed",
    "RS.MA-05": "The criteria for initiating incident recovery are applied",
    "RS.AN-03": "Analysis is performed to establish what has taken place and the root cause",
    "RS.AN-06": "Actions performed during an investigation are recorded and their integrity preserved",
    "RS.AN-07": "Incident data and metadata are collected and their integrity preserved",
    "RS.AN-08": "An incident's magnitude is estimated and validated",
    "RS.CO-02": "Internal and external stakeholders are notified of incidents",
    "RS.CO-03": "Information is shared with designated internal and external stakeholders",
    "RS.MI-01": "Incidents are contained",
    "RS.MI-02": "Incidents are eradicated",
    "RC.RP-01": "The recovery portion of the incident response plan is executed once initiated",
    "RC.RP-02": "Recovery actions are selected, scoped, prioritized and performed",
    "RC.RP-03": "The integrity of backups and other restoration assets is verified before use",
    "RC.RP-04": "Critical mission functions and cybersecurity risk management are considered during recovery",
    "RC.RP-05": "The integrity of restored assets is verified, systems and services restored, normal status confirmed",
    "RC.RP-06": "The end of incident recovery is declared and incident-related documentation completed",
    "RC.CO-03": "Recovery activities and progress are communicated to designated stakeholders",
    "RC.CO-04": "Public updates on incident recovery are shared using approved methods and messaging",
}

# ---------------------------------------------------------------------------
# NIST SP 800-53 Rev.5 -- comprehensive control set (all families)
# ---------------------------------------------------------------------------
NIST_80053_CONTROLS = {
    "AC-1": "Policy and Procedures", "AC-2": "Account Management", "AC-3": "Access Enforcement",
    "AC-4": "Information Flow Enforcement", "AC-5": "Separation of Duties", "AC-6": "Least Privilege",
    "AC-7": "Unsuccessful Logon Attempts", "AC-8": "System Use Notification", "AC-11": "Device Lock",
    "AC-12": "Session Termination", "AC-17": "Remote Access", "AC-18": "Wireless Access",
    "AC-19": "Access Control for Mobile Devices", "AC-20": "Use of External Systems",
    "AC-22": "Publicly Accessible Content",
    "AT-1": "Policy and Procedures", "AT-2": "Literacy Training and Awareness",
    "AT-3": "Role-Based Training", "AT-4": "Training Records",
    "AU-1": "Policy and Procedures", "AU-2": "Event Logging", "AU-3": "Content of Audit Records",
    "AU-4": "Audit Log Storage Capacity", "AU-5": "Response to Audit Logging Process Failures",
    "AU-6": "Audit Record Review, Analysis and Reporting", "AU-8": "Time Stamps",
    "AU-9": "Protection of Audit Information", "AU-11": "Audit Record Retention",
    "AU-12": "Audit Record Generation",
    "CA-1": "Policy and Procedures", "CA-2": "Control Assessments", "CA-3": "Information Exchange",
    "CA-5": "Plan of Action and Milestones", "CA-6": "Authorization",
    "CA-7": "Continuous Monitoring", "CA-8": "Penetration Testing", "CA-9": "Internal System Connections",
    "CM-1": "Policy and Procedures", "CM-2": "Baseline Configuration", "CM-3": "Configuration Change Control",
    "CM-4": "Impact Analyses", "CM-5": "Access Restrictions for Change", "CM-6": "Configuration Settings",
    "CM-7": "Least Functionality", "CM-8": "System Component Inventory",
    "CM-10": "Software Usage Restrictions", "CM-11": "User-Installed Software",
    "CP-1": "Policy and Procedures", "CP-2": "Contingency Plan", "CP-3": "Contingency Training",
    "CP-4": "Contingency Plan Testing", "CP-6": "Alternate Storage Site", "CP-7": "Alternate Processing Site",
    "CP-9": "System Backup", "CP-10": "System Recovery and Reconstitution",
    "IA-1": "Policy and Procedures", "IA-2": "Identification and Authentication (Organizational Users)",
    "IA-2(1)": "Multi-factor Authentication to Privileged Accounts",
    "IA-2(2)": "Multi-factor Authentication to Non-privileged Accounts",
    "IA-3": "Device Identification and Authentication", "IA-4": "Identifier Management",
    "IA-5": "Authenticator Management", "IA-6": "Authentication Feedback",
    "IA-7": "Cryptographic Module Authentication", "IA-8": "Identification and Authentication (Non-Org Users)",
    "IA-11": "Re-authentication",
    "IR-1": "Policy and Procedures", "IR-2": "Incident Response Training", "IR-3": "Incident Response Testing",
    "IR-4": "Incident Handling", "IR-5": "Incident Monitoring", "IR-6": "Incident Reporting",
    "IR-7": "Incident Response Assistance", "IR-8": "Incident Response Plan",
    "MA-1": "Policy and Procedures", "MA-2": "Controlled Maintenance", "MA-3": "Maintenance Tools",
    "MA-4": "Nonlocal Maintenance", "MA-5": "Maintenance Personnel",
    "MP-1": "Policy and Procedures", "MP-2": "Media Access", "MP-4": "Media Storage",
    "MP-5": "Media Transport", "MP-6": "Media Sanitization", "MP-7": "Media Use",
    "PE-1": "Policy and Procedures", "PE-2": "Physical Access Authorizations", "PE-3": "Physical Access Control",
    "PE-6": "Monitoring Physical Access", "PE-8": "Visitor Access Records",
    "PL-1": "Policy and Procedures", "PL-2": "System Security and Privacy Plans",
    "PL-4": "Rules of Behavior", "PL-8": "Security and Privacy Architectures",
    "PM-5": "System Inventory", "PM-9": "Risk Management Strategy",
    "PS-1": "Policy and Procedures", "PS-2": "Position Risk Designation", "PS-3": "Personnel Screening",
    "PS-4": "Personnel Termination", "PS-5": "Personnel Transfer", "PS-6": "Access Agreements",
    "PS-7": "External Personnel Security",
    "PT-1": "Policy and Procedures", "PT-2": "Authority to Process PII", "PT-3": "PII Processing Purposes",
    "RA-1": "Policy and Procedures", "RA-2": "Security Categorization", "RA-3": "Risk Assessment",
    "RA-5": "Vulnerability Monitoring and Scanning", "RA-7": "Risk Response", "RA-9": "Criticality Analysis",
    "SA-1": "Policy and Procedures", "SA-2": "Allocation of Resources", "SA-3": "System Development Life Cycle",
    "SA-4": "Acquisition Process", "SA-8": "Security and Privacy Engineering Principles",
    "SA-9": "External System Services", "SA-10": "Developer Configuration Management",
    "SA-11": "Developer Testing and Evaluation", "SA-15": "Development Process, Standards and Tools",
    "SA-22": "Unsupported System Components",
    "SC-1": "Policy and Procedures", "SC-2": "Separation of System and User Functionality",
    "SC-4": "Information in Shared System Resources", "SC-5": "Denial-of-Service Protection",
    "SC-7": "Boundary Protection", "SC-8": "Transmission Confidentiality and Integrity",
    "SC-10": "Network Disconnect", "SC-12": "Cryptographic Key Establishment and Management",
    "SC-13": "Cryptographic Protection", "SC-15": "Collaborative Computing Devices and Applications",
    "SC-17": "Public Key Infrastructure Certificates", "SC-20": "Secure Name/Address Resolution (Authoritative)",
    "SC-23": "Session Authenticity", "SC-28": "Protection of Information at Rest",
    "SI-1": "Policy and Procedures", "SI-2": "Flaw Remediation", "SI-3": "Malicious Code Protection",
    "SI-4": "System Monitoring", "SI-5": "Security Alerts, Advisories and Directives",
    "SI-7": "Software, Firmware and Information Integrity", "SI-8": "Spam Protection",
    "SI-10": "Information Input Validation", "SI-11": "Error Handling", "SI-12": "Information Management and Retention",
    "SR-1": "Policy and Procedures", "SR-2": "Supply Chain Risk Management Plan",
    "SR-3": "Supply Chain Controls and Processes", "SR-5": "Acquisition Strategies, Tools and Methods",
    "SR-6": "Supplier Assessments and Reviews", "SR-8": "Notification Agreements",
    "SR-11": "Component Authenticity",
}

# ---------------------------------------------------------------------------
# IEC 62443-3-3 -- all 51 System Requirements (OT / ICS)
# ---------------------------------------------------------------------------
IEC62443_CONTROLS = {
    "SR 1.1": "Human user identification and authentication",
    "SR 1.2": "Software process and device identification and authentication",
    "SR 1.3": "Account management",
    "SR 1.4": "Identifier management",
    "SR 1.5": "Authenticator management",
    "SR 1.6": "Wireless access management",
    "SR 1.7": "Strength of password-based authentication",
    "SR 1.8": "Public key infrastructure (PKI) certificates",
    "SR 1.9": "Strength of public key authentication",
    "SR 1.10": "Authenticator feedback",
    "SR 1.11": "Unsuccessful login attempts",
    "SR 1.12": "System use notification",
    "SR 1.13": "Access via untrusted networks",
    "SR 2.1": "Authorization enforcement",
    "SR 2.2": "Wireless use control",
    "SR 2.3": "Use control for portable and mobile devices",
    "SR 2.4": "Mobile code",
    "SR 2.5": "Session lock",
    "SR 2.6": "Remote session termination",
    "SR 2.7": "Concurrent session control",
    "SR 2.8": "Auditable events",
    "SR 2.9": "Audit storage capacity",
    "SR 2.10": "Response to audit processing failures",
    "SR 2.11": "Timestamps",
    "SR 2.12": "Non-repudiation",
    "SR 3.1": "Communication integrity",
    "SR 3.2": "Malicious code protection",
    "SR 3.3": "Security functionality verification",
    "SR 3.4": "Software and information integrity",
    "SR 3.5": "Input validation",
    "SR 3.6": "Deterministic output",
    "SR 3.7": "Error handling",
    "SR 3.8": "Session integrity",
    "SR 3.9": "Protection of audit information",
    "SR 4.1": "Information confidentiality",
    "SR 4.2": "Information persistence",
    "SR 4.3": "Use of cryptography",
    "SR 5.1": "Network segmentation",
    "SR 5.2": "Zone boundary protection",
    "SR 5.3": "General purpose person-to-person communication restrictions",
    "SR 5.4": "Application partitioning",
    "SR 6.1": "Audit log accessibility",
    "SR 6.2": "Continuous monitoring",
    "SR 7.1": "Denial of service protection",
    "SR 7.2": "Resource management",
    "SR 7.3": "Control system backup",
    "SR 7.4": "Control system recovery and reconstitution",
    "SR 7.5": "Emergency power",
    "SR 7.6": "Network and security configuration settings",
    "SR 7.7": "Least functionality",
    "SR 7.8": "Control system component inventory",
}

CATALOGS = {
    "nis2": NIS2_CONTROLS,
    "iso27001": ISO27001_CONTROLS,
    "nist_csf": NIST_CSF_CONTROLS,
    "nist_800_53": NIST_80053_CONTROLS,
    "iec62443": IEC62443_CONTROLS,
}

# ---------------------------------------------------------------------------
# Categories (IT + OT taxonomy)
# ---------------------------------------------------------------------------
CATEGORIES = [
    "Access Control",
    "Authentication",
    "Vulnerability Management",
    "Patch Management",
    "Network Security",
    "Cryptography",
    "Logging & Monitoring",
    "Asset Management",
    "Backup & Recovery",
    "Third Party Risk",
    "OT/ICS Network & Segmentation",
    "Industrial Protocol Security",
    "PLC / Controller Integrity",
    "Safety Instrumented Systems (SIS)",
    "OT Remote Access",
]

CATEGORY_KEYWORDS = {
    "Access Control": [
        "access control", "authorization", "privilege", "least privilege", "rbac", "acl",
        "permission", "admin access", "excessive rights", "sudo", "role", "separation of duties",
        "exposed management", "management interface", "open share", "anonymous access",
        "guest account", "directory listing", "unrestricted", "world-writable",
    ],
    "Authentication": [
        "authentication", "credential", "default cred", "default password", "weak password",
        "password policy", "admin/admin", "no password", "mfa", "2fa", "multi-factor",
        "kerberoast", "as-rep", "asrep", "brute force", "password spray", "login", "ntlm",
        "basic auth", "hardcoded password", "single factor", "session", "cookie",
    ],
    "Vulnerability Management": [
        "vulnerability", "cve-", "exploit", "rce", "remote code execution", "injection",
        "sql injection", "xss", "cross-site", "buffer overflow", "denial of service", "dos",
        "misconfiguration", "information disclosure", "disclosure", "eternalblue", "ms17-010",
        "openvas", "nessus", "scan", "vulnerable version", "banner", "enumeration",
    ],
    "Patch Management": [
        "patch", "unpatched", "outdated", "out of support", "out-of-support", "end of life",
        "end-of-life", "eol", "obsolete", "old firmware", "update available", "missing update",
        "legacy version", "deprecated version", "superseded", "fara actualizari", "iesit din suport",
    ],
    "Network Security": [
        "segmentation", "vlan", "firewall", "flat network", "zone", "dmz", "network", "port open",
        "exposed", "internet-facing", "internet facing", "rdp", "telnet", "smb", "netbios", "snmp",
        "ftp", "open port", "lateral movement", "spoofing", "arp", "reachable", "interconnection",
        "dual-homed", "pivot",
    ],
    "Cryptography": [
        "tls", "ssl", "cipher", "weak cipher", "self-signed", "certificate", "sslv3", "rc4",
        "sweet32", "poodle", "beast", "3des", "md5", "sha-1", "sha1", "cleartext", "plaintext",
        "unencrypted", "encryption", "cryptograph", "key length", "expired certificate", "hsts",
    ],
    "Logging & Monitoring": [
        "logging", "no logging", "monitoring", "siem", "detection", "audit trail", "audit log",
        "no visibility", "log retention", "event log", "alerting", "no alert", "unmonitored",
        "syslog", "no audit",
    ],
    "Asset Management": [
        "asset", "inventory", "unmanaged", "unknown host", "rogue device", "shadow it",
        "unauthorized device", "unidentified", "unknown service", "unknown device",
        "unauthorized software", "end-user device", "endpoint",
    ],
    "Backup & Recovery": [
        "backup", "no backup", "restore", "disaster recovery", "business continuity", "ransomware",
        "data loss", "snapshot", "replication", "rpo", "rto",
    ],
    "Third Party Risk": [
        "supplier", "third party", "third-party", "vendor", "supply chain", "outsourced",
        "managed service", "msp", "cloud provider", "subcontractor", "external service",
        "component authenticity", "dependency",
    ],
    "OT/ICS Network & Segmentation": [
        "ot network", "ics", "scada", "purdue", "level 0", "level 1", "level 2", "level 3",
        "conduit", "ot zone", "ot dmz", "control network", "process network", "cell/area",
        "it/ot", "it-ot", "industrial network", "field network",
    ],
    "Industrial Protocol Security": [
        "modbus", "s7", "s7comm", "dnp3", "iec-104", "iec104", "iec 60870", "profinet",
        "ethernet/ip", "ethernet-ip", "enip", "opc", "opc ua", "bacnet", "fieldbus", "cip",
        "fins", "melsec", "goose", "iec 61850", "industrial protocol",
    ],
    "PLC / Controller Integrity": [
        "plc", "rtu", "controller", "ladder logic", "program download", "logic download",
        "firmware plc", "engineering workstation", "tia portal", "step7", "rslogix",
        "codesys", "control logic", "ied",
    ],
    "Safety Instrumented Systems (SIS)": [
        "sis", "safety instrumented", "safety plc", "safety controller", "esd",
        "emergency shutdown", "safety function", "sil", "burner management", "bms safety",
    ],
    "OT Remote Access": [
        "remote access", "vendor access", "teleservice", "dial-up", "jump host", "jump server",
        "vpn", "remote maintenance", "supplier remote", "remote support", "remote engineering",
    ],
}

CATEGORY_CONTROLS = {
    "Access Control": {
        "nis2": ["21(2)(i)", "21(2)(j)"],
        "iso27001": ["A.5.15", "A.5.16", "A.5.18", "A.8.2", "A.8.3", "A.8.18"],
        "nist_csf": ["PR.AA-01", "PR.AA-05"],
        "nist_800_53": ["AC-2", "AC-3", "AC-5", "AC-6", "AC-17"],
        "iec62443": ["SR 2.1", "SR 1.3"],
    },
    "Authentication": {
        "nis2": ["21(2)(i)", "21(2)(j)"],
        "iso27001": ["A.5.17", "A.8.5"],
        "nist_csf": ["PR.AA-01", "PR.AA-02", "PR.AA-03"],
        "nist_800_53": ["IA-2", "IA-2(1)", "IA-5", "AC-7"],
        "iec62443": ["SR 1.1", "SR 1.5", "SR 1.7", "SR 1.11"],
    },
    "Vulnerability Management": {
        "nis2": ["21(2)(e)"],
        "iso27001": ["A.8.8", "A.8.29"],
        "nist_csf": ["ID.RA-01", "ID.RA-05", "ID.RA-06"],
        "nist_800_53": ["RA-3", "RA-5", "CA-8"],
        "iec62443": ["SR 3.4", "SR 7.7"],
    },
    "Patch Management": {
        "nis2": ["21(2)(e)"],
        "iso27001": ["A.8.8", "A.8.19", "A.8.32"],
        "nist_csf": ["ID.RA-01", "PR.PS-02", "PR.PS-03"],
        "nist_800_53": ["SI-2", "CM-3", "MA-2", "SA-22"],
        "iec62443": ["SR 3.4", "SR 7.6"],
    },
    "Network Security": {
        "nis2": ["21(2)(a)", "21(2)(d)", "21(2)(j)"],
        "iso27001": ["A.8.20", "A.8.21", "A.8.22", "A.8.23"],
        "nist_csf": ["PR.IR-01", "DE.CM-01"],
        "nist_800_53": ["SC-7", "AC-4", "SC-5", "AC-18"],
        "iec62443": ["SR 5.1", "SR 5.2", "SR 7.1"],
    },
    "Cryptography": {
        "nis2": ["21(2)(h)"],
        "iso27001": ["A.8.24", "A.5.14"],
        "nist_csf": ["PR.DS-01", "PR.DS-02"],
        "nist_800_53": ["SC-8", "SC-12", "SC-13", "SC-28"],
        "iec62443": ["SR 4.1", "SR 4.3", "SR 3.1"],
    },
    "Logging & Monitoring": {
        "nis2": ["21(2)(b)"],
        "iso27001": ["A.8.15", "A.8.16", "A.5.25"],
        "nist_csf": ["DE.CM-01", "DE.CM-03", "DE.AE-02", "DE.AE-03"],
        "nist_800_53": ["AU-2", "AU-6", "AU-12", "SI-4"],
        "iec62443": ["SR 2.8", "SR 6.1", "SR 6.2"],
    },
    "Asset Management": {
        "nis2": ["21(2)(i)", "21(2)(a)"],
        "iso27001": ["A.5.9", "A.5.10", "A.8.1", "A.8.9"],
        "nist_csf": ["ID.AM-01", "ID.AM-02", "ID.AM-03", "ID.AM-08"],
        "nist_800_53": ["CM-8", "CM-7", "CM-2", "PM-5"],
        "iec62443": ["SR 7.8"],
    },
    "Backup & Recovery": {
        "nis2": ["21(2)(c)"],
        "iso27001": ["A.8.13", "A.8.14", "A.5.29", "A.5.30"],
        "nist_csf": ["PR.DS-11", "RC.RP-01", "PR.IR-03"],
        "nist_800_53": ["CP-9", "CP-10", "CP-2"],
        "iec62443": ["SR 7.3", "SR 7.4"],
    },
    "Third Party Risk": {
        "nis2": ["21(2)(d)"],
        "iso27001": ["A.5.19", "A.5.20", "A.5.21", "A.5.22"],
        "nist_csf": ["GV.SC-01", "GV.SC-04", "GV.SC-07", "ID.RA-10"],
        "nist_800_53": ["SR-2", "SR-3", "SR-5", "SA-9"],
        "iec62443": ["SR 3.4"],
    },
    "OT/ICS Network & Segmentation": {
        "nis2": ["21(2)(a)", "21(2)(d)"],
        "iso27001": ["A.8.20", "A.8.22"],
        "nist_csf": ["PR.IR-01", "ID.AM-03"],
        "nist_800_53": ["SC-7", "AC-4"],
        "iec62443": ["SR 5.1", "SR 5.2", "SR 5.3", "SR 5.4"],
    },
    "Industrial Protocol Security": {
        "nis2": ["21(2)(h)", "21(2)(e)"],
        "iso27001": ["A.8.24", "A.8.20", "A.8.26"],
        "nist_csf": ["PR.DS-02", "PR.IR-01"],
        "nist_800_53": ["SC-8", "SC-7", "SI-10"],
        "iec62443": ["SR 3.1", "SR 3.5", "SR 4.1", "SR 4.3"],
    },
    "PLC / Controller Integrity": {
        "nis2": ["21(2)(e)", "21(2)(i)"],
        "iso27001": ["A.8.8", "A.8.9", "A.8.19"],
        "nist_csf": ["PR.PS-01", "ID.RA-09", "PR.AA-05"],
        "nist_800_53": ["SI-7", "CM-5", "CM-7", "AC-6"],
        "iec62443": ["SR 3.3", "SR 3.4", "SR 2.1"],
    },
    "Safety Instrumented Systems (SIS)": {
        "nis2": ["21(2)(c)", "21(2)(e)"],
        "iso27001": ["A.8.22", "A.8.31", "A.5.29"],
        "nist_csf": ["PR.IR-03", "PR.PS-01"],
        "nist_800_53": ["SC-7", "SI-7", "CP-2"],
        "iec62443": ["SR 5.4", "SR 3.3", "SR 7.4"],
    },
    "OT Remote Access": {
        "nis2": ["21(2)(j)", "21(2)(d)"],
        "iso27001": ["A.6.7", "A.8.20", "A.5.14"],
        "nist_csf": ["PR.AA-03", "DE.CM-06"],
        "nist_800_53": ["AC-17", "IA-2(1)", "SC-10"],
        "iec62443": ["SR 1.13", "SR 2.6", "SR 5.2"],
    },
}

# Default category when nothing matches (there is always something to propose).
_DEFAULT_CATEGORY = "Vulnerability Management"


# ---------------------------------------------------------------------------
# Classification + auto-association (pure logic, no Streamlit)
# ---------------------------------------------------------------------------
def _finding_text(finding: dict) -> str:
    parts = []
    for k in ("title", "name", "description", "impact", "recommendation", "protocol", "cve"):
        v = finding.get(k)
        if v:
            parts.append(str(v))
    for k in ("cves", "hosts", "ports"):
        v = finding.get(k)
        if isinstance(v, list):
            parts.append(" ".join(str(x) for x in v))
    return " ".join(parts).lower()


def _title_text(finding: dict) -> str:
    return " ".join(str(finding.get(k, "")) for k in ("title", "name")).lower()


def classify_finding(finding: dict, max_categories: int = 3) -> list[str]:
    """Classify a finding into up to ``max_categories`` categories.

    Title keyword hits are weighted much higher than body hits so long,
    detailed descriptions do not over-classify.
    """
    title = _title_text(finding)
    body = _finding_text(finding)
    scores: dict[str, int] = {}
    for cat, kws in CATEGORY_KEYWORDS.items():
        t_hits = sum(1 for kw in kws if kw in title)
        b_hits = sum(1 for kw in kws if kw in body)
        score = 3 * t_hits + b_hits
        if score > 0:
            scores[cat] = score
    if not scores:
        return [_DEFAULT_CATEGORY]
    ordered = sorted(scores, key=lambda c: (-scores[c], CATEGORIES.index(c)))
    return ordered[:max_categories]


def suggest_controls(finding: dict) -> dict[str, list[str]]:
    """Union of controls (per framework) for all categories the finding maps to."""
    cats = classify_finding(finding)
    out = {fw: [] for fw in FRAMEWORK_KEYS}
    for cat in cats:
        for fw in FRAMEWORK_KEYS:
            for cid in CATEGORY_CONTROLS.get(cat, {}).get(fw, []):
                if cid in CATALOGS[fw] and cid not in out[fw]:
                    out[fw].append(cid)
    return out


def effective_controls(finding: dict) -> dict[str, list[str]]:
    """User-selected controls if present, otherwise the auto-suggested ones."""
    stored = finding.get("controls")
    if isinstance(stored, dict) and any(stored.get(fw) for fw in FRAMEWORK_KEYS):
        return {fw: [c for c in (stored.get(fw) or []) if c in CATALOGS[fw]] for fw in FRAMEWORK_KEYS}
    return suggest_controls(finding)


def control_label(framework: str, cid: str) -> str:
    title = CATALOGS.get(framework, {}).get(cid, "")
    return f"{cid} — {title}" if title else cid


def apply_auto_suggestions(findings: list[dict], overwrite: bool = False) -> None:
    """Fill finding['controls'] / finding['categories'] from the classifier."""
    for f in findings or []:
        f["categories"] = classify_finding(f)
        if overwrite or not (isinstance(f.get("controls"), dict) and
                             any(f["controls"].get(fw) for fw in FRAMEWORK_KEYS)):
            f["controls"] = suggest_controls(f)


# ---------------------------------------------------------------------------
# Report helpers (pure logic)
# ---------------------------------------------------------------------------
def report_frameworks(report: dict) -> list[tuple[str, str]]:
    """(key, label) for the frameworks selected for export."""
    sel = report.get("control_frameworks")
    keys = [k for k in FRAMEWORK_KEYS if (k in sel if sel else k in DEFAULT_REPORT_FRAMEWORKS)]
    return [(k, FRAMEWORK_LABELS[k]) for k in keys]


def report_rows(report: dict) -> list[dict]:
    rows = []
    for f in report.get("findings", []) or []:
        controls = effective_controls(f)
        cats = f.get("categories") or classify_finding(f)
        rows.append({
            "title": f.get("title") or "Untitled finding",
            "severity": f.get("severity") or "Informational",
            "category": ", ".join(cats),
            "controls": {fw: ", ".join(controls.get(fw, [])) for fw in FRAMEWORK_KEYS},
        })
    return rows


def used_controls(report: dict) -> list[tuple[str, list[tuple[str, str]]]]:
    """Distinct controls actually referenced, per selected framework, with titles.

    Returns [(framework_label, [(id, title), ...]), ...] for the control legend.
    """
    fw_keys = [k for k, _ in report_frameworks(report)]
    used = {k: set() for k in fw_keys}
    for f in report.get("findings", []) or []:
        eff = effective_controls(f)
        for k in fw_keys:
            for cid in eff.get(k, []):
                if cid in CATALOGS[k]:
                    used[k].add(cid)
    out = []
    for k in fw_keys:
        order = list(CATALOGS[k].keys())
        ids = sorted(used[k], key=lambda c: order.index(c) if c in order else 9999)
        if ids:
            out.append((FRAMEWORK_LABELS[k], [(cid, CATALOGS[k][cid]) for cid in ids]))
    return out


# ---------------------------------------------------------------------------
# Streamlit UI (imported lazily)
# ---------------------------------------------------------------------------
def render_controls_tab(report_data: dict):
    import streamlit as st
    import pandas as pd

    st.header("Controale de conformitate")
    st.caption(
        "Fiecare constatare este clasificata automat pe categorii (inclusiv categorii OT/ICS) si "
        "primeste controale propuse din NIS2, ISO 27001:2022, NIST CSF 2.0, NIST SP 800-53 si "
        "IEC 62443-3-3. Poti revizui si modifica manual selectia."
    )

    report_data.setdefault("include_compliance", True)
    report_data.setdefault("control_frameworks", list(DEFAULT_REPORT_FRAMEWORKS))

    report_data["include_compliance"] = st.checkbox(
        "Include controalele de conformitate in raportul exportat",
        value=bool(report_data.get("include_compliance", True)),
        key="include_compliance_toggle_ct",
    )

    report_data["control_frameworks"] = st.multiselect(
        "Framework-uri de inclus in export",
        options=list(FRAMEWORK_KEYS),
        default=[k for k in FRAMEWORK_KEYS if k in (report_data.get("control_frameworks") or DEFAULT_REPORT_FRAMEWORKS)],
        format_func=lambda k: FRAMEWORK_LABELS.get(k, k),
        key="control_frameworks_ms",
    ) or list(DEFAULT_REPORT_FRAMEWORKS)

    findings = report_data.get("findings", []) or []
    if not findings:
        st.warning("Nu exista constatari inca. Adauga-le in tab-ul Findings sau importa un scan.")
        return report_data

    c1, c2 = st.columns([2, 3])
    if c1.button("Propune automat pentru toate (suprascrie)", key="cm_auto_all"):
        apply_auto_suggestions(findings, overwrite=True)
        for i in range(len(findings)):
            for fw in FRAMEWORK_KEYS:
                st.session_state.pop(f"ctrl_{fw}_{i}", None)
        c2.success("Controale propuse automat pentru toate constatarile.")
        st.rerun()

    st.markdown("---")
    for i, f in enumerate(findings):
        cats = classify_finding(f)
        with st.expander(f"{f.get('title', '(fara titlu)')}  ·  {f.get('severity', '')}", expanded=False):
            st.caption("Categorii detectate: " + ", ".join(cats))
            f["categories"] = cats
            eff = effective_controls(f)
            controls = f.get("controls") if isinstance(f.get("controls"), dict) else {}
            for fw in FRAMEWORK_KEYS:
                options = list(CATALOGS[fw].keys())
                default = [c for c in (controls.get(fw) or eff.get(fw, [])) if c in CATALOGS[fw]]
                sel = st.multiselect(
                    FRAMEWORK_LABELS[fw],
                    options=options,
                    default=default,
                    format_func=lambda cid, _fw=fw: control_label(_fw, cid),
                    key=f"ctrl_{fw}_{i}",
                )
                controls[fw] = sel
            f["controls"] = controls

    st.markdown("---")
    st.subheader("Previzualizare (ce se exporta)")
    fw_sel = [k for k, _ in report_frameworks(report_data)]
    view = []
    for r in report_rows(report_data):
        row = {"Constatare": r["title"], "Severitate": r["severity"], "Categorie": r["category"]}
        for fw in fw_sel:
            row[FRAMEWORK_LABELS[fw]] = r["controls"].get(fw, "")
        view.append(row)
    st.dataframe(pd.DataFrame(view), width="stretch", hide_index=True)
    return report_data
