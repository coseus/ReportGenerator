### Modern, Automated, Enterprise-Grade Reporting for Offensive Security + Detail Walkthrough

## 📌 Overview

**Pentest Report Generator – Corporate Edition** este o aplicație completă, extensibilă și modernă pentru generarea de rapoarte profesionale de penetration testing (PDF & DOCX), cu suport pentru:

- Import automat din **Nessus**, **OpenVAS**, **Nmap**, **CSV**, **JSON**
- Editare avansată a finding-urilor, cu **evidence images + code blocks**
- Structură corporată (Deloitte / KPMG style)
- Export PDF cu:
    - **Cover corporate**
    - **Header de pagină cu logo**
    - **Watermark opțional CONFIDENTIAL**
    - **Table of Contents automat**
    - **Findings numerotate 6.1, 6.2…**
    - **Additional reports & scans**
    - **Per-host vulnerability heatmap**
    - **Badges colorate (Critical / High / etc)**

Aplicația folosește **Streamlit** în front-end și **ReportLab** pentru generarea PDF-urilor enterprise-grade.

---

## ✨ Features

### 🔍 Import Findings

- Import automat cu parsing avansat din:
    - ✓ Nessus (.nessus XML)
    - ✓ OpenVAS / Greenbone XML
    - ✓ Nmap XML
    - ✓ CSV custom
    - ✓ JSON custom
- Auto-mapping pentru:
    - Severity
    - Title
    - Host
    - CVSS
    - CVE
    - Description / Impact / Recommendation

### 📝 Findings Editor (Advanced)

- Editare completă pentru fiecare finding
- Adăugare / ștergere **imagini (B64)** cu resize automat
- Code blocks formatate
- Deduplicare imagini
- Filtrare după severitate
- Renumbering automat 6.1, 6.2 …

### 🧩 Additional Reports

- Titlu + Description + Code + Evidențe (imagini)
- Apărute în PDF sub capitolul 7.0

### 📄 Export PDF & DOCX

- Cover corporate
- Watermark CONFIDENTIAL (opțional)
- TOC automat
- Formatting avansat (multiline, indentare exactă)
- Vulnerability Summary (with badges + totals)
- Per-host summary grid
- Technical Findings full-corporate
- Additional Reports corporate layout

---

## 📂 Project Structure

```
pentest_report/
│
├── app.py
├── run.py
├── setup_paths.py
│
├── ui/
│   ├── general_info.py
│   ├── scope_tab.py
│   ├── findings_tab.py
│   ├── additional_reports.py
│   ├── executive_summary_tab.py
│   └── export_tab.py
│
├── report/
│   ├── pdf_generator.py
│   ├── docx_generator.py
│   ├── parsers.py
│   ├── data_model.py
│   ├── numbering.py
│   ├── utils.py
│   └── sections/
│       ├── section_1_0_confidentiality_and_legal.py
│       ├── section_1_1_confidentiality_statement.py
│       ├── section_1_2_disclaimer.py
│       ├── section_1_3_contact_information.py
│       ├── section_2_0_assessment_overview.py
│       ├── section_2_1_assessment_details.py
│       ├── section_2_2_scope.py
│       ├── section_2_3_scope_exclusions.py
│       ├── section_2_4_client_allowances.py
│       ├── section_3_0_finding_severity_ratings.py
│       ├── section_4_0_technical_findings.py
│       ├── section_4_1_additional_reports.py
│       ├── section_5_0_executive_summary.py
│       └── section_5_1_vulnerability_summary.py
│
└── util/
    ├── helpers.py
    └── io_manager.py

```

---

## 🚀 Installation

### 1. Clone the repository

```
git clone https://github.com/<username>/pentest-report-generator
cd pentest-report-generator

```

### 2. Create virtual environment

```
python3 -m venv venv
source venv/bin/activate

```

### 3. Install dependencies

```
pip install -r requirements.txt

```

---

## ▶️ Running the Application

```
streamlit run app.py

```

## 🖼️ Screenshots

<img width="1370" height="1220" alt="image" src="https://github.com/user-attachments/assets/969d93d2-0fd9-4f5b-abae-c58fc7dce593" />
<img width="1394" height="1115" alt="image 1" src="https://github.com/user-attachments/assets/a368fdce-70c1-4816-a6ef-0d27c48d0939" />
<img width="1470" height="1783" alt="image 2" src="https://github.com/user-attachments/assets/9298096b-bb9c-4dcf-81a8-5275bfa75292" />
<img width="1483" height="948" alt="image 3" src="https://github.com/user-attachments/assets/20bdcdbc-7f93-4809-bd16-bcc1ffc5f253" />
<img width="1542" height="855" alt="image 4" src="https://github.com/user-attachments/assets/8fed0b9b-a948-468e-a3e4-40580570fb20" />
<img width="1540" height="1180" alt="image 5" src="https://github.com/user-attachments/assets/e5009fa5-527f-4812-ac08-d042e3e9cb36" />


