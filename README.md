# 🛡️ Pentest Report Generator

A modern, professional **Penetration Testing Report Generator** built with **Streamlit**, designed to produce **clean, executive-ready and technical reports** in:

* 📄 PDF (ReportLab)
* 📝 DOCX (python-docx)

---

## 🚀 Features

### 📊 Report Types

* **Executive Report**
* **Technical Report**
* **Combined Report**

### 🧠 Smart Content Handling

* Structured sections (`report["sections"]`)
* Automatic fallback to default legal text
* Findings sorting by severity
* Risk summary & statistics

### 🖼️ Evidence Handling

* Images (Base64)
* Code blocks (terminal output)
* Walkthrough steps
* Additional reports

### 🎨 Styling

* Custom accent color
* Clean corporate layout
* Consistent spacing (PDF + DOCX aligned)
* Centered captions & structured sections

---

## 🏗️ Project Structure

```
project/
│
├── app.py                  # Streamlit UI
├── run.py                  # Main launcher (dev mode)
├── launcher.py             # EXE launcher (production)
├── build_exe.py            # PyInstaller build script
├── setup_paths.py          # Fix import paths
├── requirements.txt
│
├── report/
│   ├── pdf_generator.py
│   ├── docx_generator.py
│   └── sections/
│
├── ui/
├── util/
├── assets/
└── data/
```

---

## ⚙️ Installation

### 1. Clone project

```bash
git clone <repo>
cd project
```

### 2. Create virtual environment

```bash
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Run Application

```bash
python run.py
```

Then open:

```
http://localhost:8501
```

---

## 📦 Build Executable (.EXE)

```bash
python build_exe.py
```

✔ Output:

```
dist/PentestReportGenerator/
```

### Important:

* Uses `--onedir` (required for Streamlit) 
* Includes all assets, UI, report modules

---

## 🧩 How It Works

### 🔹 Launcher Flow

* `run.py`:

  * checks dependencies
  * installs if missing
  * launches Streamlit 

* `launcher.py`:

  * used inside EXE
  * runs `streamlit run app.py` 

* `setup_paths.py`:

  * fixes import paths for packaged builds 

---

## 📄 Report Structure

### 1. Front Matter

* Confidentiality
* Disclaimer
* Contact info

### 2. Executive Overview

* Summary
* Risk matrix
* Scope & details

### 3. Findings Summary

* Severity distribution
* Priorities

### 4. Findings

* Title + severity
* Metadata (host, CVE, etc.)
* Description / Impact / Recommendation
* Code evidence
* Images + captions

### 5. Remediation Roadmap

* Short / Medium / Long term

### 6. Walkthrough (optional)

* Step-by-step exploitation

### 7. Additional Reports (optional)

---

## 📦 Dependencies

From `requirements.txt`:

* streamlit
* pandas
* plotly
* reportlab
* python-docx
* Pillow
* matplotlib
* lxml 

---

## 🧠 Notes

### 🔹 Table of Contents (DOCX)

* Generated automatically
* Must be updated manually in Word:

```
Right click → Update Field
```

### 🔹 Images

* Stored as Base64
* Auto-scaled
* Centered with caption

### 🔹 Sections System

Supports:

```python
report["sections"]["section_1_0_confidentiality_and_legal"]
```

Fallback:

```python
SECTION_DEFAULTS
```

---

## 🧪 Development Tips

* Use `run.py` during development
* Use `build_exe.py` for distribution
* Keep assets in `/assets`
* Keep report logic in `/report`

---

## 🔐 Security Note

This tool is designed for **authorized penetration testing only**.

---

## 📌 Roadmap (optional ideas)

* [ ] Multi-language reports
* [ ] CVSS auto-calculation
* [ ] Charts (risk trends)
* [ ] Export to HTML

---

## 👨‍💻 Author

Pentest Report Generator – Corporate Edition

---

## ✅ Status

✔ Production-ready
✔ EXE packaging ready
✔ PDF + DOCX aligned
✔ Clean architecture

---
