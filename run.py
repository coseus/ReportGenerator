"""
run.py
------
Launcher for the PenTest Report Generator (Streamlit app).
It ensures that environment paths and dependencies are correctly set up
before running the application.
"""

import os
import sys
import subprocess
from pathlib import Path

# Import internal path setup helper
import setup_paths

# Define project root
ROOT = Path(__file__).resolve().parent
APP_PATH = ROOT / "app.py"
REQUIREMENTS = ROOT / "requirements.txt"

# --- STEP 1: Verify that app.py exists ---
if not APP_PATH.exists():
    print("❌ ERROR: app.py not found in project root.")
    print(f"Expected path: {APP_PATH}")
    sys.exit(1)

# --- STEP 2: Check if Streamlit is installed ---
try:
    import streamlit
except ImportError:
    print("📦 Streamlit not found. Installing dependencies from requirements.txt...")
    if REQUIREMENTS.exists():
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS)],
            check=True
        )
    else:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "streamlit", "reportlab", "python-docx", "matplotlib", "pandas", "Pillow"],
            check=True
        )

# --- STEP 3: Launch the Streamlit app ---
os.chdir(ROOT)
print("\n🚀 Launching PenTest Report Generator...\n")
print("👉 Open your browser and go to: http://localhost:8501\n")

try:
    subprocess.run(["streamlit", "run", str(APP_PATH)], check=True)
except KeyboardInterrupt:
    print("\n🛑 Application stopped by user.")
except Exception as e:
    print(f"\n❌ Failed to launch Streamlit app: {e}")
