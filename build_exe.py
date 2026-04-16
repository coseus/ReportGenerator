# build_exe.py – Corporate Edition v4 (FULL WORKING)
import os
import subprocess
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

APP_FILE = os.path.join(BASE_DIR, "app.py")
ICON_FILE = os.path.join(BASE_DIR, "icon.ico")

EXE_NAME = "PentestReportGenerator"
DIST_DIR = os.path.join(BASE_DIR, "dist")
BUILD_DIR = os.path.join(BASE_DIR, "build")

def clean():
    for d in [DIST_DIR, BUILD_DIR]:
        if os.path.exists(d):
            print(f"[+] Cleaning {d} ...")
            shutil.rmtree(d, ignore_errors=True)

def build():
    clean()

    sep = ";" if os.name == "nt" else ":"

    cmd = [
        "pyinstaller",
        "--name", EXE_NAME,
        "--onedir",                  # IMPORTANT — Streamlit cannot run in --onefile
        "--windowed",
        "--clean",
        f"--add-data=ui{sep}ui",
        f"--add-data=util{sep}util",
        f"--add-data=report{sep}report",
        f"--add-data=report/sections{sep}report/sections",
        f"--add-data=data{sep}data",
        f"--add-data=assets{sep}assets",

        "--hidden-import=streamlit",
        "--hidden-import=reportlab",
        "--hidden-import=reportlab.pdfbase.ttfonts",
        "--hidden-import=reportlab.pdfbase.pdfmetrics",
        "--hidden-import=matplotlib",
        "--hidden-import=matplotlib.backends.backend_agg",
        "--hidden-import=pandas",
        "--hidden-import=lxml",
        "--hidden-import=lxml.etree",
        "--hidden-import=lxml._elementpath",
        "--hidden-import=python-docx",
        "--hidden-import=PIL",
        "--hidden-import=PIL._imaging",

        "--collect-all=reportlab",
        "--collect-all=python-docx",
        "--collect-all=pillow",
        "--collect-all=matplotlib",
        "--collect-all=streamlit",
    ]

    if os.path.exists(ICON_FILE):
        cmd += ["--icon", ICON_FILE]

    # The launcher will run Streamlit properly
    LAUNCHER = os.path.join(BASE_DIR, "launcher.py")
    cmd.append(LAUNCHER)

    print("\n[+] Building Pentest Report Generator (Corporate Edition)...\n")
    subprocess.run(cmd, check=True)

    print(f"\n[✔] SUCCESS! Executabilul se află în: {DIST_DIR}/{EXE_NAME}\n")

if __name__ == "__main__":
    build()
