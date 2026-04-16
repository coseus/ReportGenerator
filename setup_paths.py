# setup_paths.py
"""
Helper to add repository root to sys.path so local package imports (ui.*, report.*) work
when Streamlit runs from different working directories.
"""

import os
import sys
from pathlib import Path

# Determine repository root (assume this file is in project root)
ROOT = Path(__file__).resolve().parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Also add src/ or mount paths if present (common in deployed envs)
alt = ROOT / "src"
if alt.exists() and str(alt) not in sys.path:
    sys.path.insert(0, str(alt))
