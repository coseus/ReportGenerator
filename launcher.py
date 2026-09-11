import os
import subprocess
import sys

# Disable Streamlit usage statistics
os.environ["STREAMLIT_BROWSER_GATHER_USAGE_STATS"] = "false"

APP_PATH = os.path.join(os.path.dirname(__file__), "app.py")

subprocess.run([sys.executable, "-m", "streamlit", "run", APP_PATH])
