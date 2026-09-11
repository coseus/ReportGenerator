from __future__ import annotations

from io import BytesIO
import base64
import matplotlib
from util.i18n import t
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SEV_ORDER = ["Critical", "High", "Moderate", "Low", "Informational"]
WEIGHTS = {"Critical": 5, "High": 4, "Moderate": 3, "Low": 2, "Informational": 1}
SEV_COLORS = {"Critical": "#A61B1B", "High": "#D35400", "Moderate": "#B9770E",
              "Low": "#1F618D", "Informational": "#5D6D7E"}

def _fig_to_png_bytes(fig) -> bytes:
    bio = BytesIO()
    fig.savefig(bio, format="png", bbox_inches="tight", dpi=150)
    plt.close(fig)
    bio.seek(0)
    return bio.read()

def severity_distribution_png(summary_counts: dict[str,int], lang: str = "en") -> bytes:
    counts = [int(summary_counts.get(sev, 0)) for sev in SEV_ORDER]
    fig, ax = plt.subplots(figsize=(6.8, 3.5))
    ax.bar(SEV_ORDER, counts, color=[SEV_COLORS[s] for s in SEV_ORDER])
    ax.set_title(t(lang, "chart_severity_distribution"))
    ax.set_ylabel(t(lang, "chart_count"))
    ax.set_xlabel(t(lang, "chart_severity"))
    for idx, val in enumerate(counts):
        ax.text(idx, val + 0.05, str(val), ha='center', va='bottom', fontsize=8)
    fig.tight_layout()
    return _fig_to_png_bytes(fig)

def risk_trend_png(findings: list[dict], lang: str = "en") -> bytes:
    x = list(range(1, len(findings) + 1)) or [1]
    running = []
    total = 0
    for item in findings:
        total += WEIGHTS.get(item.get("severity"), 1)
        running.append(total)
    if not running:
        running = [0]
    fig, ax = plt.subplots(figsize=(6.8, 3.5))
    ax.plot(x, running, marker='o')
    ax.set_title(t(lang, "chart_risk_trend"))
    ax.set_ylabel(t(lang, "chart_cumulative_risk"))
    ax.set_xlabel(t(lang, "chart_finding_order"))
    fig.tight_layout()
    return _fig_to_png_bytes(fig)

def png_bytes_to_b64(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')
