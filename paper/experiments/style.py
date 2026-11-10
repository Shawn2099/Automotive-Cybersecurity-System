"""Shared figure style for the IEEE paper. Every figure script imports this so all plots match.

IEEE two-column: single column = 3.5 in, full width = 7.16 in. Body font ~8 pt in figures.
Colours: Okabe-Ito (colour-blind safe), and every series also differs by marker/linestyle so
figures survive greyscale printing.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

PAPER = Path(__file__).resolve().parents[1]
ROOT = PAPER.parent
FIG_DIR = PAPER / "figures"
RES_DIR = PAPER / "results"
TAB_DIR = PAPER / "tables"

COL_W = 3.5
FULL_W = 7.16

# Okabe-Ito
C = {
    "blue": "#0072B2", "orange": "#E69F00", "green": "#009E73", "red": "#D55E00",
    "purple": "#CC79A7", "sky": "#56B4E9", "yellow": "#F0E442", "black": "#000000", "grey": "#7F7F7F",
}
CLASS_COLOR = {"normal": C["grey"], "dos": C["red"], "fuzzy": C["orange"], "spoofing": C["blue"],
               "tunnel_attack": C["purple"]}
MARKERS = ["o", "s", "^", "D", "v", "P", "X"]
LINES = ["-", "--", "-.", ":"]


def apply() -> None:
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "mathtext.fontset": "stix",
        "font.size": 8, "axes.titlesize": 8, "axes.labelsize": 8,
        "xtick.labelsize": 7, "ytick.labelsize": 7, "legend.fontsize": 7,
        "axes.linewidth": 0.6, "lines.linewidth": 1.0, "lines.markersize": 3.5,
        "grid.linewidth": 0.4, "grid.alpha": 0.35, "axes.grid": True,
        "axes.spines.top": False, "axes.spines.right": False,
        "legend.frameon": False, "savefig.bbox": "tight", "savefig.pad_inches": 0.02,
        "pdf.fonttype": 42, "ps.fonttype": 42,  # embed TrueType (IEEE PDF eXpress)
    })


def fig(width: float = COL_W, height: float | None = None, **kw):
    apply()
    return plt.subplots(figsize=(width, height or width * 0.62), **kw)


def _tidy_log_axes(f) -> None:
    """Log axes: no minor tick labels (they overprint) and plain numbers instead of 2x10^2."""
    from matplotlib.ticker import FuncFormatter, NullFormatter

    plain = FuncFormatter(lambda v, _: f"{v:g}")
    for ax in f.get_axes():
        for axis, scale in ((ax.xaxis, ax.get_xscale()), (ax.yaxis, ax.get_yscale())):
            if scale in ("log", "symlog"):
                axis.set_minor_formatter(NullFormatter())
                axis.set_major_formatter(plain)


def log_ticks(ax, values, axis: str = "x") -> None:
    """Put major ticks exactly at the swept values on a log axis (call after set_xscale)."""
    from matplotlib.ticker import FixedLocator, NullLocator

    a = ax.xaxis if axis == "x" else ax.yaxis
    a.set_major_locator(FixedLocator(list(values)))
    a.set_minor_locator(NullLocator())


def save(f, name: str) -> list[Path]:
    """Save as vector PDF (for LaTeX) and 300 dpi PNG (for preview/Word)."""
    _tidy_log_axes(f)
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    out = [FIG_DIR / f"{name}.pdf", FIG_DIR / f"{name}.png"]
    f.savefig(out[0])
    f.savefig(out[1], dpi=300)
    plt.close(f)
    return out
