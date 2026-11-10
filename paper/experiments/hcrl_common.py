"""Shared helpers for the HCRL real-data experiments (prefix hcrl_).

Everything here is read-only with respect to the project: caches go to paper/results/hcrl_cache/,
results to paper/results/, figures via style.save(). Nothing is written under server/, common/, ml_training/ ...
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True  # keep __pycache__ out of the project packages we import

import json
import pickle
import time
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np

from paper.experiments import style

ROOT = style.ROOT
HCRL_DIR = ROOT / "data" / "hcrl"
CACHE = style.RES_DIR / "hcrl_cache"
CLASSES = ["normal", "dos", "fuzzy", "spoofing"]
ATTACK_FILES = ["DoS_dataset.csv", "Fuzzy_dataset.csv", "RPM_dataset.csv", "gear_dataset.csv"]
FILE_SHORT = {"DoS_dataset.csv": "DoS", "Fuzzy_dataset.csv": "Fuzzy", "RPM_dataset.csv": "RPM spoof",
              "gear_dataset.csv": "Gear spoof", "normal_run_data.txt": "Normal"}
FILE_COLOR = {"DoS_dataset.csv": style.C["red"], "Fuzzy_dataset.csv": style.C["orange"],
              "RPM_dataset.csv": style.C["blue"], "gear_dataset.csv": style.C["green"]}
EXPECT_CATS = {"DoS_dataset.csv": {"dos"}, "Fuzzy_dataset.csv": {"fuzzy"},
               "gear_dataset.csv": {"spoofing_gear"}, "RPM_dataset.csv": {"spoofing_rpm"}}
FILE_CLASS = {"DoS_dataset.csv": "dos", "Fuzzy_dataset.csv": "fuzzy", "RPM_dataset.csv": "spoofing",
              "gear_dataset.csv": "spoofing"}
SETTLE_S = 0.6
BASE_WIN_S = 0.1


# --------------------------------------------------------------------------- io
def jdefault(o):
    if hasattr(o, "item"):
        return o.item()
    if isinstance(o, (set, tuple)):
        return list(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    return str(o)


def save_json(name: str, obj: Any) -> Path:
    style.RES_DIR.mkdir(parents=True, exist_ok=True)
    p = style.RES_DIR / f"{name}.json"
    p.write_text(json.dumps(obj, indent=2, default=jdefault), encoding="utf-8")
    return p


def load_json(name: str) -> Any:
    return json.loads((style.RES_DIR / f"{name}.json").read_text(encoding="utf-8"))


def cached(name: str, fn, *a, **kw):
    """Pickle-cache fn(*a, **kw) under paper/results/hcrl_cache/ (delete the folder to force recomputation)."""
    CACHE.mkdir(parents=True, exist_ok=True)
    p = CACHE / f"{name}.pkl"
    if p.exists():
        with open(p, "rb") as fh:
            return pickle.load(fh)
    t0 = time.time()
    out = fn(*a, **kw)
    with open(p, "wb") as fh:
        pickle.dump(out, fh, protocol=pickle.HIGHEST_PROTOCOL)
    print(f"  [cache] {name} built in {time.time() - t0:.0f} s", flush=True)
    return out


# --------------------------------------------------------------------------- LaTeX
def tex_escape(s: Any) -> str:
    s = str(s)
    for a, b in (("\\", r"\textbackslash{}"), ("_", r"\_"), ("%", r"\%"), ("&", r"\&"), ("#", r"\#")):
        s = s.replace(a, b)
    return s


def write_table(name: str, caption: str, label: str, header: list[str], rows: list[list[Any]],
                align: str | None = None, note: str | None = None, star: bool = False,
                header_rows: list[str] | None = None) -> Path:
    """booktabs table, caption above (IEEE). Cells are escaped unless wrapped as ('raw', text)."""
    style.TAB_DIR.mkdir(parents=True, exist_ok=True)
    align = align or ("l" + "r" * (len(header) - 1))
    cell = lambda c: c[1] if isinstance(c, tuple) and c and c[0] == "raw" else tex_escape(c)  # noqa: E731
    env = "table*" if star else "table"
    L = [f"\\begin{{{env}}}[t]", "\\centering", "\\footnotesize", f"\\caption{{{caption}}}", f"\\label{{{label}}}",
         f"\\begin{{tabular}}{{{align}}}", "\\toprule"]
    if header_rows:
        L += header_rows
    L += [" & ".join(cell(h) for h in header) + r" \\", "\\midrule"]
    for r in rows:
        if r == "MID":
            L.append("\\midrule")
            continue
        L.append(" & ".join(cell(c) for c in r) + r" \\")
    L += ["\\bottomrule", "\\end{tabular}"]
    if note:
        L.append(f"\\par\\smallskip\\parbox{{0.95\\linewidth}}{{\\footnotesize {note}}}")
    L += [f"\\end{{{env}}}"]
    p = style.TAB_DIR / f"{name}.tex"
    p.write_text("\n".join(L) + "\n", encoding="utf-8")
    return p


def f3(x, d=3):
    return "--" if x is None else f"{x:.{d}f}"


# --------------------------------------------------------------------------- project imports (lazy, read-only)
def project():
    """Import the project modules once (they put ROOT on sys.path themselves via paper package import)."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from common import can_profiles as CP
    from common import vehicle_sim as VS
    from ml_training import generate_dataset as GD
    from ml_training import hcrl_import as HI
    from ml_training import train as T
    from server.app import analytics as A

    class NS:  # simple namespace
        pass

    ns = NS()
    ns.CP, ns.VS, ns.GD, ns.HI, ns.T, ns.A = CP, VS, GD, HI, T, A
    return ns


def load_hcrl_windows():
    """Cached 100 ms windows (ml_training cache, read-only). Falls back to our own cache on a miss."""
    P = project()
    return P.HI.load_windows(HCRL_DIR)


# --------------------------------------------------------------------------- metrics
def prf(y_true, y_pred) -> dict:
    from sklearn.metrics import precision_recall_fscore_support

    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    p, r, f, n = precision_recall_fscore_support(y_true, y_pred, labels=CLASSES, zero_division=0)
    out = {c: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i]), "support": int(n[i])}
           for i, c in enumerate(CLASSES)}
    out["accuracy"] = float((y_true == y_pred).mean()) if len(y_true) else float("nan")
    out["macro_f1"] = float(np.mean([out[c]["f1"] for c in CLASSES if out[c]["support"] > 0]))
    return out


def macro_f1(y_true, y_pred) -> float:
    """Macro-F1 over the classes present in y_true (zero-division -> 0)."""
    return prf(y_true, y_pred)["macro_f1"]


def confusion(y_true, y_pred) -> np.ndarray:
    from sklearn.metrics import confusion_matrix

    return confusion_matrix(y_true, y_pred, labels=CLASSES)


def pct(a, q):
    return float(np.percentile(a, q)) if len(a) else None


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return float(max(0.0, c - h)), float(min(1.0, c + h))


# --------------------------------------------------------------------------- rule replay (generalised to any window size)
def intrusions(labels, inj, gap_windows: int):
    """(first_win, last_win, first_injected_ts_s) per intrusion: runs of attack windows with gaps <= gap_windows merged."""
    out, start, last = [], None, None
    for i, l in enumerate(labels):
        if l == "normal":
            continue
        if start is not None and i - last > gap_windows:
            out.append((start, last, inj[start]))
            start = None
        if start is None:
            start = i
        last = i
    if start is not None:
        out.append((start, last, inj[start]))
    return out


def replay(name: str, wins: list, win_s: float = BASE_WIN_S, A=None, profile: str | None = None,
           gap_s: float = 0.3) -> dict:
    """Replay VehicleAnalyzer(models=None) over windows of length win_s. Logic mirrors tools/eval_hcrl.replay_rules.

    Returns raw per-window arrays plus per-intrusion latencies (alert-based: first matching alert minus first injected frame).
    """
    P = project()
    A = A or P.A
    profile = profile or P.CP.DEFAULT_PROFILE
    an = A.VehicleAnalyzer(profile, None)
    labels, preds, unsettled, alerts, cats_all, t_ends = [], [], [], [], [], []
    last_label, last_change = "normal", -1e9
    for b, label, _ in wins:
        t_end = b["ts_ms"] / 1000.0 + win_s
        res = an.update(b, None, t_end)
        for a in res["alerts"]:
            alerts.append((t_end, a["kind"], a["category"]))
        cats = an._records[-1][2]
        pred = next((A.CLASS_OF[c] for c in A.CLASS_PRIORITY if c in cats), "normal")
        if label != last_label:
            last_label, last_change = label, t_end
        labels.append(label)
        preds.append(pred)
        cats_all.append(frozenset(cats))
        t_ends.append(t_end)
        unsettled.append(t_end - last_change < SETTLE_S + win_s)
    inj = [w[2] for w in wins]
    expect = EXPECT_CATS.get(name, set())
    ivs = intrusions(labels, inj, max(1, int(round(gap_s / win_s))))
    det, lat_alert, iv_rows, iv_spans = 0, [], [], []
    for (i0, i1, t_inj) in ivs:
        t_end = t_ends[i1]
        iv_spans.append((t_inj, t_end + 1.0))
        hit = [t for (t, kind, c) in alerts if kind == "cyber" and c in expect and t_inj <= t <= t_end + 1.0]
        lat = (hit[0] - t_inj) if hit else None
        if hit:
            det += 1
            lat_alert.append(lat)
        iv_rows.append({"t_inj": t_inj, "t_end": t_end, "latency_s": lat, "n_windows": i1 - i0 + 1})

    def in_iv(t):
        return any(a <= t <= b for a, b in iv_spans)

    cyber_out = [(t, c) for (t, k, c) in alerts if k == "cyber" and not in_iv(t)]
    wrong = [(t, c) for (t, k, c) in alerts if k == "cyber" and in_iv(t) and c not in expect]
    n_norm = sum(1 for l in labels if l == "normal")
    return {
        "name": name, "win_s": win_s, "windows": len(wins), "duration_s": len(wins) * win_s,
        "labels": np.asarray(labels), "preds": np.asarray(preds), "unsettled": np.asarray(unsettled),
        "cats": cats_all, "alerts": alerts, "intrusions": iv_rows, "n_intrusions": len(ivs),
        "n_detected": det, "latencies_s": lat_alert,
        "alerts_outside": len(cyber_out), "alerts_wrong_class": len(wrong),
        "alert_counter": dict(Counter(f"{k}:{c}" for (_, k, c) in alerts)),
        "normal_seconds": n_norm * win_s,
    }


def replay_all(all_wins: dict, win_s: float = BASE_WIN_S, A=None) -> dict:
    return {n: replay(n, w, win_s, A) for n, w in all_wins.items()}


# --------------------------------------------------------------------------- raw pass over a capture
def raw_pass(path: str) -> dict:
    """One streaming pass over a raw HCRL file: arrays of (ts relative, id, injected) + injected payload stats."""
    from ml_training import hcrl_import as HI

    ts, ids, inj = [], [], []
    t_pay: Counter = Counter()
    for t, cid, dlc, data, injected in HI._fast_frames(path):
        ts.append(t)
        ids.append(cid)
        inj.append(injected)
        if injected:
            t_pay[(cid, dlc, data)] += 1
    ts = np.asarray(ts, dtype=np.float64)
    return {"ts": ts - ts[0], "id": np.asarray(ids, dtype=np.int16), "inj": np.asarray(inj, dtype=bool),
            "inj_payloads": dict(t_pay.most_common(20))}


def load_raw(name: str) -> dict:
    return cached(f"raw_{Path(name).stem}", raw_pass, str(HCRL_DIR / name))
