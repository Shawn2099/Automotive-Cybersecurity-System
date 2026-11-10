"""Exp 5: threshold sensitivity of the rule engine on real HCRL data.

Sweeps SPOOF_RATIO, DOS_UNKNOWN_ID_FPS, FUZZY_MIN_IDS by monkeypatching the module constants of
server.app.analytics inside worker processes, replaying all five captures (100 ms windows) for every value.
All five captures are replayed for every point (no subsampling); ~2-3 min on 8 cores.

    python -m paper.experiments.hcrl_sensitivity
"""
from __future__ import annotations

from collections import Counter

import numpy as np

from paper.experiments import hcrl_common as H
from paper.experiments import style

SWEEPS = {
    "SPOOF_RATIO": {"values": [1.05, 1.1, 1.2, 1.3, 1.5, 2.0, 3.0, 4.0, 5.0], "default": 1.5, "files": ["RPM_dataset.csv", "gear_dataset.csv"],
                    "cls": "spoofing", "label": "SPOOF_RATIO (x expected rate)"},
    "DOS_UNKNOWN_ID_FPS": {"values": [25, 50, 75, 100, 150, 200, 300, 400, 600], "default": 100, "files": ["DoS_dataset.csv"],
                           "cls": "dos", "label": "DOS_UNKNOWN_ID_FPS (frames/s)"},
    "FUZZY_MIN_IDS": {"values": [2, 3, 5, 7, 10, 15, 20, 30], "default": 10, "files": ["Fuzzy_dataset.csv"],
                      "cls": "fuzzy", "label": "FUZZY_MIN_IDS (distinct unknown IDs)"},
}


def run_point(param: str, value) -> dict:
    """Worker: patch one analytics constant, replay all captures, return compact counts."""
    P = H.project()
    A = P.A
    orig = getattr(A, param)
    setattr(A, param, type(orig)(value))
    try:
        wins = P.HI.load_windows(H.HCRL_DIR)
        out = {}
        for n, w in wins.items():
            r = H.replay(n, w, 0.1, A)
            c = Counter(zip(r["labels"].tolist(), r["preds"].tolist(), r["unsettled"].tolist()))
            out[n] = {"counts": [[a, b, bool(u), k] for (a, b, u), k in c.items()], "n_intrusions": r["n_intrusions"],
                      "n_detected": r["n_detected"], "alerts_outside": r["alerts_outside"],
                      "normal_seconds": r["normal_seconds"], "latencies_s": r["latencies_s"]}
    finally:
        setattr(A, param, orig)
    return {"param": param, "value": value, "files": out}


def aggregate(pt: dict, sw: dict) -> dict:
    def tot(files, cond):
        return sum(k for n in files for (a, b, u, k) in pt["files"][n]["counts"] if cond(a, b, u))

    tf = sw["files"]
    allf = list(pt["files"])
    cls = sw["cls"]
    m = {}
    for tag, settled_only in (("all", False), ("settled", True)):
        ok = (lambda u: (not u) if settled_only else True)
        att = tot(tf, lambda a, b, u: a != "normal" and ok(u))
        m[f"recall_any_{tag}"] = tot(tf, lambda a, b, u: a != "normal" and b != "normal" and ok(u)) / att
        m[f"recall_correct_{tag}"] = tot(tf, lambda a, b, u: a != "normal" and b == cls and ok(u)) / att
        nrm = tot(allf, lambda a, b, u: a == "normal" and ok(u))
        m[f"fpr_{tag}"] = tot(allf, lambda a, b, u: a == "normal" and b != "normal" and ok(u)) / nrm
        m[f"fpr_{tag}_same_class"] = tot(allf, lambda a, b, u: a == "normal" and b == cls and ok(u)) / nrm
    nint = sum(pt["files"][n]["n_intrusions"] for n in tf)
    m["intrusion_detect_rate"] = sum(pt["files"][n]["n_detected"] for n in tf) / nint
    lat = [x for n in tf for x in pt["files"][n]["latencies_s"]]
    m["latency_median_ms"] = float(np.median(lat) * 1000) if lat else None
    secs = sum(pt["files"][n]["normal_seconds"] for n in allf)
    out_alerts = sum(pt["files"][n]["alerts_outside"] for n in allf)
    m["false_alerts_outside_intrusions"] = out_alerts
    m["false_alerts_per_hour"] = out_alerts / (secs / 3600)
    m["normal_seconds"] = secs
    return m


def main():
    from joblib import Parallel, delayed

    tasks = [(p, v) for p, sw in SWEEPS.items() for v in sw["values"]]
    pts = H.cached("sensitivity_points", lambda: Parallel(n_jobs=8)(delayed(run_point)(p, v) for p, v in tasks))
    res = {}
    for p, sw in SWEEPS.items():
        rows = []
        for pt in pts:
            if pt["param"] == p:
                rows.append({"value": pt["value"], **aggregate(pt, sw)})
        res[p] = {"default": sw["default"], "target_class": sw["cls"], "files": sw["files"], "points": rows}
    H.save_json("hcrl_sensitivity", res)

    # ---- fig 1: detection vs false-positive operating curves
    f, axs = style.fig(style.FULL_W, 2.4, ncols=3)
    for ax, (p, sw) in zip(axs, SWEEPS.items()):
        pts_p = res[p]["points"]
        fpr = np.array([q["fpr_settled"] for q in pts_p]) * 100
        rec = np.array([q["recall_any_settled"] for q in pts_p]) * 100
        cor = np.array([q["recall_correct_settled"] for q in pts_p]) * 100
        ax.plot(fpr, rec, "o-", color=style.C["blue"], label="detected (any class)")
        ax.plot(fpr, cor, "s--", color=style.C["orange"], label="correct class", ms=3)
        d = [i for i, q in enumerate(pts_p) if q["value"] == sw["default"]][0]
        ax.plot(fpr[d], rec[d], "*", color=style.C["red"], ms=9, zorder=5, label="deployed")
        for i, q in enumerate(pts_p):
            ax.annotate(f"{q['value']:g}", (fpr[i], rec[i]), textcoords="offset points",
                        xytext=(2, -8 if i % 2 else 4), fontsize=5)
        ax.set_xscale("symlog", linthresh=0.1)
        ax.set_xlim(-0.02, max(1.0, fpr.max() * 1.5))
        ax.set_ylim(-3, 105)
        ax.set_xlabel("FPR, settled normal windows (%)")
        ax.set_title(p.replace("_", " "), fontsize=7)
    axs[0].set_ylabel("Recall, settled attack windows (%)")
    axs[0].legend(loc="lower right", fontsize=5.5)
    f.tight_layout()
    style.save(f, "hcrl_sensitivity")

    # ---- fig 2: metric vs threshold value
    f, axs = style.fig(style.FULL_W, 2.2, ncols=3)
    for ax, (p, sw) in zip(axs, SWEEPS.items()):
        v = [q["value"] for q in res[p]["points"]]
        ax.plot(v, [q["recall_any_settled"] * 100 for q in res[p]["points"]], "o-", color=style.C["blue"], label="recall")
        ax.plot(v, [q["fpr_settled"] * 100 for q in res[p]["points"]], "s--", color=style.C["red"], label="FPR")
        ax.axvline(sw["default"], color="k", lw=0.5, ls=":")
        ax.set_xscale("log")
        # label only ticks far enough apart on the log axis; always keep the deployed value
        ticks: list[float] = []
        for val in sorted(set(v) | {sw["default"]}, key=lambda t: (t != sw["default"], t)):
            if all(abs(np.log10(val) - np.log10(t)) >= 0.14 for t in ticks):
                ticks.append(val)
        style.log_ticks(ax, sorted(ticks))
        ax.set_xlabel(sw["label"])
        ax.set_ylim(-3, 105)
    axs[0].set_ylabel("% (settled windows)")
    axs[0].legend(fontsize=6, loc="center left")
    f.tight_layout()
    style.save(f, "hcrl_sensitivity_vs_threshold")

    # ---- table
    rows = []
    for p, sw in SWEEPS.items():
        for q in res[p]["points"]:
            tag = " *" if q["value"] == sw["default"] else ""
            rows.append([p if q is res[p]["points"][0] else "", f"{q['value']:g}{tag}",
                         f"{100 * q['recall_any_settled']:.1f}", f"{100 * q['recall_correct_settled']:.1f}",
                         f"{100 * q['fpr_settled']:.2f}", f"{100 * q['intrusion_detect_rate']:.1f}",
                         f"{q['false_alerts_per_hour']:.1f}"])
        rows.append("MID")
    rows.pop()
    H.write_table("hcrl_sensitivity",
                  "Threshold sensitivity of the rule engine on HCRL (settled 100~ms windows; FPR over all normal windows of the five "
                  "captures). Asterisk: deployed value. Recall is measured on the attack windows of the targeted captures "
                  "(spoofing: RPM and gear; DoS; fuzzy).",
                  "tab:hcrl_sensitivity",
                  ["Constant", "Value", ("raw", r"Recall any (\%)"), ("raw", r"Recall correct (\%)"), ("raw", r"FPR (\%)"),
                   ("raw", r"Intrusions found (\%)"), "False alerts/h"], rows, align="llrrrrr")
    for p in SWEEPS:
        print(p, [(q["value"], round(q["recall_any_settled"], 3), round(q["recall_correct_settled"], 3), round(q["fpr_settled"], 4))
                  for q in res[p]["points"]])


if __name__ == "__main__":
    main()
