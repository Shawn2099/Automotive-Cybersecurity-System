"""Exp 6: batch window size (50/100/200/500 ms) vs detection latency and accuracy of the rule engine on real HCRL.

Windows are cut straight from the raw captures with ml_training.hcrl_import.iter_windows(window_ms=...). Window-level F1 is
NOT comparable across sizes (a window is 'attack' if it holds any injected frame, so the attack share grows with the
window); the headline metrics are per-intrusion detection rate, latency and false alerts per hour.

    python -m paper.experiments.hcrl_window
"""
from __future__ import annotations

from collections import Counter

import numpy as np

from paper.experiments import hcrl_common as H
from paper.experiments import style

SIZES = [50, 100, 200, 500]
FILES = H.ATTACK_FILES + ["normal_run_data.txt"]


def run_one(size_ms: int, name: str) -> dict:
    P = H.project()
    keep = {m.id for m in P.CP.get_profile(P.CP.DEFAULT_PROFILE).messages}
    wins = list(P.HI.iter_windows(H.HCRL_DIR / name, P.HI.attack_class_for_file(name), size_ms, None, keep))
    r = H.replay(name, wins, size_ms / 1000.0, P.A)
    c = Counter(zip(r["labels"].tolist(), r["preds"].tolist(), r["unsettled"].tolist()))
    return {"size": size_ms, "file": name, "windows": r["windows"],
            "counts": [[a, b, bool(u), k] for (a, b, u), k in c.items()], "n_intrusions": r["n_intrusions"],
            "n_detected": r["n_detected"], "latencies_s": r["latencies_s"], "alerts_outside": r["alerts_outside"],
            "normal_seconds": r["normal_seconds"], "alert_counter": r["alert_counter"]}


def main():
    from joblib import Parallel, delayed

    tasks = [(s, n) for s in SIZES for n in FILES]
    pts = H.cached("window_points", lambda: Parallel(n_jobs=8)(delayed(run_one)(s, n) for s, n in tasks))
    res = {}
    for s in SIZES:
        P_ = [p for p in pts if p["size"] == s]
        cnt = [(a, b, u, k) for p in P_ for (a, b, u, k) in p["counts"]]
        # expand counts into per-class confusion directly
        def macro(settled_only):
            conf = Counter()
            for a, b, u, k in cnt:
                if settled_only and u:
                    continue
                conf[(a, b)] += k
            f1s = []
            for c in H.CLASSES:
                tp = conf[(c, c)]
                fp = sum(conf[(a, c)] for a in H.CLASSES if a != c)
                fn = sum(conf[(c, b)] for b in H.CLASSES if b != c)
                f1s.append(2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else 0.0)
            return float(np.mean(f1s)), dict(zip(H.CLASSES, f1s))
        per = {}
        allhit = allint = 0
        lat_all = []
        for p in P_:
            if p["file"] in H.ATTACK_FILES:
                lat = np.array(p["latencies_s"]) * 1000
                per[p["file"]] = {"intrusions": p["n_intrusions"], "detected": p["n_detected"],
                                  "median_ms": H.pct(lat, 50), "p95_ms": H.pct(lat, 95), "max_ms": H.pct(lat, 100)}
                allhit += p["n_detected"]
                allint += p["n_intrusions"]
                lat_all += list(lat)
        nsec = sum(p["normal_seconds"] for p in P_)
        fa = sum(p["alerts_outside"] for p in P_)
        nr = [p for p in P_ if p["file"] == "normal_run_data.txt"][0]
        cyb_nr = sum(v for k, v in nr["alert_counter"].items() if k.startswith("cyber:"))
        mf_all, f_all = macro(False)
        mf_set, f_set = macro(True)
        res[str(s)] = {"window_ms": s, "detect_rate": allhit / allint, "intrusions": allint, "detected": allhit,
                       "latency_median_ms": H.pct(lat_all, 50), "latency_p95_ms": H.pct(lat_all, 95),
                       "latency_max_ms": H.pct(lat_all, 100), "false_alerts_outside": fa,
                       "false_alerts_per_hour": fa / (nsec / 3600), "normal_run_cyber_alerts": cyb_nr,
                       "macro_f1_all": mf_all, "macro_f1_settled": mf_set, "f1_settled": f_set, "per_attack": per}
    H.save_json("hcrl_window", res)
    rows = []
    for s in SIZES:
        r = res[str(s)]
        rows.append([s, f"{100 * r['detect_rate']:.1f}", f"{r['latency_median_ms']:.0f}", f"{r['latency_p95_ms']:.0f}",
                     f"{r['latency_max_ms']:.0f}", f"{r['false_alerts_per_hour']:.1f}", H.f3(r["macro_f1_all"]),
                     H.f3(r["macro_f1_settled"])])
    H.write_table("hcrl_window",
                  "Effect of the batch window on the rule engine (real HCRL, all four attacks pooled, 1200 intrusions). "
                  "Latency is first injected frame to first matching alert. Window-level macro-F1 is not comparable across "
                  "sizes because a window counts as attack if it contains any injected frame.",
                  "tab:hcrl_window",
                  ["Window (ms)", ("raw", r"Detected (\%)"), "Med. (ms)", "P95 (ms)", "Max (ms)", "False alerts/h",
                   "F1 all", "F1 settled"], rows, align="rrrrrrrr")
    f, axs = style.fig(style.FULL_W, 2.3, ncols=2)
    ax = axs[0]
    x = SIZES
    ax.plot(x, [res[str(s)]["latency_median_ms"] for s in x], "o-", color=style.C["blue"], label="median")
    ax.plot(x, [res[str(s)]["latency_p95_ms"] for s in x], "s--", color=style.C["orange"], label="p95")
    ax.plot(x, x, ":", color="k", lw=0.7, label="window length (floor)")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xticks(x, [str(s) for s in x])
    style.log_ticks(ax, [50, 100, 200, 500], axis="y")
    ax.set_xlabel("Batch window (ms)")
    ax.set_ylabel("Detection latency (ms)")
    ax.legend(fontsize=6)
    ax = axs[1]
    ax.plot(x, [100 * res[str(s)]["detect_rate"] for s in x], "o-", color=style.C["green"], label="intrusions detected (%)")
    ax.plot(x, [100 * res[str(s)]["macro_f1_settled"] for s in x], "s--", color=style.C["purple"], label="macro-F1 settled (x100)")
    ax.set_xscale("log")
    ax.set_xticks(x, [str(s) for s in x])
    ax.set_xlabel("Batch window (ms)")
    ax.set_ylabel("%")
    ax.set_ylim(90, 101)
    ax2 = ax.twinx()
    ax2.plot(x, [res[str(s)]["false_alerts_per_hour"] for s in x], "^:", color=style.C["red"], label="false alerts / h")
    ax2.set_ylabel("False alerts / h", color=style.C["red"])
    ax2.set_ylim(0, max(1.0, 1.2 * max(res[str(s)]["false_alerts_per_hour"] for s in x)))
    ax2.spines["right"].set_visible(True)
    ax2.grid(False)
    h1, l1 = ax.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax.legend(h1 + h2, l1 + l2, fontsize=5.5, loc="lower left")
    f.tight_layout()
    style.save(f, "hcrl_window")
    for s in SIZES:
        r = res[str(s)]
        print(s, round(r["detect_rate"], 4), round(r["latency_median_ms"]), round(r["latency_p95_ms"]), round(r["false_alerts_per_hour"], 1),
              round(r["macro_f1_all"], 3), round(r["macro_f1_settled"], 3))


if __name__ == "__main__":
    main()
