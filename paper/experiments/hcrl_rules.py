"""Exp 2: rule-based detector (VehicleAnalyzer, models=None) replayed on real HCRL 100 ms windows.

    python -m paper.experiments.hcrl_rules
"""
from __future__ import annotations

import numpy as np

from paper.experiments import hcrl_common as H
from paper.experiments import style

C = H.CLASSES
LAB = {"normal": "Normal", "dos": "DoS", "fuzzy": "Fuzzy", "spoofing": "Spoofing"}


def cm_plot(ax, cm, title):
    n = cm / np.maximum(cm.sum(1, keepdims=True), 1)
    ax.imshow(n, vmin=0, vmax=1, cmap="Blues")
    for i in range(4):
        for j in range(4):
            ax.text(j, i, f"{100 * n[i, j]:.1f}", ha="center", va="center", fontsize=6.5,
                    color="white" if n[i, j] > 0.55 else "black")
    ax.set_xticks(range(4), [LAB[c] for c in C], rotation=30, ha="right")
    ax.set_yticks(range(4), [LAB[c] for c in C])
    ax.set_xlabel("Predicted")
    ax.set_title(title)
    ax.grid(False)
    for s in ax.spines.values():
        s.set_visible(True)


def main():
    wins = H.load_hcrl_windows()
    R = H.cached("rules_replay_100ms", H.replay_all, wins)
    y = np.concatenate([R[n]["labels"] for n in R])
    p = np.concatenate([R[n]["preds"] for n in R])
    uns = np.concatenate([R[n]["unsettled"] for n in R])
    out = {"windows": int(len(y)), "unsettled_windows": int(uns.sum()),
           "all": H.prf(y, p), "settled": H.prf(y[~uns], p[~uns]),
           "confusion_all": H.confusion(y, p).tolist(), "confusion_settled": H.confusion(y[~uns], p[~uns]).tolist(),
           "classes": C}
    # ---- table: per-class P/R/F1
    rows = []
    for c in C:
        a, s = out["all"][c], out["settled"][c]
        rows.append([LAB[c], H.f3(a["precision"]), H.f3(a["recall"]), H.f3(a["f1"]), f"{a['support']:,}",
                     H.f3(s["precision"]), H.f3(s["recall"]), H.f3(s["f1"]), f"{s['support']:,}"])
    rows.append("MID")
    rows.append(["Macro avg", "", "", H.f3(out["all"]["macro_f1"]), "", "", "", H.f3(out["settled"]["macro_f1"]), ""])
    H.write_table(
        "hcrl_rules_perclass",
        "Rule-based detector on real HCRL traffic, 100~ms windows (all five captures pooled). A window is an attack window "
        "if it holds at least one injected frame. ``Settled'' drops windows within 0.7~s of a label change, where the 0.5~s "
        "rate smoothing still lags the label.",
        "tab:hcrl_rules_perclass",
        ["Class", "P", "R", "F1", "N", "P", "R", "F1", "N"], rows, align="lrrrrrrrr",
        header_rows=[r"& \multicolumn{4}{c}{All windows} & \multicolumn{4}{c}{Settled windows} \\",
                     r"\cmidrule(lr){2-5}\cmidrule(lr){6-9}"])
    # ---- confusion figure
    f, axs = style.fig(style.FULL_W, 2.6, ncols=2)
    cm_plot(axs[0], np.array(out["confusion_all"]), "All windows (row-normalised, %)")
    axs[0].set_ylabel("True")
    cm_plot(axs[1], np.array(out["confusion_settled"]), "Settled windows (%)")
    f.tight_layout()
    style.save(f, "hcrl_rules_confusion")

    # ---- per-intrusion detection + latency
    det = {}
    rows = []
    allhit = allint = 0
    for n in H.ATTACK_FILES:
        r = R[n]
        lat = np.array(r["latencies_s"]) * 1000.0
        lo, hi = H.wilson(r["n_detected"], r["n_intrusions"])
        det[n] = {"intrusions": r["n_intrusions"], "detected": r["n_detected"],
                  "rate": r["n_detected"] / r["n_intrusions"], "wilson95": [lo, hi],
                  "latency_ms": {"min": float(lat.min()), "median": H.pct(lat, 50), "p95": H.pct(lat, 95),
                                 "max": float(lat.max()), "mean": float(lat.mean())},
                  "alerts_outside_intrusions": r["alerts_outside"], "wrong_class_alerts": r["alerts_wrong_class"],
                  "latency_ms_all": [float(x) for x in lat]}
        allhit += r["n_detected"]
        allint += r["n_intrusions"]
        rows.append([H.FILE_SHORT[n], r["n_intrusions"], r["n_detected"], f"{100 * det[n]['rate']:.1f}",
                     f"{lo * 100:.1f}--{hi * 100:.1f}", f"{det[n]['latency_ms']['median']:.0f}",
                     f"{det[n]['latency_ms']['p95']:.0f}", f"{det[n]['latency_ms']['max']:.0f}",
                     r["alerts_outside"], r["alerts_wrong_class"]])
    out["per_intrusion"] = det
    out["intrusions_total"], out["detected_total"] = allint, allhit
    H.write_table(
        "hcrl_rules_latency",
        "Per-intrusion detection by the rule engine. Latency = time from the first injected frame to the first alert of "
        "the matching category; it is quantised by the 100~ms batch, so the floor is one window. Alerts outside "
        "intrusions are counted from 1~s after a burst ends.",
        "tab:hcrl_rules_latency",
        ["Attack", "Intrus.", "Detected", ("raw", r"Rate (\%)"), ("raw", r"95\% CI (\%)"), "Med.", "P95", "Max", "False", "Wrong cl."],
        rows, align="lrrrrrrrrr",
        note="Med./P95/Max in ms. False = cyber alerts outside intrusions; Wrong cl. = alerts of another category during a burst.",
        header_rows=[r"& & & & & \multicolumn{3}{c}{Latency (ms)} & \multicolumn{2}{c}{Extra alerts} \\",
                     r"\cmidrule(lr){6-8}\cmidrule(lr){9-10}"])
    # ---- ECDF
    f, ax = style.fig(style.COL_W, 2.2)
    for k, n in enumerate(H.ATTACK_FILES):
        x = np.sort(det[n]["latency_ms_all"])
        ax.step(x, np.arange(1, len(x) + 1) / len(x), where="post", color=H.FILE_COLOR[n],
                ls=style.LINES[k], label=H.FILE_SHORT[n])
    ax.axvline(100, color="k", lw=0.5, ls=":")
    ax.text(103, 0.04, "1 window", fontsize=6)
    ax.set_xlabel("Detection latency (ms)")
    ax.set_ylabel("ECDF over intrusions")
    ax.legend(loc="lower right")
    ax.set_ylim(0, 1.02)
    style.save(f, "hcrl_rules_latency_ecdf")

    # ---- false positives
    nr = R["normal_run_data.txt"]
    hrs = nr["duration_s"] / 3600
    cyb = sum(v for k, v in nr["alert_counter"].items() if k.startswith("cyber:"))
    mec = sum(v for k, v in nr["alert_counter"].items() if k.startswith("mechanical:"))
    nsec = sum(R[n]["normal_seconds"] for n in H.ATTACK_FILES)
    out["normal_run"] = {"duration_s": nr["duration_s"], "cyber_alerts": cyb, "mechanical_alerts": mec,
                         "windows_predicted_attack": int((nr["preds"] != "normal").sum())}
    out["attack_capture_normal_stretches"] = {"seconds": nsec, "cyber_alerts_outside": sum(R[n]["alerts_outside"] for n in H.ATTACK_FILES)}
    out["per_file_confusion"] = {n: H.confusion(R[n]["labels"], R[n]["preds"]).tolist() for n in R}
    H.save_json("hcrl_rules", out)
    print({"macro_all": out["all"]["macro_f1"], "macro_settled": out["settled"]["macro_f1"], "detected": f"{allhit}/{allint}"})


if __name__ == "__main__":
    main()
