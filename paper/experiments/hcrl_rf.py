"""Exp 3: RandomForest on HCRL (HCRL-only, and the deployed HCRL+synthetic model), time-contiguous 75/25 split.

    python -m paper.experiments.hcrl_rf
"""
from __future__ import annotations

import numpy as np

from paper.experiments import hcrl_common as H
from paper.experiments import style
from paper.experiments.hcrl_rules import LAB, cm_plot

C = H.CLASSES


def build_hcrl():
    P = H.project()
    h = P.T.hcrl_dataset(H.HCRL_DIR)
    h["file_names"] = list(P.HI.load_windows(H.HCRL_DIR).keys())
    return h


def load_synth_measured():
    """Read-only load of the project's cached synthetic dataset (asserts the feature version)."""
    P = H.project()
    ds = dict(np.load(P.GD.DATA_DIR / "dataset.npz"))
    assert int(ds["version"]) == P.GD.DATASET_VERSION, "cached synthetic dataset is stale; run python -m ml_training.generate_dataset"
    return ds


def n_intrusions(labels, gap=3):
    return len(H.intrusions(list(labels), [0] * len(labels), gap))


def block(y, p, unsettled):
    return {"all": H.prf(y, p), "settled": H.prf(y[~unsettled], p[~unsettled]),
            "confusion_all": H.confusion(y, p).tolist()}


def main():
    import joblib

    P = H.project()
    h = H.cached("hcrl_features", build_hcrl)
    ds = load_synth_measured()
    xs, ys, sst = ds["X_traffic"], ds["y_attack"], ds["settle"]
    s_tr, _ = P.T.synthetic_split(ds)
    tr, te = ~h["test"], h["test"]
    fit_h = tr & ~h["settle"]
    fit_s = s_tr & (sst == 0)
    names = P.A.TRAFFIC_FEATURE_NAMES
    rf_h = P.T._rf().fit(h["X"][fit_h], h["y"][fit_h])
    rf_c = P.T._rf().fit(np.concatenate([h["X"][fit_h], xs[fit_s]]), np.concatenate([h["y"][fit_h], ys[fit_s]]))
    dep = joblib.load(P.T.MODEL_DIR / "cyber_rf.joblib")  # read-only
    assert dep["features"] == names
    rf_d = dep["model"]
    models = {"hcrl_only": rf_h, "deployed": rf_d, "hcrl_plus_synth_retrained": rf_c}
    Xte, yte, ute = h["X"][te], h["y"][te], h["settle"][te]
    out = {"split": "last 25% of every capture held out, time-contiguous; training windows within 0.6 s of a label change excluded",
           "heldout_windows": int(te.sum()), "train_windows_hcrl": int(fit_h.sum()), "train_windows_synth": int(fit_s.sum()),
           "feature_names": names, "models": {}}
    for k, m in models.items():
        out["models"][k] = block(yte, m.predict(Xte), ute)
        out["models"][k]["importance"] = dict(zip(names, map(float, m.feature_importances_)))
    out["deployed_vs_retrained_agreement"] = float((rf_d.predict(Xte) == rf_c.predict(Xte)).mean())
    # held-out size per class (windows and intrusions)
    ho = {}
    for c in C:
        ho[c] = {"windows": int((yte == c).sum())}
    ho_int = {}
    for k, nm in enumerate(h["file_names"]):
        m = te & (h["file"] == k)
        ho_int[nm] = n_intrusions(h["y"][m])
    out["heldout_intrusions_per_file"] = ho_int
    out["heldout_per_class"] = ho
    # shortcut check: drop the steering features (steering ID is absent in 3 of 4 captures)
    keep = [i for i, n in enumerate(names) if n not in ("steering_ratio", "steering_rate")]
    rf_ns = P.T._rf().fit(h["X"][fit_h][:, keep], h["y"][fit_h])
    p = rf_ns.predict(Xte[:, keep])
    out["ablation_no_steering_features"] = block(yte, p, ute)
    out["ablation_no_steering_features"]["dropped"] = ["steering_ratio", "steering_rate"]
    # per-class tables
    rows = []
    for c in C:
        r = []
        for k in ("hcrl_only", "deployed"):
            for s in ("all", "settled"):
                b = out["models"][k][s][c]
                r += [H.f3(b["precision"]), H.f3(b["recall"]), H.f3(b["f1"])]
        rows.append([LAB[c]] + r)
    rows.append("MID")
    rows.append(["Macro avg"] + sum([["", "", H.f3(out["models"][k][s]["macro_f1"])] for k in ("hcrl_only", "deployed")
                                      for s in ("all", "settled")], []))
    H.write_table(
        "hcrl_rf_perclass",
        "RandomForest on the time-contiguous HCRL hold-out (last 25\\% of each capture). HCRL-only: trained on HCRL "
        "windows; Deployed: HCRL plus simulator windows (the model shipped with the system).",
        "tab:hcrl_rf_perclass",
        ["Class"] + ["P", "R", "F1"] * 4, rows, align="l" + "rrr" * 4, star=True,
        header_rows=[r"& \multicolumn{6}{c}{HCRL-only RF} & \multicolumn{6}{c}{Deployed RF (HCRL+sim)} \\",
                     r"& \multicolumn{3}{c}{All} & \multicolumn{3}{c}{Settled} & \multicolumn{3}{c}{All} & \multicolumn{3}{c}{Settled} \\",
                     r"\cmidrule(lr){2-4}\cmidrule(lr){5-7}\cmidrule(lr){8-10}\cmidrule(lr){11-13}"])
    # importance figure
    f, ax = style.fig(style.COL_W, 2.6)
    order = np.argsort(np.array(list(out["models"]["hcrl_only"]["importance"].values())))
    y = np.arange(len(names))
    for j, (k, col, lab) in enumerate((("hcrl_only", style.C["blue"], "HCRL-only"),
                                       ("deployed", style.C["orange"], "Deployed (HCRL+sim)"))):
        v = np.array([out["models"][k]["importance"][names[i]] for i in order])
        ax.barh(y + (j - 0.5) * 0.38, v, height=0.36, color=col, label=lab, hatch=("" if j == 0 else "///"),
                edgecolor="white", lw=0.3)
    ax.set_yticks(y, [names[i].replace("_", " ") for i in order])
    ax.set_xlabel("Gini importance")
    ax.legend(loc="lower right")
    ax.grid(axis="y", visible=False)
    style.save(f, "hcrl_rf_importance")
    # confusion
    f, axs = style.fig(style.FULL_W, 2.6, ncols=2)
    cm_plot(axs[0], np.array(out["models"]["hcrl_only"]["confusion_all"]), "HCRL-only RF (%)")
    cm_plot(axs[1], np.array(out["models"]["deployed"]["confusion_all"]), "Deployed RF, HCRL+sim (%)")
    axs[0].set_ylabel("True")
    f.tight_layout()
    style.save(f, "hcrl_rf_confusion")
    H.save_json("hcrl_rf", out)
    print({k: (v["all"]["macro_f1"], v["settled"]["macro_f1"]) for k, v in out["models"].items()},
          "ablation", out["ablation_no_steering_features"]["all"]["macro_f1"], ho_int)


if __name__ == "__main__":
    main()
