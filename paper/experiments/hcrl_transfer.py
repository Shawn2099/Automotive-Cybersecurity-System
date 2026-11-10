"""Exp 4: cross-domain transfer. RF trained on {synthetic-nominal, synthetic-measured, HCRL, HCRL+synthetic}
tested on {HCRL hold-out, fresh simulator (measured), fresh simulator (nominal)}.

'nominal' simulator = the project's VirtualCar WITHOUT the measured attack behaviour (profile copy with
attack_behaviour={}: nominal paper injection rates, all legitimate traffic survives). Patched in-process via
common.can_profiles.CAN_PROFILES; no project file is modified.

    python -m paper.experiments.hcrl_transfer
"""
from __future__ import annotations

import dataclasses

import numpy as np

from paper.experiments import hcrl_common as H
from paper.experiments import style

C = H.CLASSES
SEEDS = [0, 1, 2, 3, 4]  # simulator dataset seeds (each seed = new training set + new fresh-test set)
TRAIN_SETS = [("synth_nominal", "Sim. nominal"), ("synth_measured", "Sim. measured"), ("hcrl", "HCRL"),
              ("hcrl_synth_measured", "HCRL + sim. measured")]
TEST_SETS = [("hcrl_heldout", "HCRL hold-out"), ("fresh_measured", "Fresh sim. (measured)"),
             ("fresh_nominal", "Fresh sim. (nominal)")]


def gen_sim(mode: str, seed: int) -> dict:
    """Synthetic training set + fresh test set for one simulator flavour. Runs in a worker process."""
    P = H.project()
    orig = P.CP.CAN_PROFILES[P.CP.DEFAULT_PROFILE]
    if mode == "nominal":
        P.CP.CAN_PROFILES[P.CP.DEFAULT_PROFILE] = dataclasses.replace(orig, attack_behaviour={})
    try:
        ds = P.GD.generate(seed=seed)
        jobs = [("normal", None)] * 3 + [(a, a) for a in P.VS.ATTACKS for _ in range(2)]
        X, y, st = [], [], []
        for i, (_, atk) in enumerate(jobs):
            r = P.GD.run_scenario(seed=4_000_000 + 1000 * seed + i, run_id=1000 + i, seconds=60 if atk is None else 45,
                                  attack=atk)
            X += r["xt"]
            y += r["ya"]
            st += r["settle"]
    finally:
        P.CP.CAN_PROFILES[P.CP.DEFAULT_PROFILE] = orig
    tr, _ = P.T.synthetic_split(ds)
    fit = tr & (ds["settle"] == 0)
    return {"Xtr": ds["X_traffic"][fit], "ytr": ds["y_attack"][fit],
            "Xall": ds["X_traffic"], "yall": ds["y_attack"], "settle": ds["settle"],
            "Xf": np.asarray(X, dtype=np.float32), "yf": np.asarray(y), "sf": np.asarray(st, dtype=bool)}


def _job(mode, seed):
    return (mode, seed, gen_sim(mode, seed))


def build_sims():
    from joblib import Parallel, delayed

    res = Parallel(n_jobs=min(8, 2 * len(SEEDS)))(delayed(_job)(m, s) for m in ("nominal", "measured") for s in SEEDS)
    return {(m, s): d for m, s, d in res}


def main():
    P = H.project()
    from paper.experiments.hcrl_rf import build_hcrl
    h = H.cached("hcrl_features", build_hcrl)
    sims = H.cached("transfer_sims", build_sims)
    tr, te = ~h["test"], h["test"]
    fit_h = tr & ~h["settle"]
    Xh, yh = h["X"][fit_h], h["y"][fit_h]
    Xte, yte, ute = h["X"][te], h["y"][te], h["settle"][te]

    res = {k: {t: {"all": [], "settled": []} for t, _ in TEST_SETS} for k, _ in TRAIN_SETS}
    perclass_hcrl = {}
    conf_hcrl = {}
    for s in SEEDS:
        nom, mea = sims[("nominal", s)], sims[("measured", s)]
        train = {
            "synth_nominal": (nom["Xtr"], nom["ytr"]),
            "synth_measured": (mea["Xtr"], mea["ytr"]),
            "hcrl": (Xh, yh),
            "hcrl_synth_measured": (np.concatenate([Xh, mea["Xtr"]]), np.concatenate([yh, mea["ytr"]])),
        }
        tests = {"hcrl_heldout": (Xte, yte, ute), "fresh_measured": (mea["Xf"], mea["yf"], mea["sf"]),
                 "fresh_nominal": (nom["Xf"], nom["yf"], nom["sf"])}
        for k, _ in TRAIN_SETS:
            rf = P.T._rf().fit(*train[k])
            for t, (X, y, u) in tests.items():
                p = rf.predict(X)
                res[k][t]["all"].append(H.macro_f1(y, p))
                res[k][t]["settled"].append(H.macro_f1(y[~u], p[~u]))
                if t == "hcrl_heldout" and s == 0:
                    perclass_hcrl[k] = {"all": H.prf(y, p), "settled": H.prf(y[~u], p[~u])}
                    conf_hcrl[k] = H.confusion(y, p).tolist()
    summ = {k: {t: {m: {"mean": float(np.mean(v)), "sd": float(np.std(v)), "values": v} for m, v in d.items()}
                for t, d in td.items()} for k, td in res.items()}
    out = {"seeds": SEEDS, "macro_f1": summ, "hcrl_heldout_per_class_seed0": perclass_hcrl,
           "hcrl_heldout_confusion_all_seed0": conf_hcrl, "classes": C}

    # feature medians on attack windows (settled): HCRL vs nominal sim vs measured sim (seed 0)
    names = P.A.TRAFFIC_FEATURE_NAMES
    show = ["total_ratio", "max_known_ratio", "unknown_fps", "n_unknown_ids", "max_unknown_id_fps", "bus_load_pct"]
    fm = {}
    for c in C:
        mh = (h["y"] == c) & ~h["settle"]
        row = {"hcrl": {n: float(np.median(h["X"][mh][:, names.index(n)])) for n in show}}
        for mode in ("nominal", "measured"):
            d = sims[(mode, 0)]
            m = (d["yall"] == c) & (d["settle"] == 0)
            row[mode] = {n: float(np.median(d["Xall"][m][:, names.index(n)])) for n in show}
        fm[c] = row
    out["feature_medians"] = fm
    H.save_json("hcrl_transfer", out)

    # ---- tables
    def cell(k, t, m):
        v = summ[k][t][m]
        return f"{v['mean']:.3f}" + ("" if k == "hcrl" and t == "hcrl_heldout" else f" $\\pm$ {v['sd']:.3f}")

    for m, nm in (("settled", "hcrl_transfer_settled"), ("all", "hcrl_transfer_all")):
        rows = [[lab] + [("raw", cell(k, t, m)) for t, _ in TEST_SETS] for k, lab in TRAIN_SETS]
        H.write_table(
            nm,
            f"Cross-domain transfer of the RandomForest: macro-F1 over {{normal, DoS, fuzzy, spoofing}}, "
            f"{'settled' if m == 'settled' else 'all'} windows, mean $\\pm$ s.d. over {len(SEEDS)} simulator seeds "
            "(HCRL-only has no simulator seed on the HCRL hold-out, so it has no s.d.). Rows: training data. Columns: test data. "
            "``Nominal'' simulator = injection at the published rates with all legitimate traffic surviving; "
            "``measured'' = injection rate and legitimate-traffic loss taken from the HCRL captures.",
            f"tab:{nm}", ["Trained on"] + [lab for _, lab in TEST_SETS], rows, align="lrrr")

    # ---- figure
    f, axs = style.fig(style.FULL_W, 2.5, ncols=2, sharey=True)
    cols = [style.C["red"], style.C["orange"], style.C["blue"], style.C["green"]]
    hat = ["", "//", "xx", ".."]
    for ax, (m, ttl) in zip(axs, (("settled", "Settled windows"), ("all", "All windows"))):
        w = 0.2
        for j, (k, lab) in enumerate(TRAIN_SETS):
            mu = [summ[k][t][m]["mean"] for t, _ in TEST_SETS]
            sd = [summ[k][t][m]["sd"] for t, _ in TEST_SETS]
            xs = np.arange(len(TEST_SETS)) + (j - 1.5) * w
            ax.bar(xs, mu, w, yerr=sd, color=cols[j], hatch=hat[j], edgecolor="white", lw=0.3, label=lab,
                   error_kw={"lw": 0.6, "capsize": 1.2})
            for x, v in zip(xs, mu):
                ax.text(x, v + 0.025, f"{v:.2f}", ha="center", fontsize=5, rotation=90)
        ax.set_xticks(range(len(TEST_SETS)), [lab for _, lab in TEST_SETS], fontsize=6)
        ax.set_title(ttl)
        ax.set_ylim(0, 1.5); ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
        ax.grid(axis="x", visible=False)
    axs[0].set_ylabel("Macro-F1")
    axs[0].legend(loc="upper left", fontsize=5.5, ncol=2, columnspacing=0.8, handlelength=1.2)
    f.tight_layout()
    style.save(f, "hcrl_transfer")
    print({k: {t: round(summ[k][t]["settled"]["mean"], 3) for t, _ in TEST_SETS} for k, _ in TRAIN_SETS})
    print({k: {t: round(summ[k][t]["all"]["mean"], 3) for t, _ in TEST_SETS} for k, _ in TRAIN_SETS})


if __name__ == "__main__":
    main()
