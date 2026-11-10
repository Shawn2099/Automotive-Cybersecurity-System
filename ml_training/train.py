"""Train the IsolationForest (health) and RandomForest (attack class) models.

Run:  python -m ml_training.train                 # everything from the Sonata-spec VirtualCar (synthetic)
      python -m ml_training.train --hcrl data/hcrl  # RF trained on real HCRL Car-Hacking batches
NOTE: synthetic metrics measure "does the model recognise the simulator", not real-vehicle performance.
In --hcrl mode the RF is evaluated on a time-contiguous hold-out (last 25 % of every file); the
IsolationForest stays synthetic because HCRL carries no health signals we can use.
The 'tunnel_attack' class has no traffic signature (it is event-based), so the RF never learns it.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report

from ml_training.generate_dataset import DATA_DIR, DATASET_VERSION, SETTLE_S, generate
from server.app.analytics import HEALTH_FEATURE_NAMES, TRAFFIC_FEATURE_NAMES, FeatureState, Models

MODEL_DIR = Path(__file__).resolve().parent.parent / "server" / "models"
HCRL_URL = "https://sites.google.com/hksecurity.net/hcrl/Datasets/car-hacking-dataset"


def _load_dataset(quick: bool = False) -> dict:
    path = DATA_DIR / "dataset.npz"
    if path.exists() and not quick:
        ds = dict(np.load(path))
        if int(ds.get("version", 0)) == DATASET_VERSION:
            return ds
    ds = generate(quick=quick)
    if not quick:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(path, **ds)
    return ds


def _report(y_true, y_pred) -> dict:
    return classification_report(y_true, y_pred, output_dict=True, zero_division=0)


def _f1s(rep: dict) -> dict:
    return {k: round(v["f1-score"], 3) for k, v in rep.items() if isinstance(v, dict) and k not in ("macro avg", "weighted avg")}


def train_iforest(ds: dict, train: np.ndarray, test: np.ndarray) -> tuple[Models, dict]:
    xh, yf, clean = ds["X_health"], ds["y_fault"], ds["clean"]
    fit_mask = train & (clean == 1)
    iforest = IsolationForest(n_estimators=100, contamination="auto", random_state=0).fit(xh[fit_mask])
    s_fit = -iforest.score_samples(xh[fit_mask])
    lo, hi = float(np.median(s_fit)), float(np.percentile(s_fit, 99.5))
    models = Models(iforest=iforest, if_lo=lo, if_hi=hi)
    s_test = -iforest.score_samples(xh[test])
    scores = np.clip((s_test - lo) / max(1e-6, hi - lo) / 2.0, 0.0, 1.0)  # same mapping as Models.anomaly_score
    tclean, tfault = clean[test] == 1, yf[test] == 1
    return models, {
        "train_batches": int(fit_mask.sum()),
        "mean_score_clean_heldout": float(scores[tclean].mean()),
        "frac_clean_heldout_above_0.65": float((scores[tclean] > 0.65).mean()),
        "mean_score_fault_heldout": float(scores[tfault].mean()),
        "frac_fault_heldout_above_0.65": float((scores[tfault] > 0.65).mean()),
    }


def _rf() -> RandomForestClassifier:
    return RandomForestClassifier(n_estimators=60, max_depth=12, class_weight="balanced", random_state=0, n_jobs=1)


def hcrl_dataset(folder: Path, max_seconds: float | None = None) -> dict:
    """Featurise every HCRL file (cached 100 ms windows) -> X, y, settle mask, time-contiguous test mask, file id."""
    from common.can_profiles import DEFAULT_PROFILE
    from ml_training.hcrl_import import load_windows

    xs, ys, settle, split, fid = [], [], [], [], []
    for k, (name, wins) in enumerate(load_windows(folder).items()):
        fs = FeatureState(DEFAULT_PROFILE)
        rows, labels, st = [], [], []
        last_label, last_change = "normal", -1e9
        for batch, label, _ in wins:
            t = batch["ts_ms"] / 1000.0
            if max_seconds is not None and t > max_seconds:
                break
            ctx = fs.step(batch, None, t)
            if label != last_label:
                last_label, last_change = label, t
            rows.append(ctx["traffic_vec"])
            labels.append(label)
            st.append(1 if t - last_change < SETTLE_S else 0)
        n = len(rows)
        print(f"  {name}: {n} windows, labels {dict(zip(*np.unique(labels, return_counts=True)))}" if n else f"  {name}: no frames parsed")
        xs += rows
        ys += labels
        settle += st
        split += [0] * int(n * 0.75) + [1] * (n - int(n * 0.75))
        fid += [k] * n
    return {"X": np.asarray(xs, dtype=np.float32), "y": np.asarray(ys), "settle": np.asarray(settle, dtype=bool),
            "test": np.asarray(split, dtype=bool), "file": np.asarray(fid)}


def synthetic_split(ds: dict) -> tuple[np.ndarray, np.ndarray]:
    """(train_mask, test_mask) over a synthetic dataset: whole runs held out."""
    test = (ds["run_id"] % 4) == 0
    return ~test, test


def main(argv: list[str] | None = None) -> dict | None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hcrl", default=None, help="folder with the HCRL Car-Hacking dataset (data/hcrl)")
    ap.add_argument("--combined", action="store_true",
                    help="--hcrl only: RF trained on HCRL train part + synthetic train part (evaluated on both hold-outs)")
    ap.add_argument("--max-seconds", type=float, default=None, help="--hcrl only: use first N seconds of each file")
    ap.add_argument("--quick", action="store_true", help="small synthetic dataset (not saved)")
    args = ap.parse_args(argv)
    t0 = time.time()

    hcrl = None
    if args.hcrl:
        folder = Path(args.hcrl)
        if not folder.is_dir():
            print(f"HCRL folder '{folder}' not found. Download the Car-Hacking dataset from\n  {HCRL_URL}\n"
                  f"and unzip it into '{folder}', then run: python -m ml_training.hcrl_import {folder} --write-profile")
            return None
        from common.can_profiles import get_profile

        if get_profile("hyundai_sonata_hcrl").periods_source != "hcrl_measured":
            print("WARNING: profile periods are not HCRL-measured; most HCRL IDs will look 'unknown'.\n"
                  f"  Run first: python -m ml_training.hcrl_import {folder} --write-profile")
        print("featurising HCRL files ...")
        hcrl = hcrl_dataset(folder, args.max_seconds)
        if len(hcrl["y"]) == 0:
            print("no HCRL frames parsed; nothing to train")
            return None

    ds = _load_dataset(args.quick)
    xh, xt, ya, run, settle = ds["X_health"], ds["X_traffic"], ds["y_attack"], ds["run_id"], ds["settle"]
    test = (run % 4) == 0  # hold out whole runs
    train = ~test

    models, if_metrics = train_iforest(ds, train, test)
    iforest, lo, hi = models.iforest, models.if_lo, models.if_hi

    if hcrl is None:
        source = "synthetic"
        fit = train & (settle == 0)
        rf = _rf().fit(xt[fit], ya[fit])
        pred = rf.predict(xt[test])
        rep_all = _report(ya[test], pred)
        ns = settle[test] == 0
        rep_ns = _report(ya[test][ns], pred[ns])
        n_train, n_test, counts = int(fit.sum()), int(test.sum()), dict(zip(*np.unique(ya, return_counts=True)))
    else:
        source = "hcrl+synthetic" if args.combined else "hcrl"
        h = hcrl
        tr, te = ~h["test"], h["test"]
        fit = tr & ~h["settle"]
        x_fit, y_fit = h["X"][fit], h["y"][fit]
        if args.combined:
            sfit = train & (settle == 0)
            x_fit, y_fit = np.concatenate([x_fit, xt[sfit]]), np.concatenate([y_fit, ya[sfit]])
        rf = _rf().fit(x_fit, y_fit)
        pred = rf.predict(h["X"][te])
        rep_all = _report(h["y"][te], pred)
        ns = ~h["settle"][te]
        rep_ns = _report(h["y"][te][ns], pred[ns])
        n_train, n_test = int(len(y_fit)), int(te.sum())
        counts = dict(zip(*np.unique(h["y"], return_counts=True)))
        if args.combined:  # also report the synthetic hold-out so both domains are visible
            sp = rf.predict(xt[test])
            sy_rep = _report(ya[test], sp)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": iforest, "lo": lo, "hi": hi, "features": HEALTH_FEATURE_NAMES},
                MODEL_DIR / "health_iforest.joblib")
    joblib.dump({"model": rf, "classes": [str(c) for c in rf.classes_], "features": TRAFFIC_FEATURE_NAMES},
                MODEL_DIR / "cyber_rf.joblib")
    extra = {}
    if source == "hcrl+synthetic":
        extra["random_forest_report_synthetic_heldout"] = sy_rep
    note = ("Synthetic: trained on data from the project's own VirtualCar (Sonata/HCRL-spec) and evaluated on held-out "
            "simulated runs. Near-perfect scores mostly show the models learned the simulator. Deterministic rules "
            "remain the primary detector." if source == "synthetic" else
            ("RandomForest trained on real HCRL Car-Hacking windows" + (" plus simulator windows" if source != "hcrl" else "") + " (100 ms), evaluated on the last 25 % of each file "
            "(time-contiguous hold-out). 'all' includes the ~0.6 s after each label change (rate-smoothing lag); "
            "'settled' excludes it. IsolationForest is still trained on synthetic health data. tunnel_attack is "
            "event-based and not learned from traffic."))
    metrics = {
        "training_source": source,
        "note": note,
        "dataset": {"train_batches": n_train, "test_batches": n_test,
                    "label_counts": {str(k): int(v) for k, v in counts.items()}},
        "isolation_forest": {"training_source": "synthetic", **if_metrics},
        "random_forest_report_heldout_all": rep_all,
        "random_forest_report_heldout_settled": rep_ns,
        **extra,
        "feature_names": TRAFFIC_FEATURE_NAMES,
        "train_seconds": round(time.time() - t0, 1),
    }
    (MODEL_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(json.dumps({"training_source": source, "isolation_forest": if_metrics,
                      "rf_accuracy_all": round(rep_all["accuracy"], 4), "rf_f1_all": _f1s(rep_all),
                      "rf_accuracy_settled": round(rep_ns["accuracy"], 4), "rf_f1_settled": _f1s(rep_ns)}, indent=2))
    return metrics


if __name__ == "__main__":
    main()
