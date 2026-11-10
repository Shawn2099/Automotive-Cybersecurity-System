"""Evaluate the detectors on the REAL HCRL Car-Hacking data -> server/models/hcrl_eval.json + EVALUATION.md.

    python tools/eval_hcrl.py [--hcrl data/hcrl]

  a. rules (VehicleAnalyzer, models=None) replayed over every file in time order (100 ms windows)
  b. RandomForest trained on HCRL (time-contiguous split: last 25 % of every file held out)
  c. cross-domain: RF(synthetic) -> HCRL hold-out, RF(HCRL) / RF(HCRL+synthetic) -> fresh simulator runs

First run parses the dataset into cached windows (ml_training/data/hcrl_cache, ~20 s); afterwards ~1-2 min.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sklearn.metrics import precision_recall_fscore_support  # noqa: E402

from common.can_profiles import DEFAULT_PROFILE  # noqa: E402
from ml_training import train as T  # noqa: E402
from ml_training.generate_dataset import SETTLE_S, run_scenario  # noqa: E402
from ml_training.hcrl_import import attack_class_for_file, load_windows  # noqa: E402
from common.vehicle_sim import ATTACKS  # noqa: E402
from server.app import analytics as A  # noqa: E402

CLASSES = ["normal", "dos", "fuzzy", "spoofing"]
EXPECT_CATS = {"DoS_dataset.csv": {"dos"}, "Fuzzy_dataset.csv": {"fuzzy"},
               "gear_dataset.csv": {"spoofing_gear"}, "RPM_dataset.csv": {"spoofing_rpm"}}
WIN_S = 0.1
INTRUSION_MERGE_GAP = 3  # windows


def prf(y_true, y_pred) -> dict:
    p, r, f, n = precision_recall_fscore_support(y_true, y_pred, labels=CLASSES, zero_division=0)
    out = {c: {"precision": round(float(p[i]), 4), "recall": round(float(r[i]), 4), "f1": round(float(f[i]), 4),
               "support": int(n[i])} for i, c in enumerate(CLASSES)}
    out["accuracy"] = round(float((np.asarray(y_true) == np.asarray(y_pred)).mean()), 4)
    return out


def pct(a, q):
    return round(float(np.percentile(a, q)), 3) if len(a) else None


# --------------------------------------------------------------------------- a. rules on real windows
def intrusions(labels: list[str], inj: list[float | None]) -> list[tuple[int, int, float]]:
    """(first_window, last_window, first_injected_ts_s) per intrusion (runs of attack windows, small gaps merged)."""
    out, start, last = [], None, None
    for i, l in enumerate(labels):
        if l == "normal":
            continue
        if start is not None and i - last > INTRUSION_MERGE_GAP:
            out.append((start, last, inj[start]))
            start = None
        if start is None:
            start = i
        last = i
    if start is not None:
        out.append((start, last, inj[start]))
    return out


def replay_rules(name: str, wins: list) -> dict:
    an = A.VehicleAnalyzer(DEFAULT_PROFILE, None)
    labels, preds, settle, alerts, rule_cats = [], [], [], [], []
    last_label, last_change = "normal", -1e9
    for b, label, _ in wins:
        t_end = b["ts_ms"] / 1000.0 + WIN_S
        res = an.update(b, None, t_end)
        for a in res["alerts"]:
            alerts.append((t_end, a["kind"], a["category"]))
        cats = an._records[-1][2]
        pred = next((A.CLASS_OF[c] for c in A.CLASS_PRIORITY if c in cats), "normal")
        if label != last_label:
            last_label, last_change = label, t_end
        labels.append(label)
        preds.append(pred)
        rule_cats.append(set(cats))
        settle.append(t_end - last_change < SETTLE_S + WIN_S)
    inj = [w[2] for w in wins]
    settle = np.asarray(settle)
    ivs = intrusions(labels, inj)
    expect = EXPECT_CATS.get(name)
    cls = attack_class_for_file(name)
    det, lat, lat_rule = 0, [], []
    iv_spans = []
    for (i0, i1, t_inj) in ivs:
        t_end = wins[i1][0]["ts_ms"] / 1000.0 + WIN_S
        iv_spans.append((t_inj, t_end + 1.0))
        hit = [t for (t, kind, c) in alerts if kind == "cyber" and c in (expect or set()) and t_inj <= t <= t_end + 1.0]
        if hit:
            det += 1
            lat.append(hit[0] - t_inj)
        rh = [(wins[j][0]["ts_ms"] / 1000.0 + WIN_S) for j in range(i0, min(len(wins), i1 + 11))
              if rule_cats[j] & (expect or set())]
        if rh:
            lat_rule.append(rh[0] - t_inj)

    def in_iv(t):
        return any(a <= t <= b for a, b in iv_spans)

    n_norm_win = sum(1 for l in labels if l == "normal")
    cyber_outside = [(t, c) for (t, k, c) in alerts if k == "cyber" and not in_iv(t)]
    wrong_class = [(t, c) for (t, k, c) in alerts if k == "cyber" and in_iv(t) and c not in (expect or set())]
    mech = Counter(c for (_, k, c) in alerts if k == "mechanical")
    return {
        "file": name, "windows": len(wins), "duration_s": round(len(wins) * WIN_S, 1),
        "window_confusion_all": {f"{a}->{b}": n for (a, b), n in sorted(Counter(zip(labels, preds)).items())},
        "window_confusion_settled": {f"{a}->{b}": n for (a, b), n in sorted(
            Counter(zip(np.asarray(labels)[~settle], np.asarray(preds)[~settle])).items())},
        "labels": labels, "preds": preds, "settle": settle,
        "intrusions": len(ivs), "intrusions_detected_by_alert": det,
        "detection_rate": round(det / len(ivs), 4) if ivs else None,
        "latency_alert_s": {"median": pct(lat, 50), "p95": pct(lat, 95), "max": pct(lat, 100), "min": pct(lat, 0)},
        "latency_rule_state_s": {"median": pct(lat_rule, 50), "p95": pct(lat_rule, 95), "max": pct(lat_rule, 100)},
        "alerts_total": Counter(f"{k}:{c}" for (_, k, c) in alerts),
        "cyber_alerts_outside_intrusions": len(cyber_outside),
        "cyber_alerts_wrong_class_during_intrusion": len(wrong_class),
        "normal_seconds": round(n_norm_win * WIN_S, 1),
        "mechanical_alerts": dict(mech),
    }


def eval_rules(all_wins: dict) -> dict:
    per_file = {}
    for name, wins in all_wins.items():
        per_file[name] = replay_rules(name, wins)
    ys = np.concatenate([np.asarray(r["labels"]) for r in per_file.values()])
    ps = np.concatenate([np.asarray(r["preds"]) for r in per_file.values()])
    st = np.concatenate([r["settle"] for r in per_file.values()])
    out = {"per_class_all_windows": prf(ys, ps), "per_class_settled_windows": prf(ys[~st], ps[~st]),
           "per_file": {}}
    for n, r in per_file.items():
        r = {k: v for k, v in r.items() if k not in ("labels", "preds", "settle")}
        r["alerts_total"] = dict(r["alerts_total"])
        out["per_file"][n] = r
    nr = per_file.get("normal_run_data.txt")
    if nr:
        hrs = nr["duration_s"] / 3600.0
        cyb = sum(v for k, v in nr["alerts_total"].items() if k.startswith("cyber:"))
        mec = sum(v for k, v in nr["alerts_total"].items() if k.startswith("mechanical:"))
        out["normal_run"] = {"duration_s": nr["duration_s"], "cyber_alerts": cyb, "mechanical_alerts": mec,
                             "cyber_alerts_per_hour": round(cyb / hrs, 2), "mechanical_alerts_per_hour": round(mec / hrs, 2),
                             "alerts": nr["alerts_total"]}
    # false alerts in the attack captures' own normal (R-only) stretches
    nsec = sum(r["normal_seconds"] for n, r in per_file.items() if n != "normal_run_data.txt")
    nout = sum(r["cyber_alerts_outside_intrusions"] for n, r in per_file.items() if n != "normal_run_data.txt")
    out["attack_capture_normal_stretches"] = {
        "normal_seconds": round(nsec, 1), "cyber_alerts_outside_intrusions": nout,
        "per_hour": round(nout / (nsec / 3600.0), 2) if nsec else None}
    return out


# --------------------------------------------------------------------------- b / c. RF
def fresh_sim(seed0: int = 4_000_000) -> dict:
    """Fresh simulator runs (seeds never used for training): normal + each attack incl. steering_spoof."""
    jobs = [("normal", None)] * 3 + [(a, a) for a in ATTACKS for _ in range(2)]
    X, y, st, kind = [], [], [], []
    for i, (k, atk) in enumerate(jobs):
        r = run_scenario(seed=seed0 + i, run_id=1000 + i, seconds=60 if atk is None else 45, attack=atk)
        X += r["xt"]
        y += r["ya"]
        st += r["settle"]
        kind += [k] * len(r["ya"])
    return {"X": np.asarray(X, dtype=np.float32), "y": np.asarray(y), "settle": np.asarray(st, dtype=bool),
            "kind": np.asarray(kind)}


def rf_block(rf, X, y, settle) -> dict:
    p = rf.predict(X)
    return {"all": prf(y, p), "settled": prf(y[~settle], p[~settle])}


def per_attack_recall(rf, sim) -> dict:
    p = rf.predict(sim["X"])
    out = {}
    for k in ["normal"] + list(ATTACKS):
        m = (sim["kind"] == k) & ~sim["settle"]
        if k == "normal":
            out[k] = {"windows": int(m.sum()), "false_positive_rate": round(float((p[m] != "normal").mean()), 4)}
        else:
            am = m & (sim["y"] != "normal")
            nm = m & (sim["y"] == "normal")
            out[k] = {"attack_windows": int(am.sum()), "recall": round(float((p[am] != "normal").mean()), 4),
                      "correct_class": round(float((p[am] == sim["y"][am]).mean()), 4),
                      "false_positive_rate_between_bursts": round(float((p[nm] != "normal").mean()), 4)}
    return out


def eval_rf(hcrl_dir: Path) -> dict:
    h = T.hcrl_dataset(hcrl_dir)
    syn = T._load_dataset()
    s_tr, s_te = T.synthetic_split(syn)
    xs, ys, sst = syn["X_traffic"], syn["y_attack"], syn["settle"]
    tr, te = ~h["test"], h["test"]
    fit_h = tr & ~h["settle"]
    fit_s = s_tr & (sst == 0)
    models = {
        "rf_hcrl": T._rf().fit(h["X"][fit_h], h["y"][fit_h]),
        "rf_synthetic": T._rf().fit(xs[fit_s], ys[fit_s]),
        "rf_hcrl_plus_synthetic": T._rf().fit(np.concatenate([h["X"][fit_h], xs[fit_s]]),
                                              np.concatenate([h["y"][fit_h], ys[fit_s]])),
    }
    sim = fresh_sim()
    out = {"split": "last 25 % of every HCRL file held out (time-contiguous); synthetic: whole runs held out",
           "hcrl_heldout_windows": int(te.sum()), "fresh_sim_windows": int(len(sim["y"])), "models": {}}
    for name, rf in models.items():
        out["models"][name] = {
            "on_hcrl_heldout": rf_block(rf, h["X"][te], h["y"][te], h["settle"][te]),
            "on_synthetic_heldout": rf_block(rf, xs[s_te], ys[s_te], sst[s_te] == 1),
            "on_fresh_sim": rf_block(rf, sim["X"], sim["y"], sim["settle"]),
            "fresh_sim_per_attack": per_attack_recall(rf, sim),
        }
        # per HCRL file hold-out (shows file-specific behaviour)
        out["models"][name]["on_hcrl_heldout_per_file"] = {
            str(k): {"windows": int((te & (h["file"] == k)).sum()),
                     "accuracy": round(float((models[name].predict(h["X"][te & (h["file"] == k)])
                                              == h["y"][te & (h["file"] == k)]).mean()), 4)}
            for k in np.unique(h["file"])}
    # feature distributions: simulator vs real
    names = A.TRAFFIC_FEATURE_NAMES
    dist = {}
    for lab in CLASSES:
        hm = (h["y"] == lab) & ~h["settle"]
        sm = (sim["y"] == lab) & ~sim["settle"]
        if hm.any() and sm.any():
            dist[lab] = {n: {"hcrl_median": round(float(np.median(h["X"][hm][:, j])), 3),
                             "sim_median": round(float(np.median(sim["X"][sm][:, j])), 3)}
                         for j, n in enumerate(names) if n in ("total_ratio", "max_known_ratio", "unknown_fps",
                                                               "n_unknown_ids", "max_unknown_id_fps", "bus_load_pct")}
    out["feature_medians_settled"] = dist
    return out


NOTES = """## Changes made because of the real data (all in server/app/analytics.py, synthetic tests still pass)

| change | before | after | why (measured on real HCRL) |
|---|---|---|---|
| `DOS_UNKNOWN_ID_FPS` | 500 | 100 | Real DoS 0x000 runs at only ~340 frames/s in the capture (the simulator's 3300/s never occurs): the old threshold detected 29 % of DoS windows. 100/s equals the fastest legitimate message (100 Hz), and no unknown ID is ever seen on the normal capture. |
| `SPOOF_RATIO` | 3.0 | 1.5 | Real injected 0x43F / 0x316 are often only 1.1x to 3x the normal rate (frames are lost on the saturated bus), so 4 of 300 gear intrusions were never detected. The highest per-ID ratio over 46,826 settled normal windows is 1.2x. |
| `SIGNAL_MIN_RATIO` (new) | - | 0.5 | A message arriving at under half its expected rate is not trusted as a signal source. Fixes 262 false `low_battery` alerts in the Fuzzy capture (a fuzzed random frame with ID 0x549 was decoded as a battery voltage; 0x549 is not on the real bus). |
| alert re-arm (new, `REARM_QUIET_S` = 2 s) | 10 s cool-down only | cool-down, but a traffic-rule category that has been quiet for 2 s alerts again | HCRL bursts repeat every ~7.6 s, so the 10 s debounce hid about 30-50 % of intrusions (DoS: 154 alerts for 300 intrusions). Now exactly one alert per intrusion. |
| `total_ratio`, `bus_load_pct` | all profile IDs | exclude the 4 non-HCRL messages | The same traffic gives the same features on the simulator and on real logs. |
| `DATASET_VERSION` | 2 | 3 | Features changed, cached synthetic dataset invalidated. |

Thresholds were not touched where the data showed no problem (rate smoothing 0.5 s, fuzzy 10 distinct IDs, spoof/steering physical limits).

## Deployment decision

`server/models/` holds an RF trained on HCRL train windows (last 25 % of each file excluded) plus synthetic train windows (`training_source: hcrl+synthetic`).
Reason: an RF trained only on synthetic data is useless on the real car (DoS and fuzzy recall 0, see table above), an RF trained only on HCRL still
handles the simulator, and the combined RF is as good as either on both domains, so the live demo keeps working. The IsolationForest (health) stays
synthetic: HCRL has no usable health signals. The rules remain the primary detector; the RF only acts when rules are silent.

## Caveats and suspicious findings

* Simulator fidelity under attack was fixed using the real captures. Originally the simulator injected at the nominal paper rates (DoS every 0.3 ms
  etc.) on top of normal traffic, while the real captures show far lower injection rates and legitimate traffic crowded off the bus. A simulator-only RF
  then scored macro-F1 0.29 on HCRL. The profile now carries `attack_behaviour` measured from the captures (median per 100 ms window with >= 5
  injected frames: DoS 340 frames/s injected with 15 % of legitimate traffic surviving, fuzzy 220 / 20 %, RPM spoof 630 / 76 %, gear spoof 580 / 70 %),
  and the simulator reproduces it. The simulator-only RF now scores ~0.96 on the HCRL hold-out (table c). The deployed RF still trains on HCRL + synthetic.
* Not every capture has the same IDs: 0x2B0 (steering) is absent in the DoS, RPM and gear captures and present (at ~23 Hz, not 100 Hz) in the fuzzy
  capture, and normal_run_data has it at 100 Hz. `steering_ratio` is therefore partly a file fingerprint. A missing ID never looks like an attack
  (rules only react to rates ABOVE expectation), but the RF could in principle learn it as a shortcut.
* A window is labelled attack if it has one injected frame. The R-only stretches inside the attack captures are normal traffic recorded during the
  attack session; they are used as 'normal' windows here and no alert is expected in them (none fired).
* Scores of 1.0 on settled windows mean the attack features are far outside normal; it does not mean the models are robust to a smarter attacker
  (e.g. a replay or low-rate spoof). Every intrusion in a file is the same pattern, so 300 intrusions are far fewer than 300 independent samples.
* Hold-out is time-contiguous within the same capture sessions and the same car; nothing here shows generalisation to other cars.
* Mechanical rules never fire on real data. The signals that ARE on the real bus decode to sane values on normal_run_data (rpm 527-2221,
  speed 0-49 km/h, coolant 83-95 C, throttle 0-61 %, steering within +-526 deg), so coolant, speed-vs-rpm and steering checks are exercised and quiet.
  Battery, brake, wheel and cluster speed are not on the HCRL bus (our 4 extra messages), so those rules are untested on real data. The gear signal
  (0x43F layout is 'assumed') decodes to values up to 15 and is not used by any mechanical rule.
"""


# --------------------------------------------------------------------------- markdown
def _t(rows, head):
    return "\n".join(["| " + " | ".join(head) + " |", "|" + "---|" * len(head)] + ["| " + " | ".join(map(str, r)) + " |" for r in rows])


def _cls_rows(block):
    return [[c, block[c]["precision"], block[c]["recall"], block[c]["f1"], block[c]["support"]] for c in CLASSES]


def write_md(res: dict, path: Path) -> None:
    r, rf = res["rules"], res["rf"]
    L = ["# Evaluation on the real HCRL Car-Hacking dataset", "",
         f"Generated by `python tools/eval_hcrl.py` ({res['generated']}). Windows are 100 ms; a window is an attack window "
         "if it contains at least one injected (`T`) frame. Predictions are made on the same 100 ms stream the live server sees.", "",
         "**Read this first.** (1) The HCRL attack captures are about 4.7 s injection bursts, 300 per file, separated by ~3 s of normal traffic "
         "(the `R` stretches). (2) Windows within ~0.7 s of a label change are 'unsettled': the 0.5 s rate smoothing lags the label, so "
         "'all windows' is the honest operational number and 'settled' is the steady-state one. (3) `normal_run_data.txt` is only "
         f"{res['rules']['normal_run']['duration_s']:.0f} s long, so alerts-per-hour is an extrapolation from a short recording. "
         "(4) Four of the profile messages (0x386, 0x220, 0x4F1, 0x549) do not exist on the HCRL bus, and 0x2B0 (steering) is missing from the "
         "DoS, RPM and gear captures, so the simulator and the real data are not identical even for 'normal' traffic.", ""]
    L += ["## a. Rule detector on real data (models=None)", "",
          "### Per-class, pooled over all five files", "", "All windows:", "",
          _t(_cls_rows(r["per_class_all_windows"]), ["class", "precision", "recall", "F1", "windows"]), "",
          "Settled windows only:", "", _t(_cls_rows(r["per_class_settled_windows"]), ["class", "precision", "recall", "F1", "windows"]), ""]
    rows = []
    for n, f in r["per_file"].items():
        if n == "normal_run_data.txt":
            continue
        lat = f["latency_alert_s"]
        rows.append([n, f["intrusions"], f["intrusions_detected_by_alert"], f"{100 * f['detection_rate']:.1f} %",
                     f"{lat['median']*1000:.0f} / {lat['p95']*1000:.0f} / {lat['max']*1000:.0f}" if lat["median"] is not None else "-",
                     f["cyber_alerts_outside_intrusions"], f["cyber_alerts_wrong_class_during_intrusion"]])
    L += ["### Per-intrusion detection (alert of the matching category, first injected frame to first alert)", "",
          _t(rows, ["file", "intrusions", "detected", "rate", "latency ms median / p95 / max", "alerts outside bursts",
                    "wrong-class alerts in bursts"]), ""]
    rows = []
    for n, f in r["per_file"].items():
        rows.append([n, f["duration_s"], ", ".join(f"{k}={v}" for k, v in f["window_confusion_all"].items())])
    L += ["### Window confusion per file (label->prediction: windows)", "", _t(rows, ["file", "seconds", "confusion"]), ""]
    nr = r["normal_run"]
    L += ["### False positives on normal_run_data", "",
          f"{nr['duration_s']:.0f} s of normal driving: {nr['cyber_alerts']} cyber alerts ({nr['cyber_alerts_per_hour']}/h), "
          f"{nr['mechanical_alerts']} mechanical alerts ({nr['mechanical_alerts_per_hour']}/h). Alerts: {nr['alerts'] or 'none'}.", "",
          f"In the R-only stretches of the four attack captures ({r['attack_capture_normal_stretches']['normal_seconds']:.0f} s): "
          f"{r['attack_capture_normal_stretches']['cyber_alerts_outside_intrusions']} cyber alerts outside intrusions.", ""]
    mech = {n: f["mechanical_alerts"] for n, f in r["per_file"].items() if f["mechanical_alerts"]}
    L += [f"Mechanical alerts per file: {mech or 'none'}.", ""]
    L += ["## b. RandomForest trained on HCRL (held-out = last 25 % of each file)", "",
          "All held-out windows:", "", _t(_cls_rows(rf["models"]["rf_hcrl"]["on_hcrl_heldout"]["all"]), ["class", "precision", "recall", "F1", "windows"]), "",
          "Settled windows only:", "", _t(_cls_rows(rf["models"]["rf_hcrl"]["on_hcrl_heldout"]["settled"]), ["class", "precision", "recall", "F1", "windows"]), ""]
    L += ["## c. Cross-domain (does the simulator stand in for the real car?)", "",
          "Macro-F1 over {normal, dos, fuzzy, spoofing}, settled windows (all-window numbers are in hcrl_eval.json).", ""]
    rows = []
    for name, m in rf["models"].items():
        mf = lambda b: round(float(np.mean([b["settled"][c]["f1"] for c in CLASSES])), 3)  # noqa: E731
        rows.append([name, mf(m["on_hcrl_heldout"]), mf(m["on_synthetic_heldout"]), mf(m["on_fresh_sim"])])
    L += [_t(rows, ["trained on", "HCRL hold-out", "synthetic hold-out", "fresh simulator runs"]), ""]
    L += ["Fresh simulator runs, per attack (recall = attack windows not predicted normal; settled):", ""]
    rows = []
    for name, m in rf["models"].items():
        for atk, v in m["fresh_sim_per_attack"].items():
            if atk == "normal":
                rows.append([name, "normal (FPR)", v["windows"], v["false_positive_rate"], "-"])
            else:
                rows.append([name, atk, v["attack_windows"], v["recall"], v["correct_class"]])
    L += [_t(rows, ["model", "scenario", "windows", "recall / FPR", "correct class"]), ""]
    L += ["Feature medians, settled windows (HCRL real vs simulator):", ""]
    rows = []
    for lab, d in rf["feature_medians_settled"].items():
        for fn, v in d.items():
            rows.append([lab, fn, v["hcrl_median"], v["sim_median"]])
    L += [_t(rows, ["class", "feature", "HCRL", "simulator"]), ""]
    L += res["notes_md"]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hcrl", default=str(ROOT / "data" / "hcrl"))
    args = ap.parse_args(argv)
    folder = Path(args.hcrl)
    if not folder.is_dir():
        print(f"HCRL folder {folder} not found")
        return 1
    t0 = time.time()
    wins = load_windows(folder)
    print("rules ...", flush=True)
    rules = eval_rules(wins)
    print("random forests + simulator ...", flush=True)
    rf = eval_rf(folder)
    deployed = {}
    try:
        deployed = json.loads((ROOT / "server" / "models" / "metrics.json").read_text())
    except OSError:
        pass
    res = {"generated": time.strftime("%Y-%m-%d"), "rules": rules, "rf": rf,
           "deployed_training_source": deployed.get("training_source"),
           "notes_md": NOTES.splitlines()}
    out = ROOT / "server" / "models" / "hcrl_eval.json"
    jd = {k: v for k, v in res.items() if k != "notes_md"}
    out.write_text(json.dumps(jd, indent=2, default=lambda o: o.item() if hasattr(o, "item") else str(o)), encoding="utf-8")
    write_md(res, ROOT / "EVALUATION.md")
    print(f"wrote {out} and EVALUATION.md in {time.time() - t0:.0f} s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
