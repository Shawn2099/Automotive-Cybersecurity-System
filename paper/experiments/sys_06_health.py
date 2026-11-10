"""Exp 6: health analytics on the simulator (no real labelled health data exists).

(a) time series for each fault (signal, component health, overall health, anomaly score, alert markers)
(b) forecast accuracy: predicted ETA vs actual time-to-threshold over many randomised trials
(c) IsolationForest anomaly-score distributions, normal driving vs each fault
"""

from __future__ import annotations

import random

import numpy as np

from common.can_profiles import decode_can_frames
from common.vehicle_sim import VirtualCar
from ml_training.generate_dataset import RandomDriver
from paper.experiments import style
from paper.experiments.sys_common import PROFILE, run_windows, save_json, write_table
from server.app.analytics import (BATTERY_HIGH, COOLANT_HIGH, VehicleAnalyzer, load_models)
from server.app.main import MODEL_DIR

MODELS = load_models(MODEL_DIR)
DT = 0.1


class RateCar(VirtualCar):
    """VirtualCar whose overheat / battery-drain slopes are scaled (harness-only; the stock physics is scale=1)."""

    def __init__(self, *a, scale: float = 1.0, **k):
        super().__init__(*a, **k)
        self.scale = scale

    def _physics(self, dt):
        c0, b0 = self.coolant, self.battery
        super()._physics(dt)
        if self.scale != 1.0:
            if "overheat" in self.faults:
                self.coolant = min(128.0, c0 + (self.coolant - c0) * self.scale)
            if "battery_drain" in self.faults:
                self.battery = max(10.6, b0 + (self.battery - b0) * self.scale)


def step(car, an, t):
    frames, batch = next(run_windows(car, 1))
    batch["ts_ms"] = int(t * 1000)
    dec = decode_can_frames(PROFILE, batch["frames"])
    res = an.update(batch, dec, t)
    return dec["signals"], res


# ---------------------------------------------------------------- (a) time series
def timeseries(fault: str, on: float, off: float, total: float = 60.0, seed: int = 5):
    car = RateCar(PROFILE, seed=seed)
    car.controls.update({"speed_kmh": 60.0, "throttle_pct": 20.0})
    an = VehicleAnalyzer(PROFILE, MODELS)
    t = 0.0
    for _ in range(80):  # 8 s pre-roll (speed ramps up), not recorded
        t += DT
        step(car, an, t)
    t0 = t
    rec = []
    alerts = []
    while t - t0 < total:
        t += DT
        rel = t - t0
        if rel >= on and fault not in car.faults and rel < off:
            car.faults.add(fault)
        if rel >= off:
            car.faults.discard(fault)
        sig, res = step(car, an, t)
        wm = np.mean([sig[k] for k in ("whl_fl_kmh", "whl_fr_kmh", "whl_rl_kmh", "whl_rr_kmh") if k in sig] or [np.nan])
        rec.append({"t": rel, "coolant": sig.get("coolant_c"), "battery": sig.get("battery_v"), "ems_speed": sig.get("speed_kmh"),
                    "wheel_speed": float(wm), "cluster_speed": sig.get("clu_speed_kmh"), **{f"h_{k}": v for k, v in res["health"].items()},
                    "anomaly": res["anomaly_score"], "cyber_risk": res["cyber_risk"]})
        for a in res["alerts"]:
            alerts.append({"t": rel, "category": a["category"], "severity": a["severity"]})
    return rec, alerts


# ---------------------------------------------------------------- (b) forecast accuracy
def forecast_trial(signal: str, scale: float, seed: int):
    rng = random.Random(seed)
    fault = "overheat" if signal == "coolant_c" else "battery_drain"
    car = RateCar(PROFILE, seed=seed, scale=scale)
    start = rng.uniform(84, 100) if signal == "coolant_c" else rng.uniform(13.2, 14.4)
    car.controls.update({"speed_kmh": rng.uniform(20, 100), "throttle_pct": rng.uniform(5, 30),
                         "coolant_c": start if signal == "coolant_c" else 90.0,
                         "battery_v": start if signal == "battery_v" else 13.9})
    car.coolant, car.battery = (start if signal == "coolant_c" else 90.0), (start if signal == "battery_v" else 13.9)
    an = VehicleAnalyzer(PROFILE, None)  # forecaster is rules/numpy only
    t, preds, t_cross, t_on, t_alert, t_thr = 0.0, [], None, 60 * DT, None, None
    for i in range(3000):
        t += DT
        if t >= t_on and fault not in car.faults:
            car.faults.add(fault)
        sig, res = step(car, an, t)
        truth = car.coolant if signal == "coolant_c" else car.battery
        crossed = truth > COOLANT_HIGH if signal == "coolant_c" else truth < BATTERY_HIGH
        if crossed and t_cross is None:
            t_cross = t
        for a in res["alerts"]:
            if a["category"] == ("forecast_overheat" if signal == "coolant_c" else "forecast_battery") and t_alert is None:
                t_alert = t
            if a["category"] == ("overheat" if signal == "coolant_c" else "low_battery") and t_thr is None:
                t_thr = t
        for f in res["forecast"]:
            if f["signal"] == signal and t >= t_on:
                preds.append((t, float(f["eta_s"])))
        if t_cross is not None and t > t_cross + 1.0:
            break
    if t_cross is None:
        return None
    pts = [(p, t_cross - tt) for tt, p in preds if tt <= t_cross]
    return {"signal": signal, "scale": scale, "seed": seed, "t_cross_after_onset": t_cross - t_on,
            "points": pts, "forecast_alert_lead_s": None if t_alert is None else t_cross - t_alert,
            "threshold_alert_lead_s": None if t_thr is None else t_cross - t_thr}


def forecast_experiment(n_nom=30, n_rand=30):
    res = {}
    rng = random.Random(99)
    for signal in ("coolant_c", "battery_v"):
        trials = []
        for i in range(n_nom):
            trials.append(forecast_trial(signal, 1.0, 1000 + i))
        for i in range(n_rand):
            trials.append(forecast_trial(signal, rng.uniform(0.3, 2.5), 2000 + i))
        res[signal] = [t for t in trials if t]
    return res


def fc_stats(trials):
    pred = np.array([p for t in trials for p, a in t["points"]])
    act = np.array([a for t in trials for p, a in t["points"]])
    first = [(t["points"][0]) for t in trials if t["points"]]
    err = pred - act
    s = {"n_trials": len(trials), "n_points": int(len(err)), "mae_s": float(np.abs(err).mean()),
         "median_abs_err_s": float(np.median(np.abs(err))), "bias_s": float(err.mean()),
         "rmse_s": float(np.sqrt((err ** 2).mean())),
         "first_forecast_mae_s": float(np.mean([abs(p - a) for p, a in first])),
         "first_forecast_actual_remaining_median_s": float(np.median([a for p, a in first])),
         "trials_with_forecast_alert": int(sum(t["forecast_alert_lead_s"] is not None for t in trials)),
         "forecast_alert_lead_median_s": float(np.median([t["forecast_alert_lead_s"] for t in trials if t["forecast_alert_lead_s"] is not None] or [np.nan])),
         "threshold_alert_lead_median_s": float(np.median([t["threshold_alert_lead_s"] for t in trials if t["threshold_alert_lead_s"] is not None] or [np.nan])),
         "by_remaining": {}}
    for lo, hi in [(0, 5), (5, 10), (10, 20), (20, 40), (40, 1e9)]:
        m = (act >= lo) & (act < hi)
        if m.any():
            s["by_remaining"][f"{lo}-{hi if hi < 1e8 else 'inf'}"] = {"n": int(m.sum()), "mae_s": float(np.abs(err[m]).mean()),
                                                                     "bias_s": float(err[m].mean())}
    return s


# ---------------------------------------------------------------- (c) anomaly distributions
def anomaly_scores():
    out = {"normal": [], "overheat": [], "battery_drain": [], "sensor_inconsistency": []}
    for rep in range(6):  # normal: 6 x 100 s of random driving
        rng = random.Random(5000 + rep)
        car = RateCar(PROFILE, seed=5000 + rep)
        drv = RandomDriver(car, rng)
        an = VehicleAnalyzer(PROFILE, MODELS)
        t = 0.0
        for i in range(1000):
            t += DT
            drv.tick(t)
            _, res = step(car, an, t)
            if t > 8:
                out["normal"].append(res["anomaly_score"])
    for fault in ("overheat", "battery_drain", "sensor_inconsistency"):
        for rep in range(6):
            rng = random.Random(7000 + rep)
            car = RateCar(PROFILE, seed=7000 + rep)
            drv = RandomDriver(car, rng)
            an = VehicleAnalyzer(PROFILE, MODELS)
            t = 0.0
            for i in range(900):
                t += DT
                drv.tick(t)
                if t > 20 and fault not in car.faults:
                    car.faults.add(fault)
                if fault == "sensor_inconsistency" and t > 20:
                    pass
                _, res = step(car, an, t)
                if t > 22:  # fault active (ramp has started)
                    out[fault].append(res["anomaly_score"])
    return out


def auroc(neg, pos):
    from sklearn.metrics import roc_auc_score

    y = np.r_[np.zeros(len(neg)), np.ones(len(pos))]
    return float(roc_auc_score(y, np.r_[neg, pos]))


def main():
    import matplotlib.pyplot as plt

    out: dict = {"models_loaded": MODELS is not None and MODELS.iforest is not None}
    # ---- (a)
    specs = {"overheat": (10, 42), "battery_drain": (10, 42), "sensor_inconsistency": (10, 42)}
    ts = {}
    for f, (on, off) in specs.items():
        rec, al = timeseries(f, on, off)
        ts[f] = (rec, al, on, off)
        out.setdefault("timeseries_summary", {})[f] = {
            "fault_on_s": on, "fault_off_s": off,
            "first_alerts": {a["category"]: a["t"] for a in reversed(al)},
            "min_overall_health": min(r["h_overall"] for r in rec),
            "overall_health_end": rec[-1]["h_overall"], "alerts": al}
    f, axs = style.fig(style.FULL_W, 5.4, nrows=3, ncols=3, sharex="col")
    titles = {"overheat": "Overheat", "battery_drain": "Battery drain", "sensor_inconsistency": "Sensor inconsistency"}
    cat_col = {"mechanical": style.C["red"]}
    for j, (fault, (rec, al, on, off)) in enumerate(ts.items()):
        t = [r["t"] for r in rec]
        a0, a1, a2 = axs[0, j], axs[1, j], axs[2, j]
        for a in (a0, a1, a2):
            a.axvspan(on, off, color=style.C["orange"], alpha=0.12, lw=0)
        if fault == "overheat":
            a0.plot(t, [r["coolant"] for r in rec], color=style.C["blue"])
            a0.axhline(105, color=style.C["grey"], ls=":", lw=0.7)
            a0.axhline(110, color=style.C["red"], ls="--", lw=0.7)
            a0.set_ylabel("Coolant ($^\\circ$C)")
            comp, comp_lab = "h_thermal", "thermal"
        elif fault == "battery_drain":
            a0.plot(t, [r["battery"] for r in rec], color=style.C["blue"])
            a0.axhline(11.8, color=style.C["grey"], ls=":", lw=0.7)
            a0.axhline(11.4, color=style.C["red"], ls="--", lw=0.7)
            a0.set_ylabel("Battery (V)")
            comp, comp_lab = "h_electrical", "electrical"
        else:
            a0.plot(t, [r["ems_speed"] for r in rec], color=style.C["red"], label="EMS speed")
            a0.plot(t, [r["wheel_speed"] for r in rec], color=style.C["blue"], ls="--", label="wheel mean")
            a0.plot(t, [r["cluster_speed"] for r in rec], color=style.C["green"], ls=":", label="cluster")
            a0.set_ylabel("Speed (km/h)")
            a0.legend(fontsize=5.5, loc="center right")
            comp, comp_lab = "h_engine", "engine"
        a0.set_title(titles[fault], fontsize=8)
        a1.plot(t, [r[comp] for r in rec], color=style.C["orange"], ls="--", label=f"{comp_lab} health")
        a1.plot(t, [r["h_overall"] for r in rec], color="k", label="overall health")
        a1.set_ylim(0, 105)
        a1.set_ylabel("Health (0-100)")
        a2.plot(t, [r["anomaly"] for r in rec], color=style.C["purple"])
        a2.axhline(0.65, color=style.C["grey"], ls=":", lw=0.7)
        a2.set_ylabel("IF anomaly score")
        a2.set_ylim(-0.02, 1.02)
        a2.set_xlabel("Time (s)")
        marks = {"overheat": "o", "forecast_overheat": "^", "low_battery": "o", "forecast_battery": "^",
                 "sensor_inconsistency": "o", "health_anomaly": "s"}
        for a in al:
            a1.scatter([a["t"]], [102], marker=marks.get(a["category"], "x"), s=14, color=style.C["red"], clip_on=False, zorder=5)
            a1.annotate(a["category"].replace("_", " "), (a["t"], 102), xytext=(2, 4), textcoords="offset points",
                        fontsize=4.5, rotation=40, color=style.C["red"], annotation_clip=False)
        if j == 0:
            a1.legend(fontsize=5.5, loc="lower left")
    f.tight_layout()
    style.save(f, "sys_health_timeseries")

    # ---- (b)
    fc = forecast_experiment()
    out["forecast"] = {"definition": "points are (predicted ETA, actual remaining time to threshold) from every window with a forecast",
                       "conditions": "30 trials nominal fault rate + 30 trials with fault slope scaled U(0.3,2.5) (harness-only); random start values/seeds",
                       "thresholds": {"coolant_c": COOLANT_HIGH, "battery_v": BATTERY_HIGH}}
    for s_, tr in fc.items():
        out["forecast"][s_] = fc_stats(tr)
        out["forecast"][s_]["nominal"] = fc_stats([t for t in tr if t["scale"] == 1.0])
        out["forecast"][s_]["randomised_rate"] = fc_stats([t for t in tr if t["scale"] != 1.0])
    f, axs = style.fig(style.FULL_W, 2.6, ncols=2)
    for ax, (sig, ttl) in zip(axs, [("coolant_c", "(a) Overheat: coolant to 110 $^\\circ$C"), ("battery_v", "(b) Battery drain: to 11.4 V")]):
        for cond, col, mk in [(1.0, style.C["blue"], "o"), (None, style.C["orange"], "s")]:
            pts = [(p, a) for t in fc[sig] if (t["scale"] == 1.0) == (cond == 1.0) for p, a in t["points"][::5]]
            if pts:
                p, a = np.array(pts).T
                ax.scatter(a, p, s=3, alpha=0.35, color=col, marker=mk, lw=0,
                           label="nominal fault rate" if cond == 1.0 else "randomised slope")
        mx = 120
        ax.plot([0, mx], [0, mx], "k--", lw=0.7)
        st = out["forecast"][sig]
        ax.set_title(f"{ttl}\nMAE {st['mae_s']:.1f} s, median |err| {st['median_abs_err_s']:.1f} s, n={st['n_trials']} trials", fontsize=7)
        ax.set_xlabel("Actual time to threshold (s)")
        ax.set_ylabel("Predicted ETA (s)")
        ax.set_xlim(0, 80)
        ax.set_ylim(0, 120)
        ax.legend(markerscale=3, loc="upper left")
    f.tight_layout()
    style.save(f, "sys_forecast_accuracy")

    # ---- (c)
    sc = anomaly_scores()
    norm = np.array(sc["normal"])
    out["anomaly"] = {"threshold": 0.65, "normal": {"n": int(len(norm)), "median": float(np.median(norm)),
                                                    "p99": float(np.percentile(norm, 99)), "frac_over_thr": float(np.mean(norm > 0.65))}}
    for k in ("overheat", "battery_drain", "sensor_inconsistency"):
        a = np.array(sc[k])
        out["anomaly"][k] = {"n": int(len(a)), "median": float(np.median(a)), "p95": float(np.percentile(a, 95)),
                             "frac_over_thr": float(np.mean(a > 0.65)), "auroc_vs_normal": auroc(norm, a)}
    f, ax = style.fig(style.COL_W, 2.5)
    bins = np.linspace(0, 1, 41)
    for i, (k, col) in enumerate([("normal", style.C["grey"]), ("overheat", style.C["red"]), ("battery_drain", style.C["blue"]),
                                  ("sensor_inconsistency", style.C["green"])]):
        ax.hist(sc[k], bins=bins, histtype="step", density=False, weights=np.ones(len(sc[k])) / len(sc[k]), color=col,
                ls=style.LINES[i], lw=1.1, label=k.replace("_", " "))
    ax.axvline(0.65, color="k", ls=":", lw=0.7)
    ax.set_yscale("log")
    ax.set_xlabel("IsolationForest anomaly score")
    ax.set_ylabel("Fraction of windows")
    ax.legend(fontsize=6)
    style.save(f, "sys_anomaly_hist")
    save_json("sys_health", out)

    rows = []
    for s_, nm in (("coolant_c", "Overheat (coolant to 110 $^\\circ$C)"), ("battery_v", "Battery drain (to 11.4 V)")):
        st = out["forecast"][s_]
        rows.append([nm, st["n_trials"], f"{st['mae_s']:.1f}", f"{st['median_abs_err_s']:.1f}", f"{st['bias_s']:+.1f}",
                     f"{st['first_forecast_mae_s']:.1f}", f"{st['forecast_alert_lead_median_s']:.1f}",
                     f"{st['threshold_alert_lead_median_s']:.1f}"])
    write_table("sys_forecast", ["Fault", "Trials", "MAE (s)", "Med. $|e|$ (s)", "Bias (s)", "1st-fcst MAE (s)",
                                 "Fcst alert lead (s)", "Thr. alert lead (s)"], rows,
                "Slope-forecaster accuracy on the simulator (MAE of predicted ETA vs actual time to threshold over all forecast "
                "windows; half the trials use randomised fault slopes). Lead = time between the alert and the actual threshold crossing.",
                "tab:sys_forecast", escape=False, resize=True)
    rows = [["normal driving", out["anomaly"]["normal"]["n"], f"{out['anomaly']['normal']['median']:.3f}", "--",
             f"{100*out['anomaly']['normal']['frac_over_thr']:.2f}", "--"]]
    for k in ("overheat", "battery_drain", "sensor_inconsistency"):
        a = out["anomaly"][k]
        rows.append([k.replace("_", "\\_"), a["n"], f"{a['median']:.3f}", f"{a['p95']:.3f}", f"{100*a['frac_over_thr']:.1f}",
                     f"{a['auroc_vs_normal']:.3f}"])
    write_table("sys_anomaly", ["Condition", "Windows", "Median", "p95", "$>$0.65 (\\%)", "AUROC vs normal"], rows,
                "IsolationForest anomaly score on simulator data (normal random driving vs windows during each fault).",
                "tab:sys_anomaly", escape=False)
    print("sys_06 done")


if __name__ == "__main__":
    main()
