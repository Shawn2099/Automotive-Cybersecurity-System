"""Exp 7: 90 s scripted attack scenario (dos -> fuzzy -> rpm_spoof -> tamper bursts), cyber_risk and attack_class vs time.

VehicleAnalyzer (rules + RF models as in the server) driven by VirtualCar directly; tunnel tamper events injected via
record_tunnel_event at 2 Hz (what the simulator's `tamper` toggle produces: every 5th packet at 10 Hz).
"""

from __future__ import annotations

import numpy as np

from common.can_profiles import decode_can_frames
from paper.experiments import style
from paper.experiments.sys_common import PROFILE, make_car, run_windows, save_json, write_table
from server.app.analytics import ATTACK_CLASSES, VehicleAnalyzer, load_models
from server.app.main import MODEL_DIR

DT = 0.1
TOTAL = 90.0
PHASES = [  # name, start, end, kind, expected class
    ("dos", 10, 18, "can", "dos"),
    ("fuzzy", 28, 36, "can", "fuzzy"),
    ("rpm_spoof", 46, 54, "can", "spoofing"),
    ("tamper", 64, 72, "tunnel", "tunnel_attack"),
]


def run(seed: int = 11, models=True):
    car = make_car(seed)
    an = VehicleAnalyzer(PROFILE, load_models(MODEL_DIR) if models else None)
    for i in range(50):  # 5 s pre-roll
        _, b = next(run_windows(car, 1))
        b["ts_ms"] = i * 100
        an.update(b, decode_can_frames(PROFILE, b["frames"]), -5 + i * DT)
    rec, alerts = [], []
    t = 0.0
    next_tamper = {p[0]: p[1] for p in PHASES if p[3] == "tunnel"}
    while t < TOTAL - 1e-9:
        t = round(t + DT, 6)
        for name, a, b_, kind, _ in PHASES:
            if kind == "can":
                (car.attacks.add if a <= t < b_ else car.attacks.discard)(name)
            elif a <= t < b_ and t >= next_tamper[name] - 1e-9:
                an.record_tunnel_event("tamper", t)
                next_tamper[name] += 0.5
        _, batch = next(run_windows(car, 1))
        batch["ts_ms"] = int(t * 1000)
        res = an.update(batch, decode_can_frames(PROFILE, batch["frames"]), t)
        for al in res["alerts"]:
            alerts.append({"t": t, "category": al["category"], "severity": al["severity"]})
        rec.append({"t": t, "cyber_risk": res["cyber_risk"], "attack_class": res["attack_class"],
                    "health": res["health"]["overall"], "conf": res["attack_confidence"]})
    return rec, alerts


def phase_table(rec, alerts):
    t = np.array([r["t"] for r in rec])
    risk = np.array([r["cyber_risk"] for r in rec])
    cls = [r["attack_class"] for r in rec]
    out = []
    for name, a, b, kind, exp in PHASES:
        m = (t >= a) & (t < b)
        al = [x for x in alerts if x["t"] >= a and x["t"] < b + 2]
        first_alert = min((x["t"] for x in al), default=None)
        t50 = next((tt for tt, rr in zip(t, risk) if tt >= a and rr >= 50), None)
        tcls = next((tt for tt, c in zip(t, cls) if tt >= a and c == exp), None)
        rec_t = next((tt for tt, rr in zip(t, risk) if tt >= b and rr <= 20), None)
        mis = sum(1 for tt, c in zip(t, cls) if a <= tt < b and c not in ("normal", exp))
        out.append({"phase": name, "start_s": a, "end_s": b, "expected_class": exp,
                    "first_alert_delay_s": None if first_alert is None else round(first_alert - a, 2),
                    "first_alert_categories": sorted({x["category"] for x in al}),
                    "risk_ge_50_delay_s": None if t50 is None else round(t50 - a, 2),
                    "class_correct_delay_s": None if tcls is None else round(tcls - a, 2),
                    "peak_risk": int(risk[m].max()), "mean_risk_in_phase": float(risk[m].mean()),
                    "frac_windows_class_correct": float(np.mean([c == exp for c, mm in zip(cls, m) if mm])),
                    "frac_windows_wrong_attack_class": mis / max(1, int(m.sum())),
                    "recovery_to_risk_le_20_s": None if rec_t is None else round(rec_t - b, 2)})
    quiet = np.ones(len(t), bool)
    for _, a, b, *_ in PHASES:
        quiet &= ~((t >= a) & (t < b + 6))  # exclude attack and 6 s decay
    return out, {"quiet_windows": int(quiet.sum()), "max_risk_quiet": int(risk[quiet].max()),
                 "false_class_windows_quiet": int(sum(1 for c, q in zip(cls, quiet) if q and c != "normal"))}


def main():
    rec, alerts = run()
    ph, quiet = phase_table(rec, alerts)
    # robustness: repeat with different seeds, collect per-phase detection delay
    reps = {p[0]: [] for p in PHASES}
    for s in range(20, 30):
        r, a = run(seed=s)
        p, _ = phase_table(r, a)
        for x in p:
            reps[x["phase"]].append(x["first_alert_delay_s"])
    save_json("sys_cyber_timeline", {"phases": ph, "quiet": quiet, "alerts": alerts,
                                     "first_alert_delay_over_10_seeds": reps,
                                     "series": {"t": [r["t"] for r in rec], "cyber_risk": [r["cyber_risk"] for r in rec],
                                                "attack_class": [r["attack_class"] for r in rec]}})
    for p in ph:
        print(p)
    print(quiet)

    f, (a1, a2) = style.fig(style.FULL_W, 3.0, nrows=2, sharex=True, gridspec_kw={"height_ratios": [2.2, 1]})
    t = [r["t"] for r in rec]
    for name, a, b, kind, exp in PHASES:
        for ax in (a1, a2):
            ax.axvspan(a, b, color=style.CLASS_COLOR[exp], alpha=0.16, lw=0)
        a1.text((a + b) / 2, 104, name.replace("_", " "), ha="center", fontsize=6.5, color=style.CLASS_COLOR[exp])
    a1.plot(t, [r["cyber_risk"] for r in rec], color="k", lw=1.0)
    a1.axhline(50, color=style.C["grey"], ls=":", lw=0.6)
    mk = {"dos": "v", "fuzzy": "s", "spoofing_rpm": "D", "tamper": "^"}
    seen = set()
    for al in alerts:
        a1.scatter([al["t"]], [-6], marker=mk.get(al["category"], "x"), s=16, color=style.C["red"], clip_on=False,
                   zorder=5, label=None if al["category"] in seen else f"alert: {al['category']}")
        seen.add(al["category"])
    a1.set_ylim(0, 100)
    a1.set_ylabel("Cyber risk (0-100)")
    a1.legend(loc="center right", fontsize=6, ncol=1, bbox_to_anchor=(1.0, 0.55))
    yi = {c: i for i, c in enumerate(ATTACK_CLASSES)}
    a2.step(t, [yi[r["attack_class"]] for r in rec], where="post", color="k", lw=1.0)
    a2.set_yticks(range(len(ATTACK_CLASSES)))
    a2.set_yticklabels([c.replace("_", " ") for c in ATTACK_CLASSES], fontsize=6)
    a2.set_ylabel("attack_class")
    a2.set_xlabel("Time (s)")
    a2.set_xlim(0, TOTAL)
    f.tight_layout()
    style.save(f, "sys_cyber_timeline")

    rows = []
    for p in ph:
        fmt = lambda v: "--" if v is None else f"{v:.1f}"  # noqa: E731
        rows.append([p["phase"].replace("_", "\\_"), f"{p['start_s']}--{p['end_s']}", fmt(p["first_alert_delay_s"]),
                     fmt(p["risk_ge_50_delay_s"]), fmt(p["class_correct_delay_s"]), p["peak_risk"],
                     f"{100*p['frac_windows_class_correct']:.0f}", fmt(p["recovery_to_risk_le_20_s"])])
    write_table("sys_cyber_timeline", ["Burst", "Window (s)", "1st alert (s)", "Risk$\\geq$50 (s)", "Class ok (s)", "Peak risk",
                                       "Class ok (\\%)", "Recovery (s)"], rows,
                f"Scripted 90~s scenario: delays are measured from burst onset. Outside bursts ({quiet['quiet_windows']} windows) "
                f"the maximum risk was {quiet['max_risk_quiet']} and {quiet['false_class_windows_quiet']} windows had a non-normal class.",
                "tab:sys_cyber_timeline", escape=False, resize=True)
    print("sys_07 done")


if __name__ == "__main__":
    main()
