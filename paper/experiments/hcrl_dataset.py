"""Exp 1: dataset characterisation. Table of captures + per-ID rate figure + one representative intrusion per attack.

    python -m paper.experiments.hcrl_dataset
"""
from __future__ import annotations

import numpy as np

from paper.experiments import hcrl_common as H
from paper.experiments import style

BURST_GAP_S = 1.5     # injected frames closer than this belong to the same intrusion (bursts are ~3 s apart; a few bursts pause 0.6-0.7 s)
JUMP_S = 5.0          # timestamp discontinuity (the captures concatenate sessions with hours-long gaps)
BIN_S = 0.02          # time-series bin (20 ms)
ALL_FILES = H.ATTACK_FILES + ["normal_run_data.txt"]


def clusters(t_inj: np.ndarray, gap: float):
    """[(start_ts, end_ts, n_frames)] of injected frames separated by > gap seconds."""
    if len(t_inj) == 0:
        return []
    cut = np.where(np.diff(t_inj) > gap)[0]
    s = np.r_[0, cut + 1]
    e = np.r_[cut, len(t_inj) - 1]
    return [(float(t_inj[a]), float(t_inj[b]), int(b - a + 1)) for a, b in zip(s, e)]


def burst_stats(raw: dict, cl) -> dict:
    ts, inj = raw["ts"], raw["inj"]
    keep, inj_fps, dur = [], [], []
    for (a, b, n) in cl:
        d = b - a
        if d <= 0.5:
            continue
        pre = ((ts >= a - 1.0) & (ts < a - 0.1) & ~inj).sum() / 0.9
        mid = ((ts >= a) & (ts <= b) & ~inj).sum() / d
        if pre > 0:
            keep.append(mid / pre)
        inj_fps.append(n / d)
        dur.append(d)
    return {"median_duration_s": float(np.median(dur)), "median_inject_fps": float(np.median(inj_fps)),
            "median_legit_retained": float(np.median(keep)),
            "legit_retained_p5_p95": [float(np.percentile(keep, 5)), float(np.percentile(keep, 95))]}


def describe_attack(raw: dict) -> tuple[str, dict]:
    pay = raw["inj_payloads"]
    n_inj = int(raw["inj"].sum())
    ids = raw["id"][raw["inj"]]
    uid, cnt = np.unique(ids, return_counts=True)
    top = int(uid[np.argmax(cnt)])
    share = float(cnt.max() / max(1, n_inj))
    (cid, dlc, data), c0 = next(iter(pay.items()))
    if share > 0.9:
        txt = f"0x{top:03X} / {' '.join(data[i:i + 2] for i in range(0, len(data), 2))}"
    else:
        txt = f"random ({len(uid)} IDs)"
    return txt, {"top_id": top, "top_id_share": share, "distinct_injected_ids": int(len(uid)),
                 "top_payload": data, "top_payload_share": float(c0 / max(1, n_inj))}


def main():
    P = H.project()
    prof = P.CP.get_profile(P.CP.DEFAULT_PROFILE)
    raws = {n: H.load_raw(n) for n in ALL_FILES}
    out = {"files": {}}
    rows = []
    for n in ALL_FILES:
        r = raws[n]
        ts, ids, inj = r["ts"], r["id"], r["inj"]
        cl = clusters(ts[inj], BURST_GAP_S)
        dts = np.diff(ts)
        jumps = dts[dts > JUMP_S]
        active = float(ts[-1] - jumps.sum())
        d = {"duration_s": active, "span_s": float(ts[-1]), "timestamp_jumps": int(len(jumps)),
             "jump_total_s": float(jumps.sum()), "frames": int(len(ts)), "distinct_ids": int(len(np.unique(ids))),
             "injected_frames": int(inj.sum()), "intrusions": len(cl), "frames_per_s": float(len(ts) / active)}
        txt = "--"
        if n != "normal_run_data.txt":
            txt, ex = describe_attack(r)
            d.update(ex)
            d.update(burst_stats(r, cl))
            d["attack_target"] = txt
            d["median_gap_between_intrusions_s"] = float(np.median([cl[i + 1][0] - cl[i][1] for i in range(len(cl) - 1)]))
        out["files"][n] = d
        rows.append([f"{H.FILE_SHORT[n]}", f"{d['duration_s']:.0f}", f"{d['frames'] / 1e6:.2f}M",
                     d["distinct_ids"], f"{d['injected_frames']:,}" if d["injected_frames"] else "--",
                     d["intrusions"] if d["intrusions"] else "--", txt,
                     f"{d['median_inject_fps']:.0f}" if "median_inject_fps" in d else "--",
                     f"{100 * d['median_legit_retained']:.0f}" if "median_legit_retained" in d else "--"])
    H.write_table(
        "hcrl_dataset_files",
        "HCRL Car-Hacking captures used in this study. Intrusions are runs of injected (T) frames separated by more than "
        f"{BURST_GAP_S:g}~s. Injected rate and legitimate share are medians over intrusions "
        "(share = legitimate frames/s during the burst divided by the 0.9~s before it). Durations exclude timestamp jumps "
        "of more than 5~s between recording sessions.",
        "tab:hcrl_dataset",
        ["Capture", "Dur. (s)", "Frames", "IDs", "Injected", "Intrus.", "Attack ID / payload", "Inj. fr/s",
         "Legit. kept (%)"],
        rows, align="lrrrrrlrr", star=True)

    # ---- per-ID rate figure (normal driving)
    nr = raws["normal_run_data.txt"]
    u, c = np.unique(nr["id"], return_counts=True)
    rate = c / nr["ts"][-1]
    order = np.argsort(-rate)
    u, rate = u[order], rate[order]
    prim = {m.id for m in prof.messages}
    out["normal_per_id_hz"] = {f"0x{int(i):03X}": float(r) for i, r in zip(u, rate)}
    out["normal_total_hz"] = float(rate.sum())
    out["profile_messages_on_hcrl_bus"] = sorted(f"0x{i:03X}" for i in prim if i in set(u.tolist()))
    out["fastest_legit_hz"] = float(rate.max())
    f, ax = style.fig(style.FULL_W, 2.3)
    colors = [style.C["blue"] if int(i) in prim else style.C["grey"] for i in u]
    ax.bar(range(len(u)), rate, color=colors, width=0.8)
    ax.set_yscale("log")
    ax.set_xticks(range(len(u)))
    ax.set_xticklabels([f"{int(i):03X}" for i in u], rotation=90, fontsize=6)
    ax.set_xlabel("CAN ID (hex), sorted by rate")
    ax.set_ylabel("Frames / s (normal driving)")
    ax.set_ylim(0.5, 2000)
    ax.axhline(100, color=style.C["black"], lw=0.5, ls="--")
    ax.text(len(u) - 0.5, 125, "100 Hz: fastest legitimate message", ha="right", fontsize=6)
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=style.C["blue"], label="Decoded profile message (signals + rate checks)"),
                       Patch(color=style.C["grey"], label="Background message (rate check only)")],
              loc="upper right", fontsize=6)
    ax.grid(axis="x", visible=False)
    style.save(f, "hcrl_id_rates")

    # ---- representative intrusion per attack (middle intrusion of the file)
    f, axs = style.fig(style.FULL_W, 3.6, nrows=2, ncols=2, sharey=True)
    rep = {}
    for ax, n in zip(axs.ravel(), H.ATTACK_FILES):
        r = raws[n]
        cl = [c for c in clusters(r["ts"][r["inj"]], BURST_GAP_S) if c[1] - c[0] > 0.5]
        a, b, nfr = cl[len(cl) // 2]
        lo, hi = a - 1.5, b + 1.5
        sel = (r["ts"] >= lo) & (r["ts"] < hi)
        t, inj = r["ts"][sel], r["inj"][sel]
        edges = np.arange(lo, hi + BIN_S, BIN_S)
        ctr = 0.5 * (edges[1:] + edges[:-1]) - a
        leg = np.histogram(t[~inj], edges)[0] / BIN_S
        inj_h = np.histogram(t[inj], edges)[0] / BIN_S
        ax.axvspan(0, b - a, color=style.C["grey"], alpha=0.12, lw=0)
        ax.plot(ctr, leg, color=style.C["black"], lw=0.8, label="Legitimate (R)")
        ax.plot(ctr, inj_h, color=H.FILE_COLOR[n], lw=0.9, ls="--", label="Injected (T)")
        ax.set_title(H.FILE_SHORT[n], fontsize=8)
        rep[n] = {"intrusion_index": len(cl) // 2, "of": len(cl), "t_start_s": a, "duration_s": b - a,
                  "injected_frames": nfr,
                  "mean_legit_fps_in_burst": float(((r["ts"] >= a) & (r["ts"] <= b) & ~r["inj"]).sum() / (b - a)),
                  "mean_legit_fps_before": float(((r["ts"] >= a - 1.0) & (r["ts"] < a - 0.1) & ~r["inj"]).sum() / 0.9)}
    for ax in axs[1]:
        ax.set_xlabel("Time from first injected frame (s)")
    for ax in axs[:, 0]:
        ax.set_ylabel("Frames / s (20 ms bins)")
    axs[0, 0].legend(loc="center right", fontsize=6)
    f.tight_layout()
    style.save(f, "hcrl_burst_timeseries")
    out["representative_intrusions"] = rep
    out["representative_rule"] = "middle intrusion of each capture (index = n_intrusions // 2, intrusions longer than 0.5 s)"
    H.save_json("hcrl_dataset", out)
    print({k: (v["duration_s"], v["frames"], v["distinct_ids"], v["injected_frames"], v["intrusions"])
           for k, v in out["files"].items()})


if __name__ == "__main__":
    main()
