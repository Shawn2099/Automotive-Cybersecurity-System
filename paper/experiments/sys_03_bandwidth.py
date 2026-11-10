"""Exp 3: bandwidth. Raw CAN bus bits vs naive per-frame JSON vs our bounded batch + AES-GCM envelope at 10 Hz."""

from __future__ import annotations

import numpy as np

from common.tunnel import ClientSession, ServerSession
from common.vehicle_sim import BUS_BITRATE, frame_bits
from paper.experiments import style
from paper.experiments.sys_common import (PSK1, SCENARIOS, WINDOW_MS, compact_json, gen_scenario, save_json,
                                          write_table)

SECONDS = 30.0
REPEATS = 3  # independent seeds


def ws_overhead(n: int) -> int:
    """Client->server WebSocket frame header: 2 + extended length (0/2/8) + 4 mask bytes."""
    return 2 + (0 if n < 126 else 2 if n < 65536 else 8) + 4


def one(attack: str, seed: int, nominal: bool = False) -> dict:
    fl, bl = gen_scenario(attack, seconds=SECONDS, seed=seed, keep_frames=True, nominal=nominal)
    s = ServerSession(lambda d: PSK1)
    c = ClientSession(1, PSK1)
    c.handle_welcome(s.handle_hello(c.handle_challenge(s.challenge())))
    raw_bits = sum(frame_bits(int(f.get("dlc", 8))) for fr in fl for f in fr)
    nframes = sum(len(fr) for fr in fl)
    naive = sum(len(compact_json(fr)) for fr in fl)  # every frame as JSON object, no encryption
    plain, env, wire = [], [], []
    for b in bl:
        plain.append(len(compact_json(b)))
        m = c.seal(b)
        env.append(len(m))
        wire.append(len(m) + ws_overhead(len(m)))
    dur = len(bl) * WINDOW_MS / 1000.0
    return {
        "frames_per_s": nframes / dur, "raw_can_bps": raw_bits / dur, "raw_can_Bps": raw_bits / 8 / dur,
        "bus_load_pct_formula": 100.0 * raw_bits / dur / BUS_BITRATE,
        "naive_json_Bps": naive / dur, "plain_json_Bps": sum(plain) / dur, "bounded_Bps": sum(env) / dur,
        "bounded_wire_Bps": sum(wire) / dur, "env_sizes": env, "plain_sizes": plain,
    }


def aggregate(sc: str, nominal: bool) -> tuple[dict, np.ndarray]:
    runs = [one(sc, 10 + r, nominal) for r in range(REPEATS)]
    agg = {k: float(np.mean([r[k] for r in runs])) for k in
           ("frames_per_s", "raw_can_bps", "raw_can_Bps", "bus_load_pct_formula", "naive_json_Bps",
            "plain_json_Bps", "bounded_Bps", "bounded_wire_Bps")}
    agg["raw_can_Bps_sd"] = float(np.std([r["raw_can_Bps"] for r in runs]))
    agg["bounded_Bps_sd"] = float(np.std([r["bounded_Bps"] for r in runs]))
    sizes = np.concatenate([r["env_sizes"] for r in runs])
    agg["batch_env_bytes"] = {"min": int(sizes.min()), "median": float(np.median(sizes)),
                              "p95": float(np.percentile(sizes, 95)), "p99": float(np.percentile(sizes, 99)),
                              "max": int(sizes.max()), "mean": float(sizes.mean()), "n": int(len(sizes))}
    agg["reduction_vs_raw_can"] = agg["raw_can_Bps"] / agg["bounded_Bps"]
    agg["reduction_vs_naive_json"] = agg["naive_json_Bps"] / agg["bounded_Bps"]
    return agg, sizes


def worst_case_packet() -> int:
    """Theoretical upper bound: all 2048 11-bit IDs present in one window (one frame each)."""
    frames = [{"id": i, "dlc": 8, "data": "FFFFFFFFFFFFFFFF"} for i in range(2048)]
    b = {"window_ms": 100, "frames": frames, "counts": {str(i): 99 for i in range(2048)}, "bus_load_pct": 100,
         "rx_err": 0, "ts_ms": 1234567890}
    return len(compact_json(b)) + 36


def bars(ax, scn, title, ylabel=True):
    x = np.arange(len(SCENARIOS))
    w = 0.27
    vals = [[scn[s][k] / 1000 for s in SCENARIOS] for k in ("raw_can_Bps", "naive_json_Bps", "bounded_Bps")]
    labs = ["Raw CAN bus", "Naive per-frame JSON", "Bounded batch + AES-GCM"]
    cols = [style.C["grey"], style.C["orange"], style.C["blue"]]
    for i in range(3):
        ax.bar(x + (i - 1) * w, vals[i], w, label=labs[i], color=cols[i], hatch=["", "//", "xx"][i],
               edgecolor="white", lw=0.3)
    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels([s.replace("_", "\n") for s in SCENARIOS], fontsize=6)
    if ylabel:
        ax.set_ylabel("Uplink rate (kB/s)")
    ax.set_title(title, fontsize=8)
    ax.set_ylim(5, 300)


def main():
    out: dict = {"seconds_per_run": SECONDS, "repeats": REPEATS, "window_ms": WINDOW_MS, "bitrate": BUS_BITRATE,
                 "raw_bits_model": "frame_bits(dlc) = int((47 + 8*dlc) * 1.2) per frame (11-bit ID, ~20% stuffing)",
                 "modes": {"measured": "simulator default: injection rate and legit-traffic crowd-out measured on real HCRL",
                           "nominal": "HCRL-paper nominal injection rates (dos 3333/s, fuzzy 2000/s, spoof 1000/s), legit traffic kept"},
                 "scenarios": {}, "scenarios_nominal": {}}
    sizes_m, sizes_n = {}, {}
    for sc in SCENARIOS:
        out["scenarios"][sc], sizes_m[sc] = aggregate(sc, False)
        out["scenarios_nominal"][sc], sizes_n[sc] = aggregate(sc, True)
        print(sc, "measured", {k: round(v, 1) for k, v in out["scenarios"][sc].items() if not isinstance(v, dict)})
        print(sc, "nominal ", {k: round(v, 1) for k, v in out["scenarios_nominal"][sc].items() if not isinstance(v, dict)})
    out["worst_case_packet_bytes_all_2048_ids"] = worst_case_packet()
    out["max_batch_env_bytes_overall"] = int(max(max(s.max() for s in sizes_m.values()), max(s.max() for s in sizes_n.values())))
    save_json("sys_bandwidth", out)

    rows = []
    for sc in SCENARIOS:
        m, n = out["scenarios"][sc], out["scenarios_nominal"][sc]
        rows.append([sc.replace("_", "\_"), f"{m['frames_per_s']:.0f}", f"{m['raw_can_Bps']/1000:.1f}", f"{m['bounded_Bps']/1000:.1f}",
                     f"{m['reduction_vs_raw_can']:.2f}$\times$",
                     f"{n['frames_per_s']:.0f}", f"{n['raw_can_Bps']/1000:.1f}", f"{n['naive_json_Bps']/1000:.1f}",
                     f"{n['bounded_Bps']/1000:.1f}", f"{n['reduction_vs_raw_can']:.2f}$\times$",
                     f"{n['batch_env_bytes']['max']}"])
    write_table("sys_bandwidth",
                ["Traffic", "fr/s", "Raw", "Bnd.", "Red.", "fr/s", "Raw", "JSON", "Bnd.", "Red.", "Max B"], rows,
                "Uplink at 10~Hz batching in kB/s (mean of " + str(REPEATS) + " runs of " + f"{SECONDS:.0f}" +
                "~s). Left block: simulator with injection rates measured on real HCRL. Right block: nominal HCRL-paper "
                "injection rates with legitimate traffic kept (worst case). Raw = CAN-bus bits (500~kbps model), JSON = naive "
                "per-frame JSON, Bnd. = bounded batch in the AES-GCM envelope, Red. = Raw/Bnd., Max B = largest packet.",
                "tab:sys_bandwidth", colspec="lrrrr|rrrrrr", escape=False, resize=True)

    f, (a1, a2, a3) = style.fig(style.FULL_W, 2.6, ncols=3, gridspec_kw={"width_ratios": [1.25, 1.25, 1]})
    bars(a1, out["scenarios"], "(a) Measured-HCRL behaviour")
    bars(a2, out["scenarios_nominal"], "(b) Nominal injection rates", ylabel=False)
    a1.legend(loc="upper right", fontsize=5.5, ncol=1)
    x = np.arange(len(SCENARIOS))
    data, pos, cols = [], [], []
    for i, sc in enumerate(SCENARIOS):
        data += [sizes_m[sc], sizes_n[sc]]
        pos += [i - 0.18, i + 0.18]
    bp = a3.boxplot(data, positions=pos, widths=0.3, patch_artist=True, flierprops={"markersize": 1.2},
                    medianprops={"color": "black", "lw": 0.8})
    for k, patch in enumerate(bp["boxes"]):
        patch.set_facecolor(style.C["sky"] if k % 2 == 0 else style.C["red"])
        patch.set_alpha(0.75)
    a3.set_yscale("log")
    a3.set_xticks(x)
    a3.set_xticklabels([s.replace("_", "\n") for s in SCENARIOS], fontsize=6)
    a3.set_ylabel("Packet size (B)")
    a3.set_title("(c) Batch size (blue: measured, red: nominal)", fontsize=7)
    f.tight_layout()
    style.save(f, "sys_bandwidth")
    print("sys_03 done")


if __name__ == "__main__":
    main()
