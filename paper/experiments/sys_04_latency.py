"""Exp 4: end-to-end latency.

(a) packet ingest-to-broadcast: own harness sends sealed batches (ClientSession) over a real WebSocket to a real
    server subprocess and receives the telemetry broadcast on /ws/live. Sender and live client share one process
    and one clock (time.perf_counter_ns), matching packets by the per-device packets_ok counter. Plus an
    in-process per-stage breakdown (decrypt / decode / analytics / JSON serialisation).
(b) attack/fault-onset-to-alert: real server + real simulator subprocesses; toggle through the simulator REST API,
    observe the alert on /ws/live. >= 10 trials per scenario.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time

import httpx
import numpy as np
from websockets.asyncio.client import connect

from common.can_profiles import decode_can_frames
from common.tunnel import ClientSession, ServerSession
from paper.experiments import style
from paper.experiments.sys_common import (PROFILE, PSK1, ServerProc, gen_scenario, save_json, write_table)

ns = time.perf_counter_ns
N_TRIALS = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 10


# ====================================================================== (a)
async def stream(srv: ServerProc, batches: list[dict], device: int, psk: bytes):
    """Send batches at 10 Hz; returns latencies (ms) ingest->broadcast."""
    async with httpx.AsyncClient() as hc:
        st = (await hc.get(f"{srv.http}/api/status")).json()["devices"][str(device)]
        base = st["packets_ok"]
    t_send: dict[int, int] = {}
    t_recv: dict[int, int] = {}

    async def live():
        async with connect(srv.ws_live, max_size=2**22) as ws:
            async for raw in ws:
                t = ns()
                m = json.loads(raw)
                if m.get("type") == "telemetry" and m.get("device_id") == device:
                    t_recv.setdefault(m["link"]["packets_ok"], t)

    lt = asyncio.ensure_future(live())
    await asyncio.sleep(0.5)
    cs = ClientSession(device, psk)
    async with connect(srv.ws_ingest, max_size=2**20) as ws:
        cs.handle_welcome(await _hs(ws, cs))
        loop = asyncio.get_running_loop()
        nxt = loop.time()
        for b in batches:
            nxt += 0.1
            await asyncio.sleep(max(0.0, nxt - loop.time()))
            msg = cs.seal(b)
            t_send[base + cs.seq] = ns()
            await ws.send(msg)
        await asyncio.sleep(1.0)
    lt.cancel()
    lat = [(t_recv[k] - t_send[k]) / 1e6 for k in t_send if k in t_recv]
    return lat, len(t_send), len(t_recv)


async def _hs(ws, cs):
    ch = await ws.recv()
    await ws.send(cs.handle_challenge(ch))
    return await ws.recv()


def lat_stats(l):
    a = np.asarray(l)
    return {"n": int(len(a)), "median_ms": float(np.median(a)), "mean_ms": float(a.mean()),
            "p95_ms": float(np.percentile(a, 95)), "p99_ms": float(np.percentile(a, 99)), "max_ms": float(a.max()),
            "min_ms": float(a.min())}


def stage_breakdown():
    """In-process cost of each server stage per batch (same code as server.app.main.Hub.handle_batch)."""
    from server.app.analytics import VehicleAnalyzer, load_models
    from server.app.main import MODEL_DIR

    models = load_models(MODEL_DIR)
    out = {"models_loaded": models is not None}
    for sc in ("normal", "dos", "fuzzy"):
        _, bl = gen_scenario(sc, seconds=20, seed=21)
        s = ServerSession(lambda d: PSK1)
        c = ClientSession(1, PSK1)
        c.handle_welcome(s.handle_hello(c.handle_challenge(s.challenge())))
        msgs = [c.seal(b) for b in bl]
        an = VehicleAnalyzer(PROFILE, models)
        t_open, t_dec, t_an, t_ser = [], [], [], []
        for i, m in enumerate(msgs):
            t0 = ns()
            env = s.open_data(m)
            t1 = ns()
            dec = decode_can_frames(PROFILE, env.payload.get("frames", []))
            t2 = ns()
            res = an.update(env.payload, dec, i * 0.1)
            t3 = ns()
            json.dumps({"type": "telemetry", "device_id": 1, "signals": dec["signals"], "analysis": res,
                        "link": {"packets_ok": i, "last_plain": env.payload}})
            t4 = ns()
            t_open.append(t1 - t0), t_dec.append(t2 - t1), t_an.append(t3 - t2), t_ser.append(t4 - t3)
        md = lambda a: float(np.median(a) / 1e6)  # noqa: E731
        out[sc] = {"decrypt_ms": md(t_open), "decode_ms": md(t_dec), "analytics_ms": md(t_an),
                   "json_serialise_ms": md(t_ser),
                   "total_ms": md(np.add(np.add(t_open, t_dec), np.add(t_an, t_ser))),
                   "analytics_p95_ms": float(np.percentile(t_an, 95) / 1e6)}
    return out


def part_a():
    res = {}
    with ServerProc(8865) as srv:
        for sc, secs in (("normal", 40), ("dos", 20), ("fuzzy", 20)):
            _, bl = gen_scenario(sc, seconds=secs, seed=31)
            lat, sent, recv = asyncio.run(stream(srv, bl, 1, PSK1))
            lat = lat[20:]  # warm-up
            res[sc] = {**lat_stats(lat), "sent": sent, "broadcast_received": recv,
                       "fraction_over_100ms": float(np.mean(np.asarray(lat) > 100)), "raw_ms": [round(x, 3) for x in lat]}
            print("ingest->broadcast", sc, {k: round(v, 2) for k, v in res[sc].items() if k != "raw_ms" and isinstance(v, float)})
    res["stages"] = stage_breakdown()
    return res


# ====================================================================== (b)
SCEN = [
    # name, route, key, expected alert categories, "kind", timeout
    ("dos", "attacks", "dos", {"dos"}, "attack", 15),
    ("fuzzy", "attacks", "fuzzy", {"fuzzy"}, "attack", 15),
    ("rpm_spoof", "attacks", "rpm_spoof", {"spoofing_rpm"}, "attack", 15),
    ("gear_spoof", "attacks", "gear_spoof", {"spoofing_gear"}, "attack", 15),
    ("steering_spoof", "attacks", "steering_spoof", {"spoofing_steering"}, "attack", 15),
    ("replay", "tunnel", "replay", {"replay"}, "tunnel", 15),
    ("tamper", "tunnel", "tamper", {"tamper"}, "tunnel", 15),
    ("wrong_key", "tunnel", "wrong_key", {"auth_fail"}, "tunnel", 20),
    ("sensor_inconsistency", "faults", "sensor_inconsistency", {"sensor_inconsistency"}, "fault", 25),
    ("overheat", "faults", "overheat", {"overheat", "forecast_overheat"}, "fault", 40),
    ("battery_drain", "faults", "battery_drain", {"low_battery", "forecast_battery"}, "fault", 50),
]
THRESH_ALERT = {"overheat": "overheat", "battery_drain": "low_battery"}


class Live:
    def __init__(self, url):
        self.url = url
        self.events: list[tuple[int, str, dict]] = []
        self.health, self.risk, self.connected = 100, 0, False
        self.task = None

    async def run(self):
        async with connect(self.url, max_size=2**22) as ws:
            async for raw in ws:
                t = ns()
                m = json.loads(raw)
                if m.get("type") == "alert" and m.get("device_id") == 1:
                    self.events.append((t, "alert", m["alert"]))
                elif m.get("type") == "telemetry" and m.get("device_id") == 1:
                    a = m["analysis"]
                    self.health, self.risk = a["health"]["overall"], a["cyber_risk"]
                    self.events.append((t, "tel", {"health": self.health, "risk": self.risk,
                                                   "cls": a["attack_class"]}))
                elif m.get("type") == "link" and m.get("device_id") == 1:
                    self.connected = m["connected"]

    def first(self, after: int, pred):
        for t, k, p in self.events:
            if t >= after and pred(k, p):
                return t
        return None


async def wait_for(cond, timeout, every=0.05):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        await asyncio.sleep(every)
    return False


async def part_b_async(srv: ServerProc, n_trials: int):
    live = Live(srv.ws_live)
    live.task = asyncio.ensure_future(live.run())
    out = {}
    async with httpx.AsyncClient(timeout=5) as hc:
        await hc.post(f"{srv.sim_http}/api/cars/1/controls", json={"speed_kmh": 60, "throttle_pct": 20})
        await wait_for(lambda: live.health is not None and len(live.events) > 30, 40)
        for name, route, key, cats, kind, tmo in SCEN:
            trials = []
            last_alert_t = 0
            for i in range(n_trials):
                healthy = lambda: live.health >= 85 and live.risk <= 20  # noqa: E731
                ok = await wait_for(healthy, 90)
                gap = 4.0 if kind == "attack" else 11.0
                await wait_for(lambda: (ns() - last_alert_t) / 1e9 > gap, 30)
                await asyncio.sleep(0.5)
                t0 = ns()
                await hc.post(f"{srv.sim_http}/api/cars/1/{route}", json={key: True})
                t_post = ns()
                got = await wait_for(lambda: live.first(t0, lambda k, p: k == "alert" and p.get("category") in cats) is not None, tmo)
                ta = live.first(t0, lambda k, p: k == "alert" and p.get("category") in cats)
                if kind == "fault":
                    thr = THRESH_ALERT.get(name)
                    if thr:  # also wait for the threshold-crossing alert (forecast alert comes earlier)
                        await wait_for(lambda: live.first(t0, lambda k, p: k == "alert" and p.get("category") == thr) is not None, 30)
                    else:
                        await asyncio.sleep(0.5)
                    thr_t = live.first(t0, lambda k, p: k == "alert" and p.get("category") == thr) if thr else None
                    ts = live.first(t0, lambda k, p: k == "tel" and p["health"] < 85)
                else:
                    await asyncio.sleep(1.0)
                    thr_t = None
                    ts = live.first(t0, lambda k, p: k == "tel" and p["risk"] >= 50)
                tc = live.first(t0, lambda k, p: k == "tel" and p["cls"] != "normal") if kind != "fault" else None
                cats_seen = sorted({p.get("category") for t, k, p in live.events if k == "alert" and t >= t0})
                trials.append({
                    "alert_ms": None if ta is None else (ta - t0) / 1e6,
                    "alert_ms_from_post_return": None if ta is None else (ta - t_post) / 1e6,
                    "post_rtt_ms": (t_post - t0) / 1e6,
                    "score_ms": None if ts is None else (ts - t0) / 1e6,
                    "class_ms": None if tc is None else (tc - t0) / 1e6,
                    "threshold_alert_ms": None if thr_t is None else (thr_t - t0) / 1e6,
                    "detected": bool(got), "categories_seen": cats_seen, "was_healthy_at_start": bool(ok)})
                if ta is not None:
                    last_alert_t = max(last_alert_t, max(t for t, k, p in live.events if k == "alert" and t >= t0))
                await hc.post(f"{srv.sim_http}/api/cars/1/{route}", json={key: False})
                print(f"  {name} trial {i}: alert {trials[-1]['alert_ms']}, score {trials[-1]['score_ms']}", flush=True)
                await asyncio.sleep(1.5)
            out[name] = {"kind": kind, "expected_categories": sorted(cats), "trials": trials}
    live.task.cancel()
    return out


def summarize(vals):
    a = np.asarray([v for v in vals if v is not None], dtype=float)
    if len(a) == 0:
        return {"n": 0}
    return {"n": int(len(a)), "median": float(np.median(a)), "mean": float(a.mean()), "p95": float(np.percentile(a, 95)),
            "min": float(a.min()), "max": float(a.max())}


def part_b(n_trials):
    with ServerProc(8867, 8868) as srv:
        return asyncio.run(part_b_async(srv, n_trials))


def main():
    out = {"n_trials": N_TRIALS, "note_clock": "all timestamps from time.perf_counter_ns in one process (same machine)"}
    out["ingest_to_broadcast"] = part_a()
    out["onset_to_alert"] = part_b(N_TRIALS)
    for name, d in out["onset_to_alert"].items():
        d["alert_ms_summary"] = summarize([t["alert_ms"] for t in d["trials"]])
        d["score_ms_summary"] = summarize([t["score_ms"] for t in d["trials"]])
        d["threshold_alert_ms_summary"] = summarize([t["threshold_alert_ms"] for t in d["trials"]])
        d["class_ms_summary"] = summarize([t["class_ms"] for t in d["trials"]])
        d["detection_rate"] = float(np.mean([t["detected"] for t in d["trials"]]))
    save_json("sys_latency", out)
    render(out)


def render(out):
    N_TRIALS = out["n_trials"]

    # ---- table
    rows = []
    for name, d in out["onset_to_alert"].items():
        s, r = d["alert_ms_summary"], d["class_ms_summary"]
        slow = d["kind"] == "fault" and name != "sensor_inconsistency"
        fmt = (lambda x: f"{x/1000:.1f}") if slow else (lambda x: f"{x:.0f}")
        unit = "s" if slow else "ms"
        if s["n"]:
            rows.append([name, d["kind"], f"{d['detection_rate']*100:.0f}", f"{fmt(s['median'])}", f"{fmt(s['p95'])}",
                         f"{fmt(s['min'])}--{fmt(s['max'])}", unit,
                         (fmt(r["median"]) if r["n"] else "--")])
        else:
            rows.append([name, d["kind"], "0", "--", "--", "--", unit, "--"])
    write_table("sys_latency", ["Scenario", "Type", "Det. (\\%)", "Median", "p95", "Range", "Unit",
                                "Class set (med.)"], [[x.replace("_", "\\_") if i == 0 else x for i, x in enumerate(r)] for r in rows],
                f"Onset-to-alert latency through the full stack (simulator REST toggle $\\rightarrow$ alert on /ws/live), "
                f"{N_TRIALS} trials per scenario. ``Class set'' is the time until attack\_class leaves normal (attacks only).",
                "tab:sys_latency", colspec="llrrrrlr", escape=False, resize=True)
    ia = out["ingest_to_broadcast"]
    rows2 = [[sc, f"{ia[sc]['median_ms']:.1f}", f"{ia[sc]['p95_ms']:.1f}", f"{ia[sc]['p99_ms']:.1f}", f"{ia[sc]['max_ms']:.1f}",
              f"{ia['stages'][sc]['decrypt_ms']:.2f}", f"{ia['stages'][sc]['decode_ms']:.2f}",
              f"{ia['stages'][sc]['analytics_ms']:.2f}", f"{ia['stages'][sc]['json_serialise_ms']:.2f}"] for sc in ("normal", "dos", "fuzzy")]
    write_table("sys_ingest_latency", ["Traffic", "Med.", "p95", "p99", "Max", "Decrypt", "Decode", "Analytics", "JSON"], rows2,
                "Packet ingest-to-broadcast latency in ms (client send $\\rightarrow$ /ws/live receipt, loopback) and "
                "median in-process time per server stage in ms.", "tab:sys_ingest_latency", escape=False, resize=True)

    # ---- figure
    f, (a1, a2) = style.fig(style.FULL_W, 2.7, ncols=2, gridspec_kw={"width_ratios": [2.0, 1]})
    names1 = [n for n, d in out["onset_to_alert"].items() if d["kind"] != "fault"]
    names2 = [n for n, d in out["onset_to_alert"].items() if d["kind"] == "fault"]
    colr = {"attack": style.C["sky"], "tunnel": style.C["purple"], "fault": style.C["orange"]}

    def box(ax, names, scale, unit):
        data = [[t["alert_ms"] / scale for t in out["onset_to_alert"][n]["trials"] if t["alert_ms"] is not None] or [np.nan] for n in names]
        bp = ax.boxplot(data, patch_artist=True, widths=0.55, flierprops={"markersize": 2}, medianprops={"color": "black"})
        for p, n in zip(bp["boxes"], names):
            p.set_facecolor(colr[out["onset_to_alert"][n]["kind"]])
            p.set_alpha(0.8)
        for i, d in enumerate(data):
            ax.scatter(np.random.default_rng(i).normal(i + 1, 0.06, len(d)), d, s=3, color="k", alpha=0.5, zorder=3)
        ax.set_xticks(range(1, len(names) + 1))
        ax.set_xticklabels([n.replace("_", "\n") for n in names], fontsize=6)
        ax.set_ylabel(f"Onset-to-alert ({unit})")

    box(a1, names1, 1.0, "ms")
    a1.set_title("(a) CAN attacks (blue) and tunnel attacks (purple)", fontsize=7)
    box(a2, names2, 1000.0, "s")
    a2.set_title("(b) Faults (first alert, incl. forecast)", fontsize=7)
    f.tight_layout()
    style.save(f, "sys_alert_latency")
    print("sys_04 done")


if __name__ == "__main__":
    if "--render" in sys.argv:
        from paper.experiments.sys_common import load_json

        render(load_json("sys_latency"))
    else:
        main()
