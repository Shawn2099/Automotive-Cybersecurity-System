"""Exp 5: server scalability. N simulated devices stream at 10 Hz through the real tunnel to a real server subprocess."""

from __future__ import annotations

import asyncio
import json
import os
import time

import httpx
import numpy as np
import psutil
from websockets.asyncio.client import connect

from common.tunnel import ClientSession
from paper.experiments import style
from paper.experiments.sys_common import PSK1, ServerProc, gen_scenario, save_json, write_table

ns = time.perf_counter_ns
NS = [1, 2, 5, 10, 20, 40]
DUR = float(os.environ.get("SYS_SCALE_SECONDS", 30))
LATE_MS = 100.0


async def device_task(srv, dev, psk, pool, t_send, base, stop_at, lag, start_delay):
    cs = ClientSession(dev, psk)
    async with connect(srv.ws_ingest, max_size=2**20) as ws:
        await ws.send(cs.handle_challenge(await ws.recv()))
        cs.handle_welcome(await ws.recv())
        loop = asyncio.get_running_loop()
        await asyncio.sleep(start_delay)
        nxt = loop.time()
        i = 0
        while loop.time() < stop_at:
            nxt += 0.1
            await asyncio.sleep(max(0.0, nxt - loop.time()))
            lag.append((loop.time() - nxt) * 1000)
            b = dict(pool[i % len(pool)])
            b["ts_ms"] = int(time.monotonic() * 1000)
            i += 1
            msg = cs.seal(b)
            t_send[(dev, base[dev] + cs.seq)] = ns()
            await ws.send(msg)
        await asyncio.sleep(0.3)


async def run_one(srv, psks, n, pool, proc):
    devs = list(range(1, n + 1))
    async with httpx.AsyncClient(timeout=120) as hc:
        st = (await hc.get(f"{srv.http}/api/status")).json()["devices"]
        base = {d: st[str(d)]["packets_ok"] for d in devs}
    t_send: dict = {}
    t_recv: dict = {}

    async def live():
        async with connect(srv.ws_live, max_size=2**22) as ws:
            async for raw in ws:
                t = ns()
                m = json.loads(raw)
                if m.get("type") == "telemetry":
                    t_recv.setdefault((m["device_id"], m["link"]["packets_ok"]), t)

    lt = asyncio.ensure_future(live())
    await asyncio.sleep(0.5)
    lag: list[float] = []
    loop = asyncio.get_running_loop()
    dur = DUR if n <= 10 else DUR / 2  # overloaded points: shorter (queue grows without bound)
    stop_at = loop.time() + 1.5 + dur
    me = psutil.Process()
    rng = np.random.default_rng(n)
    cstart = proc.cpu_times()
    tasks = [asyncio.ensure_future(device_task(srv, d, psks[d], pool, t_send, base, stop_at, lag, float(rng.uniform(0, 0.1))))
             for d in devs]
    await asyncio.sleep(1.5)  # connections up; measure from here
    c0, w0, m0 = proc.cpu_times(), time.perf_counter(), me.cpu_times()
    t_meas0 = ns()
    await asyncio.gather(*tasks)
    c1, w1, m1 = proc.cpu_times(), time.perf_counter(), me.cpu_times()
    rss = proc.memory_info().rss / 2**20
    # let an overloaded server drain its backlog so late packets are measured, not censored
    last, last_t = -1, time.time()
    drain_t0 = time.time()
    while time.time() - drain_t0 < 400:
        got = sum(1 for k in t_send if k in t_recv)
        if got >= len(t_send):
            break
        if got != last:
            last, last_t = got, time.time()
        elif time.time() - last_t > 6:
            break
        await asyncio.sleep(0.5)
    drain_s = time.time() - drain_t0
    c2 = proc.cpu_times()
    async with httpx.AsyncClient(timeout=120) as hc:
        st = (await hc.get(f"{srv.http}/api/status")).json()["devices"]
        ok = {d: st[str(d)]["packets_ok"] - base[d] for d in devs}
        rej = sum(st[str(d)]["packets_rejected"] for d in devs)
    lt.cancel()
    sent = len(t_send)
    # only packets sent inside the measurement window (after the 1.5 s warm-up)
    meas = [k for k, t in t_send.items() if t >= t_meas0]
    lat = np.asarray([(t_recv[k] - t_send[k]) / 1e6 for k in meas if k in t_recv])
    cpu = (c1.user + c1.system) - (c0.user + c0.system)
    wall = w1 - w0
    proc_ok = sum(ok.values())
    return {
        "n_devices": n, "drain_wait_s": drain_s, "sent": sent, "server_ok": proc_ok, "dropped": sent - proc_ok, "rejected": rej,
        "broadcast_received": int(sum(1 for k in t_send if k in t_recv)),
        "server_cpu_s": cpu, "wall_s": wall, "server_cpu_pct_one_core": 100 * cpu / wall,
        "server_cpu_pct_of_machine": 100 * cpu / wall / (psutil.cpu_count(logical=True) or 1),
        "server_ms_cpu_per_packet": 1000 * ((c2.user + c2.system) - (cstart.user + cstart.system)) / max(1, proc_ok),
        "server_rss_mb": rss,
        "lat_median_ms": float(np.median(lat)), "lat_mean_ms": float(lat.mean()), "lat_p95_ms": float(np.percentile(lat, 95)),
        "lat_p99_ms": float(np.percentile(lat, 99)), "lat_max_ms": float(lat.max()),
        "late_fraction_over_100ms": float(np.mean(lat > LATE_MS)), "late_fraction_over_250ms": float(np.mean(lat > 250)),
        "sender_sched_lag_p95_ms": float(np.percentile(lag, 95)), "sender_sched_lag_max_ms": float(np.max(lag)),
        "harness_cpu_pct_one_core": 100 * ((m1.user + m1.system) - (m0.user + m0.system)) / wall,
        "achieved_pkts_per_s": len(meas) / wall,
    }


async def main_async():
    out = {"duration_s": DUR, "duration_s_for_n_gt_10": DUR / 2, "rate_hz": 10, "late_threshold_ms": LATE_MS, "runs": {}}
    pools = {sc: gen_scenario(sc, seconds=20, seed=41)[1] for sc in ("normal", "dos")}
    with ServerProc(8869) as srv:
        proc = psutil.Process(srv.srv.pid)
        psks = {1: PSK1}
        async with httpx.AsyncClient(timeout=10) as hc:
            for d in range(2, max(NS) + 1):
                r = await hc.post(f"{srv.http}/api/vehicles", json={
                    "device_id": d, "name": f"sim{d}", "brand": "Hyundai", "model": "Sonata", "plate": f"SIM-{d:02d}",
                    "can_profile": "hyundai_sonata_hcrl"})
                assert r.status_code == 201, r.text
                psks[d] = bytes.fromhex(r.json()["psk_hex"])
        # warm-up run (not recorded)
        await run_one(srv, psks, 2, pools["normal"], proc)
        for sc in ("normal", "dos"):
            out["runs"][sc] = []
            for n in NS:
                r = await run_one(srv, psks, n, pools[sc], proc)
                out["runs"][sc].append(r)
                print(sc, n, {k: round(v, 2) for k, v in r.items() if isinstance(v, float)}, flush=True)
                await asyncio.sleep(2)
    return out


def main():
    out = asyncio.run(main_async())
    save_json("sys_scalability", out)
    render(out)


def render(out):
    rows = []
    for sc in ("normal", "dos"):
        for r in out["runs"][sc]:
            rows.append([sc, r["n_devices"], f"{r['server_cpu_pct_one_core']:.1f}", f"{r['server_ms_cpu_per_packet']:.2f}",
                         f"{r['lat_median_ms']:.1f}", f"{r['lat_p95_ms']:.1f}", f"{100*r['late_fraction_over_100ms']:.1f}",
                         r["dropped"], f"{r['server_rss_mb']:.0f}"])
    write_table("sys_scalability", ["Traffic", "N", "CPU (\\% core)", "CPU ms/pkt", "Lat. med (ms)", "Lat. p95 (ms)",
                                    "Late $>$100ms (\\%)", "Unproc. at end", "RSS (MB)"], rows,
                f"Server scalability: N devices at 10~Hz each, {out['duration_s']:.0f}~s per point ({out['duration_s_for_n_gt_10']:.0f}~s for $N>10$), one server process "
                "(single-threaded asyncio) on the laptop. CPU is process CPU time over wall time (100\\% = one core).",
                "tab:sys_scalability", colspec="lrrrrrrrr", escape=False, resize=True)

    f, axs = style.fig(style.FULL_W, 2.3, ncols=3)
    for i, (sc, col) in enumerate([("normal", style.C["blue"]), ("dos", style.C["red"])]):
        R = out["runs"][sc]
        x = [r["n_devices"] for r in R]
        kw = dict(color=col, marker=style.MARKERS[i], ls=style.LINES[i], label=sc)
        axs[0].plot(x, [r["server_cpu_pct_one_core"] for r in R], **kw)
        axs[1].plot(x, [r["server_ms_cpu_per_packet"] for r in R], **kw)
        axs[2].plot(x, [r["lat_median_ms"] for r in R], **kw)
        axs[2].plot(x, [r["lat_p95_ms"] for r in R], color=col, marker=style.MARKERS[i], ls=":", alpha=0.6, mfc="none")
    for a, yl, t in zip(axs, ["Server CPU (% of one core)", "CPU time per packet (ms)", "Ingest-to-broadcast (ms)"],
                        ["(a) CPU", "(b) Cost per packet", "(c) Latency: median (solid), p95 (dotted)"]):
        a.set_xlabel("Simulated devices (10 Hz each)")
        a.set_ylabel(yl)
        a.set_title(t, fontsize=7)
        a.set_xscale("log")
        a.set_xticks(NS)
        a.set_xticklabels([str(n) for n in NS])
        a.minorticks_off()
    axs[2].set_yscale("log")
    axs[2].axhline(100, color="grey", lw=0.6, ls="--")
    axs[0].axhline(100, color="grey", lw=0.6, ls="--")
    axs[0].legend()
    f.tight_layout()
    style.save(f, "sys_scalability")
    print("sys_05 done")


if __name__ == "__main__":
    import sys

    if "--render" in sys.argv:
        from paper.experiments.sys_common import load_json

        render(load_json("sys_scalability"))
    else:
        main()
