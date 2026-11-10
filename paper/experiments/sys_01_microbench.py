"""Exp 1: tunnel/crypto microbenchmarks (handshake, seal/open vs payload size, throughput, byte overhead)."""

from __future__ import annotations

import gc
import statistics as st
import time

import numpy as np

from common.crypto import GCM_TAG_SIZE, HEADER_SIZE
from common.tunnel import ClientSession, ServerSession
from paper.experiments import style
from paper.experiments.sys_common import (PSK1, SCENARIOS, compact_json, gen_scenario, pct, save_json, write_table)

N_HS = 1000
lookup = lambda d: PSK1 if d == 1 else None  # noqa: E731
ns = time.perf_counter_ns


def pair():
    s, c = ServerSession(lookup), ClientSession(1, PSK1)
    c.handle_welcome(s.handle_hello(c.handle_challenge(s.challenge())))
    return s, c


def stats_us(a_ns):
    a = np.asarray(a_ns, dtype=float) / 1000.0
    return {"median_us": float(np.median(a)), "p95_us": float(np.percentile(a, 95)), "mean_us": float(a.mean()),
            "min_us": float(a.min()), "n": int(len(a))}


def handshake():
    tot, srv, cli = [], [], []
    for i in range(N_HS + 50):
        t0 = ns()
        s = ServerSession(lookup)
        ch = s.challenge()
        t1 = ns()
        c = ClientSession(1, PSK1)
        he = c.handle_challenge(ch)
        t2 = ns()
        wl = s.handle_hello(he)
        t3 = ns()
        c.handle_welcome(wl)
        t4 = ns()
        assert s.established and c.established
        if i >= 50:  # warm-up
            tot.append(t4 - t0)
            srv.append((t1 - t0) + (t3 - t2))
            cli.append((t2 - t1) + (t4 - t3))
    return {"total": stats_us(tot), "server_side": stats_us(srv), "client_side": stats_us(cli),
            "msgs": {"CH": 18, "HE": 2 + 2 + 16 + 16, "OK": 18}, "bytes_total": 18 + 36 + 18}


def per_message(payloads, reps=1):
    """Seal then open every payload (fresh session), timing each call. Returns seal_ns, open_ns, sizes, plain."""
    s, c = pair()
    msgs, seal_t, plain = [], [], []
    for p in payloads * reps:
        plain.append(len(compact_json(p)))
        t0 = ns()
        m = c.seal(p)
        seal_t.append(ns() - t0)
        msgs.append(m)
    open_t = []
    for m in msgs:
        t0 = ns()
        s.open_data(m)
        open_t.append(ns() - t0)
    return seal_t, open_t, [len(m) for m in msgs], plain


def main():
    gc.collect()
    out: dict = {"n_handshakes": N_HS}
    out["handshake"] = handshake()

    # ---- real batches
    real = {}
    allpts = []
    for sc in SCENARIOS:
        _, bl = gen_scenario(sc, seconds=20, seed=3)
        sl, ol, wire, plain = per_message(bl, reps=3)
        overhead = sorted({w - p for w, p in zip(wire, plain)})
        real[sc] = {"payload_bytes_median": float(np.median(plain)), "payload_bytes_p95": pct(plain, 95),
                    "payload_bytes_max": int(max(plain)), "wire_bytes_median": float(np.median(wire)),
                    "overhead_bytes_observed": overhead, "seal": stats_us(sl), "open": stats_us(ol),
                    "roundtrip_median_us": float(np.median(np.add(sl, ol)) / 1000.0), "n": len(sl)}
        import json as _j
        dj, lj = [], []
        for b in bl:
            t0 = ns(); raw = _j.dumps(b, separators=(",", ":")).encode(); dj.append(ns() - t0)
            t0 = ns(); _j.loads(raw.decode()); lj.append(ns() - t0)
        real[sc]["json_encode_median_us"] = float(np.median(dj) / 1000)
        real[sc]["json_decode_median_us"] = float(np.median(lj) / 1000)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aes, gt, gd = AESGCM(PSK1), [], []
        for i, b in enumerate(bl):
            raw = compact_json(b); nonce = i.to_bytes(12, "big"); aad = b"\x00" * 6
            t0 = ns(); ct = aes.encrypt(nonce, raw, aad); gt.append(ns() - t0)
            t0 = ns(); aes.decrypt(nonce, ct, aad); gd.append(ns() - t0)
        real[sc]["gcm_only_seal_median_us"] = float(np.median(gt) / 1000)
        real[sc]["gcm_only_open_median_us"] = float(np.median(gd) / 1000)
    out["real_batches"] = real
    out["overhead_expected_bytes"] = 2 + HEADER_SIZE + GCM_TAG_SIZE
    out["overhead_verified"] = all(v["overhead_bytes_observed"] == [out["overhead_expected_bytes"]] for v in real.values())

    # ---- synthetic size sweep
    sizes = [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768]
    sweep = []
    for sz in sizes:
        base = len(compact_json({"pad": ""}))
        payload = [{"pad": "x" * (sz - base)}]
        sl, ol, wire, plain = per_message(payload, reps=400)
        sweep.append({"payload_bytes": plain[0], "wire_bytes": wire[0], "seal": stats_us(sl[20:]), "open": stats_us(ol[20:])})
    out["sweep"] = sweep

    # ---- throughput (single thread, seal + open back-to-back)
    thr = {}
    for sc in ("normal", "dos", "fuzzy"):
        _, bl = gen_scenario(sc, seconds=20, seed=4)
        s, c = pair()
        n = 0
        t0 = time.perf_counter()
        for _ in range(25):
            for b in bl:
                s.open_data(c.seal(b))
                n += 1
        dt = time.perf_counter() - t0
        thr[sc] = {"msgs": n, "seconds": dt, "msgs_per_s": n / dt,
                   "device_equivalents_at_10hz": n / dt / 10.0}
    out["throughput_seal_open"] = thr
    save_json("sys_microbench", out)

    # ---- table
    hs = out["handshake"]
    rows = []
    for sc in SCENARIOS:
        r = real[sc]
        rows.append([sc, f"{r['payload_bytes_median']:.0f}", f"{r['wire_bytes_median']:.0f}",
                     f"{r['seal']['median_us']:.1f}", f"{r['open']['median_us']:.1f}", f"{r['open']['p95_us']:.1f}",
                     f"{thr[sc]['msgs_per_s']:.0f}" if sc in thr else "--"])
    write_table("sys_microbench", ["Traffic", "Payload (B)", "On-wire (B)", "Seal ($\mu$s)", "Open ($\mu$s)",
                                   "Open p95 ($\mu$s)", "Seal+open msg/s"], rows,
                f"AES-128-GCM tunnel cost per DATA message (median over {real['normal']['n']} real batches per "
                f"traffic type). Handshake: median {hs['total']['median_us']:.0f}~$\mu$s, p95 "
                f"{hs['total']['p95_us']:.0f}~$\mu$s (N={N_HS}). Overhead is a constant "
                f"{out['overhead_expected_bytes']}~B per message.", "tab:sys_microbench", escape=False)

    # ---- figure
    f, ax = style.fig(style.COL_W, 2.4)
    x = [p["payload_bytes"] for p in sweep]
    for i, (k, lab) in enumerate([("seal", "seal (encrypt)"), ("open", "open (decrypt+verify)")]):
        med = np.array([p[k]["median_us"] for p in sweep])
        p95 = np.array([p[k]["p95_us"] for p in sweep])
        ax.plot(x, med, marker=style.MARKERS[i], ls=style.LINES[i], label=lab, color=[style.C["blue"], style.C["red"]][i])
        ax.fill_between(x, med, p95, alpha=0.15, color=[style.C["blue"], style.C["red"]][i], lw=0)
    for sc, mk, col in [("normal", "o", "grey"), ("dos", "s", "orange"), ("fuzzy", "^", "green")]:
        r = real[sc]
        ax.scatter([r["payload_bytes_median"]] * 2, [r["seal"]["median_us"], r["open"]["median_us"]], s=22,
                   marker=mk, facecolors="none", edgecolors=style.C[col], zorder=5, label=f"real {sc} batch")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Plaintext payload size (bytes)")
    ax.set_ylabel("Latency per message ($\mu$s)")
    ax.legend(ncol=1, fontsize=6, loc="upper left")
    style.save(f, "sys_crypto_latency")
    print("sys_01 done; handshake median us:", hs["total"]["median_us"], "overhead verified:", out["overhead_verified"])


if __name__ == "__main__":
    main()
