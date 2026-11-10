"""Write paper/results/sys_SUMMARY.md from paper/results/sys_*.json (every number is read from the results, none typed by hand).

    python -m paper.experiments.sys_summary

Only the standard library is used, so this never touches the simulator/server and is safe to run at any time.
Prose (captions, method text, threats) is template text; numbers, the machine description and the list of
tested attacks all come from the JSON files.
"""
from __future__ import annotations

import json
from pathlib import Path

PAPER = Path(__file__).resolve().parents[1]
RES = PAPER / "results"

NAMES = ("microbench", "security", "bandwidth", "latency", "scalability", "health", "cyber_timeline")
SCEN = ("normal", "dos", "fuzzy", "rpm_spoof", "gear_spoof", "steering_spoof")


def load(name: str) -> dict:
    return json.loads((RES / f"sys_{name}.json").read_text(encoding="utf-8"))


def x(r: float) -> str:
    """Reduction factor: two decimals below 1 (a batch larger than the raw bus), one decimal otherwise."""
    return f"{r:.2f}x" if r < 1 else f"{r:.1f}x"


def ms_s(v_ms: float) -> str:
    """Latency in ms, switching to seconds above 1 s."""
    return f"{v_ms / 1000:.1f} s" if v_ms >= 1000 else f"{v_ms:.0f} ms"


def rng(vals, fmt="{:.0f}") -> str:
    lo, hi = min(vals), max(vals)
    return fmt.format(lo) if fmt.format(lo) == fmt.format(hi) else f"{fmt.format(lo)}-{fmt.format(hi)}"


def main():
    MB, SEC, BW, LAT, SC, HE, CT = (load(n) for n in NAMES)

    # ---------------------------------------------------------------- machine (must agree across files)
    machines = [d["machine"] for d in (MB, SEC, BW, LAT, SC, HE, CT)]
    m0 = machines[0]
    diffs = sorted({k for m in machines for k in set(m) | set(m0)
                    if k not in ("timestamp", "on_ac_power") and m.get(k) != m0.get(k)})
    stamps = sorted(m["timestamp"] for m in machines)
    libs = ", ".join(f"{k} {v}" for k, v in m0["libs"].items())
    machine_line = (f"{m0['cpu'].replace('(R)', '').replace('(TM)', '').replace(' CPU', '')} "
                    f"({m0['cpu_cores_physical']}C/{m0['cpu_threads']}T), {m0['ram_gb']} GB RAM, {m0['os']}, "
                    f"{m0['python_impl']} {m0['python']}, {libs}")
    if diffs:
        machine_line += f". WARNING: the machine info differs between result files in: {', '.join(diffs)}"
    cores = m0["cpu_cores_physical"]

    # ---------------------------------------------------------------- derived numbers
    rb = MB["real_batches"]
    hs = MB["handshake"]
    nreal = sum(v["n"] for v in rb.values())
    ovh_all = {o for v in rb.values() for o in v["overhead_bytes_observed"]}
    ovh = MB["overhead_expected_bytes"]
    assert MB["overhead_verified"] and ovh_all == {ovh}, "overhead not constant in microbench JSON"
    rate_hz = 1000 // BW["window_ms"]
    thr = MB["throughput_seal_open"]
    gcm = [v[k] for v in rb.values() for k in ("gcm_only_seal_median_us", "gcm_only_open_median_us")]
    enc = [v["json_encode_median_us"] for v in rb.values()]
    dec = [v["json_decode_median_us"] for v in rb.values()]
    sweep_lo, sweep_hi = MB["sweep"][0]["payload_bytes"], MB["sweep"][-1]["payload_bytes"]
    sweep_n = MB["sweep"][0]["seal"]["n"]
    nb = rb["normal"]

    tests = SEC["tests"]
    benign = tests[0]
    attacks = tests[1:]
    assert benign["expected"] == "accept"
    all_rej = all(t["rejected"] == t["trials"] and t["success_rate_pct"] == 100.0 for t in attacks)
    n_exc = sum(t["unexpected_exceptions"] for t in tests)
    tpt = SEC["trials_per_test"]
    # "rule of three": 100 % over n trials bounds the failure probability at about 3/n (95 %)
    r3 = 300.0 / tpt

    sc, sn = BW["scenarios"], BW["scenarios_nominal"]
    bw_kb = lambda d, k: d[k]["raw_can_Bps"] / 1000  # noqa: E731
    bd_kb = lambda d, k: d[k]["bounded_Bps"] / 1000  # noqa: E731
    wire_extra = {round((sc[k]["bounded_wire_Bps"] - sc[k]["bounded_Bps"]) / rate_hz) for k in SCEN}
    wire_extra = wire_extra.pop() if len(wire_extra) == 1 else None

    st = LAT["ingest_to_broadcast"]
    stg = st["stages"]
    onset = LAT["onset_to_alert"]
    att_cats = ("dos", "fuzzy", "rpm_spoof", "gear_spoof", "steering_spoof")
    tun_cats = ("replay", "tamper", "wrong_key")
    flt_cats = ("sensor_inconsistency", "overheat", "battery_drain")
    med = lambda k: onset[k]["alert_ms_summary"]["median"]  # noqa: E731
    p95 = lambda k: onset[k]["alert_ms_summary"]["p95"]  # noqa: E731
    det_all = all(v["detection_rate"] == 1.0 and v["alert_ms_summary"]["n"] == len(v["trials"]) == LAT["n_trials"]
                  for v in onset.values())
    det_txt = f"{LAT['n_trials']}/{LAT['n_trials']} detected each" if det_all else "detection rates in the JSON"
    cls_gap = max(abs(onset[k]["class_ms_summary"]["median"] - med(k)) for k in att_cats)
    rtts = [t["post_rtt_ms"] for v in onset.values() for t in v["trials"]]
    rtts_med = sorted(rtts)[len(rtts) // 2]
    floor_lo = min(st[k]["min_ms"] for k in ("normal", "dos", "fuzzy"))
    floor_hi = max(st[k]["min_ms"] for k in ("normal", "dos", "fuzzy"))
    fault_forecast_seen = any(c.startswith("forecast") for k in ("overheat", "battery_drain")
                              for t in onset[k]["trials"] for c in t["categories_seen"])
    fault_thr_is_alert = all(abs(onset[k]["alert_ms_summary"]["median"] - onset[k]["threshold_alert_ms_summary"]["median"]) < 1
                             for k in ("overheat", "battery_drain"))

    runs = SC["runs"]
    allrows = [r for m in runs.values() for r in m]
    ok_rows = [r for r in allrows if r["n_devices"] <= 10]
    ms_pkt = sum(r["server_ms_cpu_per_packet"] for r in ok_rows) / len(ok_rows)
    cap_pps = 1000.0 / ms_pkt
    cap_dev = cap_pps / SC["rate_hz"]
    late_thr_s = SC["late_threshold_ms"]
    n_sat = min(r["n_devices"] for r in allrows if r["late_fraction_over_100ms"] >= 0.99)
    pre = [r for r in allrows if r["n_devices"] < n_sat]
    pre5 = [r for r in allrows if r["n_devices"] <= 5]
    nrm = {r["n_devices"]: r for r in runs["normal"]}
    dosr = {r["n_devices"]: r for r in runs["dos"]}
    ns = sorted(nrm)
    n_last = ns[-1]
    sat_r = nrm[n_sat]
    big = [r for m in runs for r in runs[m] if r["n_devices"] > n_sat]
    affected = [f"N={r['n_devices']} ({m})" for m in runs for r in runs[m] if r["dropped"] > 0 or r["sent"] != r["server_ok"]]
    harness = [r["harness_cpu_pct_one_core"] for r in allrows]
    rejected_total = sum(r["rejected"] for r in allrows)

    fc = HE["forecast"]
    cc, bv = fc["coolant_c"], fc["battery_v"]
    ts = HE["timeseries_summary"]
    an = HE["anomaly"]
    fa = lambda s, k: ts[s]["first_alerts"][k] - ts[s]["fault_on_s"]  # noqa: E731
    lead_gain = (cc["forecast_alert_lead_median_s"] - cc["threshold_alert_lead_median_s"],
                 bv["forecast_alert_lead_median_s"] - bv["threshold_alert_lead_median_s"])
    if_fault = ("overheat", "battery_drain", "sensor_inconsistency")
    if_cross = [k for k in if_fault if an[k]["frac_over_thr"] > 0]

    ph = CT["phases"]
    quiet = CT["quiet"]
    seeds = CT["first_alert_delay_over_10_seeds"]
    nseeds = len(next(iter(seeds.values())))
    t_end = CT["series"]["t"][-1]
    ph_names = {"dos": "DoS", "fuzzy": "fuzzy", "rpm_spoof": "RPM spoof", "tamper": "tamper"}
    ph_txt = ", ".join(f"{ph_names.get(p['phase'], p['phase'])} ({p['start_s']}-{p['end_s']} s)" for p in ph)
    slash = lambda key, fmt: " / ".join(fmt.format(p[key]) for p in ph)  # noqa: E731
    pct_ok = lambda p: 100 * p["frac_windows_class_correct"]  # noqa: E731

    L: list[str] = []
    A = L.append
    A("<!-- generated by paper/experiments/sys_summary.py from results/sys_*.json; do not edit by hand -->")
    A("# System-level experiments: summary (prefix `sys_`)\n")
    A("Run everything: `python -m paper.experiments.run_sys_all` (long: exps 4 and 5 start their own server/simulator on local ports with temp DBs and need an idle machine). "
      "Single: `python -m paper.experiments.sys_0N_*`. Exps 4 and 5 can re-render figures/tables from saved JSON with `--render`. "
      "This file is generated by `python -m paper.experiments.sys_summary` from `paper/results/sys_*.json`; it can be regenerated at any time without re-running the experiments.\n")
    A(f"Machine (also embedded in every `sys_*.json`; runs recorded {stamps[0]} to {stamps[-1]}): {machine_line}. "
      "The laptop is the edge server. A demo server was running on the same machine during the runs.\n")
    A("Shared helper: `paper/experiments/sys_common.py`. All figures use `paper/experiments/style.py`. All tables are booktabs in `paper/tables/`.\n")

    # ------------------------------------------------------------------ Headline
    A("## Headline numbers")
    A(f"- Tunnel: handshake median {hs['total']['median_us']:.0f} us (p95 {hs['total']['p95_us']:.0f} us, N={MB['n_handshakes']}, in-process, "
      f"{hs['bytes_total']} B on wire in {len(hs['msgs'])} messages). Seal+open of a real {nb['payload_bytes_median'] / 1000:.1f} kB batch ~{nb['roundtrip_median_us']:.0f} us "
      f"(seal {nb['seal']['median_us']:.0f} us, open {nb['open']['median_us']:.0f} us); about {thr['normal']['msgs_per_s'] / 1000:.1f}k msgs/s on one core "
      f"(a {rate_hz} Hz device needs {rate_hz} msg/s). Overhead is exactly {ovh} B per message, verified on {nreal} real messages. "
      f"Pure AES-GCM is only ~{min(gcm):.0f}-{max(gcm):.0f} us of that; JSON encode/decode (~{min(enc):.0f}-{max(enc):.0f}/{min(dec):.0f}-{max(dec):.0f} us) dominates.")
    A(f"- Security: {len(attacks)} attack classes x {tpt} trials each: "
      + (f"{min(t['success_rate_pct'] for t in attacks):.0f}% rejected" if all_rej else "NOT all rejected (see JSON)")
      + f", {benign['rejected']} false rejects on {benign['trials']} benign messages, {n_exc} unexpected exceptions.")
    A(f"- Bandwidth: normal bounded batch = {bd_kb(sc, 'normal'):.1f} kB/s ({nb['wire_bytes_median']:.0f} B/pkt) vs raw CAN {bw_kb(sc, 'normal'):.1f} kB/s -> only **{x(sc['normal']['reduction_vs_raw_can'])}** "
      f"reduction ({x(sc['normal']['reduction_vs_naive_json'])} vs naive per-frame JSON). Under nominal HCRL-paper DoS the reduction is {x(sn['dos']['reduction_vs_raw_can'])} "
      f"(raw {bw_kb(sn, 'dos'):.1f} kB/s vs {bd_kb(sn, 'dos'):.1f} kB/s). "
      f"**Fuzzy is the exception: the batch is larger than the raw bus bytes** ({x(sc['fuzzy']['reduction_vs_raw_can'])} measured, {x(sn['fuzzy']['reduction_vs_raw_can'])} nominal: "
      f"{bd_kb(sc, 'fuzzy'):.1f} kB/s and {bd_kb(sn, 'fuzzy'):.0f} kB/s) because each distinct random ID adds a frame entry. "
      f"Worst-case packet if all 2048 IDs appear: {BW['worst_case_packet_bytes_all_2048_ids'] / 1000:.1f} kB. Observed max {BW['max_batch_env_bytes_overall'] / 1000:.1f} kB.")
    A(f"- Latency: ingest-to-broadcast median {st['normal']['median_ms']:.1f} ms, p95 {st['normal']['p95_ms']:.1f} ms, p99 {st['normal']['p99_ms']:.0f} ms (normal, loopback, 1 device). "
      f"Onset-to-alert over the full stack ({LAT['n_trials']} trials each, {'100% detected' if det_all else 'see JSON'}): "
      + ", ".join(f"{k} {med(k):.0f}" for k in att_cats) + " ms (medians); tunnel: "
      + ", ".join(f"{k} {med(k):.0f}" for k in tun_cats) + " ms; faults: "
      + f"sensor_inconsistency {med('sensor_inconsistency'):.0f} ms, overheat {med('overheat') / 1000:.1f} s, battery_drain {med('battery_drain') / 1000:.1f} s.")
    A(f"- Scalability: **one server process saturates at ~{cap_dev:.0f} devices at {SC['rate_hz']} Hz** ({ms_pkt:.1f} ms CPU per packet, ~{cap_pps:.0f} packets/s/core). "
      f"N<={max(r['n_devices'] for r in pre5)}: median latency {rng([r['lat_median_ms'] for r in pre5])} ms, p95 <{max(r['lat_p95_ms'] for r in pre5) + 1:.0f} ms. "
      f"N>={n_sat}: queue grows without bound (median {sat_r['lat_median_ms'] / 1000:.1f} s at N={n_sat}).")
    A(f"- Health: IsolationForest "
      + ("never crosses" if not {"overheat", "battery_drain"} & set(if_cross) else "crosses (see JSON)")
      + f" its {an['threshold']} alert threshold on overheat or battery drain (AUROC {an['overheat']['auroc_vs_normal']:.2f} / {an['battery_drain']['auroc_vs_normal']:.2f}), "
        f"only partly on sensor inconsistency (AUROC {an['sensor_inconsistency']['auroc_vs_normal']:.2f}, {100 * an['sensor_inconsistency']['frac_over_thr']:.1f}% of windows > {an['threshold']}); rules do the detecting. "
        f"Forecaster: MAE {cc['mae_s']:.1f} s (overheat) / {bv['mae_s']:.1f} s (battery) over all windows, but median |err| {cc['median_abs_err_s']:.1f} / {bv['median_abs_err_s']:.1f} s "
        f"and MAE {cc['by_remaining']['0-5']['mae_s']:.1f} / {bv['by_remaining']['0-5']['mae_s']:.1f} s within 5 s of the threshold; early forecasts are strongly biased high "
        f"(bias +{cc['bias_s']:.1f} / +{bv['bias_s']:.1f} s).")
    A(f"- Cyber timeline: first alert {rng([p['first_alert_delay_s'] for p in ph], '{:.1f}')} s after burst onset for all {len(ph)} bursts, "
      f"risk >= 50 after {rng([p['risk_ge_50_delay_s'] for p in ph], '{:.1f}')} s, class correct {rng([pct_ok(p) for p in ph])}% of in-burst windows, "
      f"{quiet['false_class_windows_quiet']} non-normal windows and max risk {quiet['max_risk_quiet']} in {quiet['quiet_windows']} quiet windows, "
      f"recovery to risk <= 20 in {rng([p['recovery_to_risk_le_20_s'] for p in ph], '{:.1f}')} s after the burst.\n")
    A("---\n")

    # ------------------------------------------------------------------ Exp 1
    A("## Exp 1: tunnel/crypto microbenchmarks")
    A("- Files: `results/sys_microbench.json`, `tables/sys_microbench.tex`, `figures/sys_crypto_latency.{pdf,png}` (script `sys_01_microbench.py`).")
    A("- Caption draft: \"Per-message latency of AES-128-GCM seal and open versus plaintext size (median line, median-to-p95 band). "
      "Open markers are real batches, which cost more than same-sized synthetic payloads because JSON encoding/decoding dominates.\"")
    A(f"- Key numbers: handshake total median {hs['total']['median_us']:.1f} us / p95 {hs['total']['p95_us']:.1f} us "
      f"(server-side {hs['server_side']['median_us']:.1f} us, client-side {hs['client_side']['median_us']:.1f} us). "
      "Real batch medians (seal/open us): " + ", ".join(
          f"{k} {rb[k]['seal']['median_us']:.1f}/{rb[k]['open']['median_us']:.1f} ({rb[k]['payload_bytes_median']:.0f} B)" for k in ("normal", "dos", "fuzzy"))
      + f". AES-GCM alone ~{min(gcm):.0f}-{max(gcm):.0f} us; JSON encode {min(enc):.0f}-{max(enc):.0f} us, decode {min(dec):.0f}-{max(dec):.0f} us. "
      "Throughput seal+open: " + ", ".join(f"{k} {thr[k]['msgs_per_s'] / 1000:.1f}k msg/s" for k in ("normal", "dos", "fuzzy"))
      + f". Per-message overhead {ovh} B (observed constant for every message"
      + (f"; WebSocket client framing adds a further {wire_extra} B at these sizes, counted separately in Exp 3" if wire_extra is not None else "")
      + ").")
    A(f"- Method: handshake = ServerSession+ClientSession in one process, {MB['n_handshakes']} timed runs after warm-up. "
      f"Seal/open timed per message with `perf_counter_ns` on {nb['n']} real batches per scenario (generated by VirtualCar at {rate_hz} Hz) and on a synthetic size sweep "
      f"({sweep_lo} B-{sweep_hi // 1024} kB, {sweep_n} timed reps per size). Throughput = back-to-back seal+open of {thr['normal']['msgs']} messages. "
      "GCM-only cost measured by calling AESGCM directly.\n")

    # ------------------------------------------------------------------ Exp 2
    A("## Exp 2: security property tests")
    A("- Files: `results/sys_security.json`, `tables/sys_security.tex` (script `sys_02_security.py`).")
    A(f"- Caption draft: \"Tunnel security tests, {tpt} independent trials per attack; all malicious inputs are rejected and all benign ones accepted.\"")
    A(f"- Key numbers: benign {benign['accepted']}/{benign['trials']} accepted. "
      + ("All" if all_rej else "NOT all") + f" {len(attacks)} attack cases rejected {tpt}/{tpt} (rejection exception type in brackets; full counts in the JSON): "
      + "; ".join(f"{t['test']} [{'/'.join(t['outcomes'])}]" for t in attacks) + ".")
    A("- Method: every case calls `common.tunnel` directly (sessions in-process, random batches from the simulator, random bit positions/seq offsets, random device ids). "
      "Rate = share of trials with the expected outcome.\n")

    # ------------------------------------------------------------------ Exp 3
    A("## Exp 3: bandwidth")
    A("- Files: `results/sys_bandwidth.json`, `tables/sys_bandwidth.tex`, `figures/sys_bandwidth.{pdf,png}` (script `sys_03_bandwidth.py`).")
    A(f"- Caption draft: \"Uplink bandwidth at {rate_hz} Hz for raw CAN bits, naive per-frame JSON and the bounded batch in the AES-GCM envelope, for normal traffic and each attack: "
      "(a) injection rates measured on real HCRL as in the simulator, (b) nominal HCRL-paper injection rates; (c) distribution of packet sizes.\"")

    def pair(k):
        a, b = sc[k], sn[k]
        if k == "normal":
            return f"{bw_kb(sc, k):.1f} -> {bd_kb(sc, k):.1f} ({x(a['reduction_vs_raw_can'])})"
        if k in ("dos", "fuzzy", "rpm_spoof"):
            return (f"{bw_kb(sc, k):.1f} -> {bd_kb(sc, k):.1f} ({x(a['reduction_vs_raw_can'])}) / "
                    f"{bw_kb(sn, k):.1f} -> {bd_kb(sn, k):.1f} ({x(b['reduction_vs_raw_can'])})")
        return f"{x(a['reduction_vs_raw_can'])} / {x(b['reduction_vs_raw_can'])}"
    A("- Key numbers (kB/s raw CAN -> bounded batch, measured/nominal): " + "; ".join(
        f"{k.replace('_spoof', '') if k.endswith('_spoof') and k != 'rpm_spoof' else k} {pair(k)}" for k in SCEN)
      + f". Packet median {nb['wire_bytes_median']:.0f} B (normal), {sn['fuzzy']['batch_env_bytes']['median'] / 1000:.1f} kB (nominal fuzzy). "
        f"Naive per-frame JSON is {sc['normal']['naive_json_Bps'] / 1000:.0f} kB/s for normal traffic, so bounded batching is {x(sc['normal']['reduction_vs_naive_json'])} smaller there and "
        f"{x(sn['dos']['reduction_vs_naive_json'])} under nominal DoS.")
    A(f"- Method: VirtualCar (HCRL profile, fixed speed) for {BW['seconds_per_run']:.0f} s x {BW['repeats']} seeds per scenario, {BW['window_ms']} ms windows. "
      f"Raw bits = sum of `{BW['raw_bits_model']}` over all emitted frames / duration (the repo's model); naive JSON = compact JSON of every frame; bounded = real sealed packet size (`ts_ms` included). "
      f"Modes: measured = {BW['modes']['measured']}; nominal = {BW['modes']['nominal']}.\n")

    # ------------------------------------------------------------------ Exp 4
    A("## Exp 4: end-to-end latency")
    A("- Files: `results/sys_latency.json`, `tables/sys_latency.tex`, `tables/sys_ingest_latency.tex`, `figures/sys_alert_latency.{pdf,png}` (script `sys_04_latency.py`).")
    A(f"- Caption draft: \"Attack/fault onset to alert latency through the full stack (simulator REST toggle to alert on /ws/live), {LAT['n_trials']} trials per scenario: (a) CAN and tunnel attacks, (b) faults.\"")
    A(f"- (a) Ingest-to-broadcast (own sender -> server -> /ws/live, loopback, one device, same clock): normal median {st['normal']['median_ms']:.1f} ms / p95 {st['normal']['p95_ms']:.1f} / p99 {st['normal']['p99_ms']:.0f} "
      f"(n={st['normal']['n']}, {100 * st['normal']['fraction_over_100ms']:.1f}% > 100 ms); "
      + "; ".join(f"{k} {st[k]['median_ms']:.1f}/{st[k]['p95_ms']:.1f}/{st[k]['p99_ms']:.1f}" for k in ("dos", "fuzzy"))
      + f". Per-stage in-process medians for a normal batch: decrypt {stg['normal']['decrypt_ms']:.2f} ms, decode {stg['normal']['decode_ms']:.2f} ms, "
        f"**analytics {stg['normal']['analytics_ms']:.1f} ms**, JSON serialisation {stg['normal']['json_serialise_ms']:.2f} ms "
        f"(analytics is ~{100 * stg['normal']['analytics_ms'] / stg['normal']['total_ms']:.0f}% of server compute; the IsolationForest `score_samples` call dominates; "
        f"{stg['fuzzy']['analytics_ms']:.1f} ms under fuzzy where the health vector is unavailable).")
    A("- (b) Onset-to-alert (median / p95, " + det_txt + "): "
      + ", ".join(f"{k} {med(k):.0f}/{p95(k):.0f}" for k in att_cats + tun_cats + ("sensor_inconsistency",))
      + f" ms; overheat {med('overheat') / 1000:.1f} s / {p95('overheat') / 1000:.1f} s; battery_drain {med('battery_drain') / 1000:.1f} s / {p95('battery_drain') / 1000:.1f} s. "
        f"Time until `attack_class` leaves normal equals the alert time for CAN attacks (medians within {cls_gap:.1f} ms) and is later for tunnel events "
        f"(replay {onset['replay']['class_ms_summary']['median']:.0f} ms, tamper {onset['tamper']['class_ms_summary']['median']:.0f} ms). "
        f"Tamper is slow ({med('tamper'):.0f} ms vs replay {med('replay'):.0f} ms) because the simulator tampers only a subset of packets, so the first tampered packet arrives later. "
        + ("For overheat and battery the first alert is the threshold alert" if fault_thr_is_alert else "For overheat and battery the first alert differs from the threshold alert (see JSON)")
        + ("; the forecast alert did not come earlier in these runs." if not fault_forecast_seen else "; a forecast alert was also seen in some runs (see JSON)."))
    A(f"- Method: real `server.app.main` and `simulator` subprocesses (local ports, temp DB). (a) sender is a `ClientSession` on a real WebSocket, packets matched to broadcasts by the per-device `packets_ok` counter, "
      f"both timestamps from `perf_counter_ns` in one process. (b) an async `/ws/live` client records alerts; onset = time just before the REST POST (includes the REST round trip, median {rtts_med:.1f} ms, max {max(rtts):.1f} ms); "
      "each trial waits for health >= 85 and risk <= 20 plus the per-category alert cooldown before toggling.\n")

    # ------------------------------------------------------------------ Exp 5
    A("## Exp 5: server scalability")
    A("- Files: `results/sys_scalability.json`, `tables/sys_scalability.tex`, `figures/sys_scalability.{pdf,png}` (script `sys_05_scalability.py`).")
    A(f"- Caption draft: \"Server load versus number of simulated devices streaming at {SC['rate_hz']} Hz: (a) CPU as a percentage of one core, (b) CPU time per packet, "
      f"(c) ingest-to-broadcast latency (log scale, dashed line = one {BW['window_ms']} ms window). The single-process server saturates near {cap_dev:.0f} devices.\"")

    def srow(n):
        r = nrm[n]
        s = f"N={n}: {r['server_cpu_pct_one_core']:.0f}% CPU, median {ms_s(r['lat_median_ms'])}"
        if r["lat_median_ms"] < 1000:
            s += f", p95 {r['lat_p95_ms']:.0f} ms"
            if n >= 5:
                s += f", {100 * r['late_fraction_over_100ms']:.1f}% late"
        else:
            s += " (queue grows)" if n == n_sat else ""
        return s
    shown = [n for n in ns if n in (1, 2, 5, n_sat)]
    tail = [n for n in ns if n > n_sat]
    A(f"- Key numbers (normal traffic; dos is the same within noise): " + "; ".join(srow(n) for n in shown)
      + "; N=" + "/".join(str(n) for n in tail) + f": ~{rng([nrm[n]['server_cpu_pct_one_core'] for n in tail] + [dosr[n]['server_cpu_pct_one_core'] for n in tail])}% CPU, medians "
      + " / ".join(ms_s(nrm[n]['lat_median_ms']) for n in tail)
      + f". CPU per processed packet {rng([r['server_ms_cpu_per_packet'] for r in ok_rows], '{:.1f}')} ms for N<={max(r['n_devices'] for r in ok_rows)} (so capacity ~{cap_pps:.0f} packets/s ~ {cap_dev:.0f} devices); "
        f"RSS {rng([r['server_rss_mb'] for r in allrows])} MB. "
      + ("No packets rejected. " if rejected_total == 0 else f"{rejected_total} packets rejected. ")
      + f"Late (>{late_thr_s:.0f} ms) {rng([100 * r['late_fraction_over_100ms'] for r in pre5], '{:.1f}')}% up to N={max(r['n_devices'] for r in pre5)}, "
        f"{100 * min(r['late_fraction_over_100ms'] for r in allrows if r['n_devices'] >= n_sat):.0f}% from N={n_sat}.")
    A(f"- Method: one server subprocess; devices 2..{n_last} registered via POST /api/vehicles (real PSKs); N async `ClientSession` senders in one harness process at {SC['rate_hz']} Hz from pre-generated normal or dos batches, "
      f"plus one /ws/live client. CPU from `psutil` process CPU time over the {SC['duration_s']:.0f} s window ({SC['duration_s_for_n_gt_10']:.0f} s for N>10). "
      "Latency matched via `packets_ok` as in Exp 4. After sending the harness waits (bounded) for the server to drain.\n")

    # ------------------------------------------------------------------ Exp 6
    A("## Exp 6: health analytics (simulator only)")
    A("- Files: `results/sys_health.json`, figures `sys_health_timeseries`, `sys_forecast_accuracy`, `sys_anomaly_hist`; tables `sys_forecast.tex`, `sys_anomaly.tex` (script `sys_06_health.py`).")
    A(f"- Captions: \"Signal, component health, overall health and IsolationForest score for each injected fault (shaded = fault active, dots = alerts).\" / "
      f"\"Forecast ETA vs actual time to threshold, {cc['n_trials']} trials per signal ({cc['nominal']['n_trials']} nominal, {cc['randomised_rate']['n_trials']} with randomised fault slope).\" / "
      "\"IsolationForest anomaly score distribution, normal driving vs each fault.\"")
    A(f"- Key numbers: first alerts after fault onset (fault on at {ts['overheat']['fault_on_s']} s, off at {ts['overheat']['fault_off_s']} s): "
      f"overheat {fa('overheat', 'overheat'):.1f} s later, battery {fa('battery_drain', 'low_battery'):.1f} s later (`low_battery`; `forecast_battery` at {fa('battery_drain', 'forecast_battery'):.1f} s), "
      f"sensor_inconsistency {fa('sensor_inconsistency', 'sensor_inconsistency'):.1f} s. "
      f"Overall health drops to {ts['overheat']['min_overall_health']} (overheat), {ts['battery_drain']['min_overall_health']} (battery) and {ts['sensor_inconsistency']['min_overall_health']} (sensor) "
      f"and is back at {ts['overheat']['overall_health_end']} at the end of the run. "
      f"Forecaster: overheat MAE {cc['mae_s']:.1f} s, median |err| {cc['median_abs_err_s']:.1f} s, bias {cc['bias_s']:+.1f} s; battery MAE {bv['mae_s']:.1f} s, median {bv['median_abs_err_s']:.1f} s, bias {bv['bias_s']:+.1f} s. "
      "Error by remaining time (overheat): " + ", ".join(f"{cc['by_remaining'][b]['mae_s']:.1f} s MAE at {b} s" for b in ("0-5", "5-10", "10-20"))
      + f". First-forecast MAE is {cc['first_forecast_mae_s']:.0f} s / {bv['first_forecast_mae_s']:.0f} s (the fit window still contains pre-fault flat data, so the first estimates are very high). "
        f"Forecast alert lead before the real threshold crossing: median {cc['forecast_alert_lead_median_s']:.1f} s (overheat) / {bv['forecast_alert_lead_median_s']:.1f} s (battery), "
        f"vs {cc['threshold_alert_lead_median_s']:.1f} / {bv['threshold_alert_lead_median_s']:.1f} s for the threshold alert, i.e. the forecast gives {lead_gain[0]:.1f} / {lead_gain[1]:.1f} s earlier warning "
        f"in {cc['trials_with_forecast_alert']}/{cc['n_trials']} and {bv['trials_with_forecast_alert']}/{bv['n_trials']} trials. "
        f"IsolationForest: normal median {an['normal']['median']:.2f}, p99 {an['normal']['p99']:.2f}; overheat median {an['overheat']['median']:.2f} (AUROC {an['overheat']['auroc_vs_normal']:.2f}), "
        f"battery {an['battery_drain']['median']:.2f} (AUROC {an['battery_drain']['auroc_vs_normal']:.2f}), sensor_inconsistency {an['sensor_inconsistency']['median']:.2f} "
        f"(AUROC {an['sensor_inconsistency']['auroc_vs_normal']:.2f}, {100 * an['sensor_inconsistency']['frac_over_thr']:.1f}% of windows above {an['threshold']}); "
        + ("none of the faults is detected by the IF at the " + f"{an['threshold']} threshold in practice." if set(if_cross) <= {"sensor_inconsistency"} else "see JSON for IF threshold crossings."))
    A(f"- Method: VirtualCar + VehicleAnalyzer driven in simulated time ({BW['window_ms']} ms windows, same decode path as the server); models from `server/models`. "
      f"Forecast trials use random start values/seeds; half use a harness-only subclass that scales the fault slope ({fc['conditions'].split('scaled ')[1].split(' (')[0]}). "
      "Actual time-to-threshold from the car's noise-free true state.\n")

    # ------------------------------------------------------------------ Exp 7
    A("## Exp 7: cyber-risk time series")
    A("- Files: `results/sys_cyber_timeline.json`, `tables/sys_cyber_timeline.tex`, `figures/sys_cyber_timeline.{pdf,png}` (script `sys_07_cyber_timeline.py`).")
    A(f"- Caption draft: \"{t_end:.0f} s scripted scenario: cyber risk (top) and attack class (bottom) through {ph_txt} bursts; markers show alerts.\"")
    A(f"- Key numbers: first alert delay {slash('first_alert_delay_s', '{:.1f}')} s, risk >= 50 after {slash('risk_ge_50_delay_s', '{:.1f}')} s, "
      f"peak risk {slash('peak_risk', '{:.0f}')}, class correct in {' / '.join(f'{pct_ok(p):.1f}' for p in ph)}% of burst windows, "
      f"recovery to risk <= 20 in {slash('recovery_to_risk_le_20_s', '{:.1f}')} s. Quiet periods: {quiet['quiet_windows']} windows, max risk {quiet['max_risk_quiet']}, "
      f"{quiet['false_class_windows_quiet']} non-normal classes. Alert delay over {nseeds} other seeds: "
      + ", ".join(f"{k} {rng(v, '{:.1f}')} s" for k, v in seeds.items()) + " (all values in the JSON).")
    A("- Method: VehicleAnalyzer with the server's RF/IF models, VirtualCar at fixed speed, tamper bursts as `record_tunnel_event(\"tamper\", t)` at a fixed interval. "
      "This is analyzer-side time (no network).\n")
    A("---\n")

    # ------------------------------------------------------------------ Threats
    A("## Threats to validity")
    T = [
        "**Simulated everything**: car, product module and \"attacks\" are the repo's simulator (HCRL-derived rates/payloads), not real hardware, a real CAN bus or real traffic. "
        "Attack detection times are for these generated attacks and one car profile. Health faults are linear ramps with fixed slopes and have no real labelled data.",
        f"**Same machine, loopback**: server, simulator and harness share one {cores}-core laptop, no real Wi-Fi/Internet latency, no TLS/NAT; Windows timer granularity shows up in sender jitter "
        f"and the {floor_lo:.0f}-{floor_hi:.0f} ms minimum ingest-to-broadcast latency. A demo server was running on the same machine. "
        f"The harness itself used {min(harness):.0f}-{max(harness):.0f}% of a core.",
        f"**Onset timing** includes the REST round trip (median {rtts_med:.1f} ms) and the car's own tick and {BW['window_ms']} ms batching; the alert debounce forced waits between trials, "
        "so trials are not fully independent (same car state, same seed family).",
        f"**Bandwidth model**: raw CAN bits use the repo's approximate `{BW['raw_bits_model']}` (no interframe space). Raw CAN rates come from the simulator's emission model "
        f"(measured-HCRL mode leaves total bus traffic LOWER under DoS/fuzzy because legitimate frames are crowded out). The nominal mode exceeds the physical {BW['bitrate'] // 1000} kbps bus "
        f"(dos {sn['dos']['bus_load_pct_formula']:.0f}% of capacity) and is an upper bound, not a feasible bus state. Bounded-batch size grows with the number of distinct IDs; "
        f"it is bounded (<= ~{BW['worst_case_packet_bytes_all_2048_ids'] / 1000:.0f} kB for all 2048 IDs) but not small under fuzzing.",
        f"**Scalability** measures a single-process server with an ML scoring step costing {ms_pkt:.0f} ms/packet; the limit (~{cap_dev:.0f} devices/core) is an implementation property "
        "(sklearn per-packet call), not of the protocol. Senders are async tasks in one process; backpressure from the server throttles them at saturation, so \"unprocessed at end\" "
        + (f"and the CPU-per-packet values for {', '.join(affected)} " if affected else "")
        + f"are affected by the drain-wait heuristic (the harness stops waiting once the server stops making progress) and are not reliable; use CPU% and the N<={max(r['n_devices'] for r in ok_rows)} rows. "
        "Latency at saturation is queueing delay that grows with test length, not a steady-state value.",
        "**Forecast and IF evaluation** share the simulator that generated both the models' training data and the test faults (the IF was trained on `ml_training` simulator data; "
        "its poor overheat/battery sensitivity is likely because those faults stay inside its training range for most of the ramp). "
        "The forecaster is evaluated against the same linear ramps it assumes; the randomised slope condition is a harness-only modification of the stock physics.",
        f"**Security tests** exercise the protocol logic in-process over crafted messages; they do not cover side channels, timing attacks, PSK compromise, key rotation, DoS against the handshake, "
        f"or WebSocket/TLS-layer issues. A 100% rate over {tpt} trials bounds the failure probability only at roughly <{r3:.1f}% (95%), and tag forgery probability is a cryptographic property of GCM that is not measured here.",
        "**Microbenchmarks** are CPython on x86 with AES-NI; an ESP32 will be orders of magnitude slower per message. Results are not a firmware estimate.",
        f"**Sample sizes**: {LAT['n_trials']} trials per onset-latency scenario (fine for medians, weak for p95 tails), {BW['repeats']} seeds x {BW['seconds_per_run']:.0f} s for bandwidth, "
        f"{cc['n_trials']} forecast trials per signal.",
    ]
    for i, t in enumerate(T, 1):
        A(f"{i}. {t}")

    out = RES / "sys_SUMMARY.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    print("wrote", out)


if __name__ == "__main__":
    main()
