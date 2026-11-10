"""End-to-end check: server + 2 virtual cars, trigger every fault/attack, assert alert + score move + recovery.

    python tools/e2e_demo.py            # starts its own server (:8765) and simulator (:8766) with a temp DB
    python tools/e2e_demo.py --only dos,replay
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
SRV_PORT, SIM_PORT = 8765, 8766
SRV = f"http://127.0.0.1:{SRV_PORT}"
SIM = f"http://127.0.0.1:{SIM_PORT}"
DEV = 1

# name: (sim route, toggle key, expected alert categories (any), kind, timeout_s)
SCENARIOS = [
    ("sensor_inconsistency", "faults", "sensor_inconsistency", {"sensor_inconsistency"}, "mech", 15),
    ("overheat", "faults", "overheat", {"overheat", "forecast_overheat"}, "mech", 40),
    ("battery_drain", "faults", "battery_drain", {"low_battery", "forecast_battery"}, "mech", 45),
    ("dos", "attacks", "dos", {"dos"}, "cyber", 15),
    ("fuzzy", "attacks", "fuzzy", {"fuzzy"}, "cyber", 15),
    ("rpm_spoof", "attacks", "rpm_spoof", {"spoofing_rpm"}, "cyber", 15),
    ("gear_spoof", "attacks", "gear_spoof", {"spoofing_gear"}, "cyber", 15),
    ("steering_spoof", "attacks", "steering_spoof", {"spoofing_steering"}, "cyber", 15),
    ("replay", "tunnel", "replay", {"replay"}, "cyber", 15),
    ("tamper", "tunnel", "tamper", {"tamper"}, "cyber", 15),
    ("wrong_key", "tunnel", "wrong_key", {"auth_fail"}, "cyber", 20),
]


def status(c: httpx.Client) -> dict:
    return c.get(f"{SRV}/api/status").json()["devices"][str(DEV)]


def max_alert_id(c: httpx.Client) -> int:
    a = c.get(f"{SRV}/api/alerts", params={"device_id": DEV, "limit": 1}).json()
    return a[0]["id"] if a else 0


def new_categories(c: httpx.Client, after: int) -> set[str]:
    a = c.get(f"{SRV}/api/alerts", params={"device_id": DEV, "limit": 200}).json()
    return {x["category"] for x in a if x["id"] > after}


def wait(pred, timeout: float, every: float = 0.5):
    end = time.time() + timeout
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(every)
    return None


def healthy(s: dict) -> bool:
    return (s.get("health") or 0) >= 85 and (s.get("cyber_risk") or 0) <= 20


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    args = ap.parse_args()
    only = set(filter(None, args.only.split(",")))

    tmp = tempfile.mkdtemp()
    env = dict(os.environ, TELEMETRY_DB_PATH=str(Path(tmp) / "e2e.db"), TELEMETRY_HTTP_PORT=str(SRV_PORT),
               TELEMETRY_HTTP_HOST="127.0.0.1", PYTHONPATH=str(ROOT))
    logs = Path(tmp)
    srv = subprocess.Popen([sys.executable, "-m", "server.app.main"], cwd=ROOT, env=env,
                           stdout=open(logs / "server.log", "w"), stderr=subprocess.STDOUT)
    sim = subprocess.Popen([sys.executable, "-m", "simulator", "--server", f"ws://127.0.0.1:{SRV_PORT}/ws/ingest",
                            "--port", str(SIM_PORT), "--cars", "1"], cwd=ROOT, env=env,
                           stdout=open(logs / "sim.log", "w"), stderr=subprocess.STDOUT)
    results: list[tuple[str, bool, str]] = []
    try:
        with httpx.Client(timeout=5) as c:
            up = wait(lambda: _try(lambda: c.get(f"{SRV}/api/status").status_code == 200
                                   and c.get(f"{SIM}/api/cars").status_code == 200), 30)
            assert up, "server/simulator did not start (logs in %s)" % logs
            print("analyzer:", c.get(f"{SRV}/api/status").json().get("analyzer"))
            c.post(f"{SIM}/api/cars/{DEV}/controls", json={"speed_kmh": 60, "throttle_pct": 20})
            ok = wait(lambda: status(c)["connected"] and status(c)["packets_ok"] > 20, 30)
            results.append(("bench car streaming", bool(ok), str(status(c))))
            # portal: register a second car (any brand) -> PSK returned once, shows as not streaming
            r = c.post(f"{SRV}/api/vehicles", json={"name": "Family Swift", "brand": "Maruti Suzuki",
                                                    "model": "Swift", "plate": "KL-07-AB-1234"})
            body = r.json() if r.status_code < 300 else {}
            new_id = body.get("device_id") or (body.get("vehicle") or {}).get("device_id")
            listed = [v for v in c.get(f"{SRV}/api/vehicles").json() if v.get("device_id") == new_id]
            reg_ok = (r.status_code in (200, 201) and "psk_hex" in str(body) and listed
                      and "psk_hex" not in listed[0]
                      and not c.get(f"{SRV}/api/status").json()["devices"][str(new_id)]["connected"])
            results.append(("portal add-car (PSK once, offline)", bool(reg_ok), f"{r.status_code} {body} {listed}"))
            base = wait(lambda: _ok(status(c), healthy), 30)
            results.append(("baseline healthy", bool(base), str(status(c))))

            for name, route, key, cats, kind, tmo in SCENARIOS:
                if only and name not in only:
                    continue
                before = max_alert_id(c)
                c.post(f"{SIM}/api/cars/{DEV}/{route}", json={key: True})
                got = wait(lambda: new_categories(c, before) & cats, tmo)
                if kind == "mech":
                    moved = wait(lambda: (status(c).get("health") or 100) < 85, tmo)
                else:
                    moved = wait(lambda: (status(c).get("cyber_risk") or 0) >= 30, tmo)
                s_peak = status(c)
                c.post(f"{SIM}/api/cars/{DEV}/{route}", json={key: False})
                rec = wait(lambda: _ok(status(c), healthy), 45)
                detail = (f"alerts={sorted(new_categories(c, before))} peak(health={s_peak.get('health')}, "
                          f"cyber={s_peak.get('cyber_risk')}, class={s_peak.get('attack_class')}) "
                          f"recovered={status(c).get('health')}/{status(c).get('cyber_risk')}")
                passed = bool(got) and bool(moved) and bool(rec)
                results.append((name, passed, detail))
                print(("PASS " if passed else "FAIL ") + name + "  " + detail, flush=True)
    finally:
        for p in (sim, srv):
            p.terminate()
        for p in (sim, srv):
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()

    print("\n==== E2E summary ====")
    for n, p, d in results:
        print(f"{'PASS' if p else 'FAIL'}  {n}" + ("" if p else f"   {d}"))
    print("logs:", logs)
    return 0 if all(p for _, p, _ in results) else 1


def _try(f):
    try:
        return f()
    except Exception:
        return False


def _ok(s, f):
    return s if f(s) else None


if __name__ == "__main__":
    sys.exit(main())
