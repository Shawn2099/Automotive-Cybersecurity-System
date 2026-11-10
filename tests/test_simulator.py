"""Simulator tests: VirtualProductModule against a fake tunnel server + REST API."""

from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient
from websockets.asyncio.server import serve

from common.can_profiles import decode_can_frames
from common.crypto import PacketCryptoError, ReplayError
from common.tunnel import HandshakeError, ServerSession
from simulator.controller import CarRuntime, Simulator, create_app

PSK = bytes.fromhex("00112233445566778899aabbccddeeff")


async def run_case(duration: float, setup=None, midway=None, mid_at: float = 0.0, runtime_kw=None):
    res = {"batches": [], "errors": [], "handshake_errors": [], "handshakes_ok": 0}

    async def handler(ws):
        ss = ServerSession(lambda d: PSK if d == 1 else None)
        await ws.send(ss.challenge())
        try:
            welcome = ss.handle_hello(await ws.recv())
        except HandshakeError as exc:
            res["handshake_errors"].append(exc)
            await ws.send(ss.reject(str(exc)))
            await ws.close()
            return
        await ws.send(welcome)
        res["handshakes_ok"] += 1
        try:
            async for msg in ws:
                try:
                    res["batches"].append(ss.open_data(msg))
                except PacketCryptoError as exc:  # includes ReplayError
                    res["errors"].append(exc)
        except Exception:
            pass

    async with serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        rt = CarRuntime(1, "T", "hyundai_sonata_hcrl", PSK, f"ws://127.0.0.1:{port}",
                        wrong_key_retry_s=0.3, **(runtime_kw or {}))
        if setup:
            setup(rt)
        rt.start()
        if midway:
            await asyncio.sleep(mid_at)
            midway(rt)
            await asyncio.sleep(duration - mid_at)
        else:
            await asyncio.sleep(duration)
        await rt.stop()
        res["rt"] = rt
    return res


def test_batches_decrypt_and_counts():
    res = asyncio.run(run_case(1.5))
    batches = [e.payload for e in res["batches"]]
    assert len(batches) >= 8
    assert not res["errors"]
    prof = "hyundai_sonata_hcrl"
    assert all(b["window_ms"] == 100 and "ts_ms" in b for b in batches)
    assert [e.seq_num for e in res["batches"]] == sorted(e.seq_num for e in res["batches"])
    total_pt = sum(b["counts"].get("790", 0) for b in batches)  # 0x316 EMS11
    secs = len(batches) * 0.1
    assert 0.5 * secs * 100 <= total_pt <= 1.6 * secs * 100  # profile period 10 ms
    dec = decode_can_frames(prof, [f for b in batches for f in b["frames"]])
    assert dec["unknown_ids"] == [] and {"speed_kmh", "rpm", "coolant_c", "battery_v"} <= set(dec["signals"])
    assert res["rt"].module.stats["packets_sent"] >= 8


def test_dos_inflates_counts():
    res = asyncio.run(run_case(1.0, setup=lambda rt: rt.car.attacks.add("dos")))
    assert max(e.payload["counts"].get("0", 0) for e in res["batches"]) >= 25  # HCRL-measured DoS ~340 frames/s


def test_fuzzy_many_distinct_ids_and_spoof_counts():
    res = asyncio.run(run_case(1.0, setup=lambda rt: rt.car.attacks.update({"fuzzy", "rpm_spoof"})))
    assert max(len(e.payload["counts"]) for e in res["batches"]) > 40  # 31 profile IDs + random fuzz IDs (~220/s)
    assert max(e.payload["counts"].get("790", 0) for e in res["batches"]) >= 50  # 0x316 flooded


def test_attack_burst_turns_off():
    async def go():
        rt = CarRuntime(1, "T", "hyundai_sonata_hcrl", PSK, "ws://127.0.0.1:1/ws/ingest")
        rt.burst("dos", 0.2)
        await asyncio.sleep(0.05)
        on = "dos" in rt.car.attacks
        await asyncio.sleep(0.4)
        return on, "dos" in rt.car.attacks
    assert asyncio.run(go()) == (True, False)


def test_replay_causes_replay_error():
    res = asyncio.run(run_case(2.6, setup=lambda rt: rt.module.tunnel.update(replay=True)))
    assert any(isinstance(e, ReplayError) for e in res["errors"])
    assert res["rt"].module.stats["replays_sent"] >= 1


def test_tamper_causes_crypto_error():
    res = asyncio.run(run_case(1.5, setup=lambda rt: rt.module.tunnel.update(tamper=True)))
    errs = [e for e in res["errors"] if not isinstance(e, ReplayError)]
    assert errs and res["batches"]


def test_wrong_key_rejected_then_recovers():
    def fix(rt):
        rt.module.tunnel["wrong_key"] = False

    res = asyncio.run(
        run_case(2.5, setup=lambda rt: rt.module.tunnel.update(wrong_key=True), midway=fix, mid_at=1.0)
    )
    assert res["handshake_errors"] and isinstance(res["handshake_errors"][0], HandshakeError)
    assert res["rt"].module.stats["handshake_failures"] >= 1
    assert res["handshakes_ok"] >= 1 and res["batches"]


def test_default_simulator_is_single_bench_car(monkeypatch):
    monkeypatch.delenv("PSK_DEVICE_1", raising=False)
    sim = Simulator("ws://127.0.0.1:1/ws/ingest")
    assert list(sim.cars) == [1]
    c = sim.cars[1]
    assert (c.name, c.profile_id) == ("Bench Car (ESP32)", "hyundai_sonata_hcrl")
    assert c.module.psk == PSK


def test_extra_cars_use_env_psk(monkeypatch):
    monkeypatch.setenv("PSK_DEVICE_3", "ab" * 16)
    sim = Simulator("ws://127.0.0.1:1/ws/ingest", [1, 3])
    assert sim.cars[3].module.psk == bytes.fromhex("ab" * 16)
    assert sim.cars[3].profile_id == "hyundai_sonata_hcrl"


def test_rest_api_controls():
    sim = Simulator("ws://127.0.0.1:1/ws/ingest", [1, 2])
    client = TestClient(create_app(sim, autostart=False))
    cars = client.get("/api/cars").json()
    assert [c["device_id"] for c in cars] == [1, 2]
    assert "fuel_pct" not in cars[0]["controls"] and "fuel_pct" not in cars[0]["state"]

    r = client.post("/api/cars/1/controls", json={"speed_kmh": 300, "steering_deg": -100, "auto_rpm": False, "rpm": 3000})
    assert r.status_code == 200
    assert r.json()["controls"]["speed_kmh"] == 200  # clamped
    car = sim.cars[1].car
    for _ in range(400):
        car.step(0.05)
    assert car.state()["speed_kmh"] > 150 and car.state()["steering_deg"] < -90

    assert client.post("/api/cars/1/controls", json={"bogus": 1}).status_code == 400
    assert client.post("/api/cars/1/controls", json={"fuel_pct": 50}).status_code == 400
    assert client.post("/api/cars/9/controls", json={"speed_kmh": 1}).status_code == 404

    j = client.post("/api/cars/1/faults", json={"overheat": True}).json()
    assert j["faults"] == ["overheat"]
    assert client.post("/api/cars/1/faults", json={"overheat": False}).json()["faults"] == []
    assert client.post("/api/cars/2/attacks", json={"dos": True, "steering_spoof": True}).json()["attacks"] == ["dos", "steering_spoof"]
    all_atk = {a: True for a in ["dos", "fuzzy", "rpm_spoof", "gear_spoof", "steering_spoof"]}
    assert sorted(client.post("/api/cars/1/attacks", json=all_atk).json()["attacks"]) == sorted(all_atk)
    assert client.post("/api/cars/1/attacks", json={"unknown_id": True}).status_code == 400
    assert client.post("/api/cars/2/tunnel", json={"replay": True}).json()["tunnel"]["replay"] is True
    assert sim.cars[2].module.tunnel["replay"] is True
    assert client.post("/api/cars/1/faults", json={"nope": True}).status_code == 400
    assert client.post("/api/cars/1/preset", json={"name": "highway"}).json()["controls"]["speed_kmh"] == 110
    assert client.post("/api/cars/1/burst", json={"attack": "nope"}).status_code == 400
    assert client.get("/").status_code == 200


def test_frame_rate_normal_and_dos():
    """Normal rate matches the profile schedule (HCRL-measured ~2100 fps); summarising stays bounded."""
    from common.vehicle_sim import VirtualCar, summarize_window
    car = VirtualCar("hyundai_sonata_hcrl", seed=1)
    expected = car.profile.expected_total_hz
    n = sum(len(car.step(0.02)) for _ in range(100))  # 2 s
    assert 0.9 * expected <= n / 2 <= 1.1 * expected
    car.attacks.update({"dos", "fuzzy", "rpm_spoof", "gear_spoof", "steering_spoof"})
    frames = [f for _ in range(5) for f in car.step(0.02)]  # 0.1 s of everything at once
    b = summarize_window(frames, 100)
    assert len(b["frames"]) <= 260 and b["counts"]["0"] >= 25
