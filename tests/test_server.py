import os
import tempfile

os.environ.setdefault("TELEMETRY_DB_PATH", os.path.join(tempfile.mkdtemp(), "import.db"))

import pytest
from fastapi.testclient import TestClient

from common.tunnel import ClientSession, HandshakeError
from common.vehicle_sim import VirtualCar, summarize_window
from server.app.main import StubAnalyzer, create_app

PSK1 = bytes.fromhex("00112233445566778899aabbccddeeff")


@pytest.fixture()
def client(tmp_path):
    app = create_app(tmp_path / "t.db", analyzer_factory=lambda pid: StubAnalyzer(pid))
    with TestClient(app) as c:
        yield c


def make_batch(car, ts):
    frames = car.step(0.1)
    b = summarize_window(frames, 100)
    b["ts_ms"] = ts
    return b


def connect(ws, device_id=1, psk=PSK1):
    cs = ClientSession(device_id, psk)
    ws.send_bytes(cs.handle_challenge(ws.receive_bytes()))
    cs.handle_welcome(ws.receive_bytes())
    return cs


def test_seed_and_crud(client):
    vs = client.get("/api/vehicles").json()
    assert len(vs) == 1
    v = vs[0]
    assert (v["device_id"], v["name"], v["brand"], v["model"], v["plate"], v["can_profile"]) == (
        1, "Bench Car (ESP32)", "Hyundai", "YF Sonata (HCRL spec)", "BENCH-01", "hyundai_sonata_hcrl")
    assert "psk_hex" not in v and v["status"] == "awaiting_device"
    body = dict(device_id=7, name="Test", brand="Tata", model="Nexon", plate="X",
                can_profile="hyundai_sonata_hcrl", psk_hex="ab" * 16)
    assert client.post("/api/vehicles", json=body).status_code == 201
    assert client.post("/api/vehicles", json=body).status_code == 409
    assert client.post("/api/vehicles", json={**body, "device_id": 8, "can_profile": "nope"}).status_code == 422
    assert client.post("/api/vehicles", json={**body, "device_id": 8, "psk_hex": "zz"}).status_code == 422
    assert client.post("/api/vehicles", json={k: x for k, x in body.items() if k != "plate"}).status_code == 422
    assert len(client.get("/api/vehicles").json()) == 2
    assert client.delete("/api/vehicles/7").status_code == 200
    assert client.delete("/api/vehicles/7").status_code == 404
    assert client.get("/").status_code == 200
    assert client.get("/static/app.js").status_code == 200


def test_add_car_autoid_generated_psk_once(client):
    base = dict(name="Daily Swift", brand="Maruti Suzuki", model="Swift", plate="KL-07-AB-1234")
    r = client.post("/api/vehicles", json=base, headers={"host": "example.test:8123"})
    assert r.status_code == 201
    j = r.json()
    assert j["device_id"] == 2  # next free after the seeded car
    assert j["can_profile"] == "unassigned" and j["status"] == "awaiting_device"
    assert len(j["psk_hex"]) == 32 and int(j["psk_hex"], 16) >= 0
    prov = j["provisioning"]
    assert prov["device_id"] == 2 and prov["psk_hex"] == j["psk_hex"]
    assert prov["ingest_url"] == "ws://example.test:8123/ws/ingest"
    # the PSK is never returned again
    for v in client.get("/api/vehicles").json():
        assert "psk_hex" not in v
    assert "psk_hex" not in client.patch("/api/vehicles/2", json={"name": "x"}).json()
    r2 = client.post("/api/vehicles", json={**base, "can_profile": "none"}).json()
    assert r2["device_id"] == 3 and r2["can_profile"] == "unassigned" and r2["psk_hex"] != j["psk_hex"]
    # the generated PSK really authenticates the new device
    with client.websocket_connect("/ws/ingest") as ws:
        connect(ws, 2, bytes.fromhex(j["psk_hex"]))
    assert client.get("/api/vehicles").json()[1]["last_seen_at"]
    # rotate-key: new PSK shown once, old one stops working
    rk = client.post("/api/vehicles/2/rotate-key").json()
    assert rk["device_id"] == 2 and rk["psk_hex"] != j["psk_hex"] and len(rk["psk_hex"]) == 32
    with client.websocket_connect("/ws/ingest") as ws:
        cs = ClientSession(2, bytes.fromhex(j["psk_hex"]))
        ws.send_bytes(cs.handle_challenge(ws.receive_bytes()))
        with pytest.raises(HandshakeError):
            cs.handle_welcome(ws.receive_bytes())
    with client.websocket_connect("/ws/ingest") as ws:
        connect(ws, 2, bytes.fromhex(rk["psk_hex"]))
    assert client.post("/api/vehicles/99/rotate-key").status_code == 404


def test_patch_vehicle(client):
    j = client.post("/api/vehicles", json=dict(name="A", brand="B", model="C", plate="P")).json()
    did = j["device_id"]
    r = client.patch(f"/api/vehicles/{did}", json={"name": "Renamed", "plate": "NEW-1",
                                                    "can_profile": "hyundai_sonata_hcrl"})
    assert r.status_code == 200
    assert (r.json()["name"], r.json()["plate"], r.json()["can_profile"]) == ("Renamed", "NEW-1", "hyundai_sonata_hcrl")
    assert r.json()["profile_supported"] is True
    assert client.patch(f"/api/vehicles/{did}", json={"can_profile": "none"}).json()["can_profile"] == "unassigned"
    assert client.patch(f"/api/vehicles/{did}", json={"can_profile": "bogus"}).status_code == 422
    assert client.patch(f"/api/vehicles/{did}", json={"name": ""}).status_code == 422
    assert client.patch("/api/vehicles/99", json={"name": "x"}).status_code == 404
    # brand/model untouched by a partial patch
    v = [x for x in client.get("/api/vehicles").json() if x["device_id"] == did][0]
    assert (v["brand"], v["model"], v["can_profile"]) == ("B", "C", "unassigned")


def test_profiles_shape(client):
    ps = client.get("/api/profiles").json()
    p = {x["profile_id"]: x for x in ps}["hyundai_sonata_hcrl"]
    assert {"profile_id", "brand", "model", "description", "messages"} <= set(p)
    assert p["brand"] == "Hyundai"
    m = {x["name"]: x for x in p["messages"]}
    assert m["EMS11"]["id"] == 790 and m["EMS11"]["id_hex"] == "0x316"
    assert {"rpm", "speed_kmh"} <= set(m["EMS11"]["signals"])
    assert not any(x["profile_id"].startswith("sim_") for x in ps)


def _unsupported_send(client, did, psk):
    car = VirtualCar("hyundai_sonata_hcrl", seed=3)
    with client.websocket_connect("/ws/ingest") as ws:
        cs = connect(ws, did, psk)
        for i in range(3):
            ws.send_bytes(cs.seal(make_batch(car, 100 * i)))
        bad = bytearray(cs.seal(make_batch(car, 400)))
        bad[-3] ^= 0xFF
        ws.send_bytes(bytes(bad))  # tunnel event on an unsupported car must not crash either
        ws.send_bytes(cs.seal(make_batch(car, 500)))
        st = client.get("/api/status").json()["devices"][str(did)]
    return st


def test_unassigned_profile_device_does_not_crash(client):
    j = client.post("/api/vehicles", json=dict(name="N", brand="B", model="M", plate="P")).json()
    st = _unsupported_send(client, j["device_id"], bytes.fromhex(j["psk_hex"]))
    assert st["status"] == "profile_unsupported" and st["packets_ok"] == 4 and st["packets_rejected"] == 1
    v = [x for x in client.get("/api/vehicles").json() if x["device_id"] == j["device_id"]][0]
    assert v["status"] == "profile_unsupported" and v["profile_supported"] is False
    assert "tamper" in {a["category"] for a in client.get(f"/api/alerts?device_id={j['device_id']}").json()}
    with client.websocket_connect("/ws/live") as live:  # live feed also fine
        assert live.receive_json()["type"] == "link"


def test_legacy_profile_row_does_not_crash(client):
    """A DB row from before the Sonata rewrite (profile no longer exists) must not 500."""
    client.app.state.db.upsert_vehicle(dict(device_id=5, name="Old", brand="Maruti", model="Swift", plate="K",
                                            can_profile="sim_maruti_v1", psk_hex="cd" * 16))
    st = _unsupported_send(client, 5, bytes.fromhex("cd" * 16))
    assert st["status"] == "profile_unsupported" and st["can_profile"] == "sim_maruti_v1"
    # assigning a supported profile via PATCH makes it work
    assert client.patch("/api/vehicles/5", json={"can_profile": "hyundai_sonata_hcrl"}).json()["status"] != "profile_unsupported"
    st = _unsupported_send(client, 5, bytes.fromhex("cd" * 16))
    assert st["health"] == 100  # stub analyzer scored it


def test_ingest_and_live(client):
    car = VirtualCar("hyundai_sonata_hcrl", seed=1)
    car.controls["speed_kmh"] = 60
    with client.websocket_connect("/ws/live") as live:
        # initial link snapshot for the seeded vehicle
        assert live.receive_json()["type"] == "link"
        with client.websocket_connect("/ws/ingest") as ws:
            cs = connect(ws)
            assert live.receive_json() == {"type": "link", "device_id": 1, "connected": True}
            for i in range(3):
                ws.send_bytes(cs.seal(make_batch(car, 100 * i)))
            msgs = [live.receive_json() for _ in range(3)]
            m = msgs[-1]
            assert m["type"] == "telemetry" and m["device_id"] == 1
            assert m["link"]["packets_ok"] == 3 and m["link"]["packets_rejected"] == 0
            assert len(m["link"]["last_cipher_hex"]) == 64
            assert "frames" in m["link"]["last_plain"]
            assert "speed_kmh" in m["signals"] and "rpm" in m["signals"] and m["analysis"]["health"]["overall"] == 100
        # disconnect -> link false
        assert live.receive_json() == {"type": "link", "device_id": 1, "connected": False}
    assert len(client.get("/api/history/1").json()) >= 1  # 1 Hz logging
    st = client.get("/api/status").json()["devices"]["1"]
    assert st["packets_ok"] == 3 and st["connected"] is False and st["status"] == "offline"


def test_replay_and_tamper(client):
    car = VirtualCar("hyundai_sonata_hcrl", seed=2)
    with client.websocket_connect("/ws/ingest") as ws:
        cs = connect(ws)
        good = cs.seal(make_batch(car, 0))
        ws.send_bytes(good)
        ws.send_bytes(good)  # replay
        bad = bytearray(cs.seal(make_batch(car, 100)))
        bad[-3] ^= 0xFF  # tamper
        ws.send_bytes(bytes(bad))
        ws.send_bytes(cs.seal(make_batch(car, 200)))  # connection still alive
    cats = {a["category"] for a in client.get("/api/alerts?device_id=1").json()}
    assert {"replay", "tamper"} <= cats
    st = client.get("/api/status").json()["devices"]["1"]
    assert st["packets_ok"] == 2 and st["packets_rejected"] == 2


def test_wrong_psk_rejected(client):
    with client.websocket_connect("/ws/ingest") as ws:
        cs = ClientSession(1, bytes(16))
        ws.send_bytes(cs.handle_challenge(ws.receive_bytes()))
        with pytest.raises(HandshakeError):
            cs.handle_welcome(ws.receive_bytes())
    assert "auth_fail" in {a["category"] for a in client.get("/api/alerts?device_id=1").json()}
    assert client.get("/api/status").json()["devices"]["1"]["connected"] is False


def test_unknown_device_rejected(client):
    with client.websocket_connect("/ws/ingest") as ws:
        cs = ClientSession(99, PSK1)
        ws.send_bytes(cs.handle_challenge(ws.receive_bytes()))
        with pytest.raises(HandshakeError):
            cs.handle_welcome(ws.receive_bytes())
