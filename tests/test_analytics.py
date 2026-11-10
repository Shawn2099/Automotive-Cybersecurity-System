"""Analytics tests (v2, HCRL-spec Sonata): drive VehicleAnalyzer with VirtualCar for every fault and attack."""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from common.can_profiles import decode_can_frames, get_profile
from common.vehicle_sim import ATTACKS, VirtualCar, summarize_window
from ml_training.generate_dataset import RandomDriver
from server.app.analytics import VehicleAnalyzer, load_models

PROFILE = "hyundai_sonata_hcrl"
MODEL_DIR = Path(__file__).resolve().parent.parent / "server" / "models"
MODELS = load_models(MODEL_DIR)
DT = 0.1
CYBER = {"dos", "fuzzy", "spoofing_rpm", "spoofing_gear", "spoofing_steering", "auth_fail", "replay", "tamper"}


@pytest.fixture(params=["rules_only", "with_models"])
def models(request):
    if request.param == "rules_only":
        return None
    if MODELS is None:
        pytest.skip("trained models not present (run python -m ml_training.train)")
    return MODELS


class Rig:
    def __init__(self, models, speed=60.0, seed=1):
        self.car = VirtualCar(PROFILE, seed=seed)
        self.car.controls.update(speed_kmh=speed, throttle_pct=30.0)
        self.car.speed = speed
        self.az = VehicleAnalyzer(PROFILE, models)
        self.t = 0.0
        self.alerts: list[tuple[float, dict]] = []
        self.last: dict = {}
        self.driver = None

    def run(self, seconds: float) -> dict:
        for _ in range(int(round(seconds / DT))):
            if self.driver:
                self.driver.tick(self.t)
            self.feed(self.car.step(DT))
        return self.last

    def feed(self, frames, mutate=None) -> dict:
        self.t += DT
        batch = summarize_window(frames, 100)
        batch["ts_ms"] = int(self.t * 1000)
        if mutate:
            mutate(batch)
        dec = decode_can_frames(PROFILE, batch["frames"])
        self.last = self.az.update(batch, dec, self.t)
        self.alerts += [(self.t, a) for a in self.last["alerts"]]
        return self.last

    def cats(self) -> set[str]:
        return {a["category"] for _, a in self.alerts}


def test_normal_driving_is_quiet(models):
    r = Rig(models)
    res = r.run(15)
    assert r.cats() == set(), r.alerts
    assert res["health"]["overall"] > 85
    assert res["cyber_risk"] < 20
    assert res["attack_class"] == "normal"
    assert set(res["health"]) == {"overall", "engine", "thermal", "electrical", "steering_brakes"}


@pytest.mark.parametrize("seed", [3, 11])
def test_no_false_positives_in_60s_varied_normal_driving(models, seed):
    r = Rig(models, speed=0.0, seed=seed)
    r.driver = RandomDriver(r.car, random.Random(seed))
    worst_risk, classes = 0, set()
    for _ in range(60):
        res = r.run(1)
        worst_risk = max(worst_risk, res["cyber_risk"])
        classes.add(res["attack_class"])
    assert not (r.cats() & CYBER), r.alerts
    assert worst_risk < 20 and classes == {"normal"}
    assert not [a for _, a in r.alerts if a["kind"] == "cyber"]


def test_result_shape(models):
    res = Rig(models).run(1)
    assert {"health", "cyber_risk", "attack_class", "attack_confidence", "anomaly_score", "forecast", "alerts"} <= set(res)
    assert 0 <= res["anomaly_score"] <= 1
    assert res["attack_class"] in {"normal", "dos", "fuzzy", "spoofing", "tunnel_attack"}


def test_missing_signals_are_carried_forward(models):
    r = Rig(models)
    r.run(2)
    ems11 = get_profile(PROFILE).id_for_signal("rpm")
    r.feed([f for f in r.car.step(DT) if f["id"] == ems11])  # only the EMS11 frames
    assert r.az.fs.last["coolant_c"] > 0 and r.az.fs.last["battery_v"] > 0 and "whl_fl_kmh" in r.az.fs.last


# ------------------------------------------------------------------ faults
def test_overheat(models):
    r = Rig(models)
    r.run(5)
    r.car.faults = {"overheat"}
    res = r.run(20)
    assert "overheat" in r.cats()
    assert "forecast_overheat" in r.cats()
    assert res["health"]["thermal"] < 60 and res["health"]["overall"] < 85
    r.car.faults = set()
    r.car.coolant = 90.0
    res = r.run(8)
    assert res["health"]["overall"] > 85 and res["health"]["thermal"] > 85


def test_forecast_eta_before_threshold(models):
    r = Rig(models)
    r.run(3)
    r.car.faults = {"overheat"}
    seen = None
    for _ in range(150):
        res = r.run(0.1)
        if res["forecast"] and res["forecast"][0]["eta_s"] < 60:
            seen = res["forecast"][0]
            break
    assert seen and seen["signal"] == "coolant_c" and seen["threshold"] == 110 and 0 < seen["eta_s"] < 60
    assert r.car.coolant < 110  # warned before the threshold was crossed


def test_battery_drain(models):
    r = Rig(models)
    r.run(5)
    r.car.faults = {"battery_drain"}
    res = r.run(22)
    assert "low_battery" in r.cats()
    assert "forecast_battery" in r.cats()
    assert res["health"]["electrical"] < 60
    r.car.faults = set()
    r.car.battery = 13.9
    res = r.run(8)
    assert res["health"]["overall"] > 85 and res["health"]["electrical"] > 85


def test_sensor_inconsistency(models):
    r = Rig(models)
    r.run(3)
    r.car.faults = {"sensor_inconsistency"}
    res = r.run(4)
    assert "sensor_inconsistency" in r.cats()
    assert res["health"]["overall"] < 85
    r.car.faults = set()
    res = r.run(8)
    assert res["health"]["overall"] > 85


def test_speed_mismatch_wheel_and_cluster():
    for key in ("wheel", "cluster"):
        r = Rig(None)
        r.run(2)
        orig = r.car.state

        def patched(orig=orig, key=key):
            s = orig()
            if key == "wheel":
                s.update(whl_fl_kmh=20, whl_fr_kmh=20, whl_rl_kmh=20, whl_rr_kmh=20)
            else:
                s["clu_speed_kmh"] = 20
            return s

        r.car.state = patched
        r.run(1)
        assert "sensor_inconsistency" in r.cats(), key
        assert key in r.alerts[0][1]["message"]


def test_throttle_brake_conflict():
    r = Rig(None)
    r.run(2)
    r.car.controls.update(throttle_pct=80.0, brake_pct=60.0)
    r.run(1)
    assert "sensor_inconsistency" in r.cats()


# ------------------------------------------------------------------ attacks
EXPECT = {
    "dos": ("dos", "dos"),
    "fuzzy": ("fuzzy", "fuzzy"),
    "rpm_spoof": ("spoofing_rpm", "spoofing"),
    "gear_spoof": ("spoofing_gear", "spoofing"),
    "steering_spoof": ("spoofing_steering", "spoofing"),
}


@pytest.mark.parametrize("attack", ATTACKS)
def test_attack_detected_and_recovers(models, attack):
    cat, cls = EXPECT[attack]
    r = Rig(models)
    r.run(5)
    assert r.last["cyber_risk"] < 20
    r.car.attacks = {attack}
    res = r.run(4)
    assert cat in r.cats(), (r.cats(), r.alerts)
    assert res["cyber_risk"] > 40
    assert res["attack_class"] == cls
    assert res["attack_confidence"] > 0.5
    r.car.attacks = set()
    res = r.run(8)
    assert res["cyber_risk"] < 20
    assert res["attack_class"] == "normal"
    assert res["health"]["overall"] > 85


def test_dos_and_fuzzy_are_not_confused(models):
    for attack, other in (("dos", "fuzzy"), ("fuzzy", "dos")):
        r = Rig(models)
        r.run(3)
        r.car.attacks = {attack}
        r.run(6)
        assert EXPECT[attack][0] in r.cats()
        assert EXPECT[other][0] not in r.cats(), (attack, r.alerts)
        assert not any(a["category"].startswith("spoofing") for _, a in r.alerts)


def test_spoof_alert_names_the_right_message(models):
    r = Rig(models)
    r.run(3)
    r.car.attacks = {"rpm_spoof"}
    r.run(3)
    assert r.cats() == {"spoofing_rpm"}  # no cross-talk into gear / steering / dos


def test_intermittent_bursts_like_hcrl(models):
    """3-5 s injections separated by quiet gaps: each burst detected, quiet between them."""
    r = Rig(models)
    r.run(3)
    for attack in ("rpm_spoof", "dos", "fuzzy", "gear_spoof"):
        before = len(r.alerts)
        r.car.attacks = {attack}
        res = r.run(4)
        assert res["attack_class"] != "normal" and len(r.alerts) > before, attack
        r.car.attacks = set()
        res = r.run(6)
        assert res["attack_class"] == "normal" and res["cyber_risk"] < 20, attack


def test_steering_physics_trigger_without_traffic_anomaly():
    r = Rig(None)
    r.run(2)
    for i in range(10):  # steering wheel jumping +-450 deg every 100 ms, normal frame rates
        r.car.steering = 450.0 * (1 if i % 2 else -1)
        r.car.controls["steering_deg"] = r.car.steering
        r.feed(r.car.step(DT))
    assert "spoofing_steering" in r.cats()


def test_unnamed_known_id_flood_raises_risk_but_no_alert():
    """A flood of some other known ID (e.g. coolant message) is class 'spoofing', risk only, no alert."""
    r = Rig(None)
    r.run(2)
    cid = get_profile(PROFILE).id_for_signal("coolant_c")
    res = {}
    for _ in range(20):
        res = r.feed(r.car.step(DT), mutate=lambda b: b["counts"].__setitem__(str(cid), 110))
    assert res["cyber_risk"] > 40 and res["attack_class"] == "spoofing"
    assert r.cats() == set()


# ------------------------------------------------------------------ tunnel events
@pytest.mark.parametrize("kind", ["auth_fail", "replay", "tamper"])
def test_tunnel_events(models, kind):
    r = Rig(models)
    r.run(3)
    r.az.record_tunnel_event(kind, r.t)
    pending = r.az.drain_alerts(r.t)  # works without any batch
    assert [a["category"] for a in pending] == [kind]
    assert pending[0]["kind"] == "cyber" and pending[0]["severity"] in ("high", "critical")
    assert r.az.drain_alerts(r.t) == []  # drained
    res = r.run(1)
    assert res["alerts"] == []  # already delivered via drain
    assert res["cyber_risk"] > 30 and res["attack_class"] == "tunnel_attack"
    res = r.run(9)
    assert res["cyber_risk"] < 20 and res["attack_class"] == "normal"


def test_tunnel_alert_surfaces_on_next_update(models):
    r = Rig(models)
    r.run(2)
    r.az.record_tunnel_event("tamper", r.t)
    r.run(0.1)
    assert "tamper" in r.cats()


def test_bad_tunnel_kind():
    with pytest.raises(ValueError):
        VehicleAnalyzer(PROFILE).record_tunnel_event("nope", 0.0)


# ------------------------------------------------------------------ debounce
def test_debounce_one_alert_per_category_per_10s(models):
    r = Rig(models)
    r.run(2)
    r.car.faults = {"overheat"}
    r.car.attacks = {"dos"}
    r.run(35)
    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    by_cat: dict[str, list[tuple[float, int]]] = {}
    for t, a in r.alerts:
        by_cat.setdefault(a["category"], []).append((t, rank[a["severity"]]))
    assert "overheat" in by_cat and "dos" in by_cat
    for cat, ts in by_cat.items():
        for (ta, sa), (tb, sb) in zip(ts, ts[1:]):
            # within the cooldown, a repeat is allowed only as a severity escalation
            assert tb - ta >= 10.0 - 1e-6 or sb > sa, (cat, ts)
    assert len(by_cat["dos"]) <= 4


def test_severity_escalation_inside_cooldown():
    r = Rig(None)
    r.run(2)
    r.car.controls["coolant_c"] = r.car.coolant = 107.0  # medium
    r.run(2)
    r.car.controls["coolant_c"] = r.car.coolant = 115.0  # high, still inside the 10 s cooldown
    r.run(2)
    r.run(3)  # sustained: no more repeats
    sev = [a["severity"] for _, a in r.alerts if a["category"] == "overheat"]
    assert sev == ["medium", "high"], sev


def test_tunnel_burst_debounced():
    az = VehicleAnalyzer(PROFILE)
    for i in range(20):
        az.record_tunnel_event("replay", i * 0.1)
    assert len(az.drain_alerts(2.0)) == 1


def test_alert_shape(models):
    r = Rig(models)
    r.car.attacks = {"dos"}
    r.run(2)
    assert r.alerts
    for _, a in r.alerts:
        assert set(a) == {"category", "kind", "severity", "message"}
        assert a["kind"] in ("mechanical", "cyber") and a["severity"] in ("low", "medium", "high", "critical")


# ------------------------------------------------------------------ models
def test_load_models_missing(tmp_path):
    assert load_models(tmp_path) is None
    assert load_models(tmp_path / "nope") is None


def test_load_models_trained():
    if MODELS is None:
        pytest.skip("models not trained")
    assert MODELS.iforest is not None and MODELS.rf is not None
