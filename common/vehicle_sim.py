"""Shared virtual vehicle model: physics, fault injection, HCRL-style CAN attacks, batch summarising.

Used by BOTH the live simulator (stand-in for the ESP32 car) and the ML training-data generator.
The car emits every message of its CAN profile (default: HCRL Car-Hacking Hyundai YF Sonata
layout) at the profile's periods. Attacks mirror the HCRL Car-Hacking dataset. Injection rates and how much legitimate traffic
survives come from the profile's `attack_behaviour` (measured from the real HCRL captures); the
nominal paper rates below are only a fallback:
  dos         ID 0x000, 8 zero bytes, every 0.3 ms
  fuzzy       random ID (0x000-0x7FF) + random payload, every 0.5 ms
  rpm_spoof   the RPM message (0x316) with the exact HCRL injected payload, every 1 ms
  gear_spoof  the gear message (0x43F) with the exact HCRL injected payload, every 1 ms
  steering_spoof (our extra) steering message with alternating +/-450 deg, every 1 ms
"""

from __future__ import annotations

import random
from typing import Any

from common.can_profiles import DEFAULT_PROFILE, encode_message, get_profile

FAULTS = ["overheat", "battery_drain", "sensor_inconsistency"]
ATTACKS = ["dos", "fuzzy", "rpm_spoof", "gear_spoof", "steering_spoof"]

DOS_PERIOD_S = 0.0003
FUZZY_PERIOD_S = 0.0005
SPOOF_PERIOD_S = 0.001
SPOOF_RPM = 6500.0
SPOOF_GEAR = 1

GEAR_FACTOR = [0, 110, 70, 50, 40, 33, 28]  # rpm per km/h by gear
BUS_BITRATE = 500_000


def frame_bits(dlc: int) -> int:
    """Approx bits on the wire for an 11-bit frame incl. ~20% stuffing."""
    return int((47 + 8 * dlc) * 1.2)


def _approach(cur: float, target: float, max_delta: float) -> float:
    if target > cur:
        return min(target, cur + max_delta)
    return max(target, cur - max_delta)


def default_controls() -> dict[str, Any]:
    return {
        "speed_kmh": 0.0,
        "steering_deg": 0.0,
        "throttle_pct": 0.0,
        "brake_pct": 0.0,
        "coolant_c": 90.0,
        "battery_v": 13.9,
        "auto_rpm": True,
        "rpm": 800.0,  # used only when auto_rpm is False
        "gear": 0,  # used only when auto_rpm is False
    }


class VirtualCar:
    """One simulated vehicle that emits CAN frames for a given profile."""

    def __init__(self, profile_id: str = DEFAULT_PROFILE, seed: int | None = None) -> None:
        self.profile_id = profile_id
        self.profile = get_profile(profile_id)
        self.rng = random.Random(seed)
        self.controls: dict[str, Any] = default_controls()
        self.faults: set[str] = set()
        self.attacks: set[str] = set()

        self.speed = 0.0
        self.prev_speed = 0.0
        self.steering = 0.0
        self.coolant = 90.0
        self.battery = 13.9
        self.t = 0.0

        self._acc = {m.id: self.rng.uniform(0, m.period_ms / 1000.0) for m in self.profile.all_messages}
        self._atk_acc = {a: 0.0 for a in ATTACKS}
        self._spoof_sign = 1
        self._accel = 0.0

    # ------------------------------------------------------------------ physics
    def _gear_for(self, speed: float) -> int:
        if speed < 1:
            return 0
        return min(6, 1 + int(speed // 30))

    def _rpm_gear(self) -> tuple[float, int]:
        c = self.controls
        if not c.get("auto_rpm", True):
            return float(c.get("rpm", 800)), int(c.get("gear", 0))
        gear = self._gear_for(self.speed)
        base = 800 + self.speed * GEAR_FACTOR[gear] + 15 * float(c.get("throttle_pct", 0))
        return base + self.rng.uniform(-30, 30), gear

    def _physics(self, dt: float) -> None:
        c = self.controls
        self.prev_speed = self.speed
        self.speed = _approach(self.speed, float(c["speed_kmh"]), 25.0 * dt)
        self._accel = ((self.speed - self.prev_speed) / 3.6) / dt if dt > 0 else 0.0
        self.steering = _approach(self.steering, float(c["steering_deg"]), 360.0 * dt)
        if "overheat" in self.faults:
            self.coolant = min(128.0, self.coolant + 1.5 * dt)
        else:
            self.coolant = _approach(self.coolant, float(c["coolant_c"]), 3.0 * dt)
        if "battery_drain" in self.faults:
            self.battery = max(10.6, self.battery - 0.12 * dt)
        else:
            self.battery = _approach(self.battery, float(c["battery_v"]), 0.5 * dt)

    def state(self) -> dict[str, Any]:
        """Current *reported* signals (what the ECUs put on the bus), profile signal names."""
        c = self.controls
        rpm, gear = self._rpm_gear()
        true_speed = self.speed
        ems_speed = true_speed
        if "sensor_inconsistency" in self.faults:
            ems_speed = max(true_speed, 100.0)  # engine ECU reports 100 km/h, wheels disagree
            rpm = 0.0
        w = lambda: max(0.0, true_speed + self.rng.uniform(-0.3, 0.3))  # noqa: E731
        return {
            "rpm": max(0.0, rpm),
            "speed_kmh": ems_speed,
            "throttle_pct": float(c["throttle_pct"]),
            "steering_deg": self.steering + self.rng.uniform(-0.3, 0.3),
            "brake_bar": float(c["brake_pct"]) * 1.5,
            "gear": gear,
            "coolant_c": self.coolant + self.rng.uniform(-0.4, 0.4),
            "battery_v": self.battery + self.rng.uniform(-0.04, 0.04),
            "whl_fl_kmh": w(), "whl_fr_kmh": w(), "whl_rl_kmh": w(), "whl_rr_kmh": w(),
            "long_accel": self._accel - 0.08 * float(c["brake_pct"]) + self.rng.uniform(-0.05, 0.05),
            "clu_speed_kmh": true_speed,
        }

    # ------------------------------------------------------------------ frames
    def step(self, dt: float) -> list[dict[str, Any]]:
        """Advance by dt seconds and return every CAN frame emitted during dt."""
        self.t += dt
        self._physics(dt)
        out: list[dict[str, Any]] = []
        st = self.state()
        # Real HCRL captures show injected traffic crowding legitimate frames off the bus:
        # keep each legitimate frame with the measured probability for the active attacks.
        keep = min([self._behaviour(a)["legit_keep"] for a in self.attacks] or [1.0])
        for m in self.profile.all_messages:
            if m.period_ms <= 0:
                continue
            p = m.period_ms / 1000.0
            self._acc[m.id] += dt
            while self._acc[m.id] >= p:
                self._acc[m.id] -= p
                if keep >= 1.0 or self.rng.random() < keep:
                    out.append(encode_message(m, st))
        out.extend(self._attack_frames(dt, st))
        return out

    def _behaviour(self, attack: str) -> dict[str, float]:
        """Measured HCRL injection rate / legit-traffic survival, falling back to the nominal rates."""
        nominal = {"dos": 1 / DOS_PERIOD_S, "fuzzy": 1 / FUZZY_PERIOD_S}.get(attack, 1 / SPOOF_PERIOD_S)
        b = self.profile.attack_behaviour.get(attack, {})
        return {"inject_fps": float(b.get("inject_fps", nominal)), "legit_keep": float(b.get("legit_keep", 1.0))}

    def _n(self, attack: str, period: float, dt: float) -> int:
        period = 1.0 / self._behaviour(attack)["inject_fps"]
        self._atk_acc[attack] += dt / period
        n = int(self._atk_acc[attack])
        self._atk_acc[attack] -= n
        return n

    def _attack_frames(self, dt: float, st: dict[str, Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        prof = self.profile
        if "dos" in self.attacks:
            out.extend({"id": 0x000, "dlc": 8, "data": "0000000000000000"}
                       for _ in range(self._n("dos", DOS_PERIOD_S, dt)))
        if "fuzzy" in self.attacks:
            for _ in range(self._n("fuzzy", FUZZY_PERIOD_S, dt)):
                data = bytes(self.rng.getrandbits(8) for _ in range(8)).hex().upper()
                out.append({"id": self.rng.randint(0, 0x7FF), "dlc": 8, "data": data})
        for attack, signal, value in (("rpm_spoof", "rpm", SPOOF_RPM), ("gear_spoof", "gear", SPOOF_GEAR)):
            if attack in self.attacks:
                mid = prof.attack_target_id(attack) or prof.id_for_signal(signal)
                msg = prof.message(mid) if mid is not None else None
                n = self._n(attack, SPOOF_PERIOD_S, dt)
                if msg is not None and n:
                    if msg.spoof_data:  # replay the exact HCRL injected frame
                        fr = {"id": msg.id, "dlc": msg.dlc, "data": msg.spoof_data.hex().upper()}
                    else:
                        fr = encode_message(msg, {**st, signal: value})
                    out.extend(dict(fr) for _ in range(n))
        if "steering_spoof" in self.attacks:
            msg = prof.message(prof.id_for_signal("steering_deg") or -1)
            for _ in range(self._n("steering_spoof", SPOOF_PERIOD_S, dt)):
                self._spoof_sign = -self._spoof_sign
                if msg is not None:
                    out.append(encode_message(msg, {**st, "steering_deg": 450.0 * self._spoof_sign}))
        return out


def summarize_window(frames: list[dict[str, Any]], window_ms: int) -> dict[str, Any]:
    """Bounded batch (Contract B, without ts_ms): latest frame per ID + per-ID counts + bus stats."""
    latest: dict[int, dict[str, Any]] = {}
    counts: dict[str, int] = {}
    bits = 0
    for f in frames:
        latest[int(f["id"])] = f
        k = str(int(f["id"]))
        counts[k] = counts.get(k, 0) + 1
        bits += frame_bits(int(f.get("dlc", 8)))
    load = min(100, round(100 * bits / (BUS_BITRATE * window_ms / 1000.0))) if window_ms else 0
    return {
        "window_ms": window_ms,
        "frames": [latest[i] for i in sorted(latest)],
        "counts": counts,
        "bus_load_pct": int(load),
        "rx_err": 0,
    }
