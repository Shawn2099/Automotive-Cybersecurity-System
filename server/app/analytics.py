"""Vehicle analytics (PLAN.md Contract D, v2 / section 9c): deterministic rules + optional ML + forecaster.

Rules are the main detector and always work.  ML (IsolationForest health anomaly score,
RandomForest attack classifier) is optional; `models=None` gives rules-only operation.

Cyber detection is relative to the CAN profile (`expected_hz`, `valid_ids`, attack-target IDs):
  spoofing = a known ID at > SPOOF_RATIO x its expected rate (HCRL injects at 1 kHz vs 100 Hz -> ~11x),
             category chosen by which message (rpm / gear / steering); any other known ID only raises
             risk (`spoofing_other`), no alert, because the alert categories are fixed.
  dos      = one unknown ID above DOS_UNKNOWN_ID_FPS, or total rate > 3x expected with few distinct IDs.
  fuzzy    = >= FUZZY_MIN_IDS distinct unknown IDs in the smoothing window (never raised together with dos).

Feature extraction lives here (`FeatureState`, `health_features`, `traffic_features`) and is
imported by `ml_training/` so training and serving features are identical.
"""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from common.can_profiles import PROFILE_DIR, decode_can_frames, get_profile
from common.vehicle_sim import BUS_BITRATE, frame_bits

# --------------------------------------------------------------------------- tunables
WINDOW_S = 5.0  # rolling score window
RECENT_S = 1.0  # recent-emphasis sub-window
COOLDOWN_S = 10.0  # alert debounce per category
REARM_QUIET_S = 2.0  # a traffic-rule category quiet this long re-arms (next intrusion alerts again; HCRL bursts repeat every ~7 s)
TUNNEL_ACTIVE_S = 3.0  # how long a tunnel event keeps cyber_risk raised
FORECAST_WINDOW_S = 30.0
FORECAST_ETA_ALERT_S = 60.0

COOLANT_MED, COOLANT_HIGH = 105.0, 110.0
BATTERY_MED, BATTERY_HIGH = 11.8, 11.4
SPEED_MISMATCH_KMH = 15.0  # EMS speed vs wheel / cluster speed
STEER_RATE_LIMIT = 1000.0  # deg/s (physical steering never exceeds ~400 deg/s)

# traffic / cyber thresholds (all relative to the CAN profile)
SMOOTH_S = 0.5  # rate smoothing window
MIN_SPAN_S = 0.2  # no rate-based rule before this much traffic has been seen
MIN_EXPECTED_HZ = 10.0  # floor for the denominator of a per-ID rate ratio (avoids noise on slow IDs)
SPOOF_RATIO = 1.5  # known ID at > 1.5x its expected rate (real normal HCRL max over 47k windows: 1.2x; real injections 1.1-30x, sim ~11x)
DOS_UNKNOWN_ID_FPS = 100.0  # one unknown ID above the fastest legit message rate (100 Hz) = flood (HCRL real: 150-1000/s, sim: 3300/s)
DOS_TOTAL_RATIO = 3.0  # total rate > 3x expected with few distinct IDs
DOS_MAX_UNKNOWN_IDS = 3
FUZZY_MIN_IDS = 10  # distinct unknown IDs in the smoothing window
FUZZY_MIN_FPS = 50.0
RATIO_CAP = 100.0
SIGNAL_MIN_RATIO = 0.5  # trust a message's signals only if it arrives at >= half its expected rate (a lone fuzzed frame is not a signal)

CYBER_PEN = {
    "dos": 95,
    "fuzzy": 90,
    "spoofing_steering": 85,
    "spoofing_rpm": 85,
    "spoofing_gear": 85,
    "spoofing_other": 70,  # risk only, no alert (alert categories are fixed)
    "replay": 80,
    "tamper": 80,
    "auth_fail": 70,
    "ml_attack": 50,
}
CLASS_OF = {
    "dos": "dos",
    "fuzzy": "fuzzy",
    "spoofing_steering": "spoofing",
    "spoofing_rpm": "spoofing",
    "spoofing_gear": "spoofing",
    "spoofing_other": "spoofing",
    "auth_fail": "tunnel_attack",
    "replay": "tunnel_attack",
    "tamper": "tunnel_attack",
}
CLASS_PRIORITY = ["dos", "fuzzy", "spoofing_steering", "spoofing_rpm", "spoofing_gear", "spoofing_other",
                  "replay", "tamper", "auth_fail"]
ATTACK_CLASSES = ["normal", "dos", "fuzzy", "spoofing", "tunnel_attack"]

HEALTH_FEATURE_NAMES = [
    "speed_kmh", "rpm", "throttle_pct", "brake_bar", "coolant_c", "battery_v",
    "steering_abs", "rpm_per_speed", "speed_mismatch",
]
TRAFFIC_FEATURE_NAMES = [
    "total_ratio", "max_known_ratio", "rpm_ratio", "gear_ratio", "steering_ratio",
    "unknown_fps", "n_unknown_ids", "max_unknown_id_fps", "bus_load_pct", "steering_rate",
]


# --------------------------------------------------------------------------- feature extraction
def _non_hcrl_ids(profile_id: str) -> dict[int, tuple[float, int]]:
    """Messages the profile adds that the real HCRL car bus does not carry: {id: (expected_hz, dlc)}.

    The simulator emits them, real HCRL traffic never does. Total rate and bus load are computed WITHOUT them so
    a given traffic situation produces the same features on the simulator and on real HCRL logs.
    """
    out: dict[int, tuple[float, int]] = {}
    try:
        for p in PROFILE_DIR.glob("*.json"):
            raw = json.loads(p.read_text(encoding="utf-8"))
            if raw.get("profile_id") != profile_id:
                continue
            for m in raw.get("messages", []):
                if m.get("in_hcrl") is False and float(m.get("period_ms", 0)) > 0:
                    out[int(m["id"])] = (1000.0 / float(m["period_ms"]), int(m.get("dlc", 8)))
    except (OSError, ValueError, KeyError):
        pass
    return out


def _wheel_mean(sig: dict[str, Any]) -> float | None:
    w = [float(sig[k]) for k in ("whl_fl_kmh", "whl_fr_kmh", "whl_rl_kmh", "whl_rr_kmh") if k in sig]
    return sum(w) / len(w) if w else None


def health_features(sig: dict[str, Any]) -> list[float] | None:
    """Per-batch health feature vector from MERGED last-known signals (None if incomplete)."""
    try:
        speed = float(sig["speed_kmh"])
        rpm = float(sig["rpm"])
        thr = float(sig["throttle_pct"])
        brake = float(sig["brake_bar"])
        cool = float(sig["coolant_c"])
        bat = float(sig["battery_v"])
        steer = float(sig["steering_deg"])
    except KeyError:
        return None
    wm = _wheel_mean(sig)
    mismatch = abs(speed - wm) if wm is not None else 0.0
    return [speed, rpm, thr, brake, cool, bat, abs(steer), rpm / (speed + 5.0), mismatch]


def traffic_features(ctx: dict[str, Any]) -> list[float]:
    """Traffic feature vector; every value derives from a Contract-B batch + the profile (see FeatureState)."""
    return [
        ctx["total_ratio"], ctx["max_known_ratio"], ctx["rpm_ratio"], ctx["gear_ratio"], ctx["steering_ratio"],
        ctx["unknown_fps"], float(ctx["n_unknown_ids"]), ctx["max_unknown_id_fps"], float(ctx["bus_load_pct"]),
        min(abs(ctx["steering_rate"]), 20000.0),
    ]


class FeatureState:
    """Stateful per-vehicle feature extractor: merges signals and smooths per-ID rates.

    Needs only a Contract-B batch (counts, frames, bus_load_pct, ts_ms) and the CAN profile; `decoded`
    is optional (decoded here from the batch frames when omitted).
    """

    def __init__(self, profile_id: str) -> None:
        self.profile = get_profile(profile_id)
        prof = self.profile
        self.last: dict[str, Any] = {}
        self._win: deque[tuple[dict[int, int], float]] = deque()  # (counts, window_s) over ~SMOOTH_S
        self._prev_steer: tuple[float, float] | None = None
        self._exp = prof.expected_hz
        self._extra = _non_hcrl_ids(profile_id)  # not on the real HCRL bus: excluded from total rate / bus load
        self._exp_total = max(1.0, prof.expected_total_hz - sum(hz for hz, _ in self._extra.values()))
        self.rpm_id = prof.attack_target_id("rpm_spoof") or prof.id_for_signal("rpm")
        self.gear_id = prof.attack_target_id("gear_spoof") or prof.id_for_signal("gear")
        self.steer_id = prof.id_for_signal("steering_deg")
        self.spoof_category = {i: c for i, c in ((self.rpm_id, "spoofing_rpm"), (self.gear_id, "spoofing_gear"),
                                                 (self.steer_id, "spoofing_steering")) if i is not None}
        self._primary_ids = {m.id for m in prof.messages}

    def _core_bus_load(self, batch: dict[str, Any], counts: dict[int, int], window_s: float) -> float:
        load = float(batch.get("bus_load_pct", 0) or 0)
        extra_bits = sum(n * frame_bits(self._extra[i][1]) for i, n in counts.items() if i in self._extra)
        return max(0.0, load - 100.0 * extra_bits / (BUS_BITRATE * window_s))

    def step(self, batch: dict[str, Any], decoded: dict[str, Any] | None, now_s: float) -> dict[str, Any]:
        prof = self.profile
        window_s = max(0.001, float(batch.get("window_ms", 100) or 100) / 1000.0)
        t_dev = float(batch["ts_ms"]) / 1000.0 if batch.get("ts_ms") is not None else now_s
        if decoded is None:
            decoded = decode_can_frames(prof.profile_id, batch.get("frames") or [])
        counts = {int(k): int(v) for k, v in (batch.get("counts") or {}).items() if int(v) > 0}
        self._win.append((counts, window_s))
        while len(self._win) > 1 and sum(w for _, w in self._win) - self._win[0][1] >= SMOOTH_S:
            self._win.popleft()
        span = sum(w for _, w in self._win)
        agg: dict[int, int] = {}
        for c, _ in self._win:
            for i, n in c.items():
                agg[i] = agg.get(i, 0) + n
        fps = {i: n / span for i, n in agg.items()}
        total_fps = sum(n for i, n in agg.items() if i not in self._extra) / span

        ratios = {i: min(RATIO_CAP, f / max(self._exp[i], MIN_EXPECTED_HZ)) for i, f in fps.items() if i in self._exp}
        unknown = {i: f for i, f in fps.items() if i not in prof.valid_ids}

        # Untrusted signals: the batch keeps only the LATEST frame per ID, so under injection that frame is
        # likely forged. Drop signals of spoofed messages, and all signals while fuzzing is in progress.
        new = dict(decoded.get("signals", {}))
        if span >= MIN_SPAN_S:
            if len(unknown) >= FUZZY_MIN_IDS and sum(unknown.values()) >= FUZZY_MIN_FPS:
                new = {}
            else:
                for i, r in ratios.items():
                    m = prof.message(i)
                    # Low rate is only suspicious when random IDs are in play (fuzz frames landing on a
                    # real ID). Under DoS (one flooding ID) real frames are scarce but genuine.
                    low_rate_forged = r < SIGNAL_MIN_RATIO and len(unknown) > 1
                    if (r > SPOOF_RATIO or low_rate_forged) and m is not None:
                        for sg in m.signals:
                            new.pop(sg.name, None)
        self.last.update(new)

        steer_rate = 0.0
        if "steering_deg" in new:
            st = float(new["steering_deg"])
            if self._prev_steer is not None:
                dt = t_dev - self._prev_steer[1]
                if dt >= 0.02:
                    steer_rate = abs(st - self._prev_steer[0]) / dt
            self._prev_steer = (st, t_dev)

        ctx = {
            "signals": dict(self.last), "new_signals": new, "window_s": window_s, "span_s": span,
            "reliable": span >= MIN_SPAN_S,
            "total_fps": total_fps, "total_ratio": min(RATIO_CAP, total_fps / self._exp_total),
            "fps": fps, "ratios": ratios, "max_known_ratio": max(ratios.values(), default=0.0),
            "rpm_ratio": ratios.get(self.rpm_id, 0.0), "gear_ratio": ratios.get(self.gear_id, 0.0),
            "steering_ratio": ratios.get(self.steer_id, 0.0),
            "unknown_ids": unknown, "n_unknown_ids": len(unknown), "unknown_fps": sum(unknown.values()),
            "max_unknown_id_fps": max(unknown.values(), default=0.0),
            "max_unknown_id": max(unknown, key=unknown.get) if unknown else None,
            "steering_rate": steer_rate, "bus_load_pct": self._core_bus_load(batch, counts, window_s),
        }
        ctx["health_vec"] = health_features(self.last)
        ctx["traffic_vec"] = traffic_features(ctx)
        return ctx


# --------------------------------------------------------------------------- models
@dataclass
class Models:
    iforest: Any = None
    if_lo: float = 0.0  # median of -score_samples on normal training data
    if_hi: float = 1.0  # 99.5th percentile of the same
    rf: Any = None
    rf_classes: list[str] | None = None

    def anomaly_score(self, vec: list[float]) -> float:
        if self.iforest is None or vec is None:
            return 0.0
        s = -float(self.iforest.score_samples(np.asarray([vec], dtype=float))[0])
        a = (s - self.if_lo) / max(1e-6, self.if_hi - self.if_lo)  # 1.0 == edge of normal
        return float(min(1.0, max(0.0, a / 2.0)))

    def classify(self, vec: list[float]) -> tuple[str, float, float]:
        """Returns (label, confidence of label, probability of 'normal')."""
        if self.rf is None:
            return "normal", 0.0, 1.0
        proba = self.rf.predict_proba(np.asarray([vec], dtype=float))[0]
        classes = list(self.rf_classes or self.rf.classes_)
        i = int(np.argmax(proba))
        p_norm = float(proba[classes.index("normal")]) if "normal" in classes else 0.0
        return str(classes[i]), float(proba[i]), p_norm


def load_models(model_dir: Path | str) -> Models | None:
    """Load trained models; None if no model files (analyzer then runs rules-only)."""
    d = Path(model_dir)
    p_if, p_rf = d / "health_iforest.joblib", d / "cyber_rf.joblib"
    if not (p_if.exists() or p_rf.exists()):
        return None
    try:
        import joblib

        m = Models()
        if p_if.exists():
            b = joblib.load(p_if)
            if b.get("features") == HEALTH_FEATURE_NAMES:  # stale (v1) model -> ignore
                m.iforest, m.if_lo, m.if_hi = b["model"], float(b["lo"]), float(b["hi"])
        if p_rf.exists():
            b = joblib.load(p_rf)
            if b.get("features") == TRAFFIC_FEATURE_NAMES:
                m.rf, m.rf_classes = b["model"], list(b["classes"])
        if m.iforest is None and m.rf is None:
            return None
        return m
    except Exception:  # corrupt / incompatible files -> rules-only
        return None


# --------------------------------------------------------------------------- analyzer
_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class VehicleAnalyzer:
    def __init__(self, profile_id: str, models: Models | None = None) -> None:
        self.profile_id = profile_id
        self.models = models
        self.fs = FeatureState(profile_id)
        self._records: deque[tuple[float, dict[str, float], set[str]]] = deque()
        self._last_alert: dict[str, float] = {}
        self._last_active: dict[str, float] = {}  # traffic-rule categories: last time the rule was true
        self._last_sev: dict[str, int] = {}  # highest severity raised in the current cooldown window
        self._pending: list[dict[str, Any]] = []
        self._tunnel: deque[tuple[float, str]] = deque()
        self._hist: deque[tuple[float, float, float]] = deque()  # (t, coolant, battery)
        self._forecast: list[dict[str, Any]] = []
        self._steer_hits: deque[bool] = deque(maxlen=5)
        self._anom_run = 0
        self._ml_run = 0
        self._ml_label = "normal"

    # ---- alerts
    def _raise(self, category: str, kind: str, severity: str, message: str, now_s: float) -> None:
        last = self._last_alert.get(category)
        rank = _SEV_RANK
        escalated = rank.get(severity, 0) > self._last_sev.get(category, -1)
        if last is not None and 0 <= now_s - last < COOLDOWN_S and not escalated:
            return
        if last is None or now_s - last >= COOLDOWN_S:
            self._last_sev[category] = -1
        self._last_sev[category] = max(self._last_sev.get(category, -1), rank.get(severity, 0))
        self._last_alert[category] = now_s
        self._pending.append({"category": category, "kind": kind, "severity": severity, "message": message})

    def _take_pending(self) -> list[dict[str, Any]]:
        out, self._pending = self._pending, []
        return out

    def drain_alerts(self, now_s: float) -> list[dict[str, Any]]:
        """Pending debounced alerts (e.g. tunnel events) without needing a batch."""
        return self._take_pending()

    def record_tunnel_event(self, kind: str, now_s: float) -> None:
        if kind not in ("auth_fail", "replay", "tamper"):
            raise ValueError(f"unknown tunnel event kind: {kind}")
        self._tunnel.append((now_s, kind))
        sev, msg = {
            "auth_fail": ("high", "Tunnel authentication failure (bad key / unknown device)"),
            "replay": ("high", "Replayed tunnel packet rejected"),
            "tamper": ("critical", "Tampered tunnel packet rejected (tag mismatch)"),
        }[kind]
        self._raise(kind, "cyber", sev, msg, now_s)

    # ---- main entry
    def update(self, batch: dict[str, Any], decoded: dict[str, Any], now_s: float) -> dict[str, Any]:
        ctx = self.fs.step(batch, decoded, now_s)
        sig = ctx["signals"]
        pens = {"engine": 0.0, "thermal": 0.0, "electrical": 0.0, "steering_brakes": 0.0}

        self._mechanical_rules(sig, pens, now_s)
        self._update_forecast(ctx, now_s, pens)

        # ML health anomaly
        anomaly = 0.0
        if self.models is not None and self.models.iforest is not None and ctx["health_vec"] is not None:
            anomaly = self.models.anomaly_score(ctx["health_vec"])
        if anomaly > 0.65:
            self._anom_run += 1
            pens["engine"] = max(pens["engine"], 10.0)
            if self._anom_run >= 5:
                self._raise("health_anomaly", "mechanical", "low",
                            f"Unusual driving/sensor pattern (anomaly {anomaly:.2f})", now_s)
        else:
            self._anom_run = 0

        cats = self._cyber_rules(ctx, now_s)

        # ML attack classifier (only acts when rules are silent and traffic is reliable)
        rf_label, rf_conf, rf_pnorm = "normal", 0.0, 1.0
        if self.models is not None and self.models.rf is not None and ctx["reliable"]:
            rf_label, rf_conf, rf_pnorm = self.models.classify(ctx["traffic_vec"])
        if rf_label not in ("normal", "tunnel_attack") and rf_conf > 0.8 and not cats:
            self._ml_run += 1
            if self._ml_run >= 3:
                cats.add("ml_attack")
                self._ml_label = rf_label
        else:
            self._ml_run = 0

        # rolling window
        self._records.append((now_s, pens, cats))
        while self._records and now_s - self._records[0][0] > WINDOW_S:
            self._records.popleft()

        health = self._health_scores(now_s)
        cyber_risk = self._cyber_risk(now_s)
        attack_class, attack_conf = self._attack_class(now_s, rf_label, rf_conf, rf_pnorm)

        return {
            "health": health,
            "cyber_risk": cyber_risk,
            "attack_class": attack_class,
            "attack_confidence": round(attack_conf, 2),
            "anomaly_score": round(anomaly, 3),
            "forecast": list(self._forecast),
            "alerts": self._take_pending(),
        }

    # ---- rules
    def _mechanical_rules(self, sig: dict[str, Any], pens: dict[str, float], now_s: float) -> None:
        coolant = sig.get("coolant_c")
        if coolant is not None and coolant > COOLANT_HIGH:
            pens["thermal"] = max(pens["thermal"], 75.0)
            self._raise("overheat", "mechanical", "high", f"Coolant {coolant:.0f} °C - engine overheating", now_s)
        elif coolant is not None and coolant > COOLANT_MED:
            pens["thermal"] = max(pens["thermal"], 40.0)
            self._raise("overheat", "mechanical", "medium", f"Coolant {coolant:.0f} °C - running hot", now_s)

        bat = sig.get("battery_v")
        if bat is not None:
            if bat < BATTERY_HIGH:
                pens["electrical"] = max(pens["electrical"], 75.0)
                self._raise("low_battery", "mechanical", "high", f"Battery {bat:.1f} V - critically low", now_s)
            elif bat < BATTERY_MED:
                pens["electrical"] = max(pens["electrical"], 40.0)
                self._raise("low_battery", "mechanical", "medium", f"Battery {bat:.1f} V - low", now_s)

        speed, rpm = sig.get("speed_kmh"), sig.get("rpm")
        thr, brake = sig.get("throttle_pct"), sig.get("brake_bar")
        if speed is not None:
            ref = {"wheel": _wheel_mean(sig), "cluster": sig.get("clu_speed_kmh")}
            for name, other in ref.items():
                if other is not None and max(speed, other) > 10 and abs(speed - other) > SPEED_MISMATCH_KMH:
                    pens["engine"] = max(pens["engine"], 45.0)
                    self._raise("sensor_inconsistency", "mechanical", "medium",
                                f"Engine-ECU speed {speed:.0f} km/h vs {name} speed {other:.0f} km/h", now_s)
                    break
        if speed is not None and rpm is not None and speed > 15 and rpm < 300:
            pens["engine"] = max(pens["engine"], 45.0)
            self._raise("sensor_inconsistency", "mechanical", "medium",
                        f"Speed {speed:.0f} km/h but RPM {rpm:.0f} - sensor mismatch", now_s)
        if thr is not None and brake is not None and thr > 50 and brake > 60:
            pens["steering_brakes"] = max(pens["steering_brakes"], 40.0)
            self._raise("sensor_inconsistency", "mechanical", "medium",
                        f"Throttle {thr:.0f}% and brake {brake:.0f} bar at once", now_s)

    def _cyber_rules(self, ctx: dict[str, Any], now_s: float) -> set[str]:
        cats: set[str] = set()
        fs = self.fs
        speed = ctx["signals"].get("speed_kmh", 0) or 0

        if ctx["reliable"]:
            # --- spoofing: a known ID far above its expected rate
            spoof_ids = {i: r for i, r in ctx["ratios"].items() if r > SPOOF_RATIO}
            for i, r in sorted(spoof_ids.items()):
                cat = fs.spoof_category.get(i)
                if cat is None:
                    cats.add("spoofing_other")  # risk only, see module docstring
                    continue
                cats.add(cat)
                what = {"spoofing_rpm": "RPM", "spoofing_gear": "gear", "spoofing_steering": "steering"}[cat]
                self._raise(cat, "cyber", "high",
                            f"{what} message 0x{i:X} at {ctx['fps'][i]:.0f} frames/s "
                            f"({r:.1f}x expected) - injected frames suspected", now_s)

            # --- dos vs fuzzy (exclusive, prefer the better fit)
            n_unk, unk_max = ctx["n_unknown_ids"], ctx["max_unknown_id_fps"]
            dos_flood = unk_max > DOS_UNKNOWN_ID_FPS
            dos_total = (ctx["total_ratio"] > DOS_TOTAL_RATIO and n_unk <= DOS_MAX_UNKNOWN_IDS and not spoof_ids)
            if dos_flood or dos_total:
                cats.add("dos")
                uid = ctx["max_unknown_id"]
                where = f"ID 0x{uid:X} at {unk_max:.0f}/s" if dos_flood and uid is not None else "few distinct IDs"
                self._raise("dos", "cyber", "critical",
                            f"CAN flood: {ctx['total_fps']:.0f} frames/s, {ctx['total_ratio']:.1f}x expected ({where})",
                            now_s)
            elif n_unk >= FUZZY_MIN_IDS and ctx["unknown_fps"] >= FUZZY_MIN_FPS:
                cats.add("fuzzy")
                self._raise("fuzzy", "cyber", "high",
                            f"{n_unk} distinct unknown CAN IDs at {ctx['unknown_fps']:.0f} frames/s - fuzzing suspected",
                            now_s)

        # --- physical steering-rate check (secondary spoofing_steering trigger)
        # (needs >= 3 of the last 5 batches: one injected/fuzzed frame makes a jump out AND back = 2 hits)
        self._steer_hits.append(ctx["steering_rate"] > STEER_RATE_LIMIT and speed > 20)
        if sum(self._steer_hits) >= 3:
            cats.add("spoofing_steering")
            self._raise("spoofing_steering", "cyber", "high",
                        f"Steering spoofing suspected: steering moving {ctx['steering_rate']:.0f} deg/s", now_s)

        for c in cats:
            self._last_active[c] = now_s
        for c in ("dos", "fuzzy", "spoofing_rpm", "spoofing_gear", "spoofing_steering"):
            if c in self._last_alert and c not in cats and now_s - self._last_active.get(c, now_s) >= REARM_QUIET_S:
                del self._last_alert[c]
                self._last_sev.pop(c, None)

        for t, kind in self._tunnel:
            if 0 <= now_s - t <= TUNNEL_ACTIVE_S:
                cats.add(kind)
        while self._tunnel and now_s - self._tunnel[0][0] > WINDOW_S:
            self._tunnel.popleft()
        return cats

    # ---- forecast
    def _update_forecast(self, ctx: dict[str, Any], now_s: float, pens: dict[str, float]) -> None:
        last = ctx["signals"]
        if "coolant_c" in ctx["new_signals"] and "battery_v" in last:
            self._hist.append((now_s, float(last["coolant_c"]), float(last["battery_v"])))
            while self._hist and now_s - self._hist[0][0] > FORECAST_WINDOW_S:
                self._hist.popleft()
            self._forecast = self._compute_forecast()
        for f in self._forecast:
            if f["eta_s"] < FORECAST_ETA_ALERT_S:
                if f["signal"] == "coolant_c":
                    pens["thermal"] = max(pens["thermal"], 8.0)
                    self._raise("forecast_overheat", "mechanical", "medium",
                                f"Coolant trending to {f['threshold']:.0f} °C in ~{f['eta_s']:.0f} s", now_s)
                else:
                    pens["electrical"] = max(pens["electrical"], 8.0)
                    self._raise("forecast_battery", "mechanical", "medium",
                                f"Battery trending to {f['threshold']:.1f} V in ~{f['eta_s']:.0f} s", now_s)

    def _compute_forecast(self) -> list[dict[str, Any]]:
        if len(self._hist) < 10:
            return []
        h = np.asarray(self._hist, dtype=float)
        x = h[:, 0] - h[0, 0]
        if x[-1] < 4.0:
            return []
        out: list[dict[str, Any]] = []
        # coolant rising toward 110
        slope, icpt = np.polyfit(x, h[:, 1], 1)
        v = h[-1, 1]
        if slope > 0.1 and v < COOLANT_HIGH and abs(v - (slope * x[-1] + icpt)) < 3.0:
            eta = (COOLANT_HIGH - v) / slope
            if eta < 300:
                out.append({"signal": "coolant_c", "eta_s": int(round(eta)), "threshold": COOLANT_HIGH})
        # battery falling toward 11.4
        slope, icpt = np.polyfit(x, h[:, 2], 1)
        v = h[-1, 2]
        if slope < -0.01 and v > BATTERY_HIGH and abs(v - (slope * x[-1] + icpt)) < 0.3:
            eta = (v - BATTERY_HIGH) / -slope
            if eta < 300:
                out.append({"signal": "battery_v", "eta_s": int(round(eta)), "threshold": BATTERY_HIGH})
        return out

    # ---- scoring over rolling window
    def _health_scores(self, now_s: float) -> dict[str, int]:
        recs = list(self._records)
        recent = [r for r in recs if now_s - r[0] <= RECENT_S] or recs[-1:]
        sub = {}
        for k in ("engine", "thermal", "electrical", "steering_brakes"):
            allm = sum(r[1][k] for r in recs) / len(recs)
            rec = sum(r[1][k] for r in recent) / len(recent)
            sub[k] = int(round(max(0.0, min(100.0, 100.0 - (0.5 * allm + 0.5 * rec)))))
        vals = list(sub.values())
        overall = int(round(0.5 * min(vals) + 0.5 * (sum(vals) / len(vals))))
        return {"overall": overall, **sub}

    def _cyber_risk(self, now_s: float) -> int:
        recs = list(self._records)
        recent = [r for r in recs if now_s - r[0] <= RECENT_S] or recs[-1:]
        risks = []
        for c, pen in CYBER_PEN.items():
            fa = sum(1 for r in recs if c in r[2]) / len(recs)
            fr = sum(1 for r in recent if c in r[2]) / len(recent)
            if fa or fr:
                risks.append(pen * (0.5 * fa + 0.5 * fr))
        if not risks:
            return 0
        risks.sort(reverse=True)
        return int(round(min(100.0, risks[0] + 0.2 * sum(risks[1:]))))

    def _attack_class(self, now_s: float, rf_label: str, rf_conf: float, rf_pnorm: float) -> tuple[str, float]:
        active: set[str] = set()
        for t, _, cats in self._records:
            if now_s - t <= RECENT_S:
                active |= cats
        for c in CLASS_PRIORITY:
            if c in active:
                cls = CLASS_OF[c]
                conf = max(0.95, rf_conf) if rf_label == cls else 0.95
                return cls, conf
        if "ml_attack" in active:
            return self._ml_label, rf_conf
        if self.models is not None and self.models.rf is not None:
            return "normal", rf_pnorm
        return "normal", 0.9
