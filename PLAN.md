# PoC Plan: what we keep, cut and change

This plan replaces the build plan in `architecture.md` / `features.md` §6. Those docs remain the background.
Scope: a **proof of concept**. No production hardening. ESP32 firmware is **out of scope for now**. A Python
virtual car and a Python virtual product module stand in for the two boards, and they use the same wire protocol
that the firmware will use later.

---

## 1. Where the original plan is wrong or too big

| # | Original plan | Problem | Decision |
|---|---|---|---|
| 1 | "Edge device (Pi/Jetson)" + "optional cloud" + "local LAN server" | Three roles for one laptop. The docs say "LAN only", but you want it **over the internet via Wi-Fi**. | The laptop is the **edge server**. No cloud sync in the PoC. The tunnel is end-to-end encrypted at the app layer, so it works the same over a LAN, a port-forward, ngrok or Tailscale. |
| 2 | AES-GCM envelope **or** TLS (both listed) | Two schemes means two things to debug on the ESP32. | **One scheme**: PSK-authenticated session handshake + AES-128-GCM frames (§3). No TLS. Every byte stays inspectable for the demo. |
| 3 | Raw TCP on :9000 | TCP has no message framing, so you would have to add length prefixes. | **Binary WebSocket** at `/ws/ingest` on the same FastAPI app. That gives one process, one port and built-in framing. ESP32 has `arduinoWebSockets` / `esp_websocket_client`. |
| 4 | `ReplayGuard` keyed on `device_id`, `seq <= last` is rejected | When the ESP32 reboots, `seq` restarts at 0 and the device is **locked out forever**. When the server restarts, it forgets everything and accepts old replays. The "signed session-reset handshake" was never specified. | A **per-connection session key** from a challenge-response handshake. Each connection restarts `seq` at 1. Old packets fail the tag under the new key, so cross-session replay is impossible, and no state needs to survive restarts. |
| 5 | Nonce in code = `device_id‖seq‖random6` per packet; doc says `‖millis` | Mismatch between code and doc. | `device_id(2)‖seq(4)‖session_salt(6)`. The salt is drawn **once per session**, and `seq` is unique within a session, so nonces never repeat under one key. |
| 6 | Batch = every raw frame every 100 ms | Under a DoS flood the bus carries thousands of frames/s. That won't fit in one ESP32 packet and makes JSON huge. | **Bounded batch**: latest frame per CAN ID + per-ID frame **counts** + bus stats (§4). Rate, unknown-ID, heartbeat and steering-rate features all survive. |
| 7 | 5 ML models (rules, IsolationForest, RF/XGBoost, slope, autoencoder/CNN) + HCRL benchmark | Too much. A model trained on the simulator's own synthetic data **mostly learns the simulator**. The rules would catch the same attacks. | **Rules carry the demo**. ML adds: IsolationForest (health anomaly score), RandomForest (attack-class label + confidence), numpy slope forecaster (time-to-threshold). **Cut**: XGBoost, the autoencoder/CNN, and the HCRL benchmark (Phase 2, report only). |
| 8 | "Toyota profile = Maruti IDs + 0x200" | This is **not** brand support. Real cars use proprietary CAN (DBC) maps. The only cross-brand standard is OBD-II PIDs, which need the module to **transmit** requests, and that conflicts with "read-only". | Keep the per-vehicle `can_profile` mechanism (it is the right abstraction). Label the profiles honestly as **simulated stand-ins**. Real brand support means adding a DBC-derived profile. The read-only vs OBD-II polling trade-off is listed as an open question. |
| 9 | Multi-user (`owner_id`) | req.md lines 76–79 ask for **one app showing many cars of any brand**, not multiple users. | Single owner. The dashboard has a vehicle switcher and an "all cars" overview. `owner_id` stays in the DB, unused. |
| 10 | Encryption attacks listed (Replay, auth failure), but nothing generates them | The encryption half of the demo would have nothing to show. | The virtual product module has **tunnel attack toggles**: replay old packet, flip a ciphertext byte, wrong key. Each one shows up as a cyber alert. |
| 11 | Health = 100 minus deducted penalties | A running deduction never recovers after the fault clears. | Scores come from a **rolling window** (last ~5 s), so they recover. Alerts are **debounced** per (vehicle, category), with a 10 s cooldown. This also throttles voice. |
| 12 | Log every 100 ms packet to SQLite | That is 36k rows/h per car for no benefit. | Store telemetry at **1 Hz** and all alerts. Keep the live stream in memory. |
| 13 | pandas, XGBoost, websockets lib, TCP listener | Unneeded dependencies. | `fastapi`, `uvicorn`, `cryptography`, `numpy`, `scikit-learn`, `joblib`, `pytest`, `httpx`. |

Things we keep as they are: the CAN frame map (`0x100–0x130`), the `common/can_profiles.py` encode/decode, the
`server/app/database.py` schema, AES-128-GCM with a 16-byte PSK per device, the browser `speechSynthesis` voice alerts,
and the read-only product module.

### Open questions (not blocking the PoC)
- Real car support: will the product module **passively sniff** brand CAN (needs DBC per brand, stays read-only) or
  **poll OBD-II PIDs** (works on any brand, but must transmit)? This decides what "retrofittable" means.
- Over the internet: the laptop sits behind NAT. For the demo, use the same Wi-Fi, or Tailscale/ngrok TCP. The protocol does not care which.

---

## 2. Architecture (PoC)

```
 simulator/ (one Python process, replaces both ESP32s)              server/ (laptop, FastAPI :8000)
 ┌─────────────────────────────┐                                  ┌────────────────────────────────────┐
 │ Car Controller web UI :8100 │  sliders/faults/attacks          │ /ws/ingest  (binary WS)            │
 │   (= ESP32 #1 dashboard)    │                                  │   handshake → session key          │
 │ VirtualCar  (common/        │ frames                           │   decrypt → ReplayGuard            │
 │   vehicle_sim.py) per car   │────────► VirtualProductModule ──►│   decode (can_profile per vehicle) │
 │                             │          (= ESP32 #2)   WS, AES  │   analytics (rules+ML) → scores    │
 └─────────────────────────────┘          tunnel attacks          │   SQLite (1 Hz + alerts)           │
                                                                  │ /ws/live  → User Dashboard (/ )    │
                                                                  │ REST /api/vehicles /alerts /history│
                                                                  └────────────────────────────────────┘
```
Later, ESP32 #1 replaces `VirtualCar` + controller UI, and ESP32 #2 replaces `VirtualProductModule`. The server does not change.

---

## 3. Contract A: the encrypted tunnel (`common/tunnel.py`)

Transport: one WebSocket connection per device to `ws://<server>:8000/ws/ingest`. All messages are binary.

Handshake (mutual PSK authentication, fresh session key per connection):
```
S → D  CHALLENGE  : b"CH" ‖ server_nonce(16)
D → S  HELLO      : b"HE" ‖ device_id(2, BE) ‖ device_nonce(16) ‖ mac_d(16)
        mac_d = HMAC-SHA256(PSK, b"HELLO" ‖ device_id ‖ server_nonce ‖ device_nonce)[:16]
S → D  WELCOME    : b"OK" ‖ mac_s(16)
        mac_s = HMAC-SHA256(PSK, b"WELCOME" ‖ device_id ‖ server_nonce ‖ device_nonce)[:16]
        session_key = HMAC-SHA256(PSK, b"SESSION" ‖ server_nonce ‖ device_nonce)[:16]
   on failure  S → D  b"NO" ‖ reason (utf-8), then close
D → S  DATA       : b"DA" ‖ envelope    (envelope = common/crypto.py encrypt_envelope with session_key,
                                         seq starting at 1, boot_salt = session salt drawn once)
```
Server rules: verify the tag first, then `ReplayGuard.check_and_update` (one guard per session). An auth failure or replay
is counted against that `device_id` as a cyber event, and the server **does not** close the connection on a bad packet
(it drops that packet). Unknown `device_id` or bad `mac_d` → `NO` + close, and an `auth_fail` cyber event is logged.

## 4. Contract B: the plaintext batch (inside DATA, JSON)
```json
{
  "ts_ms": 184220,                       // device monotonic ms
  "window_ms": 100,
  "frames": [{"id": 256, "dlc": 4, "data": "09C43C28"}],   // LATEST frame per CAN ID seen in window
  "counts": {"256": 2, "272": 2, "102": 412},                // frames per CAN ID in window (string keys)
  "bus_load_pct": 14,
  "rx_err": 0
}
```

## 5. Contract C: decoded signals (from `common.can_profiles.decode_can_frames`)
`rpm, speed_kmh, throttle_pct, steering_deg, brake_bar, gear, coolant_c, oil_c, battery_v, flags, fuel_pct, heartbeat`
`flags` bit0 = MIL, bit1 = ABS fault, bit2 = overheat.

## 6. Contract D: analytics (`server/app/analytics.py`)
```python
class VehicleAnalyzer:                       # one instance per device_id, keeps rolling state
    def __init__(self, profile_id: str, models: "Models | None" = None): ...
    def update(self, batch: dict, decoded: dict, now_s: float) -> dict: ...   # returns AnalysisResult
    def record_tunnel_event(self, kind: str, now_s: float) -> None: ...       # kind: "auth_fail"|"replay"|"tamper"
    def drain_alerts(self, now_s: float) -> list[dict]: ...                   # pending alerts without a batch (tunnel events)
def load_models(model_dir: Path) -> "Models | None"  # None → rules-only (must still work)
```
AnalysisResult:
```json
{
  "health": {"overall": 92, "engine": 95, "thermal": 88, "electrical": 97, "steering_brakes": 100},
  "cyber_risk": 12,
  "attack_class": "normal",          // normal | dos | fuzzy_unknown_id | spoofing | tunnel_attack
  "attack_confidence": 0.93,
  "anomaly_score": 0.08,             // 0..1 from IsolationForest (0 if no model)
  "forecast": [{"signal": "coolant_c", "eta_s": 42, "threshold": 110}],
  "alerts": [{"category": "overheat", "kind": "mechanical", "severity": "high", "message": "Coolant 112 °C"}]
}
```
`alerts` contains only **newly raised** alerts (already debounced, 10 s cooldown per category). Scores come from a rolling ~5 s window.
Alert categories: mechanical `overheat, low_battery, sensor_inconsistency, mil_on, abs_fault, forecast_overheat,
forecast_battery, health_anomaly`; cyber `dos, unknown_id, spoofing_steering, heartbeat_anomaly, auth_fail, replay, tamper`.
Severity: `low | medium | high | critical`.

## 7. Contract E: dashboard live stream (`/ws/live`, JSON text, server → browser, ≤10 Hz per car)
```json
{"type": "telemetry", "device_id": 1, "signals": {...Contract C...}, "analysis": {...Contract D...},
 "link": {"connected": true, "packets_ok": 1234, "packets_rejected": 3, "last_cipher_hex": "a1b2..", "last_plain": {...}}}
{"type": "alert", "device_id": 1, "alert": {...}, "ts": "ISO8601"}
{"type": "link", "device_id": 1, "connected": false}
```

## 8. Contract F: shared vehicle model (`common/vehicle_sim.py`)
Shared by the simulator and the ML training-data generator, so the models train on the same physics the demo produces.
```python
FAULTS  = ["overheat", "battery_drain", "sensor_inconsistency"]
ATTACKS = ["dos", "unknown_id", "steering_spoof"]
class VirtualCar:
    def __init__(self, profile_id: str, seed: int | None = None): ...
    controls: dict            # speed_kmh, steering_deg, throttle_pct, brake_pct, coolant_c, battery_v, auto_rpm(bool), rpm, gear
    faults: set[str]; attacks: set[str]
    def step(self, dt: float) -> list[dict]   # advance physics by dt seconds, return CAN frames emitted during dt
    def state(self) -> dict                   # current physical state (Contract C keys)
def summarize_window(frames: list[dict], window_ms: int) -> dict   # → Contract B batch (minus ts_ms)
```

---

## 9. Repository layout and ownership
```
common/            can_profiles.py, crypto.py (kept), tunnel.py, vehicle_sim.py (new, written first)
simulator/         car controller web UI + VirtualProductModule + tunnel attack toggles     ← agent: simulator
ml_training/       generate_dataset.py, train.py → server/models/*.joblib                  ← agent: analytics
server/app/        analytics.py                                                             ← agent: analytics
server/app/        main.py (FastAPI, /ws/ingest, /ws/live, REST), dashboard/ (static)      ← agent: server
tests/             pytest per module; tools/e2e_demo.py (end-to-end check)
```

## 9b. Real data and proven tools (from RESEARCH.md)
The **live demo models stay trained on simulator data**. Public datasets don't share our CAN IDs. Real data comes in as a separate **benchmark track** (Phase 2, `ml_training/benchmark_hcrl.py`):
1. **HCRL Car-Hacking** (academic use): run the same RF traffic features on it and report per-class F1 for DoS, fuzzy and spoofing. This gives real-world evidence for the cyber model. **ROAD** shows its limits honestly.
2. **KIT OBD-II** (CC-BY): fit the IsolationForest "normal driving" baseline and calibrate rule thresholds on real RPM/speed/coolant relationships.
3. **opendbc + cantools**: the path from stand-in brand profiles to real brand decoding. A `can_profile` becomes a DBC file.
4. Battery-fault data does not exist publicly. Keep it synthetic, and say so in the report.

## 9c. v2: the bench car follows the HCRL Car-Hacking spec (supersedes §5, §8 and the Maruti/Toyota profiles)
**Decision**: the PoC targets **one car**, the ESP32 bench car. It is specced as the HCRL Car-Hacking dataset car (Hyundai YF Sonata),
so the cyber model can be trained or benchmarked on real attack data and still run on our car unchanged. The portal can still
**register** more cars (any brand), but those cars only stream once a profile and a device exist for them.
- Profile: `common/profiles/hyundai_sonata_hcrl.json`. It uses DBC-style signals (Intel bit order), with layouts from opendbc `hyundai_can.dbc`.
  Some fields are marked `assumed`: the gear message 0x43F, three of the wheel channels, brake pressure, and all periods. `ml_training/hcrl_import.py` replaces the periods with values measured from the HCRL normal data.
- Messages: 0x316 EMS11 (rpm, speed_kmh), 0x329 EMS12 (coolant_c), 0x260 EMS16 (throttle_pct ≈ torque), 0x2B0 SAS11 (steering_deg),
  0x43F (gear), 0x386 WHL_SPD11 (whl_fl/fr/rl/rr_kmh), 0x220 ESP12 (brake_bar, long_accel), 0x4F1 CLU11 (clu_speed_kmh), 0x549 BAT11 (battery_v).
  Normal traffic is ≈ 660 frames/s, about 17 % bus load.
- **Signals (replaces Contract C)**: `rpm, speed_kmh, throttle_pct, steering_deg, gear, coolant_c, battery_v, brake_bar, long_accel,
  whl_fl_kmh, whl_fr_kmh, whl_rl_kmh, whl_rr_kmh, clu_speed_kmh`. Dropped: `oil_c, flags, fuel_pct, heartbeat`, because this car has no such messages.
- **Attacks (replaces ATTACKS)**: `dos` (0x000 every 0.3 ms), `fuzzy` (random ID/payload every 0.5 ms), `rpm_spoof` (0x316 every 1 ms),
  `gear_spoof` (0x43F every 1 ms), `steering_spoof` (0x2B0 every 1 ms, our extra). These are the HCRL injection rates.
- **attack_class**: `normal | dos | fuzzy | spoofing | tunnel_attack`.
- **Cyber alert categories**: `dos, fuzzy, spoofing_rpm, spoofing_gear, spoofing_steering, auth_fail, replay, tamper`.
  **Mechanical**: `overheat, low_battery, sensor_inconsistency, forecast_overheat, forecast_battery, health_anomaly`.
  sensor_inconsistency covers EMS speed vs wheel/cluster speed mismatch, speed>15 with rpm<300, and throttle+brake conflict.
- Cyber features are **relative to the profile**: rate of each known ID ÷ expected rate (spoofing = a known ID far above its rate),
  unknown-ID rate and number of distinct unknown IDs (one ID flooding = dos, many random IDs = fuzzy), and total rate / bus load.
- HCRL path: `ml_training/hcrl_import.py` cuts the raw HCRL logs into the same 100 ms Contract-B batches. Train and serve then compute identical features.
  When the dataset folder is present, the RF trains on real HCRL data. Otherwise it trains on the Sonata-spec simulator.

### 9d. What the real HCRL data confirmed (2026-11-10, dataset in `data/hcrl/`, gitignored)
- **Normal bus**: 27 IDs, about 1,950 frames/s. The measured periods and base payloads are now in the profile (`periods_source: hcrl_measured`).
  The simulated car emits all 27 IDs, plus 4 extras the HCRL car does not carry (0x386 wheel speeds, 0x220 brake/accel, 0x4F1 cluster speed,
  0x549 battery). The extras are marked `in_hcrl: false`.
- **opendbc layouts decode real traffic plausibly**: rpm 525–2229, speed 0–49 km/h, coolant 83–95 °C, steering ±520°, throttle 0–61 %.
- **Attack targets confirmed**: RPM spoof = 0x316, payload `45 29 24 FF 29 24 00 FF`. Gear spoof = 0x43F, payload `01 45 60 FF 6B 00 00 00`.
  DoS = 0x000 zeros. The simulator now injects these exact frames.
- **Not confirmed**: the gear bit layout in 0x43F. Byte 0 is not a clean gear field, so decoded gear is shown as indicative only.
  Gear-spoof detection uses the message rate, so it does not depend on this layout.

## 10. Done means
`tools/e2e_demo.py` starts the server and two virtual cars (Maruti + Toyota profiles). It triggers each fault and each
attack (CAN and tunnel). For each one, it asserts that the expected alert category appears and the score moves the right way.
It then clears the trigger and asserts the score recovers. `pytest` passes. The README explains how to run the demo.
