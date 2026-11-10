# System Architecture & Technical Specification

> Technical blueprint implementing the requirements in `req.md` using a **2-ESP32 CAN bus bench setup** (Car Simulator + Telemetry/Security Module) and an **encrypted local LAN Python server**.

---

## 1. High-Level Architecture

```
+-----------------------------------+          CAN Bus (500 kbps)          +-----------------------------------+
|      ESP32 #1: Car Simulator      |   CANH ------------------------ CANH |    ESP32 #2: Product Module       |
|  - Wi-Fi AP/STA + Web Dashboard   |   CANL ------------------------ CANL |  - TWAI (CAN) Frame Collector     |
|  - Sliders: Speed, RPM, Steering  |   120Ω                          120Ω |  - Batching + AES-128-GCM Encrypt |
|  - Fault & Cyber Attack Toggles   |        (via SN65HVD230 x 2)          |  - TLS / TCP Client over Wi-Fi    |
+-----------------------------------+                                      +-----------------+-----------------+
                                                                                             |
                                                                           Encrypted LAN     | (Wi-Fi -> Local IP)
                                                                           Payload + Nonce   v
                                                                           +-----------------------------------+
                                                                           |   Local Edge Server (Python)      |
                                                                           |  - FastAPI + WebSocket Backend    |
                                                                           |  - Decryption & Replay Guard      |
                                                                           |  - DBC/Profile Decoder (Multi-Car)|
                                                                           |  - ML Health & Cyber Risk Engine  |
                                                                           |  - Live User Dashboard + Voice    |
                                                                           +-----------------------------------+
```

---

## 2. Hardware Bill of Materials & Wiring

### Required Hardware
- **2× ESP32 DevKit** (ESP32-WROOM-32 or ESP32-S3 — avoid ESP32-C2/single-core variants without TWAI)
- **2× `SN65HVD230` 3.3 V CAN Transceiver Modules** (preferred over 5 V TJA1050 so no level shifters are needed)
- Jumper wires + twisted pair (2 wires) for `CANH` and `CANL`
- Multimeter (to verify ~60 Ω across `CANH`–`CANL` with power off, confirming two 120 Ω terminators)

### Pinout (Both ESP32s)
| ESP32 Pin | `SN65HVD230` Pin | Notes |
| :--- | :--- | :--- |
| `GPIO 21` (or `GPIO 5`) | `CTX` / `TXD` | TWAI TX |
| `GPIO 22` (or `GPIO 4`) | `CRX` / `RXD` | TWAI RX |
| `3V3` | `VCC` | Strict 3.3 V |
| `GND` | `GND` | Common ground (keep shared GND or clean twisted pair) |

### TWAI Mode Note (Important for 2-Node Bench)
- On a 2-node CAN bus, if ESP32 #2 is set to `TWAI_MODE_LISTEN_ONLY`, it will not send hardware ACK bits and ESP32 #1 will enter bus-error state.
- **Bench Solution**: Run ESP32 #2 in `TWAI_MODE_NORMAL` at the driver level while **enforcing read-only behavior in firmware** (never calling `twai_transmit()`), OR send frames with `TWAI_MSG_FLAG_SELF` / `NO_ACK` on ESP32 #1 when testing strict listen-only mode.

---

## 3. CAN Bus Frame Map & Multi-Brand Profiles

Standard bitrate: **500 kbps** (11-bit standard CAN IDs).  
To support **multi-car / multi-brand monitoring** (`req.md` lines 76–79: e.g., Maruti + Toyota in one app), the server stores a **CAN Profile** per vehicle (`profile_id`: `generic_obd`, `maruti_profile`, `toyota_profile`) mapping CAN IDs and byte layouts to normalized telemetry signals.

### Default Simulator CAN IDs (Profile: `sim_v1`)

| CAN ID (Hex) | Subsystem | Period | Byte Layout (Big-Endian / Unsigned unless noted) | Scaling / Units |
| :--- | :--- | :--- | :--- | :--- |
| `0x100` | Powertrain | 50 ms (20 Hz) | `B0-B1`: RPM (`uint16`), `B2`: Speed (`uint8`), `B3`: Throttle % (`uint8`) | RPM × 1, km/h × 1, % (0–100) |
| `0x110` | Steering / Chassis | 50 ms (20 Hz) | `B0-B1`: Steering Angle (`int16`), `B2`: Brake Pressure (`uint8`), `B3`: Gear (`uint8`) | Angle × 0.1 deg (-540.0 to +540.0), bar (0–200), 0=P/N, 1–6 |
| `0x120` | Thermal / Battery | 200 ms (5 Hz) | `B0`: Coolant Temp (`uint8`), `B1`: Oil Temp (`uint8`), `B2-B3`: Battery mV (`uint16`) | Temp = `raw - 40` (°C), mV × 1 (e.g., 12600 = 12.6 V) |
| `0x130` | Safety / Flags | 200 ms (5 Hz) | `B0`: ABS/ESC/MIL bitmask, `B1`: Fuel Level % (`uint8`), `B2-B3`: Heartbeat Counter (`uint16`) | Bit 0=MIL, Bit 1=ABS Fault, Bit 2=Overheat |

### Multi-Car Switching Strategy
- Each ESP32 #2 has a provisioned `device_id` (e.g., `0x0001` for Car 1, `0x0002` for Car 2) bound to a vehicle record in the server DB (`brand`, `model`, `plate`, `can_profile`).
- In a 1-pair bench demo, the Simulator Web UI can also include a **Vehicle Profile Switcher** (e.g., *Maruti Swift* vs. *Toyota Corolla*) that switches the active `device_id` / CAN ID offset (`+0x200` for Toyota profile) so you can demonstrate switching cars live in the same dashboard.

---

## 4. Simulator Controls, Fault Injection & Attack Modes (ESP32 #1)

ESP32 #1 serves a responsive local web page (hosted via `ESPAsyncWebServer` + WebSocket) with two control tabs:

### A. Driving Controls (Real-Time)
- **Vehicle Speed** (`0 – 200 km/h`)
- **Engine RPM** (`0 – 7000 RPM`, with optional "Auto-link RPM to Speed/Gear" toggle)
- **Steering Angle** (`-540° to +540°`)
- **Throttle & Brake** (`0 – 100%`)
- **Coolant Temp** (`60 – 130 °C`) & **Battery Voltage** (`10.5 – 14.8 V`)

### B. Fault & Cyber-Attack Simulation Toggles
1. **Engine Overheat / Cooling Fault**: Gradually ramps coolant temp > 110 °C while triggering MIL flag.
2. **Battery / Alternator Failure**: Drops voltage below 11.4 V under load.
3. **Sensor Inconsistency Fault**: Reports Speed = 100 km/h while RPM = 0 (or Brake = 90% while accelerating).
4. **CAN DoS / Bus Flood Attack**: Floods `0x001`–`0x050` at high frequency (> 500 frames/sec).
5. **CAN Spoofing / Unauthorized ID Attack**: Injects unknown CAN ID (`0x666` or `0x7DF`) or erratic steering jumps (`-450°` → `+450°` in 50 ms at high speed).

---

## 5. Encrypted LAN Transport (ESP32 #2 -> Local Server)

Rather than encrypting every raw 8-byte CAN frame separately (which adds overhead and Wi-Fi jitter), **ESP32 #2 batches CAN frames every 100 ms (10 Hz)** and sends an encrypted telemetry envelope over **TCP (or WebSocket) on the LAN**.

### Envelope Format (AES-128-GCM)
Every packet sent by ESP32 #2 has:

```
+---------------+---------------+---------------+-------------------------------+-------------------+
| device_id (2B)| seq_num (4B)  | iv/nonce (12B)| ciphertext (N bytes)          | auth_tag (16B)    |
+---------------+---------------+---------------+-------------------------------+-------------------+
```

- **Key**: Pre-shared 128-bit device key (`PSK`) provisioned per `device_id` (stored in NVS on ESP32 #2 and `.env`/DB on the server).
- **AAD (Additional Authenticated Data)**: `device_id || seq_num` (prevents tampering with metadata).
- **Nonce**: `4B device_id/boot_salt || 4B seq_num || 4B millis_lsb` (strictly unique per packet for a given key).
- **Replay Protection**: Server tracks `last_seq_num` per `device_id` and rejects packets where `seq_num <= last_seq_num` (unless a signed/authenticated session-reset handshake occurs on reboot).
- **Plaintext Payload (inside ciphertext)** — compact binary or JSON:
  ```json
  {
    "ts_ms": 184220,
    "bus_load_pct": 14,
    "rx_err": 0,
    "frames": [
      {"id": 256, "dlc": 4, "data": "09C43C28"},
      {"id": 272, "dlc": 4, "data": "FFCE0003"}
    ]
  }
  ```

> **Alternative**: Use TLS 1.2/1.3 (`WiFiClientSecure` on ESP32 + `ssl` in Python FastAPI/Uvicorn) with a self-signed local CA certificate. AES-128-GCM at the packet layer is recommended here because it keeps the encryption visible and inspectable for cybersecurity demos (you can log ciphertext vs decrypted plaintext and test replay/tamper rejection directly).

---

## 6. Local Server Analytics & Scoring Engine (Python)

### Pipeline per Incoming Packet
1. **Decrypt & Verify**: Authenticate AES-GCM tag and check `seq_num` freshness.
2. **Decode Signals**: Look up `device_id` -> `vehicle` -> `can_profile`, decode raw CAN frames into physical values.
3. **Rule + ML Analysis**:
   - **Sensor Consistency Rules**:
     - Speed > 15 km/h while RPM == 0 -> Mechanical/Sensor fault
     - High throttle + high brake simultaneously -> Sensor/Pedal inconsistency
     - Physically impossible steering rate (`|Δangle / Δt|` > threshold at Speed > 60 km/h) -> Spoofing / Cyber anomaly
   - **ML Predictive & Anomaly Model (`scikit-learn`)**:
     - Sliding window (last 3–5 seconds of speed, RPM, coolant temp, voltage, steering variance, CAN frame rate).
     - `IsolationForest` (or lightweight `RandomForestClassifier` trained on simulated normal vs. fault/attack logs) outputs an anomaly score.
     - Trend forecasting (linear/exponential slope on coolant temp and battery voltage) flags **upcoming overheating / battery drain** before threshold breach.
4. **Scoring Formulas (0–100)**:
   - **Component Health Scores** (`Engine`, `Thermal`, `Electrical`, `Steering/Brakes`): Start at `100`, deduct weighted penalties for rule violations, forecast drift, and ML anomaly confidence.
   - **Overall Vehicle Health Score** (`0–100`): Weighted average of component scores.
   - **Cybersecurity Risk Score** (`0–100`, where `0` = safe, `100` = active attack): Driven by frame-rate spikes (DoS), unknown CAN IDs, timing jitter anomalies, impossible state jumps, and failed packet auth/replay attempts.

### User Dashboard (Web UI)
- **Vehicle Switcher**: Dropdown/cards for all registered vehicles (e.g., *Maruti Swift*, *Toyota Innova*).
- **Live Gauges & Charts**: Speed, RPM, Steering wheel indicator, Coolant Temp, Battery Voltage.
- **Health & Security Panel**: Overall Health Score (`0–100`), per-component bars, Cybersecurity Risk meter, and live Alert Feed.
- **Voice Alerts**: Browser `window.speechSynthesis` announces high-severity faults or cyber attacks with cooldown throttling (e.g., max once every 10 seconds).

---

## 7. Proposed Repository Layout

```text
automotive-cybersecurity-project/
├── req.md
├── architecture.md
├── firmware/
│   ├── car_simulator_esp32/      # ESP32 #1: Web sliders + fault/attack injection + CAN TX
│   └── product_module_esp32/     # ESP32 #2: CAN RX + batching + AES-128-GCM + LAN client
└── server/
    ├── app/
    │   ├── main.py               # FastAPI + WebSocket + TCP telemetry listener
    │   ├── crypto.py             # AES-128-GCM decrypt + replay check
    │   ├── can_decoder.py        # Multi-brand CAN profile decoder
    │   ├── ml_engine.py          # Consistency checks, ML anomaly & health/risk scoring
    │   └── models.py             # Vehicle & telemetry schemas (SQLite)
    ├── ml_training/              # Script to generate synthetic CAN dataset & train model
    ├── dashboard/                # Frontend (HTML/JS/CSS live gauges + vehicle switcher + voice)
    └── requirements.txt
```

---

## 8. Implementation Milestones

1. **Milestone 1 (Firmware Base)**: PlatformIO / Arduino skeletons for both ESP32s + basic CAN ping-pong verification.
2. **Milestone 2 (Simulator UI)**: ESP32 #1 web dashboard with driving sliders and fault/attack toggles.
3. **Milestone 3 (Encrypted Pipe)**: ESP32 #2 AES-128-GCM packet streaming + Python server receiver & decoder.
4. **Milestone 4 (AI + Live Dashboard)**: Synthetic dataset generator, trained `scikit-learn` model, health/cyber scoring, multi-car switching, and voice-enabled dashboard.

