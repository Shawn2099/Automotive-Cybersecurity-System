# Planned Features Specification

This document organizes all features discussed in `req.md` and `architecture.md` into actionable modules and priority tiers (`MVP` vs. `Phase 2 / Enhancement`).

---

## 1. ESP32 #1 — Car Simulator & Control Dashboard

Simulates a physical vehicle's ECUs and broadcasts real-time CAN bus traffic over `SN65HVD230` at 500 kbps.

### Core (MVP)

- **Wi-Fi Web Dashboard (Car Controls)**
  - Real-time sliders/inputs for:
    - Vehicle Speed (`0–200 km/h`)
    - Gear postion
    - Engine RPM (`0–7000 RPM`, with optional auto-sync to Speed)
    - Steering Angle (`-540°` to `+540°`)
    - Throttle & Brake Pressure (`0–100%`)
    - Coolant Temperature (`60–130 °C`) & Battery Voltage (`10.5–14.8 V`)
- **CAN Frame Transmission Engine**
  - Periodic TWAI broadcasting (`0x100` Powertrain, `0x110` Steering/Brake, `0x120` Thermal/Battery, `0x130` Safety/Heartbeat).
- **Fault Injection Controls**
  - Trigger **Engine Overheat** (coolant temp ramp + MIL flag).
  - Trigger **Battery / Alternator Drop** (voltage < 11.4 V).
  - Trigger **Sensor Inconsistency** (e.g., Speed > 80 km/h while RPM = 0).
- **Cyber-Attack Simulation Controls**
  - **CAN DoS / Bus Flood** (high-rate low-ID frames).
  - **Spoofed / Unknown CAN ID Injection** (unauthorized IDs such as `0x666`).
  - **Impossible Physics / Steering Attack** (instant extreme steering angle jumps at high speed).

### Phase 2

- **Multi-Vehicle Profile Switcher on Simulator**: Toggle between simulated vehicle brands (e.g., Maruti vs. Toyota CAN ID mappings/device IDs) from the simulator UI.
- **Recorded Drive Replay**: Play back realistic driving cycles (city idle, highway cruise, hard braking).

---

## 2. ESP32 #2 — Product Module (CAN Telemetry & Security Gateway)

Acts as the plug-and-play retrofittable vehicle interface (`req.md`).

### Core (MVP)

- **Read-Only CAN Acquisition**
  - Captures all CAN bus frames via ESP32 TWAI without transmitting control frames onto the vehicle bus.
- **Frame Batching & Bus Statistics**
  - Collects frames into 100 ms (10 Hz) batches alongside bus load % and RX error counts.
- **Encrypted LAN Transmission**
  - Encrypts each telemetry batch with **AES-128-GCM** (via ESP32 `mbedtls`) using a provisioned pre-shared key (`PSK`).
  - Attaches `device_id` + monotonic `seq_num` + unique 12-byte IV/nonce for integrity and replay protection.
- **Offline / Local LAN Resilience**
  - Streams directly to the local server IP over Wi-Fi without requiring internet or cellular connectivity.

### Phase 2

- **Local Ring-Buffer Caching**: Briefly buffer batches in RAM/LittleFS if LAN Wi-Fi momentarily drops, then flush on reconnect.
- **Secure Key Provisioning**: Store per-device `PSK` and `device_id` in ESP32 NVS (Non-Volatile Storage) rather than hardcoded strings.

---

## 3. Local LAN Edge Server (Python / FastAPI)

Runs locally on a laptop, Raspberry Pi, or NVIDIA Jetson for privacy-first, offline-capable processing.

### Core (MVP)

- **Decryption & Anti-Replay Gateway**
  - Authenticates AES-128-GCM tags, decrypts telemetry batches, and rejects replayed or out-of-order `seq_num` packets.
- **Multi-Brand CAN Decoder**
  - Decodes raw CAN IDs and bytes into physical values using configurable JSON/DBC vehicle profiles (supporting different brands such as Maruti and Toyota).
- **Sensor Consistency & Fault Detection**
  - Deterministic cross-sensor sanity checks (e.g., speed vs. RPM mismatch, throttle + brake conflict, thermal/voltage threshold breaches).
- **ML Predictive Maintenance & Anomaly Detection**
  - **Health / Anomaly Model (`IsolationForest` / `RandomForest` via `scikit-learn`)**: Detects abnormal multi-sensor patterns against healthy driving baselines.
  - **Trend Forecasting**: Tracks rolling slopes (e.g., rising coolant temp or dropping voltage) to warn before critical failure.
- **Component & Overall Vehicle Health Scoring (`0–100`)**
  - Individual health scores for **Engine**, **Thermal**, **Electrical**, and **Steering/Brakes**, combined into an overall `0–100` score.
- **CAN Cybersecurity Analytics & Risk Scoring (`0–100`)**
  - Detects DoS frame-rate spikes, unauthorized/unknown CAN IDs, timing jitter, impossible state transitions, and packet auth/replay failures.
- **Telemetry Storage (Local SQLite)**
  - Stores vehicle profiles, historical health/risk scores, and alert logs locally.

### Phase 2

- **Optional Encrypted Cloud Sync**: Background sync of anonymized summaries or alerts when internet is available (`req.md` line 60).
- **Dataset Export**: One-click CSV export of captured CAN traffic for retraining models.

---

## 4. Live User Monitoring Dashboard (Web App)

Unified interface for vehicle owners to monitor health, security, and multiple vehicles.

### Core (MVP)

- **Live Telemetry View (WebSockets)**
  - Real-time gauges/readouts for Speed, RPM, Steering Angle, Throttle, Brake, Coolant Temp, and Battery Voltage.
- **Health Score & Component Breakdown**
  - Prominent `0–100` overall vehicle health gauge plus per-subsystem health bars.
- **Cybersecurity Risk Monitor**
  - Real-time `0–100` cyber risk meter and live intrusion alert log (showing attack type: DoS, Spoofing, Unknown ID, Replay).
- **Multi-Car / Multi-Brand Management**
  - Single account/dashboard to add, select, and monitor multiple vehicles of any brand (e.g., Maruti + Toyota) mapped by `device_id` and CAN profile.
- **Voice Alerts**
  - Hands-free spoken alerts via browser Web Speech API (`window.speechSynthesis`) for critical mechanical faults or active cyber attacks (with cooldown throttling).

### Phase 2

- **Historical Trends & Trip Reports**: Time-series charts of health/risk scores and past fault events.
- **Raw CAN & Encryption Inspector Tab**: Side-by-side view of raw CAN hex frames vs. encrypted LAN packet vs. decrypted telemetry (great for project demos).

---

## 5. ML Models & Features Gained From Each

We combine lightweight classical ML and rule-based checks so the edge server runs fast on any laptop, Raspberry Pi, or Jetson without requiring heavy GPUs.

| Model / Engine                                                           | Role                                           | Input Features                                                                                                                           | Capabilities & Features Gained                                                                                                                                                                                                                                                                                                                                                                    |
| :----------------------------------------------------------------------- | :--------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **1. Deterministic Rule & Physics Engine**                         | Sanity & threshold checks                      | Speed, RPM, Throttle, Brake, Coolant Temp, Battery mV, CAN ID whitelist, `seq_num`                                                     | - Instant zero-training detection of hard faults (overheat > 105 °C, low battery < 11.5 V, MIL/ABS flags).- Cross-sensor consistency checks (e.g., Speed > 15 km/h while RPM = 0; simultaneous high throttle + brake).- Immediate rejection of unknown CAN IDs and AES-GCM replay/tamper attempts.                                                                                               |
| **2. `IsolationForest` (`scikit-learn`)**                      | Unsupervised vehicle health anomaly detection  | Normalized rolling window of `[RPM, Speed, Throttle, Brake, Coolant Temp, Battery mV, Steering Angle]`                                 | - Learns normal multi-sensor relationships using **only healthy driving data** (no need to collect every possible mechanical failure upfront).- Detects subtle combined-sensor drift (e.g., excessive RPM for current speed/throttle) even before hard thresholds trip.- Produces a continuous anomaly score that drives the **`0–100` Component & Overall Vehicle Health Score**. |
| **3. `RandomForestClassifier` / `XGBoost` (`scikit-learn`)** | Supervised CAN cybersecurity attack classifier | Windowed CAN bus traffic stats: `time_delta`, frames/sec, CAN ID frequency/entropy, payload byte deltas, steering rate `Δangle/Δt` | - Classifies the **specific attack category** instead of a generic warning: `Normal`, `DoS Flood`, `Fuzzy / Unknown ID`, or `Spoofing` (RPM/Speed/Steering).- Directly powers the **`0–100` Cybersecurity Risk Score**, attack alert feed, and targeted voice warnings.                                                                                                    |
| **4. Rolling Linear / Slope Forecaster (`numpy`)**               | Short-horizon predictive maintenance           | Last 30–60 s time-series of Coolant Temp, Battery Voltage, and Health Score                                                             | - Estimates **time-to-threshold** (e.g., predicts coolant overheating or battery drain 30–120 s *before* failure occurs).- Enables proactive *"maintenance/attention needed soon"* warnings in `req.md`.                                                                                                                                                                             |
| **5. *(Optional Phase 2)* Autoencoder / 1D-CNN**                 | Deep temporal sequence inspection              | Multi-channel time-series CAN signal matrix                                                                                              | - Catches stealthy replay/spoofing sequences where single values look valid on their own but break temporal driving patterns.                                                                                                                                                                                                                                                                     |

---

## 6. Software-First Implementation Plan (Skipping ESP32 for Now)

We will build and verify the entire software stack first by replacing the two ESP32 boards with a **Python Virtual Car + Encrypted Sender** that strictly follows the exact CAN frame map and AES-128-GCM packet format in `architecture.md`. Later, ESP32 #1 and #2 drop in without changing the server.

### Step 1 — Project Scaffold & Shared Wire Protocol (`server/` + `simulator/`)

- Set up Python project structure, `requirements.txt` (`fastapi`, `uvicorn`, `cryptography`, `scikit-learn`, `pandas`, `numpy`, `websockets`), and shared config.
- Implement the **AES-128-GCM crypto module** (`crypto.py`) with `device_id`, `seq_num` anti-replay protection, and JSON CAN-batch envelope.
- **Starting point**: Verify a test packet encrypted by the Python virtual sender decrypts cleanly on the server and rejects tampered/replayed packets.

### Step 2 — Multi-Brand CAN Decoder & Local Storage

- Build `can_decoder.py` with JSON vehicle CAN profiles (e.g., `sim_maruti_v1`, `sim_toyota_v1`) to normalize raw CAN IDs/bytes into physical telemetry.
- Set up local **SQLite** tables (`vehicles`, `telemetry_logs`, `alerts`) for multi-car ownership under one user.

### Step 3 — Synthetic Training Data & ML Model Training Pipeline

- Build `ml_training/generate_and_train.py` to generate realistic normal driving, mechanical fault, and cyber-attack CAN sequences (and optionally ingest the HCRL Car-Hacking Dataset).
- Train and save `health_isoforest.joblib` (Health Anomaly) and `cyber_rf.joblib` (CAN IDS Classifier) + evaluation metrics.

### Step 4 — Real-Time Analytics, Scoring & FastAPI Backend

- Wire incoming decrypted batches through:
  `Decode -> Rules -> IsolationForest -> RandomForest -> Slope Forecaster -> Health (0–100) & Cyber Risk (0–100)`.
- Expose REST endpoints (`/vehicles`, `/alerts`, `/history`) and live WebSocket streams (`/ws/telemetry`) for the dashboard.

### Step 5 — Live User Dashboard, Virtual Car Control UI & Voice Alerts

- Build the **User Monitoring Dashboard**: vehicle switcher (Maruti/Toyota), live gauges, component health bars, cyber risk meter, encrypted packet inspector, and browser `window.speechSynthesis` voice alerts.
- Build a **Web Virtual Car Controller** (temporary browser replacement for ESP32 #1) with sliders + Fault/Attack trigger buttons so you can demo the complete system live on one PC before flashing hardware.

---

## 7. Reference Sources (GitHub Repositories & Datasets)

### Machine Learning & CAN Intrusion Detection (Active for SW Phase)

- **CAN-Bus-Sentinel-IDS** (Rule-based checks + Isolation Forest + web dashboard): https://github.com/AlCodes808/CAN-Bus-Sentinel-IDS
- **Western-OC2-Lab — ML IDS** (Decision Tree, Random Forest, XGBoost for CAN bus IDS): https://github.com/Western-OC2-Lab/Intrusion-Detection-System-Using-Machine-Learning
- **Western-OC2-Lab — CNN & Transfer Learning IDS** (Deep learning reference): https://github.com/Western-OC2-Lab/Intrusion-Detection-System-Using-CNN-and-Transfer-Learning
- **CANShield** (Signal-level Deep Autoencoder framework for CAN time-series): https://github.com/shahriar0651/CANShield
- **HCRL Car-Hacking Dataset** (Real CAN logs with DoS, Fuzzy, Gear & RPM spoofing): https://ocslab.hksecurity.net/Datasets/CAN-intrusion-dataset

### ESP32 CAN & Simulator References (For Later Hardware Phase)

- **esp-can-scanner** (ESP32 TWAI + SoftAP web UI + ring buffer): https://github.com/phlangone/esp-can-scanner
- **esp32-obd2-emulator** (ESP32 Wi-Fi web-controlled OBD-II CAN emulator): https://github.com/limiter121/esp32-obd2-emulator
- **ESP32-ECU-emulator** (500 kbps CAN bench ECU simulator): https://github.com/coniferconifer/ESP32-ECU-emulator

### Vehicle Health & Predictive Maintenance Datasets / Pipelines

- **Predictive-Maintenance-for-Vehicules** (EDA + ML anomaly/health classification notebooks on engine sensor data): https://github.com/nassriayman/Predictive-Maintenance-for-Vehicules
- **ML-Based-Vehicle-Predictive-Maintenance-System-with-Real-Time-Visualization** (Gradient Boosting on real-time sensor streams + failure probabilities): https://github.com/iDharshan/ML-Based-Vehicle-Predictive-Maintenance-System-with-Real-Time-Visualization
- **OBDdatasets** (Real OBD-II driving telemetry captures by Cephas Barreto): https://github.com/cephasax/OBDdatasets
- **pmx_data** (CMU Auton Lab curated index of predictive maintenance benchmarks): https://github.com/autonlab/pmx_data
- **Kaggle Datasets**: `Automotive Vehicles Engine Health Dataset` (`engine_data.csv`) and `OBD-II datasets` (Cephas Barreto)

---

## 8. Build Effort & Two-Track Dataset Strategy

### Estimated Difficulty by Layer

- **Encrypted LAN Server & Multi-Car DB** (`FastAPI`, `AES-128-GCM`, `SQLite`, `WebSockets`): **Easy → Moderate**
- **Live User Dashboard & Voice Alerts** (`HTML/JS` gauges + `window.speechSynthesis`): **Easy**
- **ML Anomaly & Scoring Engine** (`IsolationForest`, `RandomForest`, sliding-window features & false-positive tuning): **Moderate**
- **ESP32 Hardware & CAN Wiring (Later Phase)**: **Moderate** (`SN65HVD230` 3.3 V transceivers, 120 Ω bus termination, 2-node ACK behavior)

### Two-Track ML Dataset Strategy

Public datasets do not match our custom CAN IDs (`0x100–0x130` / `0x300–0x330`) or exact signal set one-to-one. We will use:

1. **Runtime Models (Live Server)**: Trained on synthetic normal, fault, and cyber-attack telemetry matching our exact CAN frame schema so live demos score reliably.
2. **Benchmark Validation (Report / Evaluation)**: Evaluate the same `RandomForest` / `IsolationForest` pipeline on the **HCRL Car-Hacking Dataset** (and Kaggle Engine Health / OBD-II datasets) to prove real-world accuracy.
