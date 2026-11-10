# Automotive Telematics + CAN Cybersecurity: proof of concept

A car (ESP32 #1, simulated for now) puts CAN frames on the bus. The product module (ESP32 #2, simulated for now) reads them
**read-only**, batches them, and sends them through a **PSK-authenticated AES-128-GCM tunnel** over Wi-Fi/internet to a
laptop server. The server decodes per-brand CAN profiles, runs rules + ML, scores health (0–100) and cyber risk (0–100),
and streams everything to a dashboard (one live bench car; more cars can be registered) with voice alerts.

Read [`PLAN.md`](PLAN.md) for what changed from `architecture.md`/`features.md` and why, plus the frozen interfaces.
[`RESEARCH.md`](RESEARCH.md) lists prior work and public datasets.

## Run the demo
```powershell
pip install -r requirements.txt
python -m server.app.main                                              # server + dashboard -> http://localhost:8000
python -m simulator --server ws://127.0.0.1:8000/ws/ingest --port 8100 # bench-car stand-in + controller -> http://localhost:8100
```
- **Port 8000 busy?** Set `TELEMETRY_HTTP_PORT` for the server and point the simulator at the same port with `--server`:
  ```powershell
  $env:TELEMETRY_HTTP_PORT = "8001"; python -m server.app.main
  python -m simulator --server ws://127.0.0.1:8001/ws/ingest --port 8100   # default follows TELEMETRY_HTTP_PORT if set in that shell
  ```
- The PoC has **one car**: the ESP32 **bench car**, specced as the HCRL Car-Hacking vehicle (Hyundai YF Sonata, profile `hyundai_sonata_hcrl`, device 1, PSK from `PSK_DEVICE_1`, default `0011...eeff`). The simulator stands in for it (~660 CAN frames/s, up to ~4000/s under DoS).
- In the **car controller** (`:8100`) set speed, steering, throttle, brake, coolant, battery and presets. Toggle:
  - **Faults**: overheat, battery_drain, sensor_inconsistency
  - **CAN attacks** (HCRL-style): dos, fuzzy, rpm_spoof, gear_spoof, steering_spoof, each with a "burst 4 s" button
  - **Tunnel attacks**: replay, tamper, wrong_key
- The **dashboard** (`:8000`) shows car cards with a status (Live / Offline / Awaiting device / Profile not supported), health and cyber-risk gauges, the attack class, forecasts, live signals (speed, rpm, steering wheel, throttle, brake, gear, coolant, battery, wheel/cluster speed, long. accel), the alert feed, the encryption inspector and voice alerts. Click once on the page so the browser allows speech.
- **Add a car** (any brand) from the dashboard: brand, model, name, plate and a CAN profile (or "Not supported yet"). The portal assigns a device id, generates a PSK and shows the provisioning card once (device id, PSK, `ws://<host>:<port>/ws/ingest`). This is **registration only**: the car shows "Awaiting device" until an ESP32 with that id/PSK connects, and "Profile not supported" if it connects without a usable CAN profile. Edit name/plate/profile, rotate the key, or delete from the same UI. REST: `POST/PATCH/DELETE /api/vehicles`, `POST /api/vehicles/{id}/rotate-key`, `GET /api/profiles`.
- To run a second simulated car for a registered device: `$env:PSK_DEVICE_2 = "<psk>"; python -m simulator --cars 1,2` (extra cars use the Sonata profile, so register device 2 with `hyundai_sonata_hcrl`).
- Over the internet: run the simulator (or the ESP32) elsewhere with `--server ws://<laptop-ip-or-tunnel>:<port>/ws/ingest`. The encryption is end-to-end at the app layer, so a LAN, port-forward, Tailscale or ngrok all work.
- Older `telemetry.db` files with removed profiles (`sim_maruti_v1`, `sim_toyota_v1`) still load; those cars show "Profile not supported" once a device connects. Edit the car and pick `hyundai_sonata_hcrl`, or delete the DB.
- Retrain the models with `python -m ml_training.generate_dataset && python -m ml_training.train`. They are written to `server/models/`, with metrics in `metrics.json`.

## Verify
```powershell
python -m pytest -q            # tunnel crypto, analytics, server, simulator
python tools/e2e_demo.py       # starts server + the bench car, fires every fault/attack, checks alert + score + recovery
```

## Layout
| Path | Role |
|---|---|
| `common/tunnel.py` | Handshake (challenge → HELLO MAC → WELCOME MAC → per-session key) + DATA frames |
| `common/crypto.py` | AES-128-GCM envelope (`device_id‖seq` as AAD) + replay guard |
| `common/can_profiles.py` | DBC-style CAN profiles (`hyundai_sonata_hcrl` = the bench car; more cars = more profile JSON) |
| `common/vehicle_sim.py` | Shared car physics, faults, CAN attacks, bounded batch builder (also used for ML training) |
| `simulator/` | Virtual car + controller UI (= ESP32 #1), `VirtualProductModule` + tunnel attacks (= ESP32 #2) |
| `server/app/main.py` | FastAPI: `/ws/ingest`, `/ws/live`, REST `/api/*`, dashboard |
| `server/app/analytics.py` | Rules, IsolationForest, RandomForest, slope forecaster, rolling scores, debounced alerts |
| `ml_training/` | Synthetic dataset generator + training |

## Honest limits (PoC)
- **Real data**: the attack model (RF) is trained on the real **HCRL Car-Hacking** captures plus simulator data. The rules alone detect **1200/1200** real HCRL intrusions (median latency ~80 ms) with 0 false alerts on normal driving. See [`EVALUATION.md`](EVALUATION.md). HCRL is easy and repetitive (300 identical bursts per file, one car), so these scores do not prove robustness to other cars or subtler attacks.
- Health has no real labelled data (HCRL has no coolant/battery faults; battery/brake/wheel/cluster messages are not on the HCRL bus). The health rules and IsolationForest are tested on the simulator only.
- Reproduce: put the HCRL zip contents in `data/hcrl/`, then run `python -m ml_training.train --hcrl data/hcrl --combined` and `python tools/eval_hcrl.py`. The dataset is academic-use only; cite Seo et al. 2018.
- Only the bench car has a CAN profile. Other brands need a DBC-derived profile (opendbc + cantools); until then they are registrations only.
- PSKs live in plaintext in SQLite/env. There is no TLS and no user accounts; key rotation is manual (`rotate-key`). None of this is production hardened.
- ESP32 firmware is not written yet. The wire protocol in PLAN.md §3–§4 is what it must implement (mbedTLS HMAC-SHA256 + AES-GCM, WebSocket client).
