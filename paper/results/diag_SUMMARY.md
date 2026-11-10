# Conceptual diagrams: summary

All figures: `paper/figures/<name>.pdf` (vector) + `.png` (300 dpi); TikZ twin `paper/diagrams/<name>.tex`
(a `tikzpicture` snippet, inch coordinates, uses `\definecolor`; wrap in `standalone` or `\input`).
Script: `python -m paper.experiments.<name>` (shared helper `paper/experiments/diag_common.py` emits PDF/PNG and TikZ from one layout).
Style: Times, 6.5-7 pt, greyscale-safe (fills + dashed/solid/thick borders); dashed border = simulated stand-in for planned hardware; thick shaded box = attacker.

| # | Name | Width | Section | Caption draft |
|---|---|---|---|---|
| 1 | `diag_architecture` | full (7.16 in) | System architecture | End-to-end architecture. A bench car emulating the HCRL Sonata ECUs (ESP32 #1) feeds a read-only product module (ESP32 #2) that batches CAN traffic every 100 ms and sends it through an AES-128-GCM tunnel to a laptop edge server running decoding, rule/ML analytics, scoring, storage and a dashboard. Dashed blocks are simulated in this proof of concept; A1 and A2 mark the on-bus and network attack entry points. |
| 2 | `diag_handshake` | single | Secure tunnel / protocol design | PSK challenge-response handshake. Both sides prove knowledge of the pre-shared key with truncated HMAC-SHA256 tags (mac_d, mac_s) and derive a fresh per-session AES-128 key; DATA messages then carry seq = 1, 2, ..., and the server checks the GCM tag before the replay guard. |
| 3 | `diag_envelope` | single | Secure tunnel / protocol design | DATA message layout and plaintext schema. The 12-byte nonce is device_id, seq and a per-session 6-byte salt; device_id and seq are authenticated as AAD. The encrypted payload is one JSON batch with the latest frame per CAN ID, per-ID counts, bus load and RX errors. |
| 4 | `diag_pipeline` | full (7.16 in) | Analytics / detection method | Per-batch analytics pipeline. Profile-relative traffic features and a health vector feed rules, a RandomForest, an IsolationForest and a slope forecaster; outputs are fused over a rolling 5 s window and debounced (10 s cool-down, 2 s re-arm, severity escalation) into health and cyber-risk scores (0-100) and alerts. |
| 5 | `diag_threat_model` | single | Threat model (before design/evaluation) | Threat model. An on-bus injector (A1) is detected but not blocked because the module is read-only; a network attacker (A2) is rejected by the tunnel's authentication, integrity and freshness checks. |
| 6 | `diag_training` | single | Dataset and model training / evaluation setup | Data and training flow. Real HCRL captures yield the measured schedule and attack behaviour that define the CAN profile and simulator; HCRL and simulator windows share one feature extractor to train the RandomForest, while the IsolationForest uses simulator-normal health features. Evaluation paths are separate for real attack data and simulator-only checks. |

## Notes for authors
- Facts are taken from `common/tunnel.py`, `common/crypto.py`, `PLAN.md` and `analytics.py` constants (WINDOW_S 5, COOLDOWN_S 10, REARM_QUIET_S 2). The ECU label (ID count, frames/s) is computed from the live profile `common/profiles/hyundai_sonata_hcrl.json`: 27 HCRL-measured IDs + 4 extra PoC messages ≈ 2,100 frames/s.
- The 'DA' type bytes are drawn as the 2-byte type; "envelope header 18 B" = device_id + seq + nonce as in `HEADER_SIZE`.
- `diag_training` evaluation boxes are deliberately number-free; fill in results from `EVALUATION.md` in the text, not the figure.
- Abbreviations to define in the paper: RF = RandomForest, PSK, AAD, DBC.
- Matplotlib text falls back from Times New Roman if unavailable; TikZ output follows the document font.
