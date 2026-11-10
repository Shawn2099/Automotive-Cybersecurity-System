# Paper materials index

Index of the materials for the future IEEE paper on CAN-bus intrusion detection and secure telemetry for the PoC car. Every figure, table, diagram and result here is produced by `paper/experiments/` (screenshots are captured by hand).

This README is an index only. It is not the paper and contains no experimental numbers: those live in the generated summaries and the results JSONs (see "Where the numbers are").

## Folder layout

| Folder | Contents |
|---|---|
| `figures/` | 24 figures, each as `.pdf` (for LaTeX) and `.png` (preview): 6 diagrams, 10 HCRL, 8 system |
| `tables/` | 17 booktabs `.tex` tables (LaTeX fragments, included with `\input`) |
| `diagrams/` | 6 TikZ twins of the diagram figures (`tikzpicture` snippets, one per diagram) |
| `screenshots/` | 10 PoC web-UI screenshots (`.jpg` / `.png`) and `SCREENSHOTS.md` (captions and the state each one shows) |
| `literature/` | `refs.bib`, `related_work_table.md` / `.csv`, `related_work_notes.md` |
| `results/` | Result JSONs, generated summaries (`*_SUMMARY.md`), `RUN_MANIFEST.json` and `run_logs/` (written by `run_all`), `hcrl_cache/` (intermediates, safe to delete) |
| `experiments/` | Scripts that produce everything above. `run_all.py` is the entry point. `style.py`, `diag_common.py`, `hcrl_common.py`, `sys_common.py` are shared helpers. `run_hcrl_all.py` and `run_sys_all.py` are older per-group runners that the summaries still cite. |

## Regenerate everything

Run from the project root:

```
python -m paper.experiments.run_all                 # everything (about 1 to 1.5 h; sys_04 and sys_05 are long timing runs)
python -m paper.experiments.run_all --quick         # skip the two long timing runs (sys_04, sys_05)
python -m paper.experiments.run_all --only hcrl     # one group: diag | hcrl | sys
python -m paper.experiments.run_all --cold          # also delete cached HCRL intermediates first
```

- Each step runs in its own process with a time limit, so a hang is reported as TIMEOUT instead of stalling the run.
- Results are written to `paper/results/RUN_MANIFEST.json` (code version, per-step status and duration, lists of changed and byte-identical outputs). Logs go to `paper/results/run_logs/`. The exit code is non-zero if any step failed.
- `--cold` deletes `paper/results/hcrl_cache/` and `ml_training/data/hcrl_cache/`.
- **HCRL group needs the dataset in `data/hcrl/`.** The Car-Hacking captures are not in the repo (`data/` is git-ignored). The dataset has an academic-use licence and must not be redistributed. Cite Seo et al. 2018 (bib key `seo2018gids`). The `diag` and `sys` groups need no dataset.
- The `sys` group starts its own server and simulator on ports 8865 to 8869 with temporary databases. Run it on an otherwise idle machine.

### After a code change

Rerun the affected group (`--only diag|hcrl|sys`), or a single step with `python -m paper.experiments.<module>`. The scripts import the live code (thresholds in `server/app/analytics.py`, `common/profiles/hyundai_sonata_hcrl.json`, `common/tunnel.py`), so the numbers, figures and tables update without editing anything by hand. Check `RUN_MANIFEST.json` for which outputs changed. If the change touches the HCRL parser or feature extraction, use `--cold`, because HCRL intermediates are cached and would otherwise be reused.

## Diagrams

Files are in `figures/` as `.pdf` and `.png`. Each diagram also has a TikZ twin in `diagrams/<name>.tex`. All six are written by their script through `diag_common.py`.

| File (no extension) | Shows | Script | Suggested section |
|---|---|---|---|
| `diag_architecture` | End-to-end architecture: bench car, read-only product module, edge server, attack entry points | `diag_architecture.py` | System architecture |
| `diag_handshake` | PSK challenge-response handshake and per-session key derivation | `diag_handshake.py` | Secure tunnel |
| `diag_envelope` | Encrypted DATA message layout: nonce, header, AAD and batch plaintext | `diag_envelope.py` | Secure tunnel |
| `diag_pipeline` | Per-batch analytics pipeline: features, rules, RF, IF, forecaster, fusion and debounce | `diag_pipeline.py` | Detection method |
| `diag_threat_model` | Threat model: on-bus injector (detected, not blocked) and network attacker (rejected) | `diag_threat_model.py` | Threat model |
| `diag_training` | Data and training flow from HCRL captures and simulator to RF, IF and evaluation paths | `diag_training.py` | Dataset and training |

## HCRL experiments

Figures are `.pdf` plus `.png`. Tables are `.tex` in `tables/`. Scripts write the matching `paper/results/hcrl_*.json`, which `hcrl_summary.py` reads to write `hcrl_SUMMARY.md`.

### Figures

| File (no extension) | Shows | Script | Suggested section |
|---|---|---|---|
| `hcrl_id_rates` | Frame rate per CAN ID during normal driving (log scale), with decoded profile messages highlighted | `hcrl_dataset.py` | HCRL dataset |
| `hcrl_burst_timeseries` | Legitimate vs injected frame rate around one representative intrusion per attack | `hcrl_dataset.py` | HCRL dataset |
| `hcrl_rules_confusion` | Row-normalised window confusion matrices of the rule engine, all windows and settled windows | `hcrl_rules.py` | Rule-based detection on real traffic |
| `hcrl_rules_latency_ecdf` | ECDF of per-intrusion detection latency of the rule engine, one curve per attack | `hcrl_rules.py` | Rule-based detection on real traffic |
| `hcrl_rf_importance` | Gini feature importance of the HCRL-only and deployed RandomForest | `hcrl_rf.py` | RandomForest on HCRL |
| `hcrl_rf_confusion` | Hold-out confusion matrices of the HCRL-only and deployed RandomForest | `hcrl_rf.py` | RandomForest on HCRL |
| `hcrl_transfer` | Macro-F1 of simulator-trained, HCRL-trained and combined RFs on HCRL and fresh simulator data | `hcrl_transfer.py` | Cross-domain transfer |
| `hcrl_sensitivity` | Detection rate vs false-positive rate on settled windows as one rule constant is swept | `hcrl_sensitivity.py` | Threshold sensitivity |
| `hcrl_sensitivity_vs_threshold` | The same sweep plotted against the constant's value | `hcrl_sensitivity.py` | Threshold sensitivity |
| `hcrl_window` | Window size vs detection latency and accuracy of the rule engine | `hcrl_window.py` | Window size |

### Tables

| File (no extension) | Shows | Script |
|---|---|---|
| `hcrl_dataset_files` | Attack and normal captures: frame and intrusion counts, targets, burst statistics | `hcrl_dataset.py` |
| `hcrl_rules_perclass` | Per-class precision, recall and F1 of the rule engine on HCRL | `hcrl_rules.py` |
| `hcrl_rules_latency` | Per-attack detection and latency of the rule engine | `hcrl_rules.py` |
| `hcrl_rf_perclass` | Per-class precision, recall and F1 of the RandomForest, HCRL-only vs deployed | `hcrl_rf.py` |
| `hcrl_transfer_all` | Transfer macro-F1 over all windows | `hcrl_transfer.py` |
| `hcrl_transfer_settled` | Transfer macro-F1 over settled windows | `hcrl_transfer.py` |
| `hcrl_sensitivity` | Threshold sweep results | `hcrl_sensitivity.py` |
| `hcrl_window` | Window size vs latency and accuracy | `hcrl_window.py` |

## System experiments

Figures are `.pdf` plus `.png`. Tables are `.tex` in `tables/`. Each script also writes its `paper/results/sys_*.json`. The summary for this group is `paper/results/sys_SUMMARY.md`, written by the `sys_summary` step of `run_all`.

### Figures

| File (no extension) | Shows | Script | Suggested section |
|---|---|---|---|
| `sys_crypto_latency` | Seal and open latency vs message size, with real batches marked | `sys_01_microbench.py` | Tunnel performance |
| `sys_bandwidth` | Uplink bandwidth per scenario for raw CAN, naive JSON and the bounded batch, plus packet-size distribution | `sys_03_bandwidth.py` | Bandwidth |
| `sys_alert_latency` | Onset-to-alert latency per attack and fault through the full stack | `sys_04_latency.py` | End-to-end latency |
| `sys_scalability` | Server CPU, CPU per packet and latency vs number of simulated devices | `sys_05_scalability.py` | Scalability |
| `sys_health_timeseries` | Signal, component health, overall health and IF score for each injected fault | `sys_06_health.py` | Vehicle health analytics |
| `sys_forecast_accuracy` | Forecast ETA vs actual time to threshold | `sys_06_health.py` | Vehicle health analytics |
| `sys_anomaly_hist` | IsolationForest score distribution, normal driving vs each fault | `sys_06_health.py` | Vehicle health analytics |
| `sys_cyber_timeline` | Cyber risk and attack class over a scripted multi-attack scenario | `sys_07_cyber_timeline.py` | Cyber risk over time |

### Tables

| File (no extension) | Shows | Script |
|---|---|---|
| `sys_microbench` | Handshake and seal/open cost per traffic type | `sys_01_microbench.py` |
| `sys_security` | Tunnel security test outcomes per attack class | `sys_02_security.py` |
| `sys_bandwidth` | Bandwidth per scenario and encoding | `sys_03_bandwidth.py` |
| `sys_latency` | Onset-to-alert latency per scenario | `sys_04_latency.py` |
| `sys_ingest_latency` | Ingest-to-broadcast latency and per-stage server cost | `sys_04_latency.py` |
| `sys_scalability` | Load vs number of devices | `sys_05_scalability.py` |
| `sys_forecast` | Forecaster error per signal | `sys_06_health.py` |
| `sys_anomaly` | IsolationForest score per condition | `sys_06_health.py` |
| `sys_cyber_timeline` | Cyber-risk timeline per burst | `sys_07_cyber_timeline.py` |

## Screenshots

Captured by hand with the browser tool. No script produces them. `screenshots/SCREENSHOTS.md` holds the caption draft and the exact state each screenshot shows. The `ui_*.jpg` files are JPEG and the `ui_crop_*` and `ui_add_car` / `ui_vehicle_list` files are PNG. Convert them if the venue needs PNG throughout.

| File | Shows | Suggested section |
|---|---|---|
| `ui_controller.jpg` | Car controller simulator in city mode, no faults or attacks | Implementation (PoC) |
| `ui_dashboard_normal.jpg` | Monitoring dashboard during normal driving | Implementation (PoC) |
| `ui_dashboard_dos.jpg` | Dashboard detecting a CAN DoS flood | Evaluation |
| `ui_crop_cyber_panel.png` | Close-up of the cyber-risk panel and alert feed during the DoS flood | Evaluation |
| `ui_dashboard_rpm_spoof.jpg` | Dashboard detecting forged RPM messages (see SCREENSHOTS.md for a caveat on the displayed value) | Evaluation |
| `ui_dashboard_overheat.jpg` | Dashboard response to an engine overheating fault | Evaluation |
| `ui_dashboard_tamper.jpg` | Dashboard during a tunnel tampering attack | Evaluation |
| `ui_crop_encryption_inspector.png` | Encryption inspector rejecting tampered tunnel packets | Secure tunnel |
| `ui_add_car.png` | Provisioning a new vehicle in the portal (PSK redacted) | Implementation (PoC) |
| `ui_vehicle_list.png` | Vehicle list with mixed registration states | Implementation (PoC) |

## Tables (`paper/tables/*.tex`)

All 17 tables are listed above in the HCRL and system sections. Diagrams have no tables. Each table is written by the script named in its row.

## Literature

- `refs.bib`: 38 entries (lines starting with `@`). The file header says the active entries were checked against fetched pages on 2026-11-10. Two UNVERIFIED entries are commented out at the bottom, `iso11898_2024` and `autosar_secoc`. **Check both against the primary source by hand before uncommenting or citing them.**
- `related_work_table.md` (readable) and `related_work_table.csv` (same content for spreadsheets): reported results of prior work on HCRL, with scope and metric as printed. Look up the values there, not in this README.
- `related_work_notes.md`: prose notes for each `refs.bib` key, grouped by topic (attacks, CAN authentication, timing and entropy IDS, ML and DL IDS, datasets and critiques).

## Where the numbers are

- `paper/results/hcrl_SUMMARY.md`: all HCRL results, written by `hcrl_summary.py` from the `hcrl_*.json` files.
- `paper/results/sys_SUMMARY.md`: all system-experiment results, written by the `sys_summary` step of `run_all`.
- `paper/results/diag_SUMMARY.md`: diagram captions and notes. It has no results.
- `EVALUATION.md` (project root): the project's running evaluation document. It can quote older values (`hcrl_SUMMARY.md` notes one such case), so when the two disagree, the generated summaries and JSONs win.
- Raw results (`paper/results/`):
  - HCRL: `hcrl_dataset.json`, `hcrl_rules.json`, `hcrl_rf.json`, `hcrl_transfer.json`, `hcrl_sensitivity.json`, `hcrl_window.json`
  - System: `sys_microbench.json`, `sys_security.json`, `sys_bandwidth.json`, `sys_latency.json`, `sys_scalability.json`, `sys_health.json`, `sys_cyber_timeline.json`
  - Run status: `RUN_MANIFEST.json` (written by `run_all`), with per-step logs in `run_logs/`
