# Prior work and datasets (research pass, 2026-11-10)

A Haiku research agent gathered this. Links were fetched to check they exist, except where marked UNVERIFIED. Star counts are approximate as of the fetch.

## Similar / reusable projects
| Project | Stars / license | What we take from it |
|---|---|---|
| [commaai/opendbc](https://github.com/commaai/opendbc) | ~3.6k, MIT | Real per-brand DBC files (Toyota, Hyundai…). This is the route from our stand-in profiles to real brand decoding. |
| [cantools/cantools](https://github.com/cantools/cantools) | ~2.3k, MIT | DBC parser/decoder, so we can load opendbc files as `can_profile`s (Phase 2). |
| [hardbyte/python-can](https://github.com/hardbyte/python-can) | ~1.6k, LGPL-3.0 | Bus I/O + virtual bus. Use it if we later connect a USB-CAN adapter on the laptop. |
| [Western-OC2-Lab ML IDS](https://github.com/Western-OC2-Lab/Intrusion-Detection-System-Using-Machine-Learning) | ~600, MIT | Tree-model IDS (DT/RF/ExtraTrees/XGBoost) on Car-Hacking. Confirms that RF is a sound choice. |
| [lorenzo9uerra/road_ids_cscs_2024](https://github.com/lorenzo9uerra/road_ids_cscs_2024) | MIT | Labelling scripts for ROAD + Car-Hacking (`label_road.py`, `label_car-hacking.py`). |
| [SERLABUniba/MaREA](https://github.com/SERLABUniba/MaREA) | license n/a | Multi-class RF on Car-Hacking. Closest to our RF design. |
| [limiter121/esp32-obd2-emulator](https://github.com/limiter121/esp32-obd2-emulator) | ~500, MPL-2.0, archived | ESP32 + transceiver at 500 kbps. Model for the ESP32 #1 firmware phase. |

## Datasets
| Dataset | Access | Labels | Use for us |
|---|---|---|---|
| [HCRL Car-Hacking](https://sites.google.com/hksecurity.net/hcrl/Datasets/car-hacking-dataset) | Academic use, cite Seo et al. 2018 | DoS (ID 0x000), fuzzy, gear spoof, RPM spoof | **IDS benchmark #1.** Its classes map 1:1 to ours (dos / fuzzy_unknown_id / spoofing). Papers report RF F1 ≈ 1.0, so it is easy. Report per-class F1. |
| [ROAD (ORNL)](https://zenodo.org/records/10462796) | CC-BY | fuzzing, fabrication, masquerade, signal-level | Harder benchmark. Use it to show limits honestly (RF F1 0–0.8 on masquerade). |
| [can-train-and-test](https://bitbucket.org/brooke-lampe/can-train-and-test/src/master/) | open, ~7.5 GB | multiple | Realistic generalisation test (optional). |
| [SynCAN (ETAS)](https://github.com/etas/SynCAN) | non-commercial | signal-level synthetic | Optional second benchmark. |
| [KIT OBD-II](https://radar.kit.edu/radar/en/dataset/bCtGxdTklQlfQcAq) | CC-BY 4.0, 11.6 MB | none (normal driving) | **Health model**: calibrate normal ranges for RPM/speed/coolant/throttle, and train IsolationForest on *real* normal driving relationships. |
| [NASA C-MAPSS](https://www.nasa.gov/intelligent-systems-division/discovery-and-systems-health/pcoe/pcoe-data-set-repository/) | free | run-to-failure | Validate the trend/time-to-threshold method (not automotive). |
| Kaggle "engine health" | original page not found, only HF mirrors | binary | Low trust. Skip unless the original source is confirmed. |

No public dataset has **battery voltage with labelled faults**. Our electrical faults stay synthetic, and we say so.

## Techniques to adopt
- IDS features used in the HCRL/ROAD papers: per-ID frequency, inter-arrival time mean/std, DLC, payload bytes. Our bounded batch already gives per-ID frequency. Inter-arrival stats would need the ESP32 to add per-ID min/mean gap to the batch (cheap, Phase 2).
- Per-attack one-vs-rest models do better than multiclass on ROAD.
- Report **per-class F1**, not accuracy. HCRL saturates.
