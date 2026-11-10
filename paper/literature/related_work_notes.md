# Related-work notes (keys refer to refs.bib)

## 1. Attacks on vehicles
- **koscher2010**: Physical and internal-bus attacks on a production car; shows the CAN bus trusts every node. Motivates CAN-level monitoring.
- **checkoway2011**: Systematic external attack surface analysis (wireless, diagnostics, telematics). Shows remote compromise is realistic, which justifies the encrypted tunnel and the threat model for the edge server.
- **miller2015** (whitepaper; authors listed as Valasek and Miller on the IOActive page): Remote exploitation of an unaltered 2014 Jeep Cherokee through its infotainment unit. Supports the claim that attackers can reach the bus remotely.

## 2. CAN protocol and authentication
- **iso11898_2024** (UNVERIFIED, commented out in refs.bib): The current CAN data-link standard. ISO withdrew the 2015 edition and replaced it with the 2024 edition. Only search-listing evidence was seen, so it must be read before it is cited.
- **autosar_secoc** (UNVERIFIED, commented out): The AUTOSAR message-authentication spec for CAN. The spec PDFs could not be read, so we have no confirmed title or document ID. **This is a gap**: the paper needs the SecOC citation to argue that authentication is standardised but not deployed on legacy buses.

## 3. Timing, frequency and entropy IDS
- **muter2011entropy**: Entropy of CAN payload distributions to flag anomalies. The earliest statistical IDS for in-vehicle networks; a simple baseline.
- **song2016icoin**: Detects injection by inter-arrival time analysis of CAN messages. Same feature family as the planned per-ID inter-arrival stats.
- **cho2016cids**: Clock-skew fingerprinting of ECUs (CIDS). Identifies the sending ECU from timing, which our per-ID stats cannot do; a stronger but hardware-dependent option.
- **taylor2016lstm** (DSAA 2016): LSTM on CAN data for anomaly detection. Early deep-learning CAN baseline.
- **taylor2015** (WCICSS 2015): frequency-based anomaly detection on CAN. Optional if space is limited.

## 4. ML and DL IDS on CAN
- **yang2019tree**: Tree ensembles (DT, RF, ET, XGBoost, stacking) on the CAN-intrusion dataset. Near-perfect dataset-level scores, with RF among the cheapest to run. Supports our RF choice and the Western-OC2 code base.
- **song2020dcnn**: DCNN IDS trained on CAN frames without hand-crafted features. Its data came from the authors' own real vehicle, not HCRL, and no numbers were extracted.
- **guerra2023road**: Compares RF, LightGBM, LCCDE, DCNN, TAN and LSTM on HCRL with per-class precision/recall/F1. LSTM is weakest on FUZZY (F1 0.918), which shows that per-class reporting exposes differences the averages hide.
- **frenken2025vgae** (arXiv preprint): Knowledge-distilled VGAE/GAT evaluated on Car-Hacking and can-train-and-test. Recent, but a preprint.
- **yang2022lccde** (arXiv listing says accepted at GLOBECOM 2022): Decision-based ensemble of per-attack best models. Reports near-perfect dataset-level results on Car-Hacking.
- **seo2018gids**: GAN-based IDS that learns normal traffic only, so unseen attacks can be flagged. Its own table shows detection falling to 0 to 33% for attacks not in training, which is a useful caution about generalisation.
- **aljarrah2023icics** (verified as 2023, not 2019): Compares ML-based CAN IDS. No numbers were extracted, so cite it only as a comparison.
- **dupont2019survey**, **young2019survey**, **wu2020survey**: Surveys of CAN IDS covering rule-based, statistical and ML methods. Wu et al. (IEEE T-ITS 2020) is the main survey to cite for the classification of approaches.
- **hanselmann2020canet** (IEEE Access 2020): Unsupervised deep model on real and synthetic CAN data, with no HCRL results. Use for the unsupervised-approach discussion.

## 5. Datasets and critiques
- **hcrl_cartack** (HCRL page): Source of the DoS, fuzzy, gear and RPM data we use. The page also says that Table 2 in the PST version has errors and that the arXiv version is corrected.
- **verma2024road** (PLOS ONE 2024): Introduces ROAD (fabrication, suspension and masquerade attacks, with real fuzzing). Its Section 3.3 is the critique we need. It says the HCRL dataset was captured with the car not being driven, that attacks are "particularly unstealthy" in terms of bus timing, and that "this dataset does not seem like a good choice, even for testing a simple detector." Its abstract also says public datasets are limited to real fabrication attacks. **Use these as direct quotes with the section number.**
- **road_zenodo**: Data release (CC BY 4.0) for the ROAD paper.
- **lampe2023canttt** (arXiv 2308.04972): Curated dataset of four vehicles from two manufacturers, with train/test splits for unseen vehicles and attacks. It is the best generalisation test if we add one.
- **syncan** (ETAS, non-commercial): Synthetic signal-level CAN benchmark. Verma et al. argue synthetic data has fidelity limits, so use it only as a secondary benchmark.
- **kit_obd** (KIT, CC BY 4.0): Ten OBD-II signals in normal driving. Basis for calibrating the health model's normal ranges.

## 6. Vehicle health and predictive maintenance
- **theissler2021pdm** (RESS 2021): Survey of ML predictive maintenance in automotive use cases and challenges. The main citation for the health side.

## 7. Telematics and privacy
- **walter2020privacy** (Telematics and Informatics 2020): Privacy-aware acceptance model for connected-vehicle services. Supports the claim that telematics data is sensitive and that users care about it.

## 8. Crypto and tooling (standards)
- **nist2007gcm** (SP 800-38D): AES-GCM. NIST says it intends to revise this document, so cite the 2007 version with that caveat.
- **rfc2104**, **rfc5869** (HKDF), **rfc6455** (WebSocket): For the PSK-derived keys, the message authentication, and the dashboard link.
- **espressif_twai**: ESP32 TWAI controller documentation.
- **opendbc**, **cantools**, **westernoc2_ids**: Software for DBC decoding and the tree-based IDS code base.
- **liu2008iforest**, **breiman2001rf**, **pedregosa2011sklearn**: Isolation Forest (health anomaly scoring), Random Forest (the IDS classifier), and scikit-learn (implementation).

## Suggested positioning sentences
1. Most CAN IDS papers evaluate on the HCRL Car-Hacking dataset, where tree models reach near-perfect scores [yang2019tree, guerra2023road]; the dataset's artefacts and easy attacks limit what such scores show [verma2024road].
2. We therefore report per-class F1 and per-intrusion detection latency rather than only dataset-level accuracy.
3. Our novelty is not a new classifier. It is a profile-measured simulator whose fidelity against the real bus is quantified, so that models can be trained in simulation and tested on hardware traffic.
4. Few IDS deployments pair detection with secure transport. We describe a read-only retrofit that uses an ESP32 with a PSK-authenticated AES-128-GCM tunnel to an edge server, and we discuss how this relates to the standardised SecOC approach [autosar_secoc, to be confirmed].
5. Vehicle health monitoring is usually separate from intrusion detection [theissler2021pdm]. We combine both in one score so that a cyber fault and a mechanical fault are reported on one dashboard.

## Gaps to close before submission
- Read the AUTOSAR SecOC specification and the ISO 11898-1:2024 edition (both currently UNVERIFIED).
- Read the full text of the DCNN paper (Vehicular Communications 2020) if it is to be used as an HCRL result. It currently does not appear to be one.
- Confirm the Computers & Security journal version of can-train-and-test (DOI 10.1016/j.cose.2024.103777 was seen in a secondary index only; not verified).
