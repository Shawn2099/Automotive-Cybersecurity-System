# Reported results on the HCRL Car-Hacking dataset

All numbers were read from the source text or tables (fetched 2026-11-10). Metric names are as printed. Scope is stated for each row: "per-attack" or "per-class" rows are split by attack; "overall" rows are dataset-level. Full detail is in `related_work_table.csv`.

| Key | Year / venue | Method | Scope | Metric(s) as printed | Table | Values as printed |
|---|---|---|---|---|---|---|
| seo2018gids | 2018 PST (arXiv 1907.07377) | GIDS discriminator 2 (GAN, normal data only, attacks unseen in training) | per-attack | Detection rate; Precision; Accuracy; AUC | Table 3 | DoS 99.6 / 96.8 / 97.9 / 0.999; FUZZY 99.5 / 97.3 / 98.0 / 0.999; RPM 99.0 / 98.3 / 98.0 / 0.999; GEAR 96.5 / 98.1 / 96.2 / 0.996 |
| seo2018gids | 2018 PST | GIDS discriminator 1 (known-attack classifier) | per-attack (diagonal) | Detection rate (%) by training/test attack | Table 2 | DoS 99.9; FUZZY 98.7; RPM 99.6; GEAR 99.8. Cross-attack off-diagonal values range 0.0% to 33.0%. |
| yang2019tree | 2019 IEEE GLOBECOM (arXiv 1910.08635) | Decision tree | overall | Acc (%); DR (%); FAR (%); F1 Score | Table III ("CAN-intrusion dataset") | DT 99.99 / 99.99 / 0.006 / 0.999 |
| yang2019tree | 2019 | Random forest | overall | same | Table III | RF 99.99 / 99.99 / 0.0003 / 0.999 |
| yang2019tree | 2019 | Extra trees | overall | same | Table III | ET 99.99 / 99.99 / 0.0005 / 0.999 |
| yang2019tree | 2019 | XGBoost | overall | same | Table III | XGBoost 99.98 / 99.98 / 0.012 / 0.999 |
| yang2019tree | 2019 | Stacking ensemble | overall | same | Table III | Stacking 100 / 100 / 0.0 / 1.0 |
| yang2019tree | 2019 | FS RF (feature-selected) | overall | same | Table III | FS RF 99.99 / 99.99 / 0.0013 / 0.999 |
| guerra2023road | 2023 Proc. 2024 CSCS workshop (arXiv 2408.17235) | RF, LightGBM, LCCDE, DCNN, TAN, LSTM | per-class | Precision; Recall; F1 score | Table 4 ("HCRL Car Hacking") | RF: 1.0000 / 1.0000 / 1.0000 on all four classes. DCNN F1: DoS 0.9995, FUZZY 0.9980, GEAR 0.9994, RPM 0.9996. LSTM F1: DoS 1.0000, FUZZY 0.9179, GEAR 0.9792, RPM 1.0000. TAN F1: DoS 0.9980, FUZZY 0.9999, GEAR 0.9957, RPM 0.9982. LightGBM and LCCDE: 1.0000 on all three metrics for all four classes. |
| frenken2025vgae | 2025 arXiv 2508.04845 (preprint) | Ours (VGAE/GAT teacher-student) and baselines A&D, G-IDCS, GUARD-CAN, KD-GAT | overall | Acc.; F1 | Table 2 (CarH column) | Ours 99.89 / 99.89; A&D 99.95 / 99.94; G-IDCS 97.25 / 93.36; GUARD-CAN 97.02 / 97.27; KD-GAT 99.97 / 99.97 |
| yang2022lccde | 2022 IEEE GLOBECOM (arXiv 2208.03399) | LCCDE (proposed) | overall | Accuracy; Precision; Recall; F1 (all %) | Table II | LCCDE 99.9997 on all four. LightGBM 99.9997, XGBoost 99.9994, CatBoost 99.9994 (all four). Baselines as printed: KNN acc 97.4 / F1 93.4; SVM acc 96.5 / F1 93.3; LSTM-AE acc 99.0 / F1 99.0; DCNN acc 99.93 / F1 99.91. |
| song2020dcnn | 2020 Vehicular Communications 21:100198 | DCNN (proposed) | n/a | none extracted | n/a | Not on HCRL. The abstract says the authors used "datasets we built with a real vehicle". The ScienceDirect full text was blocked (HTTP 403), so no numbers were read. |

## Notes for use in the paper

- Yang 2019 Table III also lists KNN and SVM rows quoted from prior work ([8] in that paper). They are in the CSV but omitted here. They are not the authors' own results.
- GIDS: the paper's text claims about 98% average accuracy. Table 3 values average 97.5%. Report the table values, not the text claim.
- GIDS: the HCRL dataset page states that Table 2 of the PST version contains errors, and that the arXiv version gives the corrected numbers. Use the arXiv version (1907.07377).
- Yang 2019 and LCCDE report DR, accuracy, and F1 near 99.9%. This is the "saturation" effect that motivates per-class F1 and harder datasets such as ROAD.
- Guerra 2023 (Table 4) is the only source here with per-class precision and recall on HCRL. Its LSTM FUZZY row (F1 0.9179) is the most useful contrast with the near-perfect tree models.
- Verma et al. 2024 (ROAD) and Hanselmann et al. 2020 (CANet) are not HCRL papers and have no HCRL rows. They are cited in the notes file.
