"""Fast checks on a slice (first 200k lines of each file) of the REAL HCRL dataset. Skipped when data/hcrl is absent."""

from __future__ import annotations

from pathlib import Path

import pytest

from common.can_profiles import DEFAULT_PROFILE
from ml_training.hcrl_import import attack_class_for_file, find_files, iter_windows
from server.app.analytics import CLASS_OF, CLASS_PRIORITY, VehicleAnalyzer

HCRL = Path(__file__).resolve().parent.parent / "data" / "hcrl"
pytestmark = pytest.mark.skipif(not HCRL.is_dir() or not any(HCRL.glob("*.csv")),
                                reason="real HCRL dataset not present in data/hcrl")
SLICE_LINES = 200_000


def _replay(path: Path):
    label = attack_class_for_file(path)
    an = VehicleAnalyzer(DEFAULT_PROFILE, None)
    labels, preds, alerts = [], [], []
    for b, lab, _ in iter_windows(path, label, 100, None, None, SLICE_LINES):
        t = b["ts_ms"] / 1000.0 + 0.1
        res = an.update(b, None, t)
        alerts += [(a["kind"], a["category"]) for a in res["alerts"]]
        cats = an._records[-1][2]
        labels.append(lab)
        preds.append(next((CLASS_OF[c] for c in CLASS_PRIORITY if c in cats), "normal"))
    return labels, preds, alerts


@pytest.mark.parametrize("fname,cls", [("DoS_dataset.csv", "dos"), ("Fuzzy_dataset.csv", "fuzzy"),
                                       ("gear_dataset.csv", "spoofing"), ("RPM_dataset.csv", "spoofing")])
def test_rules_detect_real_attack_class(fname, cls):
    p = HCRL / fname
    if not p.exists():
        pytest.skip(f"{fname} missing")
    labels, preds, alerts = _replay(p)
    inj = [i for i, l in enumerate(labels) if l == cls]
    assert len(inj) > 500, "slice should contain several injection bursts"
    recall = sum(preds[i] == cls for i in inj) / len(inj)
    assert recall > 0.8, f"{fname}: recall {recall:.3f}"
    assert any(k == "cyber" and CLASS_OF.get(c) == cls for k, c in alerts)


def test_normal_run_has_no_cyber_alerts():
    p = next((q for q in find_files(HCRL) if "normal" in q.name.lower()), None)
    if p is None:
        pytest.skip("normal_run_data.txt missing")
    labels, preds, alerts = _replay(p)
    assert len(labels) > 1000
    assert set(preds) == {"normal"}
    assert not [a for a in alerts if a[0] == "cyber"], alerts
