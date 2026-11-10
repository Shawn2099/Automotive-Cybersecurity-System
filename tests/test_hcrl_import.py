"""HCRL importer tests on tiny synthetic fixtures in both file formats (we never ship the real dataset)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from common.can_profiles import _load_profile
from ml_training import hcrl_import as H
from server.app.analytics import TRAFFIC_FEATURE_NAMES, FeatureState

PROFILE_JSON = H.DEFAULT_PROFILE_JSON


def _csv_row(ts, cid, data, flag):
    return f"{ts:.6f},{cid:04x},{len(data)}," + ",".join(f"{b:02x}" for b in data) + f",{flag}"


@pytest.fixture()
def normal_txt(tmp_path):
    """0x316 every 10 ms (DLC 8), 0x43F every 20 ms (DLC 2), unknown 0x7A0 every 50 ms."""
    lines = []
    t0 = 1479121434.0
    for k in range(300):  # 3 s
        t = t0 + k * 0.01
        lines.append(f"Timestamp: {t:.6f}        ID: 0316    000    DLC: 8    05 28 84 66 6d 00 00 a2")
        if k % 2 == 0:
            lines.append(f"Timestamp: {t + 0.001:.6f}        ID: 043f    000    DLC: 2    10 7f")
        if k % 5 == 0:
            lines.append(f"Timestamp: {t + 0.002:.6f}        ID: 07a0    000    DLC: 8    01 02 03 04 05 06 07 08")
    p = tmp_path / "normal_run_data.txt"
    p.write_text("\n".join(lines) + "\n")
    return p


def _attack_csv(path: Path, injected_window=(1.0, 1.3)):
    rows, t0 = ["Timestamp,CAN ID,DLC,DATA0,DATA1,DATA2,DATA3,DATA4,DATA5,DATA6,DATA7,Flag"], 1478198376.0
    for k in range(300):  # 3 s
        t = t0 + k * 0.01
        rows.append(_csv_row(t, 0x316, bytes([5, 0x21, 0x68, 9, 0x21, 0x21, 0, 0x6F]), "R"))
        if k % 2 == 0:
            rows.append(_csv_row(t + 0.001, 0x43F, bytes([0x10, 0x7F]), "R"))  # DLC<8: flag right after data
    t = t0 + injected_window[0]
    while t < t0 + injected_window[1]:
        rows.append(_csv_row(t, 0x316, bytes([0, 0, 0xFF, 0xFF, 0, 0, 0, 0]), "T"))
        t += 0.001
    # rows are in time order in the real files; sort by timestamp field
    body = sorted(rows[1:], key=lambda r: float(r.split(",")[0]))
    path.write_text("\n".join([rows[0]] + body) + "\n")
    return t0


def test_parse_txt_format(normal_txt):
    fr = list(H.iter_frames(normal_txt))
    assert fr[0] == (1479121434.0, 0x316, 8, "0528846 66D0000A2".replace(" ", ""), False)
    assert any(f[1] == 0x43F and f[2] == 2 and f[3] == "107F" for f in fr)
    assert all(f[4] is False for f in fr)


def test_parse_csv_with_short_dlc_and_flags(tmp_path):
    p = tmp_path / "RPM_dataset.csv"
    p.write_text("Timestamp,CAN ID,DLC,DATA0\n"
                 "1478198376.389427,0316,8,05,21,68,09,21,21,00,6f,R\n"
                 "1478198376.389900,043f,2,10,7f,T\n"
                 "1478198376.390000,0000,8,00,00,00,00,00,00,00,00,T\n"
                 "garbage line\n"
                 "1478198376.391000,0545,0,R\n")
    fr = list(H.iter_frames(p))
    assert fr[0] == (1478198376.389427, 0x316, 8, "052168092121006F", False)
    assert fr[1] == (1478198376.3899, 0x43F, 2, "107F", True)
    assert fr[2][1] == 0 and fr[2][4] is True
    assert fr[3][1:4] == (0x545, 0, "") and fr[3][4] is False
    assert len(fr) == 4


def test_measure_schedule(normal_txt):
    s = H.measure_schedule(normal_txt)
    assert set(s) == {0x316, 0x43F, 0x7A0}
    assert s[0x316]["period_ms"] == pytest.approx(10.0, abs=0.01)
    assert s[0x43F]["period_ms"] == pytest.approx(20.0, abs=0.01) and s[0x43F]["dlc"] == 2
    assert s[0x7A0]["period_ms"] == pytest.approx(50.0, abs=0.01)
    assert s[0x316]["data"] == "05288466" "6D0000A2"


def test_write_profile_schedule_on_tmp_copy(tmp_path, normal_txt):
    tmp_json = tmp_path / "profile.json"
    shutil.copy(PROFILE_JSON, tmp_json)
    orig = json.loads(tmp_json.read_text())
    sched = H.measure_schedule(normal_txt)
    sched[0x316]["period_ms"] = 12.5  # prove the period is taken from the schedule
    H.write_profile_schedule(tmp_json, sched, write=False)
    assert json.loads(tmp_json.read_text()) == orig  # dry run leaves the file alone
    H.write_profile_schedule(tmp_json, sched)
    new = json.loads(tmp_json.read_text())
    assert new["periods_source"] == "hcrl_measured"
    per = {m["id"]: m["period_ms"] for m in new["messages"]}
    assert per[0x316] == 12.5 and per[0x43F] == pytest.approx(20.0, abs=0.01)
    assert per[0x2B0] == {m["id"]: m["period_ms"] for m in orig["messages"]}[0x2B0]  # unmeasured: untouched
    assert new["background"] == [{"id": 0x7A0, "name": "HCRL_0x7A0", "dlc": 8,
                                  "period_ms": pytest.approx(50.0, abs=0.01), "data": "0102030405060708"}]
    prof = _load_profile(tmp_json)  # loadable by the real profile loader
    assert 0x7A0 in prof.valid_ids and prof.expected_hz[0x7A0] == pytest.approx(20.0, rel=0.01)
    assert prof.periods_source == "hcrl_measured"


def test_batch_windowing_and_labels(tmp_path):
    p = tmp_path / "RPM_dataset.csv"
    _attack_csv(p)
    batches = H.to_batches(p, H.attack_class_for_file(p), 100)
    assert H.attack_class_for_file(p) == "spoofing"
    assert 29 <= len(batches) <= 31
    labels = [lab for _, lab in batches]
    assert set(labels) == {"normal", "spoofing"}
    # injected burst covers t=1.0-1.3 s -> windows 10..12 are labelled, the rest are normal
    assert [i for i, l in enumerate(labels) if l == "spoofing"] == [10, 11, 12]
    b, _ = batches[11]
    assert {"ts_ms", "window_ms", "frames", "counts", "bus_load_pct"} <= set(b)
    assert b["ts_ms"] == 1100 and b["window_ms"] == 100
    assert b["counts"][str(0x316)] >= 100 and b["counts"][str(0x43F)] == 5 and b["bus_load_pct"] > 0
    assert any(f["id"] == 0x316 for f in b["frames"])



def test_normal_txt_batches_all_normal(normal_txt):
    bs = H.to_batches(normal_txt, None)
    assert bs and {lab for _, lab in bs} == {"normal"}


def test_file_class_mapping():
    assert [H.attack_class_for_file(f) for f in
            ("DoS_dataset.csv", "Fuzzy_dataset.csv", "gear_dataset.csv", "RPM_dataset.csv", "normal_run_data.txt")] \
        == ["dos", "fuzzy", "spoofing", "spoofing", None]


def test_traffic_features_on_imported_batches(tmp_path):
    p = tmp_path / "RPM_dataset.csv"
    _attack_csv(p)
    fs = FeatureState("hyundai_sonata_hcrl")
    rows = []
    for b, label in H.to_batches(p, "spoofing"):
        ctx = fs.step(b, None, b["ts_ms"] / 1000.0)  # decodes from the batch itself
        assert len(ctx["traffic_vec"]) == len(TRAFFIC_FEATURE_NAMES)
        rows.append((label, dict(zip(TRAFFIC_FEATURE_NAMES, ctx["traffic_vec"]))))
    normal = [f for l, f in rows[5:9] if l == "normal"]
    attack = [f for l, f in rows if l == "spoofing"]
    assert normal and attack
    assert all(f["rpm_ratio"] < 1.5 for f in normal)
    assert max(f["rpm_ratio"] for f in attack) > 3  # injected 0x316 stream shows as a rate spike


def test_cli_missing_folder_exits_zero(tmp_path, capsys):
    assert H.main([str(tmp_path / "nope")]) == 0
    assert "car-hacking-dataset" in capsys.readouterr().out


def test_train_hcrl_missing_folder_exits_zero(tmp_path, capsys):
    from ml_training import train

    assert train.main(["--hcrl", str(tmp_path / "nope")]) is None
    assert "car-hacking-dataset" in capsys.readouterr().out
