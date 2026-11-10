"""Import the real HCRL Car-Hacking dataset (user downloads it into data/hcrl/; we never download).

Dataset: https://sites.google.com/hksecurity.net/hcrl/Datasets/car-hacking-dataset

Formats handled (leniently, line by line, so mixed folders work):
  * attack CSVs  `Timestamp,CAN ID(hex),DLC,DATA0..DATA[DLC-1],Flag`  (Flag T = injected, R = normal).
    Known quirk: when DLC < 8 the Flag follows the last data byte, so the column count varies.
  * normal_run_data.txt  `Timestamp: 1479121434.850202   ID: 0350   000   DLC: 8   05 28 84 66 6d 00 00 a2`

CLI:
  python -m ml_training.hcrl_import data/hcrl                    # measure schedule, print profile diff
  python -m ml_training.hcrl_import data/hcrl --write-profile    # modify common/profiles/hyundai_sonata_hcrl.json
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

import numpy as np

from common.vehicle_sim import frame_bits

DATASET_URL = "https://sites.google.com/hksecurity.net/hcrl/Datasets/car-hacking-dataset"
DEFAULT_PROFILE_JSON = Path(__file__).resolve().parent.parent / "common" / "profiles" / "hyundai_sonata_hcrl.json"

_TXT_RE = re.compile(r"Timestamp:\s*([0-9]+(?:\.[0-9]*)?)\s+ID:\s*([0-9A-Fa-f]+)\b.*?DLC:\s*(\d+)(.*)$")
_HEX2 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")

FILE_CLASS_HINTS = (("dos", "dos"), ("fuzzy", "fuzzy"), ("gear", "spoofing"), ("rpm", "spoofing"))


def attack_class_for_file(path: str | Path) -> str | None:
    """Attack class implied by a dataset file name (None for normal data)."""
    name = Path(path).name.lower()
    for hint, cls in FILE_CLASS_HINTS:
        if hint in name:
            return cls
    return None


# --------------------------------------------------------------------------- parsing
def _parse_txt(line: str) -> tuple[float, int, int, str, bool] | None:
    m = _TXT_RE.search(line)
    if not m:
        return None
    dlc = int(m.group(3))
    data = "".join(_HEX2.findall(m.group(4))[:dlc]).upper()
    return float(m.group(1)), int(m.group(2), 16), dlc, data, False


def _parse_csv(line: str) -> tuple[float, int, int, str, bool] | None:
    parts = [p.strip() for p in line.strip().split(",")]
    parts = [p for p in parts if p != ""]
    if len(parts) < 3:
        return None
    try:
        ts = float(parts[0])
        can_id = int(parts[1], 16)
        dlc = int(parts[2])
    except ValueError:
        return None  # header or garbage
    rest = parts[3:]
    injected = False
    if rest and rest[-1].upper() in ("T", "R"):
        injected = rest[-1].upper() == "T"
        rest = rest[:-1]
    # data bytes are the first `dlc` tokens (flag position varies with DLC)
    toks = [t for t in rest[:dlc] if _HEX2.fullmatch(t)]
    return ts, can_id, dlc, "".join(toks).upper(), injected


def iter_frames(path: str | Path) -> Iterator[tuple[float, int, int, str, bool]]:
    """Yield (timestamp_s, can_id, dlc, data_hex, injected) from an HCRL attack CSV or normal .txt file."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            rec = _parse_txt(line) if line.lstrip().startswith("Timestamp:") else _parse_csv(line)
            if rec is not None:
                yield rec


# --------------------------------------------------------------------------- schedule / profile
def measure_schedule(normal_path: str | Path) -> dict[int, dict[str, Any]]:
    """Per-ID median period (ms) and most common payload from a normal-traffic file."""
    last: dict[int, float] = {}
    diffs: dict[int, list[float]] = {}
    payloads: dict[int, Counter] = {}
    dlcs: dict[int, Counter] = {}
    for ts, cid, dlc, data, _ in iter_frames(normal_path):
        if cid in last:
            d = ts - last[cid]
            if d > 0:
                diffs.setdefault(cid, []).append(d)
        last[cid] = ts
        payloads.setdefault(cid, Counter())[data] += 1
        dlcs.setdefault(cid, Counter())[dlc] += 1
    out: dict[int, dict[str, Any]] = {}
    for cid, d in diffs.items():
        if len(d) < 2:
            continue
        dlc = dlcs[cid].most_common(1)[0][0]
        out[cid] = {
            "period_ms": round(float(np.median(d)) * 1000.0, 3),
            "dlc": dlc,
            "data": payloads[cid].most_common(1)[0][0],
            "n": len(d) + 1,
        }
    return out


def write_profile_schedule(profile_json: str | Path, schedule: dict[int, dict[str, Any]],
                           write: bool = True) -> dict[str, Any]:
    """Update message periods from `schedule`, put the other measured IDs in `background`.

    Returns the updated profile dict; writes the file only when `write` is true.
    """
    path = Path(profile_json)
    prof = json.loads(path.read_text(encoding="utf-8"))
    known = set()
    for m in prof["messages"]:
        known.add(int(m["id"]))
        s = schedule.get(int(m["id"]))
        if s:
            m["period_ms"] = s["period_ms"]
    bg = []
    for cid in sorted(schedule):
        if cid in known:
            continue
        s = schedule[cid]
        bg.append({"id": cid, "name": f"HCRL_0x{cid:03X}", "dlc": s["dlc"], "period_ms": s["period_ms"],
                   "data": s["data"]})
    prof["background"] = bg
    prof["periods_source"] = "hcrl_measured"
    if write:
        path.write_text(json.dumps(prof, indent=2) + "\n", encoding="utf-8")
    return prof


# --------------------------------------------------------------------------- batching
def _fast_frames(path: str | Path) -> Iterator[tuple[float, int, int, str, bool]]:
    """Same output as iter_frames, ~4x faster on well-formed lines (falls back to the lenient parser otherwise)."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                if line[0] == "T":  # "Timestamp: <ts>  ID: <id>  000  DLC: <n>  <bytes...>"
                    t = line.split()
                    dlc = int(t[6])
                    yield float(t[1]), int(t[3], 16), dlc, "".join(t[7:7 + dlc]).upper(), False
                    continue
                t = line.rstrip().split(",")
                dlc = int(t[2])
                yield float(t[0]), int(t[1], 16), dlc, "".join(t[3:3 + dlc]).upper(), t[-1] == "T"
                continue
            except (ValueError, IndexError):
                pass
            if not line.strip():
                continue
            rec = _parse_txt(line) if line.lstrip().startswith("Timestamp:") else _parse_csv(line)
            if rec is not None:
                yield rec


def iter_windows(path: str | Path, file_label: str | None = None, window_ms: int = 100,
                 max_seconds: float | None = None, keep_ids: set[int] | None = None,
                 max_lines: int | None = None) -> Iterator[tuple[dict[str, Any], str, float | None]]:
    """Cut a file into Contract-B batches: yields (batch, label, first_injected_ts_s_or_None).

    Label = `file_label` if any frame in the window is injected, else normal. `keep_ids` limits the `frames`
    list (latest frame per ID) to those IDs (the features only decode profile messages); counts and bus load
    always cover every frame. Timestamps are relative to the first frame of the file.
    """
    win_s = window_ms / 1000.0
    t0: float | None = None
    cur: int | None = None
    latest: dict[int, dict[str, Any]] = {}
    counts: dict[str, int] = {}
    bits = 0
    inj_ts: float | None = None
    label = file_label or "normal"
    cap = window_ms and 500_000 * window_ms / 1000.0

    def flush() -> tuple[dict[str, Any], str, float | None]:
        frames = [latest[i] for i in sorted(latest) if keep_ids is None or i in keep_ids]
        b = {"window_ms": window_ms, "frames": frames, "counts": counts,
             "bus_load_pct": int(min(100, round(100 * bits / cap))) if cap else 0, "rx_err": 0,
             "ts_ms": int(round(cur * win_s * 1000))}
        return b, (label if inj_ts is not None else "normal"), inj_ts

    n = 0
    for ts, cid, dlc, data, injected in _fast_frames(path):
        n += 1
        if max_lines is not None and n > max_lines:
            break
        if t0 is None:
            t0 = ts
        if max_seconds is not None and ts - t0 > max_seconds:
            break
        w = int((ts - t0) / win_s)
        if cur is None:
            cur = w
        if w != cur:
            if counts:
                yield flush()
            latest, counts, bits, inj_ts, cur = {}, {}, 0, None, w
        latest[cid] = {"id": cid, "dlc": dlc, "data": data}
        k = str(cid)
        counts[k] = counts.get(k, 0) + 1
        bits += frame_bits(dlc)
        if injected and inj_ts is None:
            inj_ts = ts - t0
    if counts and cur is not None:
        yield flush()


def iter_batches(path: str | Path, file_label: str | None = None, window_ms: int = 100,
                 max_seconds: float | None = None) -> Iterator[tuple[dict[str, Any], str]]:
    """Cut a file into Contract-B batches. Label = `file_label` if any frame in the window is injected, else normal."""
    for b, lab, _ in iter_windows(path, file_label, window_ms, max_seconds):
        yield b, lab


def to_batches(path: str | Path, label_for_file: str | None, window_ms: int = 100,
               max_seconds: float | None = None) -> list[tuple[dict[str, Any], str]]:
    return list(iter_batches(path, label_for_file, window_ms, max_seconds))


# --------------------------------------------------------------------------- cached windows (parse once, reuse)
CACHE_DIR = Path(__file__).resolve().parent / "data" / "hcrl_cache"


def _build_cache(args: tuple[str, str | None, int | None]) -> str:
    import pickle

    path, label, max_lines = args
    from common.can_profiles import DEFAULT_PROFILE, get_profile

    keep = {m.id for m in get_profile(DEFAULT_PROFILE).messages}
    wins = list(iter_windows(path, label, 100, None, keep, max_lines))
    out = _cache_path(Path(path), max_lines)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "wb") as fh:
        pickle.dump({"stat": _stat(Path(path)), "windows": wins}, fh, protocol=pickle.HIGHEST_PROTOCOL)
    return str(out)


def _stat(p: Path) -> tuple[int, int]:
    st = p.stat()
    return st.st_size, int(st.st_mtime)


def _cache_path(p: Path, max_lines: int | None) -> Path:
    return CACHE_DIR / f"{p.stem}{'' if max_lines is None else f'_{max_lines}'}.pkl"


def load_windows(folder: str | Path, max_lines: int | None = None, workers: int = 4,
                 ) -> dict[str, list[tuple[dict[str, Any], str, float | None]]]:
    """{file name: [(batch, label, first_injected_ts_s), ...]} for every file in `folder`, cached on disk.

    Batches keep `frames` only for the profile's messages (all the features decode), so memory stays small.
    """
    import pickle
    from concurrent.futures import ProcessPoolExecutor

    files = find_files(Path(folder))
    todo = []
    for p in files:
        c = _cache_path(p, max_lines)
        ok = False
        if c.exists():
            try:
                with open(c, "rb") as fh:
                    ok = pickle.load(fh)["stat"] == _stat(p)
            except Exception:
                ok = False
        if not ok:
            todo.append((str(p), attack_class_for_file(p), max_lines))
    if todo:
        print(f"parsing {len(todo)} HCRL file(s) into 100 ms windows (cached afterwards) ...", flush=True)
        if len(todo) > 1 and workers > 1:
            with ProcessPoolExecutor(max_workers=min(workers, len(todo))) as ex:
                list(ex.map(_build_cache, todo))
        else:
            for a in todo:
                _build_cache(a)
    out = {}
    for p in files:
        with open(_cache_path(p, max_lines), "rb") as fh:
            out[p.name] = pickle.load(fh)["windows"]
    return out


# --------------------------------------------------------------------------- CLI
def find_files(folder: Path) -> list[Path]:
    return sorted(p for p in folder.rglob("*") if p.suffix.lower() in (".csv", ".txt") and p.is_file())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", nargs="?", default="data/hcrl")
    ap.add_argument("--write-profile", "--write", action="store_true", dest="write",
                    help="modify the profile JSON in place (default: only print a diff)")
    ap.add_argument("--profile", default=str(DEFAULT_PROFILE_JSON))
    args = ap.parse_args(argv)

    folder = Path(args.folder)
    if not folder.is_dir():
        print(f"HCRL folder '{folder}' not found. Download the Car-Hacking dataset from\n  {DATASET_URL}\n"
              f"and unzip it into '{folder}' (needs normal_run_data.txt for period measurement).")
        return 0
    normal = [p for p in find_files(folder) if "normal" in p.name.lower()]
    if not normal:
        print(f"No normal-traffic file (name containing 'normal', e.g. normal_run_data.txt) in '{folder}'.")
        return 0
    print(f"measuring schedule from {normal[0]} ...")
    sched = measure_schedule(normal[0])
    print(f"  {len(sched)} IDs; total ~{sum(1000.0 / s['period_ms'] for s in sched.values()):.0f} frames/s")
    prof_path = Path(args.profile)
    before = prof_path.read_text(encoding="utf-8")
    new = write_profile_schedule(prof_path, sched, write=False)
    after = json.dumps(new, indent=2) + "\n"
    if args.write:
        prof_path.write_text(after, encoding="utf-8")
        print(f"wrote {prof_path} (periods_source=hcrl_measured, {len(new['background'])} background IDs)")
    else:
        sys.stdout.writelines(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                                   "current", "measured"))
        print("\n(dry run; add --write-profile to modify the profile)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
