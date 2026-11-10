"""Regenerate ALL paper materials (results, figures, tables, diagrams, summaries) from the current code.

    python -m paper.experiments.run_all                 # everything (~1-1.5 h; sys 4/5 are long timing runs)
    python -m paper.experiments.run_all --quick         # skip the two long timing runs (sys_04, sys_05)
    python -m paper.experiments.run_all --only hcrl     # one group: diag | hcrl | sys
    python -m paper.experiments.run_all --cold          # also delete cached HCRL intermediates first

Each step runs in its own process with a time limit, so a hang is reported as TIMEOUT instead of
stalling the run. Writes paper/results/RUN_MANIFEST.json (code version, per-step status/duration)
and logs to paper/results/run_logs/. Exit code is non-zero if any step failed.
Needs the HCRL dataset in data/hcrl/ for the hcrl group (not redistributed; see README).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAPER = ROOT / "paper"
RES = PAPER / "results"
LOGS = RES / "run_logs"
OUT_DIRS = [PAPER / "figures", PAPER / "tables", PAPER / "diagrams", RES]

# (group, module, timeout_s, long)
STEPS: list[tuple[str, str, int, bool]] = [
    ("diag", "diag_architecture", 300, False),
    ("diag", "diag_handshake", 300, False),
    ("diag", "diag_envelope", 300, False),
    ("diag", "diag_pipeline", 300, False),
    ("diag", "diag_threat_model", 300, False),
    ("diag", "diag_training", 300, False),
    ("hcrl", "hcrl_dataset", 1800, False),
    ("hcrl", "hcrl_rules", 1800, False),
    ("hcrl", "hcrl_rf", 1800, False),
    ("hcrl", "hcrl_transfer", 1800, False),
    ("hcrl", "hcrl_sensitivity", 1800, False),
    ("hcrl", "hcrl_window", 1800, False),
    ("hcrl", "hcrl_summary", 300, False),
    ("sys", "sys_01_microbench", 900, False),
    ("sys", "sys_02_security", 900, False),
    ("sys", "sys_03_bandwidth", 900, False),
    ("sys", "sys_04_latency", 3600, True),
    ("sys", "sys_05_scalability", 3600, True),
    ("sys", "sys_06_health", 1800, False),
    ("sys", "sys_07_cyber_timeline", 900, False),
    ("sys", "sys_summary", 300, False),
]


def _snapshot() -> dict[str, str]:
    out = {}
    for d in OUT_DIRS:
        for p in d.glob("*"):
            if p.is_file() and p.suffix in {".json", ".csv", ".tex", ".pdf", ".png", ".md"} and p.name != "RUN_MANIFEST.json":
                out[str(p.relative_to(PAPER))] = hashlib.sha1(p.read_bytes()).hexdigest()
    return out


def _code_version() -> dict[str, str]:
    def git(*a: str) -> str:
        try:
            return subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True, timeout=20).stdout.strip()
        except Exception:  # noqa: BLE001
            return ""
    return {"commit": git("rev-parse", "--short", "HEAD"), "dirty_files": str(len(git("status", "--porcelain").splitlines()))}


def _kill_tree(proc: subprocess.Popen) -> None:
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
    else:
        proc.kill()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="skip long timing runs (sys_04, sys_05)")
    ap.add_argument("--only", choices=["diag", "hcrl", "sys"])
    ap.add_argument("--cold", action="store_true", help="delete cached HCRL intermediates first")
    a = ap.parse_args()

    if a.cold:
        for c in (RES / "hcrl_cache", ROOT / "ml_training" / "data" / "hcrl_cache"):
            shutil.rmtree(c, ignore_errors=True)
    if a.only in (None, "hcrl") and not (ROOT / "data" / "hcrl").is_dir():
        print("WARNING: data/hcrl/ missing - hcrl steps will fail (dataset is not in the repo).")

    LOGS.mkdir(parents=True, exist_ok=True)
    before = _snapshot()
    steps, t_all = [], time.time()
    for group, mod, timeout, long in STEPS:
        if (a.only and group != a.only) or (a.quick and long):
            steps.append({"step": mod, "group": group, "status": "SKIPPED"})
            continue
        log = LOGS / f"{mod}.log"
        t0 = time.time()
        print(f"[{datetime.now():%H:%M:%S}] {mod} ...", end=" ", flush=True)
        with open(log, "w", encoding="utf-8") as fh:
            proc = subprocess.Popen([sys.executable, "-m", f"paper.experiments.{mod}"], cwd=ROOT,
                                    stdout=fh, stderr=subprocess.STDOUT)
            try:
                rc = proc.wait(timeout=timeout)
                status = "OK" if rc == 0 else f"FAILED (exit {rc})"
            except subprocess.TimeoutExpired:
                _kill_tree(proc)
                status = f"TIMEOUT (> {timeout} s)"
        dt = time.time() - t0
        print(f"{status}  {dt:.0f} s", flush=True)
        if status != "OK":
            print("    last log lines:\n    " + "\n    ".join(log.read_text(encoding="utf-8", errors="replace").splitlines()[-8:]))
        steps.append({"step": mod, "group": group, "status": status, "seconds": round(dt, 1), "log": str(log.relative_to(PAPER))})

    after = _snapshot()
    changed = sorted(k for k in after if before.get(k) != after[k])
    untouched = sorted(k for k in after if k in before and before[k] == after[k])
    manifest = {
        "finished": datetime.now().isoformat(timespec="seconds"),
        "total_seconds": round(time.time() - t_all, 1),
        "code": _code_version(),
        "python": sys.version.split()[0],
        "args": vars(a),
        "steps": steps,
        "outputs_changed": changed,
        "outputs_identical": untouched,
    }
    (RES / "RUN_MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    bad = [s for s in steps if s["status"] not in ("OK", "SKIPPED")]
    print(f"\n{len(steps) - len(bad)}/{len(steps)} steps OK or skipped; {len(changed)} outputs changed, "
          f"{len(untouched)} byte-identical. Manifest: paper/results/RUN_MANIFEST.json")
    for s in bad:
        print(f"  {s['status']}: {s['step']} (see paper/{s['log']})")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
