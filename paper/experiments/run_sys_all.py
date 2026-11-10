"""Run every sys_* experiment in order (from the project root: python -m paper.experiments.run_sys_all [--skip 4,5]).

Experiments 4 and 5 start their own server/simulator subprocesses on private ports (8865-8869) with temp DBs.
Run on an otherwise idle machine: 4 and 5 are timing measurements. Total runtime is roughly 45-60 minutes.
"""

from __future__ import annotations

import argparse
import importlib
import time

MODS = [
    ("1", "sys_01_microbench"), ("2", "sys_02_security"), ("3", "sys_03_bandwidth"),
    ("4", "sys_04_latency"), ("5", "sys_05_scalability"), ("6", "sys_06_health"), ("7", "sys_07_cyber_timeline"),
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip", default="", help="comma-separated experiment numbers to skip")
    a = ap.parse_args()
    skip = set(filter(None, a.skip.split(",")))
    import sys

    sys.argv = sys.argv[:1]  # sys_04 reads an optional trial count from argv
    for num, mod in MODS:
        if num in skip:
            continue
        t0 = time.time()
        print(f"=== experiment {num}: {mod}", flush=True)
        importlib.import_module(f"paper.experiments.{mod}").main()
        print(f"=== {mod} done in {time.time() - t0:.0f} s", flush=True)


if __name__ == "__main__":
    main()
