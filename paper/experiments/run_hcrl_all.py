"""Regenerate every HCRL result, table and figure, then the summary.

    python -m paper.experiments.run_hcrl_all

Order matters little; each script caches heavy intermediates in paper/results/hcrl_cache/ (delete it to recompute from scratch).
"""
from __future__ import annotations

import time

from paper.experiments import (hcrl_dataset, hcrl_rf, hcrl_rules, hcrl_sensitivity, hcrl_summary, hcrl_transfer,
                               hcrl_window)

if __name__ == "__main__":
    t0 = time.time()
    for m in (hcrl_dataset, hcrl_rules, hcrl_rf, hcrl_transfer, hcrl_sensitivity, hcrl_window, hcrl_summary):
        print(f"=== {m.__name__} ===", flush=True)
        m.main()
    print(f"done in {time.time() - t0:.0f} s")
