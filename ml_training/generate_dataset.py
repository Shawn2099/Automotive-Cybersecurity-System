"""Generate labeled per-batch datasets from the shared VirtualCar (Sonata / HCRL-spec profile).

Run:  python -m ml_training.generate_dataset
Output: ml_training/data/dataset.npz with
  X_health  (N, 9)   health features (merged last-known signals)
  X_traffic (N, 10)  traffic features (profile-relative rates, see analytics.traffic_features)
  y_attack  (N,)     normal | dos | fuzzy | spoofing   (per batch, attack active)
  y_fault   (N,)     0 = healthy batch, 1 = fault active
  clean     (N,)     1 if no fault and no attack (IsolationForest training set)
  settle    (N,)     1 if within ~0.6 s after an attack on/off change (rate smoothing lag)
  run_id    (N,)     scenario run index (used for the train/test split by run)
Attacks run as intermittent bursts (3-5 s on, 3-6 s off) like the HCRL injections.
"""

from __future__ import annotations

import random
from pathlib import Path

import numpy as np

from common.can_profiles import DEFAULT_PROFILE
from common.vehicle_sim import ATTACKS, FAULTS, VirtualCar, summarize_window
from server.app.analytics import FeatureState

DATA_DIR = Path(__file__).parent / "data"
DATASET_VERSION = 4  # 3: total_ratio / bus_load exclude non-HCRL messages
PROFILE = DEFAULT_PROFILE
WINDOW_MS = 100
DT = WINDOW_MS / 1000.0
SETTLE_S = 0.6
ATTACK_LABEL = {"dos": "dos", "fuzzy": "fuzzy", "rpm_spoof": "spoofing", "gear_spoof": "spoofing",
                "steering_spoof": "spoofing"}
KEYS = ("xh", "xt", "ya", "yf", "clean", "settle", "run")


class RandomDriver:
    """Random but physically sensible driving targets, changing every few seconds."""

    def __init__(self, car: VirtualCar, rng: random.Random) -> None:
        self.car, self.rng, self.next_t = car, rng, 0.0

    def tick(self, t: float) -> None:
        if t < self.next_t:
            return
        r, c = self.rng, self.car.controls
        self.next_t = t + r.uniform(2.0, 6.0)
        target = 0.0 if r.random() < 0.12 else r.uniform(10, 130)
        c["speed_kmh"] = target
        c["steering_deg"] = r.uniform(-400, 400) if r.random() < 0.1 else r.uniform(-90, 90) * r.random()
        if target > self.car.speed:
            c["throttle_pct"], c["brake_pct"] = r.uniform(10, 75), 0.0
        else:
            c["throttle_pct"], c["brake_pct"] = r.uniform(0, 12), (r.uniform(0, 40) if r.random() < 0.5 else 0.0)
        c["coolant_c"] = r.uniform(84, 100)
        c["battery_v"] = r.uniform(13.4, 14.4)


def burst_schedule(rng: random.Random, seconds: float, onset: float) -> list[tuple[float, float]]:
    """Intermittent injection bursts (3-5 s on, 3-6 s off), like HCRL's injected segments."""
    out, t = [], onset
    while t < seconds:
        d = rng.uniform(3.0, 5.0)
        out.append((t, min(seconds, t + d)))
        t += d + rng.uniform(3.0, 6.0)
    return out


def run_scenario(seed: int, run_id: int, seconds: float, fault: str | None = None,
                 attack: str | None = None, onset: float = 8.0, profile: str = PROFILE) -> dict[str, list]:
    rng = random.Random(seed)
    car = VirtualCar(profile, seed=seed)
    car.controls["speed_kmh"] = rng.uniform(0, 80)
    car.speed = car.controls["speed_kmh"] * rng.random()
    drv = RandomDriver(car, rng)
    fs = FeatureState(profile)
    bursts = burst_schedule(rng, seconds, onset) if attack else []
    out: dict[str, list] = {k: [] for k in KEYS}
    t, last_change, prev_on = 0.0, -1e9, False
    for _ in range(int(seconds / DT)):
        drv.tick(t)
        if fault and t >= onset:
            car.faults = {fault}
        a_on = any(a <= t < b for a, b in bursts)
        car.attacks = {attack} if a_on else set()
        if a_on != prev_on:
            last_change, prev_on = t, a_on
        frames = car.step(DT)
        t += DT
        batch = summarize_window(frames, WINDOW_MS)
        batch["ts_ms"] = int(t * 1000)
        ctx = fs.step(batch, None, t)
        if ctx["health_vec"] is None:
            continue
        f_on = bool(fault) and t >= onset
        out["xh"].append(ctx["health_vec"])
        out["xt"].append(ctx["traffic_vec"])
        out["ya"].append(ATTACK_LABEL[attack] if a_on else "normal")
        out["yf"].append(1 if f_on else 0)
        out["clean"].append(0 if (a_on or f_on) else 1)
        out["settle"].append(1 if t - last_change < SETTLE_S else 0)
        out["run"].append(run_id)
    return out


def generate(seed: int = 0, quick: bool = False) -> dict[str, np.ndarray]:
    n_norm, n_each = (3, 1) if quick else (14, 4)
    jobs: list[dict] = [dict(seconds=60) for _ in range(n_norm)]
    for f in FAULTS:
        jobs += [dict(seconds=45, fault=f) for _ in range(n_each)]
    for a in ATTACKS:
        jobs += [dict(seconds=45, attack=a) for _ in range(n_each)]
    acc: dict[str, list] = {k: [] for k in KEYS}
    for i, job in enumerate(jobs):
        res = run_scenario(run_id=i, seed=seed * 100003 + i, **job)
        for k in acc:
            acc[k].extend(res[k])
    return {
        "X_health": np.asarray(acc["xh"], dtype=np.float32),
        "X_traffic": np.asarray(acc["xt"], dtype=np.float32),
        "y_attack": np.asarray(acc["ya"]),
        "y_fault": np.asarray(acc["yf"], dtype=np.int8),
        "clean": np.asarray(acc["clean"], dtype=np.int8),
        "settle": np.asarray(acc["settle"], dtype=np.int8),
        "run_id": np.asarray(acc["run"], dtype=np.int32),
        "version": np.asarray(DATASET_VERSION),
    }


def main() -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ds = generate()
    path = DATA_DIR / "dataset.npz"
    np.savez_compressed(path, **ds)
    labels = dict(zip(*np.unique(ds["y_attack"], return_counts=True)))
    print(f"wrote {path}: {len(ds['y_attack'])} batches; labels: {labels}")
    return path


if __name__ == "__main__":
    main()
