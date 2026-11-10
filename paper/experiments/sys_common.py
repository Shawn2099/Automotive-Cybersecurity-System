"""Shared helpers for the sys_* system experiments (machine info, batch generation, server subprocess, LaTeX tables)."""

from __future__ import annotations

import json
import os
import platform
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from paper.experiments.style import RES_DIR, ROOT, TAB_DIR

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.vehicle_sim import ATTACKS, VirtualCar, summarize_window  # noqa: E402

PROFILE = "hyundai_sonata_hcrl"
PSK1 = bytes.fromhex("00112233445566778899aabbccddeeff")
WINDOW_MS = 100
SCENARIOS = ["normal"] + ATTACKS


# ------------------------------------------------------------------ machine
def _cpu_name() -> str:
    try:
        import winreg

        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
        return str(winreg.QueryValueEx(k, "ProcessorNameString")[0]).strip()
    except Exception:  # noqa: BLE001
        return platform.processor() or "unknown"


def machine_info() -> dict[str, Any]:
    import importlib.metadata as md

    libs = {}
    for n in ["numpy", "scipy", "matplotlib", "cryptography", "fastapi", "uvicorn", "websockets", "httpx",
              "scikit-learn", "psutil"]:
        try:
            libs[n] = md.version(n)
        except Exception:  # noqa: BLE001
            libs[n] = None
    info: dict[str, Any] = {
        "cpu": _cpu_name(), "os": platform.platform(), "python": sys.version.split()[0],
        "python_impl": platform.python_implementation(), "libs": libs,
    }
    try:
        import psutil

        info["cpu_cores_physical"] = psutil.cpu_count(logical=False)
        info["cpu_threads"] = psutil.cpu_count(logical=True)
        info["ram_gb"] = round(psutil.virtual_memory().total / 2**30, 1)
        b = psutil.sensors_battery()
        info["on_ac_power"] = None if b is None else bool(b.power_plugged)
    except Exception:  # noqa: BLE001
        info["cpu_threads"] = os.cpu_count()
    info["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
    return info


# ------------------------------------------------------------------ io
def save_json(name: str, obj: dict[str, Any]) -> Path:
    RES_DIR.mkdir(parents=True, exist_ok=True)
    obj = {"machine": machine_info(), **obj}
    p = RES_DIR / f"{name}.json"
    p.write_text(json.dumps(obj, indent=1, default=float), encoding="utf-8")
    return p


def load_json(name: str) -> dict[str, Any]:
    return json.loads((RES_DIR / f"{name}.json").read_text(encoding="utf-8"))


def save_csv(name: str, header: list[str], rows: list[list[Any]]) -> Path:
    RES_DIR.mkdir(parents=True, exist_ok=True)
    p = RES_DIR / f"{name}.csv"
    with p.open("w", encoding="utf-8", newline="") as f:
        f.write(",".join(header) + "\n")
        for r in rows:
            f.write(",".join(str(x) for x in r) + "\n")
    return p


def tex_escape(s: Any) -> str:
    s = str(s)
    for a, b in [("\\", r"\textbackslash{}"), ("_", r"\_"), ("%", r"\%"), ("&", r"\&"), ("#", r"\#")]:
        s = s.replace(a, b)
    return s


def write_table(name: str, header: list[str], rows: list[list[Any]], caption: str, label: str,
                colspec: str | None = None, escape: bool = True, resize: bool = False) -> Path:
    """IEEE-style booktabs table; goes into paper/tables/<name>.tex."""
    TAB_DIR.mkdir(parents=True, exist_ok=True)
    esc = tex_escape if escape else str
    colspec = colspec or ("l" + "r" * (len(header) - 1))
    lines = [r"\begin{table}[t]", r"\centering", r"\caption{" + caption + "}", r"\label{" + label + "}",
             r"\footnotesize" if not resize else r"\scriptsize"]
    lines += [r"\begin{tabular}{" + colspec + "}", r"\toprule",
              " & ".join(esc(h) if escape else h for h in header) + r" \\", r"\midrule"]
    for r in rows:
        lines.append(" & ".join(esc(x) for x in r) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    p = TAB_DIR / f"{name}.tex"
    p.write_text("\n".join(lines), encoding="utf-8")
    return p


# ------------------------------------------------------------------ batches
NOMINAL_FPS = {"dos": 1 / 0.0003, "fuzzy": 1 / 0.0005, "rpm_spoof": 1000.0, "gear_spoof": 1000.0,
               "steering_spoof": 1000.0}


def make_car(seed: int = 1, speed: float = 40.0, throttle: float = 25.0, nominal: bool = False) -> VirtualCar:
    """nominal=True: injection at the nominal HCRL-paper rates and legitimate traffic NOT crowded out (worst case
    for bandwidth); default: the simulator's measured-HCRL behaviour (what the live demo produces)."""
    car = VirtualCar(PROFILE, seed=seed)
    if nominal:
        car._behaviour = lambda a: {"inject_fps": NOMINAL_FPS[a], "legit_keep": 1.0}  # type: ignore[method-assign]
    car.controls.update({"speed_kmh": speed, "throttle_pct": throttle})
    return car


def run_windows(car: VirtualCar, n: int, window_ms: int = WINDOW_MS, sub: int = 5):
    """Yield (frames, batch) for n windows; the car ticks at window/sub like the live simulator (20 ms)."""
    dt = window_ms / 1000.0 / sub
    for _ in range(n):
        frames: list[dict[str, Any]] = []
        for _ in range(sub):
            frames.extend(car.step(dt))
        yield frames, summarize_window(frames, window_ms)


def gen_scenario(attack: str, seconds: float = 20.0, warm_s: float = 3.0, seed: int = 1,
                 keep_frames: bool = False, nominal: bool = False):
    """(list of frames-per-window or None, list of batches with ts_ms) for a scenario at 10 Hz."""
    car = make_car(seed, nominal=nominal)
    for _ in run_windows(car, int(warm_s * 10)):
        pass
    if attack != "normal":
        car.attacks.add(attack)
    fl, bl = [], []
    t_ms = 0
    for frames, b in run_windows(car, int(seconds * 10)):
        t_ms += WINDOW_MS
        b["ts_ms"] = t_ms
        bl.append(b)
        if keep_frames:
            fl.append(frames)
    return fl, bl


def compact_json(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def pct(a, q):
    import numpy as np

    return float(np.percentile(np.asarray(a, dtype=float), q))


# ------------------------------------------------------------------ subprocesses
def free_port(preferred: int) -> int:
    for p in [preferred] + list(range(preferred + 1, preferred + 30)):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    raise RuntimeError("no free port")


class ServerProc:
    """Own server (and optionally own simulator) on private ports with a temp DB. Never touches 8000/8001/8100."""

    def __init__(self, port: int = 8865, sim_port: int | None = None) -> None:
        assert port not in (8000, 8001, 8100)
        self.port = free_port(port)
        self.sim_port = free_port(sim_port) if sim_port else None
        self.tmp = tempfile.mkdtemp(prefix="sysexp_")
        self.srv: subprocess.Popen | None = None
        self.sim: subprocess.Popen | None = None

    @property
    def http(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def ws_ingest(self) -> str:
        return f"ws://127.0.0.1:{self.port}/ws/ingest"

    @property
    def ws_live(self) -> str:
        return f"ws://127.0.0.1:{self.port}/ws/live"

    @property
    def sim_http(self) -> str:
        return f"http://127.0.0.1:{self.sim_port}"

    def start(self) -> "ServerProc":
        import httpx

        env = dict(os.environ, TELEMETRY_DB_PATH=str(Path(self.tmp) / "sys.db"), TELEMETRY_HTTP_PORT=str(self.port),
                   TELEMETRY_HTTP_HOST="127.0.0.1", PYTHONPATH=str(ROOT))
        self.srv = subprocess.Popen([sys.executable, "-m", "server.app.main"], cwd=ROOT, env=env,
                                    stdout=open(Path(self.tmp) / "server.log", "w"), stderr=subprocess.STDOUT)
        self._wait(lambda: httpx.get(f"{self.http}/api/status", timeout=2).status_code == 200, 40, "server")
        if self.sim_port:
            self.sim = subprocess.Popen(
                [sys.executable, "-m", "simulator", "--server", self.ws_ingest, "--port", str(self.sim_port),
                 "--cars", "1", "--host", "127.0.0.1"], cwd=ROOT, env=env,
                stdout=open(Path(self.tmp) / "sim.log", "w"), stderr=subprocess.STDOUT)
            self._wait(lambda: httpx.get(f"{self.sim_http}/api/cars", timeout=2).status_code == 200, 40, "simulator")
        return self

    @staticmethod
    def _wait(pred, timeout: float, what: str) -> None:
        end = time.time() + timeout
        while time.time() < end:
            try:
                if pred():
                    return
            except Exception:  # noqa: BLE001
                pass
            time.sleep(0.3)
        raise RuntimeError(f"{what} did not start")

    def stop(self) -> None:
        for p in (self.sim, self.srv):
            if p is not None:
                p.terminate()
        for p in (self.sim, self.srv):
            if p is not None:
                try:
                    p.wait(10)
                except subprocess.TimeoutExpired:
                    p.kill()

    def __enter__(self) -> "ServerProc":
        return self.start()

    def __exit__(self, *a) -> None:
        self.stop()
