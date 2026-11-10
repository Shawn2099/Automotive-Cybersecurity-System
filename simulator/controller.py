"""Car controller: VirtualCar runtime (ESP32 #1 stand-in) + REST API + web UI."""

from __future__ import annotations

import asyncio
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from common.vehicle_sim import ATTACKS, FAULTS, VirtualCar
from simulator.product_module import TUNNEL_TOGGLES, CarBus, VirtualProductModule

STATIC_DIR = Path(__file__).parent / "static"

BENCH_PROFILE = "hyundai_sonata_hcrl"
DEFAULT_PSK_1 = "00112233445566778899aabbccddeeff"
BURST_SECONDS = 4.0

# Short HCRL-style descriptions of the CAN attacks (shown in the controller UI).
ATTACK_INFO = {
    "dos": "DoS: ID 0x000, 8 zero bytes, one frame every 0.3 ms (~3300/s) - floods the bus.",
    "fuzzy": "Fuzzy: random ID (0x000-0x7FF) + random payload every 0.5 ms (~2000/s).",
    "rpm_spoof": "RPM spoof: forged RPM message (0x316) with RPM 6500, every 1 ms.",
    "gear_spoof": "Gear spoof: forged gear message (0x43F) forcing gear 1, every 1 ms.",
    "steering_spoof": "Steering spoof (extra): forged steering message alternating +/-450 deg, every 1 ms.",
}


def car_spec(device_id: int) -> dict[str, Any]:
    """Device 1 = the bench car. Other ids use PSK_DEVICE_<n> (the PSK the portal showed at registration)."""
    if device_id == 1:
        return {"device_id": 1, "name": "Bench Car (ESP32)", "profile_id": BENCH_PROFILE,
                "psk_hex": os.getenv("PSK_DEVICE_1", DEFAULT_PSK_1)}
    return {"device_id": device_id, "name": f"Bench Car #{device_id}", "profile_id": BENCH_PROFILE,
            "psk_hex": os.getenv(f"PSK_DEVICE_{device_id}", DEFAULT_PSK_1)}

RANGES = {
    "speed_kmh": (0, 200), "steering_deg": (-540, 540), "throttle_pct": (0, 100),
    "brake_pct": (0, 100), "coolant_c": (60, 130), "battery_v": (10.5, 14.8),
    "rpm": (0, 8000), "gear": (0, 6),
}
PRESETS = {
    "idle": {"speed_kmh": 0, "throttle_pct": 0, "brake_pct": 0, "steering_deg": 0, "auto_rpm": True},
    "city": {"speed_kmh": 40, "throttle_pct": 25, "brake_pct": 0, "steering_deg": 0, "auto_rpm": True},
    "highway": {"speed_kmh": 110, "throttle_pct": 45, "brake_pct": 0, "steering_deg": 0, "auto_rpm": True},
    "hard_brake": {"speed_kmh": 0, "throttle_pct": 0, "brake_pct": 100, "auto_rpm": True},
}


class CarRuntime:
    def __init__(self, device_id: int, name: str, profile_id: str, psk: bytes,
                 server_url: str, tick_s: float = 0.02, **module_kw: Any) -> None:
        self.device_id, self.name, self.profile_id = device_id, name, profile_id
        self.car = VirtualCar(profile_id)
        self.bus = CarBus()
        self.module = VirtualProductModule(device_id, psk, server_url, self.bus, **module_kw)
        self.tick_s = tick_s
        self._task: asyncio.Task | None = None
        self._bursts: dict[str, asyncio.Task] = {}

    async def _burst(self, attack: str, seconds: float) -> None:
        self.car.attacks.add(attack)
        try:
            await asyncio.sleep(seconds)
        finally:
            self.car.attacks.discard(attack)
            self._bursts.pop(attack, None)

    def burst(self, attack: str, seconds: float = BURST_SECONDS) -> None:
        """HCRL-style burst: attack on for `seconds`, then off. Re-triggering restarts the timer."""
        old = self._bursts.pop(attack, None)
        if old:
            old.cancel()
        self._bursts[attack] = asyncio.ensure_future(self._burst(attack, seconds))

    async def _car_loop(self) -> None:
        last = time.monotonic()
        while True:
            await asyncio.sleep(self.tick_s)
            now = time.monotonic()
            dt, last = min(now - last, 0.2), now
            self.bus.publish(self.car.step(dt))

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.ensure_future(self._car_loop())
        self.module.start()

    async def stop(self) -> None:
        for t in list(self._bursts.values()):
            t.cancel()
        self._bursts.clear()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        await self.module.stop()

    def snapshot(self) -> dict[str, Any]:
        c = self.car
        return {
            "device_id": self.device_id,
            "name": self.name,
            "profile_id": self.profile_id,
            "controls": dict(c.controls),
            "faults": sorted(c.faults),
            "attacks": sorted(c.attacks),
            "tunnel": dict(self.module.tunnel),
            "state": {k: (round(v, 2) if isinstance(v, float) else v) for k, v in c.state().items()},
            "link": dict(self.module.stats),
        }


class Simulator:
    def __init__(self, server_url: str, car_ids: list[int] | None = None, **module_kw: Any) -> None:
        self.server_url = server_url
        self.cars: dict[int, CarRuntime] = {}
        for device_id in (car_ids or [1]):
            spec = car_spec(device_id)
            self.cars[device_id] = CarRuntime(
                device_id, spec["name"], spec["profile_id"],
                bytes.fromhex(spec["psk_hex"]), server_url, **module_kw)

    def start(self) -> None:
        for c in self.cars.values():
            c.start()

    async def stop(self) -> None:
        for c in self.cars.values():
            await c.stop()


def _toggle(body: dict[str, Any], allowed, setter) -> None:
    for k, v in body.items():
        if k not in allowed:
            raise HTTPException(400, f"unknown name '{k}', allowed: {list(allowed)}")
        if not isinstance(v, bool):
            raise HTTPException(400, f"'{k}' must be true/false")
    for k, v in body.items():
        setter(k, v)


def create_app(sim: Simulator, autostart: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if autostart:
            sim.start()
        yield
        await sim.stop()

    app = FastAPI(title="Car Controller (simulator)", lifespan=lifespan)

    def get(car_id: int) -> CarRuntime:
        if car_id not in sim.cars:
            raise HTTPException(404, f"no car {car_id}")
        return sim.cars[car_id]

    @app.get("/api/cars")
    def list_cars() -> list[dict[str, Any]]:
        return [c.snapshot() for c in sim.cars.values()]

    @app.get("/api/cars/{car_id}")
    def one_car(car_id: int) -> dict[str, Any]:
        return get(car_id).snapshot()

    @app.post("/api/cars/{car_id}/controls")
    def controls(car_id: int, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        rt = get(car_id)
        clean: dict[str, Any] = {}
        for k, v in body.items():
            if k == "auto_rpm":
                if not isinstance(v, bool):
                    raise HTTPException(400, "auto_rpm must be true/false")
                clean[k] = v
            elif k in RANGES:
                if isinstance(v, bool) or not isinstance(v, (int, float)):
                    raise HTTPException(400, f"'{k}' must be a number")
                lo, hi = RANGES[k]
                v = max(lo, min(hi, v))
                clean[k] = int(v) if k == "gear" else float(v)
            else:
                raise HTTPException(400, f"unknown control '{k}', allowed: {list(RANGES) + ['auto_rpm']}")
        rt.car.controls.update(clean)
        return rt.snapshot()

    @app.post("/api/cars/{car_id}/preset")
    def preset(car_id: int, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        rt = get(car_id)
        name = body.get("name")
        if name not in PRESETS:
            raise HTTPException(400, f"unknown preset, allowed: {list(PRESETS)}")
        rt.car.controls.update(PRESETS[name])
        return rt.snapshot()

    def set_in(s: set, k: str, v: bool) -> None:
        (s.add if v else s.discard)(k)

    @app.post("/api/cars/{car_id}/faults")
    def faults(car_id: int, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        rt = get(car_id)
        _toggle(body, FAULTS, lambda k, v: set_in(rt.car.faults, k, v))
        return rt.snapshot()

    @app.post("/api/cars/{car_id}/attacks")
    def attacks(car_id: int, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        rt = get(car_id)
        _toggle(body, ATTACKS, lambda k, v: set_in(rt.car.attacks, k, v))
        return rt.snapshot()

    @app.post("/api/cars/{car_id}/burst")
    async def burst(car_id: int, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        """HCRL burst: {"attack": "dos", "seconds": 4} turns the attack on, then off again."""
        rt = get(car_id)
        name = body.get("attack")
        if name not in ATTACKS:
            raise HTTPException(400, f"unknown attack, allowed: {ATTACKS}")
        secs = body.get("seconds", BURST_SECONDS)
        if isinstance(secs, bool) or not isinstance(secs, (int, float)) or not 0.1 <= secs <= 30:
            raise HTTPException(400, "seconds must be a number between 0.1 and 30")
        rt.burst(name, float(secs))
        return rt.snapshot()

    @app.get("/api/attack-info")
    def attack_info() -> dict[str, str]:
        return ATTACK_INFO

    @app.post("/api/cars/{car_id}/tunnel")
    def tunnel(car_id: int, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        rt = get(car_id)
        _toggle(body, TUNNEL_TOGGLES, lambda k, v: rt.module.tunnel.__setitem__(k, v))
        return rt.snapshot()

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app
