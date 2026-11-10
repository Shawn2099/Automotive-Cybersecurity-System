"""VirtualProductModule: stand-in for ESP32 #2 (read-only CAN tap + encrypted uplink)."""

from __future__ import annotations

import asyncio
import collections
import logging
import time
from typing import Any

from websockets.asyncio.client import connect
from websockets.exceptions import WebSocketException

from common.tunnel import ClientSession, HandshakeError
from common.vehicle_sim import summarize_window

log = logging.getLogger("simulator.module")

TUNNEL_TOGGLES = ("replay", "tamper", "wrong_key")


class CarBus:
    """The 'CAN bus': the car appends frames, the product module drains them (read-only)."""

    def __init__(self, maxlen: int = 20000) -> None:
        self._frames: collections.deque[dict[str, Any]] = collections.deque(maxlen=maxlen)

    def publish(self, frames: list[dict[str, Any]]) -> None:
        self._frames.extend(frames)

    def drain(self) -> list[dict[str, Any]]:
        out = list(self._frames)
        self._frames.clear()
        return out


class VirtualProductModule:
    def __init__(
        self,
        device_id: int,
        psk: bytes,
        server_url: str,
        bus: CarBus,
        window_ms: int = 100,
        wrong_key_retry_s: float = 3.0,
    ) -> None:
        self.device_id = device_id
        self.psk = psk
        self.server_url = server_url
        self.bus = bus
        self.window_ms = window_ms
        self.wrong_key_retry_s = wrong_key_retry_s
        self.tunnel: dict[str, bool] = {k: False for k in TUNNEL_TOGGLES}
        self.stats: dict[str, Any] = {
            "packets_sent": 0,
            "replays_sent": 0,
            "tampered_sent": 0,
            "handshakes_ok": 0,
            "handshake_failures": 0,
            "connected": False,
            "last_error": None,
            "last_cipher_hex": None,
        }
        self._task: asyncio.Task | None = None

    # ------------------------------------------------------------- lifecycle
    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.ensure_future(self.run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        self.stats["connected"] = False

    def _wrong_psk(self) -> bytes:
        return bytes(b ^ 0xFF for b in self.psk)

    # ------------------------------------------------------------- main loop
    async def run(self) -> None:
        backoff = 0.5
        while True:
            wrong = self.tunnel["wrong_key"]
            try:
                await self._session(wrong)
                backoff = 0.5
            except asyncio.CancelledError:
                raise
            except HandshakeError as exc:
                self.stats["handshake_failures"] += 1
                self.stats["last_error"] = f"handshake: {exc}"
            except (OSError, WebSocketException, asyncio.TimeoutError) as exc:
                self.stats["last_error"] = f"{type(exc).__name__}: {exc}"
            except Exception as exc:  # PoC: never die
                self.stats["last_error"] = f"{type(exc).__name__}: {exc}"
            self.stats["connected"] = False
            if wrong:
                delay = self.wrong_key_retry_s
            else:
                delay = backoff
                backoff = min(backoff * 2, 5.0)
            # wake early if the wrong_key toggle flips
            end = time.monotonic() + delay
            while time.monotonic() < end and self.tunnel["wrong_key"] == wrong:
                await asyncio.sleep(0.05)

    async def _session(self, wrong: bool) -> None:
        psk = self._wrong_psk() if wrong else self.psk
        cs = ClientSession(self.device_id, psk)
        async with connect(self.server_url, open_timeout=5, max_size=2**20) as ws:
            ch = await asyncio.wait_for(ws.recv(), 5)
            await ws.send(cs.handle_challenge(ch))
            resp = await asyncio.wait_for(ws.recv(), 5)
            cs.handle_welcome(resp)  # raises HandshakeError on NO / bad MAC
            self.stats["handshakes_ok"] += 1
            self.stats["connected"] = True
            self.stats["last_error"] = None
            await self._send_loop(ws, cs, wrong)

    async def _send_loop(self, ws, cs: ClientSession, wrong: bool) -> None:
        loop = asyncio.get_running_loop()
        window_s = self.window_ms / 1000.0
        self.bus.drain()  # drop stale frames from before (re)connect
        history: collections.deque[bytes] = collections.deque(maxlen=10)
        n = 0
        last_replay = loop.time()
        next_t = loop.time()
        while True:
            next_t += window_s
            await asyncio.sleep(max(0.0, next_t - loop.time()))
            if self.tunnel["wrong_key"] != wrong:
                return  # reconnect with the right/wrong key
            batch = summarize_window(self.bus.drain(), self.window_ms)
            batch["ts_ms"] = int(time.monotonic() * 1000)
            msg = cs.seal(batch)
            history.append(msg)
            n += 1
            out = msg
            if self.tunnel["tamper"] and n % 5 == 0 and len(msg) > 24:
                b = bytearray(msg)
                b[2 + 18 + 2] ^= 0x01  # flip one ciphertext bit
                out = bytes(b)
                self.stats["tampered_sent"] += 1
            await ws.send(out)
            self.stats["packets_sent"] += 1
            self.stats["last_cipher_hex"] = out[:32].hex()
            if self.tunnel["replay"] and loop.time() - last_replay >= 1.0 and len(history) > 1:
                last_replay = loop.time()
                await ws.send(history[0])  # old seq -> ReplayError on the server
                self.stats["replays_sent"] += 1
