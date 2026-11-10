"""FastAPI app: encrypted ingest (/ws/ingest), live dashboard feed (/ws/live), REST API, static dashboard."""

from __future__ import annotations

import logging
import os
import re
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from common.can_profiles import CAN_PROFILES, decode_can_frames
from common.crypto import PacketCryptoError, ReplayError
from common.tunnel import HandshakeError, ServerSession
from server.app.config import BASE_DIR, DEFAULT_DB_PATH, HTTP_HOST, HTTP_PORT, UNASSIGNED_PROFILE
from server.app.database import Database

log = logging.getLogger("server")
DASHBOARD_DIR = BASE_DIR / "server" / "dashboard"
MODEL_DIR = BASE_DIR / "server" / "models"
PSK_RE = re.compile(r"^[0-9a-fA-F]{32}$")
CYBER_CATEGORIES = {
    "dos", "fuzzy", "spoofing_rpm", "spoofing_gear", "spoofing_steering",
    "auth_fail", "replay", "tamper",
}


# ---------------------------------------------------------------- analytics (lazy, with stub fallback)
class StubAnalyzer:
    """Fallback when server.app.analytics is unavailable: neutral scores, tunnel-event alerts only."""

    def __init__(self, profile_id: str, models: Any = None) -> None:
        self._pending: list[dict[str, Any]] = []

    def update(self, batch: dict, decoded: dict, now_s: float) -> dict[str, Any]:
        return {
            "health": {"overall": 100, "engine": 100, "thermal": 100, "electrical": 100, "steering_brakes": 100},
            "cyber_risk": 0,
            "attack_class": "normal",
            "attack_confidence": 1.0,
            "anomaly_score": 0.0,
            "forecast": [],
            "alerts": [],
        }

    def record_tunnel_event(self, kind: str, now_s: float) -> None:
        sev = {"auth_fail": "high", "replay": "high", "tamper": "critical"}.get(kind, "medium")
        self._pending.append(
            {"category": kind, "kind": "cyber", "severity": sev, "message": f"Tunnel event: {kind}"}
        )

    def drain_alerts(self, now_s: float) -> list[dict[str, Any]]:
        out, self._pending = self._pending, []
        return out


def default_analyzer_factory() -> tuple[Callable[[str], Any], str]:
    try:
        from server.app.analytics import VehicleAnalyzer, load_models  # type: ignore

        try:
            models = load_models(MODEL_DIR)
        except Exception:  # noqa: BLE001
            log.exception("load_models failed; rules-only")
            models = None
        return (lambda profile_id: VehicleAnalyzer(profile_id, models)), "analytics"
    except Exception as exc:  # noqa: BLE001
        log.warning("analytics unavailable (%s); using stub analyzer", exc)
        return (lambda profile_id: StubAnalyzer(profile_id)), "stub"


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------- hub
class Hub:
    """Per-app runtime state: analyzers, link stats, merged signals, live websocket clients."""

    def __init__(self, db: Database, analyzer_factory: Callable[[str], Any]) -> None:
        self.db = db
        self.analyzer_factory = analyzer_factory
        self.analyzers: dict[int, Any] = {}
        self.links: dict[int, dict[str, Any]] = {}
        self.clients: set[WebSocket] = set()
        self.last_log_s: dict[int, float] = {}

    def link(self, device_id: int) -> dict[str, Any]:
        return self.links.setdefault(
            device_id,
            {
                "connected": False, "packets_ok": 0, "packets_rejected": 0,
                "last_cipher_hex": "", "last_plain": None,
                "signals": {}, "analysis": None, "_conns": 0,
            },
        )

    def analyzer(self, device_id: int, profile_id: str) -> Any:
        a = self.analyzers.get(device_id)
        if a is None:
            a = self.analyzers[device_id] = self.analyzer_factory(profile_id)
        return a

    def profile_supported(self, vehicle: dict[str, Any]) -> bool:
        return vehicle.get("can_profile") in CAN_PROFILES

    def status_of(self, vehicle: dict[str, Any]) -> str:
        """awaiting_device (never connected) | profile_unsupported (connected, no usable profile) | live | offline."""
        l = self.link(vehicle["device_id"])
        seen = bool(vehicle.get("last_seen_at") or l["packets_ok"] > 0 or l["connected"])
        if not seen:
            return "awaiting_device"  # never connected (regardless of profile)
        if not self.profile_supported(vehicle):
            return "profile_unsupported"  # device talks to us but we cannot decode it
        return "live" if l["connected"] else "offline"

    def public_vehicle(self, vehicle: dict[str, Any]) -> dict[str, Any]:
        v = {k: x for k, x in vehicle.items() if k != "psk_hex"}
        v["status"] = self.status_of(vehicle)
        v["connected"] = self.link(vehicle["device_id"])["connected"]
        v["profile_supported"] = self.profile_supported(vehicle)
        return v

    def reset_analysis(self, device_id: int) -> None:
        """Drop analyzer + decoded state (e.g. after the CAN profile changed); keep link state."""
        self.analyzers.pop(device_id, None)
        l = self.link(device_id)
        l["signals"], l["analysis"] = {}, None

    def forget(self, device_id: int) -> None:
        self.analyzers.pop(device_id, None)
        self.links.pop(device_id, None)
        self.last_log_s.pop(device_id, None)

    def link_public(self, device_id: int) -> dict[str, Any]:
        l = self.link(device_id)
        return {k: v for k, v in l.items() if k not in ("signals", "analysis", "_conns")}

    async def broadcast(self, msg: dict[str, Any]) -> None:
        dead = []
        for ws in list(self.clients):
            try:
                await ws.send_json(msg)
            except Exception:  # noqa: BLE001
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)

    async def emit_alerts(self, device_id: int, alerts: list[dict[str, Any]]) -> None:
        for al in alerts:
            al = dict(al)
            al.setdefault("kind", "cyber" if al.get("category") in CYBER_CATEGORIES else "mechanical")
            self.db.log_alert(
                device_id, al.get("category", "unknown"), al.get("severity", "low"),
                al.get("message", ""), {"kind": al["kind"], **{k: v for k, v in al.items()
                                                                if k not in ("category", "severity", "message")}},
            )
            await self.broadcast({"type": "alert", "device_id": device_id, "alert": al, "ts": _iso()})

    async def tunnel_event(self, device_id: int, kind: str) -> None:
        v = self.db.get_vehicle(device_id)
        if not v:
            return
        now = time.monotonic()
        try:
            if self.profile_supported(v):
                a = self.analyzer(device_id, v["can_profile"])
            else:  # no profile -> no analytics, but tunnel events are still worth reporting
                a = self.analyzers.setdefault(device_id, StubAnalyzer(""))
            a.record_tunnel_event(kind, now)
            pending = a.drain_alerts(now)
        except Exception:  # noqa: BLE001
            log.exception("analyzer tunnel event failed")
            pending = []
        await self.emit_alerts(device_id, pending)
        if not self.profile_supported(v):
            return
        # A device failing the handshake sends no data, so the analyzer never re-scores it.
        # Mark its last known state as "under tunnel attack" until valid batches resume.
        l = self.link(device_id)
        if not l["connected"] and kind == "auth_fail":
            an = dict(l["analysis"] or StubAnalyzer("").update({}, {}, now))
            an.update(cyber_risk=max(int(an.get("cyber_risk") or 0), 60),
                      attack_class="tunnel_attack", attack_confidence=0.95, alerts=[])
            l["analysis"] = an
            await self.broadcast({
                "type": "telemetry", "device_id": device_id,
                "signals": dict(l["signals"]), "analysis": an, "link": self.link_public(device_id),
            })

    async def set_connected(self, device_id: int, connected: bool) -> None:
        l = self.link(device_id)
        l["_conns"] += 1 if connected else -1
        l["connected"] = l["_conns"] > 0
        if connected:
            self.db.mark_seen(device_id)
        await self.broadcast({"type": "link", "device_id": device_id, "connected": l["connected"]})

    async def handle_batch(self, device_id: int, seq: int, batch: dict[str, Any], cipher_hex: str) -> None:
        v = self.db.get_vehicle(device_id)
        if not v:
            return
        l = self.link(device_id)
        l["packets_ok"] += 1
        l["last_cipher_hex"] = cipher_hex
        l["last_plain"] = batch
        if not self.profile_supported(v):
            # Registered car whose CAN profile is unassigned/unknown (e.g. legacy DB row): the
            # tunnel works, but we cannot decode or analyse its frames.
            l["signals"], l["analysis"] = {}, None
            return
        decoded = decode_can_frames(v["can_profile"], batch.get("frames", []))
        now = time.monotonic()
        a = self.analyzer(device_id, v["can_profile"])
        result = a.update(batch, decoded, now)
        l["analysis"] = result
        # The batch keeps only the latest frame per ID, so during an injection attack decoded values
        # may be the attacker's. Hold the last good values on the dashboard while an attack is active.
        if result.get("attack_class") in (None, "normal", "tunnel_attack"):
            l["signals"].update(decoded["signals"])
        await self.emit_alerts(device_id, result.get("alerts", []))
        if now - self.last_log_s.get(device_id, -1e9) >= 1.0:
            self.last_log_s[device_id] = now
            self.db.log_telemetry({
                "device_id": device_id, "ts_ms": int(batch.get("ts_ms", 0)), "seq_num": seq,
                "signals": l["signals"], "bus_load_pct": batch.get("bus_load_pct", 0),
                "rx_err": batch.get("rx_err", 0), "unknown_ids": decoded["unknown_ids"],
            })
        await self.broadcast({
            "type": "telemetry", "device_id": device_id,
            "signals": dict(l["signals"]), "analysis": result, "link": self.link_public(device_id),
        })


# ---------------------------------------------------------------- app factory
class VehicleIn(BaseModel):
    device_id: int | None = None
    name: str
    brand: str
    model: str
    plate: str
    can_profile: str | None = None
    psk_hex: str | None = None


class VehiclePatch(BaseModel):
    name: str | None = None
    brand: str | None = None
    model: str | None = None
    plate: str | None = None
    can_profile: str | None = None


def _norm_profile(value: str | None) -> str:
    """None / "" / "none" / "unassigned" -> "unassigned"; a known profile id -> itself; else 422."""
    if value is None or value.strip().lower() in ("", "none", UNASSIGNED_PROFILE):
        return UNASSIGNED_PROFILE
    if value not in CAN_PROFILES:
        raise HTTPException(422, f"unknown can_profile; choose one of {sorted(CAN_PROFILES)} or 'none'")
    return value


def create_app(db_path: Path | str | None = None,
               analyzer_factory: Callable[[str], Any] | None = None) -> FastAPI:
    db = Database(db_path or os.getenv("TELEMETRY_DB_PATH") or DEFAULT_DB_PATH)
    source = "custom"
    if analyzer_factory is None:
        analyzer_factory, source = default_analyzer_factory()
    hub = Hub(db, analyzer_factory)
    app = FastAPI(title="Vehicle Health & Cyber Monitor")
    app.state.hub = hub
    app.state.db = db
    app.state.analyzer_source = source

    def psk_lookup(device_id: int) -> bytes | None:
        v = db.get_vehicle(device_id)
        return bytes.fromhex(v["psk_hex"]) if v else None

    # ---- ingest
    @app.websocket("/ws/ingest")
    async def ws_ingest(ws: WebSocket) -> None:
        await ws.accept()
        session = ServerSession(psk_lookup)
        await ws.send_bytes(session.challenge())
        try:
            hello = await ws.receive_bytes()
            try:
                await ws.send_bytes(session.handle_hello(hello))
            except HandshakeError as exc:
                log.warning("handshake failed: %s", exc)
                if session.device_id is not None:
                    await hub.tunnel_event(session.device_id, "auth_fail")
                await ws.send_bytes(ServerSession.reject("auth failed"))
                await ws.close()
                return
        except (WebSocketDisconnect, KeyError, RuntimeError):
            return
        device_id = session.device_id
        assert device_id is not None
        await hub.set_connected(device_id, True)
        try:
            while True:
                msg = await ws.receive_bytes()
                l = hub.link(device_id)
                try:
                    env = session.open_data(msg)
                except ReplayError:
                    l["packets_rejected"] += 1
                    await hub.tunnel_event(device_id, "replay")
                    continue
                except PacketCryptoError:
                    l["packets_rejected"] += 1
                    await hub.tunnel_event(device_id, "tamper")
                    continue
                try:
                    await hub.handle_batch(device_id, env.seq_num, env.payload, msg[2:].hex()[:64])
                except Exception:  # noqa: BLE001
                    log.exception("batch handling failed")
        except (WebSocketDisconnect, KeyError, RuntimeError):
            pass
        finally:
            await hub.set_connected(device_id, False)

    # ---- live
    @app.websocket("/ws/live")
    async def ws_live(ws: WebSocket) -> None:
        await ws.accept()
        hub.clients.add(ws)
        try:
            for v in db.list_vehicles():
                l = hub.link(v["device_id"])
                await ws.send_json({"type": "link", "device_id": v["device_id"], "connected": l["connected"]})
                if l["analysis"] is not None:
                    await ws.send_json({
                        "type": "telemetry", "device_id": v["device_id"], "signals": dict(l["signals"]),
                        "analysis": l["analysis"], "link": hub.link_public(v["device_id"]),
                    })
            while True:
                await ws.receive_text()  # ignore client messages; detects disconnect
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            hub.clients.discard(ws)

    # ---- REST
    def provisioning(request: Request, device_id: int, psk_hex: str) -> dict[str, Any]:
        scheme = "wss" if request.url.scheme == "https" else "ws"
        return {
            "device_id": device_id,
            "psk_hex": psk_hex,
            "ingest_url": f"{scheme}://{request.url.netloc}/ws/ingest",
            "note": "Flash these into the ESP32 product module. The PSK is shown only once.",
        }

    @app.get("/api/vehicles")
    def list_vehicles() -> list[dict[str, Any]]:
        return [hub.public_vehicle(v) for v in db.list_vehicles()]

    @app.post("/api/vehicles", status_code=201)
    def add_vehicle(v: VehicleIn, request: Request) -> dict[str, Any]:
        for f in ("name", "brand", "model", "plate"):
            if not getattr(v, f).strip():
                raise HTTPException(422, f"{f} is required")
        device_id = v.device_id if v.device_id is not None else db.next_free_device_id()
        if device_id is None or not (1 <= device_id <= 0xFFFF):
            raise HTTPException(422, "device_id must be 1..65535")
        profile = _norm_profile(v.can_profile)
        if v.psk_hex:
            if not PSK_RE.match(v.psk_hex):
                raise HTTPException(422, "psk_hex must be 32 hex characters (16 bytes)")
            psk = v.psk_hex.lower()
        else:
            psk = secrets.token_hex(16)
        if db.get_vehicle(device_id):
            raise HTTPException(409, "device_id already registered")
        saved = db.upsert_vehicle({
            "device_id": device_id, "name": v.name.strip(), "brand": v.brand.strip(),
            "model": v.model.strip(), "plate": v.plate.strip(), "can_profile": profile, "psk_hex": psk,
        })
        out = hub.public_vehicle(saved)
        out["psk_hex"] = psk  # returned ONCE; GET never exposes it
        out["provisioning"] = provisioning(request, device_id, psk)
        return out

    @app.patch("/api/vehicles/{device_id}")
    def patch_vehicle(device_id: int, p: VehiclePatch) -> dict[str, Any]:
        cur = db.get_vehicle(device_id)
        if not cur:
            raise HTTPException(404, "unknown device")
        fields = {k: x.strip() for k, x in p.model_dump(exclude_none=True).items() if k != "can_profile"}
        if any(x == "" for x in fields.values()):
            raise HTTPException(422, "fields must not be empty")
        profile_changed = False
        if "can_profile" in p.model_fields_set:
            fields["can_profile"] = _norm_profile(p.can_profile)
            profile_changed = fields["can_profile"] != cur["can_profile"]
        saved = db.update_vehicle(device_id, fields)
        if profile_changed:
            hub.reset_analysis(device_id)
        assert saved is not None
        return hub.public_vehicle(saved)

    @app.post("/api/vehicles/{device_id}/rotate-key")
    def rotate_key(device_id: int, request: Request) -> dict[str, Any]:
        if not db.get_vehicle(device_id):
            raise HTTPException(404, "unknown device")
        psk = secrets.token_hex(16)
        db.set_psk(device_id, psk)  # live sessions keep their session key; the next handshake needs the new PSK
        return provisioning(request, device_id, psk)

    @app.delete("/api/vehicles/{device_id}")
    def delete_vehicle(device_id: int) -> dict[str, Any]:
        if not db.delete_vehicle(device_id):
            raise HTTPException(404, "unknown device")
        hub.forget(device_id)
        return {"deleted": device_id}

    @app.get("/api/alerts")
    def alerts(device_id: int | None = None, limit: int = 50) -> list[dict[str, Any]]:
        return db.get_alerts(device_id, max(1, min(limit, 500)))

    @app.get("/api/history/{device_id}")
    def history(device_id: int, limit: int = 120) -> list[dict[str, Any]]:
        return db.get_telemetry_history(device_id, max(1, min(limit, 5000)))

    @app.get("/api/profiles")
    def profiles() -> list[dict[str, Any]]:
        return [{
            "profile_id": p.profile_id, "brand": p.brand, "model": p.model, "description": p.description,
            "messages": [{"id": m.id, "id_hex": f"0x{m.id:03X}", "name": m.name,
                          "signals": [s.name for s in m.signals]} for m in p.messages],
        } for p in CAN_PROFILES.values()]

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        out = {}
        for v in db.list_vehicles():
            l = hub.link(v["device_id"])
            a = l["analysis"] or {}
            out[str(v["device_id"])] = {
                "name": v["name"], "connected": l["connected"], "status": hub.status_of(v),
                "profile_supported": hub.profile_supported(v), "can_profile": v["can_profile"],
                "packets_ok": l["packets_ok"], "packets_rejected": l["packets_rejected"],
                "health": (a.get("health") or {}).get("overall"), "cyber_risk": a.get("cyber_risk"),
                "attack_class": a.get("attack_class"),
            }
        return {"analyzer": app.state.analyzer_source, "devices": out}

    # ---- dashboard
    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(DASHBOARD_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    uvicorn.run("server.app.main:app", host=HTTP_HOST, port=HTTP_PORT)
