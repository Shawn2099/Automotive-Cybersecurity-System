"""SQLite storage layer for multi-vehicle profiles, telemetry logs, and alerts."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from server.app.config import DEFAULT_VEHICLES


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    """Lightweight SQLite wrapper supporting multi-car telemetry and alerts."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_schema(self) -> None:
        """Create tables if missing and seed default demo vehicles when empty."""
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS vehicles (
                    device_id   INTEGER PRIMARY KEY,
                    owner_id    TEXT NOT NULL DEFAULT 'owner_1',
                    name        TEXT NOT NULL,
                    brand       TEXT NOT NULL,
                    model       TEXT NOT NULL,
                    plate       TEXT NOT NULL DEFAULT '',
                    can_profile TEXT NOT NULL,
                    psk_hex     TEXT NOT NULL,
                    created_at  TEXT NOT NULL,
                    last_seen_at TEXT
                );

                CREATE TABLE IF NOT EXISTS telemetry_logs (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id       INTEGER NOT NULL,
                    ts_ms           INTEGER NOT NULL,
                    seq_num         INTEGER NOT NULL,
                    speed_kmh       REAL,
                    rpm             REAL,
                    steering_deg    REAL,
                    throttle_pct    REAL,
                    brake_bar       REAL,
                    gear            INTEGER,
                    coolant_c       REAL,
                    oil_c           REAL,
                    battery_v       REAL,
                    fuel_pct        REAL,
                    flags           INTEGER,
                    bus_load_pct    INTEGER,
                    rx_err          INTEGER,
                    unknown_ids_json TEXT NOT NULL DEFAULT '[]',
                    received_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_telemetry_device_id
                    ON telemetry_logs(device_id, id DESC);

                CREATE TABLE IF NOT EXISTS alerts (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id    INTEGER NOT NULL,
                    category     TEXT NOT NULL,
                    severity     TEXT NOT NULL,
                    message      TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    created_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_device_id
                    ON alerts(device_id, id DESC);
                """
            )
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(vehicles)").fetchall()}
            if "last_seen_at" not in cols:  # migrate DBs created before provisioning existed
                conn.execute("ALTER TABLE vehicles ADD COLUMN last_seen_at TEXT")
            count = conn.execute("SELECT COUNT(*) AS cnt FROM vehicles").fetchone()["cnt"]
            if count == 0:
                now = _utc_now()
                conn.executemany(
                    """
                    INSERT INTO vehicles
                        (device_id, owner_id, name, brand, model, plate, can_profile, psk_hex, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            v["device_id"],
                            v["owner_id"],
                            v["name"],
                            v["brand"],
                            v["model"],
                            v["plate"],
                            v["can_profile"],
                            v["psk_hex"],
                            now,
                        )
                        for v in DEFAULT_VEHICLES
                    ],
                )

    def list_vehicles(self, owner_id: str | None = None) -> list[dict[str, Any]]:
        """Return registered vehicles without exposing raw PSKs."""
        query = (
            "SELECT device_id, owner_id, name, brand, model, plate, can_profile, created_at, last_seen_at "
            "FROM vehicles"
        )
        params: tuple[Any, ...] = ()
        if owner_id is not None:
            query += " WHERE owner_id = ?"
            params = (owner_id,)
        query += " ORDER BY device_id ASC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def get_vehicle(self, device_id: int) -> dict[str, Any] | None:
        """Fetch full vehicle record including psk_hex for decryption."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM vehicles WHERE device_id = ?", (device_id,)
            ).fetchone()
            return dict(row) if row else None

    def upsert_vehicle(self, vehicle: dict[str, Any]) -> dict[str, Any]:
        """Register or update a vehicle profile."""
        now = _utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO vehicles
                    (device_id, owner_id, name, brand, model, plate, can_profile, psk_hex, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    owner_id    = excluded.owner_id,
                    name        = excluded.name,
                    brand       = excluded.brand,
                    model       = excluded.model,
                    plate       = excluded.plate,
                    can_profile = excluded.can_profile,
                    psk_hex     = excluded.psk_hex
                """,
                (
                    vehicle["device_id"],
                    vehicle.get("owner_id", "owner_1"),
                    vehicle["name"],
                    vehicle["brand"],
                    vehicle["model"],
                    vehicle.get("plate", ""),
                    vehicle["can_profile"],
                    vehicle["psk_hex"],
                    now,
                ),
            )
        saved = self.get_vehicle(vehicle["device_id"])
        assert saved is not None
        saved.pop("psk_hex", None)
        return saved

    def next_free_device_id(self) -> int | None:
        """Smallest unused device_id in 1..65535 (None if the space is full)."""
        with self._connect() as conn:
            used = {r["device_id"] for r in conn.execute("SELECT device_id FROM vehicles").fetchall()}
        for i in range(1, 0x10000):
            if i not in used:
                return i
        return None

    def update_vehicle(self, device_id: int, fields: dict[str, Any]) -> dict[str, Any] | None:
        """Update editable columns (name, brand, model, plate, can_profile). Returns public record."""
        allowed = {"name", "brand", "model", "plate", "can_profile"}
        sets = {k: v for k, v in fields.items() if k in allowed}
        with self._connect() as conn:
            if sets:
                conn.execute(
                    f"UPDATE vehicles SET {', '.join(k + ' = ?' for k in sets)} WHERE device_id = ?",
                    (*sets.values(), device_id),
                )
        v = self.get_vehicle(device_id)
        if v:
            v.pop("psk_hex", None)
        return v

    def set_psk(self, device_id: int, psk_hex: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("UPDATE vehicles SET psk_hex = ? WHERE device_id = ?", (psk_hex, device_id))
            return cur.rowcount > 0

    def mark_seen(self, device_id: int) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE vehicles SET last_seen_at = ? WHERE device_id = ?", (_utc_now(), device_id))

    def log_telemetry(self, record: dict[str, Any]) -> int:
        """Persist a decoded telemetry sample and return its row id."""
        signals = record["signals"]
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO telemetry_logs (
                    device_id, ts_ms, seq_num, speed_kmh, rpm, steering_deg,
                    throttle_pct, brake_bar, gear, coolant_c, oil_c, battery_v,
                    fuel_pct, flags, bus_load_pct, rx_err, unknown_ids_json, received_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["device_id"],
                    record.get("ts_ms", 0),
                    record["seq_num"],
                    signals.get("speed_kmh"),
                    signals.get("rpm"),
                    signals.get("steering_deg"),
                    signals.get("throttle_pct"),
                    signals.get("brake_bar"),
                    signals.get("gear"),
                    signals.get("coolant_c"),
                    signals.get("oil_c"),
                    signals.get("battery_v"),
                    signals.get("fuel_pct"),
                    signals.get("flags"),
                    record.get("bus_load_pct", 0),
                    record.get("rx_err", 0),
                    json.dumps(record.get("unknown_ids", [])),
                    record.get("received_at", _utc_now()),
                ),
            )
            return int(cur.lastrowid)

    def get_telemetry_history(self, device_id: int, limit: int = 50) -> list[dict[str, Any]]:
        """Fetch recent telemetry records for a vehicle."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM telemetry_logs WHERE device_id = ? ORDER BY id DESC LIMIT ?",
                (device_id, limit),
            ).fetchall()
            result = []
            for r in rows:
                item = dict(r)
                item["unknown_ids"] = json.loads(item.pop("unknown_ids_json", "[]"))
                result.append(item)
            return result

    def log_alert(
        self,
        device_id: int,
        category: str,
        severity: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> int:
        """Persist a mechanical or cybersecurity alert."""
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO alerts (device_id, category, severity, message, details_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    category,
                    severity,
                    message,
                    json.dumps(details or {}),
                    _utc_now(),
                ),
            )
            return int(cur.lastrowid)

    def get_alerts(self, device_id: int | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """Fetch recent alerts, optionally filtered by device_id."""
        query = "SELECT * FROM alerts"
        params: list[Any] = []
        if device_id is not None:
            query += " WHERE device_id = ?"
            params.append(device_id)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
            result = []
            for r in rows:
                item = dict(r)
                item["details"] = json.loads(item.pop("details_json", "{}"))
                result.append(item)
            return result


    def delete_vehicle(self, device_id: int) -> bool:
        """Remove a vehicle and its telemetry/alerts. Returns True if it existed."""
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM vehicles WHERE device_id = ?", (device_id,))
            conn.execute("DELETE FROM telemetry_logs WHERE device_id = ?", (device_id,))
            conn.execute("DELETE FROM alerts WHERE device_id = ?", (device_id,))
            return cur.rowcount > 0
