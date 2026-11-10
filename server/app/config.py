"""Configuration defaults for the local LAN telemetry server."""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = Path(os.getenv("TELEMETRY_DB_PATH", str(BASE_DIR / "telemetry.db")))

TCP_HOST = os.getenv("TELEMETRY_TCP_HOST", "0.0.0.0")
TCP_PORT = int(os.getenv("TELEMETRY_TCP_PORT", "9000"))

HTTP_HOST = os.getenv("TELEMETRY_HTTP_HOST", "0.0.0.0")
HTTP_PORT = int(os.getenv("TELEMETRY_HTTP_PORT", "8000"))

# Seed: ONE default vehicle, the ESP32 bench car (HCRL / Hyundai YF Sonata CAN spec).
# 16-byte (32 hex char) AES-128-GCM pre-shared key; override with PSK_DEVICE_1.
# More cars are registered through the portal (POST /api/vehicles) and get a generated PSK.
DEFAULT_VEHICLES = [
    {
        "device_id": 1,
        "owner_id": "owner_1",
        "name": "Bench Car (ESP32)",
        "brand": "Hyundai",
        "model": "YF Sonata (HCRL spec)",
        "plate": "BENCH-01",
        "can_profile": "hyundai_sonata_hcrl",
        "psk_hex": os.getenv("PSK_DEVICE_1", "00112233445566778899aabbccddeeff"),
    },
]

# can_profile value for cars that are registered but have no CAN profile yet.
UNASSIGNED_PROFILE = "unassigned"
