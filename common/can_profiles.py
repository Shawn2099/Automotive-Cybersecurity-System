"""DBC-style CAN profiles loaded from common/profiles/*.json, with generic encode/decode.

A profile lists messages (CAN ID, DLC, period) and their signals in DBC terms
(Intel/little-endian start bit, length, factor, offset, signed). Adding a car = adding a JSON
file (e.g. derived from an opendbc DBC). `background` messages are extra IDs replayed with a
fixed payload (filled by ml_training/hcrl_import.py from measured HCRL normal traffic).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROFILE_DIR = Path(__file__).resolve().parent / "profiles"
DEFAULT_PROFILE = "hyundai_sonata_hcrl"


@dataclass(frozen=True)
class Signal:
    name: str
    start: int
    length: int
    factor: float
    offset: float
    signed: bool
    min: float
    max: float


@dataclass(frozen=True)
class Message:
    id: int
    name: str
    dlc: int
    period_ms: float
    signals: tuple[Signal, ...]
    static_data: bytes = b""  # base payload for bits not covered by signals
    attack_target: str | None = None
    spoof_data: bytes = b""  # exact injected payload from the HCRL attack files, if known


@dataclass(frozen=True)
class CanProfile:
    profile_id: str
    brand: str
    model: str
    description: str
    messages: tuple[Message, ...]
    background: tuple[Message, ...] = field(default=())
    periods_source: str = "assumed"
    attack_behaviour: dict = field(default_factory=dict)  # attack -> {inject_fps, legit_keep} measured from HCRL

    @property
    def all_messages(self) -> tuple[Message, ...]:
        return self.messages + self.background

    @property
    def valid_ids(self) -> set[int]:
        return {m.id for m in self.all_messages}

    @property
    def expected_hz(self) -> dict[int, float]:
        return {m.id: 1000.0 / m.period_ms for m in self.all_messages if m.period_ms > 0}

    @property
    def expected_total_hz(self) -> float:
        return sum(self.expected_hz.values())

    def message(self, can_id: int) -> Message | None:
        for m in self.all_messages:
            if m.id == can_id:
                return m
        return None

    def id_for_signal(self, signal: str) -> int | None:
        for m in self.messages:
            if any(s.name == signal for s in m.signals):
                return m.id
        return None

    def attack_target_id(self, attack: str) -> int | None:
        for m in self.messages:
            if m.attack_target == attack:
                return m.id
        return None

    @property
    def signal_names(self) -> list[str]:
        return [s.name for m in self.messages for s in m.signals]


def _load_profile(path: Path) -> CanProfile:
    raw = json.loads(path.read_text(encoding="utf-8"))

    def msg(d: dict[str, Any]) -> Message:
        sigs = tuple(
            Signal(n, int(s["start"]), int(s["len"]), float(s["factor"]), float(s["offset"]),
                   bool(s.get("signed", False)), float(s.get("min", -1e18)), float(s.get("max", 1e18)))
            for n, s in (d.get("signals") or {}).items()
        )
        return Message(int(d["id"]), d.get("name", hex(int(d["id"]))), int(d.get("dlc", 8)),
                       float(d.get("period_ms", 0)), sigs, bytes.fromhex(d.get("data", "")),
                       d.get("hcrl_attack_target"), bytes.fromhex(d.get("spoof_data", "")))

    return CanProfile(
        profile_id=raw["profile_id"], brand=raw.get("brand", ""), model=raw.get("model", ""),
        description=raw.get("description", ""),
        messages=tuple(msg(m) for m in raw["messages"]),
        background=tuple(msg(m) for m in raw.get("background", [])),
        periods_source=raw.get("periods_source", "assumed"),
        attack_behaviour={k: v for k, v in (raw.get("attack_behaviour") or {}).items() if not k.startswith("_")},
    )


def load_profiles(directory: Path = PROFILE_DIR) -> dict[str, CanProfile]:
    out = {}
    for p in sorted(directory.glob("*.json")):
        prof = _load_profile(p)
        out[prof.profile_id] = prof
    return out


CAN_PROFILES: dict[str, CanProfile] = load_profiles()


def get_profile(profile_id: str) -> CanProfile:
    """Return a registered CAN profile or raise KeyError."""
    if profile_id not in CAN_PROFILES:
        raise KeyError(f"Unknown CAN profile: {profile_id}")
    return CAN_PROFILES[profile_id]


# ------------------------------------------------------------------ bit packing (DBC Intel @1)
def _put(word: int, sig: Signal, value: float) -> int:
    value = max(sig.min, min(sig.max, float(value)))
    raw = int(round((value - sig.offset) / sig.factor))
    mask = (1 << sig.length) - 1
    if sig.signed:
        lo, hi = -(1 << (sig.length - 1)), (1 << (sig.length - 1)) - 1
        raw = max(lo, min(hi, raw)) & mask
    else:
        raw = max(0, min(mask, raw))
    word &= ~(mask << sig.start)
    return word | (raw << sig.start)


def _get(word: int, sig: Signal) -> float:
    mask = (1 << sig.length) - 1
    raw = (word >> sig.start) & mask
    if sig.signed and raw & (1 << (sig.length - 1)):
        raw -= 1 << sig.length
    return raw * sig.factor + sig.offset


def encode_message(msg: Message, state: dict[str, Any]) -> dict[str, Any]:
    base = msg.static_data.ljust(msg.dlc, b"\x00")[: msg.dlc]
    word = int.from_bytes(base, "little")
    for s in msg.signals:
        if s.name in state and state[s.name] is not None:
            word = _put(word, s, state[s.name])
    data = word.to_bytes(msg.dlc, "little")
    return {"id": msg.id, "dlc": msg.dlc, "data": data.hex().upper()}


def encode_telemetry_to_frames(profile_id: str, state: dict[str, Any],
                               ids: set[int] | None = None) -> list[dict[str, Any]]:
    """One frame per profile message (optionally only `ids`), packing state signals."""
    prof = get_profile(profile_id)
    return [encode_message(m, state) for m in prof.all_messages if ids is None or m.id in ids]


def decode_can_frames(profile_id: str, frames: list[dict[str, Any]]) -> dict[str, Any]:
    """Decode raw CAN frame dicts into named signals and list unknown CAN IDs."""
    prof = get_profile(profile_id)
    signals: dict[str, Any] = {}
    unknown_ids: list[int] = []
    for frame in frames:
        can_id = int(frame["id"])
        msg = prof.message(can_id)
        if msg is None:
            unknown_ids.append(can_id)
            continue
        raw = bytes.fromhex(frame["data"])
        word = int.from_bytes(raw.ljust(msg.dlc, b"\x00"), "little")
        for s in msg.signals:
            if s.start + s.length <= max(len(raw), 1) * 8:
                v = _get(word, s)
                signals[s.name] = int(v) if s.name == "gear" else round(v, 3)
    return {"profile_id": profile_id, "signals": signals, "unknown_ids": unknown_ids,
            "frame_count": len(frames)}
