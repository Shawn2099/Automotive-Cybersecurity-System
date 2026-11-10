"""AES-128-GCM telemetry envelope encryption, decryption, and replay protection."""

from __future__ import annotations

import json
import os
import struct
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HEADER_FORMAT = ">HI12s"  # device_id (uint16), seq_num (uint32), nonce (12 bytes)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 18 bytes
GCM_TAG_SIZE = 16
MIN_PACKET_SIZE = HEADER_SIZE + GCM_TAG_SIZE


class PacketCryptoError(Exception):
    """Raised when packet framing, authentication, or decryption fails."""


class ReplayError(PacketCryptoError):
    """Raised when a packet sequence number is replayed or stale."""


@dataclass(frozen=True)
class DecryptedEnvelope:
    """Verified telemetry envelope extracted from an encrypted packet."""

    device_id: int
    seq_num: int
    payload: dict[str, Any]
    raw_size: int


def build_nonce(device_id: int, seq_num: int, boot_salt: bytes | None = None) -> bytes:
    """Construct a unique 12-byte GCM nonce from device_id, seq_num, and salt."""
    salt = boot_salt if boot_salt is not None else os.urandom(6)
    if len(salt) != 6:
        raise ValueError("boot_salt must be exactly 6 bytes")
    return struct.pack(">HI", device_id, seq_num) + salt


def encrypt_envelope(
    device_id: int,
    seq_num: int,
    payload: dict[str, Any],
    psk: bytes,
    boot_salt: bytes | None = None,
) -> bytes:
    """Serialize and encrypt a telemetry payload into the binary AES-128-GCM envelope."""
    if len(psk) != 16:
        raise ValueError("AES-128-GCM requires a 16-byte pre-shared key")
    if not (0 <= device_id <= 0xFFFF):
        raise ValueError("device_id must fit in uint16")
    if not (0 <= seq_num <= 0xFFFFFFFF):
        raise ValueError("seq_num must fit in uint32")

    nonce = build_nonce(device_id, seq_num, boot_salt=boot_salt)
    aad = struct.pack(">HI", device_id, seq_num)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext_and_tag = AESGCM(psk).encrypt(nonce, plaintext, aad)
    return struct.pack(HEADER_FORMAT, device_id, seq_num, nonce) + ciphertext_and_tag


def peek_device_id(packet: bytes) -> int:
    """Read device_id from an encrypted packet header without decrypting."""
    if len(packet) < MIN_PACKET_SIZE:
        raise PacketCryptoError(f"Packet too short ({len(packet)} bytes)")
    device_id, _seq_num, _nonce = struct.unpack(HEADER_FORMAT, packet[:HEADER_SIZE])
    return device_id


def decrypt_envelope(packet: bytes, psk: bytes) -> DecryptedEnvelope:
    """Verify the AES-128-GCM tag and decrypt a binary telemetry envelope."""
    if len(psk) != 16:
        raise ValueError("AES-128-GCM requires a 16-byte pre-shared key")
    if len(packet) < MIN_PACKET_SIZE:
        raise PacketCryptoError(f"Packet too short ({len(packet)} bytes)")

    device_id, seq_num, nonce = struct.unpack(HEADER_FORMAT, packet[:HEADER_SIZE])
    aad = struct.pack(">HI", device_id, seq_num)
    ciphertext_and_tag = packet[HEADER_SIZE:]

    try:
        plaintext = AESGCM(psk).decrypt(nonce, ciphertext_and_tag, aad)
    except InvalidTag as exc:
        raise PacketCryptoError("AES-GCM authentication failed (tampered or wrong key)") from exc

    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PacketCryptoError("Decrypted payload is not valid UTF-8 JSON") from exc

    if not isinstance(payload, dict):
        raise PacketCryptoError("Decrypted payload must be a JSON object")

    return DecryptedEnvelope(
        device_id=device_id,
        seq_num=seq_num,
        payload=payload,
        raw_size=len(packet),
    )


class ReplayGuard:
    """Tracks highest observed sequence numbers per device to block replay attacks."""

    def __init__(self) -> None:
        self._last_seq: dict[int, int] = {}

    def check_and_update(self, device_id: int, seq_num: int) -> None:
        """Raise ReplayError if seq_num is not strictly newer than the last seen one."""
        prev = self._last_seq.get(device_id)
        if prev is not None and seq_num <= prev:
            raise ReplayError(
                f"Replay/stale sequence for device {device_id}: got {seq_num}, last {prev}"
            )
        self._last_seq[device_id] = seq_num

    def reset_device(self, device_id: int) -> None:
        """Clear stored sequence state for a device (e.g., on authenticated reboot)."""
        self._last_seq.pop(device_id, None)

