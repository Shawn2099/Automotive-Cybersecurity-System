"""Encrypted device tunnel: PSK challenge-response handshake + AES-128-GCM data frames.

Transport-agnostic: every method takes/returns raw message bytes, which the caller carries
over a binary WebSocket (see PLAN.md §3). The same byte layout is what the ESP32 #2 firmware
will implement later with mbedTLS (HMAC-SHA256 + AES-GCM).

    S → D  b"CH" ‖ server_nonce(16)
    D → S  b"HE" ‖ device_id(2 BE) ‖ device_nonce(16) ‖ mac_d(16)
    S → D  b"OK" ‖ mac_s(16)        |  b"NO" ‖ reason
    D → S  b"DA" ‖ envelope (common.crypto, keyed with the per-session key)
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import Any, Callable

from common.crypto import (
    DecryptedEnvelope,
    PacketCryptoError,
    ReplayGuard,
    decrypt_envelope,
    encrypt_envelope,
)

NONCE_LEN = 16
MAC_LEN = 16

T_CHALLENGE = b"CH"
T_HELLO = b"HE"
T_WELCOME = b"OK"
T_REJECT = b"NO"
T_DATA = b"DA"


class HandshakeError(PacketCryptoError):
    """Handshake failed: unknown device, bad MAC, or malformed message."""


def _mac(psk: bytes, label: bytes, *parts: bytes) -> bytes:
    return hmac.new(psk, label + b"".join(parts), hashlib.sha256).digest()[:MAC_LEN]


def derive_session_key(psk: bytes, server_nonce: bytes, device_nonce: bytes) -> bytes:
    """16-byte AES-128 session key, unique per connection."""
    return _mac(psk, b"SESSION", server_nonce, device_nonce)


class ServerSession:
    """Server side of one device connection."""

    def __init__(self, psk_lookup: Callable[[int], bytes | None]) -> None:
        self._lookup = psk_lookup
        self.server_nonce = os.urandom(NONCE_LEN)
        self.device_id: int | None = None
        self._key: bytes | None = None
        self._guard = ReplayGuard()

    @property
    def established(self) -> bool:
        return self._key is not None

    def challenge(self) -> bytes:
        return T_CHALLENGE + self.server_nonce

    def handle_hello(self, msg: bytes) -> bytes:
        """Verify HELLO; returns the WELCOME message. Raises HandshakeError (caller sends reject())."""
        if len(msg) != 2 + 2 + NONCE_LEN + MAC_LEN or msg[:2] != T_HELLO:
            raise HandshakeError("malformed HELLO")
        (device_id,) = struct.unpack(">H", msg[2:4])
        device_nonce = msg[4 : 4 + NONCE_LEN]
        mac_d = msg[4 + NONCE_LEN :]
        self.device_id = device_id  # recorded even on failure so the server can attribute auth_fail
        psk = self._lookup(device_id)
        if psk is None:
            raise HandshakeError(f"unknown device_id {device_id}")
        did = msg[2:4]
        expected = _mac(psk, b"HELLO", did, self.server_nonce, device_nonce)
        if not hmac.compare_digest(expected, mac_d):
            raise HandshakeError(f"bad HELLO MAC for device {device_id} (wrong key?)")
        self._key = derive_session_key(psk, self.server_nonce, device_nonce)
        return T_WELCOME + _mac(psk, b"WELCOME", did, self.server_nonce, device_nonce)

    @staticmethod
    def reject(reason: str) -> bytes:
        return T_REJECT + reason.encode("utf-8")[:120]

    def open_data(self, msg: bytes) -> DecryptedEnvelope:
        """Decrypt a DATA message. Tag is verified BEFORE the replay guard advances.

        Raises PacketCryptoError (tamper / wrong key) or ReplayError (stale seq).
        """
        if self._key is None:
            raise PacketCryptoError("DATA before handshake")
        if msg[:2] != T_DATA:
            raise PacketCryptoError("not a DATA message")
        env = decrypt_envelope(msg[2:], self._key)
        if env.device_id != self.device_id:
            raise PacketCryptoError("device_id in envelope does not match session")
        self._guard.check_and_update(env.device_id, env.seq_num)
        return env


class ClientSession:
    """Device side (VirtualProductModule now, ESP32 #2 firmware later)."""

    def __init__(self, device_id: int, psk: bytes) -> None:
        if len(psk) != 16:
            raise ValueError("PSK must be 16 bytes")
        self.device_id = device_id
        self._psk = psk
        self.device_nonce = os.urandom(NONCE_LEN)
        self.session_salt = os.urandom(6)  # fixed for the session → unique nonces with seq
        self._server_nonce: bytes | None = None
        self._key: bytes | None = None
        self.seq = 0

    @property
    def established(self) -> bool:
        return self._key is not None

    def handle_challenge(self, msg: bytes) -> bytes:
        if len(msg) != 2 + NONCE_LEN or msg[:2] != T_CHALLENGE:
            raise HandshakeError("malformed CHALLENGE")
        self._server_nonce = msg[2:]
        did = struct.pack(">H", self.device_id)
        mac_d = _mac(self._psk, b"HELLO", did, self._server_nonce, self.device_nonce)
        return T_HELLO + did + self.device_nonce + mac_d

    def handle_welcome(self, msg: bytes) -> None:
        if msg[:2] == T_REJECT:
            raise HandshakeError("server rejected: " + msg[2:].decode("utf-8", "replace"))
        if msg[:2] != T_WELCOME or self._server_nonce is None:
            raise HandshakeError("malformed WELCOME")
        did = struct.pack(">H", self.device_id)
        expected = _mac(self._psk, b"WELCOME", did, self._server_nonce, self.device_nonce)
        if not hmac.compare_digest(expected, msg[2:]):
            raise HandshakeError("server failed to prove PSK knowledge (rogue server?)")
        self._key = derive_session_key(self._psk, self._server_nonce, self.device_nonce)

    def seal(self, payload: dict[str, Any]) -> bytes:
        """Encrypt one batch into a DATA message (seq increments from 1)."""
        if self._key is None:
            raise PacketCryptoError("seal before handshake")
        self.seq += 1
        env = encrypt_envelope(self.device_id, self.seq, payload, self._key, boot_salt=self.session_salt)
        return T_DATA + env
