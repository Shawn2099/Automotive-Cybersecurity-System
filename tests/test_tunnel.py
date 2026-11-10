"""Tunnel handshake + AES-GCM data frame tests (tamper, replay, wrong key, cross-session replay)."""

import pytest

from common.crypto import PacketCryptoError, ReplayError
from common.tunnel import ClientSession, HandshakeError, ServerSession

PSK = bytes.fromhex("00112233445566778899aabbccddeeff")
BAD = bytes.fromhex("ffffffffffffffffffffffffffffffff")


def _lookup(did):
    return PSK if did == 1 else None


def _connect(psk=PSK, device_id=1):
    s = ServerSession(_lookup)
    c = ClientSession(device_id, psk)
    hello = c.handle_challenge(s.challenge())
    c.handle_welcome(s.handle_hello(hello))
    return s, c


def test_roundtrip_and_seq():
    s, c = _connect()
    for i in range(1, 4):
        env = s.open_data(c.seal({"i": i}))
        assert env.seq_num == i and env.payload == {"i": i}


def test_replay_rejected():
    s, c = _connect()
    m = c.seal({"x": 1})
    s.open_data(m)
    with pytest.raises(ReplayError):
        s.open_data(m)


def test_tamper_rejected_and_does_not_advance_seq():
    s, c = _connect()
    m = bytearray(c.seal({"x": 1}))
    m[-5] ^= 0x01
    with pytest.raises(PacketCryptoError):
        s.open_data(bytes(m))
    # header seq tamper is also caught by AAD
    m2 = bytearray(c.seal({"x": 2}))
    m2[5] ^= 0x01
    with pytest.raises(PacketCryptoError):
        s.open_data(bytes(m2))
    assert s.open_data(c.seal({"x": 3})).seq_num == 3


def test_wrong_key_handshake_rejected():
    s = ServerSession(_lookup)
    c = ClientSession(1, BAD)
    with pytest.raises(HandshakeError):
        s.handle_hello(c.handle_challenge(s.challenge()))


def test_unknown_device_rejected():
    s = ServerSession(_lookup)
    c = ClientSession(9, PSK)
    with pytest.raises(HandshakeError):
        s.handle_hello(c.handle_challenge(s.challenge()))
    assert s.device_id == 9


def test_cross_session_replay_fails():
    s1, c1 = _connect()
    old = c1.seal({"x": 1})
    s1.open_data(old)
    s2, _c2 = _connect()  # device "reboots": new session, seq restarts
    with pytest.raises(PacketCryptoError):
        s2.open_data(old)


def test_reconnect_restarts_seq():
    _connect()
    s, c = _connect()
    assert s.open_data(c.seal({})).seq_num == 1


def test_rogue_server_detected():
    rogue = ServerSession(lambda d: BAD)
    c = ClientSession(1, PSK)
    hello = c.handle_challenge(rogue.challenge())
    with pytest.raises(HandshakeError):
        rogue.handle_hello(hello)  # rogue can't verify
    # even if rogue fakes a WELCOME, client rejects it
    with pytest.raises(HandshakeError):
        c.handle_welcome(b"OK" + bytes(16))
