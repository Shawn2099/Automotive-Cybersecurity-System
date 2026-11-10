"""Exp 2: tunnel security property tests (attack -> expected -> observed over N trials), all via common.tunnel."""

from __future__ import annotations

import os
import random
import struct
from collections import Counter

from common.crypto import PacketCryptoError, ReplayError
from common.tunnel import ClientSession, HandshakeError, ServerSession
from paper.experiments.sys_common import PSK1, gen_scenario, save_json, write_table

N = 1000
rng = random.Random(7)
PSKS = {1: PSK1, 2: bytes.fromhex("a1" * 16)}
lookup = lambda d: PSKS.get(d)  # noqa: E731
_, BATCHES = gen_scenario("normal", seconds=10, seed=5)


def pair(dev=1, psk=None):
    s, c = ServerSession(lookup), ClientSession(dev, psk or PSKS[dev])
    c.handle_welcome(s.handle_hello(c.handle_challenge(s.challenge())))
    return s, c


def batch():
    return rng.choice(BATCHES)


def outcome(fn) -> str:
    """'accepted' or the exception class name."""
    try:
        fn()
        return "accepted"
    except (HandshakeError, ReplayError, PacketCryptoError) as e:
        return type(e).__name__
    except Exception as e:  # noqa: BLE001 - anything else is a bug, recorded as such
        return "UNEXPECTED:" + type(e).__name__


def flip(msg: bytes, bit: int) -> bytes:
    b = bytearray(msg)
    b[bit // 8] ^= 1 << (bit % 8)
    return bytes(b)


# each test returns (Counter of outcomes, number of trials)
def t_benign():
    c = Counter()
    for _ in range(N):
        s, cl = pair()
        for _ in range(3):
            c[outcome(lambda: s.open_data(cl.seal(batch())))] += 1
    return c, 3 * N


def t_replay_same():
    c = Counter()
    for _ in range(N):
        s, cl = pair()
        m = cl.seal(batch())
        s.open_data(m)
        c[outcome(lambda: s.open_data(m))] += 1
    return c, N


def t_replay_old():  # replay an older seq after later ones were accepted
    c = Counter()
    for _ in range(N):
        s, cl = pair()
        ms = [cl.seal(batch()) for _ in range(6)]
        for m in ms:
            s.open_data(m)
        c[outcome(lambda: s.open_data(rng.choice(ms[:-1])))] += 1
    return c, N


def t_cross_session():
    c = Counter()
    for _ in range(N):
        sa, ca = pair()
        sb, _cb = pair()
        m = ca.seal(batch())
        sa.open_data(m)
        c[outcome(lambda: sb.open_data(m))] += 1  # same device and PSK, different session
    return c, N


def t_cross_session_fresh():  # captured packet never delivered in its own session
    c = Counter()
    for _ in range(N):
        _sa, ca = pair()
        sb, _cb = pair()
        m = ca.seal(batch())
        c[outcome(lambda: sb.open_data(m))] += 1
    return c, N


def t_bitflip_body():  # flip in ciphertext or tag (after 2-byte type + 18-byte header)
    c = Counter()
    for _ in range(N):
        s, cl = pair()
        m = cl.seal(batch())
        bit = rng.randrange(20 * 8, len(m) * 8)
        c[outcome(lambda: s.open_data(flip(m, bit)))] += 1
    return c, N


def t_bitflip_any():  # flip anywhere in the message including type and header
    c = Counter()
    for _ in range(N):
        s, cl = pair()
        m = cl.seal(batch())
        bit = rng.randrange(0, len(m) * 8)
        c[outcome(lambda: s.open_data(flip(m, bit)))] += 1
    return c, N


def t_hdr_seq_future():  # attacker bumps seq in the cleartext header
    c = Counter()
    for _ in range(N):
        s, cl = pair()
        m = bytearray(cl.seal(batch()))
        did, seq = struct.unpack(">HI", m[2:8])
        m[2:8] = struct.pack(">HI", did, seq + rng.randrange(1, 1000))
        c[outcome(lambda: s.open_data(bytes(m)))] += 1
    return c, N


def t_hdr_seq_rewind():  # rewrite seq of a fresh packet to an already-seen number
    c = Counter()
    for _ in range(N):
        s, cl = pair()
        s.open_data(cl.seal(batch()))
        m = bytearray(cl.seal(batch()))
        did, _seq = struct.unpack(">HI", m[2:8])
        m[2:8] = struct.pack(">HI", did, 1)
        c[outcome(lambda: s.open_data(bytes(m)))] += 1
    return c, N


def t_hdr_device():  # claim another (registered) device id in the cleartext header
    c = Counter()
    for _ in range(N):
        s, cl = pair()
        m = bytearray(cl.seal(batch()))
        m[2:4] = struct.pack(">H", 2)
        c[outcome(lambda: s.open_data(bytes(m)))] += 1
    return c, N


def t_other_device_same_session():  # device 2 (valid PSK, own session) sends into device-1's server session
    c = Counter()
    for _ in range(N):
        s1, _c1 = pair(1)
        _s2, c2 = pair(2)
        c[outcome(lambda: s1.open_data(c2.seal(batch())))] += 1
    return c, N


def t_wrong_psk_hs():
    c = Counter()
    for _ in range(N):
        s = ServerSession(lookup)
        cl = ClientSession(1, os.urandom(16))
        c[outcome(lambda: s.handle_hello(cl.handle_challenge(s.challenge())))] += 1
    return c, N


def t_wrong_psk_data():  # attacker forges DATA with a random key into a live session
    c = Counter()
    for _ in range(N):
        s, _cl = pair()
        fake = ClientSession(1, os.urandom(16))
        fake._key = os.urandom(16)
        c[outcome(lambda: s.open_data(fake.seal(batch())))] += 1
    return c, N


def t_unknown_device():
    c = Counter()
    for _ in range(N):
        s = ServerSession(lookup)
        cl = ClientSession(rng.randrange(3, 65535), os.urandom(16))
        c[outcome(lambda: s.handle_hello(cl.handle_challenge(s.challenge())))] += 1
    return c, N


def t_hello_replay():  # captured HELLO replayed to a new server session (new server nonce)
    c = Counter()
    for _ in range(N):
        s0 = ServerSession(lookup)
        cl = ClientSession(1, PSK1)
        hello = cl.handle_challenge(s0.challenge())
        s0.handle_hello(hello)
        s1 = ServerSession(lookup)
        c[outcome(lambda: s1.handle_hello(hello))] += 1
    return c, N


def t_rogue_server():  # attacker has no PSK and sends WELCOME with a guessed MAC
    c = Counter()
    for _ in range(N):
        s = ServerSession(lookup)
        cl = ClientSession(1, PSK1)
        cl.handle_challenge(s.challenge())
        c[outcome(lambda: cl.handle_welcome(b"OK" + os.urandom(16)))] += 1
    return c, N


def t_rogue_server_wrongpsk():  # rogue server runs the protocol honestly but with another PSK
    c = Counter()
    for _ in range(N):
        rogue_psk = os.urandom(16)
        rogue = ServerSession(lambda d, p=rogue_psk: p)
        cl = ClientSession(1, PSK1)
        hello = cl.handle_challenge(rogue.challenge())
        try:
            welcome = rogue.handle_hello(hello)  # HELLO MAC fails under the rogue key; attacker forges anyway
        except HandshakeError:
            welcome = b"OK" + os.urandom(16)
        c[outcome(lambda: cl.handle_welcome(welcome))] += 1
    return c, N


def t_rogue_welcome_replay():  # WELCOME captured from an earlier genuine session, replayed to a new client
    c = Counter()
    for _ in range(N):
        s0 = ServerSession(lookup)
        c0 = ClientSession(1, PSK1)
        w0 = s0.handle_hello(c0.handle_challenge(s0.challenge()))
        s1 = ServerSession(lookup)
        c1 = ClientSession(1, PSK1)
        c1.handle_challenge(s1.challenge())
        c[outcome(lambda: c1.handle_welcome(w0))] += 1
    return c, N


def t_truncated():
    c = Counter()
    for _ in range(N):
        s, cl = pair()
        m = cl.seal(batch())
        c[outcome(lambda: s.open_data(m[: rng.randrange(0, len(m) - 1)]))] += 1
    return c, N


TESTS = [
    # name, fn, expected, expect_accept
    ("Benign traffic (control)", t_benign, "accept", True),
    ("Replay: same packet, same session", t_replay_same, "reject (ReplayError)", False),
    ("Replay: older packet after newer ones", t_replay_old, "reject (ReplayError)", False),
    ("Replay: packet into another session", t_cross_session, "reject (tag mismatch)", False),
    ("Replay: undelivered packet into another session", t_cross_session_fresh, "reject (tag mismatch)", False),
    ("Ciphertext/tag bit-flip", t_bitflip_body, "reject (tag mismatch)", False),
    ("Bit-flip anywhere in message", t_bitflip_any, "reject", False),
    ("Header tamper: seq increased", t_hdr_seq_future, "reject (tag mismatch)", False),
    ("Header tamper: seq rewound", t_hdr_seq_rewind, "reject", False),
    ("Header tamper: device\\_id changed", t_hdr_device, "reject (tag mismatch)", False),
    ("Valid device 2 into device 1 session", t_other_device_same_session, "reject", False),
    ("Wrong PSK: handshake", t_wrong_psk_hs, "reject (bad HELLO MAC)", False),
    ("Wrong key: forged DATA in live session", t_wrong_psk_data, "reject (tag mismatch)", False),
    ("Unknown device\\_id: handshake", t_unknown_device, "reject (unknown device)", False),
    ("Captured HELLO replayed (new nonce)", t_hello_replay, "reject (bad HELLO MAC)", False),
    ("Rogue server: forged WELCOME", t_rogue_server, "client rejects", False),
    ("Rogue server: wrong PSK", t_rogue_server_wrongpsk, "client rejects", False),
    ("Rogue server: replayed WELCOME", t_rogue_welcome_replay, "client rejects", False),
    ("Truncated DATA message", t_truncated, "reject", False),
]


def main():
    res, rows = [], []
    for name, fn, expected, accept in TESTS:
        oc, n = fn()
        acc = oc.get("accepted", 0)
        rej = n - acc
        unexpected = sum(v for k, v in oc.items() if k.startswith("UNEXPECTED"))
        rate = 100.0 * (acc if accept else rej) / n
        res.append({"test": name.replace("\\_", "_"), "expected": expected, "trials": n, "accepted": acc,
                    "rejected": rej, "success_rate_pct": rate, "outcomes": dict(oc),
                    "unexpected_exceptions": unexpected})
        obs = f"{acc}/{n} accepted" if accept else f"{rej}/{n} rejected"
        rows.append([name, expected, obs, f"{rate:.1f}"])
        print(f"{name:55s} {obs:20s} {dict(oc)}")
    save_json("sys_security", {"trials_per_test": N, "tests": res})
    write_table("sys_security", ["Attack", "Expected", "Observed", "Rate (\\%)"], rows,
                f"Tunnel security property tests ({N} independent trials each, in-process via "
                "\\texttt{common.tunnel}). Rate is the share of trials with the expected outcome "
                "(accept for the control, reject otherwise).",
                "tab:sys_security", colspec="p{3.3cm}p{2.4cm}p{1.7cm}r", escape=False, resize=True)


if __name__ == "__main__":
    main()
