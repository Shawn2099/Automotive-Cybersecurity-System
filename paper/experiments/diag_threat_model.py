"""Fig: threat model, adversaries -> assets -> defences (single column)."""
from paper.experiments.diag_common import Diagram
from paper.experiments import style


def main():
    W, H = style.COL_W, 4.45
    d = Diagram("diag_threat_model", W, H)
    cx = [0.04, 1.06, 1.98]  # column x
    cw = [1.0, 0.9, 1.48]
    top = 4.4
    for x, w, t in zip(cx, cw, ["Attack", "Asset at risk", "Defence (action)"]):
        d.text(x + w / 2, top - 0.08, t, bold=True, fs=6.8)

    def band(y, text):
        d.box(0.04, y, 3.42, 0.24, text, fill="atk", lw=1.1, fs=6.8, bold=True)

    def row(y, a, b, c, h=0.4):
        d.box(cx[0], y, cw[0], h, a, fs=6.5, fill="g1")
        d.box(cx[1], y, cw[1], h, b, fs=6.5)
        d.box(cx[2], y, cw[2], h, c, fs=6.5, fill="g2")
        d.arrow([(cx[1] - 0.0, y + h / 2), (cx[1] + 0.0, y + h / 2)], lw=0.01) if False else None

    y = 3.95
    band(y, "A1  on-bus injector (CAN access)")
    rows1 = [("DoS\n(ID 0x000 flood)", "bus availability,\ntelemetry freshness", "detect: unknown-ID rate,\ntotal-rate ratio, RF"),
             ("Fuzzy\n(random IDs)", "bus availability,\nECU behaviour", "detect: many distinct\nunknown IDs, RF"),
             ("RPM / gear /\nsteering spoof", "signal integrity\n(what the cloud sees)", "detect: per-ID rate ratio,\nsteering rate, speed mismatch")]
    y -= 0.05
    for r in rows1:
        y -= 0.43
        row(y, *r)
    y -= 0.12
    y -= 0.24
    band(y, "A2  network attacker (on the tunnel)")
    rows2 = [("Replay", "freshness", "reject: seq not newer\n(guard after tag check)"),
             ("Tamper", "batch integrity", "reject: GCM tag fails"),
             ("Wrong key /\nimpersonation", "device identity", "reject: HELLO MAC fails,\nunknown id gets ‘NO’"),
             ("Rogue server", "device trust,\nsession key", "abort: WELCOME MAC\nmismatch on module")]
    y -= 0.05
    for r in rows2:
        y -= 0.43
        row(y, *r)
    d.text(W / 2, 0.2, "Module is read-only: A1 is detected and alerted, not blocked.\nAll rejected packets and alerts raise cyber risk.",
           fs=6.5, italic=True)
    d.save()


if __name__ == "__main__":
    main()
