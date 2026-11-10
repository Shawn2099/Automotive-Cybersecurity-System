"""Fig: DATA message byte layout + plaintext batch schema (single column)."""
from paper.experiments.diag_common import Diagram
from paper.experiments import style


def main():
    W, H = style.COL_W, 3.7
    d = Diagram("diag_envelope", W, H)
    x0, y, h = 0.1, 2.75, 0.5
    segs = [("type ‘DA’", "2 B", 0.5, "g2"), ("device_id", "2 B", 0.52, "g1"), ("seq", "4 B", 0.4, "g1"),
            ("nonce", "12 B", 0.74, "g1"), ("ciphertext", "N B", 0.74, "g3"), ("tag", "16 B", 0.4, "g2")]
    xs = [x0]
    for name, ln, w, f in segs:
        d.box(xs[-1], y, w, h, f"{name}\n{ln}", fill=f, fs=6.8)
        xs.append(xs[-1] + w)
    # brackets above
    def bracket(xa, xb, yb, label, up=True):
        d.line([(xa, yb - 0.04), (xa, yb), (xb, yb), (xb, yb - 0.04)])
        d.text((xa + xb) / 2, yb + 0.1, label, fs=6.5)
    bracket(xs[1], xs[3], y + h + 0.06, "AAD = device_id ‖ seq")
    bracket(xs[1], xs[4], y + h + 0.3, "envelope header (18 B, clear)")
    # authenticated / encrypted brackets below
    yb = y - 0.07
    d.line([(xs[4], yb + 0.04), (xs[4], yb), (xs[6], yb), (xs[6], yb + 0.04)])
    d.text((xs[4] + xs[6]) / 2, yb - 0.1, "AES-128-GCM output", fs=6.5)
    # nonce breakdown
    nx, ny = xs[3], 2.0
    d.line([(xs[3], y), (0.62, ny + 0.28)], ls=":")
    d.line([(xs[4], y), (2.32, ny + 0.28)], ls=":")
    sub = [("device_id", "2", 0.52), ("seq", "4", 0.4), ("session salt", "6", 0.78)]
    sx = 0.62
    d.text(x0, ny + 0.14, "nonce =", fs=6.8, ha="left")
    xx = sx
    for name, ln, w in sub:
        d.box(xx, ny, w, 0.28, f"{name} ({ln})", fill="g1", fs=6.5)
        xx += w
    d.text(x0, ny - 0.17, "unique per message; salt drawn once per session, seq from 1", fs=6.5, ha="left")
    # plaintext
    d.arrow([(xs[5], 1.58), (xs[5], y - 0.27)], ls="--")
    d.text(xs[5] + 0.05, 2.15, "encrypt", fs=6.5, ha="left")
    d.box(x0, 0.04, 3.3, 1.52, "", fill="w")
    d.text(x0 + 0.08, 1.46, "Plaintext (JSON, one 100 ms batch)", bold=True, fs=6.8, ha="left")
    rows = [("ts_ms", "device monotonic clock"), ("window_ms", "batch window (100)"),
            ("frames", "[{id, dlc, data}] latest frame per CAN ID"),
            ("counts", "{id: frames seen in window}"), ("bus_load_pct", "bus utilisation, %"),
            ("rx_err", "CAN RX error count")]
    for i, (k, v) in enumerate(rows):
        yy = 1.27 - i * 0.205
        d.text(x0 + 0.1, yy, k, fs=6.5, ha="left", bold=True)
        d.text(x0 + 1.0, yy, v, fs=6.5, ha="left")
    d.save()


if __name__ == "__main__":
    main()
