"""Fig: PSK challenge-response handshake + first DATA message (single column)."""
from paper.experiments.diag_common import Diagram
from paper.experiments import style


def main():
    W, H = style.COL_W, 4.75
    d = Diagram("diag_handshake", W, H)
    xd, xs = 0.42, 3.08  # lifeline x: device, server
    d.box(0.02, 4.38, 0.84, 0.34, "Product\nmodule", fill="hw", ls="--", fs=6.8)
    d.box(2.66, 4.38, 0.84, 0.34, "Edge\nserver", fill="g1", fs=6.8)
    d.line([(xd, 4.38), (xd, 0.05)], ls=":")
    d.line([(xs, 4.38), (xs, 0.05)], ls=":")
    d.text(W / 2, 4.24, "M(label, …) = HMAC-SHA256(PSK, label ‖ …)[:16 B]", fs=6.5, bg=True)

    def msg(y, frm, label, sub):
        a, b = (xs, xd) if frm == "S" else (xd, xs)
        d.arrow([(a, y), (b, y)], lw=0.9)
        d.text(W / 2, y + 0.13, label, bold=True, fs=7)
        d.text(W / 2, y - 0.12, sub, fs=6.5)

    def note(y, h, text, side, w=2.15):
        x = xd + 0.07 if side == "D" else xs - 0.07 - w
        d.box(x, y, w, h, text, ls="--" if side == "D" else "-", fill="g1", fs=6.5, ha="left")

    msg(4.0, "S", "1  CH", "‘CH’ ‖ server_nonce (16 B, random)")
    note(3.18, 0.5, "device_nonce ← random(16 B)\nmac_d = M(‘HELLO’, device_id,\n  server_nonce, device_nonce)", "D")
    msg(2.95, "D", "2  HE", "‘HE’ ‖ device_id (2) ‖ device_nonce (16) ‖ mac_d (16)")
    note(1.88, 0.76, "look up PSK[device_id]; verify mac_d\nunknown id / bad MAC → ‘NO’ + close,\n  auth_fail event logged\nsession_key = M(‘SESSION’,\n  server_nonce, device_nonce)", "S")
    msg(1.66, "S", "3  OK", "‘OK’ ‖ mac_s (16),  mac_s = M(‘WELCOME’, id, …)")
    note(0.98, 0.5, "verify mac_s (detects rogue server)\nsession_key = M(‘SESSION’,\n  server_nonce, device_nonce)", "D")
    msg(0.75, "D", "4  DA", "‘DA’ ‖ envelope, seq = 1, 2, 3, …")
    note(0.04, 0.46, "1) verify GCM tag, 2) then replay guard:\nseq > last, else drop (link stays open)", "S", w=2.4)
    d.save()


if __name__ == "__main__":
    main()
