"""Fig: end-to-end system architecture (full width)."""
from paper.experiments.diag_common import Diagram
from paper.experiments import style


def _ecu_label() -> str:
    """Computed from the live CAN profile so the label follows profile changes."""
    from common.can_profiles import get_profile
    p = get_profile("hyundai_sonata_hcrl")
    return f"HCRL Sonata ECUs\n{len(p.valid_ids)} IDs, ~{round(p.expected_total_hz, -2):.0f} frames/s"


def main():
    d = Diagram("diag_architecture", style.FULL_W, 3.65)
    # --- zones -------------------------------------------------------------------
    d.box(0.05, 0.62, 1.65, 2.95, ls="--", fill="hw")
    d.text(0.875, 3.47, "Bench car (ESP32 #1)", bold=True)
    d.text(0.875, 3.33, "simulated here; HW planned", italic=True, fs=6.8)
    d.box(2.35, 0.62, 1.6, 2.95, ls="--", fill="hw")
    d.text(3.15, 3.47, "Product module (ESP32 #2)", bold=True)
    d.text(3.15, 3.33, "simulated here; HW planned", italic=True, fs=6.8)
    d.box(4.55, 0.62, 2.56, 2.95, fill="g1")
    d.text(5.83, 3.47, "Edge server (laptop)", bold=True)
    d.text(5.83, 3.33, "implemented (software)", italic=True, fs=6.8)

    # --- bench car ----------------------------------------------------------------
    d.box(0.15, 2.72, 1.45, 0.5, "Fault / attack\ncontroller (UI)")
    d.box(0.15, 1.76, 1.45, 0.5, _ecu_label())
    d.box(0.15, 0.8, 1.45, 0.5, "CAN node\n500 kbps")
    d.arrow([(0.875, 2.72), (0.875, 2.26)])
    d.arrow([(0.875, 1.76), (0.875, 1.30)])
    # --- CAN link + attacker A1 ----------------------------------------------------
    d.arrow([(1.6, 1.05), (2.45, 1.05)])
    d.text(2.03, 1.3, "CAN bus", fs=6.8, bg=True)
    d.box(1.3, 0.04, 1.45, 0.46, "A1: on-bus injector\nDoS, fuzzy, spoofing", fill="atk", lw=1.3)
    d.arrow([(2.03, 0.5), (2.03, 1.0)], ls="-", lw=1.3)
    # --- product module -------------------------------------------------------------
    d.box(2.45, 2.72, 1.4, 0.5, "AES-128-GCM tunnel\nhandshake, seq, tag")
    d.box(2.45, 1.76, 1.4, 0.5, "100 ms bounded batch\nlatest frame per ID")
    d.box(2.45, 0.8, 1.4, 0.5, "CAN RX\nread-only (no TX)")
    d.arrow([(3.15, 1.3), (3.15, 1.76)])
    d.arrow([(3.15, 2.26), (3.15, 2.72)])
    # --- Internet link + attacker A2 -------------------------------------------------
    d.arrow([(3.85, 2.98), (4.65, 2.98)])
    d.text(4.25, 3.28, "Wi-Fi /\nInternet\n(encrypted)", fs=6.8, bg=True)
    d.box(3.3, 0.04, 1.6, 0.46, "A2: network attacker\nreplay, tamper, wrong key", fill="atk", lw=1.3)
    d.arrow([(4.25, 0.5), (4.25, 2.93)], lw=1.3)
    # --- server ----------------------------------------------------------------------
    d.box(4.65, 2.8, 2.36, 0.36, "Handshake, tag check, replay guard")
    d.box(4.65, 2.32, 2.36, 0.36, "DBC-profile decoder (per vehicle)")
    d.box(4.65, 1.82, 2.36, 0.42, "Rules + IsolationForest + RandomForest\n+ slope forecaster")
    d.box(4.65, 1.36, 2.36, 0.36, "Health / cyber-risk scores, alerts")
    d.box(4.65, 0.78, 0.82, 0.44, "SQLite\n(1 Hz + alerts)", fs=6.8)
    d.box(5.57, 0.78, 1.44, 0.44, "WebSocket dashboard\n+ voice alerts", fs=6.8)
    for y0, y1 in [(2.8, 2.68), (2.32, 2.24), (1.82, 1.72)]:
        d.arrow([(5.83, y0), (5.83, y1)])
    d.arrow([(5.06, 1.36), (5.06, 1.22)])
    d.arrow([(6.29, 1.36), (6.29, 1.22)])
    # --- legend ----------------------------------------------------------------------
    d.box(5.15, 0.3, 0.28, 0.14, ls="--", fill="hw", lw=0.7)
    d.text(5.5, 0.37, "simulated stand-in for planned hardware", fs=6.5, ha="left")
    d.box(5.15, 0.08, 0.28, 0.14, fill="g1")
    d.text(5.5, 0.15, "implemented software", fs=6.5, ha="left")
    d.save()


if __name__ == "__main__":
    main()
