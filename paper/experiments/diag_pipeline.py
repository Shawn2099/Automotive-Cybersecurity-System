"""Fig: per-batch analytics pipeline (full width)."""
from paper.experiments.diag_common import Diagram
from paper.experiments import style


def main():
    W, H = style.FULL_W, 2.75
    d = Diagram("diag_pipeline", W, H)
    top, bot = 2.2, 0.35  # column body extents
    # column headers
    heads = [(0.05, 0.7, "Input"), (0.92, 1.3, "Features"), (2.4, 1.4, "Detectors"),
             (3.98, 0.9, "Scoring"), (5.06, 1.0, "Alerts"), (6.24, 0.87, "Outputs")]
    for x, w, t in heads:
        d.text(x + w / 2, 2.55, t, bold=True)
    d.box(0.05, 0.75, 0.7, 1.05, "decrypted\n100 ms\nbatch +\ndecoded\nsignals", fill="g1")
    # features
    d.box(0.92, 1.28, 1.3, 0.92, "Traffic features\nper-ID rate ÷ expected\nunknown-ID fps, count\ntotal ratio, bus load,\nsteering rate", fill="g1", fs=6.6)
    d.box(0.92, 0.35, 1.3, 0.8, "Health vector\nspeed, rpm, throttle,\nbrake, coolant, battery,\nrpm/speed, speed mismatch", fill="g1", fs=6.6)
    d.arrow([(0.75, 1.55), (0.92, 1.7)])
    d.arrow([(0.75, 1.0), (0.92, 0.8)])
    # detectors
    d.box(2.4, 1.77, 1.4, 0.43, "Rules: DoS, fuzzy, spoofing,\nsensor, thresholds", fs=6.8)
    d.box(2.4, 1.28, 1.4, 0.43, "RandomForest\n5-class attack", fs=6.8)
    d.box(2.4, 0.74, 1.4, 0.43, "IsolationForest\nhealth anomaly", fs=6.8)
    d.box(2.4, 0.35, 1.4, 0.34, "Slope forecaster (ETA)", fs=6.8)
    d.arrow([(2.22, 1.98), (2.4, 1.98)])
    d.arrow([(2.22, 1.5), (2.4, 1.5)])
    d.arrow([(2.22, 0.95), (2.4, 0.95)])
    d.arrow([(2.22, 0.52), (2.4, 0.52)])
    # scoring
    d.box(3.98, 0.35, 0.9, 1.85, "Rolling\n5 s window\n\nrecent 1 s\nweighted\n\nper-class\npenalties", fill="g2", fs=6.8)
    for y in (1.98, 1.5, 0.95, 0.52):
        d.arrow([(3.8, y), (3.98, y)])
    # alerts
    d.box(5.06, 0.35, 1.0, 1.85, "Debounce\n\n10 s cool-down\nper category\n\n2 s quiet\nre-arms\n\nescalate on\nhigher severity", fill="g2", fs=6.6)
    d.arrow([(4.88, 1.27), (5.06, 1.27)])
    # outputs
    d.box(6.24, 1.45, 0.87, 0.75, "Health\n0–100", fill="w", fs=6.8)
    d.box(6.24, 0.35, 0.87, 0.75, "Cyber risk\n0–100\n+ class", fill="w", fs=6.8)
    d.arrow([(6.06, 1.82), (6.24, 1.82)])
    d.arrow([(6.06, 0.72), (6.24, 0.72)])
    d.text(6.675, 1.28, "alerts →\ndashboard", fs=6.5)
    d.text(W / 2, 0.14, "Executed once per received batch; per-vehicle state (one analyzer per device_id)", fs=6.5, italic=True)
    d.save()


if __name__ == "__main__":
    main()
