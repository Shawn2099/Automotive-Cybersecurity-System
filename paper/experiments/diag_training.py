"""Fig: data and training flow (single column)."""
from paper.experiments.diag_common import Diagram
from paper.experiments import style


def main():
    W, H = style.COL_W, 4.4
    d = Diagram("diag_training", W, H)
    bw, bh = 1.06, 0.56
    c = [0.04, 1.22, 2.4]  # column left x
    ctr = [x + bw / 2 for x in c]
    r1, r2, r3, r4, r5 = 3.75, 2.9, 2.0, 1.2, 0.05

    d.box(c[0], r1, bw, bh, "HCRL captures\n(normal, DoS, fuzzy,\nRPM, gear)", fill="g2", fs=6.5)
    d.box(c[1], r1, bw, bh, "Measured ID\nschedule + attack\nbehaviour", fs=6.5)
    d.box(c[2], r1, bw, bh, "CAN profile\n(DBC-style JSON)", fs=6.5)
    d.arrow([(c[0] + bw, r1 + bh / 2), (c[1], r1 + bh / 2)])
    d.arrow([(c[1] + bw, r1 + bh / 2), (c[2], r1 + bh / 2)])

    d.box(c[2], r2, bw, bh, "Simulator\n(vehicle model,\nfaults, attacks)", fill="hw", ls="--", fs=6.5)
    d.arrow([(ctr[2], r1), (ctr[2], r2 + bh)])
    d.box(c[0], r2, bw, bh, "HCRL windows\n(100 ms batches)", fs=6.5)
    d.arrow([(ctr[0], r1), (ctr[0], r2 + bh)])
    d.box(c[1], r2, bw, bh, "Simulator windows\n(normal, attack,\nfault)", fs=6.5)
    d.arrow([(c[2], r2 + bh / 2), (c[1] + bw, r2 + bh / 2)])

    # features
    d.box(c[0], r3, c[1] + bw - c[0], 0.5, "Feature extraction\n(same code at train and serve time)", fill="g1", fs=6.5)
    d.arrow([(ctr[0], r2), (ctr[0], r3 + 0.5)])
    d.arrow([(ctr[1], r2), (ctr[1], r3 + 0.5)])
    # RF
    d.box(c[0], r4, c[1] + bw - c[0], 0.5, "RandomForest\n5 classes: normal, DoS, fuzzy, spoofing, tunnel", fill="g2", fs=6.5)
    d.arrow([((c[0] + c[1] + bw) / 2, r3), ((c[0] + c[1] + bw) / 2, r4 + 0.5)])
    # IF
    d.box(c[2], r3 - 0.0, bw, 0.5, "Health features\n(simulator normal)", fs=6.5)
    d.arrow([(ctr[2], r2), (ctr[2], r3 + 0.5)])
    d.box(c[2], r4, bw, 0.5, "IsolationForest", fill="g2", fs=6.5)
    d.arrow([(ctr[2], r3), (ctr[2], r4 + 0.5)])
    # evaluation paths
    d.box(c[0], r5, bw, 0.55, "Eval 1: HCRL\nheld-out windows,\nper-intrusion latency", fs=6.5)
    d.box(c[1], r5, bw, 0.55, "Eval 2: simulator\nend-to-end fault\nand attack runs", fs=6.5)
    d.box(c[2], r5, bw, 0.55, "Eval 3: simulator\nonly (no real\nhealth labels)", fs=6.5, ls="--")
    d.arrow([(ctr[0], r4), (ctr[0], r5 + 0.55)])
    d.arrow([(ctr[1], r4), (ctr[1], r5 + 0.55)])
    d.arrow([(ctr[2], r4), (ctr[2], r5 + 0.55)])
    d.save()


if __name__ == "__main__":
    main()
