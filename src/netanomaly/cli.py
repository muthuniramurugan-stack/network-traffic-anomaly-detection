import argparse
import json
import sys
from pathlib import Path

from .detect import AnomalyDetector
from .features import extract
from .report import save_reports


def main(argv=None):
    ap = argparse.ArgumentParser(prog="netanomaly", description="Network traffic anomaly detection")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="create synthetic PCAP (+ ground-truth labels)")
    g.add_argument("-o", "--out", default="data/sample.pcap")
    g.add_argument("--duration", type=int, default=300)
    g.add_argument("--seed", type=int, default=42)
    g.add_argument("--no-attacks", action="store_true")

    c = sub.add_parser("capture", help="live capture with Scapy (needs root)")
    c.add_argument("-i", "--iface")
    c.add_argument("-t", "--timeout", type=int, default=60)
    c.add_argument("-f", "--filter")
    c.add_argument("-o", "--out", default="data/capture.pcap")

    d = sub.add_parser("detect", help="analyze a PCAP (e.g. exported from Wireshark)")
    d.add_argument("pcap")
    d.add_argument("--baseline", help="clean PCAP to train on (recommended)")
    d.add_argument("-w", "--window", type=float, default=10.0)
    d.add_argument("--contamination", type=float, default=0.02)
    d.add_argument("--outdir", default="output")

    a = ap.parse_args(argv)

    if a.cmd == "generate":
        from .generate import generate
        n, labels = generate(a.out, a.duration, seed=a.seed, attacks=not a.no_attacks)
        print(f"Wrote {n} packets -> {a.out}  (labels: {labels})")
    elif a.cmd == "capture":
        from .capture import capture
        print(f"Captured {capture(a.iface, 0, a.timeout, a.filter, a.out)} packets -> {a.out}")
    else:
        test = extract(a.pcap, a.window)
        if test.empty:
            sys.exit("No IP packets found in PCAP.")
        det = AnomalyDetector(contamination=a.contamination)
        det.fit(extract(a.baseline, a.window) if a.baseline else test)
        res = det.predict(test)
        alerts = save_reports(res, a.outdir, a.window)
        print(f"{len(res)} windows analysed, {len(alerts)} alerts\n")
        cols = ["src", "window_start", "likely_type", "score", "reason"]
        print(alerts[cols].to_string(index=False) if len(alerts) else "No anomalies.")
        labp = Path(a.pcap).with_suffix(".labels.json")
        if labp.exists():
            truth = json.loads(labp.read_text())
            flagged, actual = set(alerts.src), set(truth)
            tp = len(flagged & actual)
            print(f"\nGround truth: precision={tp/max(len(flagged),1):.2f} recall={tp/max(len(actual),1):.2f} "
                  f"(TP={tp}, FP={len(flagged-actual)}, FN={len(actual-flagged)})")
        print(f"\nReports saved in {a.outdir}/")


if __name__ == "__main__":
    main()
