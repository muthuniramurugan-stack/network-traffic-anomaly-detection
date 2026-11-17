import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from .detect import wireshark_filter


def save_reports(df, outdir, window=10.0):
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    df.to_csv(out / "all_windows.csv", index=False)
    alerts = df[df.anomaly].sort_values("score", ascending=False).copy()
    if len(alerts):
        alerts["wireshark_filter"] = alerts.apply(lambda r: wireshark_filter(r, window), axis=1)
    alerts.to_csv(out / "alerts.csv", index=False)
    (out / "alerts.json").write_text(json.dumps(alerts.to_dict("records"), indent=2, default=str))

    fig, ax = plt.subplots(2, 1, figsize=(11, 7), sharex=True)
    n, a = df[~df.anomaly], df[df.anomaly]
    ax[0].scatter(n.window_start, n.pkts, s=14, c="tab:blue", label="normal")
    ax[0].scatter(a.window_start, a.pkts, s=60, c="tab:red", marker="x", label="anomaly")
    ax[0].set_ylabel("packets / window")
    ax[0].set_yscale("log")
    ax[0].legend()
    ax[0].set_title("Network traffic anomaly detection")
    ax[1].scatter(n.window_start, n.score, s=14, c="tab:blue")
    ax[1].scatter(a.window_start, a.score, s=60, c="tab:red", marker="x")
    for _, r in a.iterrows():
        ax[1].annotate(r.src, (r.window_start, r.score), fontsize=7, xytext=(3, 3), textcoords="offset points")
    ax[1].set_ylabel("anomaly score")
    ax[1].set_xlabel("epoch time (window start)")
    fig.tight_layout()
    fig.savefig(out / "anomalies.png", dpi=130)
    plt.close(fig)
    return alerts
