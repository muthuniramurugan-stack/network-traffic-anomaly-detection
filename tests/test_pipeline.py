import json

import pandas as pd

from netanomaly.cli import main
from netanomaly.features import extract
from netanomaly.generate import generate


def test_features(tmp_path):
    p = tmp_path / "a.pcap"
    generate(p, duration=60)
    df = extract(p)
    assert len(df) > 0 and df.pkts.min() >= 1


def test_detects_attacks(tmp_path):
    base, test = tmp_path / "base.pcap", tmp_path / "test.pcap"
    generate(base, duration=300, seed=1, attacks=False)
    generate(test, duration=300, seed=2, attacks=True)
    main(["detect", str(test), "--baseline", str(base), "--outdir", str(tmp_path / "out")])
    flagged = set(pd.read_csv(tmp_path / "out" / "alerts.csv").src)
    truth = set(json.loads(test.with_suffix(".labels.json").read_text()))
    assert truth <= flagged
