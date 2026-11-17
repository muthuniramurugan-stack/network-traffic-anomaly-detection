# Network Traffic Anomaly Detection (Python · Scapy · Wireshark)

Detects suspicious hosts in network traffic from PCAP files (Wireshark/tcpdump/Scapy captures).
Traffic is aggregated into **(10 s window, source IP)** feature vectors and scored by a hybrid detector:

1. **Isolation Forest** (scikit-learn) – unsupervised outlier score on log-scaled features
2. **Robust z-scores** (median/MAD) – gate + human-readable reasons
3. **Baseline envelope rule** – flags values >3x the max seen in clean traffic
4. **Heuristic labeller** – port scan / SYN flood / DNS tunneling / data exfiltration

## Features per window
packets, bytes, mean packet size, unique dst IPs, unique dst ports, SYN count & ratio,
UDP ratio, ICMP count, DNS query count, mean DNS qname length.

## Quick start
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH=src            # Windows: set PYTHONPATH=src

# 1) synthetic data (clean baseline + test traffic with 4 injected attacks)
python -m netanomaly generate -o data/baseline.pcap --no-attacks --seed 1
python -m netanomaly generate -o data/sample.pcap --seed 2

# 2) detect
python -m netanomaly detect data/sample.pcap --baseline data/baseline.pcap

# 3) real traffic (needs root; or export from Wireshark)
sudo -E python -m netanomaly capture -i eth0 -t 120 -o data/capture.pcap
python -m netanomaly detect data/capture.pcap --baseline data/baseline.pcap
```
Outputs in `output/`: `alerts.csv/json` (with Wireshark filters), `all_windows.csv`, `anomalies.png`.

## Sample result (included in `output/`)
All 4 injected attackers found, 0 false positives (precision 1.00, recall 1.00).
Synthetic data is easy; expect tuning on real networks (`--contamination`, `--window`, a good baseline).

## Layout
```
src/netanomaly/  generate.py capture.py features.py detect.py report.py cli.py
tests/           pytest end-to-end test
docs/            WIRESHARK_GUIDE.md
data/            sample + baseline PCAPs and ground-truth labels
output/          sample reports
```

## Tests
`pytest -q`

## Limitations / ideas
Per-source windows only (no flow/payload inspection); encrypted-traffic content is invisible;
add per-flow features, CICIDS2017 evaluation, autoencoder, or streaming mode.
