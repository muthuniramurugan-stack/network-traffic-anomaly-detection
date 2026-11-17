"""Hybrid detector: Isolation Forest + robust z-score explanations + heuristic labels."""
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .features import FEATURES

DENSE = ["pkts", "bytes", "uniq_dst_ip", "uniq_dst_port", "syn"]


class AnomalyDetector:
    def __init__(self, contamination=0.05, n_estimators=200, seed=42, z_thresh=6.0, envelope=3.0):
        self.model = IsolationForest(n_estimators=n_estimators, contamination=contamination, random_state=seed)
        self.scaler = StandardScaler()
        self.z_thresh, self.envelope = z_thresh, envelope
        self.max_ = None
        self.median_ = self.mad_ = None

    def fit(self, df):
        X = np.log1p(df[FEATURES].to_numpy(float))
        self.model.fit(self.scaler.fit_transform(X))
        self.median_ = np.median(X, axis=0)
        self.mad_ = np.median(np.abs(X - self.median_), axis=0) * 1.4826 + 0.2
        self.max_ = df[DENSE].max()
        return self

    def predict(self, df):
        df = df.copy()
        X = np.log1p(df[FEATURES].to_numpy(float))
        Xs = self.scaler.transform(X)
        df["score"] = -self.model.score_samples(Xs)      # higher = more anomalous
        z = (X - self.median_) / self.mad_
        df["max_z"] = z.max(axis=1)
        env = (df[DENSE] > self.envelope * self.max_).any(axis=1)  # far outside baseline envelope
        flag = self.model.predict(Xs) == -1
        df["anomaly"] = (flag & (df["max_z"] >= self.z_thresh)) | env
        df["reason"] = [self._reason(z[i], r) if r["anomaly"] else "" for i, r in enumerate(df.to_dict("records"))]
        df["likely_type"] = [classify(r) if r["anomaly"] else "" for r in df.to_dict("records")]
        return df

    def _reason(self, zrow, row, k=3):
        idx = np.argsort(zrow)[::-1][:k]
        parts = [f"{FEATURES[i]} (z={zrow[i]:.1f})" for i in idx if zrow[i] > 3]
        for f in DENSE:
            if row[f] > self.envelope * self.max_[f]:
                parts.append(f"{f}={row[f]:.0f} is {row[f] / self.max_[f]:.1f}x baseline max")
        return "; ".join(parts)


def classify(r):
    """Transparent rule-of-thumb labels for triage (not ground truth)."""
    if r["dns_q"] >= 20 and r["dns_mean_qlen"] > 40:
        return "DNS tunneling"
    if r["syn_ratio"] > 0.8 and r["uniq_dst_port"] > 100:
        return "Port scan"
    if r["syn_ratio"] > 0.8 and r["syn"] > 500:
        return "SYN flood"
    if r["bytes"] > 500_000 and r["uniq_dst_ip"] <= 2:
        return "Data exfiltration"
    return "Unclassified anomaly"


def wireshark_filter(row, window=10.0):
    start, end = row["window_start"], row["window_start"] + window
    return f'ip.src == {row["src"]} && frame.time_epoch >= {start:.0f} && frame.time_epoch < {end:.0f}'
