"""PCAP -> per-(time window, source IP) feature table."""
from collections import defaultdict

import pandas as pd
from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, PcapReader

FEATURES = [
    "pkts", "bytes", "mean_len", "uniq_dst_ip", "uniq_dst_port",
    "syn", "syn_ratio", "udp_ratio", "icmp", "dns_q", "dns_mean_qlen",
]


def _new():
    return dict(pkts=0, bytes=0, dst_ip=set(), dst_port=set(), syn=0, udp=0,
                icmp=0, dns_q=0, dns_len=0)


def extract(pcap_path, window=10.0):
    agg = defaultdict(_new)
    with PcapReader(str(pcap_path)) as reader:
        for p in reader:
            if IP not in p:
                continue
            w = int(float(p.time) // window)
            a = agg[(w, p[IP].src)]
            a["pkts"] += 1
            a["bytes"] += len(p)
            a["dst_ip"].add(p[IP].dst)
            if TCP in p:
                a["dst_port"].add(p[TCP].dport)
                if p[TCP].flags & 0x02 and not p[TCP].flags & 0x10:  # SYN without ACK
                    a["syn"] += 1
            elif UDP in p:
                a["udp"] += 1
                a["dst_port"].add(p[UDP].dport)
                if DNS in p and p.haslayer(DNSQR) and p[DNS].qr == 0:
                    a["dns_q"] += 1
                    a["dns_len"] += len(p[DNSQR].qname)
            elif ICMP in p:
                a["icmp"] += 1

    rows = []
    for (w, src), a in agg.items():
        n = a["pkts"]
        rows.append(dict(
            window=w, window_start=w * window, src=src,
            pkts=n, bytes=a["bytes"], mean_len=a["bytes"] / n,
            uniq_dst_ip=len(a["dst_ip"]), uniq_dst_port=len(a["dst_port"]),
            syn=a["syn"], syn_ratio=a["syn"] / n, udp_ratio=a["udp"] / n,
            icmp=a["icmp"], dns_q=a["dns_q"],
            dns_mean_qlen=(a["dns_len"] / a["dns_q"]) if a["dns_q"] >= 5 else 0.0,  # ignore sparse windows
        ))
    df = pd.DataFrame(rows)
    return df.sort_values(["window", "src"]).reset_index(drop=True) if len(df) else df
