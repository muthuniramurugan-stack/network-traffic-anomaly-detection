"""Synthetic traffic generator (Scapy) -> PCAP, with ground-truth labels.

Creates realistic-looking baseline traffic and optionally injects attacks:
  * port scan      (one host SYN-probing many ports)
  * SYN flood      (one host hammering a port with SYNs)
  * DNS tunneling  (long, random, high-rate DNS qnames)
  * data exfil     (large volume to one external host)
"""

import json
import random
import string
from pathlib import Path

from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Raw, wrpcap


CLIENTS = [f"10.0.0.{i}" for i in range(10, 30)]

SERVERS = [
    "10.0.0.5",
    "10.0.0.6",
    "93.184.216.34",
    "142.250.72.14",
    "151.101.1.69"
]

DNS_SERVER = "10.0.0.2"

DOMAINS = [
    "example.com",
    "google.com",
    "github.com",
    "wikipedia.org",
    "python.org",
    "mit.edu"
]


def _pkt(layer, ts):
    """Create an IP packet without an Ethernet layer."""
    p = layer
    p.time = ts
    return p


def _rand(n):
    return "".join(
        random.choices(string.ascii_lowercase + string.digits, k=n)
    )


def _web_session(pkts, ts, src):

    dst = random.choice(SERVERS)

    dport = random.choice([80, 443, 443, 443, 8080])

    sport = random.randint(20000, 60000)

    pkts.append(
        _pkt(
            IP(src=src, dst=dst) /
            TCP(sport=sport, dport=dport, flags="S"),
            ts
        )
    )

    pkts.append(
        _pkt(
            IP(src=dst, dst=src) /
            TCP(sport=dport, dport=sport, flags="SA"),
            ts + 0.01
        )
    )

    pkts.append(
        _pkt(
            IP(src=src, dst=dst) /
            TCP(sport=sport, dport=dport, flags="A"),
            ts + 0.02
        )
    )

    for i in range(random.randint(2, 8)):

        size = random.randint(100, 1200)

        pkts.append(
            _pkt(
                IP(src=src, dst=dst) /
                TCP(sport=sport, dport=dport, flags="PA") /
                Raw(b"x" * size),
                ts + 0.05 + i * 0.03
            )
        )

        pkts.append(
            _pkt(
                IP(src=dst, dst=src) /
                TCP(sport=dport, dport=sport, flags="PA") /
                Raw(b"y" * random.randint(200, 1400)),
                ts + 0.06 + i * 0.03
            )
        )


def _dns(pkts, ts, src, qname=None):

    qname = qname or random.choice(DOMAINS)

    pkts.append(
        _pkt(
            IP(src=src, dst=DNS_SERVER) /
            UDP(
                sport=random.randint(20000, 60000),
                dport=53
            ) /
            DNS(
                rd=1,
                qd=DNSQR(qname=qname)
            ),
            ts
        )
    )


def generate(
    out_pcap,
    duration=300,
    seed=42,
    attacks=True,
    start=1_700_000_000.0
):

    random.seed(seed)

    pkts, labels = [], {}

    # Generate normal baseline traffic
    for src in CLIENTS:

        t = start + random.random() * 5

        while t < start + duration:

            if random.random() < 0.7:
                _web_session(pkts, t, src)
            else:
                _dns(pkts, t, src)

            if random.random() < 0.02:

                pkts.append(
                    _pkt(
                        IP(
                            src=src,
                            dst=random.choice(SERVERS)
                        ) / ICMP(),
                        t
                    )
                )

            t += random.expovariate(1 / 6.0)

    # Inject attack traffic
    if attacks:

        # 1. Port Scan
        scanner = "10.0.0.66"

        for i, port in enumerate(range(1, 1025)):

            pkts.append(
                _pkt(
                    IP(src=scanner, dst="10.0.0.5") /
                    TCP(
                        sport=44444,
                        dport=port,
                        flags="S"
                    ),
                    start + 60 + i * 0.012
                )
            )

        labels[scanner] = "port_scan"

        # 2. SYN Flood
        flooder = "10.0.0.77"

        for i in range(4000):

            pkts.append(
                _pkt(
                    IP(src=flooder, dst="10.0.0.6") /
                    TCP(
                        sport=random.randint(1024, 65535),
                        dport=80,
                        flags="S"
                    ),
                    start + 120 + i * 0.003
                )
            )

        labels[flooder] = "syn_flood"

        # 3. DNS Tunneling
        tunneler = "10.0.0.88"

        for i in range(300):

            _dns(
                pkts,
                start + 180 + i * 0.1,
                tunneler,
                qname=_rand(48) + "." + _rand(20) + ".evil-c2.net"
            )

        labels[tunneler] = "dns_tunnel"

        # 4. Data Exfiltration
        exfil = "10.0.0.99"

        for i in range(800):

            pkts.append(
                _pkt(
                    IP(src=exfil, dst="203.0.113.50") /
                    TCP(
                        sport=50505,
                        dport=443,
                        flags="PA"
                    ) /
                    Raw(b"z" * 1400),
                    start + 240 + i * 0.025
                )
            )

        labels[exfil] = "data_exfil"

    # Sort packets by timestamp
    pkts.sort(key=lambda p: float(p.time))

    # Save PCAP file
    out_pcap = Path(out_pcap)

    out_pcap.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    wrpcap(str(out_pcap), pkts)

    # Save ground-truth labels
    out_pcap.with_suffix(".labels.json").write_text(
        json.dumps(labels, indent=2)
    )

    return len(pkts), labels