"""Live packet capture with Scapy (needs root/admin + libpcap/Npcap)."""
from scapy.all import sniff, wrpcap


def capture(iface=None, count=0, timeout=60, bpf=None, out="data/capture.pcap"):
    pkts = sniff(iface=iface, count=count, timeout=timeout, filter=bpf, store=True)
    wrpcap(out, pkts)
    return len(pkts)
