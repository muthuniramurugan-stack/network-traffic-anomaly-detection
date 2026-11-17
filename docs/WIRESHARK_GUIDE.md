# Using Wireshark with this project

## 1. Get a PCAP
- **Wireshark:** capture on your interface -> *File > Save As…* -> `.pcap` / `.pcapng`.
- **Scapy (this project):** `sudo python -m netanomaly capture -i eth0 -t 120 -o data/capture.pcap`
- **tcpdump:** `sudo tcpdump -i eth0 -w data/capture.pcap`

> Only capture networks you own or are authorised to monitor.

## 2. Analyse
```bash
python -m netanomaly detect data/capture.pcap --baseline data/clean_baseline.pcap
```

## 3. Investigate alerts in Wireshark
Open `output/alerts.csv`; each row has a ready-made `wireshark_filter`, e.g.

```
ip.src == 10.0.0.66 && frame.time_epoch >= 1700000060 && frame.time_epoch < 1700000070
```
Paste it into the Wireshark display-filter bar.

## Handy filters per attack type
| Attack | Filter |
|---|---|
| Port scan / SYN flood | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| DNS tunneling | `dns && dns.qry.name.len > 40` |
| Large outbound transfer | `ip.src == <host> && frame.len > 1000` |
| Statistics | *Statistics > Conversations*, *Statistics > Endpoints*, *Statistics > I/O Graph* |
