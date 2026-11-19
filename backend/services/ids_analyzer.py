from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from scapy.all import IP, TCP, UDP, ICMP
from scapy.utils import PcapReader
from scapy.utils import PcapNgReader


PORT_SCAN_WINDOW_SECONDS = 10.0
PORT_SCAN_UNIQUE_PORT_THRESHOLD = 10
HOST_SCAN_WINDOW_SECONDS = 10.0
HOST_SCAN_UNIQUE_DESTINATION_THRESHOLD = 10
TRAFFIC_SPIKE_WINDOW_SECONDS = 10.0
TRAFFIC_SPIKE_PACKET_THRESHOLD = 100


def _utc_from_timestamp(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def _evict_old(events: deque, cutoff: float) -> None:
    while events and events[0][0] < cutoff:
        events.popleft()


def analyze_pcap(
    file_path: str,
    port_scan_window: float = PORT_SCAN_WINDOW_SECONDS,
    port_scan_threshold: int = PORT_SCAN_UNIQUE_PORT_THRESHOLD,
    host_scan_window: float = HOST_SCAN_WINDOW_SECONDS,
    host_scan_threshold: int = HOST_SCAN_UNIQUE_DESTINATION_THRESHOLD,
    traffic_window: float = TRAFFIC_SPIKE_WINDOW_SECONDS,
    traffic_threshold: int = TRAFFIC_SPIKE_PACKET_THRESHOLD,
) -> Dict:
    """Incrementally analyze a PCAP or PCAPNG file and return alerts/statistics."""
    path = Path(file_path)
    if path.stat().st_size == 0:
        empty_statistics = {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "other_packets": 0,
            "unique_source_ips": 0,
            "unique_destination_ips": 0,
            "unique_ip_addresses": 0,
            "alert_count": 0,
            "suspicious_ip_count": 0,
        }
        return {"packet_statistics": empty_statistics, "alerts": [], "ip_summaries": []}

    reader = PcapNgReader(str(path)) if path.suffix.lower() == ".pcapng" else PcapReader(str(path))

    total_packets = 0
    tcp_packets = 0
    udp_packets = 0
    icmp_packets = 0
    other_packets = 0
    source_ips = set()
    destination_ips = set()
    all_ips = set()
    ip_profiles = defaultdict(lambda: {
        "packets_sent": 0,
        "packets_received": 0,
        "bytes_sent": 0,
        "bytes_received": 0,
        "protocols": {"tcp": 0, "udp": 0, "icmp": 0, "other": 0},
        "tcp_source_ports": set(),
        "tcp_destination_ports": set(),
        "udp_source_ports": set(),
        "udp_destination_ports": set(),
        "first_seen": None,
        "last_seen": None,
    })

    traffic_events: Dict[str, deque] = defaultdict(deque)
    port_events: Dict[str, deque] = defaultdict(deque)
    host_events: Dict[tuple[str, int], deque] = defaultdict(deque)
    port_scan_cooldowns: Dict[str, float] = {}
    host_scan_cooldowns: Dict[tuple[str, int], float] = {}
    traffic_cooldowns: Dict[str, float] = {}
    alerts: List[Dict] = []
    suspicious_ips = set()

    try:
        with reader:
            for packet in reader:
                total_packets += 1
                timestamp = float(getattr(packet, "time", 0.0))

                if packet.haslayer(TCP):
                    tcp_packets += 1
                elif packet.haslayer(UDP):
                    udp_packets += 1
                elif packet.haslayer(ICMP):
                    icmp_packets += 1
                else:
                    other_packets += 1

                if not packet.haslayer(IP):
                    continue

                ip = packet[IP]
                src = ip.src
                dst = ip.dst
                source_ips.add(src)
                destination_ips.add(dst)
                all_ips.add(src)
                all_ips.add(dst)

                if packet.haslayer(TCP):
                    protocol = "tcp"
                elif packet.haslayer(UDP):
                    protocol = "udp"
                elif packet.haslayer(ICMP):
                    protocol = "icmp"
                else:
                    protocol = "other"

                packet_time = _utc_from_timestamp(timestamp).isoformat()
                packet_length = int(ip.len or len(ip))
                for address, direction in ((src, "sent"), (dst, "received")):
                    profile = ip_profiles[address]
                    profile[f"packets_{direction}"] += 1
                    profile[f"bytes_{direction}"] += packet_length
                    profile["protocols"][protocol] += 1
                    if profile["first_seen"] is None:
                        profile["first_seen"] = packet_time
                    profile["last_seen"] = packet_time

                if packet.haslayer(TCP):
                    ip_profiles[src]["tcp_source_ports"].add(int(packet[TCP].sport))
                    ip_profiles[dst]["tcp_destination_ports"].add(int(packet[TCP].dport))
                elif packet.haslayer(UDP):
                    ip_profiles[src]["udp_source_ports"].add(int(packet[UDP].sport))
                    ip_profiles[dst]["udp_destination_ports"].add(int(packet[UDP].dport))

                traffic_events[src].append((timestamp, dst))
                traffic_cutoff = timestamp - traffic_window
                _evict_old(traffic_events[src], traffic_cutoff)

                traffic_count = len(traffic_events[src])
                traffic_active_until = traffic_cooldowns.get(src)
                if traffic_count >= traffic_threshold and (traffic_active_until is None or timestamp >= traffic_active_until):
                    suspicious_ips.add(src)
                    alerts.append({
                        "alert_type": "Unusual Traffic Volume",
                        "severity": "Medium",
                        "source_ip": src,
                        "destination_ip": dst,
                        "description": (
                            f"{src} sent {traffic_count} packets within "
                            f"{traffic_window:g} seconds, exceeding the threshold of {traffic_threshold}."
                        ),
                        "evidence": {
                            "packet_count": traffic_count,
                            "time_window_seconds": traffic_window,
                            "threshold": traffic_threshold,
                            "destination_ips": sorted({item[1] for item in traffic_events[src]}),
                        },
                    })
                    traffic_cooldowns[src] = timestamp + traffic_window
                elif traffic_count < traffic_threshold:
                    traffic_cooldowns.pop(src, None)

                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    syn = bool(int(tcp.flags) & 0x02)
                    ack = bool(int(tcp.flags) & 0x10)
                    if syn and not ack:
                        port_events[src].append((timestamp, int(tcp.dport), dst))
                        port_cutoff = timestamp - port_scan_window
                        _evict_old(port_events[src], port_cutoff)

                        ports = sorted({item[1] for item in port_events[src]})
                        port_active_until = port_scan_cooldowns.get(src)
                        if len(ports) > port_scan_threshold and (port_active_until is None or timestamp >= port_active_until):
                            destinations = sorted({item[2] for item in port_events[src]})
                            suspicious_ips.add(src)
                            alerts.append({
                                "alert_type": "Port Scan Detected",
                                "severity": "High",
                                "source_ip": src,
                                "destination_ip": destinations[0] if len(destinations) == 1 else None,
                                "description": (
                                    f"{src} contacted {len(ports)} unique destination ports within "
                                    f"{port_scan_window:g} seconds, exceeding the threshold of {port_scan_threshold}."
                                ),
                                "evidence": {
                                    "destination_ports": ports,
                                    "unique_destination_port_count": len(ports),
                                    "time_window_seconds": port_scan_window,
                                    "threshold": port_scan_threshold,
                                    "destination_ips": destinations,
                                    "detected_at": _utc_from_timestamp(timestamp).isoformat(),
                                },
                            })
                            port_scan_cooldowns[src] = timestamp + port_scan_window

                        host_key = (src, int(tcp.dport))
                        host_events[host_key].append((timestamp, dst))
                        host_cutoff = timestamp - host_scan_window
                        _evict_old(host_events[host_key], host_cutoff)

                        destinations = sorted({item[1] for item in host_events[host_key]})
                        host_active_until = host_scan_cooldowns.get(host_key)
                        if len(destinations) > host_scan_threshold and (
                            host_active_until is None or timestamp >= host_active_until
                        ):
                            suspicious_ips.add(src)
                            alerts.append({
                                "alert_type": "Host Scan Detected",
                                "severity": "High",
                                "source_ip": src,
                                "destination_ip": None,
                                "description": (
                                    f"{src} contacted {len(destinations)} unique destination IPs on "
                                    f"TCP port {int(tcp.dport)} within {host_scan_window:g} seconds, "
                                    f"exceeding the threshold of {host_scan_threshold}."
                                ),
                                "evidence": {
                                    "destination_ips": destinations,
                                    "destination_ip_count": len(destinations),
                                    "destination_port": int(tcp.dport),
                                    "time_window_seconds": host_scan_window,
                                    "threshold": host_scan_threshold,
                                    "detected_at": _utc_from_timestamp(timestamp).isoformat(),
                                },
                            })
                            host_scan_cooldowns[host_key] = timestamp + host_scan_window
    except Exception as exc:
        raise ValueError("The capture could not be read as a valid PCAP or PCAPNG file") from exc

    statistics = {
        "total_packets": total_packets,
        "tcp_packets": tcp_packets,
        "udp_packets": udp_packets,
        "icmp_packets": icmp_packets,
        "other_packets": other_packets,
        "unique_source_ips": len(source_ips),
        "unique_destination_ips": len(destination_ips),
        "unique_ip_addresses": len(all_ips),
        "alert_count": len(alerts),
        "suspicious_ip_count": len(suspicious_ips),
    }
    alert_types_by_ip = defaultdict(list)
    for alert in alerts:
        alert_types_by_ip[alert["source_ip"]].append(alert["alert_type"])

    ip_summaries = []
    for address, profile in ip_profiles.items():
        ip_summaries.append({
            "ip": address,
            "suspicious": address in suspicious_ips,
            "alert_types": sorted(set(alert_types_by_ip[address])),
            "packets_sent": profile["packets_sent"],
            "packets_received": profile["packets_received"],
            "bytes_sent": profile["bytes_sent"],
            "bytes_received": profile["bytes_received"],
            "protocols": profile["protocols"],
            "tcp_source_ports": sorted(profile["tcp_source_ports"]),
            "tcp_destination_ports": sorted(profile["tcp_destination_ports"]),
            "udp_source_ports": sorted(profile["udp_source_ports"]),
            "udp_destination_ports": sorted(profile["udp_destination_ports"]),
            "first_seen": profile["first_seen"],
            "last_seen": profile["last_seen"],
        })

    return {"packet_statistics": statistics, "alerts": alerts, "ip_summaries": ip_summaries}
