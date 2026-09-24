"""Statistical aggregation and communication flow tracking for network packets.

Calculates deterministic protocol distributions, bandwidth metrics, endpoint talkers,
TCP conversation handshakes, and communication flow matrices.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .models import FlowRecord, PacketRecord, TrafficStatistics


class StatisticsEngine:
    """Computes reproducible traffic statistics and flow records from parsed packets."""

    def __init__(self):
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.first_timestamp: Optional[float] = None
        self.last_timestamp: Optional[float] = None

        self.protocol_counter: Counter[str] = Counter()
        self.protocol_bytes: Counter[str] = Counter()

        self.source_ip_counter: Counter[str] = Counter()
        self.source_ip_bytes: Counter[str] = Counter()

        self.dest_ip_counter: Counter[str] = Counter()
        self.dest_ip_bytes: Counter[str] = Counter()

        self.dest_port_counter: Counter[int] = Counter()
        self.tcp_flags_counter: Counter[str] = Counter()

        # Flows key: (src_ip, src_port, dst_ip, dst_port, protocol)
        self.flows: Dict[Tuple[str, Optional[int], str, Optional[int], str], FlowRecord] = {}

        # Application specific protocol counts
        self.tcp_packet_count: int = 0
        self.udp_packet_count: int = 0
        self.icmp_packet_count: int = 0
        self.dns_packet_count: int = 0
        self.http_packet_count: int = 0
        self.tls_packet_count: int = 0

        # DNS, HTTP, TLS tracking lists
        self.dns_queries: List[Dict[str, Any]] = []
        self.http_records: List[Dict[str, Any]] = []
        self.tls_records: List[Dict[str, Any]] = []

    def process_packet(self, pkt: PacketRecord) -> None:
        """Update metrics and flows with an incoming packet record."""
        self.total_packets += 1
        self.total_bytes += pkt.packet_length

        if self.first_timestamp is None or pkt.timestamp < self.first_timestamp:
            self.first_timestamp = pkt.timestamp
        if self.last_timestamp is None or pkt.timestamp > self.last_timestamp:
            self.last_timestamp = pkt.timestamp

        # Protocol distribution
        proto = pkt.protocol.upper()
        self.protocol_counter[proto] += 1
        self.protocol_bytes[proto] += pkt.packet_length

        # Specific protocol tallies
        if pkt.transport_protocol == "TCP" or proto == "TCP":
            self.tcp_packet_count += 1
        elif pkt.transport_protocol == "UDP" or proto == "UDP":
            self.udp_packet_count += 1
        elif pkt.transport_protocol == "ICMP" or proto == "ICMP":
            self.icmp_packet_count += 1

        if proto == "DNS" or pkt.dns_query is not None:
            self.dns_packet_count += 1
            if pkt.dns_query:
                self.dns_queries.append({
                    "packet_number": pkt.packet_number,
                    "timestamp": pkt.timestamp,
                    "source_ip": pkt.source_ip,
                    "query": pkt.dns_query,
                    "query_type": pkt.dns_query_type or "A",
                    "response": pkt.dns_response,
                    "answers": pkt.dns_answers or [],
                })

        if proto == "HTTP" or pkt.http_host is not None or pkt.http_method is not None:
            self.http_packet_count += 1
            self.http_records.append({
                "packet_number": pkt.packet_number,
                "timestamp": pkt.timestamp,
                "source_ip": pkt.source_ip,
                "destination_ip": pkt.destination_ip,
                "method": pkt.http_method,
                "host": pkt.http_host,
                "uri": pkt.http_uri,
                "status_code": pkt.http_status_code,
                "user_agent": pkt.http_user_agent,
            })

        if proto == "TLS" or pkt.tls_information is not None:
            self.tls_packet_count += 1
            tls_data = pkt.tls_information or {}
            self.tls_records.append({
                "packet_number": pkt.packet_number,
                "timestamp": pkt.timestamp,
                "source_ip": pkt.source_ip,
                "destination_ip": pkt.destination_ip,
                "version": tls_data.get("version"),
                "handshake_type": tls_data.get("handshake_type"),
                "sni": tls_data.get("sni"),
            })

        # Endpoint accounting
        if pkt.source_ip:
            self.source_ip_counter[pkt.source_ip] += 1
            self.source_ip_bytes[pkt.source_ip] += pkt.packet_length

        if pkt.destination_ip:
            self.dest_ip_counter[pkt.destination_ip] += 1
            self.dest_ip_bytes[pkt.destination_ip] += pkt.packet_length

        if pkt.destination_port is not None:
            self.dest_port_counter[pkt.destination_port] += 1

        # TCP Flags
        if pkt.flags:
            for flag_name, is_set in pkt.flags.items():
                if is_set:
                    self.tcp_flags_counter[flag_name] += 1

        # Flow tracking
        if pkt.source_ip and pkt.destination_ip:
            self._update_flow(pkt)

    def _update_flow(self, pkt: PacketRecord) -> None:
        """Track endpoint conversation flow with TCP state and rate metrics."""
        src_ip = pkt.source_ip or "0.0.0.0"
        dst_ip = pkt.destination_ip or "0.0.0.0"
        src_port = pkt.source_port
        dst_port = pkt.destination_port
        protocol = pkt.transport_protocol or pkt.protocol

        flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)
        if flow_key not in self.flows:
            port_str_src = f":{src_port}" if src_port else ""
            port_str_dst = f":{dst_port}" if dst_port else ""
            flow_id = f"{src_ip}{port_str_src} -> {dst_ip}{port_str_dst} [{protocol}]"
            self.flows[flow_key] = FlowRecord(
                flow_id=flow_id,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                protocol=protocol,
                packet_count=0,
                byte_count=0,
                first_seen=pkt.timestamp,
                last_seen=pkt.timestamp,
                duration_seconds=0.0,
            )

        flow = self.flows[flow_key]
        flow.packet_count += 1
        flow.byte_count += pkt.packet_length
        flow.last_seen = max(flow.last_seen, pkt.timestamp)
        flow.first_seen = min(flow.first_seen, pkt.timestamp)
        flow.duration_seconds = max(0.0, flow.last_seen - flow.first_seen)

        # Compute PPS and BPS
        eff_duration = max(flow.duration_seconds, 0.001)
        flow.packets_per_second = round(flow.packet_count / eff_duration, 2)
        flow.bytes_per_second = round(flow.byte_count / eff_duration, 2)

        if pkt.flags:
            is_syn = pkt.flags.get("SYN", False)
            is_ack = pkt.flags.get("ACK", False)
            is_fin = pkt.flags.get("FIN", False)
            is_rst = pkt.flags.get("RST", False)

            if is_syn and not is_ack:
                flow.syn_count += 1
            elif is_syn and is_ack:
                flow.syn_ack_count += 1
            if is_ack and not is_syn:
                flow.ack_count += 1
            if is_fin:
                flow.fin_count += 1
            if is_rst:
                flow.rst_count += 1

            # Check if this flow saw an established handshake (SYN + ACK)
            if flow.syn_count > 0 and (flow.ack_count > 0 or flow.syn_ack_count > 0):
                flow.completed_handshake = True

        # Flow classification based on observable packet behavior
        if protocol == "UDP":
            flow.classification = "UDP communication"
        elif protocol == "ICMP":
            flow.classification = "ICMP communication"
        elif protocol == "TCP":
            if flow.syn_count > 3 and not flow.completed_handshake:
                flow.classification = "repeated connection attempts"
            elif flow.syn_count > 0 and not flow.completed_handshake:
                flow.classification = "incomplete TCP connection"
            else:
                flow.classification = "normal TCP session"

    def get_summary_statistics(self) -> TrafficStatistics:
        """Compile computed metrics into a TrafficStatistics object."""
        duration = 0.0
        if self.first_timestamp is not None and self.last_timestamp is not None:
            duration = max(0.0, self.last_timestamp - self.first_timestamp)

        # Calculate handshake and SYN metrics
        total_syns = sum(f.syn_count for f in self.flows.values())
        completed_hs = sum(1 for f in self.flows.values() if f.protocol == "TCP" and f.completed_handshake)
        incomplete_hs = sum(1 for f in self.flows.values() if f.protocol == "TCP" and f.syn_count > 0 and not f.completed_handshake)
        total_resets = self.tcp_flags_counter.get("RST", 0)

        # Top Source IPs
        top_sources = []
        for ip, count in self.source_ip_counter.most_common(10):
            byte_val = self.source_ip_bytes.get(ip, 0)
            pct = (count / self.total_packets * 100.0) if self.total_packets else 0.0
            top_sources.append({
                "ip": ip,
                "packet_count": count,
                "byte_count": byte_val,
                "percentage": round(pct, 2),
            })

        # Top Destination IPs
        top_destinations = []
        for ip, count in self.dest_ip_counter.most_common(10):
            byte_val = self.dest_ip_bytes.get(ip, 0)
            pct = (count / self.total_packets * 100.0) if self.total_packets else 0.0
            top_destinations.append({
                "ip": ip,
                "packet_count": count,
                "byte_count": byte_val,
                "percentage": round(pct, 2),
            })

        # Top Destination Ports
        top_ports = []
        for port, count in self.dest_port_counter.most_common(10):
            pct = (count / self.total_packets * 100.0) if self.total_packets else 0.0
            top_ports.append({
                "port": port,
                "packet_count": count,
                "percentage": round(pct, 2),
            })

        return TrafficStatistics(
            total_packets=self.total_packets,
            total_bytes=self.total_bytes,
            capture_duration=duration,
            unique_source_ips=len(self.source_ip_counter),
            unique_destination_ips=len(self.dest_ip_counter),
            unique_conversations=len(self.flows),
            tcp_packet_count=self.tcp_packet_count,
            udp_packet_count=self.udp_packet_count,
            icmp_packet_count=self.icmp_packet_count,
            dns_packet_count=self.dns_packet_count,
            http_packet_count=self.http_packet_count,
            tls_packet_count=self.tls_packet_count,
            total_syn_packets=total_syns,
            completed_handshakes=completed_hs,
            incomplete_handshakes=incomplete_hs,
            total_resets=total_resets,
            protocol_distribution=dict(self.protocol_counter),
            protocol_bytes=dict(self.protocol_bytes),
            top_source_ips=top_sources,
            top_destination_ips=top_destinations,
            top_destination_ports=top_ports,
            tcp_flags_distribution=dict(self.tcp_flags_counter),
        )

    def get_sorted_flows(self, sort_by: str = "packets", limit: int = 50) -> List[FlowRecord]:
        """Return flows sorted by packet count, bytes, or recency.

        Args:
            sort_by: One of 'packets', 'bytes', 'duration', 'newest'
            limit: Maximum number of flows to return
        """
        all_flows = list(self.flows.values())
        if sort_by == "bytes":
            all_flows.sort(key=lambda f: f.byte_count, reverse=True)
        elif sort_by == "duration":
            all_flows.sort(key=lambda f: f.duration_seconds, reverse=True)
        elif sort_by == "newest":
            all_flows.sort(key=lambda f: f.last_seen, reverse=True)
        else:  # 'packets'
            all_flows.sort(key=lambda f: f.packet_count, reverse=True)

        return all_flows[:limit]
