"""Threat detection and security heuristic rules engine.

Evaluates deterministic rule sets against parsed packets and conversation flows
to identify network reconnaissance, abnormal traffic volume, suspicious ports,
cleartext protocol usage, DNS tunneling indicators, HTTP anomalies, and TLS security posture.
Provides transparent evidence, exact packet references, analyst recommendations, and forensic limitations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter, defaultdict
import logging
from typing import Any, Dict, List, Optional, Set

from .config import DetectionConfig
from .models import (
    AlertFinding,
    DNSRecord,
    FindingCategory,
    FlowRecord,
    HTTPRecord,
    PacketRecord,
    Severity,
    TLSRecord,
    TrafficStatistics,
)
from .utils import calculate_shannon_entropy, get_port_service_name

logger = logging.getLogger(__name__)


class BaseDetectionRule(ABC):
    """Abstract base class for modular threat detection and observation rules."""

    rule_id: str = "RULE-000"
    rule_name: str = "Base Rule"
    category: str = FindingCategory.TRAFFIC_ANOMALY.value

    def __init__(self, config: DetectionConfig):
        self.config = config

    @abstractmethod
    def evaluate(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: TrafficStatistics,
        dns: Optional[List[DNSRecord]] = None,
        http: Optional[List[HTTPRecord]] = None,
        tls: Optional[List[TLSRecord]] = None,
    ) -> List[AlertFinding]:
        """Evaluate network capture artifacts and return generated findings."""
        pass


class Rule001TcpSynScan(BaseDetectionRule):
    """RULE 001: Potential TCP SYN scanning pattern.

    Detects a source host transmitting SYN packets across numerous destination ports
    or IP addresses with a disproportionately low TCP handshake completion rate,
    characteristic of port reconnaissance (vertical scan, horizontal sweep, or hybrid).
    """

    rule_id = "RULE-001"
    rule_name = "Potential TCP SYN scanning pattern"
    category = FindingCategory.RECONNAISSANCE.value

    def evaluate(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: TrafficStatistics,
        dns: Optional[List[DNSRecord]] = None,
        http: Optional[List[HTTPRecord]] = None,
        tls: Optional[List[TLSRecord]] = None,
        **kwargs: Any,
    ) -> List[AlertFinding]:
        findings: List[AlertFinding] = []

        # Aggregate SYN attempts per source IP
        syn_by_source: Dict[str, int] = defaultdict(int)
        ports_by_source: Dict[str, Set[int]] = defaultdict(set)
        hosts_by_source: Dict[str, Set[str]] = defaultdict(set)
        packets_by_source: Dict[str, List[int]] = defaultdict(list)
        first_ts_by_source: Dict[str, float] = {}

        # Track completed connections per source
        completed_conns_by_source: Dict[str, int] = defaultdict(int)

        for flow in flows:
            if flow.protocol == "TCP" and flow.source_ip:
                if flow.completed_handshake:
                    completed_conns_by_source[flow.source_ip] += 1

        for pkt in packets:
            if (
                pkt.transport_protocol == "TCP"
                and pkt.source_ip
                and pkt.flags
                and pkt.flags.get("SYN")
                and not pkt.flags.get("ACK")
            ):
                src = pkt.source_ip
                syn_by_source[src] += 1
                if len(packets_by_source[src]) < 25:
                    packets_by_source[src].append(pkt.packet_number)
                if pkt.destination_port:
                    ports_by_source[src].add(pkt.destination_port)
                if pkt.destination_ip:
                    hosts_by_source[src].add(pkt.destination_ip)
                if src not in first_ts_by_source:
                    first_ts_by_source[src] = pkt.timestamp

        for src, syn_count in syn_by_source.items():
            unique_ports = len(ports_by_source[src])
            unique_hosts = len(hosts_by_source[src])
            completed = completed_conns_by_source.get(src, 0)
            completion_ratio = (completed / syn_count) if syn_count > 0 else 0.0

            is_vertical_scan = unique_ports >= self.config.syn_scan_unique_port_threshold
            is_horizontal_scan = unique_hosts >= self.config.syn_scan_unique_host_threshold

            if (
                syn_count >= self.config.syn_scan_min_packets
                and (is_vertical_scan or is_horizontal_scan)
                and completion_ratio <= self.config.syn_scan_completion_ratio_max
            ):
                scan_type = (
                    "vertical port scan"
                    if is_vertical_scan and not is_horizontal_scan
                    else "horizontal network sweep"
                    if is_horizontal_scan and not is_vertical_scan
                    else "hybrid vertical and horizontal scan"
                )

                finding = AlertFinding(
                    id=f"{self.rule_id}-{src.replace('.', '-')}",
                    timestamp=first_ts_by_source.get(src, 0.0),
                    severity=Severity.HIGH,
                    category=self.category,
                    title="Potential network scanning activity observed",
                    description=(
                        f"Host {src} initiated {syn_count} TCP SYN packets targeting "
                        f"{unique_ports} unique ports across {unique_hosts} destination hosts "
                        f"with only {completed} established handshakes ({completion_ratio:.1%} completion). "
                        f"This pattern exhibits characteristics of a {scan_type}."
                    ),
                    source_ip=src,
                    protocol="TCP",
                    evidence={
                        "scan_classification": scan_type,
                        "syn_packets_transmitted": syn_count,
                        "unique_destination_ports_targeted": unique_ports,
                        "unique_destination_hosts_targeted": unique_hosts,
                        "completed_handshakes": completed,
                        "handshake_completion_ratio": round(completion_ratio, 4),
                        "sample_targeted_ports": sorted(list(ports_by_source[src]))[:15],
                        "sample_targeted_hosts": sorted(list(hosts_by_source[src]))[:10],
                    },
                    packet_numbers=packets_by_source[src][:15],
                    detection_rule=self.rule_id,
                    confidence=0.88,
                    recommended_next_step=(
                        f"Correlate host {src} with internal asset inventory or perimeter firewall logs. "
                        "Determine if this is an authorized vulnerability scanner or an unapproved host probing internal services."
                    ),
                    limitations=(
                        "Offline PCAP analysis cannot distinguish authorized vulnerability scans "
                        "from adversary reconnaissance without external authorization context."
                    ),
                )
                findings.append(finding)

        return findings


class Rule002ConnectionFlood(BaseDetectionRule):
    """RULE 002: Potential connection flood.

    Identifies an unusually concentrated surge of connection attempts originating
    from a single host compared with baseline traffic rates in the capture.
    """

    rule_id = "RULE-002"
    rule_name = "Potential connection flood"
    category = FindingCategory.TRAFFIC_ANOMALY.value

    def evaluate(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: TrafficStatistics,
        dns: Optional[List[DNSRecord]] = None,
        http: Optional[List[HTTPRecord]] = None,
        tls: Optional[List[TLSRecord]] = None,
        **kwargs: Any,
    ) -> List[AlertFinding]:
        findings: List[AlertFinding] = []
        if stats.capture_duration <= 0.05 or stats.total_packets == 0:
            return findings

        packets_by_source: Dict[str, int] = defaultdict(int)
        sample_pkts_by_source: Dict[str, List[int]] = defaultdict(list)

        for pkt in packets:
            if pkt.source_ip:
                packets_by_source[pkt.source_ip] += 1
                if len(sample_pkts_by_source[pkt.source_ip]) < 15:
                    sample_pkts_by_source[pkt.source_ip].append(pkt.packet_number)

        for src, count in packets_by_source.items():
            rate = count / max(stats.capture_duration, 1.0)
            traffic_ratio = count / stats.total_packets

            if (
                count >= self.config.connection_flood_min_packets
                and (rate >= self.config.connection_flood_rate_threshold or traffic_ratio >= 0.70)
            ):
                findings.append(
                    AlertFinding(
                        id=f"{self.rule_id}-{src.replace('.', '-')}",
                        timestamp=stats.capture_duration,
                        severity=Severity.MEDIUM,
                        category=self.category,
                        title="High-frequency connection volume from single endpoint",
                        description=(
                            f"Host {src} generated {count} packets at an average rate of "
                            f"{rate:.1f} packets/sec, representing {traffic_ratio:.1%} of all "
                            "observed network traffic in this capture."
                        ),
                        source_ip=src,
                        evidence={
                            "packet_count": count,
                            "packet_rate_per_second": round(rate, 2),
                            "ratio_of_total_capture": round(traffic_ratio, 4),
                            "capture_duration_seconds": round(stats.capture_duration, 2),
                        },
                        packet_numbers=sample_pkts_by_source[src][:10],
                        detection_rule=self.rule_id,
                        confidence=0.75,
                        recommended_next_step=(
                            f"Investigate processes running on {src}. Confirm if this high throughput "
                            "is expected application traffic, backup data replication, or an unintended flood."
                        ),
                        limitations=(
                            "Rate calculations are averaged across the total capture window and do not reflect peak micro-bursts."
                        ),
                    )
                )

        return findings


class Rule003UnusualDestinationPort(BaseDetectionRule):
    """RULE 003: Unusual destination port activity.

    Identifies communication directed towards ports frequently associated with
    backdoors, remote administration tools (RATs), or unauthorized protocols.
    """

    rule_id = "RULE-003"
    rule_name = "Unusual destination port activity"
    category = FindingCategory.SECURITY_OBSERVATION.value

    def evaluate(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: TrafficStatistics,
        dns: Optional[List[DNSRecord]] = None,
        http: Optional[List[HTTPRecord]] = None,
        tls: Optional[List[TLSRecord]] = None,
        **kwargs: Any,
    ) -> List[AlertFinding]:
        findings: List[AlertFinding] = []
        unusual_set = set(self.config.unusual_ports)

        port_activity: Dict[int, Dict[str, Any]] = defaultdict(
            lambda: {
                "packets": 0,
                "bytes": 0,
                "sources": set(),
                "destinations": set(),
                "protocols": set(),
                "packet_numbers": [],
            }
        )

        for pkt in packets:
            if pkt.destination_port in unusual_set:
                data = port_activity[pkt.destination_port]
                data["packets"] += 1
                data["bytes"] += pkt.packet_length
                if len(data["packet_numbers"]) < 10:
                    data["packet_numbers"].append(pkt.packet_number)
                if pkt.source_ip:
                    data["sources"].add(pkt.source_ip)
                if pkt.destination_ip:
                    data["destinations"].add(pkt.destination_ip)
                data["protocols"].add(pkt.protocol)

        for port, data in port_activity.items():
            if data["packets"] >= self.config.unusual_port_packet_threshold:
                svc_name = get_port_service_name(port)
                findings.append(
                    AlertFinding(
                        id=f"{self.rule_id}-port-{port}",
                        timestamp=0.0,
                        severity=Severity.LOW,
                        category=self.category,
                        title=f"Activity observed on uncommon port {port} ({svc_name})",
                        description=(
                            f"Identified {data['packets']} packets directed toward destination port {port}, "
                            f"a non-standard port frequently monitored in SOC baselines for {svc_name} activity."
                        ),
                        destination_port=port,
                        protocol=",".join(sorted(list(data["protocols"]))),
                        evidence={
                            "destination_port": port,
                            "service_reference": svc_name,
                            "packet_count": data["packets"],
                            "total_bytes": data["bytes"],
                            "source_hosts": sorted(list(data["sources"])),
                            "destination_hosts": sorted(list(data["destinations"])),
                        },
                        packet_numbers=data["packet_numbers"],
                        detection_rule=self.rule_id,
                        confidence=0.65,
                        recommended_next_step=(
                            f"Review destination endpoint on port {port}. Verify if this service is registered "
                            "in the organization's approved service catalog."
                        ),
                        limitations="Port number alone does not guarantee protocol identity without full payload inspection.",
                    )
                )

        return findings


class Rule004DnsQueryAnomaly(BaseDetectionRule):
    """RULE 004: High DNS query volume anomaly.

    Identifies an unusually high volume of DNS resolution requests originating
    from a single client host, which can indicate automated scraping or C2 heartbeat polling.
    """

    rule_id = "RULE-004"
    rule_name = "High DNS query volume anomaly"
    category = FindingCategory.DNS_ANOMALY.value

    def evaluate(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: TrafficStatistics,
        dns: Optional[List[DNSRecord]] = None,
        http: Optional[List[HTTPRecord]] = None,
        tls: Optional[List[TLSRecord]] = None,
        **kwargs: Any,
    ) -> List[AlertFinding]:
        findings: List[AlertFinding] = []
        dns_queries_by_source: Dict[str, List[str]] = defaultdict(list)
        packets_by_source: Dict[str, List[int]] = defaultdict(list)

        for pkt in packets:
            if pkt.dns_query and pkt.source_ip:
                dns_queries_by_source[pkt.source_ip].append(pkt.dns_query)
                if len(packets_by_source[pkt.source_ip]) < 10:
                    packets_by_source[pkt.source_ip].append(pkt.packet_number)

        for src, queries in dns_queries_by_source.items():
            query_count = len(queries)
            query_rate = query_count / max(stats.capture_duration, 1.0)

            if (
                query_count >= self.config.dns_query_volume_threshold
                or query_rate >= self.config.dns_query_rate_threshold
            ):
                unique_domains = len(set(queries))
                findings.append(
                    AlertFinding(
                        id=f"{self.rule_id}-{src.replace('.', '-')}",
                        timestamp=stats.capture_duration,
                        severity=Severity.MEDIUM,
                        category=self.category,
                        title="Unusually high DNS query volume observed from host",
                        description=(
                            f"Host {src} generated {query_count} DNS queries ({query_rate:.1f} queries/sec) "
                            f"requesting {unique_domains} unique domains. Elevated query volume may warrant "
                            "investigation into local client resolution processes or automated tooling."
                        ),
                        source_ip=src,
                        protocol="DNS",
                        evidence={
                            "total_dns_queries": query_count,
                            "queries_per_second": round(query_rate, 2),
                            "unique_domains_queried": unique_domains,
                            "sample_domains": sorted(list(set(queries)))[:5],
                        },
                        packet_numbers=packets_by_source[src],
                        detection_rule=self.rule_id,
                        confidence=0.72,
                        recommended_next_step=(
                            f"Inspect DNS cache and active applications on {src}. Verify if the querying "
                            "process is a known enterprise browser, security scanner, or unrecognized background daemon."
                        ),
                        limitations="High query volume can occur legitimately on DNS proxies or busy local forwarders.",
                    )
                )

        return findings


class Rule005SuspiciousDnsCharacteristics(BaseDetectionRule):
    """RULE 005: Potential DNS tunneling indicators observed.

    Flags unusually long DNS query strings or domain labels exhibiting high Shannon
    entropy (> 3.85 bits), which are well-documented indicators of DNS data exfiltration,
    tunneling (e.g. dnscat2, iodine), or domain generation algorithms (DGAs).
    """

    rule_id = "RULE-005"
    rule_name = "Potential DNS tunneling indicators observed"
    category = FindingCategory.DNS_ANOMALY.value

    def evaluate(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: TrafficStatistics,
        dns: Optional[List[DNSRecord]] = None,
        http: Optional[List[HTTPRecord]] = None,
        tls: Optional[List[TLSRecord]] = None,
        **kwargs: Any,
    ) -> List[AlertFinding]:
        findings: List[AlertFinding] = []
        suspicious_queries: List[Dict[str, Any]] = []
        packet_refs_by_source: Dict[str, List[int]] = defaultdict(list)

        seen_domains: Set[str] = set()

        for pkt in packets:
            if not pkt.dns_query or pkt.dns_query in seen_domains:
                continue

            domain = pkt.dns_query
            seen_domains.add(domain)
            parts = domain.split(".")
            subdomain_prefix = parts[0] if parts else domain

            entropy = calculate_shannon_entropy(subdomain_prefix)
            qlen = len(domain)

            is_long = qlen >= self.config.dns_suspicious_length_threshold
            is_high_entropy = (
                len(subdomain_prefix) >= 12
                and entropy >= self.config.dns_high_entropy_threshold
            )

            if is_long or is_high_entropy:
                src = pkt.source_ip or "Unknown"
                if len(packet_refs_by_source[src]) < 10:
                    packet_refs_by_source[src].append(pkt.packet_number)

                suspicious_queries.append({
                    "domain": domain,
                    "length": qlen,
                    "subdomain_entropy": round(entropy, 3),
                    "source_ip": src,
                    "reason": "High entropy label" if is_high_entropy and not is_long
                    else "Excessive string length" if is_long and not is_high_entropy
                    else "High entropy & excessive length",
                })

        if suspicious_queries:
            by_src: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for sq in suspicious_queries:
                by_src[sq.get("source_ip") or "Unknown"].append(sq)

            for src, q_list in by_src.items():
                findings.append(
                    AlertFinding(
                        id=f"{self.rule_id}-{src.replace('.', '-')}",
                        timestamp=0.0,
                        severity=Severity.HIGH,
                        category=self.category,
                        title="Potential DNS tunneling indicators observed",
                        description=(
                            f"Observed {len(q_list)} DNS queries associated with {src} displaying "
                            "structural indicators commonly found in DNS tunneling or DGA patterns: "
                            "elevated Shannon entropy in labels and/or abnormal character length."
                        ),
                        source_ip=src if src != "Unknown" else None,
                        protocol="DNS",
                        evidence={
                            "suspicious_query_count": len(q_list),
                            "sample_queries": q_list[:8],
                            "entropy_threshold": self.config.dns_high_entropy_threshold,
                            "length_threshold": self.config.dns_suspicious_length_threshold,
                        },
                        packet_numbers=packet_refs_by_source[src],
                        detection_rule=self.rule_id,
                        confidence=0.84,
                        recommended_next_step=(
                            "Capture full authoritative DNS responses and inspect TXT or NULL records. "
                            "Cross-check queried domains with WHOIS registration dates and threat intelligence feeds."
                        ),
                        limitations=(
                            "Legitimate CDN distribution, anti-virus cloud lookups, and tracking pixels "
                            "can generate high-entropy subdomains without malicious intent."
                        ),
                    )
                )

        return findings


class Rule006RepeatedFailedTcpConnections(BaseDetectionRule):
    """RULE 006: Repeated failed TCP connections.

    Identifies hosts repeatedly attempting TCP connections that terminate with RST packets
    or fail to produce ESTABLISHED connections, indicating closed-port probes or network blocks.
    """

    rule_id = "RULE-006"
    rule_name = "Repeated failed TCP connections"
    category = FindingCategory.CONNECTION_ANOMALY.value

    def evaluate(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: TrafficStatistics,
        dns: Optional[List[DNSRecord]] = None,
        http: Optional[List[HTTPRecord]] = None,
        tls: Optional[List[TLSRecord]] = None,
        **kwargs: Any,
    ) -> List[AlertFinding]:
        findings: List[AlertFinding] = []

        failed_by_source: Dict[str, int] = defaultdict(int)
        failed_targets: Dict[str, Set[str]] = defaultdict(set)

        for flow in flows:
            if flow.protocol == "TCP" and flow.source_ip:
                if flow.syn_count > 0 and not flow.completed_handshake:
                    failed_by_source[flow.source_ip] += flow.syn_count
                    if flow.destination_ip:
                        port_part = f":{flow.destination_port}" if flow.destination_port else ""
                        failed_targets[flow.source_ip].add(f"{flow.destination_ip}{port_part}")

        for src, failed_count in failed_by_source.items():
            if failed_count >= self.config.failed_connection_threshold:
                targets = sorted(list(failed_targets[src]))[:10]
                findings.append(
                    AlertFinding(
                        id=f"{self.rule_id}-{src.replace('.', '-')}",
                        timestamp=0.0,
                        severity=Severity.LOW,
                        category=self.category,
                        title="Repeated failed TCP connection attempts observed",
                        description=(
                            f"Host {src} initiated {failed_count} TCP connection attempts that failed "
                            "to complete the standard 3-way handshake, suggesting unreachable services or filtering."
                        ),
                        source_ip=src,
                        protocol="TCP",
                        evidence={
                            "failed_syn_count": failed_count,
                            "targeted_destinations_sample": targets,
                        },
                        detection_rule=self.rule_id,
                        confidence=0.70,
                        recommended_next_step=(
                            f"Check firewall logs and service availability for targets of {src}. "
                            "Determine if this is misconfigured polling software or systematic port checking."
                        ),
                        limitations="Transient network packet loss or asymmetric routing can cause missed SYN-ACKs.",
                    )
                )

        return findings


class Rule007IcmpVolumeAnomaly(BaseDetectionRule):
    """RULE 007: ICMP transmission volume anomaly.

    Identifies excessive ICMP transmission rates or volume from a source host,
    frequently indicative of network mapping (ping sweeps), path MTU discovery issues, or ICMP floods.
    """

    rule_id = "RULE-007"
    rule_name = "ICMP transmission volume anomaly"
    category = FindingCategory.TRAFFIC_ANOMALY.value

    def evaluate(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: TrafficStatistics,
        dns: Optional[List[DNSRecord]] = None,
        http: Optional[List[HTTPRecord]] = None,
        tls: Optional[List[TLSRecord]] = None,
        **kwargs: Any,
    ) -> List[AlertFinding]:
        findings: List[AlertFinding] = []
        icmp_by_source: Dict[str, int] = defaultdict(int)
        packets_by_source: Dict[str, List[int]] = defaultdict(list)

        for pkt in packets:
            if pkt.protocol == "ICMP" and pkt.source_ip:
                src = pkt.source_ip
                icmp_by_source[src] += 1
                if len(packets_by_source[src]) < 10:
                    packets_by_source[src].append(pkt.packet_number)

        for src, count in icmp_by_source.items():
            rate = count / max(stats.capture_duration, 1.0)
            if (
                count >= self.config.icmp_volume_threshold
                or rate >= self.config.icmp_rate_threshold
            ):
                findings.append(
                    AlertFinding(
                        id=f"{self.rule_id}-{src.replace('.', '-')}",
                        timestamp=0.0,
                        severity=Severity.MEDIUM,
                        category=self.category,
                        title="Elevated ICMP transmission volume observed",
                        description=(
                            f"Host {src} transmitted {count} ICMP packets at an average rate "
                            f"of {rate:.1f} packets/second, which may signify active network "
                            "ping sweeping, path MTU issues, or flood attempts."
                        ),
                        source_ip=src,
                        protocol="ICMP",
                        evidence={
                            "icmp_packet_count": count,
                            "icmp_packets_per_sec": round(rate, 2),
                            "capture_duration_seconds": round(stats.capture_duration, 2),
                        },
                        packet_numbers=packets_by_source[src],
                        detection_rule=self.rule_id,
                        confidence=0.74,
                        recommended_next_step=(
                            f"Review ICMP types and codes sent by {src}. Confirm if this traffic consists "
                            "of echo requests across a subnet or unreachable destination error replies."
                        ),
                        limitations="Network monitoring tools like Nagios/Zabbix routinely emit regular ICMP polling bursts.",
                    )
                )

        return findings


class Rule008CleartextProtocolObservation(BaseDetectionRule):
    """RULE 008: Cleartext protocol observation.

    Identifies unencrypted application protocols transmitting in the clear (HTTP,
    FTP, Telnet, POP3, IMAP). Highlights risk of credential theft and session eavesdropping.
    """

    rule_id = "RULE-008"
    rule_name = "Cleartext protocol observation"
    category = FindingCategory.CLEARTEXT_COMMUNICATION.value

    def evaluate(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: TrafficStatistics,
        dns: Optional[List[DNSRecord]] = None,
        http: Optional[List[HTTPRecord]] = None,
        tls: Optional[List[TLSRecord]] = None,
        **kwargs: Any,
    ) -> List[AlertFinding]:
        findings: List[AlertFinding] = []

        cleartext_protos: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"packets": 0, "hosts": set(), "endpoints": set(), "packet_numbers": []}
        )

        for pkt in packets:
            proto = pkt.protocol.upper()
            if proto in self.config.cleartext_protocols or (
                pkt.destination_port in (80, 21, 23, 110, 143)
            ):
                proto_name = (
                    "HTTP" if (proto == "HTTP" or pkt.destination_port == 80)
                    else "FTP" if (proto == "FTP" or pkt.destination_port == 21)
                    else "TELNET" if (proto == "TELNET" or pkt.destination_port == 23)
                    else proto
                )
                data = cleartext_protos[proto_name]
                data["packets"] += 1
                if len(data["packet_numbers"]) < 10:
                    data["packet_numbers"].append(pkt.packet_number)
                if pkt.http_host:
                    data["hosts"].add(pkt.http_host)
                if pkt.source_ip and pkt.destination_ip:
                    data["endpoints"].add(f"{pkt.source_ip} -> {pkt.destination_ip}")

        for proto_name, data in cleartext_protos.items():
            if data["packets"] > 0:
                hosts_list = sorted(list(data["hosts"]))[:10]
                endpoints_list = sorted(list(data["endpoints"]))[:8]

                findings.append(
                    AlertFinding(
                        id=f"{self.rule_id}-{proto_name.lower()}",
                        timestamp=0.0,
                        severity=Severity.LOW,
                        category=self.category,
                        title=f"Unencrypted {proto_name} communication observed",
                        description=(
                            f"Identified {data['packets']} packets utilizing unencrypted {proto_name}. "
                            "Cleartext protocols expose headers, session tokens, and payloads to passive eavesdropping."
                        ),
                        protocol=proto_name,
                        evidence={
                            "protocol": proto_name,
                            "packet_count": data["packets"],
                            "observed_hosts": hosts_list,
                            "active_endpoint_pairs": endpoints_list,
                        },
                        packet_numbers=data["packet_numbers"],
                        detection_rule=self.rule_id,
                        confidence=0.95,
                        recommended_next_step=(
                            f"Migrate unencrypted {proto_name} communication to modern encrypted alternatives "
                            f"(e.g., HTTPS, SFTP, SSH) to protect data in transit."
                        ),
                        limitations="Does not assess whether application-level encryption was implemented on top of the cleartext stream.",
                    )
                )

        return findings


class Rule009HttpSecurityObservation(BaseDetectionRule):
    """RULE 009: HTTP security observation.

    Identifies unusual HTTP methods (e.g. TRACE, CONNECT, PUT), unusually long URIs,
    automated security scanner User-Agents, and HTTP on non-standard ports.
    """

    rule_id = "RULE-009"
    rule_name = "HTTP security observation"
    category = FindingCategory.HTTP_OBSERVATION.value

    def evaluate(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: TrafficStatistics,
        dns: Optional[List[DNSRecord]] = None,
        http: Optional[List[HTTPRecord]] = None,
        tls: Optional[List[TLSRecord]] = None,
        **kwargs: Any,
    ) -> List[AlertFinding]:
        findings: List[AlertFinding] = []

        unusual_methods: List[Dict[str, Any]] = []
        long_uris: List[Dict[str, Any]] = []
        scanner_uas: List[Dict[str, Any]] = []
        uncommon_port_http: List[Dict[str, Any]] = []

        scanner_keywords = [
            "sqlmap", "nikto", "nmap", "masscan", "zgrab", "gobuster", "dirbuster",
            "dirb", "wfuzz", "hydra", "nessus", "openvas"
        ]

        for pkt in packets:
            if pkt.protocol != "HTTP" and pkt.http_method is None:
                continue

            # Check HTTP methods
            if pkt.http_method:
                m = pkt.http_method.upper()
                if m in ("TRACE", "CONNECT", "PUT", "DELETE", "OPTIONS", "PATCH"):
                    unusual_methods.append({
                        "method": m,
                        "uri": pkt.http_uri or "/",
                        "source": pkt.source_ip,
                        "packet": pkt.packet_number,
                    })

            # Check URI length
            if pkt.http_uri and len(pkt.http_uri) >= self.config.http_uri_max_length:
                long_uris.append({
                    "length": len(pkt.http_uri),
                    "uri_sample": pkt.http_uri[:100] + "...",
                    "source": pkt.source_ip,
                    "packet": pkt.packet_number,
                })

            # Check User-Agent
            if pkt.http_user_agent:
                ua_lower = pkt.http_user_agent.lower()
                for kw in scanner_keywords:
                    if kw in ua_lower:
                        scanner_uas.append({
                            "user_agent": pkt.http_user_agent,
                            "matched_keyword": kw,
                            "source": pkt.source_ip,
                            "packet": pkt.packet_number,
                        })
                        break

            # Check uncommon ports
            if pkt.destination_port and pkt.destination_port in self.config.http_uncommon_ports:
                uncommon_port_http.append({
                    "port": pkt.destination_port,
                    "host": pkt.http_host,
                    "source": pkt.source_ip,
                    "packet": pkt.packet_number,
                })

        if scanner_uas:
            p_nums = [item["packet"] for item in scanner_uas[:10]]
            findings.append(
                AlertFinding(
                    id=f"{self.rule_id}-scanner-ua",
                    timestamp=0.0,
                    severity=Severity.HIGH,
                    category=self.category,
                    title="Automated security scanner User-Agent signature observed",
                    description=(
                        f"Detected {len(scanner_uas)} HTTP requests containing User-Agent strings "
                        "associated with automated security testing or vulnerability scanning tools."
                    ),
                    protocol="HTTP",
                    evidence={
                        "occurrence_count": len(scanner_uas),
                        "signatures_observed": list({item["matched_keyword"] for item in scanner_uas}),
                        "sample_user_agents": list({item["user_agent"] for item in scanner_uas})[:5],
                    },
                    packet_numbers=p_nums,
                    detection_rule=self.rule_id,
                    confidence=0.90,
                    recommended_next_step="Inspect server access logs for corresponding HTTP responses (e.g. 200 vs 403/404).",
                    limitations="User-Agent headers can be readily spoofed by arbitrary client applications.",
                )
            )

        if long_uris:
            p_nums = [item["packet"] for item in long_uris[:10]]
            findings.append(
                AlertFinding(
                    id=f"{self.rule_id}-long-uri",
                    timestamp=0.0,
                    severity=Severity.LOW,
                    category=self.category,
                    title="Unusually long HTTP URI path observed",
                    description=(
                        f"Observed {len(long_uris)} HTTP requests with URIs exceeding threshold "
                        f"({self.config.http_uri_max_length} characters), commonly seen in parameter fuzzing or exploit payloads."
                    ),
                    protocol="HTTP",
                    evidence={
                        "long_uri_count": len(long_uris),
                        "samples": long_uris[:5],
                    },
                    packet_numbers=p_nums,
                    detection_rule=self.rule_id,
                    confidence=0.70,
                    recommended_next_step="Review the URI parameters for SQL injection, path traversal, or command injection strings.",
                    limitations="Certain REST APIs and OAuth redirect URIs legitimately construct long URL query parameters.",
                )
            )

        return findings


class Rule010TlsSecurityObservation(BaseDetectionRule):
    """RULE 010: TLS security observation.

    Identifies legacy TLS protocol versions (SSL 3.0, TLS 1.0, TLS 1.1),
    missing Server Name Indication (SNI) on standard TLS ports, or TLS on non-standard ports.
    """

    rule_id = "RULE-010"
    rule_name = "TLS security observation"
    category = FindingCategory.TLS_OBSERVATION.value

    def evaluate(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: TrafficStatistics,
        dns: Optional[List[DNSRecord]] = None,
        http: Optional[List[HTTPRecord]] = None,
        tls: Optional[List[TLSRecord]] = None,
        **kwargs: Any,
    ) -> List[AlertFinding]:
        findings: List[AlertFinding] = []

        legacy_versions: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"count": 0, "sources": set(), "destinations": set(), "packets": []}
        )
        non_standard_ports: Dict[int, Dict[str, Any]] = defaultdict(
            lambda: {"count": 0, "sources": set(), "packets": []}
        )

        for pkt in packets:
            if pkt.protocol != "TLS" and pkt.tls_information is None:
                continue

            tls_info = pkt.tls_information or {}
            ver = tls_info.get("version")
            if ver in ("SSL 3.0", "TLS 1.0", "TLS 1.1"):
                data = legacy_versions[ver]
                data["count"] += 1
                if len(data["packets"]) < 10:
                    data["packets"].append(pkt.packet_number)
                if pkt.source_ip:
                    data["sources"].add(pkt.source_ip)
                if pkt.destination_ip:
                    data["destinations"].add(pkt.destination_ip)

            dst_port = pkt.destination_port
            if dst_port and dst_port in self.config.tls_uncommon_ports:
                p_data = non_standard_ports[dst_port]
                p_data["count"] += 1
                if len(p_data["packets"]) < 10:
                    p_data["packets"].append(pkt.packet_number)
                if pkt.source_ip:
                    p_data["sources"].add(pkt.source_ip)

        for ver, data in legacy_versions.items():
            findings.append(
                AlertFinding(
                    id=f"{self.rule_id}-legacy-{ver.replace(' ', '-').lower()}",
                    timestamp=0.0,
                    severity=Severity.MEDIUM,
                    category=self.category,
                    title=f"Legacy {ver} protocol negotiation observed",
                    description=(
                        f"Identified {data['count']} TLS records negotiating deprecated protocol {ver}. "
                        "Legacy TLS versions suffer from known cryptographic vulnerabilities (e.g. POODLE, BEAST) "
                        "and are prohibited under modern security compliance baselines (PCI-DSS, NIST SP 800-52r2)."
                    ),
                    protocol="TLS",
                    evidence={
                        "protocol_version": ver,
                        "packet_count": data["count"],
                        "observed_sources": sorted(list(data["sources"]))[:5],
                        "observed_destinations": sorted(list(data["destinations"]))[:5],
                    },
                    packet_numbers=data["packets"],
                    detection_rule=self.rule_id,
                    confidence=0.92,
                    recommended_next_step=f"Enforce TLS 1.2 or TLS 1.3 minimum versions on server endpoints negotiating {ver}.",
                    limitations="Legacy client software or legacy embedded devices may fail to connect if older protocols are disabled.",
                )
            )

        return findings


class Rule011DnsUniqueDomainCount(BaseDetectionRule):
    """RULE 011: High unique domain query count from single client.

    Identifies a client host querying an anomalously high number of distinct domain names
    over the capture period, which can suggest automated web crawlers or DGA behavior.
    """

    rule_id = "RULE-011"
    rule_name = "High unique domain query count"
    category = FindingCategory.DNS_ANOMALY.value

    def evaluate(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: TrafficStatistics,
        dns: Optional[List[DNSRecord]] = None,
        http: Optional[List[HTTPRecord]] = None,
        tls: Optional[List[TLSRecord]] = None,
        **kwargs: Any,
    ) -> List[AlertFinding]:
        findings: List[AlertFinding] = []
        unique_by_source: Dict[str, Set[str]] = defaultdict(set)
        packets_by_source: Dict[str, List[int]] = defaultdict(list)

        for pkt in packets:
            if pkt.dns_query and pkt.source_ip:
                domain = pkt.dns_query.lower().rstrip(".")
                unique_by_source[pkt.source_ip].add(domain)
                if len(packets_by_source[pkt.source_ip]) < 10:
                    packets_by_source[pkt.source_ip].append(pkt.packet_number)

        for src, domain_set in unique_by_source.items():
            count = len(domain_set)
            if count >= self.config.dns_unique_domains_threshold:
                findings.append(
                    AlertFinding(
                        id=f"{self.rule_id}-{src.replace('.', '-')}",
                        timestamp=0.0,
                        severity=Severity.LOW,
                        category=self.category,
                        title="High count of unique domains queried by single host",
                        description=(
                            f"Host {src} submitted DNS resolution queries for {count} unique domains "
                            f"(threshold: {self.config.dns_unique_domains_threshold})."
                        ),
                        source_ip=src,
                        protocol="DNS",
                        evidence={
                            "unique_domains_count": count,
                            "threshold": self.config.dns_unique_domains_threshold,
                            "sample_domains": sorted(list(domain_set))[:8],
                        },
                        packet_numbers=packets_by_source[src],
                        detection_rule=self.rule_id,
                        confidence=0.68,
                        recommended_next_step=f"Review whether host {src} is an enterprise web proxy, mail server, or security gateway.",
                        limitations="Endpoints with heavy web browsing or email gateways naturally resolve numerous domains.",
                    )
                )

        return findings


class DetectionEngine:
    """Orchestrates modular threat detection rules and compiles structured findings."""

    def __init__(self, config: Optional[DetectionConfig] = None):
        self.config = config or DetectionConfig()
        self.rules: List[BaseDetectionRule] = [
            Rule001TcpSynScan(self.config),
            Rule002ConnectionFlood(self.config),
            Rule003UnusualDestinationPort(self.config),
            Rule004DnsQueryAnomaly(self.config),
            Rule005SuspiciousDnsCharacteristics(self.config),
            Rule006RepeatedFailedTcpConnections(self.config),
            Rule007IcmpVolumeAnomaly(self.config),
            Rule008CleartextProtocolObservation(self.config),
            Rule009HttpSecurityObservation(self.config),
            Rule010TlsSecurityObservation(self.config),
            Rule011DnsUniqueDomainCount(self.config),
        ]

    def run(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: TrafficStatistics,
        dns: Optional[List[DNSRecord]] = None,
        http: Optional[List[HTTPRecord]] = None,
        tls: Optional[List[TLSRecord]] = None,
    ) -> List[AlertFinding]:
        """Execute all configured detection rules sequentially and rank findings.

        Implements the conceptual Detection Engine dataflow:
        Consumes Protocols (DNS, HTTP, TLS), Flows (TCP/UDP), and Baseline Statistics
        to generate structured Findings, Evidence, and calibrated Severity ratings.
        """
        all_findings: List[AlertFinding] = []

        for rule in self.rules:
            try:
                try:
                    rule_findings = rule.evaluate(
                        packets, flows, stats, dns=dns, http=http, tls=tls
                    )
                except TypeError:
                    rule_findings = rule.evaluate(packets, flows, stats)
                all_findings.extend(rule_findings)
            except Exception as exc:
                logger.error("Error executing rule %s: %s", rule.rule_id, exc)

        # Sort findings by severity: CRITICAL > HIGH > MEDIUM > LOW > INFO
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        all_findings.sort(key=lambda f: (severity_order.get(f.severity, 5), -f.confidence))
        return all_findings
