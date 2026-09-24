"""Data models for the Automated PCAP Analyzer and Threat Parser.

Defines structured dataclasses for packets, flows, findings, protocol records,
IOC records, metadata, and comprehensive analysis results.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
import json
from typing import Any, Dict, List, Optional, Union


class Severity(str, Enum):
    """Alert severity levels adhering to industry standard SOC taxonomy."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingCategory(str, Enum):
    """Categorization for security observations and alert findings."""
    RECONNAISSANCE = "Reconnaissance"
    TRAFFIC_ANOMALY = "Traffic Anomaly"
    SECURITY_OBSERVATION = "Security Observation"
    CLEARTEXT_COMMUNICATION = "Cleartext Communication"
    CONNECTION_ANOMALY = "Connection Anomaly"
    DNS_ANOMALY = "DNS Anomaly"
    TLS_OBSERVATION = "TLS Security Observation"
    HTTP_OBSERVATION = "HTTP Security Observation"


@dataclass
class PacketRecord:
    """Structured representation of a parsed network packet."""
    packet_number: int
    timestamp: float
    packet_length: int
    protocol: str
    transport_protocol: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    flags: Optional[Dict[str, bool]] = None
    dns_query: Optional[str] = None
    dns_response: Optional[str] = None
    dns_query_type: Optional[str] = None
    dns_answers: Optional[List[str]] = None
    dns_rcode: Optional[Union[int, str]] = None
    dns_tx_id: Optional[int] = None
    http_host: Optional[str] = None
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    http_status_code: Optional[int] = None
    http_user_agent: Optional[str] = None
    http_content_type: Optional[str] = None
    tls_information: Optional[Dict[str, Any]] = None
    payload_length: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert the packet record to a dictionary."""
        return asdict(self)


@dataclass
class DNSRecord:
    """Structured DNS transaction record."""
    timestamp: float
    packet_number: int
    source_ip: Optional[str]
    destination_ip: Optional[str]
    query: Optional[str]
    query_type: Optional[str]
    response_code: Optional[Union[int, str]] = None
    answers: List[str] = field(default_factory=list)
    is_response: bool = False
    transaction_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert DNS record to dictionary."""
        return asdict(self)


@dataclass
class HTTPRecord:
    """Structured HTTP transaction record."""
    timestamp: float
    packet_number: int
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    method: Optional[str] = None
    host: Optional[str] = None
    uri: Optional[str] = None
    user_agent: Optional[str] = None
    status_code: Optional[int] = None
    content_type: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert HTTP record to dictionary."""
        return asdict(self)


@dataclass
class TLSRecord:
    """Structured TLS metadata record."""
    timestamp: float
    packet_number: int
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    version: Optional[str] = None
    server_name: Optional[str] = None  # SNI
    cipher: Optional[str] = None
    handshake_type: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert TLS record to dictionary."""
        return asdict(self)


@dataclass
class IOCRecord:
    """Structured observable Indicator of Compromise (IOC) record."""
    type: str  # IPv4, IPv6, domain, hostname, URL, email, hash
    value: str
    source: str  # DNS, HTTP, TLS, IP, Payload
    first_seen: float
    last_seen: float
    packet_count: int
    context: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert IOC record to dictionary."""
        return asdict(self)


@dataclass
class FlowRecord:
    """Unidirectional or bidirectional communication flow between two endpoints."""
    flow_id: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str
    packet_count: int = 0
    byte_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    duration_seconds: float = 0.0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    syn_count: int = 0
    syn_ack_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    completed_handshake: bool = False
    classification: str = "normal TCP session"

    def to_dict(self) -> Dict[str, Any]:
        """Convert the flow record to a dictionary."""
        return asdict(self)


@dataclass
class AlertFinding:
    """Security finding or observation produced by the threat detection engine.

    Includes full deterministic evidence and explains the exact heuristic
    or rule that triggered without making unsupported assertions of malware.
    """
    finding_id: str
    rule_id: str
    timestamp: float
    severity: Severity
    confidence: float
    title: str
    category: str
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    evidence: Union[List[str], Dict[str, Any]] = field(default_factory=dict)
    packet_numbers: List[int] = field(default_factory=list)
    recommended_next_step: str = ""
    limitations: str = ""

    def __init__(
        self,
        finding_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        timestamp: float = 0.0,
        severity: Severity = Severity.LOW,
        confidence: float = 0.5,
        title: str = "",
        category: str = "",
        description: str = "",
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        source_port: Optional[int] = None,
        destination_port: Optional[int] = None,
        protocol: Optional[str] = None,
        evidence: Optional[Union[List[str], Dict[str, Any]]] = None,
        packet_numbers: Optional[List[int]] = None,
        recommended_next_step: str = "",
        limitations: str = "",
        # Backwards compatibility kwargs:
        id: Optional[str] = None,
        detection_rule: Optional[str] = None,
        **kwargs: Any,
    ):
        self.finding_id = finding_id or id or "F-0000"
        self.rule_id = rule_id or detection_rule or "RULE-000"
        self.timestamp = timestamp
        self.severity = severity if isinstance(severity, Severity) else Severity(str(severity))
        self.confidence = round(confidence, 4)
        self.title = title
        self.category = category
        self.description = description
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.source_port = source_port
        self.destination_port = destination_port
        self.protocol = protocol
        self.evidence = evidence if evidence is not None else {}
        self.packet_numbers = packet_numbers or []
        self.recommended_next_step = recommended_next_step
        self.limitations = limitations

    @property
    def id(self) -> str:
        """Backwards compatibility accessor for finding ID."""
        return self.finding_id

    @id.setter
    def id(self, val: str) -> None:
        self.finding_id = val

    @property
    def detection_rule(self) -> str:
        """Backwards compatibility accessor for rule ID."""
        return self.rule_id

    @detection_rule.setter
    def detection_rule(self, val: str) -> None:
        self.rule_id = val

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert finding to a dictionary representation matching schema."""
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "timestamp": self.timestamp,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "title": self.title,
            "category": self.category,
            "description": self.description,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "evidence": self.evidence,
            "packet_numbers": self.packet_numbers,
            "recommended_next_step": self.recommended_next_step,
            "limitations": self.limitations,
            # Legacy keys for compatibility:
            "id": self.finding_id,
            "detection_rule": self.rule_id,
        }


@dataclass
class CaptureMetadata:
    """Metadata describing the analyzed capture file and its cryptographic integrity."""
    file_path: str
    file_name: str
    file_size_bytes: int
    file_format: str
    packet_count: int
    first_timestamp: Optional[float] = None
    last_timestamp: Optional[float] = None
    duration_seconds: float = 0.0
    parser_engine: str = "Native"
    sha256_hash: str = ""
    analysis_timestamp: str = ""
    analyzer_version: str = "2.0.0"
    profile_name: str = "default"
    profile_source: str = "built-in"

    def to_dict(self) -> Dict[str, Any]:
        """Convert capture metadata to a dictionary."""
        return asdict(self)


@dataclass
class TrafficStatistics:
    """Aggregated traffic metrics computed from parsed packets."""
    total_packets: int = 0
    total_bytes: int = 0
    capture_duration: float = 0.0
    unique_source_ips: int = 0
    unique_destination_ips: int = 0
    unique_conversations: int = 0
    tcp_packet_count: int = 0
    udp_packet_count: int = 0
    icmp_packet_count: int = 0
    dns_packet_count: int = 0
    http_packet_count: int = 0
    tls_packet_count: int = 0
    total_syn_packets: int = 0
    completed_handshakes: int = 0
    incomplete_handshakes: int = 0
    total_resets: int = 0
    protocol_distribution: Dict[str, int] = field(default_factory=dict)
    protocol_bytes: Dict[str, int] = field(default_factory=dict)
    top_source_ips: List[Dict[str, Any]] = field(default_factory=list)
    top_destination_ips: List[Dict[str, Any]] = field(default_factory=list)
    top_destination_ports: List[Dict[str, Any]] = field(default_factory=list)
    tcp_flags_distribution: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert traffic statistics to a dictionary."""
        return asdict(self)


@dataclass
class AnalysisResult:
    """Complete analysis output containing metadata, stats, flows, findings, and errors."""
    metadata: CaptureMetadata
    summary: TrafficStatistics
    protocols: Dict[str, int]
    top_sources: List[Dict[str, Any]]
    top_destinations: List[Dict[str, Any]]
    flows: List[FlowRecord]
    dns: List[Dict[str, Any]]
    http: List[Dict[str, Any]]
    tls: List[Dict[str, Any]]
    findings: List[AlertFinding]
    errors: List[str]
    iocs: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    configuration: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis result into structured JSON-serializable dictionary matching Section 31 schema."""
        dns_summary = {
            "total_queries": len(self.dns),
            "records": self.dns[:100],  # sample records for clean json
        }
        http_summary = {
            "total_transactions": len(self.http),
            "records": self.http[:100],
        }
        tls_summary = {
            "total_records": len(self.tls),
            "records": self.tls[:100],
        }
        integrity = {
            "sha256": self.metadata.sha256_hash,
            "file_name": self.metadata.file_name,
            "file_size_bytes": self.metadata.file_size_bytes,
        }
        return {
            "metadata": self.metadata.to_dict(),
            "integrity": integrity,
            "configuration": self.configuration,
            "summary": self.summary.to_dict(),
            "protocols": self.protocols,
            "top_sources": self.top_sources,
            "top_destinations": self.top_destinations,
            "flows": [f.to_dict() for f in self.flows],
            "dns": dns_summary,
            "http": http_summary,
            "tls": tls_summary,
            "iocs": self.iocs,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }

    def to_json(self, indent: int = 2) -> str:
        """Produce formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)
