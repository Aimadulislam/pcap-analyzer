"""Dedicated TLS metadata analyzer and encryption posture evaluator.

Extracts ClientHello Server Name Indication (SNI), tracks TLS protocol versions,
inspects cipher suite offerings, and flags legacy or insecure protocol usage without decryption.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import logging
from typing import Any, Dict, List, Optional, Tuple

from .models import PacketRecord, TLSRecord

logger = logging.getLogger(__name__)

LEGACY_VERSIONS = {"SSL 3.0", "TLS 1.0", "TLS 1.1"}
STANDARD_TLS_PORTS = {443, 8443, 9443, 4433}


class TLSAnalyzer:
    """Extracts and evaluates unencrypted TLS handshake metadata."""

    def __init__(self):
        self.records: List[TLSRecord] = []
        self.versions: Counter[str] = Counter()
        self.server_names: Counter[str] = Counter()
        self.handshake_types: Counter[str] = Counter()
        self.destination_ports: Counter[int] = Counter()
        self.ciphers: Counter[str] = Counter()
        self.first_seen: Optional[float] = None
        self.last_seen: Optional[float] = None

    def process_packet(self, pkt: PacketRecord) -> Optional[TLSRecord]:
        """Inspect packet for TLS handshake records.

        Returns:
            Extracted TLSRecord if packet contains TLS metadata, else None.
        """
        if pkt.protocol != "TLS" and pkt.tls_information is None:
            return None

        ts = pkt.timestamp
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts

        tls_data = pkt.tls_information or {}
        ver = tls_data.get("version")
        sni = tls_data.get("sni")
        hs_type = tls_data.get("handshake_type")
        cipher = tls_data.get("cipher")

        rec = TLSRecord(
            timestamp=pkt.timestamp,
            packet_number=pkt.packet_number,
            source_ip=pkt.source_ip,
            destination_ip=pkt.destination_ip,
            source_port=pkt.source_port,
            destination_port=pkt.destination_port,
            version=ver,
            server_name=sni,
            cipher=cipher,
            handshake_type=hs_type,
        )

        self.records.append(rec)

        if ver:
            self.versions[ver] += 1
        if sni:
            self.server_names[sni.lower()] += 1
        if hs_type:
            self.handshake_types[hs_type] += 1
        if cipher:
            self.ciphers[cipher] += 1
        if pkt.destination_port:
            self.destination_ports[pkt.destination_port] += 1

        return rec

    @property
    def total_records(self) -> int:
        return len(self.records)

    def get_legacy_versions(self) -> List[Tuple[str, int]]:
        """Identify deprecated or insecure TLS/SSL protocol versions in use."""
        return [(v, c) for v, c in self.versions.items() if v in LEGACY_VERSIONS]

    def get_non_standard_ports(self) -> List[Tuple[int, int]]:
        """Identify TLS traffic communicating over non-standard TLS ports."""
        return [(port, count) for port, count in self.destination_ports.items() if port not in STANDARD_TLS_PORTS]

    def get_summary_dict(self) -> Dict[str, Any]:
        """Provide structured summary for SIEM/JSON export."""
        return {
            "total_records": len(self.records),
            "versions": dict(self.versions.most_common()),
            "handshake_types": dict(self.handshake_types.most_common()),
            "top_server_names": [{"sni": s, "count": c} for s, c in self.server_names.most_common(10)],
            "ciphers_observed": dict(self.ciphers.most_common(5)),
            "ports_distribution": dict(self.destination_ports.most_common(5)),
        }
