"""Dedicated HTTP protocol analyzer and security profiler.

Analyzes cleartext web transactions, inspects User-Agent fingerprints,
monitors URI lengths, and flags protocol deviations.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import logging
from typing import Any, Dict, List, Optional, Tuple

from .models import HTTPRecord, PacketRecord

logger = logging.getLogger(__name__)

# User-agent strings commonly affiliated with automated vulnerability scanners or bots
SUSPICIOUS_UA_PATTERNS = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "zgrab",
    "gobuster",
    "dirbuster",
    "dirb",
    "wfuzz",
    "hydra",
    "curl",
    "python-requests",
    "python-urllib",
    "go-http-client",
    "nessus",
    "openvas",
]


class HTTPAnalyzer:
    """Performs deep inspection of unencrypted HTTP transactions."""

    def __init__(self):
        self.records: List[HTTPRecord] = []
        self.methods: Counter[str] = Counter()
        self.hosts: Counter[str] = Counter()
        self.uris: Counter[str] = Counter()
        self.user_agents: Counter[str] = Counter()
        self.status_codes: Counter[int] = Counter()
        self.content_types: Counter[str] = Counter()
        self.destination_ports: Counter[int] = Counter()
        self.first_seen: Optional[float] = None
        self.last_seen: Optional[float] = None

    def process_packet(self, pkt: PacketRecord) -> Optional[HTTPRecord]:
        """Inspect packet for HTTP data and update HTTP metrics.

        Returns:
            Extracted HTTPRecord if packet contains HTTP data, else None.
        """
        if (
            pkt.protocol != "HTTP"
            and pkt.http_host is None
            and pkt.http_method is None
            and pkt.http_status_code is None
        ):
            return None

        ts = pkt.timestamp
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts

        rec = HTTPRecord(
            timestamp=pkt.timestamp,
            packet_number=pkt.packet_number,
            source_ip=pkt.source_ip,
            destination_ip=pkt.destination_ip,
            source_port=pkt.source_port,
            destination_port=pkt.destination_port,
            method=pkt.http_method,
            host=pkt.http_host,
            uri=pkt.http_uri,
            user_agent=pkt.http_user_agent,
            status_code=pkt.http_status_code,
            content_type=pkt.http_content_type,
        )

        self.records.append(rec)

        if pkt.http_method:
            self.methods[pkt.http_method.upper()] += 1
        if pkt.http_host:
            self.hosts[pkt.http_host.lower()] += 1
        if pkt.http_uri:
            self.uris[pkt.http_uri] += 1
        if pkt.http_user_agent:
            self.user_agents[pkt.http_user_agent] += 1
        if pkt.http_status_code is not None:
            self.status_codes[pkt.http_status_code] += 1
        if pkt.http_content_type:
            self.content_types[pkt.http_content_type.split(";")[0].strip()] += 1
        if pkt.destination_port:
            self.destination_ports[pkt.destination_port] += 1

        return rec

    @property
    def total_transactions(self) -> int:
        return len(self.records)

    @property
    def total_records(self) -> int:
        return len(self.records)

    def get_suspicious_user_agents(self) -> List[Tuple[str, int, str]]:
        """Identify user agents matching scanner or automated tool signatures.

        Returns:
            List of (user_agent, occurrence_count, matched_pattern)
        """
        results: List[Tuple[str, int, str]] = []
        for ua, count in self.user_agents.items():
            ua_lower = ua.lower()
            for pattern in SUSPICIOUS_UA_PATTERNS:
                if pattern in ua_lower:
                    results.append((ua, count, pattern))
                    break
        return results

    def get_longest_uris(self, limit: int = 5) -> List[Tuple[str, int, int]]:
        """Identify unusually long URIs: (uri, length, count)."""
        sorted_uris = sorted(self.uris.items(), key=lambda x: len(x[0]), reverse=True)
        return [(uri, len(uri), count) for uri, count in sorted_uris[:limit]]

    def get_summary_dict(self) -> Dict[str, Any]:
        """Provide structured summary for SIEM/JSON export."""
        return {
            "total_records": len(self.records),
            "unique_hosts": len(self.hosts),
            "methods": dict(self.methods.most_common()),
            "status_codes": dict(self.status_codes.most_common()),
            "content_types": dict(self.content_types.most_common(5)),
            "top_hosts": [{"host": h, "count": c} for h, c in self.hosts.most_common(10)],
            "user_agents_count": len(self.user_agents),
            "sample_user_agents": [ua for ua, _ in self.user_agents.most_common(5)],
        }
