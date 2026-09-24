"""Dedicated DNS protocol analyzer and anomaly profiler.

Extracts structured DNS transactions, computes label-level Shannon entropy,
tracks resolver utilization, and identifies potential protocol anomalies.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import DNSRecord, PacketRecord
from .utils import calculate_shannon_entropy

logger = logging.getLogger(__name__)


class DNSAnalyzer:
    """Performs in-depth DNS traffic inspection, resolution tracking, and heuristic profiling."""

    def __init__(self):
        self.records: List[DNSRecord] = []
        self.queries_by_source: Dict[str, List[DNSRecord]] = defaultdict(list)
        self.domain_counter: Counter[str] = Counter()
        self.query_type_counter: Counter[str] = Counter()
        self.response_code_counter: Counter[str] = Counter()
        self.resolved_ips: Counter[str] = Counter()
        self.dns_servers: Set[str] = set()
        self.dns_clients: Set[str] = set()
        self.client_to_servers: Dict[str, Set[str]] = defaultdict(set)
        self.transaction_ids: Set[int] = set()
        self.first_seen: Optional[float] = None
        self.last_seen: Optional[float] = None

    def process_packet(self, pkt: PacketRecord) -> Optional[DNSRecord]:
        """Inspect packet for DNS data and update DNS metrics.

        Returns:
            Extracted DNSRecord if packet contains DNS, else None.
        """
        if pkt.protocol != "DNS" and pkt.dns_query is None and pkt.dns_response is None:
            return None

        ts = pkt.timestamp
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts

        is_resp = bool(pkt.dns_response or (pkt.dns_answers and len(pkt.dns_answers) > 0))
        qtype = pkt.dns_query_type or "A"

        rec = DNSRecord(
            timestamp=pkt.timestamp,
            packet_number=pkt.packet_number,
            source_ip=pkt.source_ip,
            destination_ip=pkt.destination_ip,
            query=pkt.dns_query,
            query_type=qtype,
            response_code=pkt.dns_rcode,
            answers=pkt.dns_answers or [],
            is_response=is_resp,
            transaction_id=pkt.dns_tx_id,
        )

        self.records.append(rec)

        if pkt.source_ip:
            self.queries_by_source[pkt.source_ip].append(rec)

        if pkt.dns_query:
            domain_clean = pkt.dns_query.lower().rstrip(".")
            self.domain_counter[domain_clean] += 1

        if pkt.dns_query_type:
            self.query_type_counter[pkt.dns_query_type.upper()] += 1

        if pkt.dns_rcode is not None:
            self.response_code_counter[str(pkt.dns_rcode)] += 1

        if pkt.dns_tx_id is not None:
            self.transaction_ids.add(pkt.dns_tx_id)

        if pkt.dns_answers:
            for ans in pkt.dns_answers:
                # If looks like IPv4 or IPv6, record resolved IP
                if "." in ans or ":" in ans:
                    self.resolved_ips[ans] += 1

        # Track servers vs clients
        if is_resp:
            if pkt.source_ip:
                self.dns_servers.add(pkt.source_ip)
            if pkt.destination_ip:
                self.dns_clients.add(pkt.destination_ip)
                if pkt.source_ip:
                    self.client_to_servers[pkt.destination_ip].add(pkt.source_ip)
        else:
            if pkt.destination_ip:
                self.dns_servers.add(pkt.destination_ip)
            if pkt.source_ip:
                self.dns_clients.add(pkt.source_ip)
                if pkt.destination_ip:
                    self.client_to_servers[pkt.source_ip].add(pkt.destination_ip)

        return rec

    @property
    def total_queries(self) -> int:
        return len(self.records)

    @property
    def unique_domains_count(self) -> int:
        return len(self.domain_counter)

    def get_longest_queries(self, limit: int = 10) -> List[Tuple[str, int, int]]:
        """Return domains sorted by string length: (domain, length, count)."""
        sorted_by_len = sorted(self.domain_counter.items(), key=lambda item: len(item[0]), reverse=True)
        return [(domain, len(domain), count) for domain, count in sorted_by_len[:limit]]

    def get_high_entropy_labels(self, threshold: float = 3.85, min_length: int = 10) -> List[Dict[str, Any]]:
        """Calculate Shannon entropy for domain labels and return those exceeding threshold."""
        flagged: List[Dict[str, Any]] = []
        for domain, count in self.domain_counter.items():
            labels = domain.split(".")
            for label in labels:
                if len(label) >= min_length:
                    ent = calculate_shannon_entropy(label)
                    if ent >= threshold:
                        flagged.append({
                            "domain": domain,
                            "label": label,
                            "label_length": len(label),
                            "entropy": round(ent, 3),
                            "occurrence_count": count,
                        })
                        break
        flagged.sort(key=lambda x: x["entropy"], reverse=True)
        return flagged

    def get_summary_dict(self) -> Dict[str, Any]:
        """Provide structured summary for SIEM/JSON export."""
        duration = (self.last_seen - self.first_seen) if (self.first_seen and self.last_seen) else 0.0
        qps = (len(self.records) / duration) if duration > 0 else 0.0

        top_domains = [
            {"domain": d, "count": c} for d, c in self.domain_counter.most_common(10)
        ]
        top_types = dict(self.query_type_counter.most_common(10))
        rcodes = dict(self.response_code_counter.most_common(10))

        return {
            "total_records": len(self.records),
            "total_queries": len(self.records),
            "unique_domains": len(self.domain_counter),
            "unique_dns_servers": sorted(list(self.dns_servers)),
            "query_types": top_types,
            "response_codes": rcodes,
            "queries_per_second": round(qps, 2),
            "top_domains": top_domains,
            "sample_resolved_ips": [ip for ip, _ in self.resolved_ips.most_common(10)],
        }
