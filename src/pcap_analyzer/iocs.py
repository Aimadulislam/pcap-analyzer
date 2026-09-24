"""Observable Indicator of Compromise (IOC) extraction and correlation engine.

Extracts observable network indicators (IP addresses, domain names, hostnames,
URLs, email addresses, explicit hashes) present in packet headers and payloads.
Deduplicates occurrences and records forensic telemetry timestamps.
"""

from __future__ import annotations

from collections import defaultdict
import ipaddress
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Union

from .models import IOCRecord, PacketRecord


# Regular expressions for explicit observable artifacts in cleartext payloads
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")


class IOCExtractor:
    """Extracts, deduplicates, and classifies network indicators from analyzed packets."""

    def __init__(self):
        # Key: (ioc_type, value) -> metadata dict
        self._indicators: Dict[tuple[str, str], Dict[str, Any]] = {}

    def _record(
        self,
        ioc_type: str,
        value: str,
        source: str,
        timestamp: float,
        packet_number: int,
        context: Optional[str] = None,
    ) -> None:
        """Add or update an extracted IOC."""
        val = value.strip()
        if not val:
            return

        key = (ioc_type, val)
        if key not in self._indicators:
            self._indicators[key] = {
                "type": ioc_type,
                "value": val,
                "source": source,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "packet_count": 0,
                "packet_numbers": set(),
                "contexts": set(),
            }

        item = self._indicators[key]
        item["packet_count"] += 1
        item["first_seen"] = min(item["first_seen"], timestamp)
        item["last_seen"] = max(item["last_seen"], timestamp)
        if len(item["packet_numbers"]) < 20:
            item["packet_numbers"].add(packet_number)
        if context:
            item["contexts"].add(context)

    def process_packet(self, pkt: PacketRecord) -> None:
        """Extract observable indicators from an incoming packet record."""
        ts = pkt.timestamp
        pnum = pkt.packet_number

        # 1. IP Addresses
        for ip_str in (pkt.source_ip, pkt.destination_ip):
            if not ip_str:
                continue
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.is_unspecified or ip_obj.is_multicast or ip_str == "255.255.255.255":
                    continue
                ioc_type = "IPv6" if ip_obj.version == 6 else "IPv4"
                scope = "Private/Internal" if ip_obj.is_private else "Public/External"
                self._record(ioc_type, ip_str, f"IP Header ({scope})", ts, pnum)
            except ValueError:
                pass

        # 2. Domains & Hostnames from DNS
        if pkt.dns_query:
            domain = pkt.dns_query.lower().rstrip(".")
            if domain and "." in domain:
                self._record("domain", domain, "DNS Query", ts, pnum, f"Type {pkt.dns_query_type or 'A'}")
            elif domain:
                self._record("hostname", domain, "DNS Query", ts, pnum)

        if pkt.dns_answers:
            for ans in pkt.dns_answers:
                try:
                    ip_obj = ipaddress.ip_address(ans)
                    if not ip_obj.is_unspecified:
                        ioc_type = "IPv6" if ip_obj.version == 6 else "IPv4"
                        self._record(ioc_type, ans, "DNS Answer", ts, pnum)
                except ValueError:
                    if "." in ans:
                        self._record("domain", ans.lower().rstrip("."), "DNS Answer CNAME/PTR", ts, pnum)

        # 3. HTTP Host, URL, and User-Agent
        if pkt.http_host:
            host = pkt.http_host.lower().strip()
            # Split off port if present
            host_clean = host.split(":")[0]
            if "." in host_clean:
                self._record("domain", host_clean, "HTTP Host Header", ts, pnum)
            else:
                self._record("hostname", host_clean, "HTTP Host Header", ts, pnum)

            if pkt.http_uri:
                url = f"http://{host}{pkt.http_uri}"
                self._record("url", url, "HTTP Request", ts, pnum, pkt.http_method or "GET")

        # 4. TLS SNI
        if pkt.tls_information:
            sni = pkt.tls_information.get("sni")
            if sni:
                sni_clean = sni.lower().strip()
                if "." in sni_clean:
                    self._record("domain", sni_clean, "TLS ClientHello SNI", ts, pnum)
                else:
                    self._record("hostname", sni_clean, "TLS ClientHello SNI", ts, pnum)

        # 5. Cleartext Payload Regex Extraction (Emails and Hashes)
        # Check HTTP URI or payload strings if available
        candidates = []
        if pkt.http_uri:
            candidates.append(pkt.http_uri)
        if pkt.http_user_agent:
            candidates.append(pkt.http_user_agent)

        for text in candidates:
            for email in EMAIL_REGEX.findall(text):
                self._record("email", email.lower(), "HTTP Header/URI", ts, pnum)
            for h in SHA256_REGEX.findall(text):
                self._record("hash", h.lower(), "HTTP Param (SHA-256)", ts, pnum)
            for h in MD5_REGEX.findall(text):
                # Avoid capturing purely decimal strings or common words
                if not h.isdigit() and any(c in "abcdef" for c in h.lower()):
                    self._record("hash", h.lower(), "HTTP Param (MD5)", ts, pnum)

    def get_all_records(self) -> List[IOCRecord]:
        """Convert extracted items into structured IOCRecord objects."""
        records: List[IOCRecord] = []
        for (ioc_type, val), data in self._indicators.items():
            records.append(
                IOCRecord(
                    type=ioc_type,
                    value=val,
                    source=data["source"],
                    first_seen=round(data["first_seen"], 3),
                    last_seen=round(data["last_seen"], 3),
                    packet_count=data["packet_count"],
                    context={
                        "sample_packets": sorted(list(data["packet_numbers"]))[:10],
                        "contexts": sorted(list(data["contexts"])),
                    },
                )
            )
        records.sort(key=lambda r: (r.type, -r.packet_count))
        return records

    def export_dict(self) -> Dict[str, List[Dict[str, Any]]]:
        """Produce structured categorized IOC dictionary matching Section 11 schema."""
        categorized: Dict[str, List[Dict[str, Any]]] = {
            "ips": [],
            "domains": [],
            "urls": [],
            "hostnames": [],
            "emails": [],
            "hashes": [],
        }

        for rec in self.get_all_records():
            rec_dict = rec.to_dict()
            t = rec.type.lower()
            if t in ("ipv4", "ipv6"):
                categorized["ips"].append(rec_dict)
            elif t == "domain":
                categorized["domains"].append(rec_dict)
            elif t == "url":
                categorized["urls"].append(rec_dict)
            elif t == "hostname":
                categorized["hostnames"].append(rec_dict)
            elif t == "email":
                categorized["emails"].append(rec_dict)
            elif t == "hash":
                categorized["hashes"].append(rec_dict)

        return categorized

    def save_json(self, output_path: Union[str, Path], indent: int = 2) -> None:
        """Write extracted indicators to JSON file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self.export_dict(), f, indent=indent)
