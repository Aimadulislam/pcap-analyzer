"""Reporting engine for PCAP Analyzer.

Generates:
- Structured, machine-readable JSON matching the SIEM/pipeline schema.
- Comprehensive defensive cybersecurity investigation report suitable for SOC documentation.
- Formatted text report artifacts with SHA-256 integrity verification.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Union

from .models import AnalysisResult, Severity
from .utils import format_bytes, format_duration, format_timestamp_iso, get_port_service_name


class JsonReporter:
    """Produces standardized JSON output for machine consumption."""

    @staticmethod
    def generate(result: AnalysisResult, indent: int = 2) -> str:
        """Produce JSON string from AnalysisResult."""
        return result.to_json(indent=indent)

    @staticmethod
    def save(result: AnalysisResult, output_path: Union[str, Path], indent: int = 2) -> None:
        """Write JSON output to filesystem."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            f.write(result.to_json(indent=indent))


class TextReporter:
    """Generates a formal defensive cybersecurity investigation report."""

    @staticmethod
    def generate(result: AnalysisResult) -> str:
        meta = result.metadata
        summary = result.summary
        findings = result.findings
        errors = result.errors
        iocs = result.iocs

        lines: list[str] = []

        def header(title: str, level: int = 1) -> None:
            if level == 1:
                lines.append("")
                lines.append("=" * 78)
                lines.append(f" {title}")
                lines.append("=" * 78)
            elif level == 2:
                lines.append("")
                lines.append(f"--- {title} " + "-" * max(2, 70 - len(title)))

        # Title Banner
        lines.append("=" * 78)
        lines.append("      PCAP THREAT ANALYSIS & NETWORK FORENSICS REPORT")
        lines.append("      Automated Python PCAP Analyzer & Threat Parser (Stage 2)")
        lines.append("=" * 78)

        # 1. Analysis Overview
        header("1. Analysis Overview (Executive Summary)")
        crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == Severity.LOW)
        info_count = sum(1 for f in findings if f.severity == Severity.INFO)

        lines.append(f"Target Capture:     {meta.file_name}")
        lines.append(f"Analysis Profile:   {meta.profile_name} [{meta.profile_source}]")
        lines.append(f"Total Packets:      {meta.packet_count:,}")
        lines.append(f"Capture Duration:   {format_duration(meta.duration_seconds)}")
        lines.append(f"Total Findings:     {len(findings)}")
        lines.append(f"Threat Posture:     CRITICAL: {crit_count} | HIGH: {high_count} | MEDIUM: {med_count} | LOW: {low_count} | INFO: {info_count}")

        # 2. Capture Metadata
        header("2. Capture Metadata & Integrity Manifest")
        lines.append(f"File Path:          {meta.file_path}")
        lines.append(f"File Size:          {format_bytes(meta.file_size_bytes)} ({meta.file_size_bytes:,} bytes)")
        lines.append(f"SHA-256 Hash:       {meta.sha256_hash or 'Not calculated'}")
        lines.append(f"Capture Format:     {meta.file_format}")
        lines.append(f"Analyzer Engine:    {meta.parser_engine} v{meta.analyzer_version}")
        lines.append(f"Analysis Timestamp: {meta.analysis_timestamp or 'N/A'}")
        lines.append(f"First Packet Time:  {format_timestamp_iso(meta.first_timestamp)}")
        lines.append(f"Last Packet Time:   {format_timestamp_iso(meta.last_timestamp)}")

        # 3. Traffic Statistics
        header("3. Traffic Statistics & Volume")
        lines.append(f"Total Data Volume:  {format_bytes(summary.total_bytes)} ({summary.total_bytes:,} bytes)")
        avg_pkt_size = (summary.total_bytes / summary.total_packets) if summary.total_packets else 0
        lines.append(f"Average Packet:     {avg_pkt_size:.1f} bytes")
        lines.append(f"Unique Endpoints:   {summary.unique_source_ips} Source IPs | {summary.unique_destination_ips} Destination IPs")
        lines.append(f"Active Flows:       {summary.unique_conversations} distinct conversations")
        lines.append(f"TCP Handshakes:     {summary.completed_handshakes} Completed | {summary.incomplete_handshakes} Incomplete | {summary.total_resets} Resets")

        # 4. Protocol Distribution
        header("4. Protocol Distribution")
        lines.append(f"{'Protocol':<15} {'Packets':<12} {'Percentage':<12} {'Bytes':<15}")
        lines.append("-" * 60)
        sorted_protos = sorted(result.protocols.items(), key=lambda x: x[1], reverse=True)
        for proto, count in sorted_protos:
            pct = (count / summary.total_packets * 100.0) if summary.total_packets else 0.0
            byte_val = summary.protocol_bytes.get(proto, 0)
            lines.append(f"{proto:<15} {count:<12,d} {pct:>6.2f}%      {format_bytes(byte_val):<15}")

        # 5. Top Talkers
        header("5. Top Talkers")
        lines.append("Top Transmitting Sources:")
        lines.append(f"  {'Source IP':<22} {'Packets':<12} {'Traffic Volume':<15} {'Share':<10}")
        lines.append("  " + "-" * 62)
        for src in result.top_sources[:6]:
            lines.append(f"  {src['ip']:<22} {src['packet_count']:<12,d} {format_bytes(src['byte_count']):<15} {src['percentage']:>5.2f}%")

        lines.append("")
        lines.append("Top Destination Endpoints:")
        lines.append(f"  {'Destination IP':<22} {'Packets':<12} {'Traffic Volume':<15} {'Share':<10}")
        lines.append("  " + "-" * 62)
        for dst in result.top_destinations[:6]:
            lines.append(f"  {dst['ip']:<22} {dst['packet_count']:<12,d} {format_bytes(dst['byte_count']):<15} {dst['percentage']:>5.2f}%")

        # 6. Top Conversations
        header("6. Top Conversations (Flow Matrix)")
        lines.append(f"  {'Flow Identifier':<42} {'Pkts':<7} {'Rate':<10} {'Classification':<20}")
        lines.append("  " + "-" * 82)
        for flow in result.flows[:8]:
            flow_display = flow.flow_id if len(flow.flow_id) <= 41 else flow.flow_id[:38] + "..."
            rate_str = f"{flow.packets_per_second:.1f} p/s"
            lines.append(f"  {flow_display:<42} {flow.packet_count:<7,d} {rate_str:<10} {flow.classification:<20}")

        # 7. DNS Analysis
        header("7. DNS Analysis")
        lines.append(f"Total DNS Transactions: {len(result.dns)}")
        if result.dns:
            lines.append(f"  {'Pkt #':<8} {'Source IP':<16} {'Type':<6} {'Queried Domain':<42}")
            lines.append("  " + "-" * 74)
            for d in result.dns[:8]:
                q_domain = d.get('query') or 'N/A'
                if len(q_domain) > 40:
                    q_domain = q_domain[:38] + ".."
                lines.append(f"  {d.get('packet_number', 0):<8} {d.get('source_ip', 'N/A'):<16} {d.get('query_type', 'A'):<6} {q_domain:<42}")
        else:
            lines.append("  No DNS queries identified in this capture.")

        # 8. HTTP Analysis
        header("8. HTTP Analysis")
        lines.append(f"Total HTTP Transactions: {len(result.http)}")
        if result.http:
            lines.append(f"  {'Method':<8} {'Host':<28} {'URI':<38}")
            lines.append("  " + "-" * 76)
            for h in result.http[:8]:
                meth = h.get('method') or (f"HTTP {h.get('status_code')}" if h.get('status_code') else 'HTTP')
                host = h.get('host') or 'N/A'
                uri = h.get('uri') or 'N/A'
                if len(host) > 26:
                    host = host[:24] + ".."
                if len(uri) > 36:
                    uri = uri[:34] + ".."
                lines.append(f"  {meth:<8} {host:<28} {uri:<38}")
        else:
            lines.append("  No cleartext HTTP request/response payloads detected.")

        # 9. TLS Analysis
        header("9. TLS Analysis")
        lines.append(f"Total TLS Records Observed: {len(result.tls)}")
        if result.tls:
            lines.append(f"  {'Handshake':<14} {'Version':<10} {'SNI Server Name Indication':<44}")
            lines.append("  " + "-" * 72)
            for t in result.tls[:8]:
                hs = t.get('handshake_type') or 'TLS-Data'
                ver = t.get('version') or 'TLS'
                sni = t.get('server_name') or t.get('sni') or '(Encrypted / No SNI)'
                lines.append(f"  {hs:<14} {ver:<10} {sni:<44}")
        else:
            lines.append("  No TLS ClientHello/Record handshakes observed.")

        # Extracted Observable Indicators (IOCs)
        header("Extracted Observable Indicators (IOCs)")
        ioc_counts = {k: len(v) for k, v in iocs.items()}
        lines.append(f"Extracted Artifacts: {ioc_counts.get('ips', 0)} IPs | {ioc_counts.get('domains', 0)} Domains | {ioc_counts.get('urls', 0)} URLs | {ioc_counts.get('hostnames', 0)} Hostnames | {ioc_counts.get('emails', 0)} Emails | {ioc_counts.get('hashes', 0)} Hashes")
        if iocs.get("domains"):
            lines.append("Sample Observed Domains:")
            for d in iocs["domains"][:6]:
                lines.append(f"  - {d['value']} (seen {d['packet_count']}x across {d['source']})")
        if iocs.get("urls"):
            lines.append("Sample Observed URLs:")
            for u in iocs["urls"][:4]:
                lines.append(f"  - {u['value']}")

        # 10. Security Findings
        header("10. Security Findings & Threat Detections")
        if not findings:
            lines.append("  No threat signatures or anomalous behavior triggered detection rules.")
        else:
            for idx, f in enumerate(findings, 1):
                pkts_ref = ", ".join(map(str, f.packet_numbers[:6])) if f.packet_numbers else "N/A"
                if len(f.packet_numbers) > 6:
                    pkts_ref += f" (+{len(f.packet_numbers) - 6} more)"

                lines.append(f"[{f.severity.value}] FINDING #{idx:02d}: {f.title}")
                lines.append(f"  Finding ID:       {f.finding_id}")
                lines.append(f"  Rule ID:          {f.rule_id}")
                lines.append(f"  Category:         {f.category}")
                lines.append(f"  Confidence Score: {f.confidence:.2f}")
                lines.append(f"  Packet Ref(s):    {pkts_ref}")
                if f.source_ip:
                    lines.append(f"  Source Endpoint:  {f.source_ip}")
                if f.destination_port:
                    lines.append(f"  Target Port:      {f.destination_port} ({get_port_service_name(f.destination_port)})")
                lines.append(f"  Description:      {f.description}")
                lines.append("  Telemetry Evidence:")
                if isinstance(f.evidence, dict):
                    for k, v in f.evidence.items():
                        key_fmt = k.replace("_", " ").capitalize()
                        lines.append(f"    - {key_fmt}: {v}")
                elif isinstance(f.evidence, list):
                    for item in f.evidence:
                        lines.append(f"    - {item}")
                if f.recommended_next_step:
                    lines.append(f"  Investigative Step: {f.recommended_next_step}")
                if f.limitations:
                    lines.append(f"  Forensic Boundary:  {f.limitations}")
                lines.append("")

        # 11. Parsing Errors
        header("11. Parsing Errors & Stream Anomalies")
        if not errors:
            lines.append("  Zero parsing errors encountered. All packets parsed cleanly.")
        else:
            lines.append(f"  Total parsing anomalies logged: {len(errors)}")
            for err in errors[:5]:
                lines.append(f"  - {err}")
            if len(errors) > 5:
                lines.append(f"  ... and {len(errors) - 5} additional minor packet anomalies.")

        # 12. Analyst Notes
        header("12. Analyst Notes & SOC Recommendations")
        lines.append("  * Heuristic Assessment: Detections are generated using deterministic statistical")
        lines.append("    and layer-boundary rules. An alert indicates suspicious activity patterns,")
        lines.append("    not certified malicious compromise. Corroborate with host endpoint EDR logs.")
        lines.append("  * Environment Baselines: Results reflect thresholds configured in the active")
        lines.append(f"    profile ({meta.profile_name}). Tuning thresholds in config/*.json is recommended")
        lines.append("    for unique network environments.")
        lines.append("=" * 78)
        lines.append("                    END OF PCAP INVESTIGATION REPORT")
        lines.append("=" * 78)

        return "\n".join(lines)

    @staticmethod
    def save(result: AnalysisResult, output_path: Union[str, Path]) -> None:
        """Save formatted text report to a file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        report_text = TextReporter.generate(result)
        with path.open("w", encoding="utf-8") as f:
            f.write(report_text)
