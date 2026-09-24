"""Master PCAP Analyzer coordinator module.

Implements the conceptual network forensics pipeline:

                    PCAP / PCAPNG
                          │
                          ▼
                  ┌───────────────┐
                  │ Packet Parser │
                  └───────┬───────┘
                          │
          ┌───────────────┼────────────────┐
          ▼               ▼                ▼
       Protocols        Flows          Metadata
          │               │                │
    ┌─────┼─────┐         │          ┌─────┴─────┐
    ▼     ▼     ▼         ▼          ▼           ▼
   DNS   HTTP   TLS    TCP/UDP      IOCs       Integrity
    │     │     │         │
    └─────┴─────┴─────────┴──────────┐
                                     ▼
                           Detection Engine
                                     │
                     ┌───────────────┼───────────────┐
                     ▼               ▼               ▼
                  Findings        Evidence       Severity
                     │               │               │
                     └───────────────┼───────────────┘
                                     ▼
                         JSON + Security Report
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
import time
from typing import Optional, Union

from .config import AnalysisConfig
from .detections import DetectionEngine
from .dns_analyzer import DNSAnalyzer
from .http_analyzer import HTTPAnalyzer
from .iocs import IOCExtractor
from .models import AnalysisResult, CaptureMetadata, PacketRecord
from .parser import BasePcapReader, get_pcap_reader
from .reporting import JsonReporter, TextReporter
from .statistics import StatisticsEngine
from .tls_analyzer import TLSAnalyzer

logger = logging.getLogger(__name__)


def compute_sha256(file_path: Path) -> str:
    """Calculate cryptographic SHA-256 integrity hash of target file."""
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class PCAPAnalyzer:
    """End-to-end network capture analysis and threat detection pipeline."""

    def __init__(
        self,
        file_path: Union[str, Path],
        config: Optional[AnalysisConfig] = None,
    ):
        self.file_path = Path(file_path).resolve()
        self.config = config or AnalysisConfig()
        self._reader: Optional[BasePcapReader] = None
        self._stats_engine = StatisticsEngine()
        self._dns_analyzer = DNSAnalyzer()
        self._http_analyzer = HTTPAnalyzer()
        self._tls_analyzer = TLSAnalyzer()
        self._ioc_extractor = IOCExtractor()
        self._detection_engine = DetectionEngine(self.config.detection)
        self._result: Optional[AnalysisResult] = None

    def analyze(self) -> AnalysisResult:
        """Execute the full analysis pipeline against the target capture file.

        Returns:
            Structured AnalysisResult containing metadata, statistics, flows,
            protocol intelligence, extracted IOCs, and security findings.
        """
        logger.info("Initiating analysis for capture: %s", self.file_path)
        start_wall_time = time.time()

        # Step 1: File integrity verification
        sha256_digest = compute_sha256(self.file_path)
        analysis_time_iso = datetime.now(timezone.utc).isoformat()

        # Step 2: Initialize reader engine
        self._reader = get_pcap_reader(
            self.file_path, preferred_engine=self.config.preferred_engine
        )
        engine_name = self._reader.__class__.__name__.replace("PcapReader", "")

        # Step 3: Stream and process packets across all forensic modules
        packet_list: list[PacketRecord] = []
        for pkt in self._reader.read_packets(max_packets=self.config.max_packets_to_parse):
            packet_list.append(pkt)
            self._stats_engine.process_packet(pkt)
            self._dns_analyzer.process_packet(pkt)
            self._http_analyzer.process_packet(pkt)
            self._tls_analyzer.process_packet(pkt)
            self._ioc_extractor.process_packet(pkt)

        logger.info(
            "Parsed %d packets from %s using %s engine in %.2fs",
            len(packet_list),
            self.file_path.name,
            engine_name,
            time.time() - start_wall_time,
        )

        # Step 4: Compile summary statistics & conversation flows
        summary_stats = self._stats_engine.get_summary_statistics()
        flows = self._stats_engine.get_sorted_flows(sort_by="packets", limit=100)

        # Determine capture format string
        ext = self.file_path.suffix.lower()
        cap_format = "PCAPNG (Next Generation)" if ext == ".pcapng" else "PCAP (Standard Libpcap)"

        metadata = CaptureMetadata(
            file_path=str(self.file_path),
            file_name=self.file_path.name,
            file_size_bytes=self.file_path.stat().st_size,
            file_format=cap_format,
            packet_count=len(packet_list),
            first_timestamp=self._stats_engine.first_timestamp,
            last_timestamp=self._stats_engine.last_timestamp,
            duration_seconds=summary_stats.capture_duration,
            parser_engine=engine_name,
            sha256_hash=sha256_digest,
            analysis_timestamp=analysis_time_iso,
            analyzer_version="2.0.0",
            profile_name=self.config.detection.profile_name,
            profile_source=self.config.profile_source,
        )

        # Step 5: Run heuristic threat detection engine
        # Consumes Protocols (DNS, HTTP, TLS), Flows (TCP/UDP), and Baseline Statistics
        # to generate structured Findings, Evidence, and calibrated Severity ratings.
        findings = self._detection_engine.run(
            packets=packet_list,
            flows=flows,
            stats=summary_stats,
            dns=self._dns_analyzer.records,
            http=self._http_analyzer.records,
            tls=self._tls_analyzer.records,
        )
        logger.info("Evaluation complete: %d security findings identified", len(findings))

        # Step 6: Extract structured indicators of compromise
        iocs = self._ioc_extractor.export_dict()

        # Step 7: Bundle complete analysis result
        dns_data = [r.to_dict() for r in self._dns_analyzer.records]
        http_data = [r.to_dict() for r in self._http_analyzer.records]
        tls_data = [r.to_dict() for r in self._tls_analyzer.records]

        self._result = AnalysisResult(
            metadata=metadata,
            summary=summary_stats,
            protocols=dict(self._stats_engine.protocol_counter),
            top_sources=summary_stats.top_source_ips,
            top_destinations=summary_stats.top_destination_ips,
            flows=flows,
            dns=dns_data,
            http=http_data,
            tls=tls_data,
            findings=findings,
            errors=self._reader.parsing_errors,
            iocs=iocs,
            configuration=self.config.detection.to_dict(),
        )

        return self._result

    @property
    def result(self) -> AnalysisResult:
        """Retrieve computed result or trigger analysis if not yet run."""
        if self._result is None:
            return self.analyze()
        return self._result

    def export_json(self, output_path: Optional[Union[str, Path]] = None, indent: int = 2) -> str:
        """Export analysis as JSON string or write to disk if output_path is provided."""
        res = self.result
        if output_path:
            JsonReporter.save(res, output_path, indent=indent)
        return JsonReporter.generate(res, indent=indent)

    def export_report(self, output_path: Optional[Union[str, Path]] = None) -> str:
        """Export human-readable text report or write to disk if output_path is provided."""
        res = self.result
        if output_path:
            TextReporter.save(res, output_path)
        return TextReporter.generate(res)

    def export_iocs(self, output_path: Optional[Union[str, Path]] = None, indent: int = 2) -> str:
        """Export extracted IOCs as JSON string or write to disk if output_path is provided."""
        res = self.result
        iocs_json = json.dumps(res.iocs, indent=indent)
        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w", encoding="utf-8") as f:
                f.write(iocs_json)
        return iocs_json
