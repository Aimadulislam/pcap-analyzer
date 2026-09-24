"""Comprehensive Stage 2 Test Suite for Automated Python PCAP Analyzer & Threat Parser.

Validates:
- Advanced protocol extraction (DNS, HTTP, TLS)
- Dedicated protocol analyzers (DNSAnalyzer, HTTPAnalyzer, TLSAnalyzer)
- IOC extraction engine (deduplication, classification, timestamps, schema)
- Environment-aware threshold profiles (default, home_lab, enterprise, high_volume)
- Evidence-based threat detections (SYN scanning, DNS tunneling, scanner UAs, legacy TLS)
- Reproducible synthetic PCAP test fixtures
- SHA-256 integrity verification
- CLI flags (--profile, --iocs, --hash)
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from pcap_analyzer.analyzer import PCAPAnalyzer, compute_sha256
from pcap_analyzer.cli import main as cli_main
from pcap_analyzer.config import AnalysisConfig, DetectionConfig, PROFILE_DEFINITIONS
from pcap_analyzer.dns_analyzer import DNSAnalyzer
from pcap_analyzer.http_analyzer import HTTPAnalyzer
from pcap_analyzer.iocs import IOCExtractor
from pcap_analyzer.models import (
    DNSRecord,
    HTTPRecord,
    IOCRecord,
    PacketRecord,
    Severity,
    TLSRecord,
)
from pcap_analyzer.tls_analyzer import TLSAnalyzer


class TestStage2ModelsAndAnalyzers(unittest.TestCase):
    """Test new Stage 2 record models and protocol-specific analyzers."""

    def test_dns_record_and_analyzer(self):
        analyzer = DNSAnalyzer()
        pkt = PacketRecord(
            packet_number=1,
            timestamp=100.0,
            packet_length=85,
            source_ip="192.168.1.10",
            destination_ip="8.8.8.8",
            source_port=53123,
            destination_port=53,
            protocol="DNS",
            dns_query="data-exfil-node.test-tunnel.net",
            dns_query_type="TXT",
            dns_tx_id=0x1234,
        )
        rec = analyzer.process_packet(pkt)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.query, "data-exfil-node.test-tunnel.net")
        self.assertEqual(rec.query_type, "TXT")
        self.assertEqual(rec.transaction_id, 0x1234)
        self.assertEqual(analyzer.total_queries, 1)

        # Test direct DNSRecord model
        dns_rec = DNSRecord(
            timestamp=100.0,
            packet_number=1,
            source_ip="192.168.1.10",
            destination_ip="8.8.8.8",
            query="data-exfil-node.test-tunnel.net",
            query_type="TXT",
            response_code="NOERROR",
            answers=["192.168.1.1"],
            is_response=True,
            transaction_id=0x1234,
        )
        self.assertTrue(dns_rec.is_response)
        self.assertEqual(dns_rec.response_code, "NOERROR")

        summary = analyzer.get_summary_dict()
        self.assertEqual(summary["total_queries"], 1)
        self.assertEqual(summary["query_types"].get("TXT"), 1)

    def test_http_record_and_analyzer(self):
        analyzer = HTTPAnalyzer()
        pkt = PacketRecord(
            packet_number=2,
            timestamp=101.0,
            packet_length=240,
            source_ip="10.0.0.5",
            destination_ip="10.0.0.1",
            source_port=49800,
            destination_port=80,
            protocol="HTTP",
            http_method="POST",
            http_host="api.internal",
            http_uri="/v1/telemetry",
            http_user_agent="CustomAgent/1.0",
            http_status_code=None,
            http_content_type="application/json",
        )
        rec = analyzer.process_packet(pkt)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.method, "POST")
        self.assertEqual(rec.host, "api.internal")
        self.assertEqual(rec.content_type, "application/json")
        self.assertEqual(analyzer.total_records, 1)

    def test_tls_record_and_analyzer(self):
        analyzer = TLSAnalyzer()
        pkt = PacketRecord(
            packet_number=3,
            timestamp=102.0,
            packet_length=320,
            source_ip="172.16.0.4",
            destination_ip="172.16.0.100",
            source_port=54321,
            destination_port=443,
            protocol="TLS",
            tls_information={
                "version": "TLS 1.0",
                "sni": "legacy.corp.internal",
                "handshake_type": "ClientHello",
                "cipher": "TLS_RSA_WITH_AES_128_CBC_SHA",
            },
        )
        rec = analyzer.process_packet(pkt)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.version, "TLS 1.0")
        self.assertEqual(rec.server_name, "legacy.corp.internal")

        legacy = analyzer.get_legacy_versions()
        self.assertEqual(len(legacy), 1)
        self.assertEqual(legacy[0][0], "TLS 1.0")


class TestStage2IOCExtractor(unittest.TestCase):
    """Test observable Indicator of Compromise extraction and deduplication."""

    def test_ioc_extraction(self):
        extractor = IOCExtractor()

        pkt1 = PacketRecord(
            packet_number=1,
            timestamp=10.0,
            packet_length=100,
            source_ip="192.168.1.50",
            destination_ip="203.0.113.195",
            source_port=45000,
            destination_port=80,
            protocol="HTTP",
            http_host="downloads.suspicious-domain.org",
            http_uri="/bin/update.exe?contact=soc-alert@analyst.org&hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            http_user_agent="Mozilla/5.0",
        )
        extractor.process_packet(pkt1)

        records = extractor.get_all_records()
        types = {r.type for r in records}
        values = {r.value for r in records}

        # IP addresses
        self.assertIn("IPv4", types)
        self.assertIn("192.168.1.50", values)
        self.assertIn("203.0.113.195", values)

        # Domain
        self.assertIn("domain", types)
        self.assertIn("downloads.suspicious-domain.org", values)

        # URL
        self.assertIn("url", types)
        self.assertIn("http://downloads.suspicious-domain.org/bin/update.exe?contact=soc-alert@analyst.org&hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", values)

        # Email regex
        self.assertIn("email", types)
        self.assertIn("soc-alert@analyst.org", values)

        # Hash regex
        self.assertIn("hash", types)
        self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", values)

        # Categorized export schema
        exported = extractor.export_dict()
        self.assertIn("ips", exported)
        self.assertIn("domains", exported)
        self.assertIn("urls", exported)
        self.assertIn("emails", exported)
        self.assertIn("hashes", exported)
        self.assertTrue(len(exported["domains"]) >= 1)


class TestStage2EnvironmentProfiles(unittest.TestCase):
    """Test environment-aware profile loading and threshold tuning."""

    def test_builtin_profiles(self):
        for prof_name in ("default", "home_lab", "enterprise", "high_volume"):
            cfg = AnalysisConfig.from_profile(prof_name)
            self.assertEqual(cfg.detection.profile_name, prof_name)
            self.assertIn(prof_name, cfg.profile_source)

        # home_lab has lower thresholds for small labs
        home_cfg = AnalysisConfig.from_profile("home_lab")
        default_cfg = AnalysisConfig.from_profile("default")
        self.assertLess(home_cfg.detection.syn_scan_unique_port_threshold, default_cfg.detection.syn_scan_unique_port_threshold)
        self.assertLess(home_cfg.detection.dns_query_volume_threshold, default_cfg.detection.dns_query_volume_threshold)

    def test_json_profile_files(self):
        for prof_name in ("default", "home_lab", "enterprise", "high_volume"):
            file_path = Path(f"config/{prof_name}.json")
            self.assertTrue(file_path.is_file(), f"Profile file missing: {file_path}")
            cfg = AnalysisConfig.from_file(file_path)
            self.assertEqual(cfg.detection.profile_name, prof_name)


class TestStage2SyntheticPCAPFixtures(unittest.TestCase):
    """Run end-to-end PCAP analysis on synthetic test fixtures."""

    def test_scan_traffic_fixture(self):
        pcap_path = Path("tests/fixtures/scan_traffic.pcap")
        self.assertTrue(pcap_path.is_file())

        analyzer = PCAPAnalyzer(pcap_path)
        res = analyzer.analyze()

        self.assertGreater(res.metadata.packet_count, 30)
        self.assertIsNotNone(res.metadata.sha256_hash)

        # Verify scanning finding
        scan_findings = [f for f in res.findings if f.rule_id == "RULE-001"]
        self.assertTrue(len(scan_findings) >= 1)
        finding = scan_findings[0]
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertIn("scanning", finding.title.lower())
        self.assertIn("scan_classification", finding.evidence)
        self.assertTrue(len(finding.packet_numbers) > 0)
        self.assertIsNotNone(finding.recommended_next_step)
        self.assertIsNotNone(finding.limitations)

    def test_dns_tunneling_fixture(self):
        pcap_path = Path("tests/fixtures/dns_tunneling.pcap")
        self.assertTrue(pcap_path.is_file())

        analyzer = PCAPAnalyzer(pcap_path)
        res = analyzer.analyze()

        self.assertGreater(len(res.dns), 0)
        dns_findings = [f for f in res.findings if f.rule_id == "RULE-005"]
        self.assertTrue(len(dns_findings) >= 1)
        finding = dns_findings[0]
        self.assertIn("tunneling", finding.title.lower())
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertTrue(len(finding.packet_numbers) > 0)

    def test_http_cleartext_and_scanner_fixture(self):
        pcap_path = Path("tests/fixtures/http_cleartext.pcap")
        self.assertTrue(pcap_path.is_file())

        analyzer = PCAPAnalyzer(pcap_path)
        res = analyzer.analyze()

        self.assertGreater(len(res.http), 0)
        # Cleartext rule
        cleartext_findings = [f for f in res.findings if f.rule_id == "RULE-008"]
        self.assertTrue(len(cleartext_findings) >= 1)

        # Scanner UA rule or long URI rule
        http_findings = [f for f in res.findings if f.rule_id == "RULE-009"]
        self.assertTrue(len(http_findings) >= 1)

    def test_tls_legacy_fixture(self):
        pcap_path = Path("tests/fixtures/tls_legacy.pcap")
        self.assertTrue(pcap_path.is_file())

        analyzer = PCAPAnalyzer(pcap_path)
        res = analyzer.analyze()

        self.assertGreater(len(res.tls), 0)
        tls_findings = [f for f in res.findings if f.rule_id == "RULE-010"]
        self.assertTrue(len(tls_findings) >= 1)
        self.assertIn("TLS 1.0", tls_findings[0].title)

    def test_mixed_forensics_fixture(self):
        pcap_path = Path("tests/fixtures/mixed_forensics.pcap")
        self.assertTrue(pcap_path.is_file())

        analyzer = PCAPAnalyzer(pcap_path)
        res = analyzer.analyze()

        self.assertGreater(len(res.findings), 2)
        self.assertGreater(len(res.iocs["domains"]), 0)
        self.assertGreater(len(res.iocs["ips"]), 0)


class TestStage2CLIEnhancements(unittest.TestCase):
    """Test CLI enhancements (--profile, --iocs, --hash)."""

    def test_cli_execution_with_profile_and_iocs(self):
        pcap_path = "tests/fixtures/mixed_forensics.pcap"
        with tempfile.TemporaryDirectory() as tmpdir:
            json_out = Path(tmpdir) / "analysis.json"
            report_out = Path(tmpdir) / "report.txt"
            iocs_out = Path(tmpdir) / "iocs.json"

            code = cli_main([
                "-i", pcap_path,
                "-o", str(json_out),
                "-r", str(report_out),
                "--iocs", str(iocs_out),
                "--profile", "home_lab",
                "--hash",
                "--quiet",
            ])
            self.assertEqual(code, 0)
            self.assertTrue(json_out.is_file())
            self.assertTrue(report_out.is_file())
            self.assertTrue(iocs_out.is_file())

            # Verify JSON content
            with json_out.open("r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["metadata"]["profile_name"], "home_lab")
            self.assertIsNotNone(data["metadata"]["sha256_hash"])
            self.assertIn("iocs", data)

            # Verify IOCs JSON file
            with iocs_out.open("r", encoding="utf-8") as f:
                ioc_data = json.load(f)
            self.assertIn("domains", ioc_data)
            self.assertIn("ips", ioc_data)


if __name__ == "__main__":
    unittest.main()
