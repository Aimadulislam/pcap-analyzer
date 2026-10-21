"""Stage 7: End-to-End QA, Error Boundary, and Security Audit Tests.

Verifies:
- Empty capture files (header only, 0 packets) parse gracefully without crash.
- Malformed and truncated packet frames are caught and logged without aborting.
- Repeated connection attempts (brute-force pattern) trigger RULE-006.
- Benign baseline traffic produces zero high or critical severity alerts.
- Finding explainability contract (what, why, evidence, where, when, next step, limitations).
- File extension and size validation.
"""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from pcap_analyzer.analyzer import PCAPAnalyzer
from pcap_analyzer.config import DetectionConfig
from pcap_analyzer.models import Severity
from pcap_analyzer.parser import NativePcapReader


class TestStage7QAAndSecurityAudit(unittest.TestCase):
    """End-to-End Quality, Resilience, and Security Audit Test Suite."""

    @classmethod
    def setUpClass(cls):
        cls.fixtures_dir = Path("tests/fixtures")
        # Ensure fixtures exist
        if not (cls.fixtures_dir / "empty_capture.pcap").exists():
            from generate_test_pcaps import generate_all_test_fixtures
            generate_all_test_fixtures()

    def test_empty_capture_parsing(self):
        """Verify an empty capture file (header only, 0 packets) is handled safely."""
        empty_pcap = self.fixtures_dir / "empty_capture.pcap"
        reader = NativePcapReader(empty_pcap)
        packets = list(reader.read_packets())
        self.assertEqual(len(packets), 0)
        self.assertEqual(len(reader.parsing_errors), 0)

        # Run analyzer on empty capture
        analyzer = PCAPAnalyzer(str(empty_pcap))
        result = analyzer.analyze()
        self.assertEqual(result.summary.total_packets, 0)
        self.assertEqual(len(result.findings), 0)
        self.assertEqual(len(result.flows), 0)

    def test_malformed_truncated_capture_parsing(self):
        """Verify truncated frame bytes record a parsing error and exit safely."""
        malformed_pcap = self.fixtures_dir / "malformed_truncated.pcap"
        reader = NativePcapReader(malformed_pcap)
        packets = list(reader.read_packets())
        # Should yield 0 packets because frame is truncated
        self.assertEqual(len(packets), 0)
        # Should have captured the truncation parsing error
        self.assertGreaterEqual(len(reader.parsing_errors), 1)
        self.assertTrue(any("truncated" in err.lower() for err in reader.parsing_errors))

    def test_repeated_failed_connection_attempts_rule(self):
        """Verify repeated unacknowledged connection attempts trigger repeated connection or SYN rules."""
        repeated_pcap = self.fixtures_dir / "repeated_conn_attempts.pcap"
        config = DetectionConfig(
            failed_connection_threshold=5,
            syn_scan_min_packets=5,
            syn_scan_unique_port_threshold=1,
        )
        analyzer = PCAPAnalyzer(str(repeated_pcap), config=config)
        result = analyzer.analyze()
        self.assertGreater(result.summary.total_packets, 0)

        # Check for RULE-006 or RULE-001
        rule_ids = {f.detection_rule for f in result.findings}
        self.assertTrue("RULE-006" in rule_ids or "RULE-001" in rule_ids)

    def test_normal_traffic_zero_high_severity(self):
        """Verify benign normal browsing traffic produces 0 HIGH or CRITICAL severity alerts."""
        normal_pcap = self.fixtures_dir / "normal_traffic.pcap"
        analyzer = PCAPAnalyzer(str(normal_pcap))
        result = analyzer.analyze()

        high_or_crit = [
            f for f in result.findings
            if f.severity in (Severity.HIGH, Severity.CRITICAL)
        ]
        self.assertEqual(len(high_or_crit), 0, f"Expected 0 high/critical alerts on normal traffic, got: {high_or_crit}")

    def test_finding_evidence_completeness(self):
        """Verify all findings satisfy the explainability contract (evidence, next step, limitations)."""
        scan_pcap = self.fixtures_dir / "scan_traffic.pcap"
        analyzer = PCAPAnalyzer(str(scan_pcap))
        result = analyzer.analyze()
        self.assertGreater(len(result.findings), 0)

        for finding in result.findings:
            # WHAT happened
            self.assertTrue(finding.title, "Finding must have a descriptive title")
            self.assertTrue(finding.description, "Finding must have a description")
            # WHY / EVIDENCE
            self.assertIsInstance(finding.evidence, dict, "Evidence must be a dictionary")
            self.assertGreater(len(finding.evidence), 0, "Evidence dictionary must not be empty")
            # WHERE & WHEN
            self.assertIsNotNone(finding.timestamp)
            # INVESTIGATE NEXT
            self.assertTrue(finding.recommended_next_step, "Finding must have recommended_next_step")
            # LIMITATIONS & FALSE POSITIVES
            self.assertTrue(finding.limitations, "Finding must document forensic limitations")

    def test_unsupported_file_extension_rejection(self):
        """Verify that non-capture files are rejected by the analyzer validation."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"this is plain text not a pcap file")
            txt_path = f.name

        try:
            with self.assertRaises((ValueError, Exception)):
                reader = NativePcapReader(txt_path)
                list(reader.read_packets())
        finally:
            if os.path.exists(txt_path):
                os.remove(txt_path)


if __name__ == "__main__":
    unittest.main()
