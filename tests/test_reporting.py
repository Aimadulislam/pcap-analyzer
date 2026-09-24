"""Unit tests for JSON serialization and human-readable text reporting."""

import json
import os
import tempfile
import unittest

from pcap_analyzer.analyzer import PCAPAnalyzer
from pcap_analyzer.reporting import JsonReporter, TextReporter
from generate_test_pcaps import (
    build_dns_query_packet,
    build_http_request_packet,
    build_tcp_packet,
    write_pcap_file,
)


class TestReportingEngine(unittest.TestCase):
    """Test suite for reporting and output generation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.pcap_path = os.path.join(self.temp_dir.name, "report_sample.pcap")

        packets = [
            (1.0, build_tcp_packet("192.168.1.15", "10.0.0.1", 50000, 80, syn=True)),
            (1.1, build_tcp_packet("10.0.0.1", "192.168.1.15", 80, 50000, syn=True, ack=True)),
            (1.2, build_tcp_packet("192.168.1.15", "10.0.0.1", 50000, 80, ack=True)),
            (1.3, build_http_request_packet("192.168.1.15", "10.0.0.1", "secure-portal.local", "/")),
            (2.0, build_dns_query_packet("192.168.1.15", "8.8.8.8", "portal.local")),
        ]
        write_pcap_file(self.pcap_path, packets)
        self.analyzer = PCAPAnalyzer(self.pcap_path)
        self.result = self.analyzer.analyze()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_json_structure(self):
        """Verify JSON conforms to schema requirements."""
        json_str = JsonReporter.generate(self.result)
        data = json.loads(json_str)

        required_keys = [
            "metadata",
            "summary",
            "protocols",
            "top_sources",
            "top_destinations",
            "flows",
            "dns",
            "http",
            "tls",
            "findings",
            "errors",
        ]
        for key in required_keys:
            self.assertIn(key, data, f"Required JSON key '{key}' missing")

        self.assertEqual(data["metadata"]["packet_count"], 5)
        self.assertIsInstance(data["findings"], list)
        self.assertIsInstance(data["flows"], list)

    def test_text_report_sections(self):
        """Verify all 12 standard report sections are present in text output."""
        report = TextReporter.generate(self.result)

        expected_sections = [
            "1. Analysis Overview",
            "2. Capture Metadata",
            "3. Traffic Statistics",
            "4. Protocol Distribution",
            "5. Top Talkers",
            "6. Top Conversations",
            "7. DNS Analysis",
            "8. HTTP Analysis",
            "9. TLS Analysis",
            "10. Security Findings",
            "11. Parsing Errors",
            "12. Analyst Notes",
        ]

        for section in expected_sections:
            self.assertIn(section, report, f"Section '{section}' missing from generated text report")

        self.assertIn("PCAP THREAT ANALYSIS & NETWORK FORENSICS REPORT", report)
        self.assertIn("END OF PCAP INVESTIGATION REPORT", report)


if __name__ == "__main__":
    unittest.main()
