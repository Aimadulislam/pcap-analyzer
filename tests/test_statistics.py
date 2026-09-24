"""Unit tests for statistical aggregation and conversation flow tracking."""

import os
import tempfile
import unittest

from pcap_analyzer.analyzer import PCAPAnalyzer
from generate_test_pcaps import (
    build_dns_query_packet,
    build_http_request_packet,
    build_tcp_packet,
    build_udp_packet,
    write_pcap_file,
)


class TestTrafficStatistics(unittest.TestCase):
    """Test suite for traffic statistics and flow analysis."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.pcap_path = os.path.join(self.temp_dir.name, "stats_sample.pcap")

        # Create 10 packets across 2 distinct conversations
        packets = []
        # Conversation 1: 192.168.1.50 -> 10.0.0.1:80 (HTTP)
        packets.append((10.0, build_tcp_packet("192.168.1.50", "10.0.0.1", 40001, 80, syn=True)))
        packets.append((10.1, build_tcp_packet("10.0.0.1", "192.168.1.50", 80, 40001, syn=True, ack=True)))
        packets.append((10.2, build_tcp_packet("192.168.1.50", "10.0.0.1", 40001, 80, ack=True)))
        packets.append((10.3, build_http_request_packet("192.168.1.50", "10.0.0.1", "intranet.local", "/", src_port=40001)))

        # Conversation 2: 192.168.1.50 -> 8.8.8.8:53 (DNS)
        packets.append((11.0, build_dns_query_packet("192.168.1.50", "8.8.8.8", "corp.internal", src_port=53123)))
        packets.append((11.5, build_dns_query_packet("192.168.1.50", "8.8.8.8", "mail.internal", src_port=53124)))

        # Additional UDP packets from another host
        packets.append((12.0, build_udp_packet("192.168.1.99", "10.0.0.2", 1234, 5000, b"telemetry1")))
        packets.append((12.1, build_udp_packet("192.168.1.99", "10.0.0.2", 1234, 5000, b"telemetry2")))

        write_pcap_file(self.pcap_path, packets)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_summary_metrics(self):
        """Verify total packet count, byte calculation, and endpoint counts."""
        analyzer = PCAPAnalyzer(self.pcap_path)
        result = analyzer.analyze()

        self.assertEqual(result.summary.total_packets, 8)
        self.assertGreater(result.summary.total_bytes, 400)
        self.assertAlmostEqual(result.summary.capture_duration, 2.1, places=1)
        self.assertEqual(result.summary.unique_source_ips, 3)  # 192.168.1.50, 10.0.0.1, 192.168.1.99
        self.assertEqual(result.summary.unique_destination_ips, 4)  # 10.0.0.1, 192.168.1.50, 8.8.8.8, 10.0.0.2

    def test_protocol_counts(self):
        """Verify protocol breakdown."""
        analyzer = PCAPAnalyzer(self.pcap_path)
        result = analyzer.analyze()

        self.assertEqual(result.summary.dns_packet_count, 2)
        self.assertEqual(result.summary.http_packet_count, 1)

    def test_top_talkers(self):
        """Verify top sources identification."""
        analyzer = PCAPAnalyzer(self.pcap_path)
        result = analyzer.analyze()

        top_src = result.top_sources[0]
        self.assertEqual(top_src["ip"], "192.168.1.50")
        self.assertEqual(top_src["packet_count"], 5)  # 3 TCP handshake + 1 HTTP + 2 DNS? Wait: 1 handshake ack, let's check
        self.assertGreater(top_src["percentage"], 50.0)

    def test_flow_handshake_state(self):
        """Verify flow tracking captures completed handshake."""
        analyzer = PCAPAnalyzer(self.pcap_path)
        result = analyzer.analyze()

        http_flow = next(
            (f for f in result.flows if f.source_ip == "192.168.1.50" and f.destination_port == 80),
            None,
        )
        self.assertIsNotNone(http_flow)
        self.assertTrue(http_flow.completed_handshake)
        self.assertEqual(http_flow.syn_count, 1)


if __name__ == "__main__":
    unittest.main()
