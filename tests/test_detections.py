"""Unit tests for the rule-based threat detection heuristics."""

import os
import tempfile
import unittest

from pcap_analyzer.analyzer import PCAPAnalyzer
from pcap_analyzer.config import AnalysisConfig
from pcap_analyzer.models import Severity
from generate_test_pcaps import (
    build_dns_query_packet,
    build_http_request_packet,
    build_icmp_echo,
    build_tcp_packet,
    write_pcap_file,
)


class TestThreatDetections(unittest.TestCase):
    """Test suite for threat detection rules and evidence extraction."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_rule_001_tcp_syn_scan(self):
        """Verify RULE 001 fires on SYN packets targeting >20 ports with low completion."""
        pcap_path = os.path.join(self.temp_dir.name, "syn_scan.pcap")
        scanner_ip = "192.168.1.100"
        target_ip = "10.0.0.5"

        packets = []
        # Generate 25 SYN packets to 25 distinct destination ports (ports 20..44)
        for i in range(25):
            dst_port = 20 + i
            ts = 1.0 + (i * 0.05)
            packets.append((ts, build_tcp_packet(scanner_ip, target_ip, 50000 + i, dst_port, syn=True)))

        write_pcap_file(pcap_path, packets)

        analyzer = PCAPAnalyzer(pcap_path)
        result = analyzer.analyze()

        syn_finding = next((f for f in result.findings if f.detection_rule == "RULE-001"), None)
        self.assertIsNotNone(syn_finding, "RULE-001 should trigger on SYN port scan")
        self.assertEqual(syn_finding.severity, Severity.HIGH)
        self.assertEqual(syn_finding.source_ip, scanner_ip)
        self.assertIn("syn_packets_transmitted", syn_finding.evidence)
        self.assertEqual(syn_finding.evidence["unique_destination_ports_targeted"], 25)
        self.assertEqual(syn_finding.evidence["completed_handshakes"], 0)

    def test_rule_003_unusual_destination_port(self):
        """Verify RULE 003 fires when packets are sent to suspicious ports (e.g. 4444)."""
        pcap_path = os.path.join(self.temp_dir.name, "unusual_port.pcap")
        packets = [
            (1.0, build_tcp_packet("192.168.1.50", "198.51.100.20", 49152, 4444, syn=True)),
            (1.1, build_tcp_packet("198.51.100.20", "192.168.1.50", 4444, 49152, syn=True, ack=True)),
            (1.2, build_tcp_packet("192.168.1.50", "198.51.100.20", 49152, 4444, ack=True)),
        ]
        write_pcap_file(pcap_path, packets)

        analyzer = PCAPAnalyzer(pcap_path)
        result = analyzer.analyze()

        port_finding = next((f for f in result.findings if f.detection_rule == "RULE-003"), None)
        self.assertIsNotNone(port_finding, "RULE-003 should trigger on port 4444")
        self.assertEqual(port_finding.destination_port, 4444)
        self.assertIn("Metasploit", port_finding.evidence["service_reference"])

    def test_rule_005_suspicious_dns_characteristics(self):
        """Verify RULE 005 fires on high-entropy / long DNS query (tunneling)."""
        pcap_path = os.path.join(self.temp_dir.name, "dns_tunnel.pcap")
        # High entropy randomized string exceeding 50 chars
        exfil_domain = "a8f3b9c2e17d456890abcef1234567890abcdef.tunnel.attacker-c2.net"
        packets = [
            (1.0, build_dns_query_packet("192.168.1.75", "8.8.8.8", exfil_domain)),
        ]
        write_pcap_file(pcap_path, packets)

        analyzer = PCAPAnalyzer(pcap_path)
        result = analyzer.analyze()

        dns_finding = next((f for f in result.findings if f.detection_rule == "RULE-005"), None)
        self.assertIsNotNone(dns_finding, "RULE-005 should trigger on high entropy / long DNS query")
        self.assertEqual(dns_finding.severity, Severity.HIGH)
        self.assertIn("sample_queries", dns_finding.evidence)

    def test_rule_007_icmp_volume_anomaly(self):
        """Verify RULE 007 fires when ICMP volume exceeds configured threshold."""
        pcap_path = os.path.join(self.temp_dir.name, "icmp_volume.pcap")
        packets = []
        # Generate 90 ICMP echo packets in short duration
        for i in range(90):
            packets.append((1.0 + (i * 0.02), build_icmp_echo("192.168.1.200", "10.0.0.1", seq=i)))
        write_pcap_file(pcap_path, packets)

        config = AnalysisConfig()
        config.detection.icmp_volume_threshold = 50  # Lower threshold for unit test
        analyzer = PCAPAnalyzer(pcap_path, config=config)
        result = analyzer.analyze()

        icmp_finding = next((f for f in result.findings if f.detection_rule == "RULE-007"), None)
        self.assertIsNotNone(icmp_finding, "RULE-007 should trigger on high ICMP volume")
        self.assertEqual(icmp_finding.source_ip, "192.168.1.200")
        self.assertGreaterEqual(icmp_finding.evidence["icmp_packet_count"], 90)

    def test_rule_008_cleartext_http_observation(self):
        """Verify RULE 008 identifies cleartext HTTP communication."""
        pcap_path = os.path.join(self.temp_dir.name, "cleartext.pcap")
        packets = [
            (1.0, build_http_request_packet("192.168.1.10", "93.184.216.34", "login.corp.net", "/auth/login")),
        ]
        write_pcap_file(pcap_path, packets)

        analyzer = PCAPAnalyzer(pcap_path)
        result = analyzer.analyze()

        http_finding = next((f for f in result.findings if f.detection_rule == "RULE-008"), None)
        self.assertIsNotNone(http_finding, "RULE-008 should trigger on cleartext HTTP")
        self.assertEqual(http_finding.severity, Severity.LOW)
        self.assertIn("login.corp.net", http_finding.evidence["observed_hosts"])


if __name__ == "__main__":
    unittest.main()
