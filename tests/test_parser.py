"""Unit tests for the PCAP loading and packet parsing engine."""

import os
import tempfile
import unittest
from pathlib import Path

from pcap_analyzer.parser import NativePcapReader, get_pcap_reader
from generate_test_pcaps import (
    build_dns_query_packet,
    build_http_request_packet,
    build_icmp_echo,
    build_tcp_packet,
    build_udp_packet,
    write_pcap_file,
)


class TestPcapParser(unittest.TestCase):
    """Test suite for packet dissection and file reading."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.pcap_path = os.path.join(self.temp_dir.name, "test_sample.pcap")

        # Create a test PCAP containing TCP, UDP, ICMP, DNS, and HTTP
        packets = [
            (100.0, build_tcp_packet("192.168.1.10", "10.0.0.5", 50000, 443, syn=True)),
            (100.1, build_tcp_packet("10.0.0.5", "192.168.1.10", 443, 50000, syn=True, ack=True)),
            (100.2, build_tcp_packet("192.168.1.10", "10.0.0.5", 50000, 443, ack=True)),
            (101.0, build_udp_packet("192.168.1.10", "8.8.8.8", 53000, 53, b"\x00" * 20)),
            (102.0, build_icmp_echo("192.168.1.10", "10.0.0.1")),
            (103.0, build_dns_query_packet("192.168.1.10", "8.8.8.8", "example.com")),
            (104.0, build_http_request_packet("192.168.1.10", "93.184.216.34", "example.com", "/index.html")),
        ]
        write_pcap_file(self.pcap_path, packets)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_file_validation(self):
        """Test file validation with non-existent and empty files."""
        with self.assertRaises(FileNotFoundError):
            NativePcapReader("/path/to/definitely/nonexistent.pcap")

        empty_file = os.path.join(self.temp_dir.name, "empty.pcap")
        Path(empty_file).touch()
        with self.assertRaises(ValueError):
            NativePcapReader(empty_file)

    def test_read_all_packets(self):
        """Verify all packets are read and yielded."""
        reader = NativePcapReader(self.pcap_path)
        records = list(reader.read_packets())
        self.assertEqual(len(records), 7)
        self.assertEqual(len(reader.parsing_errors), 0)

    def test_tcp_flags_and_ports(self):
        """Verify TCP SYN, ACK flags and port numbers."""
        reader = NativePcapReader(self.pcap_path)
        records = list(reader.read_packets())

        syn_pkt = records[0]
        self.assertEqual(syn_pkt.source_ip, "192.168.1.10")
        self.assertEqual(syn_pkt.destination_ip, "10.0.0.5")
        self.assertEqual(syn_pkt.source_port, 50000)
        self.assertEqual(syn_pkt.destination_port, 443)
        self.assertTrue(syn_pkt.flags["SYN"])
        self.assertFalse(syn_pkt.flags["ACK"])

        syn_ack_pkt = records[1]
        self.assertTrue(syn_ack_pkt.flags["SYN"])
        self.assertTrue(syn_ack_pkt.flags["ACK"])

    def test_icmp_dissection(self):
        """Verify ICMP packet recognition."""
        reader = NativePcapReader(self.pcap_path)
        records = list(reader.read_packets())
        icmp_pkt = records[4]
        self.assertEqual(icmp_pkt.protocol, "ICMP")
        self.assertEqual(icmp_pkt.transport_protocol, "ICMP")

    def test_dns_dissection(self):
        """Verify DNS query parsing and domain extraction."""
        reader = NativePcapReader(self.pcap_path)
        records = list(reader.read_packets())
        dns_pkt = records[5]
        self.assertEqual(dns_pkt.protocol, "DNS")
        self.assertEqual(dns_pkt.dns_query, "example.com")
        self.assertEqual(dns_pkt.dns_query_type, "A")

    def test_http_dissection(self):
        """Verify cleartext HTTP host and method extraction."""
        reader = NativePcapReader(self.pcap_path)
        records = list(reader.read_packets())
        http_pkt = records[6]
        self.assertEqual(http_pkt.protocol, "HTTP")
        self.assertEqual(http_pkt.http_method, "GET")
        self.assertEqual(http_pkt.http_host, "example.com")
        self.assertEqual(http_pkt.http_uri, "/index.html")

    def test_max_packets_limit(self):
        """Verify max_packets limits read count."""
        reader = NativePcapReader(self.pcap_path)
        records = list(reader.read_packets(max_packets=3))
        self.assertEqual(len(records), 3)


if __name__ == "__main__":
    unittest.main()
