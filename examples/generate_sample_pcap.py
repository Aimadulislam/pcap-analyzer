"""Generates diverse, realistic synthetic PCAP capture files for demonstration and testing.

Allows cybersecurity analysts and students to test the analyzer immediately
without requiring live network packet capture privileges or external dependencies.
"""

from __future__ import annotations

import os
from pathlib import Path
import struct
import sys

# Ensure local test generator is importable
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "tests"))

from generate_test_pcaps import (
    build_dns_query_packet,
    build_http_request_packet,
    build_icmp_echo,
    build_tcp_packet,
    build_udp_packet,
    write_pcap_file,
)


def generate_syn_scan_pcap(output_path: Path) -> None:
    """Generate a TCP SYN port scanning scenario (RULE 001)."""
    attacker_ip = "192.168.4.88"
    target_ip = "10.10.20.5"
    packets = []
    base_time = 1700000000.0

    # Attacker scans ports 20 through 65 (45 ports)
    for i, port in enumerate(range(20, 65)):
        ts = base_time + (i * 0.04)
        src_port = 45000 + i
        packets.append((ts, build_tcp_packet(attacker_ip, target_ip, src_port, port, syn=True)))

        # Simulate only port 22 and 80 replying with SYN-ACK (closed ports reply with RST or timeout)
        if port in (22, 80):
            packets.append((ts + 0.01, build_tcp_packet(target_ip, attacker_ip, port, src_port, syn=True, ack=True)))
            packets.append((ts + 0.02, build_tcp_packet(attacker_ip, target_ip, src_port, port, ack=True)))
        elif port in (21, 23, 25):
            packets.append((ts + 0.01, build_tcp_packet(target_ip, attacker_ip, port, src_port, rst=True)))

    write_pcap_file(str(output_path), packets)
    print(f"[+] Generated SYN Scan capture: {output_path} ({len(packets)} packets)")


def generate_dns_tunneling_pcap(output_path: Path) -> None:
    """Generate a DNS exfiltration / tunneling scenario (RULE 004, RULE 005)."""
    client_ip = "10.0.5.120"
    resolver_ip = "10.0.0.2"
    packets = []
    base_time = 1700001000.0

    # 120 rapid DNS queries with randomized high-entropy base64 chunks
    hex_chunks = [
        "4a6f686e446f655f53534e5f3939392d30302d31323334",
        "50617373776f7264313233215f41646d696e5f546f6b656e",
        "657866696c74726174696f6e5f62617463685f3030313233",
        "63325f6865617274626561745f6163746976655f73657373",
        "6b657967656e5f7273615f343039365f707269766174656b",
    ]

    for i in range(110):
        ts = base_time + (i * 0.05)
        chunk = hex_chunks[i % len(hex_chunks)]
        domain = f"chunk{i:03d}.{chunk}.tunnel.stealth-c2-domain.org"
        packets.append((ts, build_dns_query_packet(client_ip, resolver_ip, domain, tx_id=1000 + i, src_port=52000 + (i % 500))))

    write_pcap_file(str(output_path), packets)
    print(f"[+] Generated DNS Tunneling capture: {output_path} ({len(packets)} packets)")


def generate_cleartext_http_pcap(output_path: Path) -> None:
    """Generate cleartext HTTP credentials scenario (RULE 008, RULE 003)."""
    client_ip = "192.168.1.42"
    server_ip = "198.51.100.80"
    packets = []
    base_time = 1700002000.0

    # Normal 3-way handshake on Port 80
    packets.append((base_time + 0.00, build_tcp_packet(client_ip, server_ip, 49200, 80, syn=True)))
    packets.append((base_time + 0.01, build_tcp_packet(server_ip, client_ip, 80, 49200, syn=True, ack=True)))
    packets.append((base_time + 0.02, build_tcp_packet(client_ip, server_ip, 49200, 80, ack=True)))

    # HTTP GET Request
    packets.append((base_time + 0.03, build_http_request_packet(client_ip, server_ip, "corp-intranet.local", "/login.php?user=admin", src_port=49200)))

    # Communication to unusual backdoor port 4444 (Metasploit)
    c2_ip = "203.0.113.99"
    packets.append((base_time + 1.00, build_tcp_packet(client_ip, c2_ip, 49250, 4444, syn=True)))
    packets.append((base_time + 1.01, build_tcp_packet(c2_ip, client_ip, 4444, 49250, syn=True, ack=True)))
    packets.append((base_time + 1.02, build_tcp_packet(client_ip, c2_ip, 49250, 4444, ack=True)))

    write_pcap_file(str(output_path), packets)
    print(f"[+] Generated Cleartext & Suspicious Port capture: {output_path} ({len(packets)} packets)")


def generate_corporate_baseline_pcap(output_path: Path) -> None:
    """Generate benign corporate baseline capture with clean HTTPS and DNS."""
    client_ip = "10.10.10.15"
    dns_server = "1.1.1.1"
    github_ip = "140.82.121.4"
    packets = []
    base_time = 1700003000.0

    # Normal DNS queries
    domains = ["github.com", "api.github.com", "slack.com", "google.com"]
    for i, d in enumerate(domains):
        ts = base_time + (i * 0.5)
        packets.append((ts, build_dns_query_packet(client_ip, dns_server, d, tx_id=2000 + i, src_port=53000 + i)))

    # Normal HTTPS 3-way handshake to GitHub (Port 443)
    ts_tls = base_time + 3.0
    packets.append((ts_tls + 0.00, build_tcp_packet(client_ip, github_ip, 50100, 443, syn=True)))
    packets.append((ts_tls + 0.01, build_tcp_packet(github_ip, client_ip, 443, 50100, syn=True, ack=True)))
    packets.append((ts_tls + 0.02, build_tcp_packet(client_ip, github_ip, 50100, 443, ack=True)))

    # TLS ClientHello packet with SNI 'api.github.com'
    # Build TLS Record Header (Type 22 = Handshake, Version 0x0303 = TLS 1.2)
    sni_bytes = b"api.github.com"
    sni_ext = struct.pack("!HHBH", 0x0000, len(sni_bytes) + 3, 0, len(sni_bytes)) + sni_bytes
    exts_len = len(sni_ext)
    # Minimal ClientHello body: HandshakeType 1 (ClientHello) + 3-byte length
    client_hello = (
        b"\x01" + struct.pack("!I", 38 + exts_len)[1:]
        + b"\x03\x03" + (b"\xaa" * 32) + b"\x00"  # Ver + Random + SessionID Len 0
        + b"\x00\x02\xc0\x2f"  # Cipher suites len 2, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        + b"\x01\x00"  # Compression len 1, 0x00
        + struct.pack("!H", exts_len) + sni_ext
    )
    tls_record = b"\x16\x03\x03" + struct.pack("!H", len(client_hello)) + client_hello
    packets.append((ts_tls + 0.03, build_tcp_packet(client_ip, github_ip, 50100, 443, syn=False, ack=True, payload=tls_record)))

    # Benign ICMP Echo to gateway
    packets.append((base_time + 4.0, build_icmp_echo(client_ip, "10.10.10.1", is_reply=False)))
    packets.append((base_time + 4.01, build_icmp_echo("10.10.10.1", client_ip, is_reply=True)))

    write_pcap_file(str(output_path), packets)
    print(f"[+] Generated Corporate Baseline capture: {output_path} ({len(packets)} packets)")


def main() -> None:
    """Generate all sample PCAP scenarios in examples/ directory."""
    examples_dir = Path(__file__).resolve().parent
    examples_dir.mkdir(parents=True, exist_ok=True)

    generate_syn_scan_pcap(examples_dir / "syn_port_scan.pcap")
    generate_dns_tunneling_pcap(examples_dir / "dns_tunneling_c2.pcap")
    generate_cleartext_http_pcap(examples_dir / "cleartext_credentials.pcap")
    generate_corporate_baseline_pcap(examples_dir / "corporate_baseline.pcap")


if __name__ == "__main__":
    main()
