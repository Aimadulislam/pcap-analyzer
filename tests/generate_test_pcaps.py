"""Synthetic PCAP generator for testing and demonstration.

Constructs RFC-compliant libpcap binary files (.pcap) using pure-Python struct packing,
allowing complete offline test execution without requiring Scapy, Wireshark, or live packet captures.
Generates reproducible test fixtures covering TCP scans, DNS anomalies, HTTP inspection, and TLS negotiation.
"""

from __future__ import annotations

from pathlib import Path
import socket
import struct
from typing import List, Optional, Tuple


def build_pcap_global_header() -> bytes:
    """Build a 24-byte libpcap standard global header (little-endian, microsecond)."""
    return struct.pack(
        "<IHHiIII",
        0xA1B2C3D4,  # Magic number
        2,           # Major version
        4,           # Minor version
        0,           # GMT offset
        0,           # Accuracy of timestamps
        65535,       # Snaplen
        1,           # Data link type (1 = Ethernet)
    )


def build_ethernet_header(
    src_mac: str = "00:11:22:33:44:55",
    dst_mac: str = "66:77:88:99:aa:bb",
    ethertype: int = 0x0800,
) -> bytes:
    """Build a 14-byte Ethernet II header."""
    dst = bytes.fromhex(dst_mac.replace(":", ""))
    src = bytes.fromhex(src_mac.replace(":", ""))
    return dst + src + struct.pack("!H", ethertype)


def build_ipv4_header(
    src_ip: str,
    dst_ip: str,
    proto: int,
    payload_len: int,
    ttl: int = 64,
    ident: int = 54321,
) -> bytes:
    """Build a 20-byte IPv4 header."""
    v_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + payload_len
    flags_frag = 0x4000  # Don't fragment
    chksum = 0  # Simplified test checksum
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    return struct.pack(
        "!BBHHHBBH4s4s",
        v_ihl,
        tos,
        total_len,
        ident,
        flags_frag,
        ttl,
        proto,
        chksum,
        src_bytes,
        dst_bytes,
    )


def build_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    syn: bool = False,
    ack: bool = False,
    fin: bool = False,
    rst: bool = False,
    seq: int = 1000,
    ack_num: int = 0,
    payload: bytes = b"",
) -> bytes:
    """Build a complete Ethernet + IPv4 + TCP packet."""
    eth = build_ethernet_header()
    flags_byte = (
        (0x01 if fin else 0)
        | (0x02 if syn else 0)
        | (0x04 if rst else 0)
        | (0x10 if ack else 0)
    )
    offset_res = 5 << 4  # 20-byte TCP header
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack_num,
        offset_res,
        flags_byte,
        65535,
        0,
        0,
    )
    ip_hdr = build_ipv4_header(
        src_ip, dst_ip, proto=6, payload_len=len(tcp_hdr) + len(payload)
    )
    return eth + ip_hdr + tcp_hdr + payload


def build_udp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
) -> bytes:
    """Build a complete Ethernet + IPv4 + UDP packet."""
    eth = build_ethernet_header()
    udp_len = 8 + len(payload)
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    ip_hdr = build_ipv4_header(src_ip, dst_ip, proto=17, payload_len=udp_len)
    return eth + ip_hdr + udp_hdr + payload


def build_icmp_echo(
    src_ip: str,
    dst_ip: str,
    is_reply: bool = False,
    seq: int = 1,
    payload: bytes = b"abcdefghijklmnopqrstuvwabcdefghi",
) -> bytes:
    """Build an ICMP Echo Request or Reply packet."""
    eth = build_ethernet_header()
    icmp_type = 0 if is_reply else 8
    icmp_hdr = struct.pack("!BBHHH", icmp_type, 0, 0, 1234, seq)
    ip_hdr = build_ipv4_header(
        src_ip, dst_ip, proto=1, payload_len=len(icmp_hdr) + len(payload)
    )
    return eth + ip_hdr + icmp_hdr + payload


def encode_dns_name(domain: str) -> bytes:
    """Encode a domain name into DNS QNAME byte format."""
    out = b""
    for part in domain.split("."):
        if part:
            out += struct.pack("!B", len(part)) + part.encode("ascii")
    out += b"\x00"
    return out


def build_dns_query_packet(
    src_ip: str,
    dst_ip: str,
    domain: str,
    tx_id: int = 0x1234,
    src_port: int = 54321,
    qtype: int = 1,  # 1 = A, 16 = TXT
) -> bytes:
    """Build a complete DNS query packet."""
    dns_hdr = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    qname = encode_dns_name(domain)
    qtype_qclass = struct.pack("!HH", qtype, 1)  # Class IN
    dns_payload = dns_hdr + qname + qtype_qclass
    return build_udp_packet(src_ip, dst_ip, src_port, 53, dns_payload)


def build_dns_response_packet(
    src_ip: str,
    dst_ip: str,
    domain: str,
    resolved_ip: str = "192.168.1.100",
    tx_id: int = 0x1234,
    src_port: int = 53,
    dst_port: int = 54321,
) -> bytes:
    """Build a complete DNS response packet with 1 A answer record."""
    dns_hdr = struct.pack("!HHHHHH", tx_id, 0x8180, 1, 1, 0, 0)  # Standard response, No error
    qname = encode_dns_name(domain)
    qtype_qclass = struct.pack("!HH", 1, 1)
    
    # Answer record: pointer to qname (0xc00c), Type A (1), Class IN (1), TTL (300), RDLENGTH (4), RDATA
    ans_name_ptr = struct.pack("!H", 0xC00C)
    ans_meta = struct.pack("!HHIH", 1, 1, 300, 4)
    ans_rdata = socket.inet_aton(resolved_ip)
    
    dns_payload = dns_hdr + qname + qtype_qclass + ans_name_ptr + ans_meta + ans_rdata
    return build_udp_packet(src_ip, dst_ip, src_port, dst_port, dns_payload)


def build_http_request_packet(
    src_ip: str,
    dst_ip: str,
    host: str,
    uri: str = "/",
    method: str = "GET",
    src_port: int = 49152,
    dst_port: int = 80,
    user_agent: str = "Mozilla/5.0 (Defensive-Audit-Lab/2.0)",
    extra_headers: Optional[str] = None,
) -> bytes:
    """Build a complete HTTP request packet over TCP."""
    headers_block = (
        f"{method} {uri} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        f"Accept: text/html,application/xhtml+xml\r\n"
    )
    if extra_headers:
        headers_block += extra_headers
    headers_block += "Connection: close\r\n\r\n"
    payload = headers_block.encode("latin-1")
    return build_tcp_packet(
        src_ip, dst_ip, src_port, dst_port, syn=False, ack=True, payload=payload
    )


def build_tls_client_hello_packet(
    src_ip: str,
    dst_ip: str,
    server_name: str,
    src_port: int = 51234,
    dst_port: int = 443,
    tls_version: int = 0x0303,  # 0x0303 = TLS 1.2, 0x0301 = TLS 1.0
    cipher_suite: int = 0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
) -> bytes:
    """Construct a RFC-compliant TLS ClientHello packet with Server Name Indication (SNI)."""
    sni_bytes = server_name.encode("ascii")
    sni_entry = struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes  # HostName type = 0
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_extension = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    ext_block = struct.pack("!H", len(sni_extension)) + sni_extension

    client_random = b"\x01" * 32
    session_id = b"\x00"  # 0 length session ID
    ciphers = struct.pack("!HH", 2, cipher_suite)
    comp_methods = b"\x01\x00"  # 1 method: null compression

    hello_body = (
        struct.pack("!H", tls_version)
        + client_random
        + session_id
        + ciphers
        + comp_methods
        + ext_block
    )

    handshake_hdr = struct.pack("!B", 1) + struct.pack("!I", len(hello_body))[1:]  # Type 1 = ClientHello
    handshake_msg = handshake_hdr + hello_body

    # TLS Record Layer: Type 22 (Handshake), Version, Length
    tls_record = struct.pack("!BHH", 22, tls_version, len(handshake_msg)) + handshake_msg

    return build_tcp_packet(
        src_ip, dst_ip, src_port, dst_port, syn=False, ack=True, payload=tls_record
    )


def write_pcap_file(file_path: str, packets: List[Tuple[float, bytes]]) -> None:
    """Write packets to a .pcap file with timestamps."""
    p = Path(file_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("wb") as f:
        f.write(build_pcap_global_header())
        for ts, raw_pkt in packets:
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            length = len(raw_pkt)
            pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, length, length)
            f.write(pkt_hdr + raw_pkt)


def generate_all_test_fixtures(fixtures_dir: str = "tests/fixtures") -> None:
    """Generate all synthetic test PCAPs for automated testing and validation."""
    fdir = Path(fixtures_dir)
    fdir.mkdir(parents=True, exist_ok=True)

    # 1. Normal Baseline Traffic
    base_pkts: List[Tuple[float, bytes]] = []
    base_pkts.append((1.0, build_dns_query_packet("192.168.1.50", "1.1.1.1", "corp.internal")))
    base_pkts.append((1.05, build_dns_response_packet("1.1.1.1", "192.168.1.50", "corp.internal", "192.168.1.10")))
    base_pkts.append((1.2, build_tcp_packet("192.168.1.50", "192.168.1.10", 49152, 443, syn=True)))
    base_pkts.append((1.21, build_tcp_packet("192.168.1.10", "192.168.1.50", 443, 49152, syn=True, ack=True)))
    base_pkts.append((1.22, build_tcp_packet("192.168.1.50", "192.168.1.10", 49152, 443, ack=True)))
    base_pkts.append((1.23, build_tls_client_hello_packet("192.168.1.50", "192.168.1.10", "secure.corp.internal", 49152, 443, 0x0303)))
    write_pcap_file(str(fdir / "normal_traffic.pcap"), base_pkts)

    # 2. TCP SYN Scan Fixture (Scanning 30 distinct ports)
    scan_pkts: List[Tuple[float, bytes]] = []
    attacker = "10.0.0.99"
    target = "10.0.0.1"
    for idx, port in enumerate(range(1000, 1035)):
        t = 2.0 + (idx * 0.05)
        scan_pkts.append((t, build_tcp_packet(attacker, target, 45000 + idx, port, syn=True)))
    write_pcap_file(str(fdir / "scan_traffic.pcap"), scan_pkts)

    # 3. DNS Tunneling & DGA Simulation Fixture
    dns_pkts: List[Tuple[float, bytes]] = []
    d_client = "192.168.10.45"
    d_server = "8.8.8.8"
    high_entropy_labels = [
        "v7x9k3m2p8q1w4z6.exfil-stage.tunnel-sec.com",
        "a9f4c2e8b1d7f3a5.exfil-stage.tunnel-sec.com",
        "99bb44aa11cc22dd.exfil-stage.tunnel-sec.com",
        "d8e1f5b2c7a3e9f4.exfil-stage.tunnel-sec.com",
        "3a8f2c9e7b1d5f4a.exfil-stage.tunnel-sec.com",
    ]
    for idx, d in enumerate(high_entropy_labels):
        t = 3.0 + (idx * 0.1)
        dns_pkts.append((t, build_dns_query_packet(d_client, d_server, d, tx_id=0x2000 + idx)))
    write_pcap_file(str(fdir / "dns_tunneling.pcap"), dns_pkts)

    # 4. HTTP Cleartext & Scanner Signature Fixture
    http_pkts: List[Tuple[float, bytes]] = []
    web_client = "172.16.5.20"
    web_server = "172.16.5.80"
    http_pkts.append((4.0, build_http_request_packet(web_client, web_server, "intranet.local", "/", user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")))
    http_pkts.append((4.1, build_http_request_packet(web_client, web_server, "intranet.local", "/admin/login.php?id=1' UNION SELECT 1,2,3--", user_agent="sqlmap/1.6#stable")))
    http_pkts.append((4.2, build_http_request_packet(web_client, web_server, "intranet.local", "/" + ("A" * 300), user_agent="nikto/2.1.6")))
    write_pcap_file(str(fdir / "http_cleartext.pcap"), http_pkts)

    # 5. Legacy TLS (TLS 1.0) Fixture
    tls_pkts: List[Tuple[float, bytes]] = []
    legacy_client = "192.168.20.15"
    legacy_server = "192.168.20.5"
    tls_pkts.append((5.0, build_tls_client_hello_packet(legacy_client, legacy_server, "legacy-service.local", 55555, 443, tls_version=0x0301)))
    write_pcap_file(str(fdir / "tls_legacy.pcap"), tls_pkts)

    # 6. Mixed Comprehensive Forensics Fixture (combining elements)
    mixed_pkts = base_pkts + scan_pkts[:15] + dns_pkts + http_pkts + tls_pkts
    mixed_pkts.sort(key=lambda x: x[0])
    write_pcap_file(str(fdir / "mixed_forensics.pcap"), mixed_pkts)


if __name__ == "__main__":
    generate_all_test_fixtures()
    print("Test fixtures generated successfully in tests/fixtures/")
