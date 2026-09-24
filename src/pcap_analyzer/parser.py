"""PCAP and PCAPNG file loaders and packet parsing abstractions.

Provides:
- Native pure-Python binary PCAP/PCAPNG parser for maximum portability and speed
  without requiring external C-libraries or system packages.
- Scapy integration for deep packet inspection when Scapy is installed.
- PyShark integration for Wireshark/tshark dissector access where available.
- Resilient error handling that tracks malformed packets without crashing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import logging
from pathlib import Path
import struct
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

from .models import PacketRecord
from .protocols import (
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    IP_PROTO_ICMP,
    IP_PROTO_IPV6_ICMP,
    IP_PROTO_TCP,
    IP_PROTO_UDP,
    dissect_dns,
    dissect_ethernet,
    dissect_http,
    dissect_icmp,
    dissect_ipv4,
    dissect_ipv6,
    dissect_tcp,
    dissect_tls,
    dissect_udp,
)

logger = logging.getLogger(__name__)

# Libpcap Global Header Constants
PCAP_MAGIC_MICRO_NATIVE = 0xA1B2C3D4
PCAP_MAGIC_MICRO_SWAPPED = 0xD4C3B2A1
PCAP_MAGIC_NANO_NATIVE = 0xA1B23C4D
PCAP_MAGIC_NANO_SWAPPED = 0x4D3CB2A1

# PCAPNG Block Types
PCAPNG_SHB_MAGIC = 0x0A0D0D0A  # Section Header Block
PCAPNG_IDB_TYPE = 0x00000001   # Interface Description Block
PCAPNG_EPB_TYPE = 0x00000006   # Enhanced Packet Block
PCAPNG_SPB_TYPE = 0x00000003   # Simple Packet Block


class BasePcapReader(ABC):
    """Abstract base class for PCAP parsing engines."""

    def __init__(self, file_path: Union[str, Path]):
        self.file_path = Path(file_path)
        self.parsing_errors: List[str] = []
        self._validate_file()

    def _validate_file(self) -> None:
        """Validate file existence and basic readability."""
        if not self.file_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.file_path}")
        if not self.file_path.is_file():
            raise IsADirectoryError(f"Path is not a regular file: {self.file_path}")
        if self.file_path.stat().st_size == 0:
            raise ValueError(f"Capture file is empty (0 bytes): {self.file_path}")

    @abstractmethod
    def read_packets(self, max_packets: Optional[int] = None) -> Iterator[PacketRecord]:
        """Read and yield parsed PacketRecord objects."""
        pass


class NativePcapReader(BasePcapReader):
    """Zero-dependency RFC-compliant binary PCAP and PCAPNG stream parser."""

    def __init__(self, file_path: Union[str, Path]):
        super().__init__(file_path)
        self.is_pcapng = False
        self.endianness = "<"
        self.nano_timestamp = False
        self.link_type = 1  # 1 = LINKTYPE_ETHERNET

    def _detect_format_and_endianness(self, f) -> None:
        """Detect PCAP vs PCAPNG format and determine endianness."""
        magic_bytes = f.read(4)
        if len(magic_bytes) < 4:
            raise ValueError("File too short to read capture magic number.")

        magic = struct.unpack(">I", magic_bytes)[0]
        if magic == PCAPNG_SHB_MAGIC:
            self.is_pcapng = True
            # Read rest of SHB header to determine endianness
            shb_rest = f.read(12)
            if len(shb_rest) >= 8:
                byte_order_magic = struct.unpack(">I", shb_rest[4:8])[0]
                if byte_order_magic == 0x1A2B3C4D:
                    self.endianness = ">"
                else:
                    self.endianness = "<"
            f.seek(0)
            return

        # Check classic libpcap magic numbers
        if magic == PCAP_MAGIC_MICRO_NATIVE:
            self.endianness = ">"
            self.nano_timestamp = False
        elif magic == PCAP_MAGIC_MICRO_SWAPPED:
            self.endianness = "<"
            self.nano_timestamp = False
        elif magic == PCAP_MAGIC_NANO_NATIVE:
            self.endianness = ">"
            self.nano_timestamp = True
        elif magic == PCAP_MAGIC_NANO_SWAPPED:
            self.endianness = "<"
            self.nano_timestamp = True
        else:
            # Check little-endian interpretation
            magic_le = struct.unpack("<I", magic_bytes)[0]
            if magic_le == PCAP_MAGIC_MICRO_NATIVE:
                self.endianness = "<"
                self.nano_timestamp = False
            elif magic_le == PCAP_MAGIC_NANO_NATIVE:
                self.endianness = "<"
                self.nano_timestamp = True
            else:
                raise ValueError(
                    f"Unsupported or invalid PCAP magic bytes: 0x{magic:08x}. "
                    "Expected standard .pcap or .pcapng file."
                )

        # Read remainder of 24-byte libpcap global header
        global_header = f.read(20)
        if len(global_header) < 20:
            raise ValueError("Truncated PCAP global header.")
        fmt = f"{self.endianness}HHIIII"
        _, _, _, _, _, self.link_type = struct.unpack(fmt, global_header)

    def read_packets(self, max_packets: Optional[int] = None) -> Iterator[PacketRecord]:
        """Parse raw packets from the capture file."""
        with self.file_path.open("rb") as f:
            self._detect_format_and_endianness(f)

            if self.is_pcapng:
                yield from self._read_pcapng_packets(f, max_packets)
            else:
                yield from self._read_classic_pcap_packets(f, max_packets)

    def _read_classic_pcap_packets(self, f, max_packets: Optional[int]) -> Iterator[PacketRecord]:
        """Read standard libpcap packet records."""
        packet_num = 0
        hdr_fmt = f"{self.endianness}IIII"
        hdr_size = 16

        while True:
            if max_packets is not None and packet_num >= max_packets:
                break

            hdr_bytes = f.read(hdr_size)
            if not hdr_bytes or len(hdr_bytes) < hdr_size:
                break

            packet_num += 1
            try:
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(hdr_fmt, hdr_bytes)
                if self.nano_timestamp:
                    timestamp = ts_sec + (ts_usec / 1_000_000_000.0)
                else:
                    timestamp = ts_sec + (ts_usec / 1_000_000.0)

                packet_data = f.read(incl_len)
                if len(packet_data) < incl_len:
                    self.parsing_errors.append(
                        f"Packet #{packet_num} truncated: expected {incl_len} bytes, read {len(packet_data)}"
                    )
                    break

                record = self._dissect_raw_packet(packet_num, timestamp, orig_len, packet_data)
                yield record

            except Exception as exc:
                self.parsing_errors.append(f"Error parsing packet #{packet_num}: {exc}")
                logger.debug("Failed packet parse: %s", exc)
                continue

    def _read_pcapng_packets(self, f, max_packets: Optional[int]) -> Iterator[PacketRecord]:
        """Read PCAPNG blocks (Enhanced Packet Blocks)."""
        packet_num = 0
        f.seek(0)

        while True:
            if max_packets is not None and packet_num >= max_packets:
                break

            block_hdr = f.read(8)
            if not block_hdr or len(block_hdr) < 8:
                break

            block_type, block_len = struct.unpack(f"{self.endianness}II", block_hdr)
            if block_len < 12:
                self.parsing_errors.append(f"Invalid PCAPNG block length {block_len} at packet #{packet_num + 1}")
                break

            body_len = block_len - 12
            body = f.read(body_len) if body_len > 0 else b""
            f.read(4)  # Trailing block total length

            if block_type == PCAPNG_EPB_TYPE and len(body) >= 20:
                packet_num += 1
                try:
                    _, ts_high, ts_low, cap_len, orig_len = struct.unpack(
                        f"{self.endianness}IIIII", body[:20]
                    )
                    ts_raw = (ts_high << 32) | ts_low
                    timestamp = ts_raw / 1_000_000.0  # Standard microsecond resolution

                    pkt_data = body[20 : 20 + cap_len]
                    record = self._dissect_raw_packet(packet_num, timestamp, orig_len, pkt_data)
                    yield record
                except Exception as exc:
                    self.parsing_errors.append(f"Error parsing PCAPNG packet #{packet_num}: {exc}")
                    continue

    def _dissect_raw_packet(
        self, packet_num: int, timestamp: float, orig_len: int, raw_bytes: bytes
    ) -> PacketRecord:
        """Dissect raw link-layer packet bytes into a PacketRecord."""
        ethertype, _, _, l3_data = dissect_ethernet(raw_bytes)
        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None
        protocol_num: Optional[int] = None
        l4_data = b""
        protocol = "Ethernet"
        transport_proto: Optional[str] = None

        if ethertype == ETHERTYPE_IPV4:
            protocol = "IPv4"
            src_ip, dst_ip, protocol_num, l4_data = dissect_ipv4(l3_data)
        elif ethertype == ETHERTYPE_IPV6:
            protocol = "IPv6"
            src_ip, dst_ip, protocol_num, l4_data = dissect_ipv6(l3_data)
        elif ethertype == 0x0806:
            protocol = "ARP"
            return PacketRecord(
                packet_number=packet_num,
                timestamp=timestamp,
                packet_length=orig_len,
                protocol="ARP",
            )
        else:
            return PacketRecord(
                packet_number=packet_num,
                timestamp=timestamp,
                packet_length=orig_len,
                protocol=f"EtherType-{hex(ethertype) if ethertype else 'Unknown'}",
            )

        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        flags: Optional[Dict[str, bool]] = None
        app_payload = b""

        # Transport Layer Dissection
        if protocol_num == IP_PROTO_TCP:
            transport_proto = "TCP"
            protocol = "TCP"
            src_port, dst_port, flags, app_payload = dissect_tcp(l4_data)
        elif protocol_num == IP_PROTO_UDP:
            transport_proto = "UDP"
            protocol = "UDP"
            src_port, dst_port, app_payload = dissect_udp(l4_data)
        elif protocol_num in (IP_PROTO_ICMP, IP_PROTO_IPV6_ICMP):
            transport_proto = "ICMP"
            protocol = "ICMP"
            icmp_info = dissect_icmp(l4_data)
            return PacketRecord(
                packet_number=packet_num,
                timestamp=timestamp,
                packet_length=orig_len,
                protocol="ICMP",
                transport_protocol="ICMP",
                source_ip=src_ip,
                destination_ip=dst_ip,
                payload_length=len(l4_data),
            )

        # Application Layer Dissection (DNS, HTTP, TLS)
        dns_query: Optional[str] = None
        dns_response: Optional[str] = None
        dns_query_type: Optional[str] = None
        dns_answers: Optional[List[str]] = None
        dns_rcode: Optional[Union[int, str]] = None
        dns_tx_id: Optional[int] = None
        http_host: Optional[str] = None
        http_method: Optional[str] = None
        http_uri: Optional[str] = None
        http_status_code: Optional[int] = None
        http_user_agent: Optional[str] = None
        http_content_type: Optional[str] = None
        tls_info: Optional[Dict[str, Any]] = None

        if app_payload:
            # Check DNS (Port 53 or DNS payload heuristic)
            if src_port == 53 or dst_port == 53:
                dns_res = dissect_dns(app_payload)
                if dns_res:
                    protocol = "DNS"
                    dns_query = dns_res.get("query")
                    dns_query_type = dns_res.get("query_type")
                    dns_answers = dns_res.get("answers")
                    dns_tx_id = dns_res.get("tx_id")
                    dns_rcode = dns_res.get("rcode_name") or dns_res.get("rcode")
                    if dns_res.get("is_response"):
                        dns_response = f"RCODE {dns_res.get('rcode', 0)} ({dns_res.get('rcode_name', '')})"

            # Check HTTP (Port 80/8080 or HTTP string heuristic)
            if protocol != "DNS":
                http_res = dissect_http(app_payload)
                if http_res:
                    protocol = "HTTP"
                    if http_res.get("type") == "request":
                        http_method = http_res.get("method")
                        http_uri = http_res.get("uri")
                        http_host = http_res.get("host")
                        http_user_agent = http_res.get("user_agent")
                        http_content_type = http_res.get("content_type")
                    elif http_res.get("type") == "response":
                        http_status_code = http_res.get("status_code")
                        http_content_type = http_res.get("content_type")

            # Check TLS (Port 443 or TLS Record content type 22/23)
            if protocol not in ("DNS", "HTTP"):
                tls_res = dissect_tls(app_payload)
                if tls_res:
                    protocol = "TLS"
                    tls_info = tls_res

        return PacketRecord(
            packet_number=packet_num,
            timestamp=timestamp,
            packet_length=orig_len,
            protocol=protocol,
            transport_protocol=transport_proto,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            flags=flags,
            dns_query=dns_query,
            dns_response=dns_response,
            dns_query_type=dns_query_type,
            dns_answers=dns_answers,
            dns_rcode=dns_rcode,
            dns_tx_id=dns_tx_id,
            http_host=http_host,
            http_method=http_method,
            http_uri=http_uri,
            http_status_code=http_status_code,
            http_user_agent=http_user_agent,
            http_content_type=http_content_type,
            tls_information=tls_info,
            payload_length=len(app_payload),
        )


class ScapyPcapReader(BasePcapReader):
    """Scapy-backed PCAP reader used when Scapy is installed."""

    def read_packets(self, max_packets: Optional[int] = None) -> Iterator[PacketRecord]:
        """Read packets using Scapy's rdpcap / PcapReader."""
        try:
            from scapy.all import PcapReader as ScapyReader, IP, IPv6, TCP, UDP, ICMP, DNS, Raw  # type: ignore
        except ImportError:
            raise ImportError(
                "Scapy is not installed in the environment. "
                "Use NativePcapReader or run 'pip install scapy'."
            )

        packet_num = 0
        with ScapyReader(str(self.file_path)) as reader:
            for pkt in reader:
                if max_packets is not None and packet_num >= max_packets:
                    break
                packet_num += 1

                try:
                    ts = float(pkt.time)
                    pkt_len = len(pkt)
                    src_ip = None
                    dst_ip = None
                    proto = "Other"
                    transport = None
                    src_port = None
                    dst_port = None
                    flags = None
                    dns_q = None
                    dns_a = None
                    http_h = None
                    http_m = None
                    tls_i = None

                    if pkt.haslayer(IP):
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        proto = "IPv4"
                    elif pkt.haslayer(IPv6):
                        src_ip = pkt[IPv6].src
                        dst_ip = pkt[IPv6].dst
                        proto = "IPv6"

                    if pkt.haslayer(TCP):
                        proto = "TCP"
                        transport = "TCP"
                        tcp = pkt[TCP]
                        src_port = tcp.sport
                        dst_port = tcp.dport
                        flags = {
                            "FIN": bool(tcp.flags & 0x01),
                            "SYN": bool(tcp.flags & 0x02),
                            "RST": bool(tcp.flags & 0x04),
                            "PSH": bool(tcp.flags & 0x08),
                            "ACK": bool(tcp.flags & 0x10),
                            "URG": bool(tcp.flags & 0x20),
                        }
                    elif pkt.haslayer(UDP):
                        proto = "UDP"
                        transport = "UDP"
                        udp = pkt[UDP]
                        src_port = udp.sport
                        dst_port = udp.dport
                    elif pkt.haslayer(ICMP):
                        proto = "ICMP"
                        transport = "ICMP"

                    # DNS layer check
                    if pkt.haslayer(DNS):
                        proto = "DNS"
                        dns = pkt[DNS]
                        if dns.qd and hasattr(dns.qd, "qname"):
                            dns_q = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")

                    # Payload heuristics for HTTP & TLS
                    if pkt.haslayer(Raw):
                        raw_data = bytes(pkt[Raw])
                        http_res = dissect_http(raw_data)
                        if http_res:
                            proto = "HTTP"
                            http_m = http_res.get("method")
                            http_h = http_res.get("host")

                        tls_res = dissect_tls(raw_data)
                        if tls_res:
                            proto = "TLS"
                            tls_i = tls_res

                    yield PacketRecord(
                        packet_number=packet_num,
                        timestamp=ts,
                        packet_length=pkt_len,
                        protocol=proto,
                        transport_protocol=transport,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        source_port=src_port,
                        destination_port=dst_port,
                        flags=flags,
                        dns_query=dns_q,
                        dns_response=dns_a,
                        http_host=http_h,
                        http_method=http_m,
                        tls_information=tls_i,
                    )
                except Exception as exc:
                    self.parsing_errors.append(f"Scapy error on packet #{packet_num}: {exc}")
                    continue


class PySharkPcapReader(BasePcapReader):
    """PyShark-backed PCAP reader for deep protocol Wireshark dissection."""

    def read_packets(self, max_packets: Optional[int] = None) -> Iterator[PacketRecord]:
        """Read packets using PyShark FileCapture."""
        try:
            import pyshark  # type: ignore
        except ImportError:
            raise ImportError(
                "PyShark is not installed or tshark is missing. "
                "Run 'pip install pyshark' and install Wireshark/tshark."
            )

        cap = pyshark.FileCapture(str(self.file_path), keep_packets=False)
        packet_num = 0
        try:
            for pkt in cap:
                if max_packets is not None and packet_num >= max_packets:
                    break
                packet_num += 1
                try:
                    ts = float(pkt.sniff_timestamp)
                    pkt_len = int(pkt.length)
                    src_ip = getattr(pkt.ip, "src", None) if hasattr(pkt, "ip") else None
                    dst_ip = getattr(pkt.ip, "dst", None) if hasattr(pkt, "ip") else None
                    highest_layer = pkt.highest_layer

                    src_port = None
                    dst_port = None
                    transport = None
                    flags = None

                    if hasattr(pkt, "tcp"):
                        transport = "TCP"
                        src_port = int(pkt.tcp.srcport)
                        dst_port = int(pkt.tcp.dstport)
                    elif hasattr(pkt, "udp"):
                        transport = "UDP"
                        src_port = int(pkt.udp.srcport)
                        dst_port = int(pkt.udp.dstport)

                    dns_q = None
                    if hasattr(pkt, "dns") and hasattr(pkt.dns, "qry_name"):
                        dns_q = str(pkt.dns.qry_name)

                    http_h = None
                    http_m = None
                    if hasattr(pkt, "http"):
                        http_h = getattr(pkt.http, "host", None)
                        http_m = getattr(pkt.http, "request_method", None)

                    tls_i = None
                    if hasattr(pkt, "tls"):
                        tls_i = {"version": getattr(pkt.tls, "record_version", "TLS")}

                    yield PacketRecord(
                        packet_number=packet_num,
                        timestamp=ts,
                        packet_length=pkt_len,
                        protocol=highest_layer,
                        transport_protocol=transport,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        source_port=src_port,
                        destination_port=dst_port,
                        flags=flags,
                        dns_query=dns_q,
                        http_host=http_h,
                        http_method=http_m,
                        tls_information=tls_i,
                    )
                except Exception as exc:
                    self.parsing_errors.append(f"PyShark error on packet #{packet_num}: {exc}")
                    continue
        finally:
            cap.close()


def get_pcap_reader(
    file_path: Union[str, Path], preferred_engine: str = "auto"
) -> BasePcapReader:
    """Factory creating the appropriate PCAP reader engine.

    Engine selection precedence:
    - 'scapy': Uses Scapy if installed; falls back to Native if missing.
    - 'pyshark': Uses PyShark if installed; falls back to Native if missing.
    - 'native': Explicitly uses high-performance zero-dependency Native reader.
    - 'auto': Checks if Scapy is present. If present, Scapy is available; however,
              Native reader is chosen by default for guaranteed speed and zero overhead,
              seamlessly falling back or switching per user preference.
    """
    path = Path(file_path)

    if preferred_engine == "scapy":
        try:
            import scapy.all  # noqa: F401
            return ScapyPcapReader(path)
        except ImportError:
            logger.warning("Scapy requested but not installed. Falling back to Native reader.")
            return NativePcapReader(path)

    if preferred_engine == "pyshark":
        try:
            import pyshark  # noqa: F401
            return PySharkPcapReader(path)
        except ImportError:
            logger.warning("PyShark requested but not installed. Falling back to Native reader.")
            return NativePcapReader(path)

    # Default: Native pure-Python reader for robust zero-dependency execution
    return NativePcapReader(path)
