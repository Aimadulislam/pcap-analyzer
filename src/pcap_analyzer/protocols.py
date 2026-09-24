"""Protocol dissection logic for Ethernet, IP, TCP, UDP, ICMP, DNS, HTTP, and TLS.

Provides pure-Python binary packet dissectors with zero external dependencies,
ensuring fast, deterministic dissection of standard layer headers and payloads.
"""

from __future__ import annotations

import socket
import struct
from typing import Any, Dict, List, Optional, Tuple


# Ethernet EtherTypes
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_IPV6 = 0x86DD

# IP Protocol Numbers
IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17
IP_PROTO_IPV6_ICMP = 58

# Common HTTP Methods
HTTP_METHODS = {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE"}


def dissect_ethernet(data: bytes) -> Tuple[Optional[int], Optional[str], Optional[str], bytes]:
    """Dissect Ethernet II frame header.

    Returns:
        Tuple of (ethertype, src_mac, dst_mac, payload)
    """
    if len(data) < 14:
        return None, None, None, data

    dst_mac = ":".join(f"{b:02x}" for b in data[0:6])
    src_mac = ":".join(f"{b:02x}" for b in data[6:12])
    ethertype = struct.unpack("!H", data[12:14])[0]
    offset = 14

    # Handle 802.1Q VLAN Tagging
    if ethertype == ETHERTYPE_VLAN and len(data) >= 18:
        ethertype = struct.unpack("!H", data[16:18])[0]
        offset = 18

    return ethertype, src_mac, dst_mac, data[offset:]


def dissect_ipv4(data: bytes) -> Tuple[Optional[str], Optional[str], Optional[int], bytes]:
    """Dissect IPv4 header.

    Returns:
        Tuple of (src_ip, dst_ip, protocol_num, payload)
    """
    if len(data) < 20:
        return None, None, None, data

    version_ihl = data[0]
    ihl = (version_ihl & 0x0F) * 4
    if len(data) < ihl or ihl < 20:
        return None, None, None, data

    protocol_num = data[9]
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])

    return src_ip, dst_ip, protocol_num, data[ihl:]


def dissect_ipv6(data: bytes) -> Tuple[Optional[str], Optional[str], Optional[int], bytes]:
    """Dissect IPv6 header.

    Returns:
        Tuple of (src_ip, dst_ip, next_header, payload)
    """
    if len(data) < 40:
        return None, None, None, data

    next_header = data[6]
    src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])

    return src_ip, dst_ip, next_header, data[40:]


def dissect_tcp(data: bytes) -> Tuple[Optional[int], Optional[int], Optional[Dict[str, bool]], bytes]:
    """Dissect TCP header and flag bitmap.

    Returns:
        Tuple of (src_port, dst_port, flags_dict, payload)
    """
    if len(data) < 20:
        return None, None, None, data

    src_port, dst_port, _, _, offset_reserved, flags_byte = struct.unpack("!HHIIBB", data[:14])
    tcp_header_len = (offset_reserved >> 4) * 4

    if len(data) < tcp_header_len or tcp_header_len < 20:
        return None, None, None, data

    flags = {
        "FIN": bool(flags_byte & 0x01),
        "SYN": bool(flags_byte & 0x02),
        "RST": bool(flags_byte & 0x04),
        "PSH": bool(flags_byte & 0x08),
        "ACK": bool(flags_byte & 0x10),
        "URG": bool(flags_byte & 0x20),
        "ECE": bool(flags_byte & 0x40),
        "CWR": bool(flags_byte & 0x80),
    }

    payload = data[tcp_header_len:]
    return src_port, dst_port, flags, payload


def dissect_udp(data: bytes) -> Tuple[Optional[int], Optional[int], bytes]:
    """Dissect UDP header.

    Returns:
        Tuple of (src_port, dst_port, payload)
    """
    if len(data) < 8:
        return None, None, data

    src_port, dst_port, length, _ = struct.unpack("!HHHH", data[:8])
    payload = data[8:length] if length >= 8 and len(data) >= length else data[8:]
    return src_port, dst_port, payload


def dissect_icmp(data: bytes) -> Dict[str, Any]:
    """Dissect ICMP header."""
    if len(data) < 4:
        return {"type": None, "code": None, "name": "Unknown ICMP"}

    icmp_type = data[0]
    icmp_code = data[1]

    names = {
        0: "Echo Reply (Pong)",
        3: "Destination Unreachable",
        5: "Redirect Message",
        8: "Echo Request (Ping)",
        11: "Time Exceeded (TTL expired)",
        13: "Timestamp Request",
        14: "Timestamp Reply",
    }

    return {
        "type": icmp_type,
        "code": icmp_code,
        "name": names.get(icmp_type, f"ICMP Type {icmp_type}"),
    }


def parse_dns_qname(data: bytes, offset: int) -> Tuple[str, int]:
    """Parse RFC 1035 DNS QNAME with label decompression pointers."""
    labels: List[str] = []
    jumped = False
    max_jumps = 5
    jumps = 0
    curr = offset
    original_offset = offset

    while curr < len(data):
        length = data[curr]
        if length == 0:
            curr += 1
            break
        # Pointer check (top two bits set 0xC0)
        if (length & 0xC0) == 0xC0:
            if curr + 1 >= len(data):
                break
            pointer_offset = ((length & 0x3F) << 8) | data[curr + 1]
            if not jumped:
                original_offset = curr + 2
                jumped = True
            curr = pointer_offset
            jumps += 1
            if jumps > max_jumps or curr >= len(data):
                break
            continue
        curr += 1
        if curr + length > len(data):
            break
        try:
            label = data[curr : curr + length].decode("ascii", errors="replace")
            labels.append(label)
        except Exception:
            labels.append("?")
        curr += length

    domain = ".".join(labels)
    final_offset = original_offset if jumped else curr
    return domain, final_offset


def dissect_dns(payload: bytes) -> Optional[Dict[str, Any]]:
    """Dissect DNS payload (RFC 1035).

    Returns:
        Dictionary with query name, query type, answers, response code, or None if invalid.
    """
    if len(payload) < 12:
        return None

    try:
        tx_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", payload[:12])
        is_response = bool(flags & 0x8000)
        rcode = flags & 0x000F

        rcode_map = {
            0: "NOERROR",
            1: "FORMERR",
            2: "SERVFAIL",
            3: "NXDOMAIN",
            4: "NOTIMP",
            5: "REFUSED",
            6: "YXDOMAIN",
            7: "YXRRSET",
            8: "NXRRSET",
            9: "NOTAUTH",
            10: "NOTZONE",
        }
        rcode_str = rcode_map.get(rcode, f"RCODE{rcode}")

        queries: List[str] = []
        qtypes: List[str] = []
        answers: List[str] = []
        offset = 12

        qtype_map = {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            12: "PTR",
            15: "MX",
            16: "TXT",
            28: "AAAA",
            255: "ANY",
        }

        # Parse Questions
        for _ in range(min(qdcount, 10)):
            if offset >= len(payload):
                break
            qname, offset = parse_dns_qname(payload, offset)
            if offset + 4 <= len(payload):
                qtype, _ = struct.unpack("!HH", payload[offset : offset + 4])
                offset += 4
                queries.append(qname)
                qtypes.append(qtype_map.get(qtype, f"TYPE{qtype}"))

        # Parse Answers if present
        if is_response and ancount > 0:
            for _ in range(min(ancount, 10)):
                if offset >= len(payload):
                    break
                _, offset = parse_dns_qname(payload, offset)
                if offset + 10 <= len(payload):
                    atype, _, _, rdlength = struct.unpack("!HHIH", payload[offset : offset + 10])
                    offset += 10
                    if offset + rdlength <= len(payload):
                        rdata = payload[offset : offset + rdlength]
                        if atype == 1 and rdlength == 4:
                            answers.append(socket.inet_ntoa(rdata))
                        elif atype == 28 and rdlength == 16:
                            answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
                        elif atype == 5:
                            cname, _ = parse_dns_qname(payload, offset)
                            answers.append(cname)
                        elif atype == 2:
                            ns_name, _ = parse_dns_qname(payload, offset)
                            answers.append(ns_name)
                        elif atype == 12:
                            ptr_name, _ = parse_dns_qname(payload, offset)
                            answers.append(ptr_name)
                        elif atype == 15 and rdlength > 2:
                            mx_name, _ = parse_dns_qname(payload, offset + 2)
                            answers.append(mx_name)
                        elif atype == 16 and rdlength > 0:
                            # TXT records have one or more <len><text> chunks
                            txt_parts: List[str] = []
                            tofs = 0
                            while tofs < rdlength:
                                tlen = rdata[tofs]
                                tofs += 1
                                if tofs + tlen <= rdlength:
                                    txt_parts.append(rdata[tofs : tofs + tlen].decode("ascii", errors="replace"))
                                tofs += tlen
                            answers.append(" ".join(txt_parts))
                        offset += rdlength

        if not queries and not is_response:
            return None

        return {
            "tx_id": tx_id,
            "is_response": is_response,
            "rcode": rcode,
            "rcode_name": rcode_str,
            "query": queries[0] if queries else None,
            "query_type": qtypes[0] if qtypes else None,
            "all_queries": queries,
            "answers": answers,
        }
    except Exception:
        return None


def dissect_http(payload: bytes) -> Optional[Dict[str, Any]]:
    """Dissect HTTP request or response if present in payload."""
    if len(payload) < 8:
        return None

    try:
        header_end = payload.find(b"\r\n\r\n")
        if header_end == -1:
            header_end = min(len(payload), 1024)
        header_text = payload[:header_end].decode("latin-1", errors="replace")
        lines = header_text.split("\r\n")
        if not lines:
            return None

        first_line = lines[0].strip()
        parts = first_line.split(" ")

        # Check for HTTP Request
        if len(parts) >= 2 and parts[0].encode("ascii", errors="ignore").upper() in HTTP_METHODS:
            method = parts[0].upper()
            uri = parts[1]
            host = None
            user_agent = None
            content_type = None

            for line in lines[1:]:
                if ":" in line:
                    key, val = line.split(":", 1)
                    key_lower = key.strip().lower()
                    if key_lower == "host":
                        host = val.strip()
                    elif key_lower == "user-agent":
                        user_agent = val.strip()
                    elif key_lower == "content-type":
                        content_type = val.strip()

            return {
                "type": "request",
                "method": method,
                "uri": uri,
                "host": host,
                "user_agent": user_agent,
                "content_type": content_type,
                "first_line": first_line,
            }

        # Check for HTTP Response
        if len(parts) >= 2 and parts[0].startswith("HTTP/"):
            try:
                status_code = int(parts[1])
            except ValueError:
                status_code = None

            content_type = None
            for line in lines[1:]:
                if ":" in line:
                    key, val = line.split(":", 1)
                    if key.strip().lower() == "content-type":
                        content_type = val.strip()

            return {
                "type": "response",
                "status_code": status_code,
                "content_type": content_type,
                "first_line": first_line,
            }

    except Exception:
        return None

    return None


def dissect_tls(payload: bytes) -> Optional[Dict[str, Any]]:
    """Dissect TLS Record layer and extract ClientHello Server Name Indication (SNI) and ciphers."""
    if len(payload) < 5:
        return None

    content_type = payload[0]
    # TLS Content Types: 20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=ApplicationData
    if content_type not in (20, 21, 22, 23):
        return None

    major_ver = payload[1]
    minor_ver = payload[2]
    if major_ver != 3:
        return None

    version_map = {
        0x0300: "SSL 3.0",
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
    }
    raw_version = (major_ver << 8) | minor_ver
    version_str = version_map.get(raw_version, f"TLS {major_ver}.{minor_ver}")

    record_length = struct.unpack("!H", payload[3:5])[0]
    sni_hostname: Optional[str] = None
    handshake_type_name: Optional[str] = None
    cipher_info: Optional[str] = None

    # Dissect Handshake if record contains Handshake (22)
    if content_type == 22 and len(payload) >= 9:
        handshake_type = payload[5]
        if handshake_type == 1:
            handshake_type_name = "ClientHello"
            # Attempt to extract SNI and cipher suite count
            try:
                offset = 5 + 4  # Handshake type (1) + length (3)
                if offset + 34 <= len(payload):
                    offset += 2 + 32  # Client version (2) + Random (32)
                    session_id_len = payload[offset]
                    offset += 1 + session_id_len
                    if offset + 2 <= len(payload):
                        cipher_suites_len = struct.unpack("!H", payload[offset : offset + 2])[0]
                        num_ciphers = cipher_suites_len // 2
                        offset += 2
                        if num_ciphers > 0 and offset + 2 <= len(payload):
                            first_cipher = struct.unpack("!H", payload[offset : offset + 2])[0]
                            cipher_info = f"{num_ciphers} suites offered (first: 0x{first_cipher:04x})"
                        offset += cipher_suites_len
                        if offset + 1 <= len(payload):
                            comp_methods_len = payload[offset]
                            offset += 1 + comp_methods_len
                            if offset + 2 <= len(payload):
                                ext_total_len = struct.unpack("!H", payload[offset : offset + 2])[0]
                                offset += 2
                                ext_end = offset + ext_total_len
                                while offset + 4 <= ext_end and offset + 4 <= len(payload):
                                    ext_type, ext_len = struct.unpack("!HH", payload[offset : offset + 4])
                                    offset += 4
                                    # SNI extension type is 0x0000
                                    if ext_type == 0 and offset + ext_len <= len(payload):
                                        # Parse Server Name list
                                        if ext_len > 5:
                                            # list_len (2), name_type (1, 0=hostname), name_len (2)
                                            name_type = payload[offset + 2]
                                            if name_type == 0:
                                                name_len = struct.unpack("!H", payload[offset + 3 : offset + 5])[0]
                                                sni_bytes = payload[offset + 5 : offset + 5 + name_len]
                                                sni_hostname = sni_bytes.decode("ascii", errors="replace")
                                        break
                                    offset += ext_len
            except Exception:
                pass
        elif handshake_type == 2:
            handshake_type_name = "ServerHello"
            try:
                offset = 5 + 4  # Handshake type (1) + length (3)
                if offset + 34 <= len(payload):
                    offset += 2 + 32  # Server version + Random
                    sess_len = payload[offset]
                    offset += 1 + sess_len
                    if offset + 2 <= len(payload):
                        selected_cipher = struct.unpack("!H", payload[offset : offset + 2])[0]
                        cipher_info = f"Selected: 0x{selected_cipher:04x}"
            except Exception:
                pass
        elif handshake_type == 11:
            handshake_type_name = "Certificate"

    return {
        "content_type": content_type,
        "version": version_str,
        "record_length": record_length,
        "handshake_type": handshake_type_name,
        "sni": sni_hostname,
        "cipher": cipher_info,
    }
