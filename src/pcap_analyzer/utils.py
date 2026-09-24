"""Utility functions for network protocol analysis, formatting, and entropy calculations."""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import math
from typing import Optional


COMMON_PORT_NAMES: dict[int, str] = {
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS/TLS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP-Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1337: "Suspicious-Elite",
    1433: "MSSQL",
    1521: "Oracle",
    2323: "Telnet-Alt",
    3128: "Squid-Proxy",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit-Default",
    4445: "Metasploit-Alt",
    5060: "SIP",
    5432: "PostgreSQL",
    5555: "ADB-Trojan-Alt",
    5900: "VNC",
    6379: "Redis",
    6667: "IRC",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt2",
    9000: "SonarQube/PHP-FPM",
    9200: "Elasticsearch",
    9999: "Urchin/Trojan-Alt",
    27017: "MongoDB",
    31337: "Back-Orifice",
}


def get_port_service_name(port: Optional[int]) -> str:
    """Return a descriptive service name for a given TCP/UDP port number."""
    if port is None:
        return "Unknown"
    return COMMON_PORT_NAMES.get(port, str(port))


def format_bytes(num_bytes: int) -> str:
    """Format byte count into human-readable representation (B, KB, MB, GB)."""
    if num_bytes < 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(num_bytes)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{num_bytes} B"


def format_duration(seconds: float) -> str:
    """Format duration in seconds to standard HH:MM:SS or HH:MM:SS.mmm format."""
    if seconds < 0:
        seconds = 0.0
    total_seconds = int(seconds)
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    secs = total_seconds % 60
    millis = int((seconds - total_seconds) * 1000)
    if hours > 0:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}.{millis:03d}"


def format_timestamp_iso(timestamp: Optional[float]) -> str:
    """Format epoch timestamp to ISO 8601 UTC string."""
    if timestamp is None or timestamp == 0.0:
        return "N/A"
    try:
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OSError):
        return f"{timestamp:.4f}"


def calculate_shannon_entropy(data_str: str) -> float:
    """Calculate the Shannon entropy of a string (bits per symbol).

    Used in network security to detect algorithmically generated domains (DGAs),
    encrypted payloads, or Base64 / hex-encoded DNS tunneling exfiltration.

    Args:
        data_str: Input ASCII string (e.g. domain name or subdomain label).

    Returns:
        Shannon entropy value between 0.0 and 8.0.
    """
    if not data_str:
        return 0.0
    length = len(data_str)
    freq: dict[str, int] = {}
    for char in data_str:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy


def classify_ip(ip_str: Optional[str]) -> str:
    """Classify an IP address into Private, Public, Loopback, Link-Local, or Multicast."""
    if not ip_str:
        return "Unknown"
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback:
            return "Loopback"
        if ip.is_private:
            return "Private (RFC 1918 / ULA)"
        if ip.is_multicast:
            return "Multicast"
        if ip.is_link_local:
            return "Link-Local"
        return "Public"
    except ValueError:
        return "Invalid IP"
