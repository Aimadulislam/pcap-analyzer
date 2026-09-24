"""Configuration module for PCAP Analyzer and Threat Detection Engine.

All detection thresholds and heuristic parameters are defined here to avoid
hardcoding values throughout the codebase. Thresholds can be loaded from
built-in environment profiles (default, home_lab, enterprise, high_volume)
or customized via JSON configuration files.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


@dataclass
class DetectionConfig:
    """Configurable heuristic thresholds for threat detection rules."""

    profile_name: str = "default"
    profile_description: str = "Standard defensive SOC baseline for mixed enterprise and lab traffic."

    # RULE 001: Scanning Detection (Vertical, Horizontal, and Hybrid)
    syn_scan_unique_port_threshold: int = 20
    syn_scan_unique_host_threshold: int = 15
    syn_scan_min_packets: int = 25
    syn_scan_completion_ratio_max: float = 0.20

    # Connection Flooding
    connection_flood_rate_threshold: float = 80.0
    connection_flood_min_packets: int = 120

    # Unusual Ports
    unusual_ports: List[int] = field(default_factory=lambda: [
        1337,   # Elite / Backdoors
        31337,  # Back Orifice
        4444,   # Metasploit default listener
        4445,   # Metasploit alternative
        5555,   # Android ADB / Trojan
        6667,   # IRC C2 communication
        8888,   # Alternative HTTP / Proxy
        9999,   # Urchin / Trojan
        12345,  # NetBus
        2323,   # Telnet alternative / IoT botnets
    ])
    unusual_port_packet_threshold: int = 2

    # DNS Heuristics
    dns_query_volume_threshold: int = 100
    dns_query_rate_threshold: float = 20.0
    dns_suspicious_length_threshold: int = 50
    dns_high_entropy_threshold: float = 3.85
    dns_unique_domains_threshold: int = 40
    dns_tunneling_min_label_length: int = 24

    # HTTP Heuristics
    http_uri_max_length: int = 256
    http_uncommon_ports: List[int] = field(default_factory=lambda: [
        8080, 8000, 8888, 8880, 3000, 5000
    ])

    # TLS Heuristics
    tls_uncommon_ports: List[int] = field(default_factory=lambda: [
        8443, 9443, 4433, 10443
    ])

    # Repeated Connection Failures
    failed_connection_threshold: int = 25

    # ICMP Volume
    icmp_volume_threshold: int = 80
    icmp_rate_threshold: float = 15.0

    # Cleartext Protocols
    cleartext_protocols: List[str] = field(default_factory=lambda: [
        "HTTP",
        "FTP",
        "TELNET",
        "POP3",
        "IMAP",
    ])

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return asdict(self)


# Built-in environment-aware profile parameter tables
PROFILE_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "default": {
        "profile_name": "default",
        "profile_description": "Balanced SOC detection profile suited for general network forensic investigations.",
        "syn_scan_unique_port_threshold": 20,
        "syn_scan_unique_host_threshold": 15,
        "syn_scan_min_packets": 25,
        "syn_scan_completion_ratio_max": 0.20,
        "dns_query_volume_threshold": 100,
        "dns_suspicious_length_threshold": 50,
        "dns_high_entropy_threshold": 3.85,
        "dns_unique_domains_threshold": 40,
        "icmp_volume_threshold": 80,
        "failed_connection_threshold": 25,
    },
    "home_lab": {
        "profile_name": "home_lab",
        "profile_description": "Sensitive profile for low-traffic homelabs, student labs, and developer testbeds.",
        "syn_scan_unique_port_threshold": 6,
        "syn_scan_unique_host_threshold": 4,
        "syn_scan_min_packets": 8,
        "syn_scan_completion_ratio_max": 0.35,
        "dns_query_volume_threshold": 30,
        "dns_suspicious_length_threshold": 45,
        "dns_high_entropy_threshold": 3.75,
        "dns_unique_domains_threshold": 15,
        "icmp_volume_threshold": 25,
        "failed_connection_threshold": 8,
    },
    "enterprise": {
        "profile_name": "enterprise",
        "profile_description": "Tuned for busy corporate enterprise segments with higher background volume.",
        "syn_scan_unique_port_threshold": 40,
        "syn_scan_unique_host_threshold": 30,
        "syn_scan_min_packets": 50,
        "syn_scan_completion_ratio_max": 0.15,
        "dns_query_volume_threshold": 500,
        "dns_suspicious_length_threshold": 65,
        "dns_high_entropy_threshold": 4.10,
        "dns_unique_domains_threshold": 150,
        "icmp_volume_threshold": 250,
        "failed_connection_threshold": 60,
    },
    "high_volume": {
        "profile_name": "high_volume",
        "profile_description": "Aggressive filtering for high-throughput datacenter and backbone perimeter captures.",
        "syn_scan_unique_port_threshold": 80,
        "syn_scan_unique_host_threshold": 60,
        "syn_scan_min_packets": 100,
        "syn_scan_completion_ratio_max": 0.10,
        "dns_query_volume_threshold": 2000,
        "dns_suspicious_length_threshold": 75,
        "dns_high_entropy_threshold": 4.25,
        "dns_unique_domains_threshold": 500,
        "icmp_volume_threshold": 1000,
        "failed_connection_threshold": 150,
    },
}


@dataclass
class AnalysisConfig:
    """Master application configuration combining analysis options and detection rules."""
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    max_packets_to_parse: Optional[int] = None
    preferred_engine: str = "auto"  # 'auto', 'native', 'scapy', 'pyshark'
    verbose_logging: bool = False
    include_payload_dumps: bool = False
    profile_source: str = "default"

    @classmethod
    def from_profile(cls, profile_name: str = "default") -> AnalysisConfig:
        """Load an AnalysisConfig initialized with an environment profile."""
        norm_name = profile_name.strip().lower()
        if norm_name in PROFILE_DEFINITIONS:
            params = PROFILE_DEFINITIONS[norm_name]
            det_cfg = DetectionConfig(**params)
            return cls(detection=det_cfg, profile_source=f"built-in ({norm_name})")

        # Check if file exists in config/
        cfg_path = Path("config") / f"{norm_name}.json"
        if cfg_path.is_file():
            cfg = cls.from_file(cfg_path)
            cfg.profile_source = f"file ({cfg_path})"
            return cfg

        raise ValueError(
            f"Unknown profile '{profile_name}'. "
            f"Available profiles: {', '.join(PROFILE_DEFINITIONS.keys())}"
        )

    @classmethod
    def from_file(cls, config_path: Union[str, Path]) -> AnalysisConfig:
        """Load configuration from a JSON file."""
        path = Path(config_path)
        if not path.is_file():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        detection_data = data.get("detection", {})
        detection_config = DetectionConfig(**detection_data)

        app_config = cls(
            detection=detection_config,
            max_packets_to_parse=data.get("max_packets_to_parse"),
            preferred_engine=data.get("preferred_engine", "auto"),
            verbose_logging=data.get("verbose_logging", False),
            include_payload_dumps=data.get("include_payload_dumps", False),
            profile_source=f"custom ({path.name})",
        )
        return app_config

    def save_to_file(self, config_path: Union[str, Path]) -> None:
        """Export current configuration to a formatted JSON file."""
        path = Path(config_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump({
                "detection": self.detection.to_dict(),
                "max_packets_to_parse": self.max_packets_to_parse,
                "preferred_engine": self.preferred_engine,
                "verbose_logging": self.verbose_logging,
                "include_payload_dumps": self.include_payload_dumps,
                "profile_source": self.profile_source,
            }, f, indent=2)
