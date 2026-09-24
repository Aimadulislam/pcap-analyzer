"""Automated Python PCAP Analyzer & Threat Parser.

A professional defensive-security and network-forensics package for offline PCAP/PCAPNG
packet parsing, protocol statistics, conversation flow analysis, and rule-based threat detection.
"""

from .analyzer import PCAPAnalyzer
from .config import AnalysisConfig, DetectionConfig
from .detections import DetectionEngine
from .models import (
    AlertFinding,
    AnalysisResult,
    CaptureMetadata,
    FlowRecord,
    PacketRecord,
    Severity,
    TrafficStatistics,
)
from .parser import BasePcapReader, NativePcapReader, get_pcap_reader
from .reporting import JsonReporter, TextReporter
from .statistics import StatisticsEngine

__version__ = "1.0.0"
__author__ = "Cybersecurity Engineering Portfolio"

__all__ = [
    "PCAPAnalyzer",
    "AnalysisConfig",
    "DetectionConfig",
    "DetectionEngine",
    "AlertFinding",
    "AnalysisResult",
    "CaptureMetadata",
    "FlowRecord",
    "PacketRecord",
    "Severity",
    "TrafficStatistics",
    "BasePcapReader",
    "NativePcapReader",
    "get_pcap_reader",
    "JsonReporter",
    "TextReporter",
    "StatisticsEngine",
    "__version__",
]
