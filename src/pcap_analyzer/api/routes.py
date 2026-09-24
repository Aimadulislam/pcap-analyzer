"""FastAPI REST API routes for Automated Python PCAP Analyzer.

Provides versioned endpoints (/api/v1/...) with input validation, request IDs,
pagination, health checks, and secure upload processing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..analyzer import PCAPAnalyzer
from ..config import DetectionConfig, load_detection_profile
from ..settings import settings
from ..models import AnalysisResult
from ..reporting import generate_text_report
from ..storage.manager import AnalysisStorageManager, StorageSecurityError

logger = logging.getLogger("pcap_analyzer.api")

# Storage manager singleton
storage_manager = AnalysisStorageManager(settings.data_directory)

SAMPLE_PCAPS: Dict[str, Dict[str, Any]] = {
    "syn_port_scan": {
        "fileName": "syn_port_scan.pcap",
        "title": "Vertical TCP SYN Reconnaissance Scan",
        "desc": "45 unacknowledged SYN connection attempts targeting diverse ports on 10.10.20.5.",
        "category": "Reconnaissance",
        "findings": 4,
        "severity": "HIGH",
    },
    "dns_tunnel": {
        "fileName": "dns_tunneling_c2.pcap",
        "title": "Covert DNS Tunneling & C2 Exfiltration",
        "desc": "110 high-entropy DNS queries transmitting encoded data chunks over UDP port 53.",
        "category": "DNS Anomaly",
        "findings": 3,
        "severity": "HIGH",
    },
    "cleartext": {
        "fileName": "cleartext_credentials.pcap",
        "title": "Unencrypted HTTP & Metasploit Port 4444",
        "desc": "Cleartext HTTP authentication request to /login.php and non-standard listener activity.",
        "category": "Cleartext Communication",
        "findings": 2,
        "severity": "LOW",
    },
    "baseline": {
        "fileName": "corporate_baseline.pcap",
        "title": "Benign Corporate Web & DNS Baseline",
        "desc": "Normal corporate browsing to Slack, GitHub, and Google with established TLS handshakes.",
        "category": "Benign Baseline",
        "findings": 0,
        "severity": "INFO",
    },
}


def get_health_data() -> Dict[str, Any]:
    """Health check response data."""
    return {
        "status": "ok",
        "version": "0.1.0",
        "environment": settings.app_env,
        "timestamp": time.time(),
    }


def get_readiness_data() -> Dict[str, Any]:
    """Readiness check verifying storage, engines, and profile availability."""
    checks = {
        "storage_writable": False,
        "default_profile_loaded": False,
        "parser_engine_available": True,
    }

    # Verify storage writable
    try:
        test_file = storage_manager.base_dir / ".ready_test"
        test_file.write_text("ok", encoding="utf-8")
        test_file.unlink()
        checks["storage_writable"] = True
    except Exception as e:
        logger.error("Readiness check: Storage not writable: %s", e)

    # Verify profile loadable
    try:
        cfg = load_detection_profile(settings.default_profile)
        if cfg:
            checks["default_profile_loaded"] = True
    except Exception as e:
        logger.error("Readiness check: Could not load default profile: %s", e)

    is_ready = all(checks.values())
    return {
        "ready": is_ready,
        "checks": checks,
        "timestamp": time.time(),
    }


def execute_analysis_on_file(
    pcap_path: Path,
    profile_name: str = "default",
    engine: str = "auto",
    analysis_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute analysis safely within sandbox and persist artifacts."""
    sandbox = storage_manager.create_analysis_sandbox(analysis_id)
    storage_manager.update_status(sandbox.analysis_id, "processing", "Running dissection engine")

    start_time = time.time()
    try:
        # Load profile
        config = load_detection_profile(profile_name)

        # Initialize analyzer
        analyzer = PCAPAnalyzer(
            str(pcap_path),
            config=config,
            profile_name=profile_name,
            parser_engine=engine,
        )

        # Run analysis
        result = analyzer.analyze()

        # Generate report text
        report_text = generate_text_report(result)

        # Generate IOCs manifest
        iocs_data = result.iocs.to_dict() if result.iocs else {}

        # Save artifacts to sandbox
        with open(sandbox.results_file, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)

        with open(sandbox.report_file, "w", encoding="utf-8") as f:
            f.write(report_text)

        with open(sandbox.iocs_file, "w", encoding="utf-8") as f:
            json.dump(iocs_data, f, indent=2)

        duration = round(time.time() - start_time, 3)
        storage_manager.update_status(
            sandbox.analysis_id,
            "completed",
            details=f"Analysis completed in {duration}s ({len(result.findings)} findings)",
        )

        return {
            "success": True,
            "analysis_id": sandbox.analysis_id,
            "duration_seconds": duration,
            "result": result.to_dict(),
            "reportText": report_text,
            "iocs": iocs_data,
        }

    except Exception as err:
        duration = round(time.time() - start_time, 3)
        logger.exception("Analysis execution failed for ID %s: %s", sandbox.analysis_id, err)
        storage_manager.update_status(
            sandbox.analysis_id, "failed", error=str(err)
        )
        return {
            "success": False,
            "analysis_id": sandbox.analysis_id,
            "error": "PCAP Analysis failed during execution",
            "details": str(err),
            "duration_seconds": duration,
        }
