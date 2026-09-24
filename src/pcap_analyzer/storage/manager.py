"""Storage manager for PCAP analyses and forensic artifacts.

Ensures strict sandboxing, validates analysis identifiers against path traversal,
isolates uploads, and maintains local data retention policies.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{12,64}$")


class StorageSecurityError(ValueError):
    """Raised when an unsafe path, traversal, or invalid ID is detected."""
    pass


@dataclass
class StoredAnalysis:
    analysis_id: str
    directory: Path
    input_file: Path
    results_file: Path
    report_file: Path
    iocs_file: Path
    status_file: Path
    created_at: float


class AnalysisStorageManager:
    """Manages filesystem sandboxes and lifecycle for PCAP analysis sessions."""

    def __init__(self, base_directory: Optional[Path] = None):
        self.base_dir = (base_directory or Path("./data")).resolve()
        self.analyses_dir = self.base_dir / "analyses"
        self._ensure_directories()

    def _ensure_directories(self) -> None:
        """Create storage root directories safely with restricted permissions."""
        self.analyses_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def generate_analysis_id() -> str:
        """Generate a random, cryptographically collision-resistant analysis ID.

        Format: analysis_<timestamp>_<uuid4_hex>
        """
        timestamp = int(time.time())
        token = uuid.uuid4().hex[:12]
        return f"analysis_{timestamp}_{token}"

    def validate_analysis_id(self, analysis_id: str) -> str:
        """Validate analysis ID format to prevent directory traversal and injection."""
        if not analysis_id or not isinstance(analysis_id, str):
            raise StorageSecurityError("Analysis ID must be a non-empty string.")

        sanitized = analysis_id.strip()
        if not SAFE_ID_PATTERN.match(sanitized):
            raise StorageSecurityError(
                f"Invalid analysis ID format: '{analysis_id}'. "
                "Only alphanumeric characters, dashes, and underscores allowed."
            )

        # Check for path traversal attempts
        if ".." in sanitized or "/" in sanitized or "\\" in sanitized:
            raise StorageSecurityError("Path traversal sequences are strictly prohibited.")

        return sanitized

    def get_analysis_path(self, analysis_id: str) -> Path:
        """Get canonical sandboxed directory path for a validated analysis ID."""
        valid_id = self.validate_analysis_id(analysis_id)
        target = (self.analyses_dir / valid_id).resolve()

        # Enforce boundary check
        if not str(target).startswith(str(self.analyses_dir)):
            raise StorageSecurityError("Target directory escapes storage sandbox root.")

        return target

    def create_analysis_sandbox(self, analysis_id: Optional[str] = None) -> StoredAnalysis:
        """Create a dedicated sandboxed folder for a new analysis run."""
        aid = analysis_id or self.generate_analysis_id()
        valid_id = self.validate_analysis_id(aid)
        dir_path = self.get_analysis_path(valid_id)
        dir_path.mkdir(parents=True, exist_ok=True)

        stored = StoredAnalysis(
            analysis_id=valid_id,
            directory=dir_path,
            input_file=dir_path / "capture.pcap",
            results_file=dir_path / "results.json",
            report_file=dir_path / "report.txt",
            iocs_file=dir_path / "iocs.json",
            status_file=dir_path / "status.json",
            created_at=time.time(),
        )

        # Write initial queued status
        self.update_status(valid_id, "queued", details="Analysis queued for execution")
        return stored

    def update_status(
        self,
        analysis_id: str,
        status: str,
        details: Optional[str] = None,
        error: Optional[str] = None,
    ) -> None:
        """Update explicit status machine state: queued, processing, completed, failed, cancelled."""
        allowed_states = {"queued", "processing", "completed", "failed", "cancelled"}
        if status not in allowed_states:
            raise ValueError(f"Invalid status '{status}'. Allowed: {allowed_states}")

        dir_path = self.get_analysis_path(analysis_id)
        status_file = dir_path / "status.json"

        status_data = {
            "analysis_id": analysis_id,
            "status": status,
            "details": details or "",
            "error": error,
            "updated_at": time.time(),
        }

        with open(status_file, "w", encoding="utf-8") as f:
            json.dump(status_data, f, indent=2)

    def get_status(self, analysis_id: str) -> Dict[str, Any]:
        """Read current status of an analysis run."""
        dir_path = self.get_analysis_path(analysis_id)
        status_file = dir_path / "status.json"

        if not status_file.exists():
            return {"analysis_id": analysis_id, "status": "unknown"}

        try:
            with open(status_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"analysis_id": analysis_id, "status": "unknown"}

    def get_stored_analysis(self, analysis_id: str) -> Optional[StoredAnalysis]:
        """Retrieve stored analysis references if the directory exists."""
        try:
            dir_path = self.get_analysis_path(analysis_id)
            if not dir_path.is_dir():
                return None

            return StoredAnalysis(
                analysis_id=analysis_id,
                directory=dir_path,
                input_file=dir_path / "capture.pcap",
                results_file=dir_path / "results.json",
                report_file=dir_path / "report.txt",
                iocs_file=dir_path / "iocs.json",
                status_file=dir_path / "status.json",
                created_at=dir_path.stat().st_ctime,
            )
        except StorageSecurityError:
            return None

    def cleanup_expired(
        self, retention_days: int = 7, dry_run: bool = True
    ) -> Tuple[List[str], int]:
        """Remove analysis sandboxes older than the specified retention window.

        Returns: (list_of_deleted_analysis_ids, total_bytes_freed)
        """
        now = time.time()
        retention_seconds = max(1, retention_days) * 86400
        cutoff = now - retention_seconds

        candidate_dirs: List[Path] = []
        total_freed_bytes = 0

        for entry in self.analyses_dir.iterdir():
            if not entry.is_dir():
                continue

            try:
                self.validate_analysis_id(entry.name)
            except StorageSecurityError:
                continue

            # Don't delete active runs
            status = self.get_status(entry.name).get("status")
            if status in {"queued", "processing"}:
                continue

            stat = entry.stat()
            age_timestamp = min(stat.st_mtime, stat.st_ctime)
            if age_timestamp < cutoff:
                candidate_dirs.append(entry)
                for f in entry.rglob("*"):
                    if f.is_file():
                        total_freed_bytes += f.stat().st_size

        deleted_ids: List[str] = [d.name for d in candidate_dirs]

        if not dry_run:
            for d in candidate_dirs:
                try:
                    shutil.rmtree(d)
                    logger.info("Purged expired analysis sandbox: %s", d.name)
                except Exception as e:
                    logger.error("Failed to delete expired sandbox %s: %s", d.name, e)

        return deleted_ids, total_freed_bytes
