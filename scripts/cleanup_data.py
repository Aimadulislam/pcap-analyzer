#!/usr/bin/env python3
"""Data retention cleanup utility for PCAP analyzer.

Removes old analysis runs and temporary forensic files older than the configured
retention period (default: 7 days).

Usage:
    python3 scripts/cleanup_data.py --dry-run
    python3 scripts/cleanup_data.py --execute --retention-days 14
"""

import argparse
import logging
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pcap_analyzer.storage.manager import AnalysisStorageManager


def format_bytes(size: int) -> str:
    """Format byte count into human-readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Clean up expired PCAP analysis artifacts and temporary files."
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=7,
        help="Retention window in days (default: 7)",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default="./data",
        help="Root path to analysis data directory (default: ./data)",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Simulate cleanup without deleting any files (default)",
    )
    mode_group.add_argument(
        "--execute",
        action="store_true",
        help="Perform actual deletion of expired analysis directories",
    )

    args = parser.parse_args()
    dry_run = not args.execute

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    storage = AnalysisStorageManager(Path(args.data_dir))
    print("=" * 60)
    print("PCAP Threat Analyzer - Data Retention Cleanup")
    print(f"Data Directory:  {storage.base_dir}")
    print(f"Retention Days:  {args.retention_days}")
    print(f"Execution Mode:  {'DRY-RUN (Simulated)' if dry_run else 'ACTIVE EXECUTION'}")
    print("=" * 60)

    deleted_ids, freed_bytes = storage.cleanup_expired(
        retention_days=args.retention_days, dry_run=dry_run
    )

    if not deleted_ids:
        print("\n[OK] No expired analysis records found exceeding retention policy.")
        return 0

    print(f"\nIdentified {len(deleted_ids)} expired analysis session(s):")
    for aid in deleted_ids:
        print(f"  - {aid}")

    print("-" * 60)
    if dry_run:
        print(
            f"[DRY-RUN] Would remove {len(deleted_ids)} directories, freeing approximately {format_bytes(freed_bytes)}."
        )
        print("To permanently delete these records, re-run with --execute.")
    else:
        print(
            f"[PURGED] Successfully removed {len(deleted_ids)} directories, freed {format_bytes(freed_bytes)}."
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
