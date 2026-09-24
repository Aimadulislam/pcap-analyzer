"""Command-line interface for the Automated PCAP Analyzer and Threat Parser."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
import sys
from typing import Optional

from .analyzer import PCAPAnalyzer
from .config import AnalysisConfig
from .utils import format_bytes, format_duration


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configure structured console logging."""
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    fmt = "[%(asctime)s] %(levelname)-8s %(name)s: %(message)s"
    logging.basicConfig(level=level, format=fmt, datefmt="%H:%M:%S")


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="pcap-analyzer",
        description="Automated Python PCAP Analyzer & Threat Parser (Stage 2 Network Forensics)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # Analyze a capture file and display summary in console:
  python3 -m pcap_analyzer capture.pcap

  # Analyze using a specific environment-aware profile (e.g. home_lab or enterprise):
  python3 -m pcap_analyzer capture.pcap --profile home_lab

  # Extract IOCs and write structured JSON:
  python3 -m pcap_analyzer -i capture.pcap -o analysis.json --iocs iocs.json

  # Generate full human-readable investigation report:
  python3 -m pcap_analyzer -i capture.pcap -r report.txt
""",
    )

    parser.add_argument(
        "pcap_file",
        nargs="?",
        help="Path to the PCAP or PCAPNG capture file to analyze.",
    )
    parser.add_argument(
        "-i", "--input",
        dest="input_file",
        help="Alternative flag to specify input capture file path.",
    )
    parser.add_argument(
        "-o", "--output", "--json",
        dest="json_output",
        help="Path to write structured JSON analysis report.",
    )
    parser.add_argument(
        "-r", "--report",
        dest="report_output",
        help="Path to write 12-section human-readable investigation report (.txt).",
    )
    parser.add_argument(
        "--iocs",
        dest="iocs_output",
        help="Path to write extracted Indicators of Compromise (IOCs) JSON file.",
    )
    parser.add_argument(
        "-p", "--profile",
        choices=["default", "home_lab", "enterprise", "high_volume"],
        default="default",
        help="Environment-aware detection profile: default, home_lab, enterprise, high_volume.",
    )
    parser.add_argument(
        "-c", "--config",
        dest="config_file",
        help="Path to custom JSON configuration file overriding detection thresholds.",
    )
    parser.add_argument(
        "--hash",
        action="store_true",
        help="Explicitly print the capture file SHA-256 integrity hash in console.",
    )
    parser.add_argument(
        "--engine",
        choices=["auto", "native", "scapy", "pyshark"],
        default="auto",
        help="Packet dissection engine: 'auto' (default), 'native', 'scapy', or 'pyshark'.",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=None,
        help="Limit number of packets parsed (useful for massive capture triage).",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug logging.",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress console progress banners; output errors only.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="Automated Python PCAP Analyzer & Threat Parser v2.0.0",
    )

    return parser


def print_cli_summary(analyzer: PCAPAnalyzer, show_hash: bool = False) -> None:
    """Print an attractive, clean terminal summary after execution."""
    res = analyzer.result
    meta = res.metadata
    summary = res.summary
    findings = res.findings
    iocs = res.iocs

    print("\n" + "=" * 70)
    print(" PCAP Threat Analysis Complete")
    print("=" * 70)
    print(f" Target File:       {meta.file_name}")
    print(f" Profile:           {meta.profile_name} [{meta.profile_source}]")
    if show_hash or meta.sha256_hash:
        print(f" SHA-256 Hash:      {meta.sha256_hash}")
    print(f" Total Packets:     {meta.packet_count:,}")
    print(f" Total Bytes:       {format_bytes(summary.total_bytes)}")
    print(f" Duration:          {format_duration(meta.duration_seconds)}")
    print(f" Engine Used:       {meta.parser_engine} v{meta.analyzer_version}")
    print(f" Unique Endpoints:  {summary.unique_source_ips} Sources -> {summary.unique_destination_ips} Destinations")
    print(f" Active Flows:      {summary.unique_conversations}")
    print(f" Extracted IOCs:    {len(iocs.get('ips', []))} IPs | {len(iocs.get('domains', []))} Domains | {len(iocs.get('urls', []))} URLs")
    print("-" * 70)

    # Findings Breakdown
    print(f" Security Findings: {len(findings)}")
    if findings:
        for idx, f in enumerate(findings, 1):
            tag = f"[{f.severity.value}]"
            print(f"  {idx:02d}. {tag:<10} {f.title}")
            if f.source_ip:
                print(f"      Source:      {f.source_ip}")
            print(f"      Rule ID:     {f.rule_id} ({f.category})")
            print(f"      Confidence:  {f.confidence:.2f}")
            if f.packet_numbers:
                p_preview = ", ".join(map(str, f.packet_numbers[:5]))
                if len(f.packet_numbers) > 5:
                    p_preview += "..."
                print(f"      Packet(s):   {p_preview}")
    else:
        print("  [OK] No anomalous behaviors or security alerts detected.")

    print("=" * 70 + "\n")


def main(argv: Optional[list[str]] = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    target_path = args.input_file or args.pcap_file
    if not target_path:
        parser.print_help()
        print("\nError: Please provide a capture file via positional argument or -i/--input.", file=sys.stderr)
        return 1

    input_file = Path(target_path)
    if not input_file.exists():
        print(f"\nError: Specified file does not exist: {input_file}", file=sys.stderr)
        return 1

    setup_logging(verbose=args.verbose, quiet=args.quiet)

    # Initialize configuration: Profile or custom config file
    if args.config_file:
        try:
            config = AnalysisConfig.from_file(args.config_file)
        except Exception as exc:
            print(f"Error loading configuration file: {exc}", file=sys.stderr)
            return 1
    elif args.profile:
        try:
            config = AnalysisConfig.from_profile(args.profile)
        except Exception as exc:
            print(f"Error loading profile '{args.profile}': {exc}", file=sys.stderr)
            return 1
    else:
        config = AnalysisConfig()

    config.preferred_engine = args.engine
    config.max_packets_to_parse = args.max_packets
    config.verbose_logging = args.verbose

    try:
        analyzer = PCAPAnalyzer(input_file, config=config)
        analyzer.analyze()

        if not args.quiet:
            print_cli_summary(analyzer, show_hash=args.hash)

        # Output JSON if requested
        if args.json_output:
            analyzer.export_json(args.json_output)
            if not args.quiet:
                print(f"[*] Structured JSON written to: {args.json_output}")

        # Output Report if requested
        if args.report_output:
            analyzer.export_report(args.report_output)
            if not args.quiet:
                print(f"[*] Human-readable report written to: {args.report_output}")

        # Output IOCs if requested
        if args.iocs_output:
            analyzer.export_iocs(args.iocs_output)
            if not args.quiet:
                print(f"[*] Extracted IOCs written to: {args.iocs_output}")

        return 0

    except Exception as exc:
        logging.exception("Fatal analysis failure: %s", exc)
        print(f"\nFatal error during analysis: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
