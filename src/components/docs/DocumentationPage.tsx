import React, { useState } from "react";
import {
  BookOpen,
  Terminal,
  Shield,
  Layers,
  Sliders,
  Server,
  FileCode,
  Search,
  CheckCircle2,
  Copy,
  Check,
  ExternalLink,
  Cpu,
  AlertTriangle,
  Info,
} from "lucide-react";

interface DocumentationPageProps {
  initialSection?: string;
  onNavigateToConsole: () => void;
}

export const DocumentationPage: React.FC<DocumentationPageProps> = ({
  initialSection = "rules",
  onNavigateToConsole,
}) => {
  const [activeSection, setActiveSection] = useState<string>(initialSection);
  const [copiedCode, setCopiedCode] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>("");

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(id);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  const sections = [
    { id: "overview", label: "Overview & Specs", icon: BookOpen },
    { id: "rules", label: "Detection Rules (11)", icon: Shield },
    { id: "profiles", label: "Configuration Profiles", icon: Sliders },
    { id: "cli", label: "CLI Reference", icon: Terminal },
    { id: "api", label: "REST API Reference", icon: Server },
    { id: "testing", label: "Synthetic Testing & CI", icon: Cpu },
    { id: "triage", label: "Analyst Triage Guide", icon: Search },
  ];

  const rulesList = [
    {
      id: "RULE-001",
      name: "Potential TCP SYN scanning pattern",
      category: "Reconnaissance",
      severity: "HIGH",
      mitre: {
        id: "T1046",
        tactic: "Discovery",
        technique: "Network Service Discovery",
        justification:
          "Targeted transmission of rapid SYN probes across diverse ports/hosts with uncompleted TCP handshakes is the definitive signature of stealth SYN port scanning (e.g. Nmap -sS).",
      },
      thresholds: "unique_ports >= 20 OR unique_hosts >= 15, packets >= 25, completion_ratio <= 15%",
      description:
        "Identifies a single source transmitting TCP SYN packets across numerous ports or hosts with a disproportionately low handshake completion rate.",
      evidence: [
        "syn_packets_transmitted",
        "unique_destination_ports_targeted",
        "unique_destination_hosts_targeted",
        "completed_handshakes",
        "handshake_completion_ratio",
        "sample_targeted_ports",
      ],
      triage:
        "Check source host IP against vulnerability scanner IPs and network inventory. Review firewall logs for dropped TCP probes.",
    },
    {
      id: "RULE-002",
      name: "Potential connection flood",
      category: "Traffic Anomaly",
      severity: "MEDIUM",
      mitre: {
        id: "T1499",
        tactic: "Impact",
        technique: "Endpoint Denial of Service",
        justification:
          "Concentrated volumetric packet surges from a single endpoint intended to exhaust stateful connection tables or network capacity.",
      },
      thresholds: "packet_rate >= 80.0 pkts/sec OR ratio_of_total_capture >= 70%, packets >= 120",
      description:
        "Flags an unusually concentrated surge of packets originating from a single endpoint compared to overall capture duration.",
      evidence: ["packet_count", "packet_rate_per_second", "ratio_of_total_capture"],
      triage:
        "Determine if traffic represents legitimate load testing, automated data sync, or potential DoS / brute-force traffic.",
    },
    {
      id: "RULE-003",
      name: "Unusual destination port activity",
      category: "Security Observation",
      severity: "LOW",
      mitre: {
        id: "T1571",
        tactic: "Command and Control",
        technique: "Non-Standard Port",
        justification:
          "Adversaries frequently configure C2 listeners or backdoors on non-standard ports (e.g. 1337, 4444, 31337) to evade standard port filters.",
      },
      thresholds: "destination_port in [1337, 2323, 4444, 4445, 5555, 6667, 8888, 9999, 31337], packets >= 2",
      description:
        "Detects communications targeting well-known backdoor, Trojan, or C2 framework default listening ports (e.g., Metasploit 4444, IRC 6667, Elite 1337).",
      evidence: ["destination_port", "service_reference", "packet_count", "total_bytes"],
      triage:
        "Isolate participating source host. Inspect active process table for unauthorized remote shell listeners or reverse shells.",
    },
    {
      id: "RULE-004",
      name: "DNS query volume anomaly",
      category: "DNS Anomaly",
      severity: "MEDIUM",
      mitre: {
        id: "T1071.004",
        tactic: "Command and Control",
        technique: "Application Layer Protocol: DNS",
        justification:
          "High query rates and elevated distinct domain resolutions frequently precede C2 communications or indicate active domain enumeration.",
      },
      thresholds: "total_queries >= 100 OR queries_per_sec >= 20.0",
      description:
        "Flags endpoints generating an anomalous query rate or total query volume towards configured recursive resolvers.",
      evidence: ["total_dns_queries", "queries_per_second", "unique_domains_queried"],
      triage:
        "Identify querying process on host. Verify whether endpoint is acting as a local DNS resolver or executing automated lookups.",
    },
    {
      id: "RULE-005",
      name: "Suspicious DNS characteristics (Tunneling / DGA)",
      category: "DNS Anomaly",
      severity: "HIGH",
      mitre: {
        id: "T1572",
        tactic: "Command and Control",
        technique: "Protocol Tunneling",
        justification:
          "DNS tunneling utilities (iodine, dnscat2) and DGAs generate long, high-entropy subdomain strings to encode raw bytes or avoid blacklists.",
      },
      thresholds: "query_length >= 50 OR (subdomain_len >= 12 AND shannon_entropy >= 3.85 bits/symbol)",
      description:
        "Calculates Shannon entropy ($H = -\\sum P(x) \\log_2 P(x)$) of leftmost subdomain labels to detect encoded payload channels and DGA lookups.",
      evidence: ["suspicious_query_count", "sample_queries", "max_entropy_observed"],
      triage:
        "Examine full FQDNs for Base32/Base64/hex encoding. Block anomalous authoritative nameserver domain at perimeter resolver.",
    },
    {
      id: "RULE-006",
      name: "Repeated failed TCP connections",
      category: "Connection Anomaly",
      severity: "MEDIUM",
      mitre: {
        id: "T1046",
        tactic: "Discovery",
        technique: "Network Service Discovery",
        justification:
          "Repeated unanswered connection attempts or RST responses reflect probes encountering closed ports or host-based firewall drops.",
      },
      thresholds: "unestablished_failed_flows >= 25",
      description:
        "Identifies hosts attempting numerous TCP connections where handshakes never complete due to timeouts, drops, or TCP RSTs.",
      evidence: ["failed_connection_count", "unique_failed_targets"],
      triage:
        "Correlate destination IPs with network segments. Determine whether source host has an invalid configuration or is systematically scanning.",
    },
    {
      id: "RULE-007",
      name: "ICMP volume anomaly",
      category: "Traffic Anomaly",
      severity: "MEDIUM",
      mitre: {
        id: "T1048",
        tactic: "Exfiltration",
        technique: "Exfiltration Over Alternative Protocol",
        justification:
          "Anomalously high ICMP packet rates can represent covert tunnel channels (icmpsh), path MTU floods, or active echo sweep reconnaissance.",
      },
      thresholds: "icmp_count >= 80 OR icmp_rate >= 15.0 pkts/sec",
      description:
        "Audits ICMP Echo Requests and Replies for volume anomalies and persistent polling behavior.",
      evidence: ["icmp_packet_count", "icmp_packets_per_sec"],
      triage:
        "Inspect ICMP packet payload sizes. Standard ping payloads are 32–64 bytes; payloads containing repetitive or high-entropy data suggest tunneling.",
    },
    {
      id: "RULE-008",
      name: "Cleartext protocol observation",
      category: "Cleartext Communication",
      severity: "LOW",
      mitre: {
        id: "T1040",
        tactic: "Credential Access",
        technique: "Network Sniffing",
        justification:
          "Unencrypted protocols transmit credentials and session identifiers in plaintext, exposing them to intermediate eavesdropping.",
      },
      thresholds: "Unencrypted protocol ports (80, 21, 23, 110, 143) with payload > 0",
      description:
        "Flags transmission of unencrypted protocols (HTTP, FTP, Telnet, POP3, IMAP) that risk leaking credentials or session tokens.",
      evidence: ["protocol", "packet_count", "observed_hosts", "sensitive_endpoints_accessed"],
      triage:
        "Migrate services to TLS-encrypted equivalents (HTTPS, SFTP, SSH, IMAPS). Audit accessed URIs for credential parameters.",
    },
    {
      id: "RULE-009",
      name: "HTTP security observation",
      category: "HTTP Anomaly",
      severity: "HIGH / LOW",
      mitre: {
        id: "T1595.002",
        tactic: "Reconnaissance",
        technique: "Vulnerability Scanning",
        justification:
          "Known security scanner User-Agent signatures (sqlmap, nikto, nessus, nmap) identify automated web assessment or exploitation attempts.",
      },
      thresholds: "User-Agent matching scanner signatures OR URI length >= 256 OR non-standard method",
      description:
        "Audits HTTP headers for vulnerability scanner User-Agents, excessive URI path lengths (fuzzing/buffer overflow), and unusual verbs.",
      evidence: ["occurrence_count", "signatures_observed", "sample_user_agents", "long_uri_count"],
      triage:
        "Check web server access logs for corresponding 404, 403, or 500 status codes. Verify whether vulnerability scanner was authorized.",
    },
    {
      id: "RULE-010",
      name: "TLS security observation",
      category: "TLS Observation",
      severity: "MEDIUM",
      mitre: {
        id: "T1573",
        tactic: "Command and Control",
        technique: "Encrypted Channel",
        justification:
          "Use of deprecated protocol versions (SSL 3.0, TLS 1.0, TLS 1.1) introduces vulnerabilities to cryptographic downgrade attacks.",
      },
      thresholds: "Negotiated version in [SSL 3.0, TLS 1.0, TLS 1.1] OR TLS on non-standard port",
      description:
        "Audits TLS ClientHello and ServerHello records for deprecated versions prohibited under modern NIST/PCI-DSS standards.",
      evidence: ["protocol_version", "packet_count", "observed_sources", "observed_destinations"],
      triage:
        "Upgrade server cipher configurations to enforce TLS 1.2 minimum. Disable legacy CBC mode and RC4 ciphers.",
    },
    {
      id: "RULE-011",
      name: "High unique domain query count",
      category: "DNS Anomaly",
      severity: "LOW",
      mitre: {
        id: "T1568.002",
        tactic: "Command and Control",
        technique: "Domain Generation Algorithms",
        justification:
          "Querying dozens of unique domains in rapid succession is characteristic of DGA seeds searching for active command servers.",
      },
      thresholds: "unique_domains >= 30",
      description:
        "Flags single hosts that query an unusually high count of distinct domains within the capture timeframe.",
      evidence: ["unique_domains_count", "threshold", "sample_domains"],
      triage:
        "Review domain registration ages (WHOIS) and reputations. Check for algorithmic naming patterns (e.g. consonants clusters).",
    },
  ];

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-12">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center space-x-2 text-xs text-cyan-400 font-mono mb-1">
            <BookOpen className="w-3.5 h-3.5" />
            <span>Technical Documentation &amp; Reference</span>
          </div>
          <h2 className="text-xl font-semibold text-slate-100">
            Platform Specifications &amp; Methodology
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Architecture, deterministic detection heuristics, profile thresholds, and analyst triage procedures.
          </p>
        </div>

        <button
          onClick={onNavigateToConsole}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold self-start sm:self-auto cursor-pointer"
        >
          <span>Open Console</span>
        </button>
      </div>

      {/* Nav Tabs */}
      <div className="flex items-center space-x-1 overflow-x-auto pb-2 border-b border-slate-800/80">
        {sections.map((sec) => {
          const Icon = sec.icon;
          const isActive = activeSection === sec.id;
          return (
            <button
              key={sec.id}
              onClick={() => setActiveSection(sec.id)}
              className={`flex items-center space-x-2 px-3 py-2 rounded text-xs font-medium transition whitespace-nowrap cursor-pointer ${
                isActive
                  ? "bg-cyan-950/80 text-cyan-300 border border-cyan-800/80 shadow-sm"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent"
              }`}
            >
              <Icon className={`w-3.5 h-3.5 ${isActive ? "text-cyan-400" : "text-slate-500"}`} />
              <span>{sec.label}</span>
            </button>
          );
        })}
      </div>

      {/* SECTION: Overview & Specs */}
      {activeSection === "overview" && (
        <div className="space-y-6">
          <div className="bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-4">
            <h3 className="text-base font-semibold text-slate-100">
              System Architecture &amp; Core Philosophy
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              The Automated Python PCAP Analyzer is designed from the ground up as a defensive,
              evidence-based network forensics tool. Unlike generic machine learning black boxes or
              synthetic alert generators, this platform enforces mathematical reproducibility: every
              finding is linked to specific packet indices, exact timestamps, and observable telemetry.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 text-xs">
              <div className="bg-slate-950 p-3.5 rounded border border-slate-800/80 space-y-1.5">
                <span className="font-semibold text-slate-200 block">Native Libpcap Parser</span>
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  C-struct zero-copy binary parser unpacking packet headers at high speed without
                  third-party binary dependencies.
                </p>
              </div>
              <div className="bg-slate-950 p-3.5 rounded border border-slate-800/80 space-y-1.5">
                <span className="font-semibold text-slate-200 block">Conversation State Engine</span>
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  Reconstructs bidirectional TCP/UDP sessions, tracking SYN, SYN-ACK, ACK, and RST
                  transitions to detect reconnaissance vs benign traffic.
                </p>
              </div>
              <div className="bg-slate-950 p-3.5 rounded border border-slate-800/80 space-y-1.5">
                <span className="font-semibold text-slate-200 block">Deterministic Heuristics</span>
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  11 tunable security rules providing explicit confidence scoring, forensic limitations,
                  and MITRE ATT&amp;CK mappings.
                </p>
              </div>
            </div>
          </div>

          <div className="bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-4">
            <h3 className="text-base font-semibold text-slate-100">
              Data Model &amp; JSON Output Schema
            </h3>
            <p className="text-xs text-slate-400">
              The engine exports analysis results conforming strictly to the unified{" "}
              <code className="text-cyan-400 font-mono">AnalysisResult</code> schema:
            </p>
            <div className="bg-slate-950 p-4 rounded border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
              <pre>{`{
  "metadata": {
    "file_name": "capture.pcap",
    "sha256_hash": "7cc5cb6e18d25410...",
    "packet_count": 45,
    "duration_seconds": 2.45,
    "parser_engine": "native"
  },
  "summary": {
    "total_packets": 45,
    "total_bytes": 3150,
    "tcp_packet_count": 45,
    "unique_conversations": 45
  },
  "flows": [
    {
      "flow_id": "192.168.1.10:49152 <-> 10.10.20.5:80 (TCP)",
      "completed_handshake": false,
      "syn_count": 1,
      "rst_count": 0
    }
  ],
  "findings": [
    {
      "rule_id": "RULE-001",
      "severity": "HIGH",
      "title": "Potential network scanning activity observed",
      "confidence": 0.88,
      "evidence": { "syn_packets_transmitted": 45, "unique_ports": 45 }
    }
  ]
}`}</pre>
            </div>
          </div>
        </div>
      )}

      {/* SECTION: Detection Rules Reference */}
      {activeSection === "rules" && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 bg-[#111827] border border-slate-800 rounded-lg p-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">
                Rule Catalog &amp; ATT&amp;CK Mapping
              </h3>
              <p className="text-xs text-slate-400">
                Deterministic detection rules with verifiable conditions and authentic ATT&amp;CK technique alignments
              </p>
            </div>
            <input
              type="text"
              placeholder="Filter rules by name, ID, or ATT&CK..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 w-full sm:w-64"
            />
          </div>

          <div className="space-y-4">
            {rulesList
              .filter((r) => {
                if (!searchQuery.trim()) return true;
                const q = searchQuery.toLowerCase();
                return (
                  r.id.toLowerCase().includes(q) ||
                  r.name.toLowerCase().includes(q) ||
                  r.category.toLowerCase().includes(q) ||
                  r.mitre.id.toLowerCase().includes(q) ||
                  r.mitre.technique.toLowerCase().includes(q)
                );
              })
              .map((rule) => (
                <div
                  key={rule.id}
                  className="bg-[#111827] border border-slate-800 rounded-lg p-5 space-y-3.5"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/70 pb-3">
                    <div className="flex items-center space-x-2.5">
                      <span className="font-mono text-xs font-bold text-cyan-400 bg-cyan-950/70 border border-cyan-800/60 px-2 py-0.5 rounded">
                        {rule.id}
                      </span>
                      <h4 className="text-sm font-semibold text-slate-200">{rule.name}</h4>
                    </div>

                    <div className="flex items-center space-x-2 text-xs">
                      <span className="text-slate-400">{rule.category}</span>
                      <span className="text-slate-600" aria-hidden="true">·</span>
                      <span
                        className={`font-mono text-[11px] font-bold px-2 py-0.5 rounded border ${
                          rule.severity.includes("HIGH")
                            ? "bg-rose-950/80 text-rose-300 border-rose-800/60"
                            : rule.severity.includes("MEDIUM")
                            ? "bg-amber-950/80 text-amber-300 border-amber-800/60"
                            : "bg-blue-950/80 text-blue-300 border-blue-800/60"
                        }`}
                      >
                        {rule.severity}
                      </span>
                    </div>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed">{rule.description}</p>

                  {/* MITRE Mapping & Evidence Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                    {/* MITRE ATT&CK */}
                    <div className="bg-slate-950 p-3.5 rounded border border-slate-800/80 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                          MITRE ATT&amp;CK Mapping
                        </span>
                        <span className="font-mono text-cyan-400 font-semibold text-[11px]">
                          {rule.mitre.id}
                        </span>
                      </div>
                      <div className="text-slate-200 font-medium">
                        {rule.mitre.tactic}: {rule.mitre.technique}
                      </div>
                      <p className="text-slate-400 text-[11px] leading-relaxed">
                        {rule.mitre.justification}
                      </p>
                    </div>

                    {/* Thresholds & Evidence */}
                    <div className="bg-slate-950 p-3.5 rounded border border-slate-800/80 space-y-1.5">
                      <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                        Trigger Thresholds
                      </span>
                      <code className="text-amber-300 font-mono text-[11px] block bg-slate-900 p-1.5 rounded">
                        {rule.thresholds}
                      </code>
                      <div className="text-[11px] text-slate-400 pt-1">
                        <strong className="text-slate-300">Evidence Fields:</strong>{" "}
                        {rule.evidence.join(", ")}
                      </div>
                    </div>
                  </div>

                  {/* Triage Guidance */}
                  <div className="bg-slate-900/60 p-3 rounded border border-slate-800/70 text-xs flex items-start space-x-2 text-slate-300">
                    <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-cyan-300">Analyst Triage:</strong> {rule.triage}
                    </div>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* SECTION: Configuration Profiles */}
      {activeSection === "profiles" && (
        <div className="space-y-6">
          <div className="bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-4">
            <h3 className="text-base font-semibold text-slate-100">
              Environment Threshold Calibration Profiles
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Network baselines vary dramatically between environments. An enterprise backbone
              regularly sustains thousands of packets per second, whereas a home lab would consider 80
              pkts/sec abnormal. To prevent alert fatigue, the analyzer supports four tuned detection
              profiles:
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 text-xs">
              <div className="bg-slate-950 p-4 rounded border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="font-semibold text-slate-200">default</h4>
                  <span className="text-[10px] font-mono text-cyan-400">Balanced / General</span>
                </div>
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  General-purpose baseline suited for standard forensic PCAPs and benchmark testing.
                </p>
                <div className="font-mono text-[10px] text-slate-500 space-y-0.5 pt-1">
                  <div>syn_scan_min_packets: 25</div>
                  <div>syn_scan_unique_port_threshold: 20</div>
                  <div>flood_packet_rate_threshold: 80.0</div>
                  <div>dns_tunnel_entropy_threshold: 3.85</div>
                </div>
              </div>

              <div className="bg-slate-950 p-4 rounded border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="font-semibold text-slate-200">home_lab</h4>
                  <span className="text-[10px] font-mono text-emerald-400">High Sensitivity</span>
                </div>
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  Tight thresholds for quiet or isolated networks where small anomalies should be
                  flagged immediately.
                </p>
                <div className="font-mono text-[10px] text-slate-500 space-y-0.5 pt-1">
                  <div>syn_scan_min_packets: 15</div>
                  <div>syn_scan_unique_port_threshold: 10</div>
                  <div>flood_packet_rate_threshold: 40.0</div>
                  <div>dns_tunnel_entropy_threshold: 3.75</div>
                </div>
              </div>

              <div className="bg-slate-950 p-4 rounded border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="font-semibold text-slate-200">enterprise</h4>
                  <span className="text-[10px] font-mono text-blue-400">Active Workstations</span>
                </div>
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  Calibrated for enterprise networks with active telemetry, software updates, and
                  legitimate background polling.
                </p>
                <div className="font-mono text-[10px] text-slate-500 space-y-0.5 pt-1">
                  <div>syn_scan_min_packets: 40</div>
                  <div>syn_scan_unique_port_threshold: 30</div>
                  <div>flood_packet_rate_threshold: 150.0</div>
                  <div>dns_tunnel_entropy_threshold: 3.90</div>
                </div>
              </div>

              <div className="bg-slate-950 p-4 rounded border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="font-semibold text-slate-200">high_volume</h4>
                  <span className="text-[10px] font-mono text-amber-400">Data Center / Highpps</span>
                </div>
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  Conservative thresholds intended for data centers or span port captures to isolate only
                  severe, sustained deviations.
                </p>
                <div className="font-mono text-[10px] text-slate-500 space-y-0.5 pt-1">
                  <div>syn_scan_min_packets: 100</div>
                  <div>syn_scan_unique_port_threshold: 50</div>
                  <div>flood_packet_rate_threshold: 500.0</div>
                  <div>dns_tunnel_entropy_threshold: 4.00</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SECTION: CLI Reference */}
      {activeSection === "cli" && (
        <div className="space-y-6">
          <div className="bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-4">
            <h3 className="text-base font-semibold text-slate-100">
              Command-Line Interface (CLI) Usage
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              The analyzer features a standalone Python CLI for offline scripting, headless forensics, and
              pipeline integration:
            </p>

            <div className="relative bg-slate-950 p-4 rounded border border-slate-800 font-mono text-xs text-slate-300">
              <button
                onClick={() =>
                  copyToClipboard(
                    "python3 -m src.pcap_analyzer.cli examples/syn_port_scan.pcap --profile enterprise -o out.json -r report.txt --iocs iocs.json",
                    "cli-cmd"
                  )
                }
                className="absolute top-3 right-3 text-slate-500 hover:text-slate-200 transition"
              >
                {copiedCode === "cli-cmd" ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
              </button>
              <pre className="overflow-x-auto">
                {`# Run full forensic analysis with enterprise profile and multi-artifact export
python3 -m src.pcap_analyzer.cli examples/syn_port_scan.pcap \\
  --profile enterprise \\
  --engine auto \\
  -o out.json \\
  -r report.txt \\
  --iocs iocs.json`}
              </pre>
            </div>

            <div className="space-y-2 text-xs">
              <h4 className="font-semibold text-slate-200">Supported CLI Options</h4>
              <div className="bg-slate-950 rounded border border-slate-800 divide-y divide-slate-900 font-mono text-[11px]">
                <div className="p-2.5 flex items-center justify-between">
                  <span className="text-cyan-400">pcap_file</span>
                  <span className="text-slate-400">Path to input .pcap or .pcapng capture file</span>
                </div>
                <div className="p-2.5 flex items-center justify-between">
                  <span className="text-cyan-400">-p, --profile</span>
                  <span className="text-slate-400">default | home_lab | enterprise | high_volume</span>
                </div>
                <div className="p-2.5 flex items-center justify-between">
                  <span className="text-cyan-400">-e, --engine</span>
                  <span className="text-slate-400">auto | native | scapy | pyshark</span>
                </div>
                <div className="p-2.5 flex items-center justify-between">
                  <span className="text-cyan-400">-o, --output</span>
                  <span className="text-slate-400">File path to write complete JSON analysis model</span>
                </div>
                <div className="p-2.5 flex items-center justify-between">
                  <span className="text-cyan-400">-r, --report</span>
                  <span className="text-slate-400">File path to write 12-section technical investigation text</span>
                </div>
                <div className="p-2.5 flex items-center justify-between">
                  <span className="text-cyan-400">--iocs</span>
                  <span className="text-slate-400">File path to export categorized JSON observable indicators</span>
                </div>
                <div className="p-2.5 flex items-center justify-between">
                  <span className="text-cyan-400">-v, --verbose</span>
                  <span className="text-slate-400">Enable verbose logging and packet debugging</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SECTION: REST API Reference */}
      {activeSection === "api" && (
        <div className="space-y-6">
          <div className="bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-4">
            <h3 className="text-base font-semibold text-slate-100">
              Backend REST API Endpoints
            </h3>
            <p className="text-xs text-slate-300">
              The full-stack Express service exposes clean JSON endpoints interfacing directly with the
              Python engine:
            </p>

            <div className="space-y-3 text-xs">
              {[
                {
                  method: "GET",
                  path: "/api/status",
                  desc: "Queries Python environment, engine versions, and operational state.",
                  response: '{"connected": true, "pythonVersion": "3.10.12", "analyzerVersion": "2.0.0", "detectionEngineOperational": true}',
                },
                {
                  method: "GET",
                  path: "/api/test-status",
                  desc: "Executes real python3 -m unittest runner and returns pass/fail metrics.",
                  response: '{"verified": true, "passed": true, "totalTests": 31, "duration": "0.07s", "summary": "31 passed (0 failures, 0 errors)"}',
                },
                {
                  method: "GET",
                  path: "/api/samples",
                  desc: "Lists pre-packaged PCAP forensic investigation scenarios.",
                  response: '{"samples": [{"id": "syn_port_scan", "fileName": "syn_port_scan.pcap", "threatCategory": "Reconnaissance"}]}',
                },
                {
                  method: "POST",
                  path: "/api/analyze-sample",
                  desc: "Executes Python analyzer on a sample scenario with requested profile/engine.",
                  payload: '{"sampleId": "syn_port_scan", "profile": "default", "engine": "auto"}',
                  response: '{"success": true, "result": {...}, "reportText": "...", "isDemo": false}',
                },
                {
                  method: "POST",
                  path: "/api/analyze-upload",
                  desc: "Receives base64-encoded .pcap or .pcapng file (max 50MB) and runs Python analyzer.",
                  payload: '{"fileName": "incident_capture.pcap", "fileData": "<base64>", "profile": "enterprise"}',
                  response: '{"success": true, "result": {...}, "reportText": "...", "isDemo": false}',
                },
              ].map((ep) => (
                <div key={ep.path} className="bg-slate-950 p-4 rounded border border-slate-800 space-y-2">
                  <div className="flex items-center space-x-2 font-mono">
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                        ep.method === "GET" ? "bg-cyan-950 text-cyan-300 border border-cyan-800" : "bg-emerald-950 text-emerald-300 border border-emerald-800"
                      }`}
                    >
                      {ep.method}
                    </span>
                    <span className="text-slate-200 font-semibold">{ep.path}</span>
                  </div>
                  <p className="text-slate-400 text-[11px]">{ep.desc}</p>
                  {ep.payload && (
                    <div className="font-mono text-[10px] text-slate-500">
                      <strong>Payload:</strong> <code>{ep.payload}</code>
                    </div>
                  )}
                  <div className="font-mono text-[10px] text-slate-500 truncate">
                    <strong>Response:</strong> <code>{ep.response}</code>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* SECTION: Synthetic Testing & CI */}
      {activeSection === "testing" && (
        <div className="space-y-6">
          <div className="bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-4">
            <h3 className="text-base font-semibold text-slate-100">
              Synthetic Testing Framework &amp; Regression Guard
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              In cybersecurity forensics, validating that rules fire on exact mathematical conditions
              requires ground-truth captures. The repository includes{" "}
              <code className="text-cyan-400 font-mono">tests/generate_test_pcaps.py</code>, an automated
              Scapy generator that crafts bit-perfect test scenarios:
            </p>

            <div className="bg-slate-950 p-4 rounded border border-slate-800 space-y-3 text-xs">
              <div className="flex items-center justify-between border-b border-slate-900 pb-2">
                <span className="font-semibold text-slate-200">31 Automated Unit Tests (Passing)</span>
                <span className="text-emerald-400 font-mono text-[11px]">Execution Time: ~0.07s</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px] text-slate-400">
                <div className="space-y-1">
                  <div className="text-slate-300 font-medium">test_parser.py</div>
                  <div>Validates native libpcap C-struct unpacking against known offsets.</div>
                </div>
                <div className="space-y-1">
                  <div className="text-slate-300 font-medium">test_detections.py</div>
                  <div>Verifies rules fire only when packets exceed calibrated thresholds.</div>
                </div>
                <div className="space-y-1">
                  <div className="text-slate-300 font-medium">test_statistics.py</div>
                  <div>Audits byte totals, protocol distribution, and top talker counts.</div>
                </div>
                <div className="space-y-1">
                  <div className="text-slate-300 font-medium">test_reporting.py</div>
                  <div>Validates the completeness of all 12 forensic report sections.</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SECTION: Analyst Triage Guide */}
      {activeSection === "triage" && (
        <div className="space-y-6">
          <div className="bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-4">
            <h3 className="text-base font-semibold text-slate-100">
              SOC Analyst Forensic Triage Guide
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              When investigating alerts in the console, follow this standardized 4-step triage
              procedure:
            </p>

            <div className="space-y-3 text-xs">
              <div className="bg-slate-950 p-4 rounded border border-slate-800 space-y-1.5">
                <div className="font-semibold text-cyan-400">Step 1: Check Handshake Completion Ratio</div>
                <p className="text-slate-300 text-[11px] leading-relaxed">
                  In port scan alerts (RULE-001), inspect the handshake completion ratio. If completion
                  is &lt; 5%, this is an unacknowledged SYN probe. If completion is &gt; 90%, the host is
                  performing authorized service polling or web crawling.
                </p>
              </div>

              <div className="bg-slate-950 p-4 rounded border border-slate-800 space-y-1.5">
                <div className="font-semibold text-cyan-400">Step 2: Evaluate Shannon Entropy Scores</div>
                <p className="text-slate-300 text-[11px] leading-relaxed">
                  In DNS alerts (RULE-005), natural language English subdomains typically exhibit
                  entropy between 2.0 and 3.4 bits/symbol. Encoded ciphertext or Base32 chunks exhibit
                  entropy $\ge 3.85$. Check for high-frequency queries targeting a single root domain.
                </p>
              </div>

              <div className="bg-slate-950 p-4 rounded border border-slate-800 space-y-1.5">
                <div className="font-semibold text-cyan-400">Step 3: Correlate Conversation Flows</div>
                <p className="text-slate-300 text-[11px] leading-relaxed">
                  Cross-reference the alert's source IP in the Network Flows module. Check if the host
                  communicated with other internal hosts beforehand (lateral movement) or external
                  unfamiliar IPs (command and control).
                </p>
              </div>

              <div className="bg-slate-950 p-4 rounded border border-slate-800 space-y-1.5">
                <div className="font-semibold text-cyan-400">Step 4: Export Observables to SIEM / EDR</div>
                <p className="text-slate-300 text-[11px] leading-relaxed">
                  Navigate to the IOCs tab and click &quot;Export IOCs Manifest (JSON)&quot;. Query the extracted
                  IPs and domains across your host-based EDR (CrowdStrike, SentinelOne, Defender) to
                  confirm whether any host processes made matching outbound sockets.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
