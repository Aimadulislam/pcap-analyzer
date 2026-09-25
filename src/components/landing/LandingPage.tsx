import React, { useState, useEffect } from "react";
import {
  Shield,
  Activity,
  Terminal,
  FileCode,
  FileText,
  CheckCircle2,
  AlertTriangle,
  Play,
  BookOpen,
  Github,
  Server,
  Layers,
  Cpu,
  Search,
  ArrowRight,
  Database,
  Radio,
  Lock,
  Globe,
  Network,
  Fingerprint,
  Sliders,
  Check,
  RefreshCw,
  Info,
  ExternalLink,
} from "lucide-react";
import { BackendStatus, TestSuiteStatus } from "../../types/analyzer";
import { fetchTestStatus } from "../../services/api";

interface LandingPageProps {
  backendStatus: BackendStatus;
  onOpenAnalyzer: () => void;
  onOpenDocumentation: (section?: string) => void;
  onSelectSample: (sampleId: string) => void;
  onRefreshBackend: () => void;
  onOpenCaseStudy?: () => void;
}

// Configurable placeholder GitHub URL
const GITHUB_URL = "https://github.com/defensive-sec/automated-python-pcap-analyzer";

export const LandingPage: React.FC<LandingPageProps> = ({
  backendStatus,
  onOpenAnalyzer,
  onOpenDocumentation,
  onSelectSample,
  onRefreshBackend,
  onOpenCaseStudy,
}) => {
  const [testStatus, setTestStatus] = useState<TestSuiteStatus | null>(null);
  const [verifyingTests, setVerifyingTests] = useState<boolean>(false);
  const [selectedArchNode, setSelectedArchNode] = useState<string>("parser");

  useEffect(() => {
    runTestVerification();
  }, []);

  const runTestVerification = async () => {
    setVerifyingTests(true);
    try {
      const status = await fetchTestStatus();
      setTestStatus(status);
    } catch {
      setTestStatus({
        verified: false,
        passed: false,
        status: "Not verified",
        totalTests: 31,
        summary: "Unable to verify test suite",
      });
    } finally {
      setVerifyingTests(false);
    }
  };

  const capabilities = [
    {
      title: "PCAP Analysis",
      icon: Terminal,
      desc: "Dual-engine dissection supporting .pcap and .pcapng with native C-struct binary unpacking and Scapy/PyShark fallback.",
      specs: "Native libpcap reader · Zero-copy header decoding",
    },
    {
      title: "Protocol Intelligence",
      icon: Layers,
      desc: "Comprehensive Layer 2–7 protocol demuxing covering Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, and TLS.",
      specs: "Header extraction · Transport state extraction",
    },
    {
      title: "Network Flow Analysis",
      icon: Network,
      desc: "Full bidirectional conversation reconstruction tracking 5-tuples, byte distributions, durations, and TCP handshake states.",
      specs: "SYN / SYN-ACK / ACK state tracking · Reset auditing",
    },
    {
      title: "Threat Detection",
      icon: Shield,
      desc: "Deterministic, evidence-based heuristic detection rules identifying port scans, SYN sweeps, floods, and unauthorized listeners.",
      specs: "11 built-in rules · Tunable mathematical thresholds",
    },
    {
      title: "IOC Extraction",
      icon: Fingerprint,
      desc: "Structured harvesting of observable network indicators: IPv4/IPv6 addresses, domains, URLs, hostnames, and timestamps.",
      specs: "De-duplicated manifests · JSON exportable",
    },
    {
      title: "DNS Investigation",
      icon: Globe,
      desc: "Shannon entropy evaluation on domain names to uncover covert C2 tunneling, data exfiltration, and DGA queries.",
      specs: "Subdomain entropy scoring · NXDOMAIN ratio tracking",
    },
    {
      title: "HTTP Analysis",
      icon: FileCode,
      desc: "Deep application layer inspection for scanner signatures (sqlmap, nikto, nessus, nmap), URI anomalies, and cleartext credentials.",
      specs: "User-Agent auditing · Cleartext password detection",
    },
    {
      title: "TLS Metadata",
      icon: Lock,
      desc: "ClientHello & ServerHello inspection auditing SNI hostnames, negotiated protocol versions (SSL 3.0–TLS 1.3), and ciphers.",
      specs: "Deprecated protocol detection · Non-standard ports",
    },
    {
      title: "Evidence-Based Findings",
      icon: Search,
      desc: "Findings grounded in packet indices, observed byte volumes, timestamp spans, and explicit forensic limitation disclosures.",
      specs: "Exact packet numbers · Ground-truth telemetry",
    },
    {
      title: "Configurable Thresholds",
      icon: Sliders,
      desc: "Environment-tuned detection profiles (default, home_lab, enterprise, high_volume) to eliminate alert fatigue across varied networks.",
      specs: "YAML/JSON profiles · CLI override flags",
    },
    {
      title: "Reproducible Testing",
      icon: Cpu,
      desc: "Automated synthetic capture generators creating mathematically deterministic PCAP fixtures for CI/CD test verification.",
      specs: "31 automated unit tests · Scapy ground-truth fixtures",
    },
    {
      title: "Security Reporting",
      icon: FileText,
      desc: "Multi-format generation including 12-section technical incident investigation reports, structured JSON schemas, and IOC lists.",
      specs: "12-section forensic report · JSON/TXT export",
    },
  ];

  const archNodes: Record<
    string,
    { title: string; component: string; path: string; desc: string; outputs: string }
  > = {
    input: {
      title: "Input Validation & Integrity",
      component: "Native File Inspector",
      path: "src/pcap_analyzer/parser.py & analyzer.py",
      desc: "Validates PCAP/PCAPNG magic bytes (0xa1b2c3d4, 0xd4c3b2a1, 0x0a0d0d0a), calculates cryptographic SHA-256 integrity hash, and enforces size boundaries.",
      outputs: "SHA-256 digest, file format identification, byte boundary validation",
    },
    parser: {
      title: "Packet Parsing Engine",
      component: "NativePcapReader / Scapy Engine",
      path: "src/pcap_analyzer/parser.py",
      desc: "Unpacks binary packet headers into structured PacketRecord instances. Parses Ethernet, IPv4/IPv6, TCP, UDP, and ICMP headers with precise timestamps and flag states.",
      outputs: "List[PacketRecord] with timestamp, layer 3/4 headers, and raw payload slices",
    },
    protocols: {
      title: "Protocol Analysis Engines",
      component: "DNS, HTTP, & TLS Dissectors",
      path: "src/pcap_analyzer/dns_analyzer.py, http_analyzer.py, tls_analyzer.py",
      desc: "Dissects Layer 7 payload data: DNS queries/answers with Shannon entropy calculation, HTTP methods/URIs/User-Agents, and TLS ClientHello/ServerHello version negotiation.",
      outputs: "DNSRecord, HTTPRecord, TLSRecord telemetry objects",
    },
    flow: {
      title: "Flow Reconstruction",
      component: "Conversation State Tracker",
      path: "src/pcap_analyzer/analyzer.py & models.py",
      desc: "Reassembles bidirectional conversation flows indexed by normalized 5-tuple (source IP, destination IP, source port, destination port, transport protocol). Tracks TCP 3-way handshake completion.",
      outputs: "List[FlowRecord] with duration, packet counts, byte rates, and TCP flag metrics",
    },
    detection: {
      title: "Detection Rules Engine",
      component: "RuleEvaluator & Heuristics",
      path: "src/pcap_analyzer/detections.py",
      desc: "Evaluates 11 deterministic detection rules against packet streams and flow states. Compares against threshold profiles to generate evidence-backed security observations.",
      outputs: "List[AlertFinding] containing exact packet references, confidence scores, and remediation steps",
    },
    iocs: {
      title: "IOC Extraction Engine",
      component: "Observable Harvester",
      path: "src/pcap_analyzer/iocs.py",
      desc: "Aggregates unique network observables across all parsed packets and flows: IP addresses, queried domain names, requested URLs, hostnames, and timestamps.",
      outputs: "CategorizedIOCs manifest with first-seen / last-seen timestamps and packet indices",
    },
    reporting: {
      title: "Unified Analysis Model & Reporting",
      component: "ReportGenerator & JSON Serializer",
      path: "src/pcap_analyzer/reporting.py & models.py",
      desc: "Packages findings, telemetry, flow matrix, and metadata into a unified AnalysisResult schema. Generates the comprehensive 12-section technical investigation text report.",
      outputs: "12-section plaintext report, structured JSON artifact, and REST API payload",
    },
    ui: {
      title: "Analyst Web Interface",
      component: "React / TypeScript SOC Workspace",
      path: "src/components/*",
      desc: "High-density SOC analyst dashboard featuring flow matrix tables, protocol drill-downs, evidence drawers, and interactive IOC search.",
      outputs: "Interactive forensic analyst console with real-time file upload and sample testing",
    },
  };

  const sampleScenarios = [
    {
      id: "syn_port_scan",
      title: "Vertical TCP SYN Reconnaissance Scan",
      category: "Reconnaissance",
      packets: 45,
      severity: "HIGH",
      desc: "Rapid unacknowledged TCP SYN connection attempts probing diverse destination ports on target 10.10.20.5.",
    },
    {
      id: "dns_tunnel",
      title: "Covert DNS Tunneling & C2 Exfiltration",
      category: "DNS Anomaly",
      packets: 110,
      severity: "HIGH",
      desc: "Repeated high-entropy subdomain requests over UDP port 53 transmitting encoded payload chunks to an external nameserver.",
    },
    {
      id: "cleartext",
      title: "Unencrypted HTTP & Metasploit Port 4444",
      category: "Cleartext & Unusual Port",
      packets: 68,
      severity: "LOW",
      desc: "Cleartext credentials passed to /login.php and non-standard listener activity on TCP port 4444.",
    },
    {
      id: "baseline",
      title: "Benign Corporate Web & DNS Baseline",
      category: "Benign Baseline",
      packets: 250,
      severity: "INFO",
      desc: "Normal corporate web browsing to Slack, GitHub, and Google with established TLS 1.3 handshakes.",
    },
  ];

  return (
    <div className="space-y-12 max-w-6xl mx-auto pb-12">
      {/* Hero Section */}
      <section className="relative pt-6 pb-4">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-8">
          <div className="max-w-2xl space-y-4">
            {/* Tech badges */}
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
              <span className="font-mono text-cyan-400 font-semibold">Python 3.10+</span>
              <span className="text-slate-600" aria-hidden="true">·</span>
              <span>Scapy</span>
              <span className="text-slate-600" aria-hidden="true">·</span>
              <span>PyShark / Wireshark</span>
              <span className="text-slate-600" aria-hidden="true">·</span>
              <span>FastAPI &amp; Express</span>
              <span className="text-slate-600" aria-hidden="true">·</span>
              <span>React &amp; TypeScript</span>
            </div>

            <div className="space-y-2">
              <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-slate-100">
                Automated Python PCAP Analyzer &amp; Threat Parser
              </h1>
              <p className="text-base sm:text-lg font-medium text-cyan-400">
                Offline Network Forensics &amp; Defensive Threat Analysis
              </p>
            </div>

            <p className="text-sm text-slate-300 leading-relaxed">
              A Python-based defensive network-analysis platform for examining PCAP/PCAPNG captures,
              extracting network telemetry, identifying indicators of interest, reconstructing
              communication flows, and detecting suspicious traffic patterns using configurable
              evidence-based rules.
            </p>

            {/* Primary & Secondary Action CTAs */}
            <div className="flex flex-wrap items-center gap-3 pt-2">
              <button
                onClick={onOpenAnalyzer}
                className="flex items-center space-x-2 px-5 py-2.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold tracking-wide transition shadow-md shadow-cyan-950/80 cursor-pointer"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Open Analyzer</span>
              </button>

              {onOpenCaseStudy && (
                <button
                  onClick={onOpenCaseStudy}
                  className="flex items-center space-x-2 px-4 py-2.5 rounded bg-cyan-950/70 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-800/80 text-xs font-medium transition cursor-pointer"
                >
                  <BookOpen className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Case Study</span>
                </button>
              )}

              <button
                onClick={() => onOpenDocumentation()}
                className="flex items-center space-x-2 px-4 py-2.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700/80 text-xs font-medium transition cursor-pointer"
              >
                <Terminal className="w-3.5 h-3.5 text-slate-400" />
                <span>Technical Docs</span>
              </button>

              <a
                href={GITHUB_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center space-x-2 px-4 py-2.5 rounded bg-slate-950 hover:bg-slate-900 text-slate-300 border border-slate-800 text-xs font-medium transition"
              >
                <Github className="w-3.5 h-3.5 text-slate-400" />
                <span>GitHub</span>
                <ExternalLink className="w-3 h-3 text-slate-500 ml-0.5" />
              </a>
            </div>
          </div>

          {/* Project Status Card */}
          <div className="w-full lg:w-80 bg-[#111827] border border-slate-800 rounded-lg p-5 shadow-lg space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <div className="flex items-center space-x-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Project Status
                </span>
              </div>
              <button
                onClick={() => {
                  onRefreshBackend();
                  runTestVerification();
                }}
                title="Refresh system status and re-run test suite verification"
                className="text-slate-500 hover:text-slate-300 transition"
              >
                <RefreshCw
                  className={`w-3.5 h-3.5 ${verifyingTests ? "animate-spin text-cyan-400" : ""}`}
                />
              </button>
            </div>

            <div className="space-y-2.5 text-xs">
              {/* Backend Status */}
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Backend</span>
                <div className="flex items-center space-x-1.5">
                  <span
                    className={`w-2 h-2 rounded-full ${
                      backendStatus.connected ? "bg-emerald-400" : "bg-amber-400"
                    }`}
                  />
                  <span
                    className={`font-medium ${
                      backendStatus.connected ? "text-emerald-400" : "text-amber-400"
                    }`}
                  >
                    {backendStatus.connected ? "Operational" : "Demo Mode"}
                  </span>
                </div>
              </div>

              {/* Frontend Status */}
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Frontend</span>
                <div className="flex items-center space-x-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  <span className="font-medium text-emerald-400">Operational</span>
                </div>
              </div>

              {/* Detection Engine Status */}
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Detection Engine</span>
                <div className="flex items-center space-x-1.5">
                  <span
                    className={`w-2 h-2 rounded-full ${
                      backendStatus.connected ? "bg-emerald-400" : "bg-cyan-400"
                    }`}
                  />
                  <span className="font-medium text-slate-200">
                    {backendStatus.connected ? "Operational (11 Rules)" : "Operational (Static)"}
                  </span>
                </div>
              </div>

              {/* Test Suite Verification */}
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Test Suite</span>
                <div className="flex items-center space-x-1.5">
                  {verifyingTests ? (
                    <span className="text-cyan-400 font-mono text-[11px] animate-pulse">
                      Verifying...
                    </span>
                  ) : testStatus && testStatus.verified && testStatus.passed ? (
                    <>
                      <span className="w-2 h-2 rounded-full bg-emerald-400" />
                      <span className="font-medium text-emerald-400">Passing</span>
                    </>
                  ) : testStatus && testStatus.verified && !testStatus.passed ? (
                    <>
                      <span className="w-2 h-2 rounded-full bg-rose-400" />
                      <span className="font-medium text-rose-400">Failing</span>
                    </>
                  ) : (
                    <span className="text-slate-500 font-mono text-[11px]">Not verified</span>
                  )}
                </div>
              </div>
            </div>

            {/* Verification details note */}
            <div className="pt-2 border-t border-slate-800/80 text-[11px] text-slate-500 font-mono leading-relaxed">
              {testStatus && testStatus.verified ? (
                <div className="flex items-center justify-between text-slate-400">
                  <span>31 unit tests</span>
                  <span>{testStatus.duration || "0.07s"}</span>
                </div>
              ) : (
                <span>Click refresh to execute real test discovery runner</span>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* Quick Launch Scenario Bar */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
              Forensic Test Scenarios
            </h3>
            <p className="text-xs text-slate-500">
              Load reproducible PCAP captures into the live analysis engine with one click
            </p>
          </div>
          <button
            onClick={onOpenAnalyzer}
            className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
          >
            <span>Custom Upload (.pcap/.pcapng)</span>
            <ArrowRight className="w-3 h-3" />
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {sampleScenarios.map((s) => (
            <div
              key={s.id}
              onClick={() => onSelectSample(s.id)}
              className="bg-[#111827] border border-slate-800 hover:border-cyan-700/80 rounded-lg p-4 cursor-pointer transition flex flex-col justify-between group"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-slate-400 font-medium">{s.category}</span>
                  <span
                    className={`font-mono font-semibold px-1.5 py-0.5 rounded text-[10px] ${
                      s.severity === "HIGH"
                        ? "bg-rose-950/80 text-rose-300 border border-rose-800/60"
                        : s.severity === "LOW"
                        ? "bg-blue-950/80 text-blue-300 border border-blue-800/60"
                        : "bg-slate-800 text-slate-300"
                    }`}
                  >
                    {s.severity}
                  </span>
                </div>
                <h4 className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 transition line-clamp-1">
                  {s.title}
                </h4>
                <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                  {s.desc}
                </p>
              </div>

              <div className="pt-3 mt-3 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-500 font-mono">
                <span>{s.packets} pkts</span>
                <span className="text-cyan-400 group-hover:translate-x-0.5 transition-transform flex items-center space-x-1">
                  <span>Analyze</span>
                  <ArrowRight className="w-3 h-3 ml-0.5" />
                </span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Interactive Architecture Visualization */}
      <section className="bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-4">
          <div>
            <h3 className="text-base font-semibold text-slate-100 flex items-center space-x-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>Technical Architecture &amp; Data Pipeline</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Click any node in the pipeline to inspect underlying implementation modules and contracts.
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500 bg-slate-900 px-2.5 py-1 rounded border border-slate-800">
            Pipeline: Deterministic Stream
          </span>
        </div>

        {/* Node Pipeline Diagram */}
        <div className="overflow-x-auto pb-2">
          <div className="min-w-[760px] flex items-center justify-between gap-2 text-xs font-mono">
            {[
              { id: "input", label: "PCAP/PCAPNG Input", sub: "Validation & SHA-256" },
              { id: "parser", label: "Packet Parser", sub: "Native / Scapy Unpack" },
              { id: "protocols", label: "Protocol Dissection", sub: "DNS / HTTP / TLS" },
              { id: "flow", label: "Flow Reconstruction", sub: "5-Tuple Sessions" },
              { id: "detection", label: "Detection Rules", sub: "11 Heuristic Rules" },
              { id: "iocs", label: "IOC Extraction", sub: "Observables Harvest" },
              { id: "reporting", label: "Analysis Model", sub: "Report & JSON API" },
              { id: "ui", label: "Analyst Console", sub: "SOC Web Interface" },
            ].map((node, idx, arr) => {
              const isSelected = selectedArchNode === node.id;
              return (
                <React.Fragment key={node.id}>
                  <button
                    onClick={() => setSelectedArchNode(node.id)}
                    className={`flex-1 p-2.5 rounded border text-left transition cursor-pointer ${
                      isSelected
                        ? "bg-cyan-950/80 border-cyan-500 text-cyan-200 shadow-md shadow-cyan-950"
                        : "bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200"
                    }`}
                  >
                    <div className="font-semibold text-[11px] truncate">{node.label}</div>
                    <div className="text-[10px] text-slate-500 truncate mt-0.5">{node.sub}</div>
                  </button>

                  {idx < arr.length - 1 && (
                    <ArrowRight className="w-3.5 h-3.5 text-slate-600 shrink-0" />
                  )}
                </React.Fragment>
              );
            })}
          </div>
        </div>

        {/* Selected Architecture Node Inspector */}
        {selectedArchNode && archNodes[selectedArchNode] && (
          <div className="bg-slate-950 rounded-lg border border-slate-800 p-4 space-y-2.5 text-xs">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <span className="font-semibold text-slate-200 text-sm">
                {archNodes[selectedArchNode].title}
              </span>
              <span className="font-mono text-[11px] text-cyan-400">
                {archNodes[selectedArchNode].path}
              </span>
            </div>
            <p className="text-slate-300 leading-relaxed">
              {archNodes[selectedArchNode].desc}
            </p>
            <div className="pt-2 border-t border-slate-900 flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-[11px] text-slate-500">
              <span>
                <strong className="text-slate-400">Outputs:</strong>{" "}
                {archNodes[selectedArchNode].outputs}
              </span>
              <span>
                <strong className="text-slate-400">Component:</strong>{" "}
                {archNodes[selectedArchNode].component}
              </span>
            </div>
          </div>
        )}
      </section>

      {/* Investigation Lifecycle / Workflow */}
      <section className="space-y-4">
        <div>
          <h3 className="text-base font-semibold text-slate-100">
            SOC Analyst Investigation Lifecycle
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            How network packet captures transition from raw bytes to correlated incident intelligence
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {[
            {
              step: "01",
              title: "Ingestion & Validation",
              desc: "Validates PCAP/PCAPNG header format, verifies file integrity, and computes SHA-256 fingerprint.",
            },
            {
              step: "02",
              title: "Protocol Dissection",
              desc: "Decodes Layer 2–7 frames extracting IPs, ports, TCP sequence/flags, and application payloads.",
            },
            {
              step: "03",
              title: "Flow Reconstruction",
              desc: "Rebuilds bidirectional TCP/UDP conversation streams and audits handshake completion states.",
            },
            {
              step: "04",
              title: "Heuristic Detection",
              desc: "Evaluates deterministic rules (RULE-001 through RULE-011) against configurable environment thresholds.",
            },
            {
              step: "05",
              title: "Evidence Correlation",
              desc: "Binds observed anomalies to exact packet indices, Shannon entropy values, and flow records.",
            },
            {
              step: "06",
              title: "Technical Reporting",
              desc: "Emits unified analysis results: 12-section technical incident report, JSON telemetry, and IOC manifest.",
            },
          ].map((w) => (
            <div
              key={w.step}
              className="bg-[#111827] border border-slate-800 rounded-lg p-3.5 space-y-2"
            >
              <div className="font-mono text-xs text-cyan-500 font-bold">{w.step}</div>
              <h4 className="text-xs font-semibold text-slate-200">{w.title}</h4>
              <p className="text-[11px] text-slate-400 leading-relaxed">{w.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Key Capabilities Grid (12 Cards) */}
      <section className="space-y-4">
        <div>
          <h3 className="text-base font-semibold text-slate-100">
            Core Technical Capabilities
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Engineered specifically for offline defensive forensics, blue team investigations, and network threat parsing
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {capabilities.map((cap) => {
            const Icon = cap.icon;
            return (
              <div
                key={cap.title}
                className="bg-[#111827] border border-slate-800 hover:border-slate-700/80 rounded-lg p-4 space-y-2.5 transition flex flex-col justify-between"
              >
                <div className="space-y-2">
                  <div className="flex items-center space-x-2.5">
                    <div className="p-1.5 rounded bg-cyan-950/60 border border-cyan-800/40 text-cyan-400">
                      <Icon className="w-4 h-4" />
                    </div>
                    <h4 className="text-sm font-medium text-slate-200">{cap.title}</h4>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{cap.desc}</p>
                </div>

                <div className="pt-2 border-t border-slate-800/60 text-[10px] text-slate-500 font-mono">
                  {cap.specs}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Real vs Synthetic PCAPs (Transparent Methodology) */}
      <section className="bg-[#111827] border border-slate-800 rounded-lg p-6 space-y-4">
        <div className="flex items-center space-x-2">
          <Database className="w-4 h-4 text-cyan-400" />
          <h3 className="text-base font-semibold text-slate-100">
            Forensic Integrity: Real Captures vs. Synthetic PCAPs
          </h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="bg-slate-950 p-4 rounded border border-slate-800/80 space-y-2">
            <h4 className="font-semibold text-slate-200 flex items-center space-x-2">
              <Check className="w-3.5 h-3.5 text-emerald-400" />
              <span>Synthetic Ground-Truth Captures</span>
            </h4>
            <p className="text-slate-400 leading-relaxed">
              Generated programmatically via Scapy (see{" "}
              <code className="text-cyan-400 font-mono">tests/generate_test_pcaps.py</code>).
              Provides mathematically deterministic packet sequences, exact flag timings, and known
              ground truth for automated CI/CD regression testing of heuristic thresholds.
            </p>
            <div className="text-[11px] text-slate-500 font-mono pt-1">
              Purpose: Automated unit testing, threshold calibration, and reproducible benchmarks
            </div>
          </div>

          <div className="bg-slate-950 p-4 rounded border border-slate-800/80 space-y-2">
            <h4 className="font-semibold text-slate-200 flex items-center space-x-2">
              <Shield className="w-3.5 h-3.5 text-cyan-400" />
              <span>Production Forensic Captures</span>
            </h4>
            <p className="text-slate-400 leading-relaxed">
              Standard PCAP and PCAPNG files captured from real network taps, span ports, or endpoint
              monitoring agents (e.g. Wireshark, tcpdump). The analyzer processes both standard formats
              without pre-conditions, producing complete IOC manifests and forensic audit reports.
            </p>
            <div className="text-[11px] text-slate-500 font-mono pt-1">
              Purpose: Incident investigation, malware traffic triage, and network security auditing
            </div>
          </div>
        </div>

        <div className="bg-slate-900/60 p-3 rounded border border-slate-800/70 text-xs text-slate-400 leading-relaxed">
          <strong className="text-slate-300">Methodology Guarantee:</strong> This application never
          generates random packet counters, fake charts, or artificial alerts. When using live mode,
          every metric, flow record, and finding is parsed directly from actual packet bytes by the
          underlying Python dissection engine.
        </div>
      </section>

      {/* Footer / CTA Banner */}
      <section className="bg-gradient-to-r from-slate-950 via-[#111827] to-slate-950 border border-slate-800 rounded-lg p-6 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="space-y-1 text-center sm:text-left">
          <h4 className="text-sm font-semibold text-slate-200">
            Ready to inspect a network packet capture?
          </h4>
          <p className="text-xs text-slate-400">
            Upload your own .pcap / .pcapng file or explore the pre-packaged forensic scenarios.
          </p>
        </div>

        <div className="flex items-center space-x-3 shrink-0">
          <button
            onClick={() => onOpenDocumentation()}
            className="px-4 py-2 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 text-xs font-medium transition cursor-pointer"
          >
            Documentation
          </button>
          <button
            onClick={onOpenAnalyzer}
            className="px-5 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition shadow-sm cursor-pointer"
          >
            Launch Console
          </button>
        </div>
      </section>
    </div>
  );
};
