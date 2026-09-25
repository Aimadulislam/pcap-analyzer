import React, { useState } from "react";
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
  ChevronRight,
  Download,
  AlertCircle,
  Compass,
} from "lucide-react";
import { PORTFOLIO_DATA } from "../../data/portfolioData";
import { BackendStatus } from "../../types/analyzer";

interface PortfolioCaseStudyPageProps {
  backendStatus: BackendStatus;
  onOpenWorkspace: () => void;
  onOpenDocumentation: (section?: string) => void;
  onSelectSample: (sampleId: string) => void;
  onNavigateToTab: (tab: any) => void;
}

export const PortfolioCaseStudyPage: React.FC<PortfolioCaseStudyPageProps> = ({
  backendStatus,
  onOpenWorkspace,
  onOpenDocumentation,
  onSelectSample,
  onNavigateToTab,
}) => {
  const [activeArchStep, setActiveArchStep] = useState<number>(0);
  const [selectedRuleId, setSelectedRuleId] = useState<string>("RULE-001");
  const [copiedText, setCopiedText] = useState<string | null>(null);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const selectedRule =
    PORTFOLIO_DATA.detectionEngineering.sampleRules.find((r) => r.id === selectedRuleId) ||
    PORTFOLIO_DATA.detectionEngineering.sampleRules[0];

  return (
    <div className="space-y-16 max-w-6xl mx-auto pb-20 pt-4 px-4 sm:px-6">
      {/* 1. HERO SECTION */}
      <section className="relative border-b border-slate-800/80 pb-12 pt-4">
        <div className="space-y-6">
          {/* Category & Verified Badge */}
          <div className="flex flex-wrap items-center gap-3">
            <span className="px-2.5 py-1 rounded bg-cyan-950/80 border border-cyan-800/80 text-cyan-300 font-mono text-xs font-semibold uppercase tracking-wider">
              {PORTFOLIO_DATA.category}
            </span>
            <span className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 text-xs font-mono">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              <span>44 Automated Tests Passing</span>
            </span>
            <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-400 text-xs font-mono">
              v0.1.0 Production Baseline
            </span>
          </div>

          {/* Title & Subtitle */}
          <div className="space-y-2">
            <h1 className="text-3xl sm:text-4xl lg:text-5xl font-extrabold tracking-tight text-slate-100">
              {PORTFOLIO_DATA.title}
            </h1>
            <p className="text-lg sm:text-xl font-medium text-cyan-400">
              {PORTFOLIO_DATA.subtitle}
            </p>
          </div>

          {/* Concise Positioning Description */}
          <p className="text-base text-slate-300 leading-relaxed max-w-3xl">
            {PORTFOLIO_DATA.descriptions.medium}
          </p>

          {/* Action CTAs */}
          <div className="flex flex-wrap items-center gap-3 pt-2">
            <button
              onClick={onOpenWorkspace}
              className="flex items-center space-x-2 px-5 py-2.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold tracking-wide transition shadow-md shadow-cyan-950 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Launch Analyst Workspace</span>
            </button>

            <button
              onClick={() => {
                onSelectSample("syn_port_scan");
                onNavigateToTab("overview");
              }}
              className="flex items-center space-x-2 px-4 py-2.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700/80 text-xs font-medium transition cursor-pointer"
            >
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span>Explore Demo Mode (SYN Scan)</span>
            </button>

            <button
              onClick={() => onOpenDocumentation("rules")}
              className="flex items-center space-x-2 px-4 py-2.5 rounded bg-slate-950 hover:bg-slate-900 text-slate-300 border border-slate-800 text-xs font-medium transition cursor-pointer"
            >
              <BookOpen className="w-3.5 h-3.5 text-slate-400" />
              <span>Technical Documentation</span>
            </button>

            <a
              href={PORTFOLIO_DATA.githubUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center space-x-2 px-4 py-2.5 rounded bg-slate-950 hover:bg-slate-900 text-slate-300 border border-slate-800 text-xs font-medium transition"
            >
              <Github className="w-3.5 h-3.5 text-slate-400" />
              <span>View Source Code</span>
              <ExternalLink className="w-3 h-3 text-slate-500 ml-0.5" />
            </a>
          </div>

          {/* Real Composite UI Visual Banner */}
          <div className="pt-6">
            <div className="rounded-lg border border-slate-800 bg-[#0B0F19] overflow-hidden shadow-2xl">
              {/* Fake Browser/Console Bar */}
              <div className="bg-[#111827] px-4 py-2.5 border-b border-slate-800 flex items-center justify-between text-xs">
                <div className="flex items-center space-x-2">
                  <div className="flex space-x-1.5">
                    <div className="w-2.5 h-2.5 rounded-full bg-slate-700" />
                    <div className="w-2.5 h-2.5 rounded-full bg-slate-700" />
                    <div className="w-2.5 h-2.5 rounded-full bg-slate-700" />
                  </div>
                  <span className="font-mono text-slate-400 ml-2">
                    forensic-session://capture.pcap [SHA-256: 7d21b4a... verified]
                  </span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="px-2 py-0.5 rounded bg-amber-950/60 border border-amber-800/60 text-amber-300 font-mono text-[10px] font-semibold">
                    DEMO DATA: SYN PORT SCAN FIXTURE
                  </span>
                </div>
              </div>

              {/* Composite Dashboard Mockup using actual styled components */}
              <div className="p-5 grid grid-cols-1 md:grid-cols-4 gap-4 bg-[#0B0F19]">
                <div className="p-4 rounded bg-[#111827] border border-slate-800 space-y-1">
                  <span className="text-[11px] font-mono uppercase text-slate-400">Total Packets</span>
                  <div className="text-2xl font-bold font-mono text-slate-100">45</div>
                  <span className="text-[11px] text-cyan-400">45 TCP SYN probes</span>
                </div>
                <div className="p-4 rounded bg-[#111827] border border-slate-800 space-y-1">
                  <span className="text-[11px] font-mono uppercase text-slate-400">Security Findings</span>
                  <div className="text-2xl font-bold font-mono text-rose-400">4 Alerts</div>
                  <span className="text-[11px] text-rose-300">1 High · 2 Med · 1 Low</span>
                </div>
                <div className="p-4 rounded bg-[#111827] border border-slate-800 space-y-1">
                  <span className="text-[11px] font-mono uppercase text-slate-400">Conversations</span>
                  <div className="text-2xl font-bold font-mono text-slate-100">45 Flows</div>
                  <span className="text-[11px] text-amber-400">0% Handshake Completion</span>
                </div>
                <div className="p-4 rounded bg-[#111827] border border-slate-800 space-y-1">
                  <span className="text-[11px] font-mono uppercase text-slate-400">Top Suspicious IP</span>
                  <div className="text-lg font-bold font-mono text-cyan-300">192.168.1.50</div>
                  <span className="text-[11px] text-slate-400">Targets 10.10.20.5:20-8080</span>
                </div>
              </div>

              {/* Sample Evidence Row Preview */}
              <div className="px-5 pb-5 pt-1 bg-[#0B0F19]">
                <div className="p-3.5 rounded border border-rose-900/40 bg-rose-950/20 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
                  <div className="flex items-center space-x-3">
                    <span className="px-2 py-0.5 rounded bg-rose-900/60 border border-rose-700/60 text-rose-300 font-mono text-[10px] font-bold">
                      RULE-001 (HIGH)
                    </span>
                    <span className="text-slate-200 font-medium">
                      Potential TCP SYN scanning pattern targeting 45 distinct ports
                    </span>
                  </div>
                  <div className="flex items-center space-x-3 text-slate-400 font-mono text-[11px]">
                    <span>MITRE: T1046</span>
                    <span className="text-slate-600">·</span>
                    <span className="text-cyan-400 underline cursor-pointer" onClick={() => onNavigateToTab("findings")}>
                      Inspect Evidence Trace →
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 2. PROJECT OVERVIEW & THE PROBLEM */}
      <section className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <div className="space-y-4">
          <div className="flex items-center space-x-2 text-cyan-400">
            <Search className="w-4 h-4" />
            <h2 className="text-xs font-mono uppercase tracking-wider font-semibold">
              01 — Project Overview
            </h2>
          </div>
          <h3 className="text-xl font-bold text-slate-100">
            Local, Offline Packet Forensics &amp; Threat Parsing
          </h3>
          <p className="text-sm text-slate-300 leading-relaxed">
            The platform processes packet captures strictly within an offline, local environment.
            Raw frame bytes are transformed through a structured sequence into verifiable forensic
            evidence, conversation flows, and technical incident reports.
          </p>
          <div className="p-4 rounded-lg bg-[#111827] border border-slate-800 font-mono text-xs text-slate-300 space-y-1.5">
            <div className="text-cyan-400 font-semibold mb-1">// Deterministic Forensic Chain</div>
            <div>PCAP → Native/Scapy Parsing → Protocol Demuxing</div>
            <div>→ 5-Tuple Flow Reconstruction → IOC Harvester</div>
            <div>→ Heuristic Rule Engine → Findings &amp; Evidence</div>
            <div>→ Analyst Investigation Console → SIEM JSON / Text Report</div>
          </div>
        </div>

        <div className="space-y-4">
          <div className="flex items-center space-x-2 text-rose-400">
            <AlertTriangle className="w-4 h-4" />
            <h2 className="text-xs font-mono uppercase tracking-wider font-semibold">
              02 — The Security Problem
            </h2>
          </div>
          <h3 className="text-xl font-bold text-slate-100">
            Manual Packet Sifting Creates Analysis Latency
          </h3>
          <p className="text-sm text-slate-300 leading-relaxed">
            During incident triage, SOC analysts and investigators receive multi-megabyte PCAP captures
            from edge firewalls and sensors. Manually inspecting packets in Wireshark packet-by-packet
            is time-intensive and risks overlooking subtle anomalies.
          </p>
          <ul className="space-y-2 text-xs text-slate-300">
            <li className="flex items-start space-x-2">
              <span className="text-rose-400 font-bold mt-0.5">•</span>
              <span><strong>Information Overload:</strong> Hundreds of thousands of raw frames obscure suspicious sequences.</span>
            </li>
            <li className="flex items-start space-x-2">
              <span className="text-rose-400 font-bold mt-0.5">•</span>
              <span><strong>State Reconstruction Complexity:</strong> Correlating TCP handshake states and unacknowledged SYNs manually.</span>
            </li>
            <li className="flex items-start space-x-2">
              <span className="text-rose-400 font-bold mt-0.5">•</span>
              <span><strong>Analyst Judgment Required:</strong> Automation must not claim to replace human analysts; it must organize facts and isolate evidence for rapid verification.</span>
            </li>
          </ul>
        </div>
      </section>

      {/* 3. THE SOLUTION & ARCHITECTURE */}
      <section className="space-y-6">
        <div className="flex items-center space-x-2 text-cyan-400">
          <Layers className="w-4 h-4" />
          <h2 className="text-xs font-mono uppercase tracking-wider font-semibold">
            03 — Architecture &amp; Data Pipeline
          </h2>
        </div>
        <div className="space-y-2">
          <h3 className="text-2xl font-bold text-slate-100">
            Defensive End-to-End Analysis Architecture
          </h3>
          <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
            Every component in the pipeline performs a single, bounded task with verifiable outputs.
            No black-box models or unvalidated external dependencies are involved.
          </p>
        </div>

        {/* Interactive Architecture Flow Diagram */}
        <div className="p-6 rounded-lg bg-[#111827] border border-slate-800 space-y-6">
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2 text-center text-xs font-mono">
            {[
              { id: 0, label: "PCAP / PCAPNG", sub: "Input Capture" },
              { id: 1, label: "Validation", sub: "SHA-256 Hash" },
              { id: 2, label: "Dissection", sub: "Native / Scapy" },
              { id: 3, label: "Flows", sub: "5-Tuple State" },
              { id: 4, label: "Protocols", sub: "DNS/HTTP/TLS" },
              { id: 5, label: "IOC Engine", sub: "Observables" },
              { id: 6, label: "11 Rules", sub: "Heuristics" },
              { id: 7, label: "Reports", sub: "JSON / TXT" },
            ].map((step) => (
              <div
                key={step.id}
                onClick={() => setActiveArchStep(step.id)}
                className={`p-2.5 rounded border transition cursor-pointer ${
                  activeArchStep === step.id
                    ? "bg-cyan-950/80 border-cyan-500 text-cyan-300 shadow-sm shadow-cyan-950"
                    : "bg-slate-900/80 border-slate-800 text-slate-400 hover:border-slate-700"
                }`}
              >
                <div className="font-bold text-[11px]">{step.label}</div>
                <div className="text-[10px] text-slate-500 mt-0.5">{step.sub}</div>
              </div>
            ))}
          </div>

          {/* Active Architecture Node Explanation */}
          <div className="p-4 rounded bg-[#0B0F19] border border-slate-800/90 text-xs space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-cyan-400 font-bold uppercase">
                {activeArchStep === 0 && "Step 0: Input Capture Ingestion"}
                {activeArchStep === 1 && "Step 1: Ingestion Validation & Integrity Check"}
                {activeArchStep === 2 && "Step 2: Layer 2–4 Packet Header Dissection"}
                {activeArchStep === 3 && "Step 3: Bidirectional 5-Tuple Flow Reconstruction"}
                {activeArchStep === 4 && "Step 4: Layer 7 Protocol Intelligence & Anomaly Scoring"}
                {activeArchStep === 5 && "Step 5: De-duplicated Observable IOC Harvester"}
                {activeArchStep === 6 && "Step 6: Deterministic Detection Heuristics"}
                {activeArchStep === 7 && "Step 7: Structured Reporting & REST API Delivery"}
              </span>
              <span className="text-slate-500 font-mono text-[11px]">
                {activeArchStep === 0 && "Engine: Raw file bytes (max 50MB)"}
                {activeArchStep === 1 && "Engine: Python hashlib.sha256"}
                {activeArchStep === 2 && "Engine: Native struct / Scapy parser"}
                {activeArchStep === 3 && "Engine: TCP state machine tracker"}
                {activeArchStep === 4 && "Engine: Shannon Entropy & regex"}
                {activeArchStep === 5 && "Engine: CategorizedIOCs manifest"}
                {activeArchStep === 6 && "Engine: 11 mathematically tuned rules"}
                {activeArchStep === 7 && "Engine: JSON & 12-section plaintext"}
              </span>
            </div>
            <p className="text-slate-300 leading-relaxed">
              {activeArchStep === 0 &&
                "Accepts standard .pcap (tcpdump/Wireshark) and .pcapng files. Rejects unsupported extensions and validates file header magic numbers."}
              {activeArchStep === 1 &&
                "Calculates cryptographic SHA-256 fingerprint upon upload to ensure chain-of-custody tracking and prevent duplicate or corrupted capture processing."}
              {activeArchStep === 2 &&
                "Decodes Ethernet frames, IPv4/IPv6 headers, TCP sequence/acknowledgment numbers and flags, UDP datagrams, and ICMP types with microsecond precision."}
              {activeArchStep === 3 &&
                "Groups packets by normalized bidirectional 5-tuple. Reconstructs TCP 3-way handshakes (SYN, SYN-ACK, ACK), tracks reset flags, durations, and byte distributions."}
              {activeArchStep === 4 &&
                "Dissects DNS queries with Shannon entropy calculations for tunneling detection, HTTP request URIs and scanner User-Agents, and TLS ClientHello SNI/version records."}
              {activeArchStep === 5 &&
                "Extracts unique IPv4/IPv6 addresses, external domains, URLs, and active ports, recording exact first-seen and last-seen timestamps and packet index ranges."}
              {activeArchStep === 6 &&
                "Evaluates 11 deterministic rules against packet metrics, flag ratios, and flow states. Compares against configured environment profiles (default, home_lab, enterprise, high_volume)."}
              {activeArchStep === 7 &&
                "Generates SIEM-ready structured JSON artifacts alongside formal 12-section plaintext technical incident reports ready for SOC archival."}
            </p>
          </div>
        </div>
      </section>

      {/* 4. TECHNOLOGY STACK */}
      <section className="space-y-6">
        <div className="flex items-center space-x-2 text-cyan-400">
          <Cpu className="w-4 h-4" />
          <h2 className="text-xs font-mono uppercase tracking-wider font-semibold">
            04 — Technology Stack
          </h2>
        </div>
        <div className="space-y-2">
          <h3 className="text-2xl font-bold text-slate-100">
            Strictly Implemented Technologies
          </h3>
          <p className="text-sm text-slate-300 leading-relaxed">
            Only technologies actually present in the codebase are listed. No placeholder or speculative libraries.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          <div className="p-4 rounded-lg bg-[#111827] border border-slate-800 space-y-2">
            <span className="font-mono text-cyan-400 font-semibold uppercase tracking-wider text-[11px]">
              Languages
            </span>
            <div className="space-y-1 text-slate-300">
              <div className="font-medium text-slate-100">Python 3.10+</div>
              <div>Backend dissection &amp; CLI</div>
              <div className="font-medium text-slate-100 pt-1">TypeScript 5</div>
              <div>Type-safe analyst console</div>
            </div>
          </div>

          <div className="p-4 rounded-lg bg-[#111827] border border-slate-800 space-y-2">
            <span className="font-mono text-cyan-400 font-semibold uppercase tracking-wider text-[11px]">
              Packet Dissection
            </span>
            <div className="space-y-1 text-slate-300">
              <div className="font-medium text-slate-100">Native struct unpacker</div>
              <div>Zero-dependency C binary reader</div>
              <div className="font-medium text-slate-100 pt-1">Scapy &amp; PyShark</div>
              <div>Deep L7 packet fallback adapters</div>
            </div>
          </div>

          <div className="p-4 rounded-lg bg-[#111827] border border-slate-800 space-y-2">
            <span className="font-mono text-cyan-400 font-semibold uppercase tracking-wider text-[11px]">
              Backend &amp; API
            </span>
            <div className="space-y-1 text-slate-300">
              <div className="font-medium text-slate-100">FastAPI &amp; Uvicorn</div>
              <div>ASGI forensic REST service</div>
              <div className="font-medium text-slate-100 pt-1">Express &amp; Node.js</div>
              <div>Local development proxy &amp; Vite server</div>
            </div>
          </div>

          <div className="p-4 rounded-lg bg-[#111827] border border-slate-800 space-y-2">
            <span className="font-mono text-cyan-400 font-semibold uppercase tracking-wider text-[11px]">
              DevSecOps &amp; Security
            </span>
            <div className="space-y-1 text-slate-300">
              <div className="font-medium text-slate-100">GitHub Actions</div>
              <div>3-matrix CI (Python 3.10/3.11/3.12)</div>
              <div className="font-medium text-slate-100 pt-1">Ruff, mypy, Gitleaks</div>
              <div>Static typing, linting &amp; secret checks</div>
            </div>
          </div>
        </div>
      </section>

      {/* 5. DETECTION ENGINEERING & MITRE ATT&CK */}
      <section className="space-y-6">
        <div className="flex items-center space-x-2 text-cyan-400">
          <Shield className="w-4 h-4" />
          <h2 className="text-xs font-mono uppercase tracking-wider font-semibold">
            05 — Detection Engineering Methodology
          </h2>
        </div>
        <div className="space-y-2">
          <h3 className="text-2xl font-bold text-slate-100">
            Observable Traffic Characteristics &amp; Tunable Rules
          </h3>
          <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
            The detection engine evaluates 11 deterministic heuristics. Alerts are not arbitrary scores;
            they represent specific, evidence-backed network observations. Detections provide circumstantial
            indicators that require human analyst contextual validation.
          </p>
        </div>

        {/* Rule Selector & Deep Dive Card */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Rule Selector List */}
          <div className="space-y-2">
            <span className="text-xs font-mono uppercase text-slate-400 font-semibold">
              Sample Implemented Rules
            </span>
            {PORTFOLIO_DATA.detectionEngineering.sampleRules.map((rule) => (
              <div
                key={rule.id}
                onClick={() => setSelectedRuleId(rule.id)}
                className={`p-3 rounded border text-xs cursor-pointer transition ${
                  selectedRuleId === rule.id
                    ? "bg-slate-900 border-cyan-500 text-slate-100"
                    : "bg-[#111827] border-slate-800 text-slate-400 hover:border-slate-700"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-cyan-400 font-bold">{rule.id}</span>
                  <span className="font-mono text-[10px] text-slate-500">
                    MITRE: {rule.mitreAssociation.id}
                  </span>
                </div>
                <div className="font-medium mt-1 text-slate-200">{rule.name}</div>
              </div>
            ))}
          </div>

          {/* Rule Detail Evidence Card */}
          <div className="lg:col-span-2 p-5 rounded-lg bg-[#111827] border border-slate-800 space-y-4 text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <span className="font-mono text-cyan-400 font-bold text-sm">
                  {selectedRule.id}: {selectedRule.name}
                </span>
                <div className="text-slate-400 text-[11px] mt-0.5">
                  Potential ATT&amp;CK Association: {selectedRule.mitreAssociation.id} — {selectedRule.mitreAssociation.technique} ({selectedRule.mitreAssociation.tactic})
                </div>
              </div>
            </div>

            <div className="space-y-3">
              <div>
                <span className="font-mono text-slate-400 uppercase text-[10px] font-semibold">
                  What It Observes:
                </span>
                <p className="text-slate-200 mt-0.5 leading-relaxed">{selectedRule.observed}</p>
              </div>

              <div>
                <span className="font-mono text-slate-400 uppercase text-[10px] font-semibold">
                  Evidence Telemetry Captured:
                </span>
                <div className="mt-1 p-2 rounded bg-[#0B0F19] border border-slate-800 font-mono text-slate-300 text-[11px]">
                  {selectedRule.evidence}
                </div>
              </div>

              <div>
                <span className="font-mono text-slate-400 uppercase text-[10px] font-semibold">
                  Potential Investigation Interpretation:
                </span>
                <p className="text-slate-300 mt-0.5">{selectedRule.interpretation}</p>
              </div>

              <div className="p-3 rounded bg-amber-950/30 border border-amber-800/50 space-y-1">
                <span className="font-mono text-amber-400 uppercase text-[10px] font-bold flex items-center space-x-1">
                  <AlertCircle className="w-3 h-3" />
                  <span>False-Positive &amp; Benign Context Considerations:</span>
                </span>
                <p className="text-amber-200/90 text-[11px] leading-relaxed">
                  {selectedRule.falsePositiveConsiderations}
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 6. INVESTIGATION WORKFLOW */}
      <section className="space-y-6">
        <div className="flex items-center space-x-2 text-cyan-400">
          <Activity className="w-4 h-4" />
          <h2 className="text-xs font-mono uppercase tracking-wider font-semibold">
            06 — Analyst Investigation Workflow
          </h2>
        </div>
        <div className="space-y-2">
          <h3 className="text-2xl font-bold text-slate-100">
            Step-by-Step Incident Investigation Sequence
          </h3>
          <p className="text-sm text-slate-300 leading-relaxed max-w-3xl">
            A standardized, repeatable workflow designed to guide an incident responder or SOC analyst
            from raw capture acquisition to formal documentation.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
          {PORTFOLIO_DATA.workflow.map((item) => (
            <div
              key={item.step}
              onClick={() => item.targetTab && onNavigateToTab(item.targetTab)}
              className="p-4 rounded-lg bg-[#111827] border border-slate-800 hover:border-cyan-800/80 transition space-y-2 cursor-pointer group"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-cyan-400 font-bold text-sm">{item.step}</span>
                <span className="text-[10px] text-slate-500 group-hover:text-cyan-400 transition font-mono">
                  Open Tab →
                </span>
              </div>
              <h4 className="font-bold text-slate-200 group-hover:text-cyan-300 transition">
                {item.title}
              </h4>
              <p className="text-slate-400 leading-relaxed text-[11px]">{item.description}</p>
            </div>
          ))}
        </div>
      </section>

      {/* 7. CONTROLLED SYNTHETIC TEST LAB */}
      <section className="space-y-6">
        <div className="flex items-center space-x-2 text-cyan-400">
          <Database className="w-4 h-4" />
          <h2 className="text-xs font-mono uppercase tracking-wider font-semibold">
            07 — Controlled Testing Environment
          </h2>
        </div>
        <div className="space-y-2">
          <h3 className="text-2xl font-bold text-slate-100">
            Synthetic PCAP Regression Fixtures
          </h3>
          <p className="text-sm text-slate-300 leading-relaxed max-w-3xl">
            To ensure deterministic unit testing and avoid committing confidential packet data, the project
            generates controlled synthetic PCAP fixtures using Scapy.
          </p>
        </div>

        <div className="p-4 rounded-lg bg-amber-950/20 border border-amber-800/40 text-xs text-amber-200/90 leading-relaxed">
          <strong>Defensive Testing Transparency:</strong> These captures are controlled test data created in a laboratory environment and do not represent real-world compromised infrastructure or live adversary activity.
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          {[
            {
              id: "syn_port_scan",
              title: "Vertical TCP SYN Scan",
              packets: "45 packets",
              targets: "10.10.20.5:20-8080",
              heuristic: "RULE-001 (High)",
            },
            {
              id: "dns_tunnel",
              title: "DNS Tunneling & C2",
              packets: "110 packets",
              targets: "High entropy subdomains",
              heuristic: "RULE-004 (High)",
            },
            {
              id: "cleartext",
              title: "Cleartext HTTP & Metasploit Port",
              packets: "68 packets",
              targets: "/login.php & Port 4444",
              heuristic: "RULE-006 & RULE-003",
            },
            {
              id: "baseline",
              title: "Benign Corporate Web Baseline",
              packets: "250 packets",
              targets: "Slack, GitHub, Google TLS",
              heuristic: "0 alerts (Verified Benign)",
            },
          ].map((scenario) => (
            <div
              key={scenario.id}
              className="p-4 rounded-lg bg-[#111827] border border-slate-800 space-y-3"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-cyan-400 font-semibold text-[11px]">{scenario.packets}</span>
                <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] text-slate-400 font-mono">
                  Synthetic
                </span>
              </div>
              <div>
                <h4 className="font-bold text-slate-100">{scenario.title}</h4>
                <p className="text-slate-400 text-[11px] mt-1">{scenario.targets}</p>
              </div>
              <div className="text-[11px] font-mono text-rose-300">
                {scenario.heuristic}
              </div>
              <button
                onClick={() => {
                  onSelectSample(scenario.id);
                  onNavigateToTab("overview");
                }}
                className="w-full py-1.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-[11px] font-medium transition cursor-pointer"
              >
                Analyze Scenario →
              </button>
            </div>
          ))}
        </div>
      </section>

      {/* 8. SECURITY HARDENING & DEFENSIVE CONTROLS */}
      <section className="space-y-6">
        <div className="flex items-center space-x-2 text-cyan-400">
          <Lock className="w-4 h-4" />
          <h2 className="text-xs font-mono uppercase tracking-wider font-semibold">
            08 — Security Considerations &amp; Hardening
          </h2>
        </div>
        <div className="space-y-2">
          <h3 className="text-2xl font-bold text-slate-100">
            Defense-in-Depth Implementation
          </h3>
          <p className="text-sm text-slate-300 leading-relaxed max-w-3xl">
            Processing untrusted binary files carries inherent risks. The platform implements multi-layer
            security controls at the OS, container, network, and application layers.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border border-slate-800 rounded-lg overflow-hidden">
            <thead className="bg-[#111827] text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800">
              <tr>
                <th className="p-3">Control</th>
                <th className="p-3">Threat Vector Mitigated</th>
                <th className="p-3">Implementation Mechanism</th>
                <th className="p-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 bg-[#0B0F19] text-slate-300">
              {PORTFOLIO_DATA.securityControls.map((sec, idx) => (
                <tr key={idx} className="hover:bg-slate-900/40">
                  <td className="p-3 font-semibold text-slate-100">{sec.control}</td>
                  <td className="p-3 text-rose-300/90">{sec.riskAddressed}</td>
                  <td className="p-3 font-mono text-[11px] text-slate-400">{sec.implementation}</td>
                  <td className="p-3">
                    <span className="flex items-center space-x-1 text-emerald-400 font-mono text-[11px]">
                      <CheckCircle2 className="w-3 h-3" />
                      <span>Verified</span>
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* 9. FORENSIC LIMITATIONS & OPERATIONAL BOUNDARIES */}
      <section className="space-y-6">
        <div className="flex items-center space-x-2 text-amber-400">
          <AlertCircle className="w-4 h-4" />
          <h2 className="text-xs font-mono uppercase tracking-wider font-semibold">
            09 — Forensic Limitations &amp; Operational Boundaries
          </h2>
        </div>
        <div className="space-y-2">
          <h3 className="text-2xl font-bold text-slate-100">
            Professional Transparency &amp; Real-World Boundaries
          </h3>
          <p className="text-sm text-slate-300 leading-relaxed max-w-3xl">
            Mature security engineering explicitly articulates operational boundaries and failure domains.
          </p>
        </div>

        <div className="p-5 rounded-lg bg-[#111827] border border-slate-800 space-y-3 text-xs">
          {PORTFOLIO_DATA.limitations.map((lim, idx) => (
            <div key={idx} className="flex items-start space-x-3 text-slate-300">
              <span className="font-mono text-amber-400 font-bold mt-0.5">[{idx + 1}]</span>
              <p className="leading-relaxed">{lim}</p>
            </div>
          ))}
        </div>
      </section>

      {/* 10. FUTURE ROADMAP (PLANNED) */}
      <section className="space-y-6">
        <div className="flex items-center space-x-2 text-cyan-400">
          <Compass className="w-4 h-4" />
          <h2 className="text-xs font-mono uppercase tracking-wider font-semibold">
            10 — Engineering Roadmap
          </h2>
        </div>
        <div className="space-y-2">
          <h3 className="text-2xl font-bold text-slate-100">
            Planned Future Enhancements
          </h3>
          <p className="text-sm text-slate-300 leading-relaxed">
            The following enhancements are formally planned and marked accordingly:
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
          {PORTFOLIO_DATA.futureRoadmap.map((item, idx) => (
            <div key={idx} className="p-4 rounded-lg bg-[#111827] border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-200">{item.item}</span>
                <span className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] text-slate-400 font-mono">
                  {item.status}
                </span>
              </div>
              <p className="text-slate-400 text-[11px] leading-relaxed">{item.description}</p>
            </div>
          ))}
        </div>
      </section>

      {/* 11. REPOSITORY & DOCUMENTATION ACTIONS */}
      <section className="border-t border-slate-800 pt-10">
        <div className="p-6 rounded-lg bg-[#111827] border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-6">
          <div className="space-y-1 text-center sm:text-left">
            <h4 className="text-lg font-bold text-slate-100">
              Explore the Implementation
            </h4>
            <p className="text-xs text-slate-400">
              Review source code, inspect rule implementations, and verify automated test suites.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={onOpenWorkspace}
              className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition cursor-pointer"
            >
              Open Analyst Workspace
            </button>
            <a
              href={PORTFOLIO_DATA.githubUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center space-x-1.5 px-4 py-2 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-medium transition"
            >
              <Github className="w-3.5 h-3.5" />
              <span>View Source Code</span>
            </a>
          </div>
        </div>
      </section>
    </div>
  );
};
