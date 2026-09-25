/**
 * Portfolio Case Study Structured Data Object
 * 
 * Strict Ground Truth: Represents only actual implemented functionality,
 * verified test suites (44 tests), native/Scapy/PyShark engines, and real architecture.
 * No fabricated statistics, testimonials, or fake attack claims.
 */

export interface PortfolioCaseStudy {
  title: string;
  subtitle: string;
  category: string;
  role: string;
  descriptions: {
    short: string;
    medium: string;
    technical: string;
  };
  technologies: {
    language: string[];
    networkAnalysis: string[];
    backend: string[];
    frontend: string[];
    testing: string[];
    devSecOps: string[];
    containerization: string[];
  };
  skills: string[];
  features: Array<{
    name: string;
    category: string;
    description: string;
    status: "IMPLEMENTED" | "PLANNED";
  }>;
  workflow: Array<{
    step: string;
    title: string;
    description: string;
    targetTab?: string;
  }>;
  detectionEngineering: {
    philosophy: string;
    rulesCount: number;
    profiles: string[];
    sampleRules: Array<{
      id: string;
      name: string;
      observed: string;
      evidence: string;
      interpretation: string;
      falsePositiveConsiderations: string;
      mitreAssociation: {
        id: string;
        technique: string;
        tactic: string;
      };
    }>;
  };
  securityControls: Array<{
    control: string;
    riskAddressed: string;
    implementation: string;
    verified: boolean;
  }>;
  limitations: string[];
  futureRoadmap: Array<{
    item: string;
    description: string;
    status: "PLANNED";
  }>;
  githubUrl: string;
}

export const PORTFOLIO_DATA: PortfolioCaseStudy = {
  title: "Automated Python PCAP Analyzer & Threat Parser",
  subtitle: "Defensive Network Forensics & Evidence-Based Threat Analysis",
  category: "Defensive Security / Network Forensics",
  role: "Security Engineer & Full-Stack Developer",
  descriptions: {
    short:
      "Python-based PCAP analysis platform for network forensics, IOC extraction, flow analysis, and evidence-based threat detection.",
    medium:
      "Built a defensive PCAP analysis platform using Python, Scapy and PyShark to reconstruct network activity, extract IOCs, analyze protocols, and identify suspicious traffic patterns through configurable detection rules.",
    technical:
      "Engineered a modular PCAP/PCAPNG analysis platform with Python, Scapy, PyShark and FastAPI, combining protocol analysis, flow reconstruction, IOC extraction, configurable detection logic, reproducible synthetic testing, and a React-based analyst interface.",
  },
  technologies: {
    language: ["Python 3.10+", "TypeScript"],
    networkAnalysis: ["Scapy", "PyShark", "Wireshark / tshark", "Native struct unpacker"],
    backend: ["FastAPI", "Pydantic", "Express", "Node.js"],
    frontend: ["React 19", "Vite", "Tailwind CSS", "Recharts", "Lucide Icons"],
    testing: ["unittest", "pytest", "44 automated test cases"],
    devSecOps: ["GitHub Actions", "Ruff", "mypy", "Gitleaks", "pip-audit"],
    containerization: ["Docker (Multi-stage non-root)", "Docker Compose"],
  },
  skills: [
    "Python",
    "PCAP Analysis",
    "Network Forensics",
    "Network Security",
    "Detection Engineering",
    "IOC Extraction",
    "SOC / Blue Team",
    "FastAPI",
    "React",
    "Docker",
    "DevSecOps",
  ],
  features: [
    {
      name: "PCAP/PCAPNG Binary Dissection",
      category: "Packet Parsing",
      description: "Dual-engine architecture utilizing zero-dependency native C-struct unpacker with Scapy & PyShark fallback.",
      status: "IMPLEMENTED",
    },
    {
      name: "Multi-Layer Protocol Demuxing",
      category: "Protocol Intelligence",
      description: "Extracts L2–L7 header data across Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, and TLS.",
      status: "IMPLEMENTED",
    },
    {
      name: "5-Tuple Flow Reconstruction",
      category: "Network Flows",
      description: "Reassembles bidirectional conversation streams, byte and packet distributions, and TCP 3-way handshake states.",
      status: "IMPLEMENTED",
    },
    {
      name: "DNS Tunneling & Anomaly Detection",
      category: "DNS Analysis",
      description: "Evaluates Shannon entropy scores across subdomains and tracks high NXDOMAIN response ratios.",
      status: "IMPLEMENTED",
    },
    {
      name: "HTTP Cleartext & Scanner Signature Auditing",
      category: "HTTP Analysis",
      description: "Audits User-Agent strings for automated recon tools (sqlmap, nikto, nessus, nmap) and flags cleartext passwords.",
      status: "IMPLEMENTED",
    },
    {
      name: "TLS Metadata & Deprecation Inspection",
      category: "TLS Metadata",
      description: "Inspects ClientHello/ServerHello SNI records, cipher suites, and negotiated TLS versions (identifying SSL 3.0–TLS 1.1).",
      status: "IMPLEMENTED",
    },
    {
      name: "Deterministic IOC Harvester",
      category: "IOC Extraction",
      description: "Harvests unique IPv4, IPv6, domain names, URLs, hostnames, and ports with exact first/last packet indices.",
      status: "IMPLEMENTED",
    },
    {
      name: "11 Evidence-Based Heuristic Rules",
      category: "Detection Engine",
      description: "Evaluates observable traffic criteria without black-box ML, producing transparent findings with packet indices.",
      status: "IMPLEMENTED",
    },
    {
      name: "Environment-Aware Profiles",
      category: "Configuration",
      description: "Provides calibrated detection profiles (default, home_lab, enterprise, high_volume) to minimize false positives.",
      status: "IMPLEMENTED",
    },
    {
      name: "Cryptographic SHA-256 Verification",
      category: "Forensic Integrity",
      description: "Calculates file integrity hash upon ingestion to ensure chain-of-custody reproducibility.",
      status: "IMPLEMENTED",
    },
    {
      name: "12-Section Investigation Report",
      category: "Forensic Reporting",
      description: "Compiles formal plaintext incident reports with executive summary, timeline, observables, and triage remediation.",
      status: "IMPLEMENTED",
    },
    {
      name: "Controlled Synthetic Test Fixtures",
      category: "Testing",
      description: "Deterministic PCAPs created via Scapy for unit testing regression validation across all 11 detection rules.",
      status: "IMPLEMENTED",
    },
    {
      name: "Sandboxed Local Storage & Retention",
      category: "Security",
      description: "Path-traversal-proof filesystem isolation with automated retention cleanup scripts.",
      status: "IMPLEMENTED",
    },
    {
      name: "Isolated Demo Mode",
      category: "Demonstration",
      description: "Safely runs 4 pre-packaged synthetic scenarios with prominent DEMO DATA indicators.",
      status: "IMPLEMENTED",
    },
  ],
  workflow: [
    {
      step: "01",
      title: "Acquire & Ingest Capture",
      description: "Upload PCAP/PCAPNG or select a controlled synthetic test scenario.",
      targetTab: "pcap",
    },
    {
      step: "02",
      title: "Verify Forensic Integrity",
      description: "Compute SHA-256 fingerprint, extract capture file metadata, and validate header boundaries.",
      targetTab: "overview",
    },
    {
      step: "03",
      title: "Dissect Multi-Layer Protocols",
      description: "Demux L2–L7 headers into structured packet records with microsecond timestamps.",
      targetTab: "overview",
    },
    {
      step: "04",
      title: "Reconstruct Network Flows",
      description: "Group packets into bidirectional 5-tuple conversations and audit TCP handshake completion states.",
      targetTab: "network",
    },
    {
      step: "05",
      title: "Inspect Deep Protocols",
      description: "Audit DNS query entropy, HTTP methods/User-Agents, and TLS SNI/version negotiation records.",
      targetTab: "dns",
    },
    {
      step: "06",
      title: "Extract Observable IOCs",
      description: "Harvest unique IP addresses, queried domains, request URLs, and active ports.",
      targetTab: "iocs",
    },
    {
      step: "07",
      title: "Evaluate Heuristic Rules",
      description: "Run 11 deterministic detection rules against configured environment thresholds.",
      targetTab: "findings",
    },
    {
      step: "08",
      title: "Validate Finding Evidence",
      description: "Examine packet references, byte ratios, and cross-reference potential MITRE ATT&CK techniques.",
      targetTab: "findings",
    },
    {
      step: "09",
      title: "Export Investigation Report",
      description: "Generate structured JSON or comprehensive 12-section plaintext technical incident reports.",
      targetTab: "reports",
    },
  ],
  detectionEngineering: {
    philosophy:
      "Detections are based strictly on observable traffic characteristics, mathematical ratios, and protocol invariants. Findings represent potential security observations that require analyst contextual validation, not definitive proof of compromise.",
    rulesCount: 11,
    profiles: ["default", "home_lab", "enterprise", "high_volume"],
    sampleRules: [
      {
        id: "RULE-001",
        name: "Potential TCP SYN scanning pattern",
        observed:
          "High volume of unacknowledged TCP SYN connection attempts targeting diverse destination ports with low completion ratio.",
        evidence:
          "syn_packets_transmitted, unique_destination_ports_targeted, completed_handshakes, handshake_completion_ratio (<= 15%), sample_targeted_ports.",
        interpretation:
          "Potential network reconnaissance or port discovery sweep across internal/external hosts.",
        falsePositiveConsiderations:
          "Legitimate vulnerability scanners, network inventory tools, or misconfigured load balancers can trigger this rule.",
        mitreAssociation: {
          id: "T1046",
          technique: "Network Service Discovery",
          tactic: "Discovery",
        },
      },
      {
        id: "RULE-004",
        name: "High-Entropy DNS Query (Tunneling / DGA)",
        observed:
          "DNS query domain with Shannon entropy >= 3.8 and length >= 25 characters.",
        evidence:
          "query_name, entropy_score (bits/char), query_length, query_type (TXT/A), destination_dns_server.",
        interpretation:
          "Potential covert DNS tunneling, data exfiltration chunks, or Algorithmically Generated Domains (DGA) query.",
        falsePositiveConsiderations:
          "Legitimate Content Delivery Networks (CDNs), anti-spam DNSBL lookups, and cloud infrastructure telemetry often use encoded subdomains.",
        mitreAssociation: {
          id: "T1071.004",
          technique: "Application Layer Protocol: DNS",
          tactic: "Command and Control",
        },
      },
      {
        id: "RULE-006",
        name: "Cleartext HTTP Authentication Credentials",
        observed:
          "HTTP request payload transmitting unencrypted authentication fields (e.g. user=, pass=, auth=) or Basic Auth headers.",
        evidence:
          "http_uri, http_method, destination_ip, destination_port, cleartext_field_matches, packet_index.",
        interpretation:
          "Potential transmission of sensitive credentials over unencrypted transport susceptible to eavesdropping.",
        falsePositiveConsiderations:
          "Legacy internal administrative utilities or deliberate honeypot endpoints on isolated test networks.",
        mitreAssociation: {
          id: "T1040",
          technique: "Network Sniffing",
          tactic: "Credential Access",
        },
      },
      {
        id: "RULE-007",
        name: "Known Automated Security Scanner User-Agent",
        observed:
          "HTTP User-Agent header matching known reconnaissance or exploitation tools (sqlmap, nikto, nessus, nmap, dirbuster).",
        evidence:
          "user_agent_string, matched_signature, client_ip, destination_ip, requested_uri, packet_index.",
        interpretation:
          "Potential automated vulnerability scanning or exploitation attempts targeting web services.",
        falsePositiveConsiderations:
          "Scheduled internal vulnerability assessments, penetration testing engagements, or security compliance scanners.",
        mitreAssociation: {
          id: "T1595.002",
          technique: "Active Scanning: Vulnerability Scanning",
          tactic: "Reconnaissance",
        },
      },
    ],
  },
  securityControls: [
    {
      control: "Strict File Upload Validation",
      riskAddressed: "Arbitrary file upload & shell execution",
      implementation: "Rejection of non-.pcap/.pcapng files, 50MB size limit (HTTP 413), and file signature check.",
      verified: true,
    },
    {
      control: "Path Traversal Defenses",
      riskAddressed: "Directory traversal & file overwrite",
      implementation: "Analysis IDs strictly validated against ^[a-zA-Z0-9_-]{12,64}$, rejection of '..' and separators.",
      verified: true,
    },
    {
      control: "Subprocess Argument Array Isolation",
      riskAddressed: "Command injection",
      implementation: "All Python CLI invocations use strict argument arrays (shell=False) with zero string concatenation.",
      verified: true,
    },
    {
      control: "Execution Timeout & Concurrency Semaphore",
      riskAddressed: "Denial of Service / resource exhaustion",
      implementation: "Hard 60s timeout guard per analysis and maximum 2 concurrent analyses (HTTP 429 when saturated).",
      verified: true,
    },
    {
      control: "Unprivileged Container Execution",
      riskAddressed: "Container breakout & host compromise",
      implementation: "Docker runs under dedicated non-root user (pcapuser, UID 10001) with no-new-privileges:true.",
      verified: true,
    },
    {
      control: "Automated Ephemeral Retention",
      riskAddressed: "Sensitive data accumulation on disk",
      implementation: "Sandboxed folders older than RETENTION_DAYS (default: 7) purged via cleanup script.",
      verified: true,
    },
  ],
  limitations: [
    "Encrypted Payload Invisibility: Encrypted TLS application data cannot be inspected without private session keys.",
    "Heuristic Alerts Are Not Proof: Statistical anomaly detections provide circumstantial indicators that require human SOC analyst verification.",
    "Packet Capture Boundary: Analysis is strictly confined to observed packets; off-path or unmirrored communications cannot be assessed.",
    "Lack of IP Reputation Data: The analyzer operates completely offline without querying live commercial threat intelligence feeds.",
    "Resource Consumption on Large Files: Processing PCAP files > 500MB without indexing can cause elevated memory utilization.",
  ],
  futureRoadmap: [
    {
      item: "Zeek & Suricata Log Ingestion",
      description: "Incorporate Zeek conn.log and Suricata EVE JSON records alongside raw PCAP parsing.",
      status: "PLANNED",
    },
    {
      item: "JA4+ TLS Client Fingerprinting",
      description: "Extend TLS metadata parser to calculate modern JA4 / JA4S cryptographic client fingerprints.",
      status: "PLANNED",
    },
    {
      item: "STIX 2.1 & TAXII Export",
      description: "Package extracted observables into structured STIX 2.1 Threat Intelligence bundles.",
      status: "PLANNED",
    },
    {
      item: "Sigma-Compatible Rule Modeling",
      description: "Support importing and executing Sigma-formatted network detection specifications.",
      status: "PLANNED",
    },
    {
      item: "Wireshark Display Filter Generator",
      description: "Auto-generate precise Wireshark capture and display filter strings for flagged finding packets.",
      status: "PLANNED",
    },
  ],
  githubUrl: "https://github.com/defensive-sec/automated-python-pcap-analyzer",
};
