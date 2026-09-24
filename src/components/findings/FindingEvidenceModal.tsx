import React, { useState } from "react";
import {
  X,
  ShieldAlert,
  Terminal,
  Copy,
  Check,
  ExternalLink,
  Info,
  AlertTriangle,
  Layers,
  ArrowRight,
  Database,
  Search,
} from "lucide-react";
import { AlertFinding } from "../../types/analyzer";
import { getSeverityBadgeClass } from "../../utils/formatters";

interface FindingEvidenceModalProps {
  finding: AlertFinding | null;
  onClose: () => void;
  onViewFlows?: (ip: string) => void;
}

const MITRE_MAP: Record<
  string,
  { id: string; tactic: string; technique: string; url: string; justification: string }
> = {
  "RULE-001": {
    id: "T1046",
    tactic: "Discovery",
    technique: "Network Service Discovery",
    url: "https://attack.mitre.org/techniques/T1046/",
    justification:
      "Rapid transmission of TCP SYN frames across target ports or hosts without completing three-way handshakes is the characteristic signature of network port scanning.",
  },
  "RULE-002": {
    id: "T1499",
    tactic: "Impact",
    technique: "Endpoint Denial of Service",
    url: "https://attack.mitre.org/techniques/T1499/",
    justification:
      "High packet-per-second volumetric transmission from a single endpoint targeted at exhausting link capacity or connection state buffers.",
  },
  "RULE-003": {
    id: "T1571",
    tactic: "Command and Control",
    technique: "Non-Standard Port",
    url: "https://attack.mitre.org/techniques/T1571/",
    justification:
      "Adversary command listeners or reverse shells configured on unusual or non-standard TCP ports (e.g. 1337, 4444, 31337).",
  },
  "RULE-004": {
    id: "T1071.004",
    tactic: "Command and Control",
    technique: "Application Layer Protocol: DNS",
    url: "https://attack.mitre.org/techniques/T1071/004/",
    justification:
      "Elevated query rates or high volumes of DNS lookups indicating C2 communication polling or active domain enumeration.",
  },
  "RULE-005": {
    id: "T1572",
    tactic: "Command and Control",
    technique: "Protocol Tunneling",
    url: "https://attack.mitre.org/techniques/T1572/",
    justification:
      "High Shannon entropy subdomain labels or unusually long query names characteristic of DNS data exfiltration tools (dnscat2, iodine) and DGAs.",
  },
  "RULE-006": {
    id: "T1046",
    tactic: "Discovery",
    technique: "Network Service Discovery",
    url: "https://attack.mitre.org/techniques/T1046/",
    justification:
      "Repeated failed connection attempts (timeouts or TCP RSTs) indicative of probes directed against closed or firewalled ports.",
  },
  "RULE-007": {
    id: "T1048",
    tactic: "Exfiltration",
    technique: "Exfiltration Over Alternative Protocol",
    url: "https://attack.mitre.org/techniques/T1048/",
    justification:
      "Anomalous ICMP traffic volume or sustained echo ping sequences indicating covert ICMP tunnel channels or aggressive host sweeps.",
  },
  "RULE-008": {
    id: "T1040",
    tactic: "Credential Access",
    technique: "Network Sniffing",
    url: "https://attack.mitre.org/techniques/T1040/",
    justification:
      "Transmission of sensitive authentication credentials or authorization tokens over unencrypted cleartext protocols (HTTP, FTP, Telnet).",
  },
  "RULE-009": {
    id: "T1595.002",
    tactic: "Reconnaissance",
    technique: "Active Scanning: Vulnerability Scanning",
    url: "https://attack.mitre.org/techniques/T1595/002/",
    justification:
      "Automated vulnerability scanner User-Agent signatures (sqlmap, nikto, nessus, nmap) or oversized fuzzing URI paths.",
  },
  "RULE-010": {
    id: "T1573",
    tactic: "Command and Control",
    technique: "Encrypted Channel",
    url: "https://attack.mitre.org/techniques/T1573/",
    justification:
      "Negotiation of cryptographically deprecated TLS protocols (SSL 3.0, TLS 1.0, TLS 1.1) susceptible to downgrade and interception attacks.",
  },
  "RULE-011": {
    id: "T1568.002",
    tactic: "Command and Control",
    technique: "Domain Generation Algorithms",
    url: "https://attack.mitre.org/techniques/T1568/002/",
    justification:
      "Rapid resolution attempts across an anomalous quantity of distinct domains characteristic of malware seeking active C2 seeds.",
  },
};

export const FindingEvidenceModal: React.FC<FindingEvidenceModalProps> = ({
  finding,
  onClose,
  onViewFlows,
}) => {
  const [copied, setCopied] = useState<boolean>(false);

  if (!finding) return null;

  const fid = finding.finding_id || finding.id || "F-0";
  const ruleId = finding.rule_id || finding.detection_rule || "RULE-000";
  const badge = getSeverityBadgeClass(finding.severity);
  const mitre = MITRE_MAP[ruleId] || {
    id: "T1046",
    tactic: "Discovery",
    technique: "Network Reconnaissance",
    url: "https://attack.mitre.org/",
    justification: "Network anomaly observed matching heuristic threshold criteria.",
  };

  const copyFindingJson = () => {
    navigator.clipboard.writeText(JSON.stringify(finding, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-[#111827] border border-slate-700/80 rounded-lg max-w-3xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center space-x-3 min-w-0">
            <span
              className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border shrink-0 ${badge.bg} ${badge.text} ${badge.border}`}
            >
              {finding.severity}
            </span>
            <div className="min-w-0">
              <div className="flex items-center space-x-2 text-xs">
                <span className="font-mono text-cyan-400 font-semibold">{ruleId}</span>
                <span className="text-slate-600" aria-hidden="true">·</span>
                <span className="text-slate-400">{finding.category}</span>
                <span className="text-slate-600" aria-hidden="true">·</span>
                <span className="text-slate-500 font-mono">
                  Confidence: {(finding.confidence * 100).toFixed(0)}%
                </span>
              </div>
              <h3 className="text-sm font-semibold text-slate-100 truncate mt-0.5">
                {finding.title}
              </h3>
            </div>
          </div>

          <div className="flex items-center space-x-2 shrink-0">
            <button
              onClick={copyFindingJson}
              title="Copy finding as JSON"
              className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition cursor-pointer"
            >
              {copied ? (
                <Check className="w-4 h-4 text-emerald-400" />
              ) : (
                <Copy className="w-4 h-4" />
              )}
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Modal Body - Scrollable */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs text-slate-300">
          {/* Narrative */}
          <div className="space-y-1.5">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
              Observation Narrative
            </span>
            <p className="p-3.5 rounded bg-slate-950/70 border border-slate-800/80 leading-relaxed text-slate-200">
              {finding.description}
            </p>
          </div>

          {/* MITRE ATT&CK Correlation */}
          <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-2">
            <div className="flex items-center justify-between border-b border-slate-900 pb-2">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                MITRE ATT&amp;CK Alignment
              </span>
              <a
                href={mitre.url}
                target="_blank"
                rel="noopener noreferrer"
                className="font-mono text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 text-[11px]"
              >
                <span>{mitre.id}</span>
                <ExternalLink className="w-3 h-3 ml-0.5" />
              </a>
            </div>

            <div className="space-y-1">
              <div className="font-semibold text-slate-200">
                {mitre.tactic} · {mitre.technique}
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                {mitre.justification}
              </p>
            </div>
          </div>

          {/* Involved Endpoints & Protocol */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono">
            <div className="bg-slate-950/80 p-3 rounded border border-slate-800 space-y-1">
              <span className="text-slate-500 text-[10px] block">Source Host</span>
              <div className="text-slate-200 font-medium truncate">
                {finding.source_ip || "Multi-Source"}
              </div>
              {finding.source_port && (
                <span className="text-slate-500 text-[10px]">Port: {finding.source_port}</span>
              )}
            </div>

            <div className="bg-slate-950/80 p-3 rounded border border-slate-800 space-y-1">
              <span className="text-slate-500 text-[10px] block">Target Destination</span>
              <div className="text-slate-200 font-medium truncate">
                {finding.destination_ip || (finding.destination_port ? `Port :${finding.destination_port}` : "Distributed")}
              </div>
              {finding.destination_port && (
                <span className="text-slate-500 text-[10px]">Port: {finding.destination_port}</span>
              )}
            </div>

            <div className="bg-slate-950/80 p-3 rounded border border-slate-800 space-y-1">
              <span className="text-slate-500 text-[10px] block">Transport Protocol</span>
              <div className="text-slate-200 font-medium">{finding.protocol || "Transport Agnostic"}</div>
              <span className="text-slate-500 text-[10px]">Deterministic Evaluation</span>
            </div>
          </div>

          {/* Packet Numbers Involved */}
          {finding.packet_numbers && finding.packet_numbers.length > 0 && (
            <div className="space-y-1.5">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                Correlated Packet Frames ({finding.packet_numbers.length} samples)
              </span>
              <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
                {finding.packet_numbers.map((pkt) => (
                  <span
                    key={pkt}
                    className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-400"
                  >
                    #{pkt}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Raw Heuristic Telemetry Evidence */}
          {finding.evidence && Object.keys(finding.evidence).length > 0 && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  Mathematical Evidence &amp; Telemetry Object
                </span>
                <span className="text-[10px] font-mono text-slate-500">Heuristic Variables</span>
              </div>
              <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
                <pre>{JSON.stringify(finding.evidence, null, 2)}</pre>
              </div>
            </div>
          )}

          {/* Remediation & Analyst Next Steps */}
          {finding.recommended_next_step && (
            <div className="bg-cyan-950/30 border border-cyan-800/50 p-4 rounded-lg space-y-1">
              <span className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider block">
                Recommended SOC Action
              </span>
              <p className="text-slate-200 leading-relaxed text-xs">
                {finding.recommended_next_step}
              </p>
            </div>
          )}

          {/* Forensic Limitations Disclosure */}
          {finding.limitations && (
            <div className="bg-slate-950/60 border border-slate-800/80 p-3.5 rounded-lg space-y-1 text-slate-400 text-[11px]">
              <div className="flex items-center space-x-1.5 text-slate-400 font-medium">
                <Info className="w-3.5 h-3.5 text-amber-400" />
                <span>Forensic Limitation Disclosure</span>
              </div>
              <p className="italic leading-relaxed">{finding.limitations}</p>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-3.5 border-t border-slate-800 bg-slate-950 flex items-center justify-between text-xs">
          <span className="text-slate-500 font-mono text-[11px]">ID: {fid}</span>

          <div className="flex items-center space-x-2">
            {onViewFlows && finding.source_ip && (
              <button
                onClick={() => {
                  onViewFlows(finding.source_ip!);
                  onClose();
                }}
                className="px-3 py-1.5 rounded bg-slate-900 hover:bg-slate-800 text-cyan-400 border border-slate-700 text-xs font-medium cursor-pointer"
              >
                Inspect Host Flows
              </button>
            )}
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold cursor-pointer"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
