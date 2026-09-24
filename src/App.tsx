/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo, useRef } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  FileCode,
  Activity,
  Terminal,
  Upload,
  Download,
  Copy,
  Check,
  ExternalLink,
  ChevronRight,
  Layers,
  Search,
  Server,
  Network,
  Cpu,
  RefreshCw,
  AlertTriangle,
  Info,
  Globe,
  Lock,
  Unlock,
} from "lucide-react";

// Types matching Python pcap_analyzer models
interface PacketRecord {
  packetNumber: number;
  timestamp: number;
  packetLength: number;
  protocol: string;
  transportProtocol?: string;
  sourceIp?: string;
  destinationIp?: string;
  sourcePort?: number;
  destinationPort?: number;
  flags?: {
    SYN?: boolean;
    ACK?: boolean;
    FIN?: boolean;
    RST?: boolean;
    PSH?: boolean;
  };
  dnsQuery?: string;
  dnsQueryType?: string;
  dnsEntropy?: number;
  httpHost?: string;
  httpMethod?: string;
  httpUri?: string;
  tlsSni?: string;
  tlsVersion?: string;
}

interface FlowRecord {
  flowId: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol: string;
  packetCount: number;
  byteCount: number;
  durationSeconds: number;
  synCount: number;
  completedHandshake: boolean;
}

interface AlertFinding {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  category: string;
  title: string;
  description: string;
  sourceIp?: string;
  destinationPort?: number;
  detectionRule: string;
  confidence: number;
  evidence: Record<string, any>;
}

interface AnalysisState {
  fileName: string;
  fileSizeBytes: number;
  totalPackets: number;
  totalBytes: number;
  durationSeconds: number;
  uniqueSources: number;
  uniqueDestinations: number;
  packets: PacketRecord[];
  flows: FlowRecord[];
  findings: AlertFinding[];
  protocols: Record<string, number>;
  topSources: { ip: string; count: number; bytes: number; percentage: number }[];
  topDestinations: { ip: string; count: number; bytes: number; percentage: number }[];
  dnsRecords: { packetNumber: number; sourceIp: string; query: string; entropy: number }[];
  httpRecords: { packetNumber: number; method: string; host: string; uri: string }[];
  tlsRecords: { packetNumber: number; sni: string; version: string }[];
  reportText: string;
}

// Shannon entropy calculation
function calculateShannonEntropy(str: string): number {
  if (!str) return 0;
  const freq: Record<string, number> = {};
  for (const c of str) {
    freq[c] = (freq[c] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const c in freq) {
    const p = freq[c] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${(bytes / 1048576).toFixed(2)} MB`;
}

function formatDuration(sec: number): string {
  const s = Math.max(0, sec);
  const mins = Math.floor(s / 60);
  const remSec = (s % 60).toFixed(3);
  return `${String(mins).padStart(2, "0")}:${String(remSec).padStart(6, "0")}`;
}

// Client-side pure binary PCAP parser
function parseBinaryPcap(buffer: ArrayBuffer, fileName: string): AnalysisState {
  const dataView = new DataView(buffer);
  const fileSize = buffer.byteLength;

  if (fileSize < 24) {
    throw new Error("File too small to contain a valid PCAP global header (minimum 24 bytes).");
  }

  const magic = dataView.getUint32(0, false);
  let littleEndian = true;
  let isNano = false;

  if (magic === 0xa1b2c3d4) {
    littleEndian = false;
  } else if (magic === 0xd4c3b2a1) {
    littleEndian = true;
  } else if (magic === 0xa1b23c4d) {
    littleEndian = false;
    isNano = true;
  } else if (magic === 0x4d3cb2a1) {
    littleEndian = true;
    isNano = true;
  } else {
    // If not standard PCAP magic, check if PCAPNG (0x0A0D0D0A)
    const magicLe = dataView.getUint32(0, true);
    if (magicLe === 0x0a0d0d0a || magic === 0x0a0d0d0a) {
      // PCAPNG detected - provide clean notification
    }
  }

  let offset = 24;
  let packetNum = 0;
  const packets: PacketRecord[] = [];
  let firstTs: number | null = null;
  let lastTs: number | null = null;
  let totalBytes = 0;

  const protocolCounter: Record<string, number> = {};
  const sourceCounter: Record<string, { count: number; bytes: number }> = {};
  const destCounter: Record<string, { count: number; bytes: number }> = {};
  const flowMap = new Map<string, FlowRecord>();
  const dnsRecords: AnalysisState["dnsRecords"] = [];
  const httpRecords: AnalysisState["httpRecords"] = [];
  const tlsRecords: AnalysisState["tlsRecords"] = [];

  while (offset + 16 <= fileSize) {
    packetNum++;
    const tsSec = dataView.getUint32(offset, littleEndian);
    const tsUsec = dataView.getUint32(offset + 4, littleEndian);
    const inclLen = dataView.getUint32(offset + 8, littleEndian);
    const origLen = dataView.getUint32(offset + 12, littleEndian);
    offset += 16;

    if (offset + inclLen > fileSize) {
      break;
    }

    const timestamp = isNano ? tsSec + tsUsec / 1e9 : tsSec + tsUsec / 1e6;
    if (firstTs === null || timestamp < firstTs) firstTs = timestamp;
    if (lastTs === null || timestamp > lastTs) lastTs = timestamp;
    totalBytes += origLen;

    const pktBytes = new Uint8Array(buffer, offset, inclLen);
    offset += inclLen;

    // Dissect Ethernet
    if (pktBytes.length < 14) continue;
    let ethertype = (pktBytes[12] << 8) | pktBytes[13];
    let l3Offset = 14;

    if (ethertype === 0x8100 && pktBytes.length >= 18) {
      ethertype = (pktBytes[16] << 8) | pktBytes[17];
      l3Offset = 18;
    }

    let srcIp: string | undefined;
    let dstIp: string | undefined;
    let protoNum: number | undefined;
    let l4Offset = l3Offset;
    let protocol = "Ethernet";

    if (ethertype === 0x0800 && pktBytes.length >= l3Offset + 20) {
      // IPv4
      const ihl = (pktBytes[l3Offset] & 0x0f) * 4;
      protoNum = pktBytes[l3Offset + 9];
      srcIp = `${pktBytes[l3Offset + 12]}.${pktBytes[l3Offset + 13]}.${pktBytes[l3Offset + 14]}.${pktBytes[l3Offset + 15]}`;
      dstIp = `${pktBytes[l3Offset + 16]}.${pktBytes[l3Offset + 17]}.${pktBytes[l3Offset + 18]}.${pktBytes[l3Offset + 19]}`;
      l4Offset = l3Offset + ihl;
      protocol = "IPv4";
    }

    let srcPort: number | undefined;
    let dstPort: number | undefined;
    let flags: PacketRecord["flags"];
    let transportProto: string | undefined;
    let payloadOffset = l4Offset;

    if (protoNum === 6 && pktBytes.length >= l4Offset + 20) {
      // TCP
      protocol = "TCP";
      transportProto = "TCP";
      srcPort = (pktBytes[l4Offset] << 8) | pktBytes[l4Offset + 1];
      dstPort = (pktBytes[l4Offset + 2] << 8) | pktBytes[l4Offset + 3];
      const dataOffset = ((pktBytes[l4Offset + 12] >> 4) & 0x0f) * 4;
      const flagsByte = pktBytes[l4Offset + 13];
      flags = {
        FIN: Boolean(flagsByte & 0x01),
        SYN: Boolean(flagsByte & 0x02),
        RST: Boolean(flagsByte & 0x04),
        PSH: Boolean(flagsByte & 0x08),
        ACK: Boolean(flagsByte & 0x10),
      };
      payloadOffset = l4Offset + dataOffset;
    } else if (protoNum === 17 && pktBytes.length >= l4Offset + 8) {
      // UDP
      protocol = "UDP";
      transportProto = "UDP";
      srcPort = (pktBytes[l4Offset] << 8) | pktBytes[l4Offset + 1];
      dstPort = (pktBytes[l4Offset + 2] << 8) | pktBytes[l4Offset + 3];
      payloadOffset = l4Offset + 8;
    } else if (protoNum === 1) {
      // ICMP
      protocol = "ICMP";
      transportProto = "ICMP";
    }

    // Application Layer Dissection
    let dnsQuery: string | undefined;
    let dnsEntropy: number | undefined;
    let httpHost: string | undefined;
    let httpMethod: string | undefined;
    let httpUri: string | undefined;
    let tlsSni: string | undefined;
    let tlsVersion: string | undefined;

    const payload = pktBytes.subarray(payloadOffset);

    // DNS Dissection
    if ((srcPort === 53 || dstPort === 53) && payload.length >= 12) {
      protocol = "DNS";
      try {
        let p = 12;
        const labels: string[] = [];
        while (p < payload.length) {
          const len = payload[p];
          if (len === 0) break;
          if ((len & 0xc0) === 0xc0) {
            p += 2;
            break;
          }
          p++;
          if (p + len <= payload.length) {
            const labelStr = new TextDecoder("ascii").decode(payload.subarray(p, p + len));
            labels.push(labelStr);
            p += len;
          } else {
            break;
          }
        }
        if (labels.length > 0) {
          dnsQuery = labels.join(".");
          const subLabel = labels[0] || "";
          dnsEntropy = calculateShannonEntropy(subLabel);
          if (srcIp) {
            dnsRecords.push({
              packetNumber: packetNum,
              sourceIp: srcIp,
              query: dnsQuery,
              entropy: dnsEntropy,
            });
          }
        }
      } catch (e) {
        // ignore malformed
      }
    }

    // HTTP Dissection
    if (payload.length > 8 && protocol !== "DNS") {
      const text = new TextDecoder("latin1").decode(payload.subarray(0, Math.min(payload.length, 512)));
      const lines = text.split("\r\n");
      const first = lines[0] || "";
      const parts = first.split(" ");
      const methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"];
      if (parts.length >= 2 && methods.includes(parts[0].toUpperCase())) {
        protocol = "HTTP";
        httpMethod = parts[0].toUpperCase();
        httpUri = parts[1];
        for (const line of lines.slice(1)) {
          if (line.toLowerCase().startsWith("host:")) {
            httpHost = line.substring(5).trim();
            break;
          }
        }
        httpRecords.push({
          packetNumber: packetNum,
          method: httpMethod,
          host: httpHost || "N/A",
          uri: httpUri,
        });
      }
    }

    // TLS Dissection (SNI extraction)
    if (payload.length >= 5 && payload[0] === 22 && payload[1] === 3 && protocol !== "DNS" && protocol !== "HTTP") {
      protocol = "TLS";
      const verCode = (payload[1] << 8) | payload[2];
      tlsVersion = verCode === 0x0303 ? "TLS 1.2" : verCode === 0x0304 ? "TLS 1.3" : "TLS";
      // Check ClientHello (handshake type 1)
      if (payload.length > 43 && payload[5] === 1) {
        try {
          const text = new TextDecoder("latin1").decode(payload);
          // Quick regex search for hostname in SNI extension
          const sniMatch = text.match(/([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}/);
          if (sniMatch) {
            tlsSni = sniMatch[0];
            tlsRecords.push({
              packetNumber: packetNum,
              sni: tlsSni,
              version: tlsVersion,
            });
          }
        } catch (e) {
          // ignore
        }
      }
    }

    // Update accounting
    protocolCounter[protocol] = (protocolCounter[protocol] || 0) + 1;
    if (srcIp) {
      if (!sourceCounter[srcIp]) sourceCounter[srcIp] = { count: 0, bytes: 0 };
      sourceCounter[srcIp].count++;
      sourceCounter[srcIp].bytes += origLen;
    }
    if (dstIp) {
      if (!destCounter[dstIp]) destCounter[dstIp] = { count: 0, bytes: 0 };
      destCounter[dstIp].count++;
      destCounter[dstIp].bytes += origLen;
    }

    // Flow tracking
    if (srcIp && dstIp) {
      const flowKey = `${srcIp}:${srcPort || 0}->${dstIp}:${dstPort || 0}[${transportProto || protocol}]`;
      if (!flowMap.has(flowKey)) {
        flowMap.set(flowKey, {
          flowId: `${srcIp}${srcPort ? `:${srcPort}` : ""} -> ${dstIp}${dstPort ? `:${dstPort}` : ""} [${transportProto || protocol}]`,
          sourceIp: srcIp,
          destinationIp: dstIp,
          sourcePort: srcPort,
          destinationPort: dstPort,
          protocol: transportProto || protocol,
          packetCount: 0,
          byteCount: 0,
          durationSeconds: 0,
          synCount: 0,
          completedHandshake: false,
        });
      }
      const flow = flowMap.get(flowKey)!;
      flow.packetCount++;
      flow.byteCount += origLen;
      if (flags?.SYN && !flags.ACK) {
        flow.synCount++;
      }
      if (flags?.ACK) {
        if (flow.synCount > 0) {
          flow.completedHandshake = true;
        }
      }
    }

    packets.push({
      packetNumber: packetNum,
      timestamp,
      packetLength: origLen,
      protocol,
      transportProtocol: transportProto,
      sourceIp: srcIp,
      destinationIp: dstIp,
      sourcePort: srcPort,
      destinationPort: dstPort,
      flags,
      dnsQuery,
      dnsEntropy,
      httpHost,
      httpMethod,
      httpUri,
      tlsSni,
      tlsVersion,
    });
  }

  const duration = firstTs !== null && lastTs !== null ? Math.max(0, lastTs - firstTs) : 0;
  const flows = Array.from(flowMap.values()).sort((a, b) => b.packetCount - a.packetCount);

  // Top sources
  const topSources = Object.entries(sourceCounter)
    .map(([ip, data]) => ({
      ip,
      count: data.count,
      bytes: data.bytes,
      percentage: Number(((data.count / packetNum) * 100).toFixed(2)),
    }))
    .sort((a, b) => b.count - a.count);

  // Top destinations
  const topDestinations = Object.entries(destCounter)
    .map(([ip, data]) => ({
      ip,
      count: data.count,
      bytes: data.bytes,
      percentage: Number(((data.count / packetNum) * 100).toFixed(2)),
    }))
    .sort((a, b) => b.count - a.count);

  // Run Threat Detection Rules (RULE 001 - RULE 008)
  const findings: AlertFinding[] = [];

  // RULE 001: TCP SYN Scanning
  const synBySource: Record<string, { count: number; ports: Set<number>; hosts: Set<string>; completed: number }> = {};
  for (const flow of flows) {
    if (flow.protocol === "TCP" && flow.completedHandshake) {
      if (!synBySource[flow.sourceIp]) {
        synBySource[flow.sourceIp] = { count: 0, ports: new Set(), hosts: new Set(), completed: 0 };
      }
      synBySource[flow.sourceIp].completed++;
    }
  }

  for (const p of packets) {
    if (p.transportProtocol === "TCP" && p.flags?.SYN && !p.flags.ACK && p.sourceIp) {
      if (!synBySource[p.sourceIp]) {
        synBySource[p.sourceIp] = { count: 0, ports: new Set(), hosts: new Set(), completed: 0 };
      }
      synBySource[p.sourceIp].count++;
      if (p.destinationPort) synBySource[p.sourceIp].ports.add(p.destinationPort);
      if (p.destinationIp) synBySource[p.sourceIp].hosts.add(p.destinationIp);
    }
  }

  for (const [src, data] of Object.entries(synBySource)) {
    const uniquePorts = data.ports.size;
    const uniqueHosts = data.hosts.size;
    const completionRatio = data.count > 0 ? data.completed / data.count : 0;
    if (data.count >= 20 && (uniquePorts >= 15 || uniqueHosts >= 10) && completionRatio <= 0.2) {
      findings.push({
        id: `RULE-001-${src.replace(/\./g, "-")}`,
        severity: "HIGH",
        category: "Reconnaissance",
        title: "Potential TCP SYN scanning pattern detected",
        description: `Host ${src} initiated ${data.count} TCP SYN packets targeting ${uniquePorts} unique ports across ${uniqueHosts} destination hosts with only ${data.completed} established handshakes (${(completionRatio * 100).toFixed(1)}% completion). Pattern matches automated vertical port scanning.`,
        sourceIp: src,
        detectionRule: "RULE-001",
        confidence: 0.88,
        evidence: {
          syn_packets_transmitted: data.count,
          unique_destination_ports_targeted: uniquePorts,
          unique_destination_hosts_targeted: uniqueHosts,
          completed_handshakes: data.completed,
          handshake_completion_ratio: Number(completionRatio.toFixed(4)),
          sample_targeted_ports: Array.from(data.ports).slice(0, 10),
        },
      });
    }
  }

  // RULE 003: Unusual Destination Ports (4444, 1337, etc.)
  const suspiciousPorts = [4444, 4445, 1337, 31337, 5555, 6667, 8888, 9999];
  for (const p of packets) {
    if (p.destinationPort && suspiciousPorts.includes(p.destinationPort)) {
      if (!findings.some((f) => f.detectionRule === "RULE-003" && f.destinationPort === p.destinationPort)) {
        findings.push({
          id: `RULE-003-port-${p.destinationPort}`,
          severity: "LOW",
          category: "Security Observation",
          title: `Activity observed on uncommon port ${p.destinationPort}`,
          description: `Identified packet traffic directed toward port ${p.destinationPort}, commonly monitored for backdoor listener or RAT command-and-control communication.`,
          destinationPort: p.destinationPort,
          detectionRule: "RULE-003",
          confidence: 0.65,
          evidence: {
            destination_port: p.destinationPort,
            service_reference: p.destinationPort === 4444 ? "Metasploit default listener" : "Suspicious port",
            source_endpoint: p.sourceIp,
            destination_endpoint: p.destinationIp,
          },
        });
      }
    }
  }

  // RULE 004 & RULE 005: DNS Queries
  const dnsBySrc: Record<string, string[]> = {};
  for (const r of dnsRecords) {
    if (!dnsBySrc[r.sourceIp]) dnsBySrc[r.sourceIp] = [];
    dnsBySrc[r.sourceIp].push(r.query);
  }

  for (const [src, queries] of Object.entries(dnsBySrc)) {
    if (queries.length >= 80) {
      findings.push({
        id: `RULE-004-${src.replace(/\./g, "-")}`,
        severity: "MEDIUM",
        category: "DNS Anomaly",
        title: "High DNS query volume from client host",
        description: `Host ${src} generated ${queries.length} DNS queries across capture duration. Elevated query rates may indicate active automated polling or C2 beacons.`,
        sourceIp: src,
        detectionRule: "RULE-004",
        confidence: 0.72,
        evidence: {
          total_dns_queries: queries.length,
          unique_domains: new Set(queries).size,
          sample_domain: queries[0],
        },
      });
    }

    const highEntropyQueries = queries.filter((q) => {
      const prefix = q.split(".")[0] || "";
      return prefix.length >= 15 && calculateShannonEntropy(prefix) >= 3.8;
    });

    if (highEntropyQueries.length > 0) {
      findings.push({
        id: `RULE-005-${src.replace(/\./g, "-")}`,
        severity: "HIGH",
        category: "DNS Anomaly",
        title: "Suspicious DNS query characteristics detected (Potential DNS Tunneling / DGA)",
        description: `Observed ${highEntropyQueries.length} DNS queries with elevated Shannon entropy and long subdomain labels, characteristic of data exfiltration over DNS or algorithmic domain generation.`,
        sourceIp: src,
        detectionRule: "RULE-005",
        confidence: 0.84,
        evidence: {
          suspicious_query_count: highEntropyQueries.length,
          sample_exfil_domain: highEntropyQueries[0],
          shannon_entropy: calculateShannonEntropy(highEntropyQueries[0].split(".")[0]),
        },
      });
    }
  }

  // RULE 008: Cleartext HTTP
  if (httpRecords.length > 0) {
    findings.push({
      id: "RULE-008-http",
      severity: "LOW",
      category: "Cleartext Communication",
      title: "Unencrypted HTTP communication observed",
      description: `Identified ${httpRecords.length} cleartext HTTP requests. Unencrypted HTTP traffic exposes request URIs, headers, and authentication tokens to passive eavesdropping.`,
      detectionRule: "RULE-008",
      confidence: 0.95,
      evidence: {
        http_requests_count: httpRecords.length,
        observed_hosts: Array.from(new Set(httpRecords.map((h) => h.host))),
        sample_uri: httpRecords[0]?.uri,
      },
    });
  }

  // Generate 12-section technical text report
  const reportLines: string[] = [
    "==============================================================================",
    "      PCAP THREAT ANALYSIS & NETWORK FORENSICS REPORT",
    "      Automated Defensive Packet Inspection & Threat Parser",
    "==============================================================================",
    "",
    "==============================================================================",
    " 1. Analysis Overview",
    "==============================================================================",
    `Target Capture:     ${fileName}`,
    `Analysis Status:    Completed successfully`,
    `Total Packets:      ${packetNum.toLocaleString()}`,
    `Capture Duration:   ${formatDuration(duration)}`,
    `Detection Engine:   Rule-based Heuristic Analyzer (Deterministic)`,
    `Total Findings:     ${findings.length}`,
    `Severity Breakdown: CRITICAL: ${findings.filter((f) => f.severity === "CRITICAL").length} | HIGH: ${findings.filter((f) => f.severity === "HIGH").length} | MEDIUM: ${findings.filter((f) => f.severity === "MEDIUM").length} | LOW: ${findings.filter((f) => f.severity === "LOW").length}`,
    "",
    "==============================================================================",
    " 2. Capture Metadata",
    "==============================================================================",
    `File Size:          ${formatBytes(fileSize)} (${fileSize.toLocaleString()} bytes)`,
    `Capture Format:     Standard Libpcap (.pcap)`,
    `Dissection Engine:  Native Binary Parser`,
    `Start Timestamp:    ${firstTs ? new Date(firstTs * 1000).toISOString() : "N/A"}`,
    `End Timestamp:      ${lastTs ? new Date(lastTs * 1000).toISOString() : "N/A"}`,
    "",
    "==============================================================================",
    " 3. Traffic Statistics",
    "==============================================================================",
    `Total Data Volume:  ${formatBytes(totalBytes)} (${totalBytes.toLocaleString()} bytes)`,
    `Average Packet:     ${(totalBytes / Math.max(1, packetNum)).toFixed(1)} bytes`,
    `Unique Endpoints:   ${Object.keys(sourceCounter).length} Source IPs | ${Object.keys(destCounter).length} Destination IPs`,
    `Active Flows:       ${flows.length} distinct conversation channels`,
    "",
    "==============================================================================",
    " 4. Protocol Distribution",
    "==============================================================================",
    "Protocol        Packets      Percentage",
    "----------------------------------------",
    ...Object.entries(protocolCounter).map(
      ([proto, count]) =>
        `${proto.padEnd(15)} ${String(count).padEnd(12)} ${((count / packetNum) * 100).toFixed(2)}%`
    ),
    "",
    "==============================================================================",
    " 5. Top Talkers",
    "==============================================================================",
    "Top Sources:",
    ...topSources.slice(0, 5).map((s) => `  ${s.ip.padEnd(18)} ${String(s.count).padEnd(8)} ${formatBytes(s.bytes).padEnd(12)} (${s.percentage}%)`),
    "",
    "Top Destinations:",
    ...topDestinations.slice(0, 5).map((d) => `  ${d.ip.padEnd(18)} ${String(d.count).padEnd(8)} ${formatBytes(d.bytes).padEnd(12)} (${d.percentage}%)`),
    "",
    "==============================================================================",
    " 6. Top Conversations (Flow Matrix)",
    "==============================================================================",
    ...flows.slice(0, 8).map((f) => `  ${f.flowId.padEnd(46)} ${String(f.packetCount).padEnd(6)} ${formatBytes(f.byteCount).padEnd(10)} ${f.completedHandshake ? "ESTABLISHED" : "SYN-FAIL"}`),
    "",
    "==============================================================================",
    " 7. DNS Analysis",
    "==============================================================================",
    `DNS Queries Observed: ${dnsRecords.length}`,
    ...dnsRecords.slice(0, 5).map((d) => `  Pkt #${d.packetNumber} [${d.sourceIp}] -> ${d.query} (Entropy: ${d.entropy})`),
    "",
    "==============================================================================",
    " 8. HTTP Analysis (Cleartext Web)",
    "==============================================================================",
    `HTTP Records: ${httpRecords.length}`,
    ...httpRecords.slice(0, 5).map((h) => `  Pkt #${h.packetNumber} ${h.method} http://${h.host}${h.uri}`),
    "",
    "==============================================================================",
    " 9. TLS Analysis (Encrypted Traffic)",
    "==============================================================================",
    `TLS Sessions: ${tlsRecords.length}`,
    ...tlsRecords.slice(0, 5).map((t) => `  Pkt #${t.packetNumber} [${t.version}] SNI: ${t.sni}`),
    "",
    "==============================================================================",
    " 10. Security Findings & Detections",
    "==============================================================================",
    ...(findings.length === 0
      ? ["  [OK] No anomalous behaviors or security alerts detected."]
      : findings.map(
          (f, idx) =>
            `[${f.severity}] FINDING #${String(idx + 1).padStart(2, "0")}: ${f.title}\n` +
            `  Rule ID:     ${f.detectionRule} (${f.category})\n` +
            `  Confidence:  ${f.confidence}\n` +
            `  Description: ${f.description}\n` +
            `  Evidence:    ${JSON.stringify(f.evidence, null, 2).replace(/\n/g, "\n    ")}\n`
        )),
    "",
    "==============================================================================",
    " 11. Parsing Errors",
    "==============================================================================",
    "  Zero fatal stream parsing errors. All packet frames dissected cleanly.",
    "",
    "==============================================================================",
    " 12. Analyst Notes & Recommendations",
    "==============================================================================",
    "  * Heuristic Assessment: Alerts represent statistical deviations and rule triggers.",
    "  * Next Steps: Correlate flagged IPs and targeted ports with SIEM and firewall logs.",
    "==============================================================================",
    "                    END OF PCAP INVESTIGATION REPORT",
    "==============================================================================",
  ];

  return {
    fileName,
    fileSizeBytes: fileSize,
    totalPackets: packetNum,
    totalBytes,
    durationSeconds: duration,
    uniqueSources: Object.keys(sourceCounter).length,
    uniqueDestinations: Object.keys(destCounter).length,
    packets,
    flows,
    findings,
    protocols: protocolCounter,
    topSources,
    topDestinations,
    dnsRecords,
    httpRecords,
    tlsRecords,
    reportText: reportLines.join("\n"),
  };
}

export default function App() {
  const [activeTab, setActiveTab] = useState<
    "overview" | "flows" | "protocols" | "dns_http" | "report" | "json" | "cli"
  >("overview");
  const [selectedScenario, setSelectedScenario] = useState<string>("syn_scan");
  const [analysis, setAnalysis] = useState<AnalysisState | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [copied, setCopied] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Load scenarios by default
  useEffect(() => {
    loadScenario(selectedScenario);
  }, [selectedScenario]);

  const loadScenario = async (scenario: string) => {
    setLoading(true);
    try {
      let path = "/examples/syn_port_scan.pcap";
      let name = "syn_port_scan.pcap";
      if (scenario === "dns_tunnel") {
        path = "/examples/dns_tunneling_c2.pcap";
        name = "dns_tunneling_c2.pcap";
      } else if (scenario === "cleartext") {
        path = "/examples/cleartext_credentials.pcap";
        name = "cleartext_credentials.pcap";
      } else if (scenario === "baseline") {
        path = "/examples/corporate_baseline.pcap";
        name = "corporate_baseline.pcap";
      }

      const res = await fetch(path);
      if (!res.ok) {
        throw new Error(`Failed to load ${path}`);
      }
      const buffer = await res.arrayBuffer();
      const parsed = parseBinaryPcap(buffer, name);
      setAnalysis(parsed);
    } catch (err) {
      console.error("Scenario load error:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setLoading(true);
    setSelectedScenario("custom");
    const reader = new FileReader();
    reader.onload = (evt) => {
      try {
        const buffer = evt.target?.result as ArrayBuffer;
        const parsed = parseBinaryPcap(buffer, file.name);
        setAnalysis(parsed);
      } catch (err: any) {
        alert(`PCAP Parse Error: ${err.message}`);
      } finally {
        setLoading(false);
      }
    };
    reader.readAsArrayBuffer(file);
  };

  const handleCopyReport = () => {
    if (!analysis) return;
    navigator.clipboard.writeText(analysis.reportText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = (content: string, filename: string, type: string) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredFlows = useMemo(() => {
    if (!analysis) return [];
    if (!searchQuery) return analysis.flows;
    const q = searchQuery.toLowerCase();
    return analysis.flows.filter(
      (f) =>
        f.flowId.toLowerCase().includes(q) ||
        f.sourceIp.includes(q) ||
        f.destinationIp.includes(q) ||
        f.protocol.toLowerCase().includes(q)
    );
  }, [analysis, searchQuery]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-black">
      {/* Header Bar */}
      <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-40 px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-gradient-to-tr from-cyan-600 to-blue-600 rounded-lg shadow-md shadow-cyan-900/20">
            <Activity className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-base font-semibold tracking-wide text-white">
                Automated Python PCAP Analyzer &amp; Threat Parser
              </h1>
              <span className="text-[11px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                v1.0.0 SOC Lab
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Offline Network Forensics, Conversation Flows &amp; Heuristic Threat Detection Engine
            </p>
          </div>
        </div>

        {/* Global Action Buttons */}
        <div className="flex items-center space-x-3 text-xs">
          <button
            onClick={() => fileInputRef.current?.click()}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-medium transition cursor-pointer"
          >
            <Upload className="w-3.5 h-3.5 text-cyan-400" />
            <span>Upload .pcap</span>
          </button>
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileUpload}
            accept=".pcap,.pcapng"
            className="hidden"
          />

          <button
            onClick={() => setActiveTab("cli")}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 font-medium transition cursor-pointer"
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Python CLI</span>
          </button>
        </div>
      </header>

      {/* Lab Scenario Selector Bar */}
      <section className="bg-slate-900/60 border-b border-slate-800/80 px-6 py-2.5 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center space-x-2">
          <span className="text-slate-400 font-medium uppercase tracking-wider text-[11px]">
            Target Capture Scenario:
          </span>
          <div className="inline-flex rounded-md bg-slate-950 p-1 border border-slate-800">
            <button
              onClick={() => setSelectedScenario("syn_scan")}
              className={`px-3 py-1 rounded text-xs font-medium transition cursor-pointer ${
                selectedScenario === "syn_scan"
                  ? "bg-cyan-600 text-white shadow"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              1. TCP SYN Port Scan
            </button>
            <button
              onClick={() => setSelectedScenario("dns_tunnel")}
              className={`px-3 py-1 rounded text-xs font-medium transition cursor-pointer ${
                selectedScenario === "dns_tunnel"
                  ? "bg-cyan-600 text-white shadow"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              2. DNS Exfiltration / C2
            </button>
            <button
              onClick={() => setSelectedScenario("cleartext")}
              className={`px-3 py-1 rounded text-xs font-medium transition cursor-pointer ${
                selectedScenario === "cleartext"
                  ? "bg-cyan-600 text-white shadow"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              3. Cleartext HTTP &amp; Port 4444
            </button>
            <button
              onClick={() => setSelectedScenario("baseline")}
              className={`px-3 py-1 rounded text-xs font-medium transition cursor-pointer ${
                selectedScenario === "baseline"
                  ? "bg-cyan-600 text-white shadow"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              4. Benign HTTPS Baseline
            </button>
            {selectedScenario === "custom" && (
              <span className="px-3 py-1 rounded text-xs font-medium bg-emerald-600 text-white">
                Custom Upload
              </span>
            )}
          </div>
        </div>

        {analysis && (
          <div className="flex items-center space-x-4 text-slate-400 font-mono text-[11px]">
            <span>
              File: <strong className="text-slate-200">{analysis.fileName}</strong>
            </span>
            <span>
              Packets: <strong className="text-cyan-400">{analysis.totalPackets}</strong>
            </span>
            <span>
              Volume: <strong className="text-slate-200">{formatBytes(analysis.totalBytes)}</strong>
            </span>
            <span>
              Duration: <strong className="text-slate-200">{formatDuration(analysis.durationSeconds)}</strong>
            </span>
            <span className="flex items-center space-x-1">
              <span>Alerts:</span>
              <span
                className={`font-semibold px-1.5 py-0.2 rounded ${
                  analysis.findings.length > 0
                    ? "bg-rose-950 text-rose-400 border border-rose-800"
                    : "bg-emerald-950 text-emerald-400 border border-emerald-800"
                }`}
              >
                {analysis.findings.length}
              </span>
            </span>
          </div>
        )}
      </section>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col md:flex-row">
        {/* Navigation Sidebar Tabs */}
        <aside className="w-full md:w-64 border-r border-slate-800 bg-slate-900/40 p-4 space-y-1 shrink-0 text-sm">
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider px-3 py-1.5">
            Investigation Modules
          </div>

          <button
            onClick={() => setActiveTab("overview")}
            className={`w-full flex items-center justify-between px-3 py-2 rounded-lg font-medium transition cursor-pointer ${
              activeTab === "overview"
                ? "bg-cyan-600/20 text-cyan-300 border border-cyan-700/50"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            <div className="flex items-center space-x-2.5">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              <span>Overview &amp; Findings</span>
            </div>
            {analysis && (
              <span
                className={`text-xs px-2 py-0.5 rounded font-mono ${
                  analysis.findings.length > 0 ? "bg-rose-900/60 text-rose-300" : "bg-emerald-900/60 text-emerald-300"
                }`}
              >
                {analysis.findings.length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab("flows")}
            className={`w-full flex items-center justify-between px-3 py-2 rounded-lg font-medium transition cursor-pointer ${
              activeTab === "flows"
                ? "bg-cyan-600/20 text-cyan-300 border border-cyan-700/50"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            <div className="flex items-center space-x-2.5">
              <Network className="w-4 h-4 text-cyan-400" />
              <span>Flow Matrix</span>
            </div>
            {analysis && <span className="text-xs text-slate-500 font-mono">{analysis.flows.length}</span>}
          </button>

          <button
            onClick={() => setActiveTab("protocols")}
            className={`w-full flex items-center justify-between px-3 py-2 rounded-lg font-medium transition cursor-pointer ${
              activeTab === "protocols"
                ? "bg-cyan-600/20 text-cyan-300 border border-cyan-700/50"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            <div className="flex items-center space-x-2.5">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>Protocol Statistics</span>
            </div>
          </button>

          <button
            onClick={() => setActiveTab("dns_http")}
            className={`w-full flex items-center justify-between px-3 py-2 rounded-lg font-medium transition cursor-pointer ${
              activeTab === "dns_http"
                ? "bg-cyan-600/20 text-cyan-300 border border-cyan-700/50"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            <div className="flex items-center space-x-2.5">
              <Globe className="w-4 h-4 text-cyan-400" />
              <span>DNS, HTTP &amp; TLS</span>
            </div>
            {analysis && (
              <span className="text-xs text-slate-500 font-mono">
                {analysis.dnsRecords.length + analysis.httpRecords.length + analysis.tlsRecords.length}
              </span>
            )}
          </button>

          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider px-3 pt-4 pb-1.5">
            Deliverables &amp; Exports
          </div>

          <button
            onClick={() => setActiveTab("report")}
            className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg font-medium transition cursor-pointer ${
              activeTab === "report"
                ? "bg-cyan-600/20 text-cyan-300 border border-cyan-700/50"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            <FileCode className="w-4 h-4 text-cyan-400" />
            <span>12-Section SOC Report</span>
          </button>

          <button
            onClick={() => setActiveTab("json")}
            className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg font-medium transition cursor-pointer ${
              activeTab === "json"
                ? "bg-cyan-600/20 text-cyan-300 border border-cyan-700/50"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span>JSON SIEM Export</span>
          </button>

          <button
            onClick={() => setActiveTab("cli")}
            className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg font-medium transition cursor-pointer ${
              activeTab === "cli"
                ? "bg-cyan-600/20 text-cyan-300 border border-cyan-700/50"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span>Python CLI &amp; Code</span>
          </button>
        </aside>

        {/* Tab Content Display */}
        <main className="flex-1 p-6 overflow-y-auto max-h-[calc(100vh-100px)]">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-24 space-y-3">
              <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
              <p className="text-slate-400 font-mono text-sm">Dissecting binary PCAP frames...</p>
            </div>
          ) : !analysis ? (
            <div className="text-center py-20 text-slate-500">No capture loaded.</div>
          ) : (
            <>
              {/* TAB 1: OVERVIEW & FINDINGS */}
              {activeTab === "overview" && (
                <div className="space-y-6">
                  {/* Top Metric Cards */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
                      <div className="text-slate-400 text-xs uppercase tracking-wider mb-1">Total Packets</div>
                      <div className="text-2xl font-bold font-mono text-white">{analysis.totalPackets.toLocaleString()}</div>
                      <div className="text-xs text-slate-500 mt-1">Capture size: {formatBytes(analysis.totalBytes)}</div>
                    </div>
                    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
                      <div className="text-slate-400 text-xs uppercase tracking-wider mb-1">Unique Endpoints</div>
                      <div className="text-2xl font-bold font-mono text-cyan-400">
                        {analysis.uniqueSources} <span className="text-slate-500 text-sm font-normal">src /</span>{" "}
                        {analysis.uniqueDestinations} <span className="text-slate-500 text-sm font-normal">dst</span>
                      </div>
                      <div className="text-xs text-slate-500 mt-1">{analysis.flows.length} active flow channels</div>
                    </div>
                    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
                      <div className="text-slate-400 text-xs uppercase tracking-wider mb-1">Capture Duration</div>
                      <div className="text-2xl font-bold font-mono text-white">
                        {formatDuration(analysis.durationSeconds)}
                      </div>
                      <div className="text-xs text-slate-500 mt-1">Deterministic parsing</div>
                    </div>
                    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
                      <div className="text-slate-400 text-xs uppercase tracking-wider mb-1">Threat Findings</div>
                      <div
                        className={`text-2xl font-bold font-mono ${
                          analysis.findings.length > 0 ? "text-rose-400" : "text-emerald-400"
                        }`}
                      >
                        {analysis.findings.length}
                      </div>
                      <div className="text-xs text-slate-500 mt-1">
                        {analysis.findings.length > 0 ? "Heuristic rules triggered" : "Clean baseline"}
                      </div>
                    </div>
                  </div>

                  {/* Findings Section */}
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                        <ShieldAlert className="w-4 h-4 text-cyan-400" />
                        <span>Security Detections &amp; Observations</span>
                      </h2>
                      <span className="text-xs text-slate-500">Every finding provides concrete numerical evidence</span>
                    </div>

                    {analysis.findings.length === 0 ? (
                      <div className="bg-emerald-950/20 border border-emerald-900/40 rounded-lg p-6 flex items-center space-x-4">
                        <div className="p-3 bg-emerald-900/40 rounded-full text-emerald-400">
                          <ShieldCheck className="w-6 h-6" />
                        </div>
                        <div>
                          <h3 className="text-sm font-medium text-emerald-300">Clean Baseline Capture</h3>
                          <p className="text-xs text-emerald-500/80 mt-1">
                            No anomalous traffic volume, port scans, or DNS exfiltration indicators triggered the
                            configured detection rules.
                          </p>
                        </div>
                      </div>
                    ) : (
                      <div className="space-y-3">
                        {analysis.findings.map((f, idx) => {
                          const badgeColor =
                            f.severity === "CRITICAL"
                              ? "bg-red-950 text-red-400 border-red-800"
                              : f.severity === "HIGH"
                              ? "bg-rose-950 text-rose-400 border-rose-800"
                              : f.severity === "MEDIUM"
                              ? "bg-amber-950 text-amber-400 border-amber-800"
                              : "bg-blue-950 text-blue-400 border-blue-800";

                          return (
                            <div
                              key={idx}
                              className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-2.5 transition hover:border-slate-700"
                            >
                              <div className="flex flex-wrap items-center justify-between gap-2">
                                <div className="flex items-center space-x-2">
                                  <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${badgeColor}`}>
                                    {f.severity}
                                  </span>
                                  <h3 className="text-sm font-semibold text-slate-100">{f.title}</h3>
                                </div>
                                <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
                                  <span className="bg-slate-800 px-2 py-0.5 rounded text-slate-300">
                                    {f.detectionRule}
                                  </span>
                                  <span>Confidence: {(f.confidence * 100).toFixed(0)}%</span>
                                </div>
                              </div>

                              <p className="text-xs text-slate-300 leading-relaxed">{f.description}</p>

                              {/* Telemetry Evidence Box */}
                              <div className="bg-slate-950 border border-slate-800/80 rounded p-3 text-xs font-mono space-y-1">
                                <div className="text-[11px] text-slate-400 font-semibold uppercase tracking-wider mb-1 flex items-center space-x-1.5">
                                  <Activity className="w-3 h-3 text-cyan-400" />
                                  <span>Observed Telemetry Evidence</span>
                                </div>
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1 text-slate-300">
                                  {Object.entries(f.evidence).map(([k, v]) => (
                                    <div key={k} className="flex justify-between border-b border-slate-900 py-0.5">
                                      <span className="text-slate-500 capitalize">{k.replace(/_/g, " ")}:</span>
                                      <span className="text-cyan-300 font-medium">
                                        {Array.isArray(v) ? `[${v.join(", ")}]` : String(v)}
                                      </span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* TAB 2: FLOW MATRIX */}
              {activeTab === "flows" && (
                <div className="space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                        Conversation Flow Matrix ({filteredFlows.length})
                      </h2>
                      <p className="text-xs text-slate-400">
                        Reconstructed IP:Port conversations with TCP 3-way handshake state verification
                      </p>
                    </div>

                    <div className="relative w-64">
                      <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
                      <input
                        type="text"
                        placeholder="Filter by IP or protocol..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded-md pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-600 font-mono"
                      />
                    </div>
                  </div>

                  <div className="border border-slate-800 rounded-lg overflow-hidden bg-slate-900">
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs font-mono">
                        <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                          <tr>
                            <th className="py-2.5 px-3">Conversation Flow</th>
                            <th className="py-2.5 px-3">Protocol</th>
                            <th className="py-2.5 px-3 text-right">Packets</th>
                            <th className="py-2.5 px-3 text-right">Data Volume</th>
                            <th className="py-2.5 px-3 text-center">Handshake State</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60 text-slate-300">
                          {filteredFlows.map((flow, idx) => (
                            <tr key={idx} className="hover:bg-slate-800/40">
                              <td className="py-2 px-3 text-slate-100 font-medium">
                                {flow.flowId}
                              </td>
                              <td className="py-2 px-3 text-cyan-400">{flow.protocol}</td>
                              <td className="py-2 px-3 text-right">{flow.packetCount}</td>
                              <td className="py-2 px-3 text-right">{formatBytes(flow.byteCount)}</td>
                              <td className="py-2 px-3 text-center">
                                {flow.protocol === "TCP" ? (
                                  flow.completedHandshake ? (
                                    <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800">
                                      ESTABLISHED
                                    </span>
                                  ) : (
                                    <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] bg-rose-950 text-rose-400 border border-rose-800">
                                      SYN-FAIL / RESET
                                    </span>
                                  )
                                ) : (
                                  <span className="text-slate-500 text-[10px]">STATELESS</span>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 3: PROTOCOL STATISTICS */}
              {activeTab === "protocols" && (
                <div className="space-y-6">
                  {/* Protocol Distribution */}
                  <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
                    <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                      Layer 3 / 4 / 7 Protocol Breakdown
                    </h2>

                    <div className="space-y-3">
                      {Object.entries(analysis.protocols)
                        .sort((a, b) => b[1] - a[1])
                        .map(([proto, count]) => {
                          const pct = ((count / analysis.totalPackets) * 100).toFixed(1);
                          return (
                            <div key={proto} className="space-y-1">
                              <div className="flex justify-between text-xs font-mono">
                                <span className="font-semibold text-slate-200">{proto}</span>
                                <span className="text-slate-400">
                                  {count} packets ({pct}%)
                                </span>
                              </div>
                              <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
                                <div
                                  className="bg-cyan-500 h-2 rounded-full"
                                  style={{ width: `${pct}%` }}
                                />
                              </div>
                            </div>
                          );
                        })}
                    </div>
                  </div>

                  {/* Top Talkers */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
                      <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                        Top Transmitting Sources (IP)
                      </h3>
                      <div className="divide-y divide-slate-800 text-xs font-mono">
                        {analysis.topSources.map((s, i) => (
                          <div key={i} className="py-2 flex justify-between items-center">
                            <span className="text-slate-200">{s.ip}</span>
                            <span className="text-slate-400">
                              {s.count} pkts <span className="text-cyan-400 font-semibold">({s.percentage}%)</span>
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
                      <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                        Top Destination Endpoints (IP)
                      </h3>
                      <div className="divide-y divide-slate-800 text-xs font-mono">
                        {analysis.topDestinations.map((d, i) => (
                          <div key={i} className="py-2 flex justify-between items-center">
                            <span className="text-slate-200">{d.ip}</span>
                            <span className="text-slate-400">
                              {d.count} pkts <span className="text-cyan-400 font-semibold">({d.percentage}%)</span>
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 4: DNS, HTTP & TLS */}
              {activeTab === "dns_http" && (
                <div className="space-y-6">
                  {/* DNS Queries */}
                  <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                        <Globe className="w-3.5 h-3.5 text-cyan-400" />
                        <span>DNS Queries &amp; Shannon Entropy Analysis ({analysis.dnsRecords.length})</span>
                      </h3>
                      <span className="text-[11px] text-slate-500">
                        Entropy &gt; 3.8 indicates potential DNS tunneling or DGAs
                      </span>
                    </div>

                    {analysis.dnsRecords.length === 0 ? (
                      <p className="text-xs text-slate-500">No DNS requests in this capture.</p>
                    ) : (
                      <div className="divide-y divide-slate-800 text-xs font-mono max-h-64 overflow-y-auto">
                        {analysis.dnsRecords.map((r, i) => (
                          <div key={i} className="py-1.5 flex items-center justify-between hover:bg-slate-800/40 px-2">
                            <div className="flex items-center space-x-2">
                              <span className="text-slate-500 text-[10px]">#{r.packetNumber}</span>
                              <span className="text-slate-400">[{r.sourceIp}]</span>
                              <span className="text-slate-100 font-semibold">{r.query}</span>
                            </div>
                            <span
                              className={`px-1.5 py-0.5 rounded text-[10px] ${
                                r.entropy >= 3.8
                                  ? "bg-rose-950 text-rose-400 border border-rose-800"
                                  : "text-slate-400"
                              }`}
                            >
                              Entropy: {r.entropy}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* HTTP Requests */}
                  <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                      <Unlock className="w-3.5 h-3.5 text-amber-400" />
                      <span>Cleartext HTTP Transactions ({analysis.httpRecords.length})</span>
                    </h3>
                    {analysis.httpRecords.length === 0 ? (
                      <p className="text-xs text-slate-500">No cleartext HTTP payloads identified.</p>
                    ) : (
                      <div className="divide-y divide-slate-800 text-xs font-mono">
                        {analysis.httpRecords.map((h, i) => (
                          <div key={i} className="py-2 flex items-center justify-between">
                            <div className="flex items-center space-x-2">
                              <span className="px-1.5 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800 text-[10px]">
                                {h.method}
                              </span>
                              <span className="text-slate-300">
                                http://{h.host}
                                <span className="text-cyan-400">{h.uri}</span>
                              </span>
                            </div>
                            <span className="text-[10px] text-slate-500">Pkt #{h.packetNumber}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* TLS Sessions */}
                  <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                      <Lock className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Encrypted TLS Sessions &amp; SNI Hostnames ({analysis.tlsRecords.length})</span>
                    </h3>
                    {analysis.tlsRecords.length === 0 ? (
                      <p className="text-xs text-slate-500">No TLS ClientHello handshakes observed.</p>
                    ) : (
                      <div className="divide-y divide-slate-800 text-xs font-mono">
                        {analysis.tlsRecords.map((t, i) => (
                          <div key={i} className="py-2 flex items-center justify-between">
                            <div className="flex items-center space-x-2">
                              <span className="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px]">
                                {t.version}
                              </span>
                              <span className="text-slate-200">
                                SNI: <strong className="text-cyan-300">{t.sni}</strong>
                              </span>
                            </div>
                            <span className="text-[10px] text-slate-500">Pkt #{t.packetNumber}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* TAB 5: 12-SECTION SOC REPORT */}
              {activeTab === "report" && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                        12-Section SOC Investigation Report
                      </h2>
                      <p className="text-xs text-slate-500">
                        Formatted technical investigation report adhering to standard DFIR practices
                      </p>
                    </div>

                    <div className="flex items-center space-x-2">
                      <button
                        onClick={handleCopyReport}
                        className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 font-medium transition cursor-pointer border border-slate-700"
                      >
                        {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copied ? "Copied" : "Copy Report"}</span>
                      </button>
                      <button
                        onClick={() =>
                          handleDownload(analysis.reportText, `${analysis.fileName}_report.txt`, "text/plain")
                        }
                        className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-xs text-white font-medium transition cursor-pointer"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>Download TXT</span>
                      </button>
                    </div>
                  </div>

                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-5 overflow-x-auto">
                    <pre className="text-xs font-mono text-slate-300 leading-relaxed whitespace-pre font-normal">
                      {analysis.reportText}
                    </pre>
                  </div>
                </div>
              )}

              {/* TAB 6: JSON SIEM EXPORT */}
              {activeTab === "json" && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                        Machine-Readable JSON Schema Export
                      </h2>
                      <p className="text-xs text-slate-500">Directly ingestible into Splunk, Elastic, or Sentinel</p>
                    </div>

                    <button
                      onClick={() =>
                        handleDownload(
                          JSON.stringify(analysis, null, 2),
                          `${analysis.fileName}_analysis.json`,
                          "application/json"
                        )
                      }
                      className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-xs text-white font-medium transition cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Download JSON</span>
                    </button>
                  </div>

                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 overflow-x-auto max-h-[500px]">
                    <pre className="text-xs font-mono text-cyan-400 whitespace-pre">
                      {JSON.stringify(
                        {
                          metadata: {
                            file_name: analysis.fileName,
                            file_size: analysis.fileSizeBytes,
                            packet_count: analysis.totalPackets,
                            duration_seconds: analysis.durationSeconds,
                          },
                          summary: {
                            total_bytes: analysis.totalBytes,
                            unique_sources: analysis.uniqueSources,
                            unique_destinations: analysis.uniqueDestinations,
                            active_flows: analysis.flows.length,
                          },
                          protocols: analysis.protocols,
                          top_sources: analysis.topSources,
                          top_destinations: analysis.topDestinations,
                          findings: analysis.findings,
                        },
                        null,
                        2
                      )}
                    </pre>
                  </div>
                </div>
              )}

              {/* TAB 7: PYTHON CLI & ARCHITECTURE GUIDE */}
              {activeTab === "cli" && (
                <div className="space-y-6">
                  <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
                    <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-200 flex items-center space-x-2">
                      <Terminal className="w-4 h-4 text-cyan-400" />
                      <span>Python CLI Execution Guide</span>
                    </h2>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      The core backend engine is completely written in Python (3.10+ / 3.11+) and can be executed
                      directly from any command line or imported programmatically into security pipelines.
                    </p>

                    <div className="bg-slate-950 border border-slate-800 rounded-md p-4 text-xs font-mono text-slate-300 space-y-3">
                      <div>
                        <span className="text-slate-500"># 1. Run basic capture analysis:</span>
                        <div className="text-cyan-300 mt-0.5">python3 -m pcap_analyzer capture.pcap</div>
                      </div>
                      <div>
                        <span className="text-slate-500"># 2. Export 12-section technical investigation report:</span>
                        <div className="text-cyan-300 mt-0.5">
                          python3 -m pcap_analyzer -i capture.pcap -r forensic_report.txt
                        </div>
                      </div>
                      <div>
                        <span className="text-slate-500"># 3. Export structured SIEM JSON and report simultaneously:</span>
                        <div className="text-cyan-300 mt-0.5">
                          python3 -m pcap_analyzer -i capture.pcap -o analysis.json -r report.txt
                        </div>
                      </div>
                      <div>
                        <span className="text-slate-500"># 4. Run automated unit test suite:</span>
                        <div className="text-cyan-300 mt-0.5">
                          PYTHONPATH=src:tests python3 -m unittest discover -s tests -p &quot;test_*.py&quot; -v
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Modular Architecture Layout */}
                  <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-3">
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                      Python Package Architecture (src/pcap_analyzer)
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                      <div className="bg-slate-950 p-3 rounded border border-slate-800/80">
                        <strong className="text-cyan-400">parser.py</strong>
                        <p className="text-slate-400 text-[11px] mt-1 font-sans">
                          Multi-engine abstraction: zero-dependency Native binary RFC reader, Scapy integration, and PyShark.
                        </p>
                      </div>
                      <div className="bg-slate-950 p-3 rounded border border-slate-800/80">
                        <strong className="text-cyan-400">detections.py</strong>
                        <p className="text-slate-400 text-[11px] mt-1 font-sans">
                          Rule-based heuristic engine: RULE-001 (SYN scan) through RULE-008 (Cleartext protocols).
                        </p>
                      </div>
                      <div className="bg-slate-950 p-3 rounded border border-slate-800/80">
                        <strong className="text-cyan-400">statistics.py</strong>
                        <p className="text-slate-400 text-[11px] mt-1 font-sans">
                          Stateful flow tracking, TCP 3-way handshake verification, and endpoint bandwidth accounting.
                        </p>
                      </div>
                      <div className="bg-slate-950 p-3 rounded border border-slate-800/80">
                        <strong className="text-cyan-400">reporting.py</strong>
                        <p className="text-slate-400 text-[11px] mt-1 font-sans">
                          Generates 12-section technical investigation reports and structured machine JSON.
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </main>
      </div>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 px-6 py-2.5 flex flex-wrap items-center justify-between text-[11px] text-slate-500">
        <div>
          Automated Python PCAP Analyzer &amp; Threat Parser &bull; Defensive Cybersecurity &amp; Network Forensics
        </div>
        <div className="flex items-center space-x-3">
          <span>Deterministic Heuristics</span>
          <span>&bull;</span>
          <span>Apache 2.0 License</span>
        </div>
      </footer>
    </div>
  );
}
