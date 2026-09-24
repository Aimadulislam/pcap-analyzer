import React, { useState, useMemo } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Clock,
  HardDrive,
  Copy,
  Check,
  Network,
  Activity,
  ArrowUpRight,
  Fingerprint,
  AlertTriangle,
} from "lucide-react";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  AreaChart,
  Area,
} from "recharts";
import { AnalysisResult } from "../../types/analyzer";
import { formatBytes, formatDuration, formatTimestamp } from "../../utils/formatters";

interface OverviewDashboardProps {
  analysis: AnalysisResult;
  onNavigateToTab: (tab: any) => void;
}

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: "#38bdf8", // Sky blue
  UDP: "#818cf8", // Indigo
  DNS: "#34d399", // Emerald
  HTTP: "#fbbf24", // Amber
  TLS: "#a78bfa", // Purple
  ICMP: "#f87171", // Rose
  Other: "#94a3b8", // Slate
};

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  analysis,
  onNavigateToTab,
}) => {
  const [copiedHash, setCopiedHash] = useState(false);
  const [destSortField, setDestSortField] = useState<"packets" | "bytes">("packets");
  const [timelineMetric, setTimelineMetric] = useState<"packets" | "bytes">("packets");

  const metadata = analysis.metadata;
  const summary = analysis.summary;
  const findings = analysis.findings || [];

  // Severity counts
  const severityCounts = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const f of findings) {
      const sev = f.severity?.toUpperCase() as keyof typeof counts;
      if (counts[sev] !== undefined) {
        counts[sev]++;
      }
    }
    return counts;
  }, [findings]);

  // Protocol chart data
  const protocolData = useMemo(() => {
    const dist = analysis.protocols || summary.protocol_distribution || {};
    const total = summary.total_packets || 1;
    return Object.entries(dist).map(([name, count]) => ({
      name,
      count,
      percentage: Number(((count / total) * 100).toFixed(1)),
      color: PROTOCOL_COLORS[name] || "#64748b",
    })).sort((a, b) => b.count - a.count);
  }, [analysis.protocols, summary]);

  // Top destinations sorted
  const sortedDestinations = useMemo(() => {
    const items = [...(analysis.top_destinations || summary.top_destination_ips || [])];
    if (destSortField === "bytes") {
      return items.sort((a, b) => b.byte_count - a.byte_count);
    }
    return items.sort((a, b) => b.packet_count - a.packet_count);
  }, [analysis.top_destinations, summary, destSortField]);

  // Compute actual timeline from flows if timestamps exist
  const timelineData = useMemo(() => {
    if (!analysis.flows || analysis.flows.length === 0) return null;
    const flowsWithTime = analysis.flows.filter((f) => f.first_seen && f.first_seen > 0);
    if (flowsWithTime.length === 0) return null;

    let minT = Infinity;
    let maxT = -Infinity;
    for (const f of flowsWithTime) {
      if (f.first_seen < minT) minT = f.first_seen;
      if (f.last_seen > maxT) maxT = f.last_seen;
    }

    const duration = maxT - minT;
    if (duration <= 0.001 || !isFinite(duration)) return null;

    // Bucket into 10 intervals
    const buckets = 10;
    const step = duration / buckets;
    const bins: { label: string; packets: number; bytes: number }[] = [];

    for (let i = 0; i < buckets; i++) {
      const bStart = minT + i * step;
      const bEnd = bStart + step;
      let pkts = 0;
      let bytes = 0;
      for (const f of flowsWithTime) {
        if (f.first_seen >= bStart && f.first_seen < bEnd) {
          pkts += f.packet_count;
          bytes += f.byte_count;
        }
      }
      bins.push({
        label: `+${(i * step).toFixed(1)}s`,
        packets: pkts,
        bytes: bytes,
      });
    }

    return bins;
  }, [analysis.flows]);

  // IOC count
  const totalIocs = useMemo(() => {
    if (!analysis.iocs) return 0;
    return Object.values(analysis.iocs).reduce((acc, list) => acc + (list?.length || 0), 0);
  }, [analysis.iocs]);

  const handleCopySha256 = () => {
    const hash = metadata.sha256_hash || analysis.integrity?.sha256;
    if (!hash) return;
    navigator.clipboard.writeText(hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const sha256Value = metadata.sha256_hash || analysis.integrity?.sha256 || "N/A";

  return (
    <div className="space-y-6">
      {/* Top Banner: PCAP Security Overview */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800/80 pb-4 mb-4">
          <div>
            <h2 className="text-lg font-semibold text-slate-100 tracking-tight">
              PCAP Security Overview
            </h2>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-400 mt-1">
              <span>Capture: <strong className="text-slate-200 font-mono">{metadata.file_name}</strong></span>
              <span aria-hidden="true">·</span>
              <span>Profile: <strong className="text-cyan-400 capitalize">{metadata.profile_name || "default"}</strong></span>
              <span aria-hidden="true">·</span>
              <span>Dissection Engine: <strong className="text-slate-200">{metadata.parser_engine}</strong></span>
              <span aria-hidden="true">·</span>
              <span>Duration: <strong className="text-slate-200 font-mono">{formatDuration(metadata.duration_seconds || summary.capture_duration)}</strong></span>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <span className="text-xs text-slate-500 font-medium">Status:</span>
            <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded bg-emerald-950/50 border border-emerald-800/70 text-emerald-400 text-xs font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>Analysis Completed</span>
            </span>
          </div>
        </div>

        {/* Cryptographic SHA-256 Hash */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs bg-slate-950/70 border border-slate-800/70 px-3.5 py-2 rounded font-mono">
          <div className="flex items-center space-x-2 min-w-0">
            <span className="text-slate-500 shrink-0">SHA-256:</span>
            <span className="text-slate-300 truncate select-all">{sha256Value}</span>
          </div>
          <button
            onClick={handleCopySha256}
            className="flex items-center space-x-1 text-cyan-400 hover:text-cyan-300 transition shrink-0 cursor-pointer self-start sm:self-auto"
            title="Copy SHA-256 checksum to clipboard"
          >
            {copiedHash ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy Hash</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Summary Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5">
        <div className="bg-[#111827] border border-slate-800 rounded-lg p-4">
          <div className="text-xs text-slate-400 mb-1">Total Packets</div>
          <div className="text-2xl font-bold font-mono text-slate-100 tabular-nums">
            {summary.total_packets.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono">
            {metadata.file_format}
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-lg p-4">
          <div className="text-xs text-slate-400 mb-1">Total Bytes</div>
          <div className="text-2xl font-bold font-mono text-slate-100 tabular-nums">
            {formatBytes(summary.total_bytes)}
          </div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono">
            {(summary.total_bytes).toLocaleString()} bytes
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-lg p-4">
          <div className="text-xs text-slate-400 mb-1">Capture Duration</div>
          <div className="text-2xl font-bold font-mono text-slate-100 tabular-nums">
            {formatDuration(summary.capture_duration || metadata.duration_seconds)}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            {metadata.duration_seconds > 0 ? `${metadata.duration_seconds.toFixed(2)}s active window` : "Instantaneous"}
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-lg p-4">
          <div className="text-xs text-slate-400 mb-1">Unique Endpoints</div>
          <div className="text-2xl font-bold font-mono text-cyan-400 tabular-nums">
            {summary.unique_source_ips} <span className="text-slate-500 text-base font-normal">/</span> {summary.unique_destination_ips}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            Sources / Destinations
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-lg p-4">
          <div className="text-xs text-slate-400 mb-1">Network Flows</div>
          <div className="text-2xl font-bold font-mono text-slate-100 tabular-nums">
            {(analysis.flows?.length || summary.unique_conversations || 0).toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            {summary.completed_handshakes || 0} established handshakes
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-lg p-4">
          <div className="text-xs text-slate-400 mb-1">Security Findings</div>
          <div className={`text-2xl font-bold font-mono tabular-nums ${
            findings.length > 0 ? "text-rose-400" : "text-emerald-400"
          }`}>
            {findings.length}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            {findings.length === 0 ? "No anomalies flagged" : `${severityCounts.HIGH + severityCounts.CRITICAL} high priority`}
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-lg p-4">
          <div className="text-xs text-slate-400 mb-1">Extracted IOCs</div>
          <div className="text-2xl font-bold font-mono text-slate-100 tabular-nums">
            {totalIocs}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            Observable indicators
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-lg p-4">
          <div className="text-xs text-slate-400 mb-1">Parsing Errors</div>
          <div className="text-2xl font-bold font-mono text-slate-100 tabular-nums">
            {analysis.errors?.length || 0}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            {analysis.errors?.length === 0 ? "Zero frame errors" : "Malformed packets logged"}
          </div>
        </div>
      </div>

      {/* Finding Summary (Severity Overview) */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-200">
              Severity Overview
            </h3>
          </div>
          <button
            onClick={() => onNavigateToTab("findings")}
            className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 cursor-pointer"
          >
            <span>View all findings</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {findings.length === 0 ? (
          <div className="flex items-center space-x-2 text-xs text-emerald-400 bg-emerald-950/30 border border-emerald-800/40 p-3 rounded">
            <ShieldCheck className="w-4 h-4 shrink-0" />
            <span>0 security findings · Traffic conforms to configured threat baseline.</span>
          </div>
        ) : (
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs">
            <div className="bg-slate-900/80 border border-red-900/40 p-3 rounded flex items-center justify-between">
              <span className="text-slate-400 font-medium">CRITICAL</span>
              <span className="font-mono font-bold text-red-400 text-sm tabular-nums">
                {String(severityCounts.CRITICAL).padStart(2, "0")}
              </span>
            </div>

            <div className="bg-slate-900/80 border border-rose-900/40 p-3 rounded flex items-center justify-between">
              <span className="text-slate-400 font-medium">HIGH</span>
              <span className="font-mono font-bold text-rose-400 text-sm tabular-nums">
                {String(severityCounts.HIGH).padStart(2, "0")}
              </span>
            </div>

            <div className="bg-slate-900/80 border border-amber-900/40 p-3 rounded flex items-center justify-between">
              <span className="text-slate-400 font-medium">MEDIUM</span>
              <span className="font-mono font-bold text-amber-400 text-sm tabular-nums">
                {String(severityCounts.MEDIUM).padStart(2, "0")}
              </span>
            </div>

            <div className="bg-slate-900/80 border border-cyan-900/40 p-3 rounded flex items-center justify-between">
              <span className="text-slate-400 font-medium">LOW</span>
              <span className="font-mono font-bold text-cyan-400 text-sm tabular-nums">
                {String(severityCounts.LOW).padStart(2, "0")}
              </span>
            </div>

            <div className="bg-slate-900/80 border border-slate-800 p-3 rounded flex items-center justify-between">
              <span className="text-slate-400 font-medium">INFO</span>
              <span className="font-mono font-bold text-slate-300 text-sm tabular-nums">
                {String(severityCounts.INFO).padStart(2, "0")}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Protocol Distribution & Traffic Activity Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Protocol Distribution */}
        <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-slate-200">
                Protocol Distribution
              </h3>
              <span className="text-xs text-slate-500 font-mono">
                {protocolData.length} protocols dissected
              </span>
            </div>

            <div className="h-52 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protocolData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={3}
                    dataKey="count"
                  >
                    {protocolData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} stroke="#0f172a" strokeWidth={2} />
                    ))}
                  </Pie>
                  <Tooltip
                    content={({ active, payload }) => {
                      if (active && payload && payload.length) {
                        const data = payload[0].payload;
                        return (
                          <div className="bg-slate-900 border border-slate-700 p-2 rounded shadow text-xs font-mono">
                            <div className="text-slate-200 font-semibold">{data.name}</div>
                            <div className="text-cyan-400">{data.count.toLocaleString()} packets ({data.percentage}%)</div>
                          </div>
                        );
                      }
                      return null;
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 pt-3 border-t border-slate-800/80 text-xs">
            {protocolData.map((p) => (
              <div key={p.name} className="flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded-sm shrink-0" style={{ backgroundColor: p.color }} />
                <span className="text-slate-400 truncate">{p.name}:</span>
                <span className="font-mono text-slate-200 tabular-nums">{p.count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Network Activity Panel */}
        <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-slate-200">
                Network Activity Timeline
              </h3>
              {timelineData && (
                <div className="flex items-center space-x-1 p-0.5 bg-slate-900 border border-slate-800 rounded text-xs">
                  <button
                    onClick={() => setTimelineMetric("packets")}
                    className={`px-2 py-0.5 rounded cursor-pointer ${
                      timelineMetric === "packets"
                        ? "bg-cyan-950 text-cyan-300 font-medium"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    Packets
                  </button>
                  <button
                    onClick={() => setTimelineMetric("bytes")}
                    className={`px-2 py-0.5 rounded cursor-pointer ${
                      timelineMetric === "bytes"
                        ? "bg-cyan-950 text-cyan-300 font-medium"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    Bytes
                  </button>
                </div>
              )}
            </div>

            {timelineData ? (
              <div className="h-52 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timelineData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="label" stroke="#64748b" tick={{ fontSize: 11 }} />
                    <YAxis
                      stroke="#64748b"
                      tick={{ fontSize: 11 }}
                      tickFormatter={(val) => (timelineMetric === "bytes" ? formatBytes(val) : val)}
                    />
                    <Tooltip
                      content={({ active, payload }) => {
                        if (active && payload && payload.length) {
                          const data = payload[0].payload;
                          return (
                            <div className="bg-slate-900 border border-slate-700 p-2 rounded shadow text-xs font-mono">
                              <div className="text-slate-400">Interval: {data.label}</div>
                              <div className="text-cyan-400">
                                {timelineMetric === "bytes"
                                  ? formatBytes(data.bytes)
                                  : `${data.packets.toLocaleString()} packets`}
                              </div>
                            </div>
                          );
                        }
                        return null;
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey={timelineMetric}
                      stroke="#06b6d4"
                      fill="#06b6d4"
                      fillOpacity={0.2}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="h-52 flex flex-col items-center justify-center text-xs text-slate-500 border border-dashed border-slate-800 rounded">
                <Clock className="w-5 h-5 text-slate-600 mb-2" />
                <p>Traffic timeline unavailable for this analysis.</p>
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-slate-800/80 text-xs text-slate-500 flex items-center justify-between">
            <span>Sample interval: Continuous capture</span>
            <span className="font-mono">Window: {formatDuration(metadata.duration_seconds || summary.capture_duration)}</span>
          </div>
        </div>
      </div>

      {/* Top Talkers & Top Destinations Tables */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Talkers (Source IPs) */}
        <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-slate-200">
              Top Talkers (Transmitting Sources)
            </h3>
            <span className="text-xs text-slate-500 font-mono">
              {(analysis.top_sources || summary.top_source_ips || []).length} sources
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500 font-medium">
                  <th className="py-2 font-normal">Source IP</th>
                  <th className="py-2 font-normal text-right">Packets</th>
                  <th className="py-2 font-normal text-right">Bytes</th>
                  <th className="py-2 font-normal text-right">Share</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {(analysis.top_sources || summary.top_source_ips || []).slice(0, 5).map((src) => (
                  <tr key={src.ip} className="hover:bg-slate-800/30">
                    <td className="py-2 text-cyan-400 font-medium select-all">{src.ip}</td>
                    <td className="py-2 text-right text-slate-200 tabular-nums">{src.packet_count.toLocaleString()}</td>
                    <td className="py-2 text-right text-slate-300 tabular-nums">{formatBytes(src.byte_count)}</td>
                    <td className="py-2 text-right text-slate-400 tabular-nums">{src.percentage.toFixed(1)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Top Destinations */}
        <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-slate-200">
              Top Destinations
            </h3>
            <div className="flex items-center space-x-1 text-xs">
              <span className="text-slate-500">Sort:</span>
              <button
                onClick={() => setDestSortField("packets")}
                className={`px-2 py-0.5 rounded cursor-pointer ${
                  destSortField === "packets"
                    ? "bg-cyan-950 text-cyan-300"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                Packets
              </button>
              <button
                onClick={() => setDestSortField("bytes")}
                className={`px-2 py-0.5 rounded cursor-pointer ${
                  destSortField === "bytes"
                    ? "bg-cyan-950 text-cyan-300"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                Bytes
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500 font-medium">
                  <th className="py-2 font-normal">Destination IP</th>
                  <th className="py-2 font-normal text-right">Packets</th>
                  <th className="py-2 font-normal text-right">Bytes</th>
                  <th className="py-2 font-normal text-right">Share</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {sortedDestinations.slice(0, 5).map((dst) => (
                  <tr key={dst.ip} className="hover:bg-slate-800/30">
                    <td className="py-2 text-slate-200 font-medium select-all">{dst.ip}</td>
                    <td className="py-2 text-right text-slate-200 tabular-nums">{dst.packet_count.toLocaleString()}</td>
                    <td className="py-2 text-right text-slate-300 tabular-nums">{formatBytes(dst.byte_count)}</td>
                    <td className="py-2 text-right text-slate-400 tabular-nums">{dst.percentage.toFixed(1)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
