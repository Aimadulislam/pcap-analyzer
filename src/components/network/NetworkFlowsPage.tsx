import React, { useState, useMemo } from "react";
import {
  Network,
  Search,
  Filter,
  ArrowUpDown,
  Download,
  CheckCircle2,
  XCircle,
  Clock,
  ArrowRight,
} from "lucide-react";
import { FlowRecord } from "../../types/analyzer";
import { formatBytes, formatDuration } from "../../utils/formatters";
import { FlowDetailModal } from "./FlowDetailModal";

interface NetworkFlowsPageProps {
  flows: FlowRecord[];
}

export const NetworkFlowsPage: React.FC<NetworkFlowsPageProps> = ({ flows = [] }) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("ALL");
  const [handshakeFilter, setHandshakeFilter] = useState("ALL");
  const [sortBy, setSortBy] = useState<"packets" | "bytes" | "duration">("packets");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [selectedFlow, setSelectedFlow] = useState<FlowRecord | null>(null);

  const filteredFlows = useMemo(() => {
    return flows
      .filter((flow) => {
        // Protocol filter
        if (protocolFilter !== "ALL" && flow.protocol.toUpperCase() !== protocolFilter) {
          return false;
        }
        // Handshake filter
        if (handshakeFilter === "ESTABLISHED" && !flow.completed_handshake) return false;
        if (handshakeFilter === "FAILED" && flow.completed_handshake) return false;

        // Search query
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const match =
            flow.flow_id.toLowerCase().includes(q) ||
            flow.source_ip.includes(q) ||
            flow.destination_ip.includes(q) ||
            (flow.source_port && flow.source_port.toString().includes(q)) ||
            (flow.destination_port && flow.destination_port.toString().includes(q));
          if (!match) return false;
        }
        return true;
      })
      .sort((a, b) => {
        let diff = 0;
        if (sortBy === "packets") diff = a.packet_count - b.packet_count;
        else if (sortBy === "bytes") diff = a.byte_count - b.byte_count;
        else if (sortBy === "duration") diff = a.duration_seconds - b.duration_seconds;
        return sortOrder === "desc" ? -diff : diff;
      });
  }, [flows, protocolFilter, handshakeFilter, searchQuery, sortBy, sortOrder]);

  const handleExportCsv = () => {
    if (!flows.length) return;
    const headers = [
      "Flow ID",
      "Source IP",
      "Source Port",
      "Destination IP",
      "Destination Port",
      "Protocol",
      "Packets",
      "Bytes",
      "Duration (s)",
      "Established Handshake",
      "Classification",
    ];

    const rows = filteredFlows.map((f) => [
      `"${f.flow_id}"`,
      `"${f.source_ip}"`,
      f.source_port || "",
      `"${f.destination_ip}"`,
      f.destination_port || "",
      `"${f.protocol}"`,
      f.packet_count,
      f.byte_count,
      f.duration_seconds.toFixed(3),
      f.completed_handshake ? "Yes" : "No",
      `"${f.classification || ""}"`,
    ]);

    const csvContent = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `network_flows_${Date.now()}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const toggleSort = (field: "packets" | "bytes" | "duration") => {
    if (sortBy === field) {
      setSortOrder((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortBy(field);
      setSortOrder("desc");
    }
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold text-slate-100 tracking-tight">
            Network Flow Matrix
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Bidirectional conversation channels reconstructed across transport and application layer streams.
          </p>
        </div>

        <button
          onClick={handleExportCsv}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-slate-100 rounded text-xs transition cursor-pointer self-start sm:self-auto"
        >
          <Download className="w-3.5 h-3.5 text-cyan-400" />
          <span>Export CSV</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row gap-3 items-center justify-between">
        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
          {/* Protocol Filter */}
          <div className="flex items-center space-x-1 bg-slate-900 border border-slate-800 rounded p-0.5 text-xs">
            {["ALL", "TCP", "UDP", "ICMP"].map((proto) => (
              <button
                key={proto}
                onClick={() => setProtocolFilter(proto)}
                className={`px-2.5 py-1 rounded cursor-pointer ${
                  protocolFilter === proto
                    ? "bg-cyan-950 text-cyan-300 font-medium"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {proto}
              </button>
            ))}
          </div>

          {/* Handshake Filter */}
          <div className="flex items-center space-x-1 bg-slate-900 border border-slate-800 rounded p-0.5 text-xs">
            <button
              onClick={() => setHandshakeFilter("ALL")}
              className={`px-2.5 py-1 rounded cursor-pointer ${
                handshakeFilter === "ALL"
                  ? "bg-cyan-950 text-cyan-300 font-medium"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              All Sessions
            </button>
            <button
              onClick={() => setHandshakeFilter("ESTABLISHED")}
              className={`px-2.5 py-1 rounded cursor-pointer ${
                handshakeFilter === "ESTABLISHED"
                  ? "bg-emerald-950 text-emerald-300 font-medium"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Established
            </button>
            <button
              onClick={() => setHandshakeFilter("FAILED")}
              className={`px-2.5 py-1 rounded cursor-pointer ${
                handshakeFilter === "FAILED"
                  ? "bg-rose-950 text-rose-300 font-medium"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Unestablished / SYN
            </button>
          </div>
        </div>

        {/* Search */}
        <div className="relative w-full md:w-64">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Filter IP or port..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Flow Matrix Table */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-medium bg-slate-900/60">
                <th className="py-2.5 px-4 font-normal">Source Endpoint</th>
                <th className="py-2.5 px-2 font-normal text-center">Direction</th>
                <th className="py-2.5 px-4 font-normal">Destination Endpoint</th>
                <th className="py-2.5 px-3 font-normal">Protocol</th>
                <th
                  onClick={() => toggleSort("packets")}
                  className="py-2.5 px-3 font-normal text-right cursor-pointer hover:text-cyan-400 select-none"
                >
                  <div className="flex items-center justify-end space-x-1">
                    <span>Packets</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th
                  onClick={() => toggleSort("bytes")}
                  className="py-2.5 px-3 font-normal text-right cursor-pointer hover:text-cyan-400 select-none"
                >
                  <div className="flex items-center justify-end space-x-1">
                    <span>Volume</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th
                  onClick={() => toggleSort("duration")}
                  className="py-2.5 px-3 font-normal text-right cursor-pointer hover:text-cyan-400 select-none"
                >
                  <div className="flex items-center justify-end space-x-1">
                    <span>Duration</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="py-2.5 px-4 font-normal text-center">Handshake State</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
              {filteredFlows.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-10 text-center text-slate-500 font-sans">
                    No network flows match the selected query.
                  </td>
                </tr>
              ) : (
                filteredFlows.map((flow) => {
                  const isTcp = flow.protocol.toUpperCase() === "TCP";
                  return (
                    <tr
                      key={flow.flow_id}
                      onClick={() => setSelectedFlow(flow)}
                      className="hover:bg-slate-800/50 cursor-pointer transition-colors"
                      title="Click to view deep 5-tuple metrics, handshake states, and Wireshark filter"
                    >
                      {/* Source */}
                      <td className="py-2.5 px-4">
                        <span className="text-cyan-400 font-medium select-all">{flow.source_ip}</span>
                        {flow.source_port !== null && (
                          <span className="text-slate-500">:{flow.source_port}</span>
                        )}
                      </td>

                      {/* Direction */}
                      <td className="py-2.5 px-2 text-center text-slate-600">
                        <ArrowRight className="w-3.5 h-3.5 mx-auto" />
                      </td>

                      {/* Destination */}
                      <td className="py-2.5 px-4">
                        <span className="text-slate-200 select-all">{flow.destination_ip}</span>
                        {flow.destination_port !== null && (
                          <span className="text-cyan-500 font-medium">:{flow.destination_port}</span>
                        )}
                      </td>

                      {/* Protocol */}
                      <td className="py-2.5 px-3">
                        <span className="text-[11px] px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                          {flow.protocol}
                        </span>
                      </td>

                      {/* Packets */}
                      <td className="py-2.5 px-3 text-right text-slate-200 tabular-nums">
                        {flow.packet_count.toLocaleString()}
                      </td>

                      {/* Bytes */}
                      <td className="py-2.5 px-3 text-right text-slate-300 tabular-nums">
                        {formatBytes(flow.byte_count)}
                      </td>

                      {/* Duration */}
                      <td className="py-2.5 px-3 text-right text-slate-400 tabular-nums">
                        {flow.duration_seconds > 0 ? `${flow.duration_seconds.toFixed(3)}s` : "0s"}
                      </td>

                      {/* Handshake */}
                      <td className="py-2.5 px-4 text-center">
                        {isTcp ? (
                          flow.completed_handshake ? (
                            <span className="inline-flex items-center space-x-1 text-[11px] text-emerald-400 bg-emerald-950/40 border border-emerald-800/60 px-2 py-0.5 rounded">
                              <CheckCircle2 className="w-3 h-3" />
                              <span>Established</span>
                            </span>
                          ) : (
                            <span className="inline-flex items-center space-x-1 text-[11px] text-amber-400 bg-amber-950/40 border border-amber-800/60 px-2 py-0.5 rounded">
                              <XCircle className="w-3 h-3" />
                              <span>SYN-Only</span>
                            </span>
                          )
                        ) : (
                          <span className="text-[11px] text-slate-500">Stateless</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Footer info */}
        <div className="p-3 border-t border-slate-800/80 bg-slate-900/40 text-xs text-slate-500 flex items-center justify-between">
          <span>
            Displaying <strong className="text-slate-300 font-mono">{filteredFlows.length}</strong> of{" "}
            <strong className="text-slate-300 font-mono">{flows.length}</strong> total conversation flows
          </span>
          <span className="font-mono">
            {flows.filter((f) => f.completed_handshake).length} established TCP sessions
          </span>
        </div>
      </div>

      {/* Deep Flow Inspection Modal */}
      {selectedFlow && (
        <FlowDetailModal
          flow={selectedFlow}
          onClose={() => setSelectedFlow(null)}
        />
      )}
    </div>
  );
};
