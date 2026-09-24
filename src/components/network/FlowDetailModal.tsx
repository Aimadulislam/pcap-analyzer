import React, { useState } from "react";
import {
  X,
  Network,
  Copy,
  Check,
  CheckCircle2,
  XCircle,
  Clock,
  ArrowRight,
  Shield,
  Activity,
  Filter,
} from "lucide-react";
import { FlowRecord } from "../../types/analyzer";
import { formatBytes, formatDuration } from "../../utils/formatters";

interface FlowDetailModalProps {
  flow: FlowRecord | null;
  onClose: () => void;
}

export const FlowDetailModal: React.FC<FlowDetailModalProps> = ({ flow, onClose }) => {
  const [copied, setCopied] = useState<string | null>(null);

  if (!flow) return null;

  const copySnippet = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const isTcp = flow.protocol.toUpperCase() === "TCP";

  // Construct standard Wireshark / tshark display filter
  const wiresharkFilter = isTcp && flow.source_port && flow.destination_port
    ? `((ip.src == ${flow.source_ip} && ip.dst == ${flow.destination_ip} && tcp.srcport == ${flow.source_port} && tcp.dstport == ${flow.destination_port}) || (ip.src == ${flow.destination_ip} && ip.dst == ${flow.source_ip} && tcp.srcport == ${flow.destination_port} && tcp.dstport == ${flow.source_port}))`
    : `((ip.src == ${flow.source_ip} && ip.dst == ${flow.destination_ip}) || (ip.src == ${flow.destination_ip} && ip.dst == ${flow.source_ip}))`;

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-[#111827] border border-slate-700/80 rounded-lg max-w-2xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center space-x-2.5 min-w-0">
            <div className="p-1.5 rounded bg-cyan-950 border border-cyan-800/80 text-cyan-400">
              <Network className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <div className="text-[10px] font-mono text-cyan-400 font-semibold uppercase tracking-wider">
                Conversation Flow Telemetry
              </div>
              <h3 className="text-xs font-semibold text-slate-200 truncate font-mono mt-0.5">
                {flow.flow_id}
              </h3>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto space-y-5 text-xs text-slate-300">
          {/* 5-Tuple Visual Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono">
            {/* Source */}
            <div className="bg-slate-950 p-3.5 rounded border border-slate-800 space-y-1">
              <span className="text-slate-500 text-[10px] uppercase block">Initiator / Source</span>
              <div className="text-cyan-400 font-semibold text-sm truncate">{flow.source_ip}</div>
              <div className="text-slate-400 text-xs">
                Port: {flow.source_port !== null ? flow.source_port : "Ephemeral / N/A"}
              </div>
            </div>

            {/* Destination */}
            <div className="bg-slate-950 p-3.5 rounded border border-slate-800 space-y-1">
              <span className="text-slate-500 text-[10px] uppercase block">Responder / Target</span>
              <div className="text-slate-200 font-semibold text-sm truncate">{flow.destination_ip}</div>
              <div className="text-slate-400 text-xs">
                Port: {flow.destination_port !== null ? flow.destination_port : "Dynamic / N/A"}
              </div>
            </div>
          </div>

          {/* Session Metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center font-mono">
            <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800/80">
              <span className="text-[10px] text-slate-500 block">Total Packets</span>
              <span className="text-sm font-semibold text-slate-200 tabular-nums">
                {flow.packet_count}
              </span>
            </div>
            <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800/80">
              <span className="text-[10px] text-slate-500 block">Total Volume</span>
              <span className="text-sm font-semibold text-slate-200 tabular-nums">
                {formatBytes(flow.byte_count)}
              </span>
            </div>
            <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800/80">
              <span className="text-[10px] text-slate-500 block">Flow Duration</span>
              <span className="text-sm font-semibold text-slate-200 tabular-nums">
                {flow.duration_seconds > 0 ? `${flow.duration_seconds.toFixed(3)}s` : "<1ms"}
              </span>
            </div>
            <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800/80">
              <span className="text-[10px] text-slate-500 block">Transport</span>
              <span className="text-sm font-semibold text-cyan-400">{flow.protocol}</span>
            </div>
          </div>

          {/* TCP Handshake State Breakdown */}
          {isTcp && (
            <div className="bg-slate-950 p-4 rounded border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  TCP Handshake &amp; State Inspection
                </span>
                <span
                  className={`inline-flex items-center space-x-1 text-[10px] font-semibold px-2 py-0.5 rounded border ${
                    flow.completed_handshake
                      ? "bg-emerald-950/60 text-emerald-300 border-emerald-800"
                      : "bg-amber-950/60 text-amber-300 border-amber-800"
                  }`}
                >
                  {flow.completed_handshake ? (
                    <>
                      <CheckCircle2 className="w-3 h-3" />
                      <span>3-Way Handshake Established</span>
                    </>
                  ) : (
                    <>
                      <XCircle className="w-3 h-3" />
                      <span>Handshake Incomplete / SYN-Only</span>
                    </>
                  )}
                </span>
              </div>

              <div className="grid grid-cols-4 gap-2 text-center font-mono text-[11px]">
                <div className="bg-slate-900/80 p-2 rounded">
                  <span className="text-slate-500 block text-[10px]">SYN</span>
                  <span className="text-slate-200">{flow.syn_count || 0}</span>
                </div>
                <div className="bg-slate-900/80 p-2 rounded">
                  <span className="text-slate-500 block text-[10px]">SYN-ACK</span>
                  <span className="text-slate-200">{flow.syn_ack_count || 0}</span>
                </div>
                <div className="bg-slate-900/80 p-2 rounded">
                  <span className="text-slate-500 block text-[10px]">ACK</span>
                  <span className="text-slate-200">{flow.ack_count || 0}</span>
                </div>
                <div className="bg-slate-900/80 p-2 rounded">
                  <span className="text-slate-500 block text-[10px]">RST / FIN</span>
                  <span className="text-slate-200">
                    {(flow.rst_count || 0) + (flow.fin_count || 0)}
                  </span>
                </div>
              </div>

              <p className="text-[11px] text-slate-400 leading-relaxed pt-1">
                {flow.completed_handshake
                  ? "Both SYN and matching SYN-ACK/ACK sequence packets were identified in this conversation, confirming an established two-way connection."
                  : "Flow terminated prematurely without established handshake confirmation. If multiple such flows originate from the same source, it represents port probing or service failure."}
              </p>
            </div>
          )}

          {/* Wireshark Filter Generator */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center space-x-1.5">
                <Filter className="w-3.5 h-3.5 text-cyan-400" />
                <span>Wireshark / TShark Filter</span>
              </span>
              <button
                onClick={() => copySnippet(wiresharkFilter, "ws-filter")}
                className="flex items-center space-x-1 text-[11px] text-cyan-400 hover:text-cyan-300 transition cursor-pointer"
              >
                {copied === "ws-filter" ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copy Filter</span>
                  </>
                )}
              </button>
            </div>

            <div className="bg-slate-950 p-3 rounded border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto select-all">
              <code>{wiresharkFilter}</code>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-3.5 border-t border-slate-800 bg-slate-950 flex items-center justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold cursor-pointer"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
