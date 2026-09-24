import React from "react";
import { Shield, Activity, Settings, RefreshCw, AlertCircle, Database } from "lucide-react";
import { BackendStatus } from "../../types/analyzer";

interface TopNavProps {
  backendStatus: BackendStatus;
  analysisStatus: "idle" | "analyzing" | "completed" | "error";
  isDemoData: boolean;
  onOpenSettings: () => void;
  onRefreshBackend: () => void;
  onNavigateToUpload: () => void;
}

export const TopNav: React.FC<TopNavProps> = ({
  backendStatus,
  analysisStatus,
  isDemoData,
  onOpenSettings,
  onRefreshBackend,
  onNavigateToUpload,
}) => {
  return (
    <header className="h-14 border-b border-slate-800 bg-[#0B0F19]/95 backdrop-blur px-4 md:px-6 flex items-center justify-between z-30 sticky top-0">
      {/* Brand Zone - Single line wordmark and clean secondary label */}
      <div className="flex items-center space-x-3 min-w-0">
        <div className="w-8 h-8 rounded bg-cyan-950/80 border border-cyan-800/60 flex items-center justify-center shrink-0 shadow-sm shadow-cyan-950">
          <Activity className="w-4 h-4 text-cyan-400" />
        </div>
        <div className="flex flex-col min-w-0">
          <div className="flex items-center space-x-2">
            <span className="text-sm font-semibold tracking-wide text-slate-100 whitespace-nowrap">
              Automated Python PCAP Analyzer
            </span>
            <span className="text-xs text-slate-500 hidden sm:inline" aria-hidden="true">·</span>
            <span className="text-xs text-slate-400 hidden sm:inline whitespace-nowrap">
              Threat Parser &amp; Network Forensics
            </span>
          </div>
        </div>
      </div>

      {/* Center / Status Zone */}
      <div className="flex items-center space-x-3 text-xs">
        {/* Backend Connection Indicator */}
        <button
          onClick={onRefreshBackend}
          title="Click to check Python backend connectivity"
          className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:border-slate-700 transition"
        >
          <span
            className={`w-2 h-2 rounded-full ${
              backendStatus.connected ? "bg-emerald-400 animate-pulse" : "bg-amber-400"
            }`}
          />
          <span className="whitespace-nowrap">
            {backendStatus.connected ? "Backend Connected" : "Demo Mode"}
          </span>
          <RefreshCw className="w-3 h-3 text-slate-500 hover:text-slate-300 ml-0.5" />
        </button>

        {/* Analysis Status */}
        <div className="hidden md:flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-900/60 border border-slate-800/80 text-slate-300">
          <span className="text-slate-500">Status:</span>
          <span
            className={`font-medium ${
              analysisStatus === "analyzing"
                ? "text-cyan-400 animate-pulse"
                : analysisStatus === "completed"
                ? "text-emerald-400"
                : analysisStatus === "error"
                ? "text-rose-400"
                : "text-slate-400"
            }`}
          >
            {analysisStatus === "analyzing"
              ? "Analyzing..."
              : analysisStatus === "completed"
              ? "Completed"
              : analysisStatus === "error"
              ? "Error"
              : "Idle"}
          </span>
        </div>

        {/* DEMO DATA label required by specification when viewing static demo fixtures */}
        {isDemoData && (
          <div
            title="Results currently displayed originate from static demo fixtures. Upload a PCAP to perform live analysis."
            className="flex items-center space-x-1 px-2.5 py-1 rounded bg-amber-950/60 border border-amber-800/70 text-amber-300 font-mono text-[11px] font-semibold"
          >
            <Database className="w-3 h-3 text-amber-400 shrink-0" />
            <span className="tracking-wide">DEMO DATA</span>
          </div>
        )}

        {/* Settings button */}
        <button
          onClick={onOpenSettings}
          title="Analysis configuration and engine settings"
          className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-transparent hover:border-slate-700 transition"
        >
          <Settings className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
};
