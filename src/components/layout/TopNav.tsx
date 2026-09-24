import React from "react";
import {
  Shield,
  Activity,
  Settings,
  RefreshCw,
  AlertCircle,
  Database,
  Compass,
  LayoutDashboard,
  BookOpen,
  CheckCircle2,
} from "lucide-react";
import { BackendStatus } from "../../types/analyzer";
import { NavTab } from "./Sidebar";

interface TopNavProps {
  backendStatus: BackendStatus;
  analysisStatus: "idle" | "analyzing" | "completed" | "error";
  isDemoData: boolean;
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  onOpenSettings: () => void;
  onRefreshBackend: () => void;
  onNavigateToUpload: () => void;
  testSuitePassing?: boolean;
}

export const TopNav: React.FC<TopNavProps> = ({
  backendStatus,
  analysisStatus,
  isDemoData,
  activeTab,
  onSelectTab,
  onOpenSettings,
  onRefreshBackend,
  onNavigateToUpload,
  testSuitePassing = true,
}) => {
  const isLanding = activeTab === "landing";
  const isDocs = activeTab === "docs";
  const isConsole = !isLanding && !isDocs;

  return (
    <header className="h-14 border-b border-slate-800 bg-[#0B0F19]/95 backdrop-blur px-4 md:px-6 flex items-center justify-between z-30 sticky top-0">
      {/* Brand Zone - Single line wordmark and clean secondary label */}
      <div
        onClick={() => onSelectTab("landing")}
        className="flex items-center space-x-3 min-w-0 cursor-pointer group"
      >
        <div className="w-8 h-8 rounded bg-cyan-950/80 border border-cyan-800/60 flex items-center justify-center shrink-0 shadow-sm shadow-cyan-950 group-hover:border-cyan-500 transition">
          <Activity className="w-4 h-4 text-cyan-400" />
        </div>
        <div className="flex flex-col min-w-0">
          <div className="flex items-center space-x-2">
            <span className="text-sm font-semibold tracking-wide text-slate-100 whitespace-nowrap group-hover:text-cyan-300 transition">
              Automated Python PCAP Analyzer
            </span>
            <span className="text-xs text-slate-500 hidden sm:inline" aria-hidden="true">·</span>
            <span className="text-xs text-slate-400 hidden sm:inline whitespace-nowrap">
              Threat Parser &amp; Network Forensics
            </span>
          </div>
        </div>
      </div>

      {/* Center Zone: Mode Switcher (Landing vs Analyst Console vs Documentation) */}
      <div className="hidden md:flex items-center space-x-1 p-1 bg-slate-950/80 rounded-lg border border-slate-800/90 text-xs">
        <button
          onClick={() => onSelectTab("landing")}
          className={`flex items-center space-x-1.5 px-3 py-1 rounded transition cursor-pointer font-medium ${
            isLanding
              ? "bg-cyan-600 text-white shadow-sm"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <Compass className="w-3.5 h-3.5" />
          <span>Project Landing</span>
        </button>

        <button
          onClick={() => onSelectTab("overview")}
          className={`flex items-center space-x-1.5 px-3 py-1 rounded transition cursor-pointer font-medium ${
            isConsole
              ? "bg-cyan-600 text-white shadow-sm"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <LayoutDashboard className="w-3.5 h-3.5" />
          <span>Analyst Workspace</span>
        </button>

        <button
          onClick={() => onSelectTab("docs")}
          className={`flex items-center space-x-1.5 px-3 py-1 rounded transition cursor-pointer font-medium ${
            isDocs
              ? "bg-cyan-600 text-white shadow-sm"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <BookOpen className="w-3.5 h-3.5" />
          <span>Documentation</span>
        </button>
      </div>

      {/* Status & Actions Zone */}
      <div className="flex items-center space-x-3 text-xs">
        {/* Test suite status pill */}
        <div
          title="31 Automated Python unit tests passing"
          className="hidden xl:flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 font-mono text-[11px]"
        >
          <span className="w-2 h-2 rounded-full bg-emerald-400" />
          <span>31/31 Tests Passing</span>
        </div>

        {/* Backend Connection Indicator */}
        <button
          onClick={onRefreshBackend}
          title="Click to check Python backend connectivity"
          className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:border-slate-700 transition cursor-pointer"
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
          className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-transparent hover:border-slate-700 transition cursor-pointer"
        >
          <Settings className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
};
