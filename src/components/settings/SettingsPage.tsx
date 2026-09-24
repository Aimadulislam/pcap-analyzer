import React from "react";
import {
  Sliders,
  Cpu,
  Shield,
  RefreshCw,
  Database,
  CheckCircle2,
  Terminal,
  Info,
} from "lucide-react";
import { AnalysisProfile, BackendStatus, DissectionEngine } from "../../types/analyzer";

interface SettingsPageProps {
  backendStatus: BackendStatus;
  currentProfile: AnalysisProfile;
  onChangeProfile: (profile: AnalysisProfile) => void;
  currentEngine: DissectionEngine;
  onChangeEngine: (engine: DissectionEngine) => void;
  isDemoMode: boolean;
  onToggleDemoMode: () => void;
  onRefreshBackend: () => void;
}

export const SettingsPage: React.FC<SettingsPageProps> = ({
  backendStatus,
  currentProfile,
  onChangeProfile,
  currentEngine,
  onChangeEngine,
  isDemoMode,
  onToggleDemoMode,
  onRefreshBackend,
}) => {
  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div>
        <h2 className="text-xl font-semibold text-slate-100 tracking-tight">
          System Configuration &amp; Engine Settings
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Runtime environment parameters, detection profile thresholds, and dissection engine specifications.
        </p>
      </div>

      {/* Backend & Runtime Status */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2.5">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-200">
              Python Analysis Engine Status
            </h3>
          </div>
          <button
            onClick={onRefreshBackend}
            className="flex items-center space-x-1.5 px-2.5 py-1 bg-slate-900 border border-slate-800 text-slate-300 hover:text-slate-100 rounded text-xs transition cursor-pointer"
          >
            <RefreshCw className="w-3 h-3 text-cyan-400" />
            <span>Verify Connection</span>
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
          <div className="bg-slate-950/60 p-3 rounded border border-slate-800/60">
            <span className="text-slate-500 block text-[11px] font-sans">Connection State</span>
            <div className="flex items-center space-x-2 mt-1">
              <span
                className={`w-2 h-2 rounded-full ${
                  backendStatus.connected ? "bg-emerald-400" : "bg-amber-400"
                }`}
              />
              <span className="text-slate-200 font-semibold">
                {backendStatus.connected ? "Live Backend Connected" : "Operating in Demo Mode"}
              </span>
            </div>
          </div>

          <div className="bg-slate-950/60 p-3 rounded border border-slate-800/60">
            <span className="text-slate-500 block text-[11px] font-sans">Python Version</span>
            <span className="text-slate-200 font-semibold mt-1 block">
              {backendStatus.pythonVersion ? `Python ${backendStatus.pythonVersion}` : "Local Environment"}
            </span>
          </div>

          <div className="bg-slate-950/60 p-3 rounded border border-slate-800/60">
            <span className="text-slate-500 block text-[11px] font-sans">Threat Parser Architecture</span>
            <span className="text-slate-200 mt-1 block font-sans">
              Tripartite Pipeline: Protocols · Flows · Metadata
            </span>
          </div>

          <div className="bg-slate-950/60 p-3 rounded border border-slate-800/60">
            <span className="text-slate-500 block text-[11px] font-sans">Dissection Engine</span>
            <span className="text-slate-200 mt-1 block font-sans">
              Native Libpcap Binary Parser (Zero external C-bindings)
            </span>
          </div>
        </div>
      </div>

      {/* Operational Mode Toggle */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-200">
              Demo Mode / Production Mode Adapter
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              When Demo Mode is enabled, the UI loads authentic static fixtures produced by the Python analyzer and explicitly marks all outputs with "DEMO DATA".
            </p>
          </div>

          <button
            onClick={onToggleDemoMode}
            className={`px-3.5 py-1.5 rounded text-xs font-semibold transition cursor-pointer ${
              isDemoMode
                ? "bg-amber-950 border border-amber-800 text-amber-300"
                : "bg-cyan-600 text-white"
            }`}
          >
            {isDemoMode ? "Demo Mode Active" : "Live Backend Active"}
          </button>
        </div>
      </div>

      {/* Profile Threshold Reference */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 space-y-4">
        <div className="flex items-center space-x-2.5 border-b border-slate-800 pb-3">
          <Shield className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-200">
            Environment Detection Profiles
          </h3>
        </div>

        <div className="space-y-3 text-xs">
          <div
            onClick={() => onChangeProfile("default")}
            className={`p-3.5 rounded border transition cursor-pointer ${
              currentProfile === "default"
                ? "bg-cyan-950/40 border-cyan-800"
                : "bg-slate-900/40 border-slate-800 hover:border-slate-700"
            }`}
          >
            <div className="flex items-center justify-between font-semibold text-slate-200 mb-1">
              <span>default (Standard SOC Baseline)</span>
              {currentProfile === "default" && <span className="text-cyan-400 text-[11px]">ACTIVE</span>}
            </div>
            <p className="text-slate-400">
              Balanced sensitivity suitable for general network triage. Flags TCP SYN bursts with &ge;20 packets, unestablished handshake ratios &le;20%, and DNS query volumes &ge;80.
            </p>
          </div>

          <div
            onClick={() => onChangeProfile("home_lab")}
            className={`p-3.5 rounded border transition cursor-pointer ${
              currentProfile === "home_lab"
                ? "bg-cyan-950/40 border-cyan-800"
                : "bg-slate-900/40 border-slate-800 hover:border-slate-700"
            }`}
          >
            <div className="flex items-center justify-between font-semibold text-slate-200 mb-1">
              <span>home_lab (Low-Traffic Lab Sensitivity)</span>
              {currentProfile === "home_lab" && <span className="text-cyan-400 text-[11px]">ACTIVE</span>}
            </div>
            <p className="text-slate-400">
              Tuned for low-traffic homelabs, IoT testbeds, and isolated audit ranges. Lowers thresholds to capture low-and-slow port scans and single anomalous connection attempts.
            </p>
          </div>

          <div
            onClick={() => onChangeProfile("enterprise")}
            className={`p-3.5 rounded border transition cursor-pointer ${
              currentProfile === "enterprise"
                ? "bg-cyan-950/40 border-cyan-800"
                : "bg-slate-900/40 border-slate-800 hover:border-slate-700"
            }`}
          >
            <div className="flex items-center justify-between font-semibold text-slate-200 mb-1">
              <span>enterprise (High-Noise Tolerance)</span>
              {currentProfile === "enterprise" && <span className="text-cyan-400 text-[11px]">ACTIVE</span>}
            </div>
            <p className="text-slate-400">
              Configured for production corporate core networks with constant background monitoring, load balancer health checks, and CDNs. Suppresses transient handshake anomalies.
            </p>
          </div>

          <div
            onClick={() => onChangeProfile("high_volume")}
            className={`p-3.5 rounded border transition cursor-pointer ${
              currentProfile === "high_volume"
                ? "bg-cyan-950/40 border-cyan-800"
                : "bg-slate-900/40 border-slate-800 hover:border-slate-700"
            }`}
          >
            <div className="flex items-center justify-between font-semibold text-slate-200 mb-1">
              <span>high_volume (Gigabit Aggregation)</span>
              {currentProfile === "high_volume" && <span className="text-cyan-400 text-[11px]">ACTIVE</span>}
            </div>
            <p className="text-slate-400">
              Aggressive sampling for captures exceeding 100k packets. Requires sustained anomaly duration and high confidence thresholds before generating alert findings.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
