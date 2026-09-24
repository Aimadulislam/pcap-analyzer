import React, { useState, useRef } from "react";
import {
  UploadCloud,
  FileCheck,
  AlertTriangle,
  Play,
  Layers,
  Cpu,
  Shield,
  FileText,
  CheckCircle2,
  RefreshCw,
  FolderOpen,
} from "lucide-react";
import { AnalysisProfile, DissectionEngine, SamplePcapInfo } from "../../types/analyzer";
import { SAMPLE_PCAP_LIST } from "../../data/demoFixtures";

interface PcapAnalysisPageProps {
  onAnalyzeSample: (sampleId: string, profile: AnalysisProfile, engine: DissectionEngine) => Promise<void>;
  onAnalyzeUpload: (file: File, profile: AnalysisProfile, engine: DissectionEngine) => Promise<void>;
  currentProfile: AnalysisProfile;
  onChangeProfile: (profile: AnalysisProfile) => void;
  currentEngine: DissectionEngine;
  onChangeEngine: (engine: DissectionEngine) => void;
  isAnalyzing: boolean;
}

export const PcapAnalysisPage: React.FC<PcapAnalysisPageProps> = ({
  onAnalyzeSample,
  onAnalyzeUpload,
  currentProfile,
  onChangeProfile,
  currentEngine,
  onChangeEngine,
  isAnalyzing,
}) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [selectedSampleId, setSelectedSampleId] = useState<string>("syn_port_scan");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const validateAndSetFile = (file: File) => {
    setErrorMessage(null);

    // Validate extension
    const name = file.name.toLowerCase();
    if (!name.endsWith(".pcap") && !name.endsWith(".pcapng")) {
      setErrorMessage("Unsupported file type. Only .pcap and .pcapng files are supported.");
      setSelectedFile(null);
      return;
    }

    // Validate size (max 50MB)
    const maxSize = 50 * 1024 * 1024;
    if (file.size > maxSize) {
      setErrorMessage("File exceeds 50MB maximum upload limit.");
      setSelectedFile(null);
      return;
    }

    if (file.size === 0) {
      setErrorMessage("Selected file is empty (0 bytes).");
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const handleStartUploadAnalysis = async () => {
    if (!selectedFile) return;
    try {
      setErrorMessage(null);
      await onAnalyzeUpload(selectedFile, currentProfile, currentEngine);
    } catch (err: any) {
      setErrorMessage(err.message || "Analysis execution failed.");
    }
  };

  const handleStartSampleAnalysis = async (sampleId: string) => {
    try {
      setErrorMessage(null);
      setSelectedSampleId(sampleId);
      await onAnalyzeSample(sampleId, currentProfile, currentEngine);
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to analyze sample capture.");
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Page Title */}
      <div>
        <h2 className="text-xl font-semibold text-slate-100 tracking-tight">
          Analyze PCAP
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Upload local network packet captures (.pcap or .pcapng) or execute target forensic scenarios through the Python dissection engine.
        </p>
      </div>

      {/* Analysis Configuration Controls */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
          Analysis Configuration
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Profile Selection */}
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              Detection Environment Profile
            </label>
            <select
              value={currentProfile}
              onChange={(e) => onChangeProfile(e.target.value as AnalysisProfile)}
              disabled={isAnalyzing}
              className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="default">Default · Balanced SOC Heuristics</option>
              <option value="home_lab">Home Lab · Lower traffic &amp; broadcast sensitivity</option>
              <option value="enterprise">Enterprise · High-volume tolerance &amp; strict thresholds</option>
              <option value="high_volume">High Volume · Aggressive aggregation</option>
            </select>
            <p className="text-[11px] text-slate-500 mt-1">
              Controls SYN flood thresholds, DNS volume tolerance, and unusual port heuristics.
            </p>
          </div>

          {/* Engine Selection */}
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              Packet Dissection Engine
            </label>
            <select
              value={currentEngine}
              onChange={(e) => onChangeEngine(e.target.value as DissectionEngine)}
              disabled={isAnalyzing}
              className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="auto">Auto · Fast native engine with Scapy fallback</option>
              <option value="native">Native · High-performance binary frame parser (recommended)</option>
              <option value="scapy">Scapy · Full packet object model</option>
            </select>
            <p className="text-[11px] text-slate-500 mt-1">
              Native binary dissection processes ~100k packets/sec with zero external dependencies.
            </p>
          </div>
        </div>
      </div>

      {/* Upload Area */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
          Capture File Ingestion
        </h3>

        {/* Dropzone */}
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragOver(true);
          }}
          onDragLeave={() => setIsDragOver(false)}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-lg p-8 flex flex-col items-center justify-center text-center transition-colors cursor-pointer ${
            isDragOver
              ? "border-cyan-500 bg-cyan-950/20"
              : selectedFile
              ? "border-cyan-800 bg-slate-900/60"
              : "border-slate-800 hover:border-slate-700 bg-slate-950/40"
          }`}
          onClick={() => fileInputRef.current?.click()}
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            accept=".pcap,.pcapng"
            className="hidden"
          />

          <div className="w-12 h-12 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center mb-3 text-cyan-400">
            <UploadCloud className="w-6 h-6" />
          </div>

          <div className="text-sm font-medium text-slate-200">
            {selectedFile ? (
              <span className="text-cyan-400 font-mono">{selectedFile.name}</span>
            ) : (
              "Drop PCAP / PCAPNG file here or Browse files"
            )}
          </div>

          <div className="text-xs text-slate-500 mt-1">
            {selectedFile
              ? `${(selectedFile.size / 1024).toFixed(1)} KB · Ready to analyze`
              : "Accepted formats: .pcap, .pcapng · Maximum file size: 50 MB"}
          </div>

          <div className="text-[11px] text-slate-500 mt-3 flex items-center space-x-1.5">
            <Shield className="w-3.5 h-3.5 text-cyan-500" />
            <span>PCAP analysis is performed locally by the analysis backend.</span>
          </div>
        </div>

        {/* Error Alert */}
        {errorMessage && (
          <div className="mt-3 flex items-center space-x-2 text-xs text-rose-400 bg-rose-950/40 border border-rose-800/80 p-3 rounded">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Actions */}
        {selectedFile && (
          <div className="mt-4 flex items-center justify-between">
            <div className="text-xs text-slate-400">
              Selected: <strong className="text-slate-200 font-mono">{selectedFile.name}</strong>
            </div>
            <button
              onClick={handleStartUploadAnalysis}
              disabled={isAnalyzing}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-semibold flex items-center space-x-2 transition disabled:opacity-50 cursor-pointer shadow-sm shadow-cyan-950"
            >
              {isAnalyzing ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Dissecting PCAP...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5" />
                  <span>Start Analysis</span>
                </>
              )}
            </button>
          </div>
        )}
      </div>

      {/* Pre-loaded Forensics Lab Scenarios */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Forensic Lab Scenario PCAPs
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Execute live analysis on authentic test captures stored in the environment.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
          {SAMPLE_PCAP_LIST.map((sample) => (
            <div
              key={sample.id}
              className="bg-slate-900/70 border border-slate-800 hover:border-slate-700 rounded-lg p-4 flex flex-col justify-between transition"
            >
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-semibold text-xs text-slate-200">
                    {sample.title}
                  </span>
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-medium ${
                      sample.severityLevel === "HIGH"
                        ? "text-rose-400 bg-rose-950/80 border border-rose-800/80"
                        : sample.severityLevel === "LOW"
                        ? "text-cyan-400 bg-cyan-950/80 border border-cyan-800/80"
                        : "text-slate-400 bg-slate-800/60 border border-slate-700/60"
                    }`}
                  >
                    {sample.severityLevel}
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 mb-2">
                  {sample.description}
                </div>
                <div className="text-[11px] font-mono text-slate-500">
                  Target: {sample.fileName} · Expected: {sample.expectedFindings} finding(s)
                </div>
              </div>

              <div className="mt-3 pt-3 border-t border-slate-800/70 flex items-center justify-between">
                <span className="text-[11px] text-slate-500">{sample.threatCategory}</span>
                <button
                  onClick={() => handleStartSampleAnalysis(sample.id)}
                  disabled={isAnalyzing}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded text-xs font-medium flex items-center space-x-1.5 transition disabled:opacity-50 cursor-pointer"
                >
                  <Play className="w-3 h-3 text-cyan-400" />
                  <span>Execute Analysis</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
