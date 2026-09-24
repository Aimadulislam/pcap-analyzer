import React, { useState } from "react";
import {
  FileText,
  Copy,
  Check,
  Download,
  Terminal,
  FileCode,
  ShieldAlert,
} from "lucide-react";
import { AnalysisResult } from "../../types/analyzer";

interface ReportsPageProps {
  analysis: AnalysisResult;
}

export const ReportsPage: React.FC<ReportsPageProps> = ({ analysis }) => {
  const [copied, setCopied] = useState(false);
  const reportText = analysis.reportText || "";

  const handleCopyReport = () => {
    navigator.clipboard.writeText(reportText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadTxt = () => {
    const filename = `${analysis.metadata.file_name || "pcap"}_investigation_report.txt`;
    const blob = new Blob([reportText], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadJson = () => {
    const filename = `${analysis.metadata.file_name || "pcap"}_analysis.json`;
    const blob = new Blob([JSON.stringify(analysis, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold text-slate-100 tracking-tight">
            Technical Investigation Report
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Complete 12-section technical incident investigation document generated directly by the Python forensic analysis engine.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleCopyReport}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-slate-100 rounded text-xs transition cursor-pointer"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5 text-cyan-400" />
                <span>Copy Text</span>
              </>
            )}
          </button>

          <button
            onClick={handleDownloadTxt}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-slate-100 rounded text-xs transition cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Download .txt</span>
          </button>

          <button
            onClick={handleDownloadJson}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-cyan-950/80 border border-cyan-800/80 hover:bg-cyan-900 text-cyan-300 rounded text-xs transition cursor-pointer"
          >
            <FileCode className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export Full JSON</span>
          </button>
        </div>
      </div>

      {/* Report Viewer Container */}
      <div className="bg-[#0B0F19] border border-slate-800 rounded-lg p-5 font-mono text-xs text-slate-300 overflow-x-auto shadow-inner leading-relaxed">
        {reportText ? (
          <pre className="whitespace-pre select-text font-mono text-[12px]">{reportText}</pre>
        ) : (
          <div className="py-12 text-center text-slate-500 font-sans">
            Report text unavailable for this analysis session.
          </div>
        )}
      </div>
    </div>
  );
};
