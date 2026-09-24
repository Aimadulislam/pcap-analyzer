import React, { useState, useMemo } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Search,
  Filter,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Info,
  CheckCircle2,
  Terminal,
  ArrowRight,
  ExternalLink,
} from "lucide-react";
import { AlertFinding, SeverityLevel } from "../../types/analyzer";
import { getSeverityBadgeClass } from "../../utils/formatters";

interface FindingsPageProps {
  findings: AlertFinding[];
}

export const FindingsPage: React.FC<FindingsPageProps> = ({ findings }) => {
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});

  const toggleExpand = (id: string) => {
    setExpandedFindings((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const expandAll = () => {
    const all: Record<string, boolean> = {};
    for (const f of findings) {
      const id = f.finding_id || f.id || "F-0";
      all[id] = true;
    }
    setExpandedFindings(all);
  };

  const collapseAll = () => {
    setExpandedFindings({});
  };

  // Filtered findings
  const filteredFindings = useMemo(() => {
    return (findings || []).filter((f) => {
      // Severity filter
      if (severityFilter !== "ALL" && f.severity?.toUpperCase() !== severityFilter) {
        return false;
      }
      // Search filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const ruleId = (f.rule_id || f.detection_rule || "").toLowerCase();
        const title = (f.title || "").toLowerCase();
        const desc = (f.description || "").toLowerCase();
        const cat = (f.category || "").toLowerCase();
        const src = (f.source_ip || "").toLowerCase();
        const dst = (f.destination_ip || "").toLowerCase();
        if (
          !ruleId.includes(q) &&
          !title.includes(q) &&
          !desc.includes(q) &&
          !cat.includes(q) &&
          !src.includes(q) &&
          !dst.includes(q)
        ) {
          return false;
        }
      }
      return true;
    });
  }, [findings, severityFilter, searchQuery]);

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold text-slate-100 tracking-tight">
            Security Findings &amp; Detections
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic observations produced by heuristic detection rules evaluated against packet and flow records.
          </p>
        </div>

        <div className="flex items-center space-x-2 text-xs">
          <button
            onClick={expandAll}
            className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:text-slate-100 cursor-pointer"
          >
            Expand All
          </button>
          <button
            onClick={collapseAll}
            className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:text-slate-100 cursor-pointer"
          >
            Collapse All
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row gap-3 items-center justify-between">
        {/* Severity Filter Tabs */}
        <div className="flex items-center space-x-1 w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((sev) => {
            const count =
              sev === "ALL"
                ? findings.length
                : findings.filter((f) => f.severity?.toUpperCase() === sev).length;
            const isActive = severityFilter === sev;
            return (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-3 py-1.5 rounded text-xs font-medium transition cursor-pointer whitespace-nowrap ${
                  isActive
                    ? "bg-cyan-600 text-white shadow-sm"
                    : "bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800"
                }`}
              >
                <span>{sev}</span>
                <span className="ml-1.5 font-mono text-[10px] tabular-nums opacity-80">
                  ({count})
                </span>
              </button>
            );
          })}
        </div>

        {/* Search Box */}
        <div className="relative w-full md:w-64">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search rules, IPs, observables..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Findings List */}
      {filteredFindings.length === 0 ? (
        <div className="bg-[#111827] border border-slate-800 rounded-lg p-12 text-center">
          <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
          <h3 className="text-sm font-semibold text-slate-200">
            0 Security Findings Identified
          </h3>
          <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
            {findings.length === 0
              ? "All packet frames and conversation flows conformed to expected baseline behavior without triggering heuristic anomalies."
              : "No findings matched your current severity or keyword filters."}
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredFindings.map((finding, idx) => {
            const fid = finding.finding_id || finding.id || `f-${idx}`;
            const ruleId = finding.rule_id || finding.detection_rule || "RULE-000";
            const badge = getSeverityBadgeClass(finding.severity);
            const isExpanded = Boolean(expandedFindings[fid]);

            return (
              <div
                key={fid}
                className="bg-[#111827] border border-slate-800 hover:border-slate-700/80 rounded-lg transition overflow-hidden"
              >
                {/* Header row */}
                <div
                  onClick={() => toggleExpand(fid)}
                  className="p-4 flex items-center justify-between cursor-pointer gap-4"
                >
                  <div className="flex items-start space-x-3 min-w-0">
                    <span
                      className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border shrink-0 mt-0.5 ${badge.bg} ${badge.text} ${badge.border}`}
                    >
                      {finding.severity}
                    </span>

                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                        <span className="text-xs font-mono text-cyan-400 font-semibold">
                          {ruleId}
                        </span>
                        <span className="text-slate-600 text-xs" aria-hidden="true">·</span>
                        <span className="text-xs text-slate-400 font-medium">
                          {finding.category}
                        </span>
                        <span className="text-slate-600 text-xs" aria-hidden="true">·</span>
                        <span className="text-xs text-slate-500 font-mono">
                          Confidence: {(finding.confidence * 100).toFixed(0)}%
                        </span>
                      </div>

                      <h4 className="text-sm font-medium text-slate-200 mt-0.5">
                        {finding.title}
                      </h4>
                    </div>
                  </div>

                  <div className="flex items-center space-x-3 shrink-0">
                    {finding.source_ip && (
                      <span className="hidden sm:inline font-mono text-xs text-slate-400 bg-slate-900 px-2 py-1 rounded border border-slate-800">
                        {finding.source_ip}
                      </span>
                    )}
                    <button className="text-slate-400 hover:text-slate-200">
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="px-4 pb-4 pt-1 border-t border-slate-800/80 space-y-3.5 text-xs">
                    {/* Description */}
                    <div>
                      <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-1">
                        Observation Narrative
                      </div>
                      <p className="text-slate-300 leading-relaxed bg-slate-950/60 p-3 rounded border border-slate-800/70">
                        {finding.description}
                      </p>
                    </div>

                    {/* Endpoint Context */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 font-mono text-slate-400">
                      <div className="bg-slate-950/40 p-2 rounded border border-slate-800/50">
                        <span className="text-slate-500 block text-[10px]">Source IP</span>
                        <span className="text-slate-200">{finding.source_ip || "N/A (Multi-host)"}</span>
                      </div>
                      <div className="bg-slate-950/40 p-2 rounded border border-slate-800/50">
                        <span className="text-slate-500 block text-[10px]">Target Endpoint</span>
                        <span className="text-slate-200">
                          {finding.destination_ip || (finding.destination_port ? `Port :${finding.destination_port}` : "Distributed")}
                        </span>
                      </div>
                      <div className="bg-slate-950/40 p-2 rounded border border-slate-800/50">
                        <span className="text-slate-500 block text-[10px]">Protocol</span>
                        <span className="text-slate-200">{finding.protocol || "Transport Agnostic"}</span>
                      </div>
                    </div>

                    {/* Deterministic Evidence Object */}
                    {finding.evidence && Object.keys(finding.evidence).length > 0 && (
                      <div>
                        <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-1">
                          Heuristic Telemetry &amp; Evidence
                        </div>
                        <div className="bg-slate-950 rounded border border-slate-800 p-3 font-mono text-[11px] text-slate-300 overflow-x-auto">
                          <pre>{JSON.stringify(finding.evidence, null, 2)}</pre>
                        </div>
                      </div>
                    )}

                    {/* Recommendations and Next Steps */}
                    {finding.recommended_next_step && (
                      <div className="bg-cyan-950/20 border border-cyan-900/40 p-3 rounded">
                        <div className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider mb-1">
                          Recommended Analyst Triage
                        </div>
                        <p className="text-slate-300 text-xs">
                          {finding.recommended_next_step}
                        </p>
                      </div>
                    )}

                    {/* Limitations */}
                    {finding.limitations && (
                      <div className="text-[11px] text-slate-500 italic">
                        Note: {finding.limitations}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
