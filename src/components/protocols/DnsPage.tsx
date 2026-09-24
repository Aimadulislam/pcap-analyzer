import React, { useState, useMemo } from "react";
import { Globe, Search, ShieldAlert, AlertTriangle, ArrowRight, ExternalLink } from "lucide-react";
import { DNSRecord, DNSContainer } from "../../types/analyzer";
import { calculateShannonEntropy } from "../../utils/formatters";

interface DnsPageProps {
  dnsData: DNSContainer | DNSRecord[];
}

export const DnsPage: React.FC<DnsPageProps> = ({ dnsData }) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [entropyFilter, setEntropyFilter] = useState<"ALL" | "HIGH">("ALL");

  const records: DNSRecord[] = useMemo(() => {
    if (!dnsData) return [];
    if (Array.isArray(dnsData)) return dnsData;
    return dnsData.records || [];
  }, [dnsData]);

  const processedRecords = useMemo(() => {
    return records.map((r) => {
      const q = r.query || "";
      const prefix = q.split(".")[0] || "";
      const ent = calculateShannonEntropy(prefix);
      return {
        ...r,
        computedEntropy: ent,
        isSuspicious: ent >= 3.5 && prefix.length >= 12,
      };
    });
  }, [records]);

  const filteredRecords = useMemo(() => {
    return processedRecords.filter((r) => {
      if (entropyFilter === "HIGH" && !r.isSuspicious) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const match =
          (r.query && r.query.toLowerCase().includes(q)) ||
          (r.source_ip && r.source_ip.includes(q)) ||
          (r.query_type && r.query_type.toLowerCase().includes(q));
        if (!match) return false;
      }
      return true;
    });
  }, [processedRecords, entropyFilter, searchQuery]);

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold text-slate-100 tracking-tight">
            DNS Protocol Analysis
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Domain query inspections, Shannon subdomain entropy evaluation, and recursive resolution telemetry.
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row gap-3 items-center justify-between">
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setEntropyFilter("ALL")}
            className={`px-3 py-1.5 rounded text-xs font-medium cursor-pointer ${
              entropyFilter === "ALL"
                ? "bg-cyan-600 text-white"
                : "bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200"
            }`}
          >
            All Queries ({records.length})
          </button>
          <button
            onClick={() => setEntropyFilter("HIGH")}
            className={`px-3 py-1.5 rounded text-xs font-medium cursor-pointer ${
              entropyFilter === "HIGH"
                ? "bg-rose-950 text-rose-300 border border-rose-800"
                : "bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200"
            }`}
          >
            High Entropy / Potential Exfiltration ({processedRecords.filter((r) => r.isSuspicious).length})
          </button>
        </div>

        {/* Search */}
        <div className="relative w-full md:w-64">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search domain, client IP..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* DNS Records Table */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-medium bg-slate-900/60">
                <th className="py-2.5 px-4 font-normal">Pkt #</th>
                <th className="py-2.5 px-3 font-normal">Client IP</th>
                <th className="py-2.5 px-4 font-normal">Query Domain</th>
                <th className="py-2.5 px-2 font-normal text-center">Type</th>
                <th className="py-2.5 px-3 font-normal text-right">Entropy</th>
                <th className="py-2.5 px-4 font-normal">Answers / Resolved IPs</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
              {filteredRecords.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-slate-500 font-sans">
                    {records.length === 0
                      ? "Zero DNS protocol records identified in this PCAP."
                      : "No DNS queries matched your filter."}
                  </td>
                </tr>
              ) : (
                filteredRecords.map((rec, i) => (
                  <tr key={`${rec.packet_number}-${i}`} className="hover:bg-slate-800/30">
                    <td className="py-2.5 px-4 text-slate-500 tabular-nums">
                      #{rec.packet_number}
                    </td>

                    <td className="py-2.5 px-3 text-cyan-400 select-all">
                      {rec.source_ip || "N/A"}
                    </td>

                    <td className="py-2.5 px-4">
                      <div className="flex items-center space-x-2">
                        <span className={`select-all ${rec.isSuspicious ? "text-rose-300 font-semibold" : "text-slate-200"}`}>
                          {rec.query}
                        </span>
                        {rec.isSuspicious && (
                          <span className="text-[10px] bg-rose-950/80 text-rose-400 border border-rose-800/80 px-1.5 py-0.2 rounded font-sans shrink-0">
                            High Entropy
                          </span>
                        )}
                      </div>
                    </td>

                    <td className="py-2.5 px-2 text-center">
                      <span className="text-[11px] px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                        {rec.query_type || "A"}
                      </span>
                    </td>

                    <td className="py-2.5 px-3 text-right">
                      <span
                        className={`tabular-nums ${
                          rec.computedEntropy >= 3.5
                            ? "text-rose-400 font-bold"
                            : rec.computedEntropy >= 3.0
                            ? "text-amber-400"
                            : "text-slate-400"
                        }`}
                      >
                        {rec.computedEntropy.toFixed(2)}
                      </span>
                    </td>

                    <td className="py-2.5 px-4 text-slate-400 truncate max-w-xs">
                      {rec.answers && rec.answers.length > 0 ? (
                        rec.answers.join(", ")
                      ) : (
                        <span className="text-slate-600 italic">No answers / Query only</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="p-3 border-t border-slate-800/80 bg-slate-900/40 text-xs text-slate-500 flex items-center justify-between">
          <span>
            Total observed queries: <strong className="text-slate-300 font-mono">{records.length}</strong>
          </span>
          <span className="font-mono">
            {processedRecords.filter((r) => r.isSuspicious).length} queries with elevated entropy (&gt; 3.5)
          </span>
        </div>
      </div>
    </div>
  );
};
