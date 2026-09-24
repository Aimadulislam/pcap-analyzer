import React, { useState, useMemo } from "react";
import {
  Fingerprint,
  Search,
  Copy,
  Check,
  Download,
  ExternalLink,
  Shield,
  Layers,
} from "lucide-react";
import { CategorizedIOCs, IOCRecord } from "../../types/analyzer";
import { formatTimestamp } from "../../utils/formatters";

interface IocsPageProps {
  iocs?: CategorizedIOCs;
}

export const IocsPage: React.FC<IocsPageProps> = ({ iocs = {} }) => {
  const [activeCategory, setActiveCategory] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [copiedValue, setCopiedValue] = useState<string | null>(null);

  // Flatten and categorize
  const allRecords = useMemo(() => {
    const list: IOCRecord[] = [];
    if (!iocs) return list;

    for (const [cat, records] of Object.entries(iocs)) {
      if (Array.isArray(records)) {
        for (const r of records) {
          list.push(r);
        }
      }
    }
    return list;
  }, [iocs]);

  const categories = useMemo(() => {
    const cats = ["ALL"];
    if (!iocs) return cats;
    for (const k of Object.keys(iocs)) {
      if (iocs[k]?.length) cats.push(k);
    }
    return cats;
  }, [iocs]);

  const filteredRecords = useMemo(() => {
    return allRecords.filter((rec) => {
      // Category filter
      if (activeCategory !== "ALL") {
        const catKey = rec.type.toLowerCase();
        if (activeCategory === "ips" && !catKey.includes("ip")) return false;
        if (activeCategory === "domains" && catKey !== "domain") return false;
        if (activeCategory === "urls" && catKey !== "url") return false;
        if (activeCategory === "hostnames" && catKey !== "hostname") return false;
        if (activeCategory === "emails" && catKey !== "email") return false;
        if (activeCategory === "hashes" && catKey !== "hash") return false;
      }

      // Search filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const match =
          rec.value.toLowerCase().includes(q) ||
          rec.source.toLowerCase().includes(q) ||
          rec.type.toLowerCase().includes(q);
        if (!match) return false;
      }
      return true;
    });
  }, [allRecords, activeCategory, searchQuery]);

  const handleCopy = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedValue(val);
    setTimeout(() => setCopiedValue(null), 2000);
  };

  const handleExportIocsJson = () => {
    const jsonStr = JSON.stringify(iocs, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `iocs_manifest_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold text-slate-100 tracking-tight">
            Indicators of Compromise (IOC) Explorer
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Observable indicators extracted and deduplicated from packet headers, DNS resolutions, HTTP requests, and payload content.
          </p>
        </div>

        <button
          onClick={handleExportIocsJson}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-slate-100 rounded text-xs transition cursor-pointer self-start sm:self-auto"
        >
          <Download className="w-3.5 h-3.5 text-cyan-400" />
          <span>Export iocs.json</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row gap-3 items-center justify-between">
        {/* Category Tabs */}
        <div className="flex items-center space-x-1 overflow-x-auto w-full md:w-auto">
          {["ALL", "ips", "domains", "urls", "hostnames"].map((cat) => {
            const count =
              cat === "ALL"
                ? allRecords.length
                : cat === "ips"
                ? allRecords.filter((r) => r.type.toLowerCase().includes("ip")).length
                : allRecords.filter((r) => r.type.toLowerCase() === cat.slice(0, -1) || r.type.toLowerCase() === cat).length;

            const isActive = activeCategory === cat;
            return (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                className={`px-3 py-1.5 rounded text-xs font-medium uppercase tracking-wider transition cursor-pointer whitespace-nowrap ${
                  isActive
                    ? "bg-cyan-600 text-white"
                    : "bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800"
                }`}
              >
                <span>{cat}</span>
                <span className="ml-1.5 font-mono text-[10px] tabular-nums opacity-80">
                  ({count})
                </span>
              </button>
            );
          })}
        </div>

        {/* Search */}
        <div className="relative w-full md:w-64">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search indicator, source..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* IOCs Table */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-medium bg-slate-900/60">
                <th className="py-2.5 px-4 font-normal">Observable Value</th>
                <th className="py-2.5 px-3 font-normal">Type</th>
                <th className="py-2.5 px-4 font-normal">Observation Source</th>
                <th className="py-2.5 px-3 font-normal text-right">Packets</th>
                <th className="py-2.5 px-3 font-normal">First Seen</th>
                <th className="py-2.5 px-4 font-normal text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
              {filteredRecords.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-slate-500 font-sans">
                    Zero Indicators of Compromise extracted for the current view.
                  </td>
                </tr>
              ) : (
                filteredRecords.map((rec, i) => (
                  <tr key={`${rec.type}-${rec.value}-${i}`} className="hover:bg-slate-800/30">
                    <td className="py-2.5 px-4">
                      <span className="text-cyan-400 font-medium select-all font-mono">
                        {rec.value}
                      </span>
                    </td>

                    <td className="py-2.5 px-3">
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300 uppercase">
                        {rec.type}
                      </span>
                    </td>

                    <td className="py-2.5 px-4 text-slate-400 font-sans">
                      {rec.source}
                    </td>

                    <td className="py-2.5 px-3 text-right text-slate-200 tabular-nums">
                      {rec.packet_count}
                    </td>

                    <td className="py-2.5 px-3 text-slate-400 tabular-nums">
                      {rec.first_seen > 0 ? `${rec.first_seen.toFixed(2)}s` : "0.00s"}
                    </td>

                    <td className="py-2.5 px-4 text-right">
                      <button
                        onClick={() => handleCopy(rec.value)}
                        className="p-1 hover:bg-slate-800 rounded text-slate-400 hover:text-slate-200 cursor-pointer"
                        title="Copy indicator value"
                      >
                        {copiedValue === rec.value ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="p-3 border-t border-slate-800/80 bg-slate-900/40 text-xs text-slate-500 flex items-center justify-between">
          <span>
            Total unique IOCs: <strong className="text-slate-300 font-mono">{allRecords.length}</strong>
          </span>
          <span className="font-mono">
            Deterministic correlation without arbitrary malware labels
          </span>
        </div>
      </div>
    </div>
  );
};
