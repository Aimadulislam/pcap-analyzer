import React, { useState, useMemo } from "react";
import { FileCode, Search, AlertTriangle, ArrowRight, Lock } from "lucide-react";
import { HTTPRecord, HTTPContainer } from "../../types/analyzer";

interface HttpPageProps {
  httpData: HTTPContainer | HTTPRecord[];
}

export const HttpPage: React.FC<HttpPageProps> = ({ httpData }) => {
  const [searchQuery, setSearchQuery] = useState("");

  const records: HTTPRecord[] = useMemo(() => {
    if (!httpData) return [];
    if (Array.isArray(httpData)) return httpData;
    return httpData.records || [];
  }, [httpData]);

  const filteredRecords = useMemo(() => {
    return records.filter((r) => {
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const match =
          (r.host && r.host.toLowerCase().includes(q)) ||
          (r.uri && r.uri.toLowerCase().includes(q)) ||
          (r.method && r.method.toLowerCase().includes(q)) ||
          (r.source_ip && r.source_ip.includes(q)) ||
          (r.destination_ip && r.destination_ip.includes(q));
        if (!match) return false;
      }
      return true;
    });
  }, [records, searchQuery]);

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold text-slate-100 tracking-tight">
            HTTP Protocol Analysis
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Inspection of unencrypted web transactions, request methods, host headers, and endpoints.
          </p>
        </div>
      </div>

      {/* Security Notice for Cleartext */}
      {records.length > 0 && (
        <div className="bg-amber-950/30 border border-amber-800/50 rounded-lg p-4 flex items-start space-x-3 text-xs">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div className="text-amber-200">
            <strong className="font-semibold text-amber-300">Cleartext Protocol Risk:</strong> Identified unencrypted HTTP traffic. Plaintext HTTP headers, cookies, and parameters can be intercepted or manipulated in transit.
          </div>
        </div>
      )}

      {/* Search Bar */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 flex items-center justify-between">
        <span className="text-xs text-slate-400 font-mono">
          {records.length} transactions dissected
        </span>

        <div className="relative w-full md:w-64">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search Host, URI, or IP..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* HTTP Records Table */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-medium bg-slate-900/60">
                <th className="py-2.5 px-4 font-normal">Pkt #</th>
                <th className="py-2.5 px-3 font-normal">Method</th>
                <th className="py-2.5 px-4 font-normal">Host Header</th>
                <th className="py-2.5 px-4 font-normal">Request URI</th>
                <th className="py-2.5 px-3 font-normal">Client IP</th>
                <th className="py-2.5 px-3 font-normal">Server IP</th>
                <th className="py-2.5 px-3 font-normal text-right">Status Code</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
              {filteredRecords.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-10 text-center text-slate-500 font-sans">
                    {records.length === 0
                      ? "Zero unencrypted HTTP records identified in this PCAP."
                      : "No HTTP transactions matched your search."}
                  </td>
                </tr>
              ) : (
                filteredRecords.map((rec, i) => (
                  <tr key={`${rec.packet_number}-${i}`} className="hover:bg-slate-800/30">
                    <td className="py-2.5 px-4 text-slate-500 tabular-nums">
                      #{rec.packet_number}
                    </td>

                    <td className="py-2.5 px-3">
                      <span className="text-[11px] font-bold px-1.5 py-0.5 rounded bg-amber-950/60 text-amber-300 border border-amber-800/60">
                        {rec.method || "GET"}
                      </span>
                    </td>

                    <td className="py-2.5 px-4 text-cyan-400 font-medium select-all">
                      {rec.host || "N/A"}
                    </td>

                    <td className="py-2.5 px-4 text-slate-200 select-all truncate max-w-xs">
                      {rec.uri || "/"}
                    </td>

                    <td className="py-2.5 px-3 text-slate-400 select-all">
                      {rec.source_ip}
                    </td>

                    <td className="py-2.5 px-3 text-slate-400 select-all">
                      {rec.destination_ip}
                    </td>

                    <td className="py-2.5 px-3 text-right">
                      {rec.status_code ? (
                        <span className="text-emerald-400">{rec.status_code}</span>
                      ) : (
                        <span className="text-slate-600">-</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
