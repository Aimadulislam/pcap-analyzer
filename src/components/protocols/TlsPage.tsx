import React, { useState, useMemo } from "react";
import { Lock, Search, ShieldCheck } from "lucide-react";
import { TLSRecord, TLSContainer } from "../../types/analyzer";

interface TlsPageProps {
  tlsData: TLSContainer | TLSRecord[];
}

export const TlsPage: React.FC<TlsPageProps> = ({ tlsData }) => {
  const [searchQuery, setSearchQuery] = useState("");

  const records: TLSRecord[] = useMemo(() => {
    if (!tlsData) return [];
    if (Array.isArray(tlsData)) return tlsData;
    return tlsData.records || [];
  }, [tlsData]);

  const filteredRecords = useMemo(() => {
    return records.filter((r) => {
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const sni = (r.sni || r.server_name || "").toLowerCase();
        const ver = (r.version || "").toLowerCase();
        const src = (r.source_ip || "").toLowerCase();
        const dst = (r.destination_ip || "").toLowerCase();
        if (!sni.includes(q) && !ver.includes(q) && !src.includes(q) && !dst.includes(q)) {
          return false;
        }
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
            TLS Encrypted Traffic Analysis
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Server Name Indication (SNI) metadata, protocol versions, and handshake type classification.
          </p>
        </div>
      </div>

      {/* Search Bar */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 flex items-center justify-between">
        <span className="text-xs text-slate-400 font-mono">
          {records.length} TLS handshake records dissected
        </span>

        <div className="relative w-full md:w-64">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search SNI, version, IP..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* TLS Table */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-medium bg-slate-900/60">
                <th className="py-2.5 px-4 font-normal">Pkt #</th>
                <th className="py-2.5 px-3 font-normal">Version</th>
                <th className="py-2.5 px-3 font-normal">Handshake</th>
                <th className="py-2.5 px-4 font-normal">Server Name Indication (SNI)</th>
                <th className="py-2.5 px-3 font-normal">Client IP</th>
                <th className="py-2.5 px-3 font-normal">Destination IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
              {filteredRecords.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-slate-500 font-sans">
                    {records.length === 0
                      ? "Zero TLS handshake records identified in this PCAP."
                      : "No TLS records matched your search."}
                  </td>
                </tr>
              ) : (
                filteredRecords.map((rec, i) => {
                  const sni = rec.sni || rec.server_name;
                  return (
                    <tr key={`${rec.packet_number}-${i}`} className="hover:bg-slate-800/30">
                      <td className="py-2.5 px-4 text-slate-500 tabular-nums">
                        #{rec.packet_number}
                      </td>

                      <td className="py-2.5 px-3">
                        <span className="text-[11px] px-1.5 py-0.5 rounded bg-purple-950/60 text-purple-300 border border-purple-800/60 font-medium">
                          {rec.version || "TLS"}
                        </span>
                      </td>

                      <td className="py-2.5 px-3 text-slate-400">
                        {rec.handshake_type || "ClientHello"}
                      </td>

                      <td className="py-2.5 px-4">
                        {sni ? (
                          <span className="text-cyan-400 font-medium select-all">{sni}</span>
                        ) : (
                          <span className="text-slate-600 italic">No SNI extension present</span>
                        )}
                      </td>

                      <td className="py-2.5 px-3 text-slate-400 select-all">
                        {rec.source_ip}
                      </td>

                      <td className="py-2.5 px-3 text-slate-400 select-all">
                        {rec.destination_ip}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
