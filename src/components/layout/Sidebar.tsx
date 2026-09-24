import React from "react";
import {
  LayoutDashboard,
  UploadCloud,
  ShieldAlert,
  Network,
  Globe,
  FileCode,
  Lock,
  Fingerprint,
  FileText,
  Sliders,
  Menu,
  X,
  Compass,
  BookOpen,
} from "lucide-react";

export type NavTab =
  | "landing"
  | "overview"
  | "pcap"
  | "findings"
  | "network"
  | "dns"
  | "http"
  | "tls"
  | "iocs"
  | "reports"
  | "docs"
  | "settings";

interface SidebarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  findingsCount: number;
  flowsCount: number;
  mobileOpen: boolean;
  onToggleMobile: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  findingsCount,
  flowsCount,
  mobileOpen,
  onToggleMobile,
}) => {
  const navItems = [
    {
      id: "landing" as NavTab,
      label: "Project Landing",
      icon: Compass,
      badge: null,
    },
    {
      id: "overview" as NavTab,
      label: "Overview",
      icon: LayoutDashboard,
      badge: null,
    },
    {
      id: "pcap" as NavTab,
      label: "PCAP Analysis",
      icon: UploadCloud,
      badge: null,
    },
    {
      id: "findings" as NavTab,
      label: "Findings",
      icon: ShieldAlert,
      badge: findingsCount > 0 ? findingsCount : null,
      badgeColor: findingsCount > 0 ? "text-rose-400 bg-rose-950/80 border border-rose-800/80" : "",
    },
    {
      id: "network" as NavTab,
      label: "Network Flows",
      icon: Network,
      badge: flowsCount > 0 ? flowsCount : null,
      badgeColor: "text-slate-400 bg-slate-800/60 border border-slate-700/60",
    },
    {
      id: "dns" as NavTab,
      label: "DNS",
      icon: Globe,
      badge: null,
    },
    {
      id: "http" as NavTab,
      label: "HTTP",
      icon: FileCode,
      badge: null,
    },
    {
      id: "tls" as NavTab,
      label: "TLS",
      icon: Lock,
      badge: null,
    },
    {
      id: "iocs" as NavTab,
      label: "IOCs",
      icon: Fingerprint,
      badge: null,
    },
    {
      id: "reports" as NavTab,
      label: "Reports",
      icon: FileText,
      badge: null,
    },
    {
      id: "docs" as NavTab,
      label: "Documentation",
      icon: BookOpen,
      badge: null,
    },
    {
      id: "settings" as NavTab,
      label: "Settings",
      icon: Sliders,
      badge: null,
    },
  ];

  const handleNavClick = (id: NavTab) => {
    onSelectTab(id);
    if (mobileOpen) {
      onToggleMobile();
    }
  };

  return (
    <>
      {/* Mobile Toggle Button */}
      <div className="md:hidden fixed bottom-4 right-4 z-50">
        <button
          onClick={onToggleMobile}
          className="p-3 rounded-full bg-cyan-600 text-white shadow-lg shadow-cyan-950 border border-cyan-400 focus:outline-none"
          aria-label="Toggle navigation menu"
        >
          {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>
      </div>

      {/* Mobile Overlay */}
      {mobileOpen && (
        <div
          onClick={onToggleMobile}
          className="md:hidden fixed inset-0 bg-black/70 backdrop-blur-sm z-40"
        />
      )}

      {/* Sidebar Container */}
      <aside
        className={`fixed md:static inset-y-0 left-0 z-40 w-64 bg-[#0E131F] border-r border-slate-800/80 flex flex-col justify-between shrink-0 transition-transform duration-200 ease-out md:translate-x-0 ${
          mobileOpen ? "translate-x-0 shadow-2xl" : "-translate-x-full"
        }`}
      >
        <div className="p-3 space-y-1">
          <div className="px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            Analyst Modules
          </div>

          <nav className="space-y-0.5">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => handleNavClick(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded text-xs font-medium transition-colors ${
                    isActive
                      ? "bg-cyan-950/70 text-cyan-300 border border-cyan-800/60 shadow-sm"
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent"
                  }`}
                >
                  <div className="flex items-center space-x-2.5 min-w-0">
                    <Icon
                      className={`w-4 h-4 shrink-0 ${
                        isActive ? "text-cyan-400" : "text-slate-500"
                      }`}
                    />
                    <span className="truncate">{item.label}</span>
                  </div>

                  {item.badge !== null && (
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-medium tabular-nums ${item.badgeColor}`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Sidebar Footer Metadata */}
        <div className="p-3 border-t border-slate-800/60 text-[11px] text-slate-500 flex flex-col space-y-1">
          <div className="flex items-center justify-between">
            <span>Engine</span>
            <span className="font-mono text-slate-400">Native Libpcap v2</span>
          </div>
          <div className="flex items-center justify-between">
            <span>SOC Taxonomy</span>
            <span className="text-slate-400">Deterministic</span>
          </div>
        </div>
      </aside>
    </>
  );
};
