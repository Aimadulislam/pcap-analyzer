import React, { useState, useEffect } from "react";
import { TopNav } from "./components/layout/TopNav";
import { Sidebar, NavTab } from "./components/layout/Sidebar";
import { LandingPage } from "./components/landing/LandingPage";
import { PortfolioCaseStudyPage } from "./components/portfolio/PortfolioCaseStudyPage";
import { DocumentationPage } from "./components/docs/DocumentationPage";
import { OverviewDashboard } from "./components/overview/OverviewDashboard";
import { PcapAnalysisPage } from "./components/pcap/PcapAnalysisPage";
import { FindingsPage } from "./components/findings/FindingsPage";
import { NetworkFlowsPage } from "./components/network/NetworkFlowsPage";
import { DnsPage } from "./components/protocols/DnsPage";
import { HttpPage } from "./components/protocols/HttpPage";
import { TlsPage } from "./components/protocols/TlsPage";
import { IocsPage } from "./components/iocs/IocsPage";
import { ReportsPage } from "./components/reports/ReportsPage";
import { SettingsPage } from "./components/settings/SettingsPage";

import {
  AnalysisResult,
  AnalysisProfile,
  DissectionEngine,
  BackendStatus,
} from "./types/analyzer";
import {
  checkBackendStatus,
  analyzeSamplePcap,
  analyzeUploadedPcap,
} from "./services/api";
import { DEMO_FIXTURES } from "./data/demoFixtures";
import { RefreshCw } from "lucide-react";

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>("landing");
  const [docsSection, setDocsSection] = useState<string>("rules");
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Engine & Profile state
  const [profile, setProfile] = useState<AnalysisProfile>("default");
  const [engine, setEngine] = useState<DissectionEngine>("auto");
  const [isDemoMode, setIsDemoMode] = useState<boolean>(false);

  // Analysis session state
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [analysisStatus, setAnalysisStatus] = useState<"idle" | "analyzing" | "completed" | "error">("idle");
  const [backendStatus, setBackendStatus] = useState<BackendStatus>({
    connected: false,
    mode: "demo",
    availableProfiles: ["default", "home_lab", "enterprise", "high_volume"],
    availableEngines: ["native", "scapy", "auto"],
  });

  // Check backend status on mount
  useEffect(() => {
    initApp();
  }, []);

  const initApp = async () => {
    setAnalysisStatus("analyzing");
    const status = await checkBackendStatus();
    setBackendStatus(status);

    if (!status.connected) {
      setIsDemoMode(true);
    }

    try {
      // Pre-load default forensic sample (SYN port scan)
      const res = await analyzeSamplePcap("syn_port_scan", "default", "auto");
      setAnalysis(res.result);
      setAnalysisStatus("completed");
    } catch (e) {
      // Fallback to static demo fixture
      setAnalysis(DEMO_FIXTURES.syn_port_scan);
      setAnalysisStatus("completed");
    }
  };

  const handleRefreshBackend = async () => {
    const status = await checkBackendStatus();
    setBackendStatus(status);
  };

  const handleAnalyzeSample = async (
    sampleId: string,
    chosenProfile: AnalysisProfile,
    chosenEngine: DissectionEngine
  ) => {
    setAnalysisStatus("analyzing");
    try {
      const res = await analyzeSamplePcap(sampleId, chosenProfile, chosenEngine);
      setAnalysis(res.result);
      setAnalysisStatus("completed");
      setActiveTab("overview");
    } catch (err) {
      console.error("Failed to analyze sample:", err);
      setAnalysisStatus("error");
      throw err;
    }
  };

  const handleAnalyzeUpload = async (
    file: File,
    chosenProfile: AnalysisProfile,
    chosenEngine: DissectionEngine
  ) => {
    setAnalysisStatus("analyzing");
    try {
      const res = await analyzeUploadedPcap(file, chosenProfile, chosenEngine);
      setAnalysis(res.result);
      setAnalysisStatus("completed");
      setActiveTab("overview");
    } catch (err) {
      console.error("Failed to analyze uploaded PCAP:", err);
      setAnalysisStatus("error");
      throw err;
    }
  };

  const handleToggleDemoMode = () => {
    if (isDemoMode) {
      setIsDemoMode(false);
      handleRefreshBackend();
    } else {
      setIsDemoMode(true);
      // Load fixture
      setAnalysis(DEMO_FIXTURES.syn_port_scan);
    }
  };

  const findingsCount = analysis?.findings?.length || 0;
  const flowsCount = analysis?.flows?.length || 0;
  const isDemoData = Boolean(analysis?.isDemo || isDemoMode);

  return (
    <div className="min-h-screen bg-[#0A0E17] text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-black antialiased">
      {/* Top Navigation */}
      <TopNav
        backendStatus={backendStatus}
        analysisStatus={analysisStatus}
        isDemoData={isDemoData}
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        onOpenSettings={() => setActiveTab("settings")}
        onRefreshBackend={handleRefreshBackend}
        onNavigateToUpload={() => setActiveTab("pcap")}
      />

      {/* Main Layout Area */}
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar */}
        <Sidebar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          findingsCount={findingsCount}
          flowsCount={flowsCount}
          mobileOpen={mobileMenuOpen}
          onToggleMobile={() => setMobileMenuOpen((prev) => !prev)}
        />

        {/* Analyst Workspace Viewport */}
        <main className="flex-1 overflow-y-auto p-4 md:p-6 lg:p-8">
          {/* Landing Page is always accessible without waiting for capture analysis */}
          {activeTab === "landing" && (
            <LandingPage
              backendStatus={backendStatus}
              onOpenAnalyzer={() => setActiveTab("overview")}
              onOpenCaseStudy={() => setActiveTab("case-study")}
              onOpenDocumentation={(sec) => {
                if (sec) setDocsSection(sec);
                setActiveTab("docs");
              }}
              onSelectSample={(id) => handleAnalyzeSample(id, profile, engine)}
              onRefreshBackend={handleRefreshBackend}
            />
          )}

          {/* Portfolio Case Study Presentation */}
          {activeTab === "case-study" && (
            <PortfolioCaseStudyPage
              backendStatus={backendStatus}
              onOpenWorkspace={() => setActiveTab("overview")}
              onOpenDocumentation={(sec) => {
                if (sec) setDocsSection(sec);
                setActiveTab("docs");
              }}
              onSelectSample={(id) => handleAnalyzeSample(id, profile, engine)}
              onNavigateToTab={setActiveTab}
            />
          )}

          {/* Documentation is always accessible */}
          {activeTab === "docs" && (
            <DocumentationPage
              initialSection={docsSection}
              onNavigateToConsole={() => setActiveTab("overview")}
            />
          )}

          {/* Console modules */}
          {activeTab !== "landing" && activeTab !== "case-study" && activeTab !== "docs" && (
            analysisStatus === "analyzing" && !analysis ? (
              <div className="flex flex-col items-center justify-center py-28 space-y-3">
                <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
                <p className="text-slate-400 text-xs font-mono">
                  Executing Python PCAP frame dissection &amp; heuristic rule evaluation...
                </p>
              </div>
            ) : !analysis ? (
              <div className="text-center py-20 text-slate-500 text-sm">
                No capture loaded. Select a scenario or upload a .pcap file to begin.
              </div>
            ) : (
              <>
                {activeTab === "overview" && (
                  <OverviewDashboard
                    analysis={analysis}
                    onNavigateToTab={setActiveTab}
                  />
                )}

                {activeTab === "pcap" && (
                  <PcapAnalysisPage
                    onAnalyzeSample={handleAnalyzeSample}
                    onAnalyzeUpload={handleAnalyzeUpload}
                    currentProfile={profile}
                    onChangeProfile={setProfile}
                    currentEngine={engine}
                    onChangeEngine={setEngine}
                    isAnalyzing={analysisStatus === "analyzing"}
                  />
                )}

                {activeTab === "findings" && (
                  <FindingsPage
                    findings={analysis.findings || []}
                    onViewFlows={() => setActiveTab("network")}
                  />
                )}

                {activeTab === "network" && (
                  <NetworkFlowsPage flows={analysis.flows || []} />
                )}

                {activeTab === "dns" && (
                  <DnsPage dnsData={analysis.dns} />
                )}

                {activeTab === "http" && (
                  <HttpPage httpData={analysis.http} />
                )}

                {activeTab === "tls" && (
                  <TlsPage tlsData={analysis.tls} />
                )}

                {activeTab === "iocs" && (
                  <IocsPage iocs={analysis.iocs} />
                )}

                {activeTab === "reports" && (
                  <ReportsPage analysis={analysis} />
                )}

                {activeTab === "settings" && (
                  <SettingsPage
                    backendStatus={backendStatus}
                    currentProfile={profile}
                    onChangeProfile={setProfile}
                    currentEngine={engine}
                    onChangeEngine={setEngine}
                    isDemoMode={isDemoData}
                    onToggleDemoMode={handleToggleDemoMode}
                    onRefreshBackend={handleRefreshBackend}
                  />
                )}
              </>
            )
          )}
        </main>
      </div>
    </div>
  );
}
