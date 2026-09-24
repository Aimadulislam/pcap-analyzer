/**
 * API Service for Automated Python PCAP Analyzer
 * 
 * Handles communication with the Express backend which executes the Python PCAP analyzer.
 * If backend is unavailable, gracefully switches to the Demo Mode adapter with explicitly marked DEMO DATA.
 */

import { AnalysisResult, AnalysisProfile, DissectionEngine, BackendStatus } from "../types/analyzer";
import { DEMO_FIXTURES, SAMPLE_PCAP_LIST } from "../data/demoFixtures";

export async function checkBackendStatus(): Promise<BackendStatus> {
  try {
    const res = await fetch("/api/status", { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      const data = await res.json();
      return {
        connected: Boolean(data.connected),
        mode: data.connected ? "live" : "demo",
        pythonVersion: data.pythonVersion,
        analyzerVersion: data.analyzerVersion || "2.0.0",
        availableProfiles: data.availableProfiles || ["default", "home_lab", "enterprise", "high_volume"],
        availableEngines: data.availableEngines || ["native", "scapy", "auto"],
      };
    }
  } catch (e) {
    // Backend unreachable
  }

  return {
    connected: false,
    mode: "demo",
    availableProfiles: ["default", "home_lab", "enterprise", "high_volume"],
    availableEngines: ["native"],
  };
}

export async function analyzeSamplePcap(
  sampleId: string,
  profile: AnalysisProfile = "default",
  engine: DissectionEngine = "auto"
): Promise<{ result: AnalysisResult; reportText?: string }> {
  try {
    const res = await fetch("/api/analyze-sample", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sampleId, profile, engine }),
      signal: AbortSignal.timeout(35000),
    });

    if (res.ok) {
      const data = await res.json();
      if (data.success && data.result) {
        return {
          result: {
            ...data.result,
            isDemo: false, // LIVE PRODUCTION RESULT
            reportText: data.reportText,
          },
          reportText: data.reportText,
        };
      }
    }
  } catch (err) {
    console.warn("Backend analysis request failed, falling back to static fixture:", err);
  }

  // Fallback to static demo fixture explicitly marked as DEMO DATA
  const fixture = DEMO_FIXTURES[sampleId] || DEMO_FIXTURES.syn_port_scan;
  return {
    result: {
      ...fixture,
      isDemo: true, // EXPLICITLY MARKED AS DEMO DATA
    },
    reportText: fixture.reportText,
  };
}

export async function analyzeUploadedPcap(
  file: File,
  profile: AnalysisProfile = "default",
  engine: DissectionEngine = "auto"
): Promise<{ result: AnalysisResult; reportText?: string }> {
  // Convert file to base64
  const base64Data = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const res = reader.result as string;
      const base64 = res.split(",")[1];
      resolve(base64);
    };
    reader.onerror = (e) => reject(e);
    reader.readAsDataURL(file);
  });

  const res = await fetch("/api/analyze-upload", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      fileName: file.name,
      fileData: base64Data,
      profile,
      engine,
    }),
    signal: AbortSignal.timeout(65000),
  });

  if (!res.ok) {
    const errorJson = await res.json().catch(() => ({}));
    throw new Error(errorJson.details || errorJson.error || `Analysis failed with HTTP ${res.status}`);
  }

  const data = await res.json();
  if (!data.success || !data.result) {
    throw new Error(data.error || "Analysis engine did not return valid results.");
  }

  return {
    result: {
      ...data.result,
      isDemo: false, // REAL ANALYSIS FROM UPLOADED PCAP
      reportText: data.reportText,
    },
    reportText: data.reportText,
  };
}
