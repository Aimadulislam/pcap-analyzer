import express, { Request, Response } from "express";
import { execFile, exec } from "child_process";
import fs from "fs";
import path from "path";
import { promisify } from "util";
import { createServer as createViteServer } from "vite";

const execPromise = promisify(exec);
const execFilePromise = promisify(execFile);
const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const isProd = process.env.NODE_ENV === "production";

app.use(express.json({ limit: "100mb" }));
app.use(express.urlencoded({ extended: true, limit: "100mb" }));

// Sample PCAPs available in the repository
const SAMPLE_PCAPS: Record<string, { fileName: string; title: string; desc: string; category: string; findings: number; severity: string }> = {
  syn_port_scan: {
    fileName: "syn_port_scan.pcap",
    title: "Vertical TCP SYN Port Reconnaissance Scan",
    desc: "45 unacknowledged SYN connection attempts targeting diverse ports on 10.10.20.5.",
    category: "Reconnaissance",
    findings: 4,
    severity: "HIGH",
  },
  dns_tunnel: {
    fileName: "dns_tunneling_c2.pcap",
    title: "Covert DNS Tunneling & C2 Exfiltration",
    desc: "110 high-entropy DNS queries transmitting encoded data chunks over UDP port 53.",
    category: "DNS Anomaly",
    findings: 3,
    severity: "HIGH",
  },
  dns_tunneling: {
    fileName: "dns_tunneling_c2.pcap",
    title: "Covert DNS Tunneling & C2 Exfiltration",
    desc: "110 high-entropy DNS queries transmitting encoded data chunks over UDP port 53.",
    category: "DNS Anomaly",
    findings: 3,
    severity: "HIGH",
  },
  cleartext: {
    fileName: "cleartext_credentials.pcap",
    title: "Unencrypted HTTP & Metasploit Port 4444",
    desc: "Cleartext HTTP authentication request to /login.php and non-standard listener activity.",
    category: "Cleartext Communication",
    findings: 2,
    severity: "LOW",
  },
  baseline: {
    fileName: "corporate_baseline.pcap",
    title: "Benign Corporate Web & DNS Baseline",
    desc: "Normal corporate browsing to Slack, GitHub, and Google with established TLS handshakes.",
    category: "Benign Baseline",
    findings: 0,
    severity: "INFO",
  },
  corporate_baseline: {
    fileName: "corporate_baseline.pcap",
    title: "Benign Corporate Web & DNS Baseline",
    desc: "Normal corporate browsing to Slack, GitHub, and Google with established TLS handshakes.",
    category: "Benign Baseline",
    findings: 0,
    severity: "INFO",
  },
};

// Check backend status and Python environment
app.get("/api/status", async (_req: Request, res: Response) => {
  try {
    const { stdout } = await execPromise(
      `python3 -c "import sys, src.pcap_analyzer; print(sys.version.split()[0])"`
    );
    res.json({
      connected: true,
      mode: "live",
      pythonVersion: stdout.trim(),
      analyzerVersion: "2.0.0",
      availableProfiles: ["default", "home_lab", "enterprise", "high_volume"],
      availableEngines: ["native", "scapy", "auto"],
    });
  } catch (err: any) {
    res.json({
      connected: false,
      mode: "demo",
      error: err.message,
      availableProfiles: ["default", "home_lab", "enterprise", "high_volume"],
      availableEngines: ["native"],
    });
  }
});

// List available sample PCAPs
app.get("/api/samples", (_req: Request, res: Response) => {
  const samples = Object.entries(SAMPLE_PCAPS).map(([id, meta]) => ({
    id,
    fileName: meta.fileName,
    title: meta.title,
    description: meta.desc,
    threatCategory: meta.category,
    expectedFindings: meta.findings,
    severityLevel: meta.severity,
  }));
  res.json({ samples });
});

// Analyze one of the built-in sample PCAPs using the Python backend
app.post("/api/analyze-sample", async (req: Request, res: Response) => {
  const { sampleId, profile = "default", engine = "auto" } = req.body;
  const sample = SAMPLE_PCAPS[sampleId];

  if (!sample) {
    return res.status(400).json({ error: `Unknown sample ID: ${sampleId}` });
  }

  const pcapPath = path.resolve(process.cwd(), "examples", sample.fileName);
  if (!fs.existsSync(pcapPath)) {
    return res.status(404).json({ error: `Sample PCAP file not found: ${pcapPath}` });
  }

  const runId = `sample_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
  const outJsonPath = path.resolve("/tmp", `${runId}_out.json`);
  const outReportPath = path.resolve("/tmp", `${runId}_report.txt`);
  const outIocsPath = path.resolve("/tmp", `${runId}_iocs.json`);

  try {
    const args = [
      "-m",
      "src.pcap_analyzer.cli",
      pcapPath,
      "--profile",
      profile,
      "--engine",
      engine,
      "-o",
      outJsonPath,
      "-r",
      outReportPath,
      "--iocs",
      outIocsPath,
    ];

    await execFilePromise("python3", args, { timeout: 30000 });

    const rawJson = fs.readFileSync(outJsonPath, "utf-8");
    const result = JSON.parse(rawJson);

    let reportText = "";
    if (fs.existsSync(outReportPath)) {
      reportText = fs.readFileSync(outReportPath, "utf-8");
    }

    let iocs = {};
    if (fs.existsSync(outIocsPath)) {
      try {
        iocs = JSON.parse(fs.readFileSync(outIocsPath, "utf-8"));
      } catch (e) {
        // fallback
      }
    }

    // Clean up temporary files
    try {
      if (fs.existsSync(outJsonPath)) fs.unlinkSync(outJsonPath);
      if (fs.existsSync(outReportPath)) fs.unlinkSync(outReportPath);
      if (fs.existsSync(outIocsPath)) fs.unlinkSync(outIocsPath);
    } catch (e) {
      // non-fatal cleanup error
    }

    res.json({
      success: true,
      result,
      reportText,
      iocs,
      isDemo: false,
    });
  } catch (err: any) {
    console.error("Analysis execution error:", err);
    res.status(500).json({
      error: "Python analyzer execution failed",
      details: err.stderr || err.message,
    });
  }
});

// Analyze uploaded PCAP/PCAPNG file
app.post("/api/analyze-upload", async (req: Request, res: Response) => {
  const { fileData, fileName, profile = "default", engine = "auto" } = req.body;

  if (!fileData || !fileName) {
    return res.status(400).json({ error: "Missing fileData (base64) or fileName" });
  }

  // Validate extension
  const ext = path.extname(fileName).toLowerCase();
  if (ext !== ".pcap" && ext !== ".pcapng") {
    return res.status(400).json({
      error: `Unsupported file type "${ext}". Only .pcap and .pcapng files are supported.`,
    });
  }

  const runId = `upload_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
  const tempPcapPath = path.resolve("/tmp", `${runId}_${fileName}`);
  const outJsonPath = path.resolve("/tmp", `${runId}_out.json`);
  const outReportPath = path.resolve("/tmp", `${runId}_report.txt`);
  const outIocsPath = path.resolve("/tmp", `${runId}_iocs.json`);

  try {
    // Write buffer from base64
    const buffer = Buffer.from(fileData, "base64");
    if (buffer.length === 0) {
      return res.status(400).json({ error: "Uploaded file is empty (0 bytes)." });
    }
    if (buffer.length > 50 * 1024 * 1024) {
      return res.status(400).json({ error: "File exceeds 50MB maximum upload limit." });
    }

    fs.writeFileSync(tempPcapPath, buffer);

    const args = [
      "-m",
      "src.pcap_analyzer.cli",
      tempPcapPath,
      "--profile",
      profile,
      "--engine",
      engine,
      "-o",
      outJsonPath,
      "-r",
      outReportPath,
      "--iocs",
      outIocsPath,
    ];

    await execFilePromise("python3", args, { timeout: 60000 });

    const rawJson = fs.readFileSync(outJsonPath, "utf-8");
    const result = JSON.parse(rawJson);

    let reportText = "";
    if (fs.existsSync(outReportPath)) {
      reportText = fs.readFileSync(outReportPath, "utf-8");
    }

    let iocs = {};
    if (fs.existsSync(outIocsPath)) {
      try {
        iocs = JSON.parse(fs.readFileSync(outIocsPath, "utf-8"));
      } catch (e) {
        // fallback
      }
    }

    // Clean up temporary files
    try {
      if (fs.existsSync(tempPcapPath)) fs.unlinkSync(tempPcapPath);
      if (fs.existsSync(outJsonPath)) fs.unlinkSync(outJsonPath);
      if (fs.existsSync(outReportPath)) fs.unlinkSync(outReportPath);
      if (fs.existsSync(outIocsPath)) fs.unlinkSync(outIocsPath);
    } catch (e) {
      // non-fatal cleanup
    }

    res.json({
      success: true,
      result,
      reportText,
      iocs,
      isDemo: false,
    });
  } catch (err: any) {
    console.error("Upload analysis execution error:", err);
    // Cleanup temp input if exists
    try {
      if (fs.existsSync(tempPcapPath)) fs.unlinkSync(tempPcapPath);
    } catch (e) {}

    res.status(500).json({
      error: "PCAP Analysis failed during execution",
      details: err.stderr || err.stdout || err.message,
    });
  }
});

// Get pre-generated sample fixture directly if needed
app.get("/api/sample-report/:id", (req: Request, res: Response) => {
  const { id } = req.params;
  const mapping: Record<string, { json: string; txt: string }> = {
    syn_port_scan: {
      json: "syn_port_scan.json",
      txt: "syn_port_scan_report.txt",
    },
    dns_tunnel: {
      json: "dns_tunneling.json",
      txt: "dns_tunneling_report.txt",
    },
    cleartext: {
      json: "cleartext.json",
      txt: "cleartext_report.txt",
    },
    baseline: {
      json: "corporate_baseline.json",
      txt: "corporate_baseline_report.txt",
    },
  };

  const fileConfig = mapping[id];
  if (!fileConfig) {
    return res.status(404).json({ error: "Sample report not found" });
  }

  const jsonPath = path.resolve(process.cwd(), "sample_reports", fileConfig.json);
  const txtPath = path.resolve(process.cwd(), "sample_reports", fileConfig.txt);

  if (!fs.existsSync(jsonPath)) {
    return res.status(404).json({ error: "Sample report JSON not found" });
  }

  const result = JSON.parse(fs.readFileSync(jsonPath, "utf-8"));
  let reportText = "";
  if (fs.existsSync(txtPath)) {
    reportText = fs.readFileSync(txtPath, "utf-8");
  }

  res.json({
    success: true,
    result,
    reportText,
    isDemo: true,
  });
});

async function startServer() {
  if (!isProd) {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: process.env.DISABLE_HMR !== "true",
      },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(process.cwd(), "dist")));
    app.get("*", (_req, res) => {
      res.sendFile(path.resolve(process.cwd(), "dist", "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[PCAP SOC Server] Running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
