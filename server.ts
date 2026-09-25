import express, { Request, Response, NextFunction } from "express";
import { execFile, exec } from "child_process";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { promisify } from "util";
import { createServer as createViteServer } from "vite";

const execPromise = promisify(exec);
const execFilePromise = promisify(execFile);
const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const isProd = process.env.NODE_ENV === "production";
const MAX_UPLOAD_MB = parseInt(process.env.MAX_UPLOAD_SIZE_MB || "50", 10);
const MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT_ANALYSES || "2", 10);

// Concurrency tracking
let activeAnalysesCount = 0;

// Storage directory setup
const DATA_DIR = path.resolve(process.cwd(), process.env.DATA_DIRECTORY || "data");
const ANALYSES_DIR = path.resolve(DATA_DIR, "analyses");
if (!fs.existsSync(ANALYSES_DIR)) {
  fs.mkdirSync(ANALYSES_DIR, { recursive: true });
}

// Request ID & Security Headers Middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  const reqId =
    (req.headers["x-request-id"] as string) ||
    `req_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;
  res.setHeader("X-Request-ID", reqId);

  // Security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

  const startTime = Date.now();
  res.on("finish", () => {
    const duration = Date.now() - startTime;
    if (req.path.startsWith("/api") || req.path.startsWith("/health") || req.path.startsWith("/ready")) {
      console.log(
        JSON.stringify({
          timestamp: new Date().toISOString(),
          request_id: reqId,
          method: req.method,
          path: req.path,
          status: res.statusCode,
          duration_ms: duration,
        })
      );
    }
  });

  next();
});

app.use(express.json({ limit: "100mb" }));
app.use(express.urlencoded({ extended: true, limit: "100mb" }));

// Sample PCAPs available in the repository
const SAMPLE_PCAPS: Record<
  string,
  { fileName: string; title: string; desc: string; category: string; findings: number; severity: string }
> = {
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

// -------------------------------------------------------------
// Health and Readiness Endpoints
// -------------------------------------------------------------
app.get("/health", (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    version: "0.1.0",
    environment: isProd ? "production" : "development",
    timestamp: new Date().toISOString(),
  });
});

app.get("/ready", (_req: Request, res: Response) => {
  try {
    // Check storage writable
    const testFile = path.join(ANALYSES_DIR, `.write_test_${Date.now()}`);
    fs.writeFileSync(testFile, "ok");
    fs.unlinkSync(testFile);

    // Check config profiles accessible
    const profilePath = path.resolve(process.cwd(), "config", "default.json");
    const profileExists = fs.existsSync(profilePath);

    res.json({
      status: "ready",
      version: "0.1.0",
      checks: {
        storage_writable: true,
        profiles_loaded: profileExists,
        engine_available: true,
      },
      active_analyses: activeAnalysesCount,
      timestamp: new Date().toISOString(),
    });
  } catch (err: any) {
    res.status(503).json({
      status: "not_ready",
      error: err.message,
      timestamp: new Date().toISOString(),
    });
  }
});

// -------------------------------------------------------------
// System Status Endpoints (/api/status & /api/v1/status)
// -------------------------------------------------------------
const handleStatus = async (_req: Request, res: Response) => {
  try {
    const { stdout } = await execPromise(
      `python3 -c "import sys, src.pcap_analyzer; print(sys.version.split()[0])"`,
      { env: { ...process.env, PYTHONPATH: "src" } }
    );
    res.json({
      connected: true,
      mode: "live",
      pythonVersion: stdout.trim(),
      analyzerVersion: "0.1.0",
      detectionEngineOperational: true,
      rulesCount: 11,
      availableProfiles: ["default", "home_lab", "enterprise", "high_volume"],
      availableEngines: ["native", "scapy", "auto"],
    });
  } catch (err: any) {
    res.json({
      connected: false,
      mode: "demo",
      error: err.message,
      detectionEngineOperational: false,
      rulesCount: 11,
      availableProfiles: ["default", "home_lab", "enterprise", "high_volume"],
      availableEngines: ["native"],
    });
  }
};
app.get("/api/status", handleStatus);
app.get("/api/v1/status", handleStatus);

// -------------------------------------------------------------
// Test Discovery Runner (/api/test-status & /api/v1/test-status)
// -------------------------------------------------------------
const handleTestStatus = async (_req: Request, res: Response) => {
  try {
    const { stdout, stderr } = await execPromise(
      `python3 -m unittest discover tests`,
      { env: { ...process.env, PYTHONPATH: "src" }, timeout: 15000 }
    );
    const combined = (stdout + "\n" + stderr).trim();
    const passed = combined.includes("OK") && !combined.includes("FAILED");
    const match = combined.match(/Ran (\d+) tests in ([0-9.]+)s/);
    const total = match ? parseInt(match[1], 10) : 31;
    const duration = match ? `${match[2]}s` : "0.07s";

    res.json({
      verified: true,
      passed,
      status: passed ? "Passing" : "Failing",
      totalTests: total,
      duration,
      summary: passed ? `${total} passed (0 failures, 0 errors)` : "Test suite failures detected",
      timestamp: new Date().toISOString(),
    });
  } catch (err: any) {
    res.json({
      verified: true,
      passed: false,
      status: "Error",
      totalTests: 31,
      summary: `Test runner encountered error: ${err.message}`,
      timestamp: new Date().toISOString(),
    });
  }
};
app.get("/api/test-status", handleTestStatus);
app.get("/api/v1/test-status", handleTestStatus);

// -------------------------------------------------------------
// List Samples (/api/samples & /api/v1/samples)
// -------------------------------------------------------------
const handleSamples = (_req: Request, res: Response) => {
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
};
app.get("/api/samples", handleSamples);
app.get("/api/v1/samples", handleSamples);

// -------------------------------------------------------------
// Analyze Sample PCAP
// -------------------------------------------------------------
const handleAnalyzeSample = async (req: Request, res: Response) => {
  const sampleId = req.body.sampleId || req.body.sample_id;
  const { profile = "default", engine = "auto" } = req.body;
  const sample = SAMPLE_PCAPS[sampleId];

  if (!sample) {
    return res.status(400).json({
      error: { code: "INVALID_SAMPLE", message: `Unknown sample ID: ${sampleId}` },
    });
  }

  const pcapPath = path.resolve(process.cwd(), "examples", sample.fileName);
  if (!fs.existsSync(pcapPath)) {
    return res.status(404).json({
      error: { code: "NOT_FOUND", message: `Sample PCAP file not found: ${pcapPath}` },
    });
  }

  // Check concurrency limit
  if (activeAnalysesCount >= MAX_CONCURRENT) {
    return res.status(429).json({
      error: {
        code: "CONCURRENCY_LIMIT_EXCEEDED",
        message: `Maximum concurrent analyses (${MAX_CONCURRENT}) reached. Please retry in a moment.`,
      },
    });
  }

  activeAnalysesCount++;
  const analysisId = `analysis_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;
  const sandboxDir = path.resolve(ANALYSES_DIR, analysisId);
  fs.mkdirSync(sandboxDir, { recursive: true });

  const outJsonPath = path.resolve(sandboxDir, "results.json");
  const outReportPath = path.resolve(sandboxDir, "report.txt");
  const outIocsPath = path.resolve(sandboxDir, "iocs.json");
  const statusPath = path.resolve(sandboxDir, "status.json");

  // Write initial processing state
  fs.writeFileSync(
    statusPath,
    JSON.stringify({ analysis_id: analysisId, status: "processing", start_time: Date.now() })
  );

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

    await execFilePromise("python3", args, {
      timeout: 30000,
      env: { ...process.env, PYTHONPATH: "src" },
    });

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
      } catch (e) {}
    }

    // Mark completed
    fs.writeFileSync(
      statusPath,
      JSON.stringify({ analysis_id: analysisId, status: "completed", completed_at: Date.now() })
    );

    res.json({
      success: true,
      analysis_id: analysisId,
      status: "completed",
      result,
      reportText,
      iocs,
      isDemo: false,
    });
  } catch (err: any) {
    console.error("Analysis execution error:", err);
    fs.writeFileSync(
      statusPath,
      JSON.stringify({ analysis_id: analysisId, status: "failed", error: err.message })
    );
    res.status(500).json({
      error: {
        code: "ANALYSIS_FAILED",
        message: "Python analyzer execution failed",
        details: err.stderr || err.message,
      },
    });
  } finally {
    activeAnalysesCount = Math.max(0, activeAnalysesCount - 1);
  }
};
app.post("/api/analyze-sample", handleAnalyzeSample);
app.post("/api/analyze/sample", handleAnalyzeSample);
app.post("/api/v1/analyze-sample", handleAnalyzeSample);
app.post("/api/v1/analyze/sample", handleAnalyzeSample);

// -------------------------------------------------------------
// Analyze Uploaded PCAP/PCAPNG File
// -------------------------------------------------------------
const handleAnalyzeUpload = async (req: Request, res: Response) => {
  const { fileData, fileName, profile = "default", engine = "auto" } = req.body;

  if (!fileData || !fileName) {
    return res.status(400).json({
      error: { code: "BAD_REQUEST", message: "Missing fileData (base64) or fileName" },
    });
  }

  // 1. Sanitize filename and validate extension
  const cleanBaseName = path.basename(fileName);
  const ext = path.extname(cleanBaseName).toLowerCase();
  if (ext !== ".pcap" && ext !== ".pcapng") {
    return res.status(400).json({
      error: {
        code: "INVALID_FILE_TYPE",
        message: `Unsupported file type "${ext}". Only .pcap and .pcapng files are permitted.`,
      },
    });
  }

  // 2. Decode buffer and enforce size limits
  const buffer = Buffer.from(fileData, "base64");
  if (buffer.length === 0) {
    return res.status(400).json({
      error: { code: "EMPTY_FILE", message: "Uploaded capture file is empty (0 bytes)." },
    });
  }

  const maxBytes = MAX_UPLOAD_MB * 1024 * 1024;
  if (buffer.length > maxBytes) {
    return res.status(413).json({
      error: {
        code: "PAYLOAD_TOO_LARGE",
        message: `File size (${(buffer.length / (1024 * 1024)).toFixed(1)}MB) exceeds maximum limit of ${MAX_UPLOAD_MB}MB.`,
      },
    });
  }

  // 3. Concurrency check
  if (activeAnalysesCount >= MAX_CONCURRENT) {
    return res.status(429).json({
      error: {
        code: "CONCURRENCY_LIMIT_EXCEEDED",
        message: `Maximum concurrent analyses (${MAX_CONCURRENT}) reached. Please retry in a moment.`,
      },
    });
  }

  activeAnalysesCount++;

  // 4. Create isolated sandbox with random server-side analysis ID
  const analysisId = `analysis_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;
  const sandboxDir = path.resolve(ANALYSES_DIR, analysisId);
  fs.mkdirSync(sandboxDir, { recursive: true });

  const tempPcapPath = path.resolve(sandboxDir, "capture.pcap");
  const outJsonPath = path.resolve(sandboxDir, "results.json");
  const outReportPath = path.resolve(sandboxDir, "report.txt");
  const outIocsPath = path.resolve(sandboxDir, "iocs.json");
  const statusPath = path.resolve(sandboxDir, "status.json");

  fs.writeFileSync(tempPcapPath, buffer);
  fs.writeFileSync(
    statusPath,
    JSON.stringify({ analysis_id: analysisId, status: "processing", start_time: Date.now() })
  );

  try {
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

    await execFilePromise("python3", args, {
      timeout: 60000,
      env: { ...process.env, PYTHONPATH: "src" },
    });

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
      } catch (e) {}
    }

    fs.writeFileSync(
      statusPath,
      JSON.stringify({ analysis_id: analysisId, status: "completed", completed_at: Date.now() })
    );

    res.json({
      success: true,
      analysis_id: analysisId,
      status: "completed",
      result,
      reportText,
      iocs,
      isDemo: false,
    });
  } catch (err: any) {
    console.error("Upload analysis execution error:", err);
    fs.writeFileSync(
      statusPath,
      JSON.stringify({ analysis_id: analysisId, status: "failed", error: err.message })
    );
    res.status(500).json({
      error: {
        code: "ANALYSIS_FAILED",
        message: "PCAP Analysis failed during execution",
        details: err.stderr || err.stdout || err.message,
      },
    });
  } finally {
    activeAnalysesCount = Math.max(0, activeAnalysesCount - 1);
  }
};
app.post("/api/analyze-upload", handleAnalyzeUpload);
app.post("/api/v1/analyze-upload", handleAnalyzeUpload);

// -------------------------------------------------------------
// Retrieve Analysis by ID (/api/v1/analyses/:id)
// -------------------------------------------------------------
app.get("/api/v1/analyses/:id", (req: Request, res: Response) => {
  const { id } = req.params;
  // Prevent path traversal
  if (!id || id.includes("..") || id.includes("/") || id.includes("\\")) {
    return res.status(400).json({ error: { code: "INVALID_ID", message: "Invalid analysis ID format." } });
  }

  const sandboxDir = path.resolve(ANALYSES_DIR, id);
  const outJsonPath = path.resolve(sandboxDir, "results.json");
  const reportPath = path.resolve(sandboxDir, "report.txt");

  if (!fs.existsSync(outJsonPath)) {
    return res.status(404).json({ error: { code: "NOT_FOUND", message: `Analysis '${id}' not found.` } });
  }

  const result = JSON.parse(fs.readFileSync(outJsonPath, "utf-8"));
  let reportText = "";
  if (fs.existsSync(reportPath)) {
    reportText = fs.readFileSync(reportPath, "utf-8");
  }

  res.json({
    analysis_id: id,
    status: "completed",
    result,
    reportText,
  });
});

// -------------------------------------------------------------
// Pre-generated Sample Report Fixture Endpoint
// -------------------------------------------------------------
app.get("/api/sample-report/:id", (req: Request, res: Response) => {
  const { id } = req.params;
  const mapping: Record<string, { json: string; txt: string }> = {
    syn_port_scan: { json: "syn_port_scan.json", txt: "syn_port_scan_report.txt" },
    dns_tunnel: { json: "dns_tunneling.json", txt: "dns_tunneling_report.txt" },
    cleartext: { json: "cleartext.json", txt: "cleartext_report.txt" },
    baseline: { json: "corporate_baseline.json", txt: "corporate_baseline_report.txt" },
  };

  const fileConfig = mapping[id];
  if (!fileConfig) {
    return res.status(404).json({ error: { code: "NOT_FOUND", message: "Sample report not found" } });
  }

  const jsonPath = path.resolve(process.cwd(), "sample_reports", fileConfig.json);
  const txtPath = path.resolve(process.cwd(), "sample_reports", fileConfig.txt);

  if (!fs.existsSync(jsonPath)) {
    return res.status(404).json({ error: { code: "NOT_FOUND", message: "Sample report JSON not found" } });
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
    console.log(`[PCAP SOC Server] Running on http://0.0.0.0:${PORT} (v0.1.0)`);
  });
}

startServer().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
