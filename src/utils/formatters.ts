/**
 * Data formatters for SOC Analyst Dashboard
 */

export function formatBytes(bytes: number): string {
  if (bytes === 0 || isNaN(bytes)) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export function formatDuration(seconds: number): string {
  if (!seconds || isNaN(seconds) || seconds < 0) return "00:00.000";
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${String(mins).padStart(2, "0")}:${secs.toFixed(3).padStart(6, "0")}`;
}

export function formatTimestamp(ts: number | null | undefined): string {
  if (!ts) return "N/A";
  const date = new Date(ts * 1000);
  return date.toISOString().replace("T", " ").replace("Z", " UTC");
}

export function calculateShannonEntropy(str: string): number {
  if (!str) return 0;
  const freq: Record<string, number> = {};
  for (const c of str) {
    freq[c] = (freq[c] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const c in freq) {
    const p = freq[c] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(2));
}

export function getSeverityBadgeClass(severity: string): { bg: string; text: string; border: string } {
  switch (severity?.toUpperCase()) {
    case "CRITICAL":
      return { bg: "bg-red-950/60", text: "text-red-400", border: "border-red-800/80" };
    case "HIGH":
      return { bg: "bg-rose-950/60", text: "text-rose-400", border: "border-rose-800/80" };
    case "MEDIUM":
      return { bg: "bg-amber-950/60", text: "text-amber-400", border: "border-amber-800/80" };
    case "LOW":
      return { bg: "bg-blue-950/60", text: "text-cyan-400", border: "border-cyan-800/80" };
    case "INFO":
    default:
      return { bg: "bg-slate-900/60", text: "text-slate-400", border: "border-slate-800/80" };
  }
}
