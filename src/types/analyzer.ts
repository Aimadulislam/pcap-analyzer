/**
 * TypeScript Data Models for Automated Python PCAP Analyzer & Threat Parser
 * 
 * Accurately aligns with Python backend schema defined in src/pcap_analyzer/models.py
 */

export type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type AnalysisProfile = "default" | "home_lab" | "enterprise" | "high_volume";

export type DissectionEngine = "auto" | "native" | "scapy" | "pyshark";

export interface CaptureMetadata {
  file_path: string;
  file_name: string;
  file_size_bytes: number;
  file_format: string;
  packet_count: number;
  first_timestamp: number | null;
  last_timestamp: number | null;
  duration_seconds: number;
  parser_engine: string;
  sha256_hash?: string;
  analysis_timestamp?: string;
  analyzer_version?: string;
  profile_name?: string;
  profile_source?: string;
}

export interface CaptureIntegrity {
  sha256: string;
  file_name: string;
  file_size_bytes: number;
}

export interface TopEndpoint {
  ip: string;
  packet_count: number;
  byte_count: number;
  percentage: number;
}

export interface TopPort {
  port: number;
  packet_count: number;
  percentage: number;
}

export interface TrafficStatistics {
  total_packets: number;
  total_bytes: number;
  capture_duration: number;
  unique_source_ips: number;
  unique_destination_ips: number;
  unique_conversations: number;
  tcp_packet_count: number;
  udp_packet_count: number;
  icmp_packet_count: number;
  dns_packet_count: number;
  http_packet_count: number;
  tls_packet_count: number;
  total_syn_packets?: number;
  completed_handshakes?: number;
  incomplete_handshakes?: number;
  total_resets?: number;
  protocol_distribution: Record<string, number>;
  protocol_bytes?: Record<string, number>;
  top_source_ips: TopEndpoint[];
  top_destination_ips: TopEndpoint[];
  top_destination_ports?: TopPort[];
  tcp_flags_distribution?: Record<string, number>;
}

export interface FlowRecord {
  flow_id: string;
  source_ip: string;
  destination_ip: string;
  source_port: number | null;
  destination_port: number | null;
  protocol: string;
  packet_count: number;
  byte_count: number;
  first_seen: number;
  last_seen: number;
  duration_seconds: number;
  packets_per_second?: number;
  bytes_per_second?: number;
  syn_count: number;
  syn_ack_count?: number;
  ack_count?: number;
  fin_count?: number;
  rst_count?: number;
  completed_handshake: boolean;
  classification?: string;
}

export interface DNSRecord {
  packet_number: number;
  timestamp: number;
  source_ip: string | null;
  destination_ip?: string | null;
  query: string | null;
  query_type: string | null;
  response?: string | null;
  response_code?: number | string | null;
  answers?: string[];
  is_response?: boolean;
  transaction_id?: number | null;
  entropy?: number;
}

export interface HTTPRecord {
  packet_number: number;
  timestamp: number;
  source_ip: string | null;
  destination_ip: string | null;
  source_port?: number | null;
  destination_port?: number | null;
  method: string | null;
  host: string | null;
  uri: string | null;
  user_agent?: string | null;
  status_code?: number | null;
  content_type?: string | null;
}

export interface TLSRecord {
  packet_number: number;
  timestamp: number;
  source_ip: string | null;
  destination_ip: string | null;
  source_port?: number | null;
  destination_port?: number | null;
  version: string | null;
  server_name?: string | null;
  sni?: string | null;
  cipher?: string | null;
  handshake_type?: string | null;
}

export interface AlertFinding {
  finding_id?: string;
  id?: string;
  rule_id?: string;
  detection_rule?: string;
  timestamp: number;
  severity: SeverityLevel;
  confidence: number;
  title: string;
  category: string;
  description: string;
  source_ip?: string | null;
  destination_ip?: string | null;
  source_port?: number | null;
  destination_port?: number | null;
  protocol?: string | null;
  evidence: Record<string, any>;
  packet_numbers?: number[];
  recommended_next_step?: string;
  limitations?: string;
}

export interface IOCRecord {
  type: string;
  value: string;
  source: string;
  first_seen: number;
  last_seen: number;
  packet_count: number;
  context?: {
    sample_packets?: number[];
    contexts?: string[];
  };
}

export interface CategorizedIOCs {
  ips?: IOCRecord[];
  domains?: IOCRecord[];
  urls?: IOCRecord[];
  hostnames?: IOCRecord[];
  emails?: IOCRecord[];
  hashes?: IOCRecord[];
  [key: string]: IOCRecord[] | undefined;
}

export interface DNSContainer {
  total_queries?: number;
  records?: DNSRecord[];
}

export interface HTTPContainer {
  total_transactions?: number;
  records?: HTTPRecord[];
}

export interface TLSContainer {
  total_records?: number;
  records?: TLSRecord[];
}

export interface AnalysisResult {
  metadata: CaptureMetadata;
  integrity?: CaptureIntegrity;
  summary: TrafficStatistics;
  protocols: Record<string, number>;
  top_sources: TopEndpoint[];
  top_destinations: TopEndpoint[];
  flows: FlowRecord[];
  dns: DNSContainer | DNSRecord[];
  http: HTTPContainer | HTTPRecord[];
  tls: TLSContainer | TLSRecord[];
  findings: AlertFinding[];
  errors: string[];
  iocs?: CategorizedIOCs;
  configuration?: Record<string, any>;
  reportText?: string;
  isDemo?: boolean;
}

export interface SamplePcapInfo {
  id: string;
  fileName: string;
  title: string;
  description: string;
  threatCategory: string;
  expectedFindings: number;
  severityLevel: SeverityLevel;
}

export interface TestSuiteStatus {
  verified: boolean;
  passed: boolean;
  status: "Passing" | "Failing" | "Not verified" | "Error";
  totalTests: number;
  duration?: string;
  summary: string;
  timestamp?: string;
}

export interface BackendStatus {
  connected: boolean;
  mode: "live" | "demo";
  pythonVersion?: string;
  analyzerVersion?: string;
  detectionEngineOperational?: boolean;
  rulesCount?: number;
  availableProfiles: AnalysisProfile[];
  availableEngines: DissectionEngine[];
  testSuite?: TestSuiteStatus;
}
