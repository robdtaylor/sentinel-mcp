/**
 * Sentinel MCP - Core Type Definitions
 */

// ============================================================================
// Severity & Risk
// ============================================================================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ScanStatus = 'pass' | 'warn' | 'fail';

// ============================================================================
// MCP Configuration
// ============================================================================

export interface MCPServerConfig {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  transport?: 'stdio' | 'sse' | 'streamable-http';
}

export interface MCPConfigFile {
  path: string;
  client: string;
  servers: Record<string, MCPServerConfig>;
  raw: unknown;
}

// ============================================================================
// Scan Findings
// ============================================================================

export interface Finding {
  id: string;
  severity: Severity;
  category: FindingCategory;
  title: string;
  description: string;
  server?: string;
  configFile?: string;
  evidence?: string;
  remediation?: string;
}

export type FindingCategory =
  | 'credential-exposure'
  | 'prompt-injection'
  | 'tool-poisoning'
  | 'tool-shadowing'
  | 'ssrf'
  | 'command-injection'
  | 'insecure-transport'
  | 'excessive-permissions'
  | 'supply-chain'
  | 'configuration';

// ============================================================================
// Scan Report
// ============================================================================

export interface ScanReport {
  timestamp: string;
  version: string;
  score: number; // 0-100
  status: ScanStatus;
  configFiles: MCPConfigFile[];
  findings: Finding[];
  summary: ScanSummary;
}

export interface ScanSummary {
  totalServers: number;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

// ============================================================================
// Baseline / Diff
// ============================================================================

export interface BaselineDiff {
  newFindings: Finding[];
  fixedFindings: Finding[];
  unchangedFindings: Finding[];
  baselineTimestamp: string;
  baselineScore: number;
  scoreDelta: number; // current - baseline (positive = improved)
}

// ============================================================================
// Scanner Interface
// ============================================================================

export interface Scanner {
  name: string;
  scan(configs: MCPConfigFile[]): Promise<Finding[]>;
}
