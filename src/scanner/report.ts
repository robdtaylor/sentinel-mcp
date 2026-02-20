/**
 * Sentinel MCP - Report Generator
 *
 * Generates security scan reports with scoring, findings, and remediation.
 */

import type { ScanReport, ScanSummary, Finding, MCPConfigFile, ScanStatus } from '../lib/types';

const VERSION = '0.1.0';

// ============================================================================
// Score Calculation
// ============================================================================

/**
 * Calculate security score (0-100, higher is better)
 *
 * Scoring:
 * - Start at 100
 * - Critical finding: -25 points
 * - High finding: -15 points
 * - Medium finding: -8 points
 * - Low finding: -3 points
 * - Info finding: -0 points
 * - Minimum score: 0
 */
function calculateScore(findings: Finding[]): number {
  let score = 100;

  for (const finding of findings) {
    switch (finding.severity) {
      case 'critical': score -= 25; break;
      case 'high': score -= 15; break;
      case 'medium': score -= 8; break;
      case 'low': score -= 3; break;
      case 'info': break;
    }
  }

  return Math.max(0, score);
}

/**
 * Determine overall scan status from score
 */
function getStatus(score: number): ScanStatus {
  if (score >= 80) return 'pass';
  if (score >= 50) return 'warn';
  return 'fail';
}

/**
 * Generate a summary from findings
 */
function summarize(findings: Finding[], configs: MCPConfigFile[]): ScanSummary {
  const totalServers = configs.reduce(
    (sum, c) => sum + Object.keys(c.servers).length, 0
  );

  return {
    totalServers,
    totalFindings: findings.length,
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    info: findings.filter((f) => f.severity === 'info').length,
  };
}

// ============================================================================
// Report Generation
// ============================================================================

/**
 * Generate a full scan report
 */
export function generateReport(
  configs: MCPConfigFile[],
  findings: Finding[]
): ScanReport {
  const score = calculateScore(findings);

  return {
    timestamp: new Date().toISOString(),
    version: VERSION,
    score,
    status: getStatus(score),
    configFiles: configs,
    findings: findings.sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity)),
    summary: summarize(findings, configs),
  };
}

function severityOrder(s: string): number {
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return order[s] ?? 5;
}

// ============================================================================
// Console Output
// ============================================================================

const COLORS = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
};

function severityColor(severity: string): string {
  switch (severity) {
    case 'critical': return COLORS.bgRed + COLORS.white;
    case 'high': return COLORS.red;
    case 'medium': return COLORS.yellow;
    case 'low': return COLORS.blue;
    case 'info': return COLORS.dim;
    default: return COLORS.reset;
  }
}

function scoreColor(score: number): string {
  if (score >= 80) return COLORS.green;
  if (score >= 50) return COLORS.yellow;
  return COLORS.red;
}

function statusBadge(status: ScanStatus): string {
  switch (status) {
    case 'pass': return `${COLORS.bgGreen}${COLORS.white} PASS ${COLORS.reset}`;
    case 'warn': return `${COLORS.bgYellow}${COLORS.white} WARN ${COLORS.reset}`;
    case 'fail': return `${COLORS.bgRed}${COLORS.white} FAIL ${COLORS.reset}`;
  }
}

/**
 * Print the scan report to console
 */
export function printReport(report: ScanReport): void {
  const { summary, findings, score, status, configFiles } = report;

  // Header
  console.log();
  console.log(`${COLORS.bold}${COLORS.cyan}  Sentinel MCP Security Scanner v${VERSION}${COLORS.reset}`);
  console.log(`${COLORS.dim}  ${'─'.repeat(50)}${COLORS.reset}`);
  console.log();

  // Config files found
  if (configFiles.length === 0) {
    console.log(`  ${COLORS.yellow}No MCP configuration files found.${COLORS.reset}`);
    console.log(`  ${COLORS.dim}Checked: Claude Desktop, Cursor, VS Code, Claude Code, Windsurf, Cline${COLORS.reset}`);
    console.log();
    return;
  }

  console.log(`  ${COLORS.bold}Configurations Found${COLORS.reset}`);
  for (const config of configFiles) {
    const serverCount = Object.keys(config.servers).length;
    console.log(`  ${COLORS.cyan}${config.client}${COLORS.reset} (${serverCount} server${serverCount !== 1 ? 's' : ''})`);
    console.log(`  ${COLORS.dim}${config.path}${COLORS.reset}`);

    for (const serverName of Object.keys(config.servers)) {
      console.log(`    ${COLORS.dim}└─${COLORS.reset} ${serverName}`);
    }
  }
  console.log();

  // Score
  console.log(`  ${COLORS.bold}Security Score${COLORS.reset}`);
  console.log(`  ${scoreColor(score)}${COLORS.bold}${score}/100${COLORS.reset}  ${statusBadge(status)}`);
  console.log();

  // Summary bar
  if (summary.totalFindings > 0) {
    const parts: string[] = [];
    if (summary.critical > 0) parts.push(`${COLORS.bgRed}${COLORS.white} ${summary.critical} CRITICAL ${COLORS.reset}`);
    if (summary.high > 0) parts.push(`${COLORS.red}${summary.high} high${COLORS.reset}`);
    if (summary.medium > 0) parts.push(`${COLORS.yellow}${summary.medium} medium${COLORS.reset}`);
    if (summary.low > 0) parts.push(`${COLORS.blue}${summary.low} low${COLORS.reset}`);
    if (summary.info > 0) parts.push(`${COLORS.dim}${summary.info} info${COLORS.reset}`);
    console.log(`  ${parts.join('  ')}`);
    console.log();
  }

  // Findings
  if (findings.length === 0) {
    console.log(`  ${COLORS.green}No security issues found.${COLORS.reset}`);
    console.log();
    return;
  }

  console.log(`  ${COLORS.bold}Findings${COLORS.reset}`);
  console.log(`  ${COLORS.dim}${'─'.repeat(50)}${COLORS.reset}`);

  for (const finding of findings) {
    const sev = severityColor(finding.severity);
    const sevLabel = finding.severity.toUpperCase().padEnd(8);

    console.log();
    console.log(`  ${sev}${sevLabel}${COLORS.reset} ${COLORS.bold}${finding.title}${COLORS.reset}  ${COLORS.dim}[${finding.id}]${COLORS.reset}`);

    if (finding.server) {
      console.log(`  ${COLORS.dim}Server:${COLORS.reset} ${finding.server}`);
    }

    console.log(`  ${finding.description}`);

    if (finding.evidence) {
      console.log(`  ${COLORS.dim}Evidence: ${finding.evidence}${COLORS.reset}`);
    }

    if (finding.remediation) {
      console.log(`  ${COLORS.green}Fix: ${finding.remediation}${COLORS.reset}`);
    }
  }

  console.log();
  console.log(`  ${COLORS.dim}${'─'.repeat(50)}${COLORS.reset}`);
  console.log(`  ${summary.totalServers} server${summary.totalServers !== 1 ? 's' : ''} scanned across ${configFiles.length} config file${configFiles.length !== 1 ? 's' : ''}`);
  console.log(`  ${summary.totalFindings} finding${summary.totalFindings !== 1 ? 's' : ''} reported`);
  console.log();
}

/**
 * Output report as JSON
 */
export function printReportJSON(report: ScanReport): void {
  // Strip raw config data to avoid leaking secrets in JSON output
  const safeReport = {
    ...report,
    configFiles: report.configFiles.map((c) => ({
      path: c.path,
      client: c.client,
      servers: Object.keys(c.servers),
    })),
  };

  console.log(JSON.stringify(safeReport, null, 2));
}
