/**
 * Sentinel MCP - Baseline / Diff Engine
 *
 * Compare scan results against a saved baseline to track
 * new findings, fixed findings, and score trends over time.
 */

import { readFileSync, writeFileSync } from 'fs';
import type { Finding, ScanReport, BaselineDiff } from '../lib/types';

export const DEFAULT_BASELINE_PATH = '.mcpsec-baseline.json';

// ============================================================================
// Fingerprinting
// ============================================================================

/**
 * Generate a stable fingerprint for a finding.
 * Same rule + same server + same config = same finding across scans.
 * Evidence is excluded because it contains rotating/masked secrets.
 */
export function findingFingerprint(finding: Finding): string {
  return `${finding.id}:${finding.server ?? ''}:${finding.configFile ?? ''}`;
}

// ============================================================================
// Diff Engine
// ============================================================================

/**
 * Diff current findings against a baseline.
 * Returns new, fixed, and unchanged findings plus score delta.
 */
export function diffFindings(
  current: Finding[],
  baseline: ScanReport
): BaselineDiff {
  const baselineFingerprints = new Map<string, Finding>();
  for (const f of baseline.findings) {
    baselineFingerprints.set(findingFingerprint(f), f);
  }

  const currentFingerprints = new Set<string>();
  const newFindings: Finding[] = [];
  const unchangedFindings: Finding[] = [];

  for (const f of current) {
    const fp = findingFingerprint(f);
    currentFingerprints.add(fp);

    if (baselineFingerprints.has(fp)) {
      unchangedFindings.push(f);
    } else {
      newFindings.push(f);
    }
  }

  const fixedFindings: Finding[] = [];
  for (const [fp, f] of baselineFingerprints) {
    if (!currentFingerprints.has(fp)) {
      fixedFindings.push(f);
    }
  }

  return {
    newFindings,
    fixedFindings,
    unchangedFindings,
    baselineTimestamp: baseline.timestamp,
    baselineScore: baseline.score,
    scoreDelta: 0, // caller sets this after report generation
  };
}

// ============================================================================
// File I/O
// ============================================================================

/**
 * Load and validate a baseline JSON file.
 * Throws on missing file or invalid JSON.
 */
export function loadBaseline(path: string): ScanReport {
  let content: string;
  try {
    content = readFileSync(path, 'utf-8');
  } catch {
    throw new Error(`Baseline file not found: ${path}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new Error(`Invalid JSON in baseline file: ${path}`);
  }

  const report = parsed as ScanReport;
  if (!report.timestamp || !report.findings || typeof report.score !== 'number') {
    throw new Error(`Invalid baseline format: missing required fields (timestamp, findings, score)`);
  }

  return report;
}

/**
 * Save a scan report as baseline JSON.
 * Strips raw config data to avoid leaking secrets (same as printReportJSON).
 */
export function saveBaseline(report: ScanReport, path: string): void {
  const safeReport = {
    ...report,
    configFiles: report.configFiles.map((c) => ({
      path: c.path,
      client: c.client,
      servers: Object.keys(c.servers),
    })),
  };

  writeFileSync(path, JSON.stringify(safeReport, null, 2) + '\n');
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
  cyan: '\x1b[36m',
};

/**
 * Print a baseline diff report to the console.
 */
export function printBaselineDiff(diff: BaselineDiff, currentScore: number): void {
  const delta = diff.scoreDelta;
  const deltaStr = delta > 0 ? `+${delta}` : `${delta}`;
  const deltaColor = delta > 0 ? COLORS.green : delta < 0 ? COLORS.red : COLORS.dim;

  const dateStr = diff.baselineTimestamp.split('T')[0];

  console.log();
  console.log(`  ${COLORS.bold}Baseline Comparison${COLORS.reset}`);
  console.log(`  ${COLORS.dim}${'─'.repeat(50)}${COLORS.reset}`);
  console.log(`  ${COLORS.dim}Baseline:${COLORS.reset} ${DEFAULT_BASELINE_PATH} (${dateStr})`);
  console.log(`  ${COLORS.dim}Score:${COLORS.reset}    ${diff.baselineScore} → ${currentScore}  ${deltaColor}(${deltaStr})${COLORS.reset}`);
  console.log();

  const parts: string[] = [];
  if (diff.fixedFindings.length > 0) {
    parts.push(`${COLORS.green}${diff.fixedFindings.length} fixed${COLORS.reset}`);
  }
  if (diff.newFindings.length > 0) {
    parts.push(`${COLORS.red}${diff.newFindings.length} new${COLORS.reset}`);
  }
  if (diff.unchangedFindings.length > 0) {
    parts.push(`${COLORS.dim}${diff.unchangedFindings.length} unchanged${COLORS.reset}`);
  }
  console.log(`  ${parts.join('   ')}`);

  if (diff.fixedFindings.length > 0) {
    console.log();
    console.log(`  ${COLORS.green}${COLORS.bold}FIXED${COLORS.reset}`);
    for (const f of diff.fixedFindings) {
      const server = f.server ? ` (${f.server})` : '';
      console.log(`    ${COLORS.green}✓${COLORS.reset} ${COLORS.dim}${f.id}${COLORS.reset}  ${f.title}${COLORS.dim}${server}${COLORS.reset}`);
    }
  }

  if (diff.newFindings.length > 0) {
    console.log();
    console.log(`  ${COLORS.red}${COLORS.bold}NEW${COLORS.reset}`);
    for (const f of diff.newFindings) {
      const server = f.server ? ` (${f.server})` : '';
      console.log(`    ${COLORS.red}✗${COLORS.reset} ${COLORS.dim}${f.id}${COLORS.reset}  ${f.title}${COLORS.dim}${server}${COLORS.reset}`);
    }
  }

  console.log();
  console.log(`  ${COLORS.dim}${'─'.repeat(50)}${COLORS.reset}`);
  console.log();
}
