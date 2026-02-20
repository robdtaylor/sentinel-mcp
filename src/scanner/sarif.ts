/**
 * Sentinel MCP - SARIF Output
 *
 * Converts scan reports to SARIF 2.1.0 format for GitHub Code Scanning
 * and other SARIF-compatible tools.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import type { ScanReport, Finding, Severity, FindingCategory } from '../lib/types';

const SARIF_SCHEMA =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json';
const TOOL_INFO_URI = 'https://github.com/robdtaylor/sentinel-mcp';

// ============================================================================
// SARIF Types (subset of 2.1.0 spec)
// ============================================================================

interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
  invocations: SarifInvocation[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: SarifLevel };
  properties: { tags: string[] };
}

interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations: SarifLocation[];
  properties: Record<string, unknown>;
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
  };
}

interface SarifInvocation {
  executionSuccessful: boolean;
  properties: Record<string, unknown>;
}

type SarifLevel = 'error' | 'warning' | 'note' | 'none';

// ============================================================================
// Conversion
// ============================================================================

/**
 * Map mcpsec severity to SARIF level
 */
function toSarifLevel(severity: Severity): SarifLevel {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
  }
}

/**
 * Map finding category to SARIF tags
 */
function categoryTags(category: FindingCategory): string[] {
  const tags = ['security'];
  switch (category) {
    case 'credential-exposure':
      tags.push('credential-exposure', 'secrets');
      break;
    case 'prompt-injection':
    case 'tool-poisoning':
    case 'tool-shadowing':
      tags.push('tool-poisoning', 'ai-safety');
      break;
    case 'ssrf':
      tags.push('ssrf', 'network');
      break;
    case 'command-injection':
      tags.push('command-injection', 'injection');
      break;
    case 'insecure-transport':
      tags.push('insecure-transport', 'encryption');
      break;
    case 'excessive-permissions':
      tags.push('excessive-permissions', 'misconfiguration');
      break;
    case 'supply-chain':
      tags.push('supply-chain', 'dependency');
      break;
    case 'configuration':
      tags.push('misconfiguration');
      break;
  }
  return tags;
}

/**
 * Generate a stable rule name from a finding ID (e.g. "CRED-001" -> "HardcodedCredential")
 */
function ruleNameFromId(id: string): string {
  // Strip numeric suffix and convert to PascalCase
  return id
    .replace(/-\d+$/, '')
    .split('-')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join('');
}

/**
 * Extract unique rules from findings
 */
function extractRules(findings: Finding[]): SarifRule[] {
  const seen = new Map<string, SarifRule>();

  for (const finding of findings) {
    const ruleId = finding.id;
    if (seen.has(ruleId)) continue;

    seen.set(ruleId, {
      id: ruleId,
      name: ruleNameFromId(ruleId),
      shortDescription: { text: finding.title },
      defaultConfiguration: { level: toSarifLevel(finding.severity) },
      properties: { tags: categoryTags(finding.category) },
    });
  }

  return Array.from(seen.values());
}

/**
 * Convert a finding to a SARIF result
 */
function toSarifResult(finding: Finding): SarifResult {
  const uri = finding.configFile || 'unknown';

  const message = [finding.description];
  if (finding.remediation) {
    message.push(`Fix: ${finding.remediation}`);
  }

  const properties: Record<string, unknown> = {};
  if (finding.server) properties.server = finding.server;
  if (finding.evidence) properties.evidence = finding.evidence;
  if (finding.severity) properties.severity = finding.severity;

  return {
    ruleId: finding.id,
    level: toSarifLevel(finding.severity),
    message: { text: message.join(' ') },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri },
        },
      },
    ],
    properties,
  };
}

/**
 * Convert a ScanReport to SARIF 2.1.0 log
 */
export function toSarif(report: ScanReport): SarifLog {
  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcpsec',
            version: report.version,
            informationUri: TOOL_INFO_URI,
            rules: extractRules(report.findings),
          },
        },
        results: report.findings.map(toSarifResult),
        invocations: [
          {
            executionSuccessful: true,
            properties: {
              score: report.score,
              status: report.status,
              timestamp: report.timestamp,
            },
          },
        ],
      },
    ],
  };
}

/**
 * Print SARIF output to stdout
 */
export function printReportSARIF(report: ScanReport): void {
  console.log(JSON.stringify(toSarif(report), null, 2));
}
