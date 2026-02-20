import { describe, test, expect } from 'bun:test';
import { toSarif } from '../src/scanner/sarif';
import type { ScanReport, Finding } from '../src/lib/types';

// ============================================================================
// Helper
// ============================================================================

function makeReport(findings: Finding[]): ScanReport {
  return {
    timestamp: '2026-01-01T00:00:00.000Z',
    version: '0.1.0',
    score: 100 - findings.length * 25,
    status: findings.length > 0 ? 'fail' : 'pass',
    configFiles: [
      {
        path: '/home/user/.cursor/mcp.json',
        client: 'Cursor',
        servers: { 'test-server': { command: 'node', args: ['server.js'] } },
        raw: {},
      },
    ],
    findings,
    summary: {
      totalServers: 1,
      totalFindings: findings.length,
      critical: findings.filter((f) => f.severity === 'critical').length,
      high: findings.filter((f) => f.severity === 'high').length,
      medium: findings.filter((f) => f.severity === 'medium').length,
      low: findings.filter((f) => f.severity === 'low').length,
      info: findings.filter((f) => f.severity === 'info').length,
    },
  };
}

const CRED_FINDING: Finding = {
  id: 'CRED-001',
  severity: 'critical',
  category: 'credential-exposure',
  title: 'Hardcoded API Key',
  description: 'Anthropic API key found in environment variables',
  server: 'slack-mcp',
  configFile: '/home/user/.cursor/mcp.json',
  evidence: 'ANTHROPIC_API_KEY=sk-ant-***',
  remediation: 'Use a secrets manager or environment variable reference',
};

const SSRF_FINDING: Finding = {
  id: 'SSRF-002',
  severity: 'critical',
  category: 'ssrf',
  title: 'SSRF Risk - Cloud Metadata',
  description: 'Server URL points to AWS metadata endpoint',
  server: 'internal-proxy',
  configFile: '/home/user/.cursor/mcp.json',
};

const TRANSPORT_FINDING: Finding = {
  id: 'TRANSPORT-001',
  severity: 'high',
  category: 'insecure-transport',
  title: 'Unencrypted Transport',
  description: 'Server uses HTTP instead of HTTPS',
  server: 'github',
  configFile: '/home/user/.config/claude/claude_desktop_config.json',
  remediation: 'Switch to HTTPS or use stdio transport',
};

const SUPPLY_FINDING: Finding = {
  id: 'SUPPLY-001',
  severity: 'medium',
  category: 'supply-chain',
  title: 'Unverified npx Package',
  description: 'Package installed via npx without version pinning',
  server: 'slack-mcp',
  configFile: '/home/user/.cursor/mcp.json',
  remediation: 'Pin to a specific version',
};

const INFO_FINDING: Finding = {
  id: 'INFO-001',
  severity: 'info',
  category: 'configuration',
  title: 'Server configured',
  description: 'Server is properly configured',
  server: 'safe-server',
  configFile: '/home/user/.cursor/mcp.json',
};

// ============================================================================
// Tests
// ============================================================================

describe('SARIF output', () => {
  test('produces valid SARIF 2.1.0 structure', () => {
    const sarif = toSarif(makeReport([CRED_FINDING]));

    expect(sarif.$schema).toContain('sarif-schema-2.1.0');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe('mcpsec');
    expect(sarif.runs[0].tool.driver.version).toBe('0.1.0');
    expect(sarif.runs[0].tool.driver.informationUri).toContain('sentinel-mcp');
  });

  test('maps critical severity to error level', () => {
    const sarif = toSarif(makeReport([CRED_FINDING]));
    expect(sarif.runs[0].results[0].level).toBe('error');
  });

  test('maps high severity to error level', () => {
    const sarif = toSarif(makeReport([TRANSPORT_FINDING]));
    expect(sarif.runs[0].results[0].level).toBe('error');
  });

  test('maps medium severity to warning level', () => {
    const sarif = toSarif(makeReport([SUPPLY_FINDING]));
    expect(sarif.runs[0].results[0].level).toBe('warning');
  });

  test('maps info severity to note level', () => {
    const sarif = toSarif(makeReport([INFO_FINDING]));
    expect(sarif.runs[0].results[0].level).toBe('note');
  });

  test('extracts unique rules from findings', () => {
    const sarif = toSarif(makeReport([CRED_FINDING, SSRF_FINDING, TRANSPORT_FINDING]));
    const rules = sarif.runs[0].tool.driver.rules;

    expect(rules).toHaveLength(3);
    expect(rules.map((r) => r.id)).toEqual(['CRED-001', 'SSRF-002', 'TRANSPORT-001']);
  });

  test('deduplicates rules with same ID', () => {
    const dup: Finding = { ...CRED_FINDING, server: 'another-server' };
    const sarif = toSarif(makeReport([CRED_FINDING, dup]));

    expect(sarif.runs[0].tool.driver.rules).toHaveLength(1);
    expect(sarif.runs[0].results).toHaveLength(2);
  });

  test('includes config file as artifact location', () => {
    const sarif = toSarif(makeReport([CRED_FINDING]));
    const location = sarif.runs[0].results[0].locations[0];

    expect(location.physicalLocation.artifactLocation.uri).toBe('/home/user/.cursor/mcp.json');
  });

  test('includes server and evidence in properties', () => {
    const sarif = toSarif(makeReport([CRED_FINDING]));
    const props = sarif.runs[0].results[0].properties;

    expect(props.server).toBe('slack-mcp');
    expect(props.evidence).toBe('ANTHROPIC_API_KEY=sk-ant-***');
    expect(props.severity).toBe('critical');
  });

  test('includes remediation in message text', () => {
    const sarif = toSarif(makeReport([CRED_FINDING]));
    const message = sarif.runs[0].results[0].message.text;

    expect(message).toContain('Anthropic API key found');
    expect(message).toContain('Fix: Use a secrets manager');
  });

  test('handles empty findings', () => {
    const sarif = toSarif(makeReport([]));

    expect(sarif.runs[0].results).toHaveLength(0);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
  });

  test('includes invocation with score and status', () => {
    const sarif = toSarif(makeReport([CRED_FINDING]));
    const invocation = sarif.runs[0].invocations[0];

    expect(invocation.executionSuccessful).toBe(true);
    expect(invocation.properties.score).toBe(75);
    expect(invocation.properties.status).toBe('fail');
  });

  test('rules have security tags from category', () => {
    const sarif = toSarif(makeReport([CRED_FINDING, SSRF_FINDING, SUPPLY_FINDING]));
    const rules = sarif.runs[0].tool.driver.rules;

    const credRule = rules.find((r) => r.id === 'CRED-001')!;
    expect(credRule.properties.tags).toContain('security');
    expect(credRule.properties.tags).toContain('credential-exposure');

    const ssrfRule = rules.find((r) => r.id === 'SSRF-002')!;
    expect(ssrfRule.properties.tags).toContain('ssrf');

    const supplyRule = rules.find((r) => r.id === 'SUPPLY-001')!;
    expect(supplyRule.properties.tags).toContain('supply-chain');
  });

  test('output is valid JSON', () => {
    const sarif = toSarif(makeReport([CRED_FINDING, SSRF_FINDING, TRANSPORT_FINDING, SUPPLY_FINDING]));
    const json = JSON.stringify(sarif);
    const parsed = JSON.parse(json);

    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs[0].results).toHaveLength(4);
  });
});
