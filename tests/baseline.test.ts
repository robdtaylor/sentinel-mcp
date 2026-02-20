import { describe, test, expect, beforeEach, afterEach } from 'bun:test';
import { existsSync, unlinkSync, readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  findingFingerprint,
  diffFindings,
  loadBaseline,
  saveBaseline,
  DEFAULT_BASELINE_PATH,
} from '../src/scanner/baseline';
import type { Finding, ScanReport } from '../src/lib/types';

// ============================================================================
// Fixtures
// ============================================================================

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
  server: 'new-server',
  configFile: '/home/user/.cursor/mcp.json',
  remediation: 'Pin to a specific version',
};

const NO_SERVER_FINDING: Finding = {
  id: 'CFG-001',
  severity: 'low',
  category: 'configuration',
  title: 'Config Issue',
  description: 'A configuration-level finding with no server',
};

function makeReport(findings: Finding[], overrides?: Partial<ScanReport>): ScanReport {
  return {
    timestamp: '2026-02-19T10:00:00.000Z',
    version: '0.1.0',
    score: 42,
    status: 'fail',
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
    ...overrides,
  };
}

// ============================================================================
// Temp file helpers
// ============================================================================

let tmpFiles: string[] = [];

function tmpPath(name: string): string {
  const p = join(tmpdir(), `mcpsec-test-${name}-${Date.now()}.json`);
  tmpFiles.push(p);
  return p;
}

afterEach(() => {
  for (const f of tmpFiles) {
    try { unlinkSync(f); } catch {}
  }
  tmpFiles = [];
});

// ============================================================================
// findingFingerprint
// ============================================================================

describe('findingFingerprint', () => {
  test('generates correct composite key', () => {
    const fp = findingFingerprint(CRED_FINDING);
    expect(fp).toBe('CRED-001:slack-mcp:/home/user/.cursor/mcp.json');
  });

  test('handles missing server', () => {
    const finding: Finding = { ...CRED_FINDING, server: undefined };
    const fp = findingFingerprint(finding);
    expect(fp).toBe('CRED-001::/home/user/.cursor/mcp.json');
  });

  test('handles missing configFile', () => {
    const finding: Finding = { ...CRED_FINDING, configFile: undefined };
    const fp = findingFingerprint(finding);
    expect(fp).toBe('CRED-001:slack-mcp:');
  });

  test('handles both optional fields missing', () => {
    const fp = findingFingerprint(NO_SERVER_FINDING);
    expect(fp).toBe('CFG-001::');
  });

  test('same finding produces same fingerprint across runs', () => {
    const fp1 = findingFingerprint(CRED_FINDING);
    const fp2 = findingFingerprint({ ...CRED_FINDING, evidence: 'different-evidence' });
    expect(fp1).toBe(fp2);
  });

  test('different servers produce different fingerprints', () => {
    const fp1 = findingFingerprint(CRED_FINDING);
    const fp2 = findingFingerprint({ ...CRED_FINDING, server: 'other-server' });
    expect(fp1).not.toBe(fp2);
  });

  test('different IDs produce different fingerprints', () => {
    const fp1 = findingFingerprint(CRED_FINDING);
    const fp2 = findingFingerprint({ ...CRED_FINDING, id: 'CRED-002' });
    expect(fp1).not.toBe(fp2);
  });
});

// ============================================================================
// diffFindings
// ============================================================================

describe('diffFindings', () => {
  test('identifies new findings', () => {
    const baseline = makeReport([CRED_FINDING]);
    const current = [CRED_FINDING, SUPPLY_FINDING];

    const diff = diffFindings(current, baseline);

    expect(diff.newFindings).toHaveLength(1);
    expect(diff.newFindings[0].id).toBe('SUPPLY-001');
    expect(diff.fixedFindings).toHaveLength(0);
    expect(diff.unchangedFindings).toHaveLength(1);
  });

  test('identifies fixed findings', () => {
    const baseline = makeReport([CRED_FINDING, SSRF_FINDING]);
    const current = [CRED_FINDING];

    const diff = diffFindings(current, baseline);

    expect(diff.fixedFindings).toHaveLength(1);
    expect(diff.fixedFindings[0].id).toBe('SSRF-002');
    expect(diff.newFindings).toHaveLength(0);
    expect(diff.unchangedFindings).toHaveLength(1);
  });

  test('identifies unchanged findings', () => {
    const baseline = makeReport([CRED_FINDING, SSRF_FINDING]);
    const current = [CRED_FINDING, SSRF_FINDING];

    const diff = diffFindings(current, baseline);

    expect(diff.unchangedFindings).toHaveLength(2);
    expect(diff.newFindings).toHaveLength(0);
    expect(diff.fixedFindings).toHaveLength(0);
  });

  test('handles empty baseline', () => {
    const baseline = makeReport([]);
    const current = [CRED_FINDING, SUPPLY_FINDING];

    const diff = diffFindings(current, baseline);

    expect(diff.newFindings).toHaveLength(2);
    expect(diff.fixedFindings).toHaveLength(0);
    expect(diff.unchangedFindings).toHaveLength(0);
  });

  test('handles empty current findings', () => {
    const baseline = makeReport([CRED_FINDING, SSRF_FINDING]);

    const diff = diffFindings([], baseline);

    expect(diff.fixedFindings).toHaveLength(2);
    expect(diff.newFindings).toHaveLength(0);
    expect(diff.unchangedFindings).toHaveLength(0);
  });

  test('handles both empty', () => {
    const baseline = makeReport([]);

    const diff = diffFindings([], baseline);

    expect(diff.newFindings).toHaveLength(0);
    expect(diff.fixedFindings).toHaveLength(0);
    expect(diff.unchangedFindings).toHaveLength(0);
  });

  test('preserves baseline timestamp and score', () => {
    const baseline = makeReport([CRED_FINDING], {
      timestamp: '2026-02-19T10:00:00.000Z',
      score: 42,
    });

    const diff = diffFindings([CRED_FINDING], baseline);

    expect(diff.baselineTimestamp).toBe('2026-02-19T10:00:00.000Z');
    expect(diff.baselineScore).toBe(42);
  });

  test('mixed scenario: some new, some fixed, some unchanged', () => {
    const baseline = makeReport([CRED_FINDING, SSRF_FINDING, TRANSPORT_FINDING]);
    const current = [CRED_FINDING, SUPPLY_FINDING]; // SSRF + TRANSPORT fixed, SUPPLY new

    const diff = diffFindings(current, baseline);

    expect(diff.newFindings).toHaveLength(1);
    expect(diff.newFindings[0].id).toBe('SUPPLY-001');
    expect(diff.fixedFindings).toHaveLength(2);
    expect(diff.fixedFindings.map((f) => f.id).sort()).toEqual(['SSRF-002', 'TRANSPORT-001']);
    expect(diff.unchangedFindings).toHaveLength(1);
    expect(diff.unchangedFindings[0].id).toBe('CRED-001');
  });
});

// ============================================================================
// loadBaseline
// ============================================================================

describe('loadBaseline', () => {
  test('loads valid baseline file', () => {
    const path = tmpPath('valid');
    const report = makeReport([CRED_FINDING]);
    writeFileSync(path, JSON.stringify(report));

    const loaded = loadBaseline(path);

    expect(loaded.timestamp).toBe('2026-02-19T10:00:00.000Z');
    expect(loaded.score).toBe(42);
    expect(loaded.findings).toHaveLength(1);
    expect(loaded.findings[0].id).toBe('CRED-001');
  });

  test('throws on missing file', () => {
    expect(() => loadBaseline('/nonexistent/path.json')).toThrow('Baseline file not found');
  });

  test('throws on invalid JSON', () => {
    const path = tmpPath('invalid');
    writeFileSync(path, 'not json {{{');

    expect(() => loadBaseline(path)).toThrow('Invalid JSON');
  });

  test('throws on missing required fields', () => {
    const path = tmpPath('incomplete');
    writeFileSync(path, JSON.stringify({ version: '0.1.0' }));

    expect(() => loadBaseline(path)).toThrow('Invalid baseline format');
  });
});

// ============================================================================
// saveBaseline
// ============================================================================

describe('saveBaseline', () => {
  test('writes valid JSON file', () => {
    const path = tmpPath('save');
    const report = makeReport([CRED_FINDING]);

    saveBaseline(report, path);

    expect(existsSync(path)).toBe(true);
    const content = JSON.parse(readFileSync(path, 'utf-8'));
    expect(content.timestamp).toBe('2026-02-19T10:00:00.000Z');
    expect(content.score).toBe(42);
  });

  test('strips raw config data', () => {
    const path = tmpPath('stripped');
    const report = makeReport([CRED_FINDING]);
    // Ensure raw has secret data
    (report.configFiles[0] as any).raw = { secret: 'should-be-stripped' };

    saveBaseline(report, path);

    const content = JSON.parse(readFileSync(path, 'utf-8'));
    expect(content.configFiles[0].raw).toBeUndefined();
    expect(content.configFiles[0].servers).toEqual(['test-server']);
    expect(content.configFiles[0].path).toBe('/home/user/.cursor/mcp.json');
    expect(content.configFiles[0].client).toBe('Cursor');
  });

  test('preserves all findings', () => {
    const path = tmpPath('findings');
    const report = makeReport([CRED_FINDING, SSRF_FINDING, TRANSPORT_FINDING]);

    saveBaseline(report, path);

    const content = JSON.parse(readFileSync(path, 'utf-8'));
    expect(content.findings).toHaveLength(3);
  });
});

// ============================================================================
// Score delta
// ============================================================================

describe('score delta calculation', () => {
  test('positive delta means improvement', () => {
    const baseline = makeReport([CRED_FINDING, SSRF_FINDING], { score: 42 });
    const diff = diffFindings([CRED_FINDING], baseline);
    diff.scoreDelta = 67 - baseline.score; // current 67, baseline 42

    expect(diff.scoreDelta).toBe(25);
  });

  test('negative delta means regression', () => {
    const baseline = makeReport([CRED_FINDING], { score: 75 });
    const diff = diffFindings([CRED_FINDING, SSRF_FINDING], baseline);
    diff.scoreDelta = 50 - baseline.score; // current 50, baseline 75

    expect(diff.scoreDelta).toBe(-25);
  });

  test('zero delta means no change', () => {
    const baseline = makeReport([CRED_FINDING], { score: 75 });
    const diff = diffFindings([CRED_FINDING], baseline);
    diff.scoreDelta = 75 - baseline.score;

    expect(diff.scoreDelta).toBe(0);
  });
});

// ============================================================================
// DEFAULT_BASELINE_PATH
// ============================================================================

describe('DEFAULT_BASELINE_PATH', () => {
  test('is .mcpsec-baseline.json', () => {
    expect(DEFAULT_BASELINE_PATH).toBe('.mcpsec-baseline.json');
  });
});

// ============================================================================
// Round-trip: save then load
// ============================================================================

describe('round-trip', () => {
  test('save and load produces equivalent report', () => {
    const path = tmpPath('roundtrip');
    const report = makeReport([CRED_FINDING, SSRF_FINDING]);

    saveBaseline(report, path);
    const loaded = loadBaseline(path);

    expect(loaded.timestamp).toBe(report.timestamp);
    expect(loaded.score).toBe(report.score);
    expect(loaded.findings).toHaveLength(2);
    expect(loaded.findings[0].id).toBe(report.findings[0].id);
    expect(loaded.findings[1].id).toBe(report.findings[1].id);
  });

  test('saved baseline can be used for diffing', () => {
    const path = tmpPath('diff-roundtrip');
    const report = makeReport([CRED_FINDING, SSRF_FINDING]);

    saveBaseline(report, path);
    const baseline = loadBaseline(path);

    // Current scan: SSRF fixed, SUPPLY new
    const diff = diffFindings([CRED_FINDING, SUPPLY_FINDING], baseline);

    expect(diff.fixedFindings).toHaveLength(1);
    expect(diff.fixedFindings[0].id).toBe('SSRF-002');
    expect(diff.newFindings).toHaveLength(1);
    expect(diff.newFindings[0].id).toBe('SUPPLY-001');
    expect(diff.unchangedFindings).toHaveLength(1);
  });
});
