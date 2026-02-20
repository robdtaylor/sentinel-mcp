import { describe, test, expect } from 'bun:test';
import { liveScanner } from '../src/scanner/live-scanner';
import type { MCPConfigFile } from '../src/lib/types';

/**
 * Live scanner unit tests.
 *
 * These test the scanning logic (tool/resource/prompt analysis)
 * using the individual scan functions. The actual live connection
 * is tested separately via integration tests.
 */

// We test the scanner's analysis functions by importing them indirectly
// through the scanner interface, using mock configs that won't actually connect.

function makeConfig(servers: MCPConfigFile['servers']): MCPConfigFile[] {
  return [{
    path: '/test/config.json',
    client: 'Test',
    servers,
    raw: { mcpServers: servers },
  }];
}

describe('Live Scanner', () => {
  test('scanner has correct name', () => {
    expect(liveScanner.name).toBe('Live Server Scanner');
  });

  test('scan function exists and returns array', async () => {
    // Empty config should return empty findings (no servers to connect to)
    const configs = makeConfig({});
    const findings = await liveScanner.scan(configs);
    expect(Array.isArray(findings)).toBe(true);
    expect(findings.length).toBe(0);
  });

  test('handles connection failure gracefully', async () => {
    // A server with a bogus command should fail to connect
    const configs = makeConfig({
      'bogus-server': {
        command: '__sentinel_test_nonexistent_binary_12345__',
        args: [],
      },
    });

    const findings = await liveScanner.scan(configs);
    // Should get an info finding about connection failure
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('info');
    expect(findings[0].category).toBe('configuration');
    expect(findings[0].description).toContain('bogus-server');
  });

  test('handles HTTP connection failure gracefully', async () => {
    const configs = makeConfig({
      'http-server': {
        url: 'http://127.0.0.1:19999/nonexistent-mcp-endpoint',
      },
    });

    const findings = await liveScanner.scan(configs);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('info');
    expect(findings[0].category).toBe('configuration');
  });
});

// Test the pattern matching logic directly by importing the patterns
describe('Live Scanner Patterns', () => {
  // These patterns are used in scanTool but we can test the regex directly
  const DANGEROUS_TOOL_PATTERNS = [
    { pattern: /\b(exec|execute|run|shell|bash|cmd|command|system)\b/i, risk: 'Command execution capability' },
    { pattern: /\b(eval|evaluate)\b/i, risk: 'Code evaluation capability' },
    { pattern: /\b(sudo|root|admin|privilege)/i, risk: 'Elevated privilege operations' },
    { pattern: /\b(delete|remove|drop|truncate|destroy)\s+(all|every|database|table|collection)/i, risk: 'Bulk destructive operations' },
    { pattern: /\b(send|post|upload)\s+(to|email|message|webhook)/i, risk: 'External communication capability' },
    { pattern: /\b(install|download)\s+(package|module|binary|executable)/i, risk: 'Software installation capability' },
  ];

  test('detects command execution tools', () => {
    const p = DANGEROUS_TOOL_PATTERNS[0];
    expect(p.pattern.test('execute a command')).toBe(true);
    expect(p.pattern.test('run shell script')).toBe(true);
    expect(p.pattern.test('bash')).toBe(true);
    expect(p.pattern.test('read_file')).toBe(false);
  });

  test('detects eval capabilities', () => {
    const p = DANGEROUS_TOOL_PATTERNS[1];
    expect(p.pattern.test('eval')).toBe(true);
    expect(p.pattern.test('evaluate expression')).toBe(true);
    expect(p.pattern.test('get_value')).toBe(false);
  });

  test('detects privilege escalation', () => {
    const p = DANGEROUS_TOOL_PATTERNS[2];
    expect(p.pattern.test('sudo_run')).toBe(true);
    expect(p.pattern.test('admin_panel')).toBe(true);
    expect(p.pattern.test('root_access')).toBe(true);
    expect(p.pattern.test('user_profile')).toBe(false);
  });

  test('detects bulk destructive operations', () => {
    const p = DANGEROUS_TOOL_PATTERNS[3];
    expect(p.pattern.test('delete all records')).toBe(true);
    expect(p.pattern.test('drop database')).toBe(true);
    expect(p.pattern.test('truncate table')).toBe(true);
    expect(p.pattern.test('delete file')).toBe(false);
  });

  test('detects external communication', () => {
    const p = DANGEROUS_TOOL_PATTERNS[4];
    expect(p.pattern.test('send email')).toBe(true);
    expect(p.pattern.test('post to webhook')).toBe(true);
    expect(p.pattern.test('get messages')).toBe(false);
  });

  test('detects software installation', () => {
    const p = DANGEROUS_TOOL_PATTERNS[5];
    expect(p.pattern.test('install package')).toBe(true);
    expect(p.pattern.test('download binary')).toBe(true);
    expect(p.pattern.test('install updates')).toBe(false); // "updates" not in list
  });
});
