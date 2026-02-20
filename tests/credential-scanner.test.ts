import { describe, test, expect } from 'bun:test';
import { credentialScanner } from '../src/scanner/credential-scanner';
import type { MCPConfigFile } from '../src/lib/types';

function makeConfig(servers: MCPConfigFile['servers']): MCPConfigFile[] {
  return [{
    path: '/test/config.json',
    client: 'Test',
    servers,
    raw: { mcpServers: servers },
  }];
}

describe('Credential Scanner', () => {
  test('detects Anthropic API key in command args', async () => {
    const configs = makeConfig({
      'test-server': {
        command: 'node',
        args: ['server.js', '--key', 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890'],
      },
    });

    const findings = await credentialScanner.scan(configs);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.title.includes('Anthropic'))).toBe(true);
    expect(findings[0].severity).toBe('critical');
  });

  test('detects OpenAI API key in env', async () => {
    const configs = makeConfig({
      'test-server': {
        command: 'node',
        args: ['server.js'],
        env: {
          OPENAI_API_KEY: 'sk-proj-FAKE_TEST_KEY_DO_NOT_USE_abcdefghijklmnopqrstuvwxyz0123456789FAKE',
        },
      },
    });

    const findings = await credentialScanner.scan(configs);
    expect(findings.some(f => f.title.includes('OpenAI'))).toBe(true);
  });

  test('detects GitHub token', async () => {
    const configs = makeConfig({
      'github-server': {
        command: 'npx',
        args: ['github-mcp', '--token', 'ghp_ABC123def456ghi789jklmnopqrstuvwxyz01'],
      },
    });

    const findings = await credentialScanner.scan(configs);
    expect(findings.some(f => f.title.includes('GitHub'))).toBe(true);
  });

  test('detects credentials embedded in URLs', async () => {
    const configs = makeConfig({
      'db-server': {
        command: 'node',
        args: ['server.js'],
        url: 'https://user:password123@db.example.com:5432/mydb',
      },
    });

    const findings = await credentialScanner.scan(configs);
    expect(findings.some(f => f.category === 'credential-exposure')).toBe(true);
  });

  test('warns on sensitive env var names', async () => {
    const configs = makeConfig({
      'test-server': {
        command: 'node',
        args: ['server.js'],
        env: {
          DATABASE_PASSWORD: 'my-secret-password-here',
        },
      },
    });

    const findings = await credentialScanner.scan(configs);
    expect(findings.some(f => f.title.includes('DATABASE_PASSWORD'))).toBe(true);
  });

  test('passes clean config with no credentials', async () => {
    const configs = makeConfig({
      'clean-server': {
        command: 'npx',
        args: ['@modelcontextprotocol/server-filesystem', '/tmp'],
      },
    });

    const findings = await credentialScanner.scan(configs);
    expect(findings.length).toBe(0);
  });
});
