/**
 * Sentinel MCP - Configuration Scanner
 *
 * Discovers and parses MCP configuration files from known client locations:
 * - Claude Desktop (claude_desktop_config.json)
 * - Cursor (.cursor/mcp.json)
 * - VS Code (settings.json with mcp servers)
 * - Claude Code (.claude/settings.json or .mcp.json)
 * - Windsurf, Cline, etc.
 */

import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import type { MCPConfigFile, MCPServerConfig, Finding } from '../lib/types';

// ============================================================================
// Known MCP Config Locations
// ============================================================================

interface ConfigLocation {
  client: string;
  paths: string[];
  parser: (raw: unknown) => Record<string, MCPServerConfig> | null;
}

function getConfigLocations(): ConfigLocation[] {
  const home = homedir();
  const platform = process.platform;

  return [
    // Claude Desktop
    {
      client: 'Claude Desktop',
      paths: [
        platform === 'darwin'
          ? join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
          : platform === 'win32'
            ? join(home, 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json')
            : join(home, '.config', 'claude', 'claude_desktop_config.json'),
      ],
      parser: parseClaudeDesktopConfig,
    },
    // Claude Code (project-level)
    {
      client: 'Claude Code',
      paths: [
        join(process.cwd(), '.mcp.json'),
        join(home, '.claude', 'settings.json'),
      ],
      parser: parseClaudeCodeConfig,
    },
    // Cursor
    {
      client: 'Cursor',
      paths: [
        join(home, '.cursor', 'mcp.json'),
      ],
      parser: parseCursorConfig,
    },
    // VS Code
    {
      client: 'VS Code',
      paths: [
        platform === 'darwin'
          ? join(home, 'Library', 'Application Support', 'Code', 'User', 'settings.json')
          : platform === 'win32'
            ? join(home, 'AppData', 'Roaming', 'Code', 'User', 'settings.json')
            : join(home, '.config', 'Code', 'User', 'settings.json'),
      ],
      parser: parseVSCodeConfig,
    },
    // Windsurf
    {
      client: 'Windsurf',
      paths: [
        join(home, '.codeium', 'windsurf', 'mcp_config.json'),
      ],
      parser: parseClaudeDesktopConfig, // Same format
    },
    // Cline
    {
      client: 'Cline',
      paths: [
        join(home, '.cline', 'mcp_settings.json'),
      ],
      parser: parseClineConfig,
    },
  ];
}

// ============================================================================
// Config Parsers
// ============================================================================

function parseClaudeDesktopConfig(raw: unknown): Record<string, MCPServerConfig> | null {
  const config = raw as Record<string, unknown>;
  if (config?.mcpServers && typeof config.mcpServers === 'object') {
    return config.mcpServers as Record<string, MCPServerConfig>;
  }
  return null;
}

function parseClaudeCodeConfig(raw: unknown): Record<string, MCPServerConfig> | null {
  const config = raw as Record<string, unknown>;
  // .mcp.json format
  if (config?.mcpServers && typeof config.mcpServers === 'object') {
    return config.mcpServers as Record<string, MCPServerConfig>;
  }
  // settings.json format
  if (config?.mcpServers && typeof config.mcpServers === 'object') {
    return config.mcpServers as Record<string, MCPServerConfig>;
  }
  return null;
}

function parseCursorConfig(raw: unknown): Record<string, MCPServerConfig> | null {
  const config = raw as Record<string, unknown>;
  if (config?.mcpServers && typeof config.mcpServers === 'object') {
    return config.mcpServers as Record<string, MCPServerConfig>;
  }
  return null;
}

function parseVSCodeConfig(raw: unknown): Record<string, MCPServerConfig> | null {
  const config = raw as Record<string, unknown>;
  // VS Code uses "mcp.servers" key
  const mcpConfig = config?.['mcp'] as Record<string, unknown> | undefined;
  if (mcpConfig?.servers && typeof mcpConfig.servers === 'object') {
    return mcpConfig.servers as Record<string, MCPServerConfig>;
  }
  return null;
}

function parseClineConfig(raw: unknown): Record<string, MCPServerConfig> | null {
  const config = raw as Record<string, unknown>;
  if (config?.mcpServers && typeof config.mcpServers === 'object') {
    return config.mcpServers as Record<string, MCPServerConfig>;
  }
  return null;
}

// ============================================================================
// Discovery
// ============================================================================

/**
 * Discover all MCP configuration files on the system
 */
export function discoverConfigs(): MCPConfigFile[] {
  const configs: MCPConfigFile[] = [];
  const locations = getConfigLocations();

  for (const location of locations) {
    for (const configPath of location.paths) {
      if (!existsSync(configPath)) continue;

      try {
        const content = readFileSync(configPath, 'utf-8');
        const raw = JSON.parse(content);
        const servers = location.parser(raw);

        if (servers && Object.keys(servers).length > 0) {
          configs.push({
            path: configPath,
            client: location.client,
            servers,
            raw,
          });
        }
      } catch {
        // Skip unparseable configs
      }
    }
  }

  return configs;
}

// ============================================================================
// Config-Level Security Checks
// ============================================================================

/**
 * Scan config files for configuration-level security issues
 */
export function scanConfigs(configs: MCPConfigFile[]): Finding[] {
  const findings: Finding[] = [];
  let findingId = 0;

  for (const config of configs) {
    for (const [serverName, server] of Object.entries(config.servers)) {
      // Check for stdio transport with absolute paths to unknown binaries
      if (server.command) {
        // npx/bunx with unknown packages
        // Handle both formats:
        //   "command": "npx -y some-pkg"  (inline)
        //   "command": "npx", "args": ["-y", "some-pkg"]  (split)
        const cmdBase = server.command.split(/\s+/)[0];
        if (/^(npx|bunx|pnpx)$/.test(cmdBase)) {
          // Extract package name from inline command or args array
          let pkg: string | undefined;
          const inlineParts = server.command.split(/\s+/).slice(1);
          const allArgs = [...inlineParts, ...(server.args || [])];
          // Find the first arg that isn't a flag (skip -y, --yes, etc.)
          for (const arg of allArgs) {
            if (!arg.startsWith('-')) {
              pkg = arg;
              break;
            }
          }

          if (pkg && !pkg.startsWith('@anthropic') && !pkg.startsWith('@modelcontextprotocol')) {
            const fullCommand = [server.command, ...(server.args || [])].join(' ');
            findings.push({
              id: `CFG-${++findingId}`,
              severity: 'medium',
              category: 'supply-chain',
              title: `Unverified npm package: ${pkg}`,
              description: `Server "${serverName}" uses npx/bunx to run "${pkg}". This package is downloaded and executed at runtime without integrity verification.`,
              server: serverName,
              configFile: config.path,
              evidence: `command: ${fullCommand}`,
              remediation: 'Pin the package version and verify its integrity. Consider installing locally instead of using npx.',
            });
          }
        }

        // Docker without security flags
        if (/^docker\s+run\b/.test(server.command) && !/--security-opt|--cap-drop/.test(server.command)) {
          findings.push({
            id: `CFG-${++findingId}`,
            severity: 'medium',
            category: 'excessive-permissions',
            title: `Docker container without security restrictions`,
            description: `Server "${serverName}" runs a Docker container without --security-opt or --cap-drop flags.`,
            server: serverName,
            configFile: config.path,
            evidence: `command: ${server.command}`,
            remediation: 'Add --security-opt=no-new-privileges and --cap-drop=ALL to the docker run command.',
          });
        }

        // Privileged docker
        if (/docker\s+run\b.*--privileged/.test(server.command)) {
          findings.push({
            id: `CFG-${++findingId}`,
            severity: 'critical',
            category: 'excessive-permissions',
            title: `Privileged Docker container`,
            description: `Server "${serverName}" runs a Docker container with --privileged, giving it full host access.`,
            server: serverName,
            configFile: config.path,
            evidence: `command: ${server.command}`,
            remediation: 'Remove --privileged flag and use specific --cap-add flags for required capabilities only.',
          });
        }
      }

      // Check for HTTP (non-HTTPS) transport URLs
      if (server.url && server.url.startsWith('http://')) {
        findings.push({
          id: `CFG-${++findingId}`,
          severity: 'high',
          category: 'insecure-transport',
          title: `Unencrypted HTTP transport`,
          description: `Server "${serverName}" uses HTTP instead of HTTPS. API keys and conversation data are transmitted in cleartext.`,
          server: serverName,
          configFile: config.path,
          evidence: `url: ${server.url}`,
          remediation: 'Use HTTPS (wss:// or https://) for the server URL.',
        });
      }
    }
  }

  return findings;
}
