/**
 * Sentinel MCP - Live Server Scanner
 *
 * Connects to running MCP servers and scans their tool descriptions,
 * resource URIs, and prompt templates for security issues:
 *
 * - Tool poisoning (hidden instructions in tool descriptions)
 * - Tool shadowing (tools impersonating other tools)
 * - Data exfiltration patterns in tool descriptions
 * - SSRF in resource URIs
 * - Prompt injection in prompt templates
 * - Excessive permissions / dangerous capabilities
 */

import type { MCPConfigFile, Finding, Scanner } from '../lib/types';
import {
  connectStdio,
  connectHTTP,
  type MCPServerInfo,
  type MCPTool,
  type MCPResource,
  type MCPPrompt,
} from '../lib/mcp-client';
import {
  analyzeForInjection,
  INJECTION_PATTERNS,
  TOOL_POISONING_PATTERNS,
} from '../lib/injection-patterns';
import { validateURL } from '../lib/url-validator';

// ============================================================================
// Dangerous Tool Patterns
// ============================================================================

/**
 * Tool names/descriptions that indicate dangerous capabilities
 */
const DANGEROUS_TOOL_PATTERNS = [
  { pattern: /\b(exec|execute|run|shell|bash|cmd|command|system)\b/i, risk: 'Command execution capability' },
  { pattern: /\b(eval|evaluate)\b/i, risk: 'Code evaluation capability' },
  { pattern: /\b(sudo|root|admin|privilege)/i, risk: 'Elevated privilege operations' },
  { pattern: /\b(delete|remove|drop|truncate|destroy)\s+(all|every|database|table|collection)/i, risk: 'Bulk destructive operations' },
  { pattern: /\b(send|post|upload)\s+(to|email|message|webhook)/i, risk: 'External communication capability' },
  { pattern: /\b(install|download)\s+(package|module|binary|executable)/i, risk: 'Software installation capability' },
];

/**
 * Known-safe tool name prefixes (reduce false positives)
 */
const SAFE_TOOL_PREFIXES = [
  '@modelcontextprotocol/',
  '@anthropic/',
  'mcp-server-',
];

// ============================================================================
// Live Scanner
// ============================================================================

export const liveScanner: Scanner = {
  name: 'Live Server Scanner',

  async scan(configs: MCPConfigFile[]): Promise<Finding[]> {
    const findings: Finding[] = [];
    let findingId = 0;

    // Track tools across all servers for cross-server shadowing detection
    const globalToolRegistry = new Map<string, { server: string; configFile: string; description: string }[]>();

    for (const config of configs) {
      for (const [serverName, serverConfig] of Object.entries(config.servers)) {
        // Connect to the server
        let info: MCPServerInfo;

        process.stderr.write(`  Connecting to ${serverName}...`);

        if (serverConfig.url) {
          info = await connectHTTP(serverConfig, serverName);
        } else {
          info = await connectStdio(serverConfig, serverName);
        }

        if (info.error) {
          process.stderr.write(` \x1b[33mfailed\x1b[0m (${info.error})\n`);
          findings.push({
            id: `LIVE-${++findingId}`,
            severity: 'info',
            category: 'configuration',
            title: `Could not connect to server`,
            description: `Server "${serverName}" could not be reached: ${info.error}`,
            server: serverName,
            configFile: config.path,
            remediation: 'Verify the server command/URL is correct and the server is running.',
          });
          continue;
        }

        const toolCount = info.tools.length;
        const resourceCount = info.resources.length;
        const promptCount = info.prompts.length;
        process.stderr.write(
          ` \x1b[32mconnected\x1b[0m (${info.connectTimeMs}ms) ` +
          `[${toolCount} tools, ${resourceCount} resources, ${promptCount} prompts]\n`
        );

        // Scan tools and register them globally
        for (const tool of info.tools) {
          const toolFindings = scanTool(tool, serverName, config.path, findingId);
          findingId += toolFindings.length;
          findings.push(...toolFindings);

          // Register tool for cross-server shadowing detection
          const entry = { server: serverName, configFile: config.path, description: tool.description || '' };
          const existing = globalToolRegistry.get(tool.name);
          if (existing) {
            existing.push(entry);
          } else {
            globalToolRegistry.set(tool.name, [entry]);
          }
        }

        // Check for duplicate tool names within this server
        const toolNames = info.tools.map((t) => t.name);
        const duplicateNames = findDuplicateToolNames(toolNames);
        for (const dup of duplicateNames) {
          findings.push({
            id: `LIVE-${++findingId}`,
            severity: 'high',
            category: 'tool-poisoning',
            title: `Duplicate tool name within server: "${dup}"`,
            description: `Server "${serverName}" exposes multiple tools named "${dup}". This is unusual and may indicate a compromised server.`,
            server: serverName,
            configFile: config.path,
            remediation: 'Investigate why the server has duplicate tool names.',
          });
        }

        // Scan resources
        for (const resource of info.resources) {
          const resourceFindings = scanResource(resource, serverName, config.path, findingId);
          findingId += resourceFindings.length;
          findings.push(...resourceFindings);
        }

        // Scan prompts
        for (const prompt of info.prompts) {
          const promptFindings = scanPrompt(prompt, serverName, config.path, findingId);
          findingId += promptFindings.length;
          findings.push(...promptFindings);
        }

        // Check for excessive capabilities
        if (info.capabilities) {
          const capFindings = scanCapabilities(info.capabilities, serverName, config.path, findingId);
          findingId += capFindings.length;
          findings.push(...capFindings);
        }
      }
    }

    // Cross-server tool shadowing detection
    const shadowFindings = detectCrossServerShadowing(globalToolRegistry, findingId);
    findings.push(...shadowFindings);

    return findings;
  },
};

// ============================================================================
// Tool Scanning
// ============================================================================

function scanTool(tool: MCPTool, serverName: string, configFile: string, startId: number): Finding[] {
  const findings: Finding[] = [];
  let findingId = startId;

  const description = tool.description || '';
  const schemaStr = tool.inputSchema ? JSON.stringify(tool.inputSchema) : '';
  const fullText = `${tool.name} ${description} ${schemaStr}`;

  // Check tool description for injection patterns
  if (description.length > 10) {
    const analysis = analyzeForInjection(description, [INJECTION_PATTERNS, TOOL_POISONING_PATTERNS]);

    if (analysis.detected) {
      for (const match of analysis.matches) {
        findings.push({
          id: `LIVE-${++findingId}`,
          severity: match.severity,
          category: match.category.includes('Shadowing') || match.category.includes('hidden') || match.category.includes('Exfiltration')
            ? 'tool-poisoning'
            : 'prompt-injection',
          title: `${match.name} in tool "${tool.name}"`,
          description: `Tool "${tool.name}" on server "${serverName}" has a suspicious pattern in its description: ${match.name}.`,
          server: serverName,
          configFile,
          evidence: truncate(description, 150),
          remediation: 'This tool description contains patterns associated with tool poisoning attacks. Review the MCP server source code.',
        });
      }
    }
  }

  // Check for dangerous tool capabilities
  for (const dangerous of DANGEROUS_TOOL_PATTERNS) {
    if (dangerous.pattern.test(tool.name) || dangerous.pattern.test(description)) {
      findings.push({
        id: `LIVE-${++findingId}`,
        severity: 'medium',
        category: 'excessive-permissions',
        title: `${dangerous.risk}: "${tool.name}"`,
        description: `Tool "${tool.name}" on server "${serverName}" has ${dangerous.risk.toLowerCase()}. Ensure this is expected and properly sandboxed.`,
        server: serverName,
        configFile,
        evidence: truncate(`${tool.name}: ${description}`, 150),
        remediation: 'Verify this tool capability is expected. Consider restricting its scope or adding authorization checks.',
      });
    }
  }

  // Check input schema for suspicious default values
  if (tool.inputSchema && typeof tool.inputSchema === 'object') {
    const schemaAnalysis = analyzeForInjection(schemaStr, [INJECTION_PATTERNS]);
    if (schemaAnalysis.detected) {
      findings.push({
        id: `LIVE-${++findingId}`,
        severity: 'high',
        category: 'prompt-injection',
        title: `Injection pattern in tool schema: "${tool.name}"`,
        description: `Tool "${tool.name}" input schema contains injection patterns. Default values or descriptions may be poisoned.`,
        server: serverName,
        configFile,
        evidence: truncate(schemaStr, 150),
        remediation: 'Review the tool input schema for hidden instructions in default values or field descriptions.',
      });
    }
  }

  return findings;
}

// ============================================================================
// Resource Scanning
// ============================================================================

function scanResource(resource: MCPResource, serverName: string, configFile: string, startId: number): Finding[] {
  const findings: Finding[] = [];
  let findingId = startId;

  // Check resource URI for SSRF
  if (resource.uri.startsWith('http://') || resource.uri.startsWith('https://')) {
    const urlResult = validateURL(resource.uri);
    if (!urlResult.valid) {
      findings.push({
        id: `LIVE-${++findingId}`,
        severity: urlResult.severity || 'high',
        category: 'ssrf',
        title: `Unsafe resource URI on "${serverName}"`,
        description: `Resource "${resource.name || resource.uri}" has an unsafe URI: ${urlResult.reason}`,
        server: serverName,
        configFile,
        evidence: `uri: ${resource.uri}`,
        remediation: 'Review the resource URI. It may point to internal services or metadata endpoints.',
      });
    }
  }

  // Check resource description for injection
  if (resource.description && resource.description.length > 10) {
    const analysis = analyzeForInjection(resource.description, [INJECTION_PATTERNS, TOOL_POISONING_PATTERNS]);
    if (analysis.detected) {
      findings.push({
        id: `LIVE-${++findingId}`,
        severity: analysis.risk === 'critical' ? 'critical' : 'high',
        category: 'prompt-injection',
        title: `Injection in resource description: "${resource.name || resource.uri}"`,
        description: `Resource description on "${serverName}" contains suspicious patterns.`,
        server: serverName,
        configFile,
        evidence: truncate(resource.description, 150),
        remediation: 'Review the resource description for hidden instructions.',
      });
    }
  }

  return findings;
}

// ============================================================================
// Prompt Scanning
// ============================================================================

function scanPrompt(prompt: MCPPrompt, serverName: string, configFile: string, startId: number): Finding[] {
  const findings: Finding[] = [];
  let findingId = startId;

  const description = prompt.description || '';

  if (description.length > 10) {
    const analysis = analyzeForInjection(description, [INJECTION_PATTERNS, TOOL_POISONING_PATTERNS]);
    if (analysis.detected) {
      for (const match of analysis.matches) {
        findings.push({
          id: `LIVE-${++findingId}`,
          severity: match.severity,
          category: 'prompt-injection',
          title: `${match.name} in prompt "${prompt.name}"`,
          description: `Prompt "${prompt.name}" on server "${serverName}" contains suspicious patterns in its description.`,
          server: serverName,
          configFile,
          evidence: truncate(description, 150),
          remediation: 'Review the prompt template for hidden instructions or injection payloads.',
        });
      }
    }
  }

  // Check argument descriptions
  if (prompt.arguments) {
    for (const arg of prompt.arguments) {
      if (arg.description && arg.description.length > 10) {
        const argAnalysis = analyzeForInjection(arg.description, [INJECTION_PATTERNS]);
        if (argAnalysis.detected) {
          findings.push({
            id: `LIVE-${++findingId}`,
            severity: 'high',
            category: 'prompt-injection',
            title: `Injection in prompt argument "${arg.name}"`,
            description: `Prompt "${prompt.name}" argument "${arg.name}" on "${serverName}" contains injection patterns.`,
            server: serverName,
            configFile,
            evidence: truncate(arg.description, 150),
            remediation: 'Review prompt argument descriptions for hidden instructions.',
          });
        }
      }
    }
  }

  return findings;
}

// ============================================================================
// Capabilities Scanning
// ============================================================================

function scanCapabilities(
  capabilities: Record<string, unknown>,
  serverName: string,
  configFile: string,
  startId: number
): Finding[] {
  const findings: Finding[] = [];
  let findingId = startId;

  // Check for sampling capability (server can make LLM calls)
  if (capabilities.sampling) {
    findings.push({
      id: `LIVE-${++findingId}`,
      severity: 'medium',
      category: 'excessive-permissions',
      title: `Server requests sampling capability`,
      description: `Server "${serverName}" requests the sampling capability, allowing it to make LLM calls through the client. This could be used for prompt injection amplification.`,
      server: serverName,
      configFile,
      evidence: `capabilities.sampling: ${JSON.stringify(capabilities.sampling)}`,
      remediation: 'Verify the server needs sampling capability. This allows the server to influence LLM behavior.',
    });
  }

  return findings;
}

// ============================================================================
// Cross-Server Tool Shadowing Detection
// ============================================================================

type ToolRegistryEntry = { server: string; configFile: string; description: string };

export function detectCrossServerShadowing(
  registry: Map<string, ToolRegistryEntry[]>,
  startId: number
): Finding[] {
  const findings: Finding[] = [];
  let findingId = startId;

  for (const [toolName, entries] of registry) {
    // Only flag if the same tool name appears on 2+ different servers
    const uniqueServers = new Set(entries.map((e) => e.server));
    if (uniqueServers.size < 2) continue;

    // Determine severity based on description similarity
    // If descriptions differ significantly, it's more likely a malicious shadow
    const descriptions = entries.map((e) => e.description);
    const allSame = descriptions.every((d) => d === descriptions[0]);
    const severity = allSame ? 'medium' : 'high';

    const serverList = entries.map((e) => `"${e.server}" (${e.configFile})`).join(', ');

    findings.push({
      id: `LIVE-${++findingId}`,
      severity,
      category: 'tool-shadowing',
      title: `Cross-server tool shadowing: "${toolName}"`,
      description:
        `Tool "${toolName}" is exposed by ${uniqueServers.size} servers: ${serverList}. ` +
        `When multiple servers provide the same tool name, the client may route calls to the wrong server, ` +
        `allowing a malicious server to intercept operations meant for a legitimate one.`,
      server: [...uniqueServers].join(', '),
      configFile: entries[0].configFile,
      evidence: allSame
        ? `All servers use identical descriptions.`
        : `Descriptions differ across servers: ${entries.map((e) => `[${e.server}]: "${truncate(e.description, 60)}"`).join(' vs ')}`,
      remediation:
        'Rename conflicting tools or remove the untrusted server. ' +
        'If both servers are trusted, use tool name prefixing to disambiguate.',
    });
  }

  return findings;
}

// ============================================================================
// Helpers
// ============================================================================

function truncate(s: string, maxLen: number): string {
  if (s.length <= maxLen) return s;
  return s.substring(0, maxLen) + '...';
}

function findDuplicateToolNames(names: string[]): string[] {
  const seen = new Set<string>();
  const duplicates = new Set<string>();
  for (const name of names) {
    if (seen.has(name)) duplicates.add(name);
    seen.add(name);
  }
  return [...duplicates];
}
