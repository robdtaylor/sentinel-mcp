/**
 * Sentinel MCP - Tool Description Scanner
 *
 * Scans MCP tool descriptions, resource URIs, and prompt templates for:
 * - Prompt injection patterns (tool poisoning)
 * - Hidden instructions in tool descriptions
 * - Tool shadowing attempts
 * - Data exfiltration indicators
 * - Command injection in default arguments
 *
 * Maps to OWASP MCP Top 10: Tool Poisoning, Excessive Agency
 */

import type { MCPConfigFile, Finding, Scanner } from '../lib/types';
import {
  analyzeForInjection,
  INJECTION_PATTERNS,
  TOOL_POISONING_PATTERNS,
  COMMAND_INJECTION_PATTERNS,
} from '../lib/injection-patterns';
import { validateURL } from '../lib/url-validator';

export const toolScanner: Scanner = {
  name: 'Tool Description Scanner',

  async scan(configs: MCPConfigFile[]): Promise<Finding[]> {
    const findings: Finding[] = [];
    let findingId = 0;

    for (const config of configs) {
      for (const [serverName, server] of Object.entries(config.servers)) {

        // Scan command + args for injection patterns
        const commandParts = [
          server.command || '',
          ...(server.args || []),
        ];

        for (const part of commandParts) {
          if (!part || part.length < 5) continue;

          // Check for command injection patterns
          const cmdAnalysis = analyzeForInjection(part, [COMMAND_INJECTION_PATTERNS]);
          if (cmdAnalysis.detected) {
            for (const match of cmdAnalysis.matches) {
              findings.push({
                id: `TOOL-${++findingId}`,
                severity: match.severity,
                category: 'command-injection',
                title: `${match.name} in server command`,
                description: `Server "${serverName}" command/args contain a ${match.name.toLowerCase()} pattern.`,
                server: serverName,
                configFile: config.path,
                evidence: part.length > 100 ? part.substring(0, 100) + '...' : part,
                remediation: 'Review and sanitize the command arguments. Avoid shell metacharacters in MCP server configs.',
              });
            }
          }

          // Check for injection patterns in args (tool descriptions are sometimes embedded)
          const injAnalysis = analyzeForInjection(part, [INJECTION_PATTERNS, TOOL_POISONING_PATTERNS]);
          if (injAnalysis.detected) {
            for (const match of injAnalysis.matches) {
              findings.push({
                id: `TOOL-${++findingId}`,
                severity: match.severity,
                category: match.category.includes('Poisoning') || match.category.includes('Shadow')
                  ? 'tool-poisoning'
                  : 'prompt-injection',
                title: `${match.name} in server arguments`,
                description: `Server "${serverName}" arguments contain a ${match.name.toLowerCase()} pattern. This may indicate a tool poisoning attack.`,
                server: serverName,
                configFile: config.path,
                evidence: part.length > 100 ? part.substring(0, 100) + '...' : part,
                remediation: 'Inspect the MCP server source code and tool descriptions for hidden instructions.',
              });
            }
          }
        }

        // Validate server URLs for SSRF
        if (server.url) {
          const urlResult = validateURL(server.url);
          if (!urlResult.valid) {
            findings.push({
              id: `TOOL-${++findingId}`,
              severity: urlResult.severity || 'high',
              category: 'ssrf',
              title: `Unsafe server URL`,
              description: `Server "${serverName}" URL failed validation: ${urlResult.reason}`,
              server: serverName,
              configFile: config.path,
              evidence: `url: ${server.url}`,
              remediation: 'Use a publicly routable HTTPS URL for remote MCP servers.',
            });
          }

          for (const warning of urlResult.warnings) {
            findings.push({
              id: `TOOL-${++findingId}`,
              severity: 'medium',
              category: warning.includes('HTTP') ? 'insecure-transport' : 'configuration',
              title: `URL warning: ${warning}`,
              description: `Server "${serverName}" URL has a security concern: ${warning}`,
              server: serverName,
              configFile: config.path,
              evidence: `url: ${server.url}`,
              remediation: warning.includes('HTTP')
                ? 'Use HTTPS to encrypt data in transit.'
                : 'Review and fix the URL configuration.',
            });
          }
        }

        // Check env vars for suspicious patterns
        if (server.env) {
          const envStr = JSON.stringify(server.env);

          // Check for injection in env values
          const envAnalysis = analyzeForInjection(envStr, [INJECTION_PATTERNS]);
          if (envAnalysis.detected) {
            for (const match of envAnalysis.matches) {
              findings.push({
                id: `TOOL-${++findingId}`,
                severity: match.severity,
                category: 'prompt-injection',
                title: `${match.name} in environment variables`,
                description: `Server "${serverName}" environment variables contain injection patterns.`,
                server: serverName,
                configFile: config.path,
                evidence: 'Injection pattern detected in env configuration',
                remediation: 'Review environment variable values for hidden instructions or injection payloads.',
              });
            }
          }
        }
      }
    }

    return findings;
  },
};
