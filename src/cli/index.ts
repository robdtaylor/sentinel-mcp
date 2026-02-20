#!/usr/bin/env bun

/**
 * Sentinel MCP - CLI Entry Point
 *
 * Usage:
 *   sentinel-mcp scan          Scan all detected MCP configurations
 *   sentinel-mcp scan --json   Output results as JSON
 *   sentinel-mcp scan --path   Scan a specific config file
 */

import { discoverConfigs, scanConfigs } from '../scanner/config-scanner';
import { credentialScanner } from '../scanner/credential-scanner';
import { toolScanner } from '../scanner/tool-scanner';
import { liveScanner } from '../scanner/live-scanner';
import { generateReport, printReport, printReportJSON } from '../scanner/report';
import { printReportSARIF } from '../scanner/sarif';
import type { Finding, MCPConfigFile } from '../lib/types';

// ============================================================================
// CLI
// ============================================================================

const HELP = `
  mcpsec - Security Scanner for Model Context Protocol

  Usage:
    mcpsec scan [options]

  Options:
    --live          Connect to running MCP servers and scan live
    --json          Output results as JSON
    --sarif         Output results as SARIF 2.1.0 (for GitHub Code Scanning)
    --path <file>   Scan a specific config file
    --no-color      Disable colored output
    --help, -h      Show this help message
    --version, -v   Show version

  Examples:
    mcpsec scan
    mcpsec scan --live
    mcpsec scan --json
    mcpsec scan --path ~/.cursor/mcp.json
`;

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === '--help' || command === '-h') {
    console.log(HELP);
    process.exit(0);
  }

  if (command === '--version' || command === '-v') {
    console.log('mcpsec v0.1.0');
    process.exit(0);
  }

  if (command !== 'scan') {
    console.error(`Unknown command: ${command}`);
    console.log(HELP);
    process.exit(1);
  }

  // Parse scan options
  const jsonOutput = args.includes('--json');
  const sarifOutput = args.includes('--sarif');
  const liveMode = args.includes('--live');
  const pathIndex = args.indexOf('--path');
  const specificPath = pathIndex !== -1 ? args[pathIndex + 1] : undefined;

  if (args.includes('--no-color')) {
    // Disable colors by overriding environment
    process.env.NO_COLOR = '1';
  }

  // Discover configs
  let configs: MCPConfigFile[];

  if (specificPath) {
    // Scan a specific file
    const { existsSync, readFileSync } = await import('fs');
    if (!existsSync(specificPath)) {
      console.error(`File not found: ${specificPath}`);
      process.exit(1);
    }

    try {
      const content = readFileSync(specificPath, 'utf-8');
      const raw = JSON.parse(content);

      // Try to detect format
      const servers = raw.mcpServers || raw.mcp?.servers || {};
      if (Object.keys(servers).length === 0) {
        console.error(`No MCP servers found in ${specificPath}`);
        process.exit(1);
      }

      configs = [{
        path: specificPath,
        client: 'Custom',
        servers,
        raw,
      }];
    } catch (e) {
      console.error(`Failed to parse ${specificPath}: ${e}`);
      process.exit(1);
    }
  } else {
    configs = discoverConfigs();
  }

  // Run all scanners
  const allFindings: Finding[] = [];

  // Config-level checks
  const configFindings = scanConfigs(configs);
  allFindings.push(...configFindings);

  // Credential scanner
  const credFindings = await credentialScanner.scan(configs);
  allFindings.push(...credFindings);

  // Tool/injection scanner
  const toolFindings = await toolScanner.scan(configs);
  allFindings.push(...toolFindings);

  // Live server scanner (connects to running servers)
  if (liveMode) {
    if (!jsonOutput) {
      process.stderr.write('\n\x1b[1m🔴 Live Server Scan\x1b[0m\n');
    }
    const liveFindings = await liveScanner.scan(configs);
    allFindings.push(...liveFindings);
  }

  // Generate report
  const report = generateReport(configs, allFindings);

  // Output
  if (sarifOutput) {
    printReportSARIF(report);
  } else if (jsonOutput) {
    printReportJSON(report);
  } else {
    printReport(report);
  }

  // Exit code based on findings
  if (report.summary.critical > 0) {
    process.exit(2); // Critical findings
  } else if (report.summary.high > 0) {
    process.exit(1); // High findings
  }

  process.exit(0);
}

main().catch((err) => {
  console.error('Sentinel scan failed:', err);
  process.exit(1);
});
