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
import { registryScanner } from '../scanner/registry-scanner';
import { generateReport, printReport, printReportJSON } from '../scanner/report';
import { printReportSARIF } from '../scanner/sarif';
import {
  loadBaseline,
  saveBaseline,
  diffFindings,
  printBaselineDiff,
  DEFAULT_BASELINE_PATH,
} from '../scanner/baseline';
import type { Finding, MCPConfigFile } from '../lib/types';

// ============================================================================
// CLI
// ============================================================================

const HELP = `
  mcpsec - Security Scanner for Model Context Protocol

  Usage:
    mcpsec scan [options]

  Options:
    --live                   Connect to running MCP servers and scan live
    --json                   Output results as JSON
    --sarif                  Output results as SARIF 2.1.0 (for GitHub Code Scanning)
    --path <file>            Scan a specific config file
    --registry               Scan servers from the official MCP registry
    --limit <n>              Max servers to fetch from registry (default: 20)
    --search <query>         Search registry servers by keyword
    --server <name>          Scan a specific registry server by name
    --save-baseline [file]   Save scan results as baseline (default: ${DEFAULT_BASELINE_PATH})
    --baseline [file]        Compare scan against baseline and show diff
    --no-color               Disable colored output
    --help, -h               Show this help message
    --version, -v            Show version

  Examples:
    mcpsec scan
    mcpsec scan --live
    mcpsec scan --json
    mcpsec scan --path ~/.cursor/mcp.json
    mcpsec scan --registry
    mcpsec scan --registry --limit 50
    mcpsec scan --registry --search "database"
    mcpsec scan --registry --server "filesystem"
    mcpsec scan --registry --json
    mcpsec scan --save-baseline
    mcpsec scan --baseline
    mcpsec scan --baseline --json
`;

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === '--help' || command === '-h') {
    console.log(HELP);
    process.exit(0);
  }

  if (command === '--version' || command === '-v') {
    console.log('mcpsec v0.3.0');
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

  // Registry flags
  const registryMode = args.includes('--registry');
  const limitIndex = args.indexOf('--limit');
  const registryLimit = limitIndex !== -1 ? parseInt(args[limitIndex + 1], 10) || 20 : 20;
  const searchIndex = args.indexOf('--search');
  const registrySearch = searchIndex !== -1 ? args[searchIndex + 1] : undefined;
  const serverIndex = args.indexOf('--server');
  const registryServer = serverIndex !== -1 ? args[serverIndex + 1] : undefined;

  // Baseline flags
  const saveBaselineIndex = args.indexOf('--save-baseline');
  const saveBaselineMode = saveBaselineIndex !== -1;
  const saveBaselinePath = saveBaselineMode
    ? (args[saveBaselineIndex + 1] && !args[saveBaselineIndex + 1].startsWith('--')
        ? args[saveBaselineIndex + 1]
        : DEFAULT_BASELINE_PATH)
    : undefined;

  const baselineIndex = args.indexOf('--baseline');
  const baselineMode = baselineIndex !== -1;
  const baselinePath = baselineMode
    ? (args[baselineIndex + 1] && !args[baselineIndex + 1].startsWith('--')
        ? args[baselineIndex + 1]
        : DEFAULT_BASELINE_PATH)
    : undefined;

  if (args.includes('--no-color')) {
    // Disable colors by overriding environment
    process.env.NO_COLOR = '1';
  }

  // Discover configs
  let configs: MCPConfigFile[];
  const allFindings: Finding[] = [];

  if (registryMode) {
    // Registry scanning mode
    if (!jsonOutput && !sarifOutput) {
      const label = registryServer
        ? `server "${registryServer}"`
        : registrySearch
          ? `"${registrySearch}" (limit: ${registryLimit})`
          : `top ${registryLimit} servers`;
      process.stderr.write(`\n\x1b[1m🌐 Registry Scan: ${label}\x1b[0m\n`);
      process.stderr.write(`\x1b[2m   Fetching from registry.modelcontextprotocol.io...\x1b[0m\n`);
    }

    try {
      const result = await registryScanner.scanRegistry({
        limit: registryLimit,
        search: registrySearch,
        server: registryServer,
      });

      configs = result.configs;
      allFindings.push(...result.findings);

      if (configs.length === 0) {
        if (!jsonOutput && !sarifOutput) {
          console.error('  No servers found matching your criteria.');
        }
        process.exit(0);
      }

      if (!jsonOutput && !sarifOutput) {
        process.stderr.write(`\x1b[2m   Found ${configs.length} server(s), running security analysis...\x1b[0m\n`);
      }
    } catch (err) {
      console.error(`Registry fetch failed: ${(err as Error).message}`);
      process.exit(1);
    }
  } else if (specificPath) {
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

  // Run standard scanners (config, credential, tool)
  const configFindings = scanConfigs(configs);
  allFindings.push(...configFindings);

  const credFindings = await credentialScanner.scan(configs);
  allFindings.push(...credFindings);

  const toolFindings = await toolScanner.scan(configs);
  allFindings.push(...toolFindings);

  // Live server scanner (connects to running servers -- not used in registry mode)
  if (liveMode && !registryMode) {
    if (!jsonOutput) {
      process.stderr.write('\n\x1b[1m🔴 Live Server Scan\x1b[0m\n');
    }
    const liveFindings = await liveScanner.scan(configs);
    allFindings.push(...liveFindings);
  }

  // Generate report
  const report = generateReport(configs, allFindings);

  // Save baseline if requested
  if (saveBaselineMode && saveBaselinePath) {
    saveBaseline(report, saveBaselinePath);
    if (!jsonOutput && !sarifOutput) {
      console.log(`\n  Baseline saved to ${saveBaselinePath}\n`);
    }
  }

  // Baseline diff if requested
  if (baselineMode && baselinePath) {
    try {
      const baseline = loadBaseline(baselinePath);
      const diff = diffFindings(allFindings, baseline);
      diff.scoreDelta = report.score - baseline.score;

      if (jsonOutput) {
        // JSON output with diff included
        const safeReport = {
          ...report,
          configFiles: report.configFiles.map((c) => ({
            path: c.path,
            client: c.client,
            servers: Object.keys(c.servers),
          })),
          diff: {
            baselineTimestamp: diff.baselineTimestamp,
            baselineScore: diff.baselineScore,
            scoreDelta: diff.scoreDelta,
            new: diff.newFindings,
            fixed: diff.fixedFindings,
            unchanged: diff.unchangedFindings.length,
          },
        };
        console.log(JSON.stringify(safeReport, null, 2));
      } else if (sarifOutput) {
        printReportSARIF(report);
      } else {
        printReport(report);
        printBaselineDiff(diff, report.score);
      }
    } catch (err) {
      console.error(`Baseline error: ${(err as Error).message}`);
      process.exit(1);
    }
  } else {
    // Normal output (no baseline)
    if (sarifOutput) {
      printReportSARIF(report);
    } else if (jsonOutput) {
      printReportJSON(report);
    } else {
      printReport(report);
    }
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
