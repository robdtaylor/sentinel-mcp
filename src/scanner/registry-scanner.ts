/**
 * Sentinel MCP - Registry Scanner
 *
 * Fetches MCP servers from public registries, converts them to synthetic
 * MCPConfigFile objects for the existing scanner pipeline, and runs
 * registry-specific supply-chain checks (npm package age, downloads, etc).
 */

import type { Finding, MCPConfigFile, Scanner } from '../lib/types';
import { fetchRegistryServers, fetchNpmPackageInfo } from '../lib/registry-client';
import type { RegistryServer } from '../lib/registry-client';

// ============================================================================
// Registry Scanner
// ============================================================================

export interface RegistryScanOptions {
  limit?: number;
  search?: string;
  server?: string;
}

/**
 * Convert a registry server entry into a synthetic MCPConfigFile
 * so existing scanners (credential, tool, config) can process it unchanged.
 */
export function toSyntheticConfig(server: RegistryServer): MCPConfigFile {
  const servers: Record<string, any> = {};

  // Build a synthetic server config based on the package type
  const npmPkg = server.packages.find((p) => p.type === 'npm');
  const pypiPkg = server.packages.find((p) => p.type === 'pypi');
  const ociPkg = server.packages.find((p) => p.type === 'oci');

  if (npmPkg) {
    servers[server.name] = {
      command: 'npx',
      args: ['-y', npmPkg.name],
    };
  } else if (pypiPkg) {
    servers[server.name] = {
      command: 'uvx',
      args: [pypiPkg.name],
    };
  } else if (ociPkg) {
    servers[server.name] = {
      command: 'docker',
      args: ['run', '-i', ociPkg.name],
    };
  } else {
    // Remote-only or unknown -- create a placeholder
    servers[server.name] = {
      command: 'unknown',
      args: [],
    };
  }

  return {
    path: `registry://modelcontextprotocol.io/${server.name}`,
    client: 'MCP Registry',
    servers,
    raw: server,
  };
}

/**
 * Run registry-specific supply-chain checks against npm packages.
 * These checks go beyond what static config analysis catches.
 */
async function checkNpmSupplyChain(
  server: RegistryServer,
  configPath: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const npmPkg = server.packages.find((p) => p.type === 'npm');

  if (!npmPkg) return findings;

  const info = await fetchNpmPackageInfo(npmPkg.name);

  if (!info) return findings; // API unavailable, skip

  // Package not found on npm
  if (!info.exists) {
    findings.push({
      id: 'REG-NPM-404',
      severity: 'high',
      category: 'supply-chain',
      title: `npm package not found: ${npmPkg.name}`,
      description: `The npm package "${npmPkg.name}" listed for "${server.name}" does not exist on the npm registry. This may indicate a typosquat risk or a removed package.`,
      server: server.name,
      configFile: configPath,
      evidence: `package: ${npmPkg.name}`,
      remediation: 'Verify the package name is correct. Do not install packages that cannot be found on npm.',
    });
    return findings; // No point checking further
  }

  // Package less than 1 week old
  if (info.created) {
    const createdDate = new Date(info.created);
    const ageMs = Date.now() - createdDate.getTime();
    const ageDays = ageMs / (1000 * 60 * 60 * 24);

    if (ageDays < 7) {
      findings.push({
        id: 'REG-NPM-NEW',
        severity: 'medium',
        category: 'supply-chain',
        title: `Very new npm package: ${npmPkg.name}`,
        description: `The npm package "${npmPkg.name}" was created ${Math.floor(ageDays)} day(s) ago. New packages have not been vetted by the community and may pose supply-chain risks.`,
        server: server.name,
        configFile: configPath,
        evidence: `created: ${info.created}`,
        remediation: 'Wait for the package to establish a track record before installing. Review the source code manually.',
      });
    }
  }

  // Low weekly downloads
  if (info.weeklyDownloads !== undefined && info.weeklyDownloads < 100) {
    findings.push({
      id: 'REG-NPM-LOW-DL',
      severity: 'low',
      category: 'supply-chain',
      title: `Low download count: ${npmPkg.name}`,
      description: `The npm package "${npmPkg.name}" has only ${info.weeklyDownloads} weekly downloads. Low adoption means fewer eyes reviewing the code for security issues.`,
      server: server.name,
      configFile: configPath,
      evidence: `weekly downloads: ${info.weeklyDownloads}`,
      remediation: 'Review the package source code before installing. Consider well-established alternatives.',
    });
  }

  // Single maintainer
  if (info.maintainers !== undefined && info.maintainers <= 1) {
    findings.push({
      id: 'REG-NPM-SOLE',
      severity: 'info',
      category: 'supply-chain',
      title: `Single maintainer: ${npmPkg.name}`,
      description: `The npm package "${npmPkg.name}" has only ${info.maintainers} maintainer(s). Single-maintainer packages are more susceptible to account takeover attacks.`,
      server: server.name,
      configFile: configPath,
      evidence: `maintainers: ${info.maintainers}`,
      remediation: 'Monitor the package for unexpected changes. Consider pinning to a specific verified version.',
    });
  }

  return findings;
}

/**
 * Check registry-level metadata for supply-chain signals
 */
function checkRegistryMetadata(
  server: RegistryServer,
  configPath: string,
): Finding[] {
  const findings: Finding[] = [];

  // No repository URL
  if (!server.repository) {
    findings.push({
      id: 'REG-NO-REPO',
      severity: 'low',
      category: 'supply-chain',
      title: `No repository URL: ${server.name}`,
      description: `The registry entry for "${server.name}" has no linked source repository. Without a repo, it's harder to audit the server's code.`,
      server: server.name,
      configFile: configPath,
      evidence: 'repository: not provided',
      remediation: 'Prefer MCP servers that link to a public source repository for auditability.',
    });
  }

  // No packages at all
  if (server.packages.length === 0) {
    findings.push({
      id: 'REG-NO-PKG',
      severity: 'low',
      category: 'supply-chain',
      title: `No install packages listed: ${server.name}`,
      description: `The registry entry for "${server.name}" has no npm or PyPI package listed. The installation method is unclear.`,
      server: server.name,
      configFile: configPath,
      evidence: 'packages: []',
      remediation: 'Check the server documentation for manual installation instructions.',
    });
  }

  return findings;
}

/**
 * Check if repository URL is reachable (HTTP HEAD request)
 */
async function checkRepositoryReachable(
  server: RegistryServer,
  configPath: string,
): Promise<Finding[]> {
  if (!server.repository) return [];

  try {
    const response = await fetch(server.repository, {
      method: 'HEAD',
      redirect: 'follow',
      signal: AbortSignal.timeout(5000),
    });

    if (response.status === 404) {
      return [{
        id: 'REG-REPO-404',
        severity: 'medium',
        category: 'supply-chain',
        title: `Repository not found: ${server.name}`,
        description: `The repository URL for "${server.name}" returns 404. The source code may have been deleted or moved.`,
        server: server.name,
        configFile: configPath,
        evidence: `repository: ${server.repository} (HTTP ${response.status})`,
        remediation: 'Do not use MCP servers whose source repository has been removed.',
      }];
    }
  } catch {
    // Timeout or network error - don't flag, could be transient
  }

  return [];
}

// ============================================================================
// Exported Scanner
// ============================================================================

export const registryScanner: Scanner & {
  scanRegistry(options: RegistryScanOptions): Promise<{
    configs: MCPConfigFile[];
    findings: Finding[];
  }>;
} = {
  name: 'Registry Scanner',

  /**
   * Standard Scanner interface - not used for registry mode,
   * but satisfies the interface for type compatibility.
   */
  async scan(_configs: MCPConfigFile[]): Promise<Finding[]> {
    return [];
  },

  /**
   * Main entry point: fetch from registry, build synthetic configs,
   * and run registry-specific checks.
   */
  async scanRegistry(options: RegistryScanOptions): Promise<{
    configs: MCPConfigFile[];
    findings: Finding[];
  }> {
    // Fetch servers from registry
    const servers = await fetchRegistryServers(options);

    if (servers.length === 0) {
      return { configs: [], findings: [] };
    }

    // Convert to synthetic configs
    const configs = servers.map(toSyntheticConfig);

    // Run registry-specific checks in parallel
    const allFindings: Finding[] = [];
    let findingCounter = 0;

    for (const server of servers) {
      const configPath = `registry://modelcontextprotocol.io/${server.name}`;

      // Metadata checks (synchronous)
      const metaFindings = checkRegistryMetadata(server, configPath);
      allFindings.push(...metaFindings);

      // npm supply-chain checks (async)
      const npmFindings = await checkNpmSupplyChain(server, configPath);
      allFindings.push(...npmFindings);

      // Repository reachability check (async)
      const repoFindings = await checkRepositoryReachable(server, configPath);
      allFindings.push(...repoFindings);
    }

    // Assign unique IDs
    for (const finding of allFindings) {
      findingCounter++;
      finding.id = `${finding.id}-${findingCounter}`;
    }

    return { configs, findings: allFindings };
  },
};
