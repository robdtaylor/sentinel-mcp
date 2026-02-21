/**
 * Sentinel MCP - Registry Client
 *
 * HTTP client for fetching MCP server listings from public registries
 * and npm package metadata for supply-chain analysis.
 */

// ============================================================================
// Types
// ============================================================================

export interface RegistryServer {
  name: string;
  description: string;
  packages: { type: string; name: string }[];
  repository?: string;
  version?: string;
}

export interface NpmPackageInfo {
  exists: boolean;
  created?: string;
  weeklyDownloads?: number;
  maintainers?: number;
  repository?: string;
}

// ============================================================================
// Official MCP Registry
// ============================================================================

const REGISTRY_BASE = 'https://registry.modelcontextprotocol.io/v0.1';

/**
 * Fetch server listings from the official MCP registry
 */
export async function fetchRegistryServers(options: {
  limit?: number;
  search?: string;
  server?: string;
}): Promise<RegistryServer[]> {
  const { limit = 20, search, server } = options;

  let url = `${REGISTRY_BASE}/servers`;
  const params = new URLSearchParams();

  if (search) {
    params.set('q', search);
  }

  if (params.toString()) {
    url += `?${params.toString()}`;
  }

  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`Registry API error: ${response.status} ${response.statusText}`);
  }

  const data = await response.json();

  // The API returns { servers: [{ server: {...}, _meta: {...} }, ...] }
  const rawEntries: any[] = Array.isArray(data)
    ? data
    : (data.servers || data.items || data.results || []);

  // Each entry wraps the actual server data in a `server` key
  let servers: RegistryServer[] = rawEntries.map((entry: any) => {
    const s = entry.server || entry;
    return {
      name: s.name || s.id || '',
      description: s.description || '',
      packages: normalizePackages(s),
      repository: (typeof s.repository === 'object' ? s.repository?.url : s.repository) || undefined,
      version: s.version || s.latest_version || undefined,
    };
  });

  // Filter to a specific server name if requested
  if (server) {
    const needle = server.toLowerCase();
    servers = servers.filter(
      (s) => s.name.toLowerCase() === needle || s.name.toLowerCase().includes(needle)
    );
  }

  return servers.slice(0, limit);
}

/**
 * Normalize the various package formats from the registry API.
 *
 * The official registry uses:
 *   packages: [{ registryType: "npm", name: "@scope/pkg" }]
 *   or: packages: [{ registryType: "oci", identifier: "docker.io/img:tag" }]
 *   or: remotes: [{ type: "streamable-http", url: "..." }] (no installable package)
 */
function normalizePackages(entry: any): { type: string; name: string }[] {
  // Direct packages array
  if (Array.isArray(entry.packages)) {
    return entry.packages
      .map((p: any) => ({
        type: p.registryType || p.registry_type || p.type || 'npm',
        name: p.name || p.identifier || p.package_name || '',
      }))
      .filter((p: { name: string }) => p.name);
  }

  // npm field directly
  if (entry.npm) {
    return [{ type: 'npm', name: entry.npm }];
  }

  // pypi field directly
  if (entry.pypi) {
    return [{ type: 'pypi', name: entry.pypi }];
  }

  // package_name field
  if (entry.package_name) {
    return [{ type: 'npm', name: entry.package_name }];
  }

  return [];
}

// ============================================================================
// npm Registry
// ============================================================================

const NPM_REGISTRY = 'https://registry.npmjs.org';
const NPM_API = 'https://api.npmjs.org';

/**
 * Fetch package metadata from npm for supply-chain analysis
 */
export async function fetchNpmPackageInfo(packageName: string): Promise<NpmPackageInfo | null> {
  try {
    // Fetch package metadata
    const metaResponse = await fetch(`${NPM_REGISTRY}/${encodeURIComponent(packageName)}`);

    if (metaResponse.status === 404) {
      return { exists: false };
    }

    if (!metaResponse.ok) {
      return null; // API error, can't determine
    }

    const meta = await metaResponse.json();

    // Extract creation date
    const created = meta.time?.created || undefined;

    // Extract maintainer count
    const maintainers = Array.isArray(meta.maintainers) ? meta.maintainers.length : undefined;

    // Extract repository URL
    const repository = typeof meta.repository === 'string'
      ? meta.repository
      : meta.repository?.url || undefined;

    // Fetch weekly download count (separate API)
    let weeklyDownloads: number | undefined;
    try {
      const dlResponse = await fetch(
        `${NPM_API}/downloads/point/last-week/${encodeURIComponent(packageName)}`
      );
      if (dlResponse.ok) {
        const dlData = await dlResponse.json();
        weeklyDownloads = dlData.downloads;
      }
    } catch {
      // Download stats unavailable, not critical
    }

    return {
      exists: true,
      created,
      weeklyDownloads,
      maintainers,
      repository,
    };
  } catch {
    return null; // Network error
  }
}
