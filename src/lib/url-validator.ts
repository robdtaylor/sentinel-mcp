/**
 * Sentinel MCP - URL Validation & SSRF Protection
 *
 * Validates URLs found in MCP server configurations for SSRF,
 * insecure transports, and suspicious patterns.
 */

import type { Severity } from './types';

export interface URLValidationResult {
  valid: boolean;
  reason?: string;
  warnings: string[];
  severity?: Severity;
}

// ============================================================================
// SSRF Protection Configuration
// ============================================================================

const BLOCKED_HOSTS = [
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  '[::1]',
];

const BLOCKED_IP_RANGES: RegExp[] = [
  /^10\./,                          // 10.0.0.0/8 (RFC1918)
  /^172\.(1[6-9]|2[0-9]|3[01])\./,  // 172.16.0.0/12 (RFC1918)
  /^192\.168\./,                     // 192.168.0.0/16 (RFC1918)
  /^169\.254\./,                     // 169.254.0.0/16 (link-local)
  /^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\./, // 100.64.0.0/10 (CGNAT)
  /^198\.51\.100\./,                 // 198.51.100.0/24 (TEST-NET-2)
  /^203\.0\.113\./,                  // 203.0.113.0/24 (TEST-NET-3)
  /^224\./,                          // 224.0.0.0/4 (multicast)
  /^240\./,                          // 240.0.0.0/4 (reserved)
];

const CLOUD_METADATA_ENDPOINTS = [
  '169.254.169.254',   // AWS/GCP/Azure metadata
  'metadata.google.internal',
  'metadata.google',
  '100.100.100.200',   // Alibaba Cloud metadata
];

// ============================================================================
// Validation
// ============================================================================

/**
 * Validate a URL for SSRF and security concerns
 */
export function validateURL(url: string): URLValidationResult {
  const warnings: string[] = [];

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { valid: false, reason: 'Invalid URL format', warnings };
  }

  const hostname = parsed.hostname.toLowerCase();
  const scheme = parsed.protocol.replace(':', '').toLowerCase();

  // Check scheme
  if (!['https', 'http'].includes(scheme)) {
    return {
      valid: false,
      reason: `Unsafe scheme: ${scheme}`,
      warnings,
      severity: 'high',
    };
  }

  // SSRF: blocked hosts
  if (BLOCKED_HOSTS.includes(hostname)) {
    return {
      valid: false,
      reason: `SSRF risk: blocked host ${hostname}`,
      warnings,
      severity: 'critical',
    };
  }

  // SSRF: cloud metadata endpoints (check before generic IP ranges for specific messaging)
  if (CLOUD_METADATA_ENDPOINTS.includes(hostname)) {
    return {
      valid: false,
      reason: `SSRF risk: cloud metadata endpoint ${hostname}`,
      warnings,
      severity: 'critical',
    };
  }

  // SSRF: blocked IP ranges
  for (const range of BLOCKED_IP_RANGES) {
    if (range.test(hostname)) {
      return {
        valid: false,
        reason: `SSRF risk: private/reserved IP range`,
        warnings,
        severity: 'critical',
      };
    }
  }

  // HTTP without TLS
  if (scheme === 'http') {
    warnings.push('Transport uses HTTP (unencrypted) - credentials and tokens may be exposed');
  }

  // Embedded credentials
  if (parsed.username || parsed.password) {
    warnings.push('URL contains embedded credentials');
  }

  // Non-standard port
  if (parsed.port && !['80', '443', '8080', '8443'].includes(parsed.port)) {
    warnings.push(`Non-standard port: ${parsed.port}`);
  }

  return {
    valid: true,
    warnings,
    severity: warnings.length > 0 ? 'medium' : undefined,
  };
}
