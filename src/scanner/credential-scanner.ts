/**
 * Sentinel MCP - Credential Scanner
 *
 * Detects hardcoded credentials, API keys, and tokens in MCP configurations.
 * Maps to OWASP MCP Top 10: Token/Credential Mismanagement.
 */

import type { MCPConfigFile, Finding, Scanner } from '../lib/types';

// ============================================================================
// Credential Patterns
// ============================================================================

interface CredentialPattern {
  name: string;
  pattern: RegExp;
  description: string;
}

const CREDENTIAL_PATTERNS: CredentialPattern[] = [
  // API Keys
  { name: 'Anthropic API Key', pattern: /sk-ant-api\d{2}-[A-Za-z0-9_-]{20,}/, description: 'Anthropic API key' },
  { name: 'OpenAI API Key', pattern: /sk-proj-[A-Za-z0-9_-]{20,}/, description: 'OpenAI project API key' },
  { name: 'OpenAI Legacy Key', pattern: /sk-[A-Za-z0-9]{48}/, description: 'OpenAI legacy API key' },
  { name: 'Google API Key', pattern: /AIzaSy[A-Za-z0-9_-]{33}/, description: 'Google API key' },
  { name: 'AWS Access Key', pattern: /AKIA[A-Z0-9]{16}/, description: 'AWS access key ID' },
  { name: 'GitHub Token', pattern: /gh[ps]_[A-Za-z0-9]{36,}/, description: 'GitHub personal access token' },
  { name: 'GitHub Fine-grained', pattern: /github_pat_[A-Za-z0-9_]{20,}/, description: 'GitHub fine-grained PAT' },
  { name: 'Slack Token', pattern: /xox[bporas]-[A-Za-z0-9-]+/, description: 'Slack API token' },
  { name: 'Stripe Key', pattern: /sk_live_[A-Za-z0-9]{24,}/, description: 'Stripe live secret key' },
  { name: 'Supabase Key', pattern: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/, description: 'JWT token (possibly Supabase/auth)' },
  { name: 'Perplexity Key', pattern: /pplx-[A-Za-z0-9]{48,}/, description: 'Perplexity API key' },
  { name: 'Twilio SID', pattern: /AC[a-f0-9]{32}/, description: 'Twilio Account SID' },
  { name: 'SendGrid Key', pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/, description: 'SendGrid API key' },
  { name: 'Mailgun Key', pattern: /key-[a-f0-9]{32}/, description: 'Mailgun API key' },
  { name: 'HuggingFace Token', pattern: /hf_[A-Za-z0-9]{34,}/, description: 'Hugging Face API token' },
  { name: 'Replicate Token', pattern: /r8_[A-Za-z0-9]{37,}/, description: 'Replicate API token' },

  // Generic patterns
  { name: 'Bearer Token', pattern: /Bearer\s+[A-Za-z0-9_.-]{20,}/, description: 'Bearer authentication token' },
  { name: 'Basic Auth', pattern: /Basic\s+[A-Za-z0-9+/=]{20,}/, description: 'Basic authentication header' },
  { name: 'Private Key', pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/, description: 'Private key material' },
  { name: 'Password in URL', pattern: /:\/\/[^:]+:[^@]+@/, description: 'Credentials embedded in URL' },
];

// Environment variable names that commonly hold secrets
const SENSITIVE_ENV_NAMES = [
  /api[_-]?key/i,
  /api[_-]?secret/i,
  /auth[_-]?token/i,
  /access[_-]?token/i,
  /secret[_-]?key/i,
  /private[_-]?key/i,
  /password/i,
  /passwd/i,
  /credential/i,
  /db[_-]?(pass|pwd|password)/i,
  /database[_-]?url/i,
  /connection[_-]?string/i,
];

// ============================================================================
// Scanner
// ============================================================================

export const credentialScanner: Scanner = {
  name: 'Credential Scanner',

  async scan(configs: MCPConfigFile[]): Promise<Finding[]> {
    const findings: Finding[] = [];
    let findingId = 0;

    for (const config of configs) {
      // Stringify the whole config to catch credentials anywhere
      const configStr = JSON.stringify(config.raw, null, 2);

      for (const [serverName, server] of Object.entries(config.servers)) {
        // Check command + args for hardcoded credentials
        const commandStr = [
          server.command || '',
          ...(server.args || []),
        ].join(' ');

        for (const cred of CREDENTIAL_PATTERNS) {
          if (cred.pattern.test(commandStr)) {
            findings.push({
              id: `CRED-${++findingId}`,
              severity: 'critical',
              category: 'credential-exposure',
              title: `Hardcoded ${cred.name} in command`,
              description: `Server "${serverName}" has a ${cred.description} hardcoded in its command/args. This is exposed to any process and in config file backups.`,
              server: serverName,
              configFile: config.path,
              evidence: maskCredential(commandStr, cred.pattern),
              remediation: 'Move credentials to environment variables or a secrets manager. Use the "env" field in server config.',
            });
          }
        }

        // Check environment variables for hardcoded values
        if (server.env) {
          for (const [envName, envValue] of Object.entries(server.env)) {
            // Check if env var name suggests it's a secret
            const isSensitiveName = SENSITIVE_ENV_NAMES.some((p) => p.test(envName));

            // Check if the value matches a known credential pattern
            for (const cred of CREDENTIAL_PATTERNS) {
              if (cred.pattern.test(envValue)) {
                findings.push({
                  id: `CRED-${++findingId}`,
                  severity: 'critical',
                  category: 'credential-exposure',
                  title: `Hardcoded ${cred.name} in env config`,
                  description: `Server "${serverName}" has a ${cred.description} hardcoded in env.${envName}. Config files are often committed to git or backed up unencrypted.`,
                  server: serverName,
                  configFile: config.path,
                  evidence: `${envName}=${maskCredential(envValue, cred.pattern)}`,
                  remediation: 'Reference system environment variables instead of hardcoding values. Use ${ENV_VAR} syntax or a .env file excluded from version control.',
                });
                break; // One match per env var is enough
              }
            }

            // Warn about sensitive-looking env vars even without pattern match
            if (isSensitiveName && envValue.length > 10 && !findings.some((f) => f.evidence?.includes(envName))) {
              findings.push({
                id: `CRED-${++findingId}`,
                severity: 'high',
                category: 'credential-exposure',
                title: `Potential secret in env: ${envName}`,
                description: `Server "${serverName}" has a value in env.${envName} that appears to be a secret based on the variable name.`,
                server: serverName,
                configFile: config.path,
                evidence: `${envName}=${envValue.substring(0, 4)}${'*'.repeat(Math.min(envValue.length - 4, 20))}`,
                remediation: 'Use system environment variables or a secrets manager instead of config file values.',
              });
            }
          }
        }

        // Check URL for embedded credentials
        if (server.url) {
          const urlCredPattern = /:\/\/([^:]+):([^@]+)@/;
          if (urlCredPattern.test(server.url)) {
            findings.push({
              id: `CRED-${++findingId}`,
              severity: 'critical',
              category: 'credential-exposure',
              title: `Credentials embedded in server URL`,
              description: `Server "${serverName}" has credentials embedded in the URL. These appear in logs, browser history, and referrer headers.`,
              server: serverName,
              configFile: config.path,
              evidence: server.url.replace(urlCredPattern, '://$1:****@'),
              remediation: 'Pass credentials via environment variables or authentication headers instead of URL.',
            });
          }
        }
      }

      // Scan raw config for credentials not in server definitions
      for (const cred of CREDENTIAL_PATTERNS) {
        const matches = configStr.match(cred.pattern);
        if (matches) {
          // Check if we already found this credential in a server-specific check
          const alreadyFound = findings.some((f) =>
            f.configFile === config.path && f.title.includes(cred.name)
          );
          if (!alreadyFound) {
            findings.push({
              id: `CRED-${++findingId}`,
              severity: 'high',
              category: 'credential-exposure',
              title: `${cred.name} found in config file`,
              description: `Config file contains what appears to be a ${cred.description}.`,
              configFile: config.path,
              evidence: maskCredential(matches[0], cred.pattern),
              remediation: 'Move credentials out of config files into environment variables or a secrets manager.',
            });
          }
        }
      }
    }

    return findings;
  },
};

// ============================================================================
// Helpers
// ============================================================================

/**
 * Mask a credential value for safe display
 */
function maskCredential(text: string, pattern: RegExp): string {
  return text.replace(pattern, (match) => {
    if (match.length <= 8) return '****';
    return match.substring(0, 4) + '*'.repeat(Math.min(match.length - 8, 20)) + match.substring(match.length - 4);
  });
}
