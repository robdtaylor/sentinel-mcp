# mcpsec

Security scanner for [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) servers. Detects tool poisoning, credential exposure, prompt injection, SSRF, and insecure transport across all your MCP configurations.

## Why

MCP gives AI agents access to tools, files, databases, and APIs. A single malicious or misconfigured MCP server can:

- **Steal credentials** hardcoded in config files
- **Poison tool descriptions** to manipulate AI behavior
- **Shadow legitimate tools** to intercept sensitive operations
- **Exfiltrate data** via SSRF to internal services or cloud metadata endpoints
- **Inject commands** through server arguments

mcpsec finds these problems before attackers do.

## Quick Start

```bash
# Scan all detected MCP configurations
npx mcpsec scan

# Connect to running servers and scan live tools/resources
npx mcpsec scan --live

# Scan a specific config file
npx mcpsec scan --path ~/.cursor/mcp.json

# JSON output for CI/CD pipelines
npx mcpsec scan --json
```

> Requires [Bun](https://bun.sh) runtime (`curl -fsSL https://bun.sh/install | bash`)

## Example Output

```
  mcpsec - MCP Security Scanner v0.1.0
  ──────────────────────────────────────────────────

  Configurations Found
  Claude Desktop (3 servers)
  ~/.config/claude/claude_desktop_config.json
    └─ filesystem
    └─ github
    └─ slack-mcp

  Security Score
  42/100   FAIL

   2 CRITICAL   1 high  1 medium

  Findings
  ──────────────────────────────────────────────────

  CRITICAL  Hardcoded API Key  [CRED-001]
  Server: slack-mcp
  Anthropic API key found in environment variables
  Evidence: ANTHROPIC_API_KEY=sk-ant-api03-****
  Fix: Use a secrets manager or environment variable reference

  CRITICAL  SSRF Risk - Cloud Metadata  [SSRF-002]
  Server: internal-proxy
  Server URL points to AWS metadata endpoint
  Evidence: http://169.254.169.254/latest/meta-data/
  Fix: Remove cloud metadata URLs from MCP configurations

  HIGH      Unencrypted Transport  [TRANSPORT-001]
  Server: github
  Server uses HTTP instead of HTTPS
  Fix: Switch to HTTPS or use stdio transport

  MEDIUM    Unverified npx Package  [SUPPLY-001]
  Server: slack-mcp
  Package installed via npx without version pinning
  Fix: Pin to a specific version: npx package@1.2.3
```

## What It Detects

### Static Analysis (default)

| Check | Category | Severity |
|-------|----------|----------|
| Hardcoded API keys (Anthropic, OpenAI, GitHub, AWS, GCP, Azure, Stripe, etc.) | Credential Exposure | Critical |
| Credentials embedded in URLs | Credential Exposure | Critical |
| Sensitive environment variable values | Credential Exposure | High |
| SSRF via cloud metadata endpoints (AWS, GCP, Azure) | SSRF | Critical |
| SSRF via localhost/private IP ranges | SSRF | High |
| Command injection in server arguments | Command Injection | Critical |
| Prompt injection patterns in tool descriptions | Tool Poisoning | Critical |
| Hidden instructions and tool shadowing | Tool Poisoning | Critical |
| Privileged Docker containers (`--privileged`, host network) | Excessive Permissions | Critical |
| Unencrypted HTTP transport | Insecure Transport | High |
| Unverified npx packages without version pinning | Supply Chain | Medium |

### Live Server Scanning (`--live`)

Connects to running MCP servers and inspects their actual tools, resources, and prompts:

| Check | Category | Severity |
|-------|----------|----------|
| Dangerous tool capabilities (exec, eval, sudo, bulk delete) | Dangerous Tools | High |
| Injection patterns in tool descriptions | Tool Poisoning | Critical |
| Injection patterns in resource/prompt descriptions | Tool Poisoning | High |
| SSRF in resource URI templates | SSRF | High |
| Sensitive input schemas (password/token fields) | Credential Exposure | Medium |
| Tool name shadowing across servers | Tool Shadowing | High |
| Sampling capability enabled | Excessive Permissions | Medium |

## Supported Clients

mcpsec auto-discovers configurations for:

- **Claude Desktop** - `~/.config/claude/claude_desktop_config.json`
- **Claude Code** - `~/.claude/settings.json` (project and global)
- **Cursor** - `~/.cursor/mcp.json`
- **VS Code** - `~/.vscode/settings.json`
- **Windsurf** - `~/.windsurf/mcp.json`
- **Cline** - VS Code extension settings

## Security Score

mcpsec calculates a 0-100 security score:

| Score | Status | Impact |
|-------|--------|--------|
| 80-100 | PASS | No critical issues |
| 50-79 | WARN | Issues found, review recommended |
| 0-49 | FAIL | Critical vulnerabilities detected |

**Scoring:** Critical = -25, High = -15, Medium = -8, Low = -3, Info = 0

## GitHub Actions

```yaml
- name: MCP Security Scan
  uses: robdtaylor/sentinel-mcp@v1
  with:
    config-path: path/to/mcp-config.json
    fail-on: high  # critical, high, medium, or none
```

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `config-path` | Yes | - | Path to MCP configuration file |
| `fail-on` | No | `high` | Minimum severity to fail: `critical`, `high`, `medium`, `none` |

### Outputs

| Output | Description |
|--------|-------------|
| `score` | Security score (0-100) |
| `status` | `pass`, `warn`, or `fail` |
| `findings` | Total number of findings |
| `critical` | Number of critical findings |
| `high` | Number of high findings |

### Example: Fail only on critical

```yaml
- name: MCP Security Scan
  uses: robdtaylor/sentinel-mcp@v1
  with:
    config-path: .cursor/mcp.json
    fail-on: critical
```

### Example: Use outputs in later steps

```yaml
- name: MCP Security Scan
  id: mcpsec
  uses: robdtaylor/sentinel-mcp@v1
  with:
    config-path: mcp-config.json
    fail-on: none

- name: Check results
  run: |
    echo "Score: ${{ steps.mcpsec.outputs.score }}"
    echo "Critical: ${{ steps.mcpsec.outputs.critical }}"
```

### SARIF + GitHub Code Scanning

Upload results to GitHub's Security tab:

```yaml
- name: MCP Security Scan
  run: npx mcpsec scan --sarif --path mcp-config.json > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### CLI in CI

You can also run the CLI directly:

```yaml
- name: MCP Security Scan
  run: npx mcpsec scan --json --path mcp-config.json > report.json
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No critical or high findings |
| 1 | High severity findings found |
| 2 | Critical severity findings found |

## CLI Reference

```
mcpsec scan [options]

Options:
  --live          Connect to running MCP servers and scan live
  --json          Output results as JSON
  --sarif         Output results as SARIF 2.1.0 (for GitHub Code Scanning)
  --path <file>   Scan a specific config file
  --no-color      Disable colored output
  --help, -h      Show help
  --version, -v   Show version
```

## Development

```bash
# Clone and install
git clone https://github.com/robdtaylor/sentinel-mcp.git
cd sentinel-mcp
bun install

# Run tests (64 tests)
bun test

# Type check
bun run typecheck

# Run locally
bun run src/cli/index.ts scan
```

## Architecture

```
src/
  cli/index.ts              CLI entry point
  lib/
    types.ts                Core types (Finding, MCPConfigFile, Scanner)
    injection-patterns.ts   Prompt injection / tool poisoning patterns
    url-validator.ts        SSRF detection (cloud metadata, private IPs)
    mcp-client.ts           MCP protocol client (stdio + HTTP)
  scanner/
    config-scanner.ts       Config-level checks (transport, docker, supply chain)
    credential-scanner.ts   API key and credential detection
    tool-scanner.ts         Injection and command injection scanning
    live-scanner.ts         Live server tool/resource/prompt analysis
    report.ts               Score calculation and report output
    sarif.ts                SARIF 2.1.0 output for GitHub Code Scanning
```

## Roadmap

- [x] Cross-server tool shadowing detection
- [x] GitHub Actions action (`uses: robdtaylor/sentinel-mcp@v1`)
- [ ] MCP server registry scanning
- [ ] Baseline / diff mode (track changes between scans)
- [x] SARIF output format (`--sarif` for GitHub Code Scanning)

## License

MIT
