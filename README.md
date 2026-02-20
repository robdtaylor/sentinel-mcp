# Sentinel MCP

**Security scanner for Model Context Protocol (MCP) servers.**

Sentinel scans your MCP configurations for security vulnerabilities including hardcoded credentials, prompt injection, tool poisoning, SSRF, and insecure transport.

## Quick Start

```bash
# Scan all detected MCP configurations
bun run src/cli/index.ts scan

# JSON output for CI/CD
bun run src/cli/index.ts scan --json

# Scan a specific config file
bun run src/cli/index.ts scan --path ~/.cursor/mcp.json
```

## What It Scans

| Check | Category | Severity |
|-------|----------|----------|
| Hardcoded API keys (Anthropic, OpenAI, GitHub, AWS, etc.) | Credential Exposure | Critical |
| Prompt injection in tool descriptions | Tool Poisoning | Critical |
| Tool shadowing / hidden instructions | Tool Poisoning | Critical |
| SSRF via server URLs (localhost, private IPs, cloud metadata) | SSRF | Critical |
| Command injection in server arguments | Command Injection | Critical |
| Unencrypted HTTP transport | Insecure Transport | High |
| Privileged Docker containers | Excessive Permissions | Critical |
| Unverified npm packages via npx | Supply Chain | Medium |
| Embedded credentials in URLs | Credential Exposure | Critical |
| Sensitive environment variable values | Credential Exposure | High |

## Supported Clients

- Claude Desktop
- Claude Code
- Cursor
- VS Code
- Windsurf
- Cline

## Security Score

Sentinel calculates a 0-100 security score:

- **80-100**: PASS - No critical issues
- **50-79**: WARN - Issues found, review recommended
- **0-49**: FAIL - Critical vulnerabilities detected

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No critical/high findings |
| 1 | High severity findings |
| 2 | Critical severity findings |

## Development

```bash
# Install dependencies
bun install

# Run tests
bun test

# Type check
bun run typecheck
```

## License

MIT
