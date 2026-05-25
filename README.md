# 🔒 CodeGuard MCP Server

> AI-powered code security review — scan code for vulnerabilities, code smells, and performance issues right inside your AI assistant.

[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## What it does

CodeGuard is an [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server that brings static security analysis into your AI coding workflow. Instead of switching tools, just ask your AI assistant to scan your code.

## Features

- 🔴 **Security Vulnerability Detection** — SQL Injection, XSS, Command Injection, Path Traversal, Unsafe Deserialization
- 🟠 **Secret Detection** — Hardcoded passwords, API keys, tokens, AWS credentials
- 🟡 **Cryptographic Weaknesses** — Weak algorithms (MD5, DES, ECB mode), low bcrypt rounds
- 🔵 **Misconfiguration** — CORS wildcards, overly permissive settings
- ⚡ **Performance Issues** — N+1 queries, regex DoS patterns
- 📋 **12 built-in rules** covering OWASP Top 10

## Quick Start

### Install

```bash
# Clone
git clone https://github.com/messiahyl/codeguard-mcp.git
cd codeguard-mcp
npm install
npm run build
```

### Use with Claude Code / Cursor / Any MCP-compatible client

Add to your MCP config (e.g., `~/.claude/mcp.json` or `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "codeguard": {
      "command": "node",
      "args": ["/path/to/codeguard-mcp/dist/index.js"]
    }
  }
}
```

### Use with npx

```json
{
  "mcpServers": {
    "codeguard": {
      "command": "npx",
      "args": ["--yes", "codeguard-mcp"]
    }
  }
}
```

## Usage Examples

Once configured, just ask your AI assistant:

```
"Scan this Java code for security issues"
"Quick check: does this code have SQL injection?"
"What security rules are available?"
"Review my API endpoint for vulnerabilities"
```

### Tools

| Tool | Description |
|------|-------------|
| `scan_code` | Full security scan with severity levels and fix suggestions |
| `quick_check` | Fast check for a specific vulnerability type |
| `list_rules` | Browse all available security rules |

### Supported Languages

Java, Python, JavaScript, TypeScript, Go, Rust, C/C++, SQL, YAML, JSON

## Example Output

```
## CodeGuard Security Scan Report

**Language:** java
**Lines Scanned:** 15
**Issues Found:** 3

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 1 |
| 🟡 Medium | 1 |

---

### 🔴 [SQL_INJECTION] SQL Injection - string concatenation in SQL queries
**Line 7:** String query = "SELECT * FROM users WHERE id = " + request.getParameter("id");
**Fix:** Use parameterized queries / PreparedStatement instead of string concatenation
```

## Contributing

Contributions are welcome! Especially:

- New security rules
- Language-specific patterns
- Fix suggestions improvements

## License

MIT
