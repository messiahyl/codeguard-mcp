# 🔒 CodeGuard MCP Server

> AI-powered code security review — scan code for vulnerabilities, code smells, and performance issues right inside your AI assistant.

[![npm version](https://img.shields.io/npm/v/codeguard-mcp.svg)](https://www.npmjs.com/package/codeguard-mcp)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/messiahyl/codeguard-mcp?style=social)](https://github.com/messiahyl/codeguard-mcp)

## What it does

CodeGuard is an [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server that brings static security analysis into your AI coding workflow. Instead of switching tools, just ask your AI assistant to scan your code.

It detects **security vulnerabilities**, **hardcoded secrets**, **cryptographic weaknesses**, **misconfigurations**, and **performance anti-patterns** — covering the OWASP Top 10 with 12 built-in rules.

## Features

- 🔴 **Security Vulnerability Detection** — SQL Injection, XSS, Command Injection, Path Traversal, Unsafe Deserialization
- 🟠 **Secret Detection** — Hardcoded passwords, API keys, tokens, AWS credentials
- 🟡 **Cryptographic Weaknesses** — Weak algorithms (MD5, DES, ECB mode), low bcrypt rounds
- 🔵 **Misconfiguration** — CORS wildcards, overly permissive settings
- ⚡ **Performance Issues** — N+1 queries, regex DoS patterns
- 📋 **12 built-in rules** covering OWASP Top 10
- 🌐 **10+ languages** supported: Java, Python, JavaScript, TypeScript, Go, Rust, C/C++, SQL, YAML, JSON

## Quick Start

### Option 1: npx (recommended)

Add to your MCP client config:

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

### Option 2: Install globally

```bash
npm install -g codeguard-mcp
```

Then in your MCP config:

```json
{
  "mcpServers": {
    "codeguard": {
      "command": "codeguard-mcp"
    }
  }
}
```

### Option 3: From source

```bash
git clone https://github.com/messiahyl/codeguard-mcp.git
cd codeguard-mcp
npm install
npm run build
```

Then in your MCP config:

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

## Usage

Once configured, just ask your AI assistant:

```
"Scan this Java code for security issues"
"Quick check: does this code have SQL injection?"
"What security rules are available?"
"Review my API endpoint for vulnerabilities"
"Check this function for hardcoded secrets"
```

## Tools

| Tool | Description |
|------|-------------|
| `scan_code` | Full security scan — analyzes code against all rules, returns severity-ranked issues with fix suggestions |
| `quick_check` | Fast targeted check — test for a specific vulnerability type (e.g., SQL injection only) |
| `list_rules` | Browse all available security rules with descriptions and supported languages |

## Security Rules

| Rule | Category | Severity | Description |
|------|----------|----------|-------------|
| `sql_injection` | Injection | 🔴 Critical | String concatenation in SQL queries |
| `command_injection` | Injection | 🔴 Critical | Unsanitized input in shell commands |
| `xss` | XSS | 🔴 Critical | Reflected/stored XSS patterns |
| `path_traversal` | Injection | 🟠 High | Directory traversal attacks |
| `hardcoded_secrets` | Secrets | 🟠 High | Hardcoded passwords, API keys, tokens |
| `unsafe_deserialization` | Injection | 🟠 High | Untrusted data deserialization |
| `weak_crypto` | Crypto | 🟡 Medium | Weak algorithms (MD5, DES, ECB) |
| `weak_password_hashing` | Crypto | 🟡 Medium | Insufficient password hashing |
| `cors_misconfiguration` | Config | 🟡 Medium | Overly permissive CORS |
| `open_redirect` | Security | 🟡 Medium | Unvalidated redirect URLs |
| `n_plus_one_queries` | Performance | 🔵 Low | Database N+1 query patterns |
| `regex_dos` | Performance | 🔵 Low | ReDoS vulnerable patterns |

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

## Supported MCP Clients

Works with any MCP-compatible client:

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code)
- [Cursor](https://cursor.sh)
- [Windsurf](https://windsurf.ai)
- [Cline](https://cline.bot)
- Any client supporting the [MCP protocol](https://modelcontextprotocol.io)

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Watch mode
npm run dev
```

## Contributing

Contributions are welcome! Especially:

- New security rules
- Language-specific patterns
- Fix suggestions improvements
- Documentation improvements

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/my-rule`)
3. Commit your changes (`git commit -m 'Add new security rule'`)
4. Push to the branch (`git push origin feature/my-rule`)
5. Open a Pull Request

## License

MIT © [messiahyl](https://github.com/messiahyl)
