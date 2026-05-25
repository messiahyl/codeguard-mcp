#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { scanCode } from "./scanner.js";
import { listRules } from "./rules/index.js";
const server = new McpServer({
    name: "codeguard",
    version: "1.0.0",
});
// Tool: Scan code for security issues
server.tool("scan_code", "Scan source code for security vulnerabilities, code smells, and performance issues. Returns a detailed report with severity levels and fix suggestions.", {
    code: z.string().describe("The source code to scan"),
    language: z
        .enum(["java", "python", "javascript", "typescript", "go", "rust", "c", "cpp", "sql", "yaml", "json"])
        .describe("Programming language of the code"),
    severity_threshold: z
        .enum(["critical", "high", "medium", "low", "info"])
        .optional()
        .default("medium")
        .describe("Minimum severity level to report (default: medium)"),
    rules_filter: z
        .array(z.string())
        .optional()
        .describe("Specific rule IDs to check (e.g., ['SQL_INJECTION', 'XSS', 'HARDCODED_SECRET'])"),
}, async ({ code, language, severity_threshold, rules_filter }) => {
    const results = scanCode(code, language, {
        severityThreshold: severity_threshold || "medium",
        rulesFilter: rules_filter,
    });
    const summary = {
        total_issues: results.length,
        critical: results.filter((r) => r.severity === "critical").length,
        high: results.filter((r) => r.severity === "high").length,
        medium: results.filter((r) => r.severity === "medium").length,
        low: results.filter((r) => r.severity === "low").length,
        info: results.filter((r) => r.severity === "info").length,
    };
    let report = `## CodeGuard Security Scan Report\n\n`;
    report += `**Language:** ${language}\n`;
    report += `**Lines Scanned:** ${code.split("\n").length}\n`;
    report += `**Issues Found:** ${summary.total_issues}\n\n`;
    report += `| Severity | Count |\n|----------|-------|\n`;
    report += `| 🔴 Critical | ${summary.critical} |\n`;
    report += `| 🟠 High | ${summary.high} |\n`;
    report += `| 🟡 Medium | ${summary.medium} |\n`;
    report += `| 🔵 Low | ${summary.low} |\n`;
    report += `| ⚪ Info | ${summary.info} |\n\n`;
    if (results.length === 0) {
        report += `✅ No issues found above the "${severity_threshold}" threshold.\n`;
    }
    else {
        report += `---\n\n`;
        for (const issue of results) {
            const emoji = issue.severity === "critical" ? "🔴" :
                issue.severity === "high" ? "🟠" :
                    issue.severity === "medium" ? "🟡" :
                        issue.severity === "low" ? "🔵" : "⚪";
            report += `### ${emoji} [${issue.ruleId}] ${issue.title}\n\n`;
            report += `**Severity:** ${issue.severity.toUpperCase()}\n`;
            report += `**Category:** ${issue.category}\n`;
            report += `**Line:** ${issue.line}\n\n`;
            report += `${issue.description}\n\n`;
            report += `**Vulnerable Code:**\n\`\`\`${language}\n${issue.codeSnippet}\n\`\`\`\n\n`;
            report += `**Fix Suggestion:**\n\`\`\`${language}\n${issue.fixSuggestion}\n\`\`\`\n\n`;
            if (issue.references && issue.references.length > 0) {
                report += `**References:**\n`;
                for (const ref of issue.references) {
                    report += `- ${ref}\n`;
                }
                report += `\n`;
            }
            report += `---\n\n`;
        }
    }
    return {
        content: [{ type: "text", text: report }],
    };
});
// Tool: List all available rules
server.tool("list_rules", "List all available security scanning rules organized by category.", {
    category: z
        .enum(["all", "injection", "secrets", "authentication", "xss", "crypto", "dos", "misconfiguration", "performance"])
        .optional()
        .default("all")
        .describe("Filter rules by category"),
}, async ({ category }) => {
    const rules = listRules(category === "all" ? undefined : category);
    let text = `## CodeGuard Available Rules (${rules.length} total)\n\n`;
    text += `| Rule ID | Category | Severity | Description |\n|---------|----------|----------|-------------|\n`;
    for (const rule of rules) {
        text += `| ${rule.id} | ${rule.category} | ${rule.severity} | ${rule.description} |\n`;
    }
    return {
        content: [{ type: "text", text }],
    };
});
// Tool: Quick security check for a specific pattern
server.tool("quick_check", "Quickly check if a code snippet contains a specific vulnerability pattern.", {
    code: z.string().describe("The source code to check"),
    check_type: z
        .enum([
        "sql_injection",
        "xss",
        "hardcoded_secrets",
        "path_traversal",
        "command_injection",
        "unsafe_deserialization",
        "weak_crypto",
        "open_redirect",
    ])
        .describe("Type of vulnerability to check for"),
}, async ({ code, check_type }) => {
    const results = scanCode(code, "auto", {
        rulesFilter: [check_type.toUpperCase()],
        severityThreshold: "low",
    });
    const found = results.length > 0;
    let text = found
        ? `⚠️ **Potential ${check_type.replace(/_/g, " ")} detected!**\n\n`
        : `✅ No ${check_type.replace(/_/g, " ")} patterns detected.\n`;
    if (found) {
        for (const r of results) {
            text += `**Line ${r.line}:** ${r.description}\n`;
            text += `**Fix:** ${r.fixSuggestion}\n\n`;
        }
    }
    return {
        content: [{ type: "text", text }],
    };
});
// Start the server
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("CodeGuard MCP Server running on stdio");
}
main().catch((error) => {
    console.error("Fatal error:", error);
    process.exit(1);
});
