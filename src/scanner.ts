export interface ScanResult {
  ruleId: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  line: number;
  codeSnippet: string;
  fixSuggestion: string;
  references: string[];
}

export interface ScanOptions {
  severityThreshold: string;
  rulesFilter?: string[];
}

export interface Rule {
  id: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  pattern: RegExp | ((code: string, lines: string[]) => RuleMatch[]);
}

export interface RuleMatch {
  line: number;
  snippet: string;
  fix: string;
  extra?: string;
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

import { getAllRules } from "./rules/index.js";

export function scanCode(
  code: string,
  language: string,
  options: ScanOptions
): ScanResult[] {
  const lines = code.split("\n");
  const rules = getAllRules().filter((rule) => {
    if (options.rulesFilter && options.rulesFilter.length > 0) {
      return options.rulesFilter.some(
        (f) => rule.id.toUpperCase().includes(f.toUpperCase()) || f.toUpperCase() === rule.category.toUpperCase()
      );
    }
    return true;
  });

  const results: ScanResult[] = [];
  const thresholdIndex = SEVERITY_ORDER.indexOf(options.severityThreshold);

  for (const rule of rules) {
    let matches: RuleMatch[];

    if (typeof rule.pattern === "function") {
      matches = rule.pattern(code, lines);
    } else {
      matches = [];
      for (let i = 0; i < lines.length; i++) {
        if (rule.pattern.test(lines[i])) {
          matches.push({
            line: i + 1,
            snippet: lines[i].trim(),
            fix: `// Review and fix the issue on line ${i + 1}`,
          });
        }
      }
    }

    for (const match of matches) {
      const severityIndex = SEVERITY_ORDER.indexOf(rule.severity);
      if (severityIndex <= thresholdIndex) {
        results.push({
          ruleId: rule.id,
          title: rule.description,
          description: `Rule: ${rule.id} - ${rule.description}`,
          severity: rule.severity,
          category: rule.category,
          line: match.line,
          codeSnippet: match.snippet,
          fixSuggestion: match.fix,
          references: match.extra ? [match.extra] : [],
        });
      }
    }
  }

  // Sort by severity
  results.sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  return results;
}
