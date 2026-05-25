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
export declare function scanCode(code: string, language: string, options: ScanOptions): ScanResult[];
