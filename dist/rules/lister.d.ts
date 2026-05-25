interface RuleInfo {
    id: string;
    category: string;
    severity: string;
    description: string;
}
export declare function listRules(category?: string): RuleInfo[];
export {};
