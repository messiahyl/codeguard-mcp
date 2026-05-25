import { allRules } from "./index.js";
import { Rule } from "../scanner.js";

interface RuleInfo {
  id: string;
  category: string;
  severity: string;
  description: string;
}

export function listRules(category?: string): RuleInfo[] {
  let rules: Rule[] = allRules;
  if (category) {
    rules = rules.filter((r) => r.category === category);
  }
  return rules.map((r) => ({
    id: r.id,
    category: r.category,
    severity: r.severity,
    description: r.description,
  }));
}
