import { allRules } from "./index.js";
export function listRules(category) {
    let rules = allRules;
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
