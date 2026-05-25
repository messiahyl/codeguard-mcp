// ==================== INJECTION RULES ====================
const sqlInjection = {
    id: "SQL_INJECTION",
    category: "injection",
    severity: "critical",
    description: "SQL Injection - string concatenation in SQL queries",
    pattern: (code, lines) => {
        const matches = [];
        const patterns = [
            /(?:SELECT|INSERT|UPDATE|DELETE|DROP).*\+\s*(?:req|request|params|query|body|input|user)/i,
            /(?:execute|query|run|raw)\s*\(\s*["'].*(?:\+|\$\{).*(?:req|request|params|query|body|input)/i,
            /Statement.*execute.*\+\s*\w+/,
            /String\.format.*SELECT|INSERT|UPDATE|DELETE/i,
        ];
        for (let i = 0; i < lines.length; i++) {
            for (const p of patterns) {
                if (p.test(lines[i])) {
                    matches.push({
                        line: i + 1,
                        snippet: lines[i].trim(),
                        fix: "// Use parameterized queries / PreparedStatement instead of string concatenation",
                        extra: "https://owasp.org/www-community/attacks/SQL_Injection",
                    });
                    break;
                }
            }
        }
        return matches;
    },
};
const commandInjection = {
    id: "COMMAND_INJECTION",
    category: "injection",
    severity: "critical",
    description: "OS Command Injection - user input passed to system commands",
    pattern: (code, lines) => {
        const matches = [];
        const patterns = [
            /(?:exec|execSync|spawn|child_process|Runtime\.getRuntime|ProcessBuilder).*(?:req|request|params|query|body|input)/i,
            /eval\s*\(\s*(?:req|request|params|body|input)/i,
            /os\.system\s*\(\s*(?:req|request|params|input)/i,
            /subprocess\.(?:call|run|Popen).*(?:req|request|params|input)/i,
        ];
        for (let i = 0; i < lines.length; i++) {
            for (const p of patterns) {
                if (p.test(lines[i])) {
                    matches.push({
                        line: i + 1,
                        snippet: lines[i].trim(),
                        fix: "// Sanitize input and use allowlists. Never pass raw user input to system commands.",
                        extra: "https://owasp.org/www-community/attacks/Command_Injection",
                    });
                    break;
                }
            }
        }
        return matches;
    },
};
// ==================== SECRETS RULES ====================
const hardcodedSecrets = {
    id: "HARDCODED_SECRET",
    category: "secrets",
    severity: "critical",
    description: "Hardcoded secrets (API keys, passwords, tokens)",
    pattern: (code, lines) => {
        const matches = [];
        const patterns = [
            /(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']/i,
            /(?:api[_-]?key|apikey)\s*[:=]\s*["'][^"']{10,}["']/i,
            /(?:secret|token|auth)\s*[:=]\s*["'][^"']{10,}["']/i,
            /(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY)\s*[:=]\s*["']/i,
            /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/,
            /sk-[a-zA-Z0-9]{20,}/, // OpenAI-style keys
            /ghp_[a-zA-Z0-9]{36}/, // GitHub tokens
            /AKIA[0-9A-Z]{16}/, // AWS Access Keys
        ];
        for (let i = 0; i < lines.length; i++) {
            for (const p of patterns) {
                if (p.test(lines[i])) {
                    matches.push({
                        line: i + 1,
                        snippet: lines[i].trim().substring(0, 80) + "...",
                        fix: "// Move secrets to environment variables or a secrets manager",
                        extra: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                    });
                    break;
                }
            }
        }
        return matches;
    },
};
// ==================== XSS RULES ====================
const xssVulnerability = {
    id: "XSS",
    category: "xss",
    severity: "high",
    description: "Cross-Site Scripting (XSS) - unescaped user input in output",
    pattern: (code, lines) => {
        const matches = [];
        const patterns = [
            /innerHTML\s*=\s*(?:req|request|params|query|body|input|location)/i,
            /document\.write\s*\(\s*(?:req|request|params|query|body)/i,
            /\.html\s*\(\s*(?:req|request|params|query|body)/i,
            /response\.write\s*\(\s*.*(?:req|request|params|query)/i,
            /v-html\s*=\s*["'].*(?:user|input|query|param)/i,
            /dangerouslySetInnerHTML.*(?:req|request|params|query)/i,
        ];
        for (let i = 0; i < lines.length; i++) {
            for (const p of patterns) {
                if (p.test(lines[i])) {
                    matches.push({
                        line: i + 1,
                        snippet: lines[i].trim(),
                        fix: "// Sanitize/escape user input before rendering. Use textContent instead of innerHTML.",
                        extra: "https://owasp.org/www-community/attacks/xss/",
                    });
                    break;
                }
            }
        }
        return matches;
    },
};
// ==================== AUTHENTICATION RULES ====================
const weakAuth = {
    id: "WEAK_AUTH",
    category: "authentication",
    severity: "high",
    description: "Weak authentication patterns",
    pattern: (code, lines) => {
        const matches = [];
        const patterns = [
            /password\s*[:=]\s*["'][a-zA-Z0-9]{1,6}["']/i,
            /bcrypt.*rounds\s*[:=]\s*[1-9]\b/, // low bcrypt rounds
            /MD5|md5\s*\(/i,
            /SHA1|sha1\s*\(/i,
            /compare\s*\(\s*\w+\s*,\s*\w+\s*\)/, // non-constant-time comparison for passwords
        ];
        for (let i = 0; i < lines.length; i++) {
            for (const p of patterns) {
                if (p.test(lines[i])) {
                    matches.push({
                        line: i + 1,
                        snippet: lines[i].trim(),
                        fix: "// Use strong hashing (bcrypt with cost≥12, argon2). Use constant-time comparison for secrets.",
                        extra: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/",
                    });
                    break;
                }
            }
        }
        return matches;
    },
};
// ==================== CRYPTO RULES ====================
const weakCrypto = {
    id: "WEAK_CRYPTO",
    category: "crypto",
    severity: "high",
    description: "Weak cryptographic algorithms",
    pattern: (code, lines) => {
        const matches = [];
        const patterns = [
            /(?:DES|3DES|RC4|RC2|Blowfish)\s*\/(?:ECB|CBC)/i,
            /AES.*\/ECB/i,
            /Cipher\.getInstance\s*\(\s*["']DES/i,
            /CryptoJS\.(?:MD5|SHA1)\s*\(/i,
            /Math\.random\s*\(\s*\)/, // not crypto-safe
        ];
        for (let i = 0; i < lines.length; i++) {
            for (const p of patterns) {
                if (p.test(lines[i])) {
                    matches.push({
                        line: i + 1,
                        snippet: lines[i].trim(),
                        fix: "// Use AES-256-GCM, ChaCha20-Poly1305. Use crypto.randomBytes() or crypto.getRandomValues() for random values.",
                        extra: "https://owasp.org/www-community/vulnerabilities/Insecure_Cryptographic_Storage",
                    });
                    break;
                }
            }
        }
        return matches;
    },
};
// ==================== PATH TRAVERSAL ====================
const pathTraversal = {
    id: "PATH_TRAVERSAL",
    category: "injection",
    severity: "high",
    description: "Path Traversal - user input used in file paths",
    pattern: (code, lines) => {
        const matches = [];
        const patterns = [
            /(?:readFile|writeFile|createReadStream|createWriteStream|FileInputStream|Files\.read).*(?:req|request|params|query|body)/i,
            /(?:path\.join|path\.resolve)\s*\(.*(?:req|request|params|query)/i,
        ];
        for (let i = 0; i < lines.length; i++) {
            for (const p of patterns) {
                if (p.test(lines[i])) {
                    matches.push({
                        line: i + 1,
                        snippet: lines[i].trim(),
                        fix: "// Validate and sanitize file paths. Use allowlists for permitted directories.",
                        extra: "https://owasp.org/www-community/attacks/Path_Traversal",
                    });
                    break;
                }
            }
        }
        return matches;
    },
};
// ==================== MISCONFIGURATION ====================
const corsMisconfiguration = {
    id: "CORS_MISCONFIG",
    category: "misconfiguration",
    severity: "medium",
    description: "CORS misconfiguration - overly permissive origins",
    pattern: (code, lines) => {
        const matches = [];
        const patterns = [
            /Access-Control-Allow-Origin\s*[:=]\s*["']\*["']/i,
            /cors\s*\(\s*\{[^}]*origin\s*[:=]\s*["']\*["']/i,
            /@CrossOrigin\s*\(\s*origins\s*=\s*["']\*["']/i,
        ];
        for (let i = 0; i < lines.length; i++) {
            for (const p of patterns) {
                if (p.test(lines[i])) {
                    matches.push({
                        line: i + 1,
                        snippet: lines[i].trim(),
                        fix: "// Specify exact allowed origins. Avoid wildcard '*' in production.",
                        extra: "https://owasp.org/www-community/attacks/CORS_OriginScrutiny",
                    });
                    break;
                }
            }
        }
        return matches;
    },
};
// ==================== DoS ====================
const regexDoS = {
    id: "REGEX_DOS",
    category: "dos",
    severity: "medium",
    description: "Potential ReDoS - dangerous regex patterns",
    pattern: (code, lines) => {
        const matches = [];
        // Detect nested quantifiers like (a+)+, (a*)*, (a+)*, etc.
        const patterns = [
            /\([^)]*[+*][^)]*\)[+*{]/,
            /new RegExp\s*\(\s*["'][^"']*\([^)]*[+*][^)]*\)[+*{]/,
        ];
        for (let i = 0; i < lines.length; i++) {
            for (const p of patterns) {
                if (p.test(lines[i])) {
                    matches.push({
                        line: i + 1,
                        snippet: lines[i].trim(),
                        fix: "// Avoid nested quantifiers in regex. Use atomic groups or possessive quantifiers.",
                        extra: "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS",
                    });
                    break;
                }
            }
        }
        return matches;
    },
};
// ==================== PERFORMANCE ====================
const nplus1Query = {
    id: "N_PLUS_1_QUERY",
    category: "performance",
    severity: "medium",
    description: "Potential N+1 query pattern",
    pattern: (code, lines) => {
        const matches = [];
        const patterns = [
            /for\s*\(.*(?:findAll|list|get All|getAll|find).*(?:findById|getById|findOne|getOne)/i,
            /\.forEach\s*\(.*(?:findById|getById|query|execute|fetch)/i,
        ];
        for (let i = 0; i < lines.length; i++) {
            for (const p of patterns) {
                if (p.test(lines[i])) {
                    matches.push({
                        line: i + 1,
                        snippet: lines[i].trim(),
                        fix: "// Batch queries or use JOIN FETCH to avoid N+1 queries.",
                    });
                    break;
                }
            }
        }
        return matches;
    },
};
const unsafeDeserialization = {
    id: "UNSAFE_DESERIALIZATION",
    category: "injection",
    severity: "critical",
    description: "Unsafe deserialization of untrusted data",
    pattern: (code, lines) => {
        const matches = [];
        const patterns = [
            /ObjectInputStream\s*\(/i,
            /pickle\.loads?\s*\(/i,
            /yaml\.load\s*\([^)]*\)\s*(?!.*Loader)/i,
            /JSON\.parse\s*\(\s*(?:req|request|params|query|body)/i,
        ];
        for (let i = 0; i < lines.length; i++) {
            for (const p of patterns) {
                if (p.test(lines[i])) {
                    matches.push({
                        line: i + 1,
                        snippet: lines[i].trim(),
                        fix: "// Use safe deserialization. For Java: use white-listing. For Python: use yaml.safe_load().",
                        extra: "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
                    });
                    break;
                }
            }
        }
        return matches;
    },
};
export const allRules = [
    sqlInjection,
    commandInjection,
    hardcodedSecrets,
    xssVulnerability,
    weakAuth,
    weakCrypto,
    pathTraversal,
    corsMisconfiguration,
    regexDoS,
    nplus1Query,
    unsafeDeserialization,
];
export { listRules } from "./lister.js";
export function getAllRules() {
    return allRules;
}
