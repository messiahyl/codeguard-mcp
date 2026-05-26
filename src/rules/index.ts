import { Rule, RuleMatch } from "../scanner.js";

// ==================== INJECTION RULES ====================

const sqlInjection: Rule = {
  id: "SQL_INJECTION",
  category: "injection",
  severity: "critical",
  description: "SQL Injection - string concatenation in SQL queries",
  pattern: (code: string, lines: string[]): RuleMatch[] => {
    const matches: RuleMatch[] = [];
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
            line: i + 1, snippet: lines[i].trim(),
            fix: "// Use parameterized queries / PreparedStatement instead of string concatenation",
            extra: "https://owasp.org/www-community/attacks/SQL_Injection",
          }); break;
        }
      }
    }
    return matches;
  },
};

const commandInjection: Rule = {
  id: "COMMAND_INJECTION",
  category: "injection",
  severity: "critical",
  description: "OS Command Injection - user input passed to system commands",
  pattern: (code: string, lines: string[]): RuleMatch[] => {
    const matches: RuleMatch[] = [];
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
            line: i + 1, snippet: lines[i].trim(),
            fix: "// Sanitize input and use allowlists. Never pass raw user input to system commands.",
            extra: "https://owasp.org/www-community/attacks/Command_Injection",
          }); break;
        }
      }
    }
    return matches;
  },
};

const pathTraversal: Rule = {
  id: "PATH_TRAVERSAL",
  category: "injection",
  severity: "high",
  description: "Path Traversal - user input used in file paths",
  pattern: (code: string, lines: string[]): RuleMatch[] => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /(?:readFile|writeFile|createReadStream|createWriteStream|FileInputStream|Files\.read).*(?:req|request|params|query|body)/i,
      /(?:path\.join|path\.resolve)\s*\(.*(?:req|request|params|query)/i,
    ];
    for (let i = 0; i < lines.length; i++) {
      for (const p of patterns) {
        if (p.test(lines[i])) {
          matches.push({
            line: i + 1, snippet: lines[i].trim(),
            fix: "// Validate and sanitize file paths. Use allowlists for permitted directories.",
            extra: "https://owasp.org/www-community/attacks/Path_Traversal",
          }); break;
        }
      }
    }
    return matches;
  },
};

const unsafeDeserialization: Rule = {
  id: "INSECURE_DESERIALIZATION",
  category: "injection",
  severity: "critical",
  description: "Unsafe deserialization of untrusted data",
  pattern: (code: string, lines: string[]): RuleMatch[] => {
    const matches: RuleMatch[] = [];
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
            line: i + 1, snippet: lines[i].trim(),
            fix: "// Use safe deserialization. For Java: use white-listing. For Python: use yaml.safe_load().",
            extra: "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
          }); break;
        }
      }
    }
    return matches;
  },
};

const ssrf: Rule = {
  id: "SSRF",
  category: "injection",
  severity: "high",
  description: "Server-Side Request Forgery - user-controlled URL",
  pattern: (code: string, lines: string[]): RuleMatch[] => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /(?:fetch|axios|request|http\.get|urllib|requests\.get|requests\.post)\s*\(\s*(?:req|request|params|query|body|input)\b/i,
      /(?:fetch|axios|request|http\.get)\s*\(\s*(?:req|request|params|query|body|input)\.\w+_?url/i,
      /(?:fetch|axios)\s*\(\s*(?:req|request)\.(?:body|params|query)\.\w+/i,
    ];
    for (let i = 0; i < lines.length; i++) {
      for (const p of patterns) {
        if (p.test(lines[i])) {
          matches.push({
            line: i + 1, snippet: lines[i].trim(),
            fix: "// Validate URLs against an allowlist. Block internal IPs (RFC 1918).",
            extra: "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
          }); break;
        }
      }
    }
    return matches;
  },
};

const unvalidatedRedirect: Rule = {
  id: "UNVALIDATED_REDIRECT",
  category: "injection",
  severity: "medium",
  description: "Unvalidated Redirect - user-controlled redirect target",
  pattern: (code: string, lines: string[]): RuleMatch[] => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /(?:redirect|sendRedirect|Response\.redirect)\s*\(\s*(?:req|request|params|query|body|input)\b/i,
      /(?:redirect|sendRedirect)\s*\(\s*(?:req|request)\.\w+/i,
    ];
    for (let i = 0; i < lines.length; i++) {
      for (const p of patterns) {
        if (p.test(lines[i])) {
          matches.push({
            line: i + 1, snippet: lines[i].trim(),
            fix: "// Validate redirect URLs against an allowlist. Never redirect to user-supplied URLs.",
            extra: "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
          }); break;
        }
      }
    }
    return matches;
  },
};

// ==================== SECRETS RULES ====================

const hardcodedSecrets: Rule = {
  id: "HARDCODED_SECRET",
  category: "secrets",
  severity: "critical",
  description: "Hardcoded secrets (API keys, passwords, tokens)",
  pattern: (code: string, lines: string[]): RuleMatch[] => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']/i,
      /(?:api[_-]?key|apikey)\s*[:=]\s*["'][^"']{10,}["']/i,
      /(?:secret|token|auth)\s*[:=]\s*["'][^"']{10,}["']/i,
      /(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY)\s*[:=]\s*["']/i,
      /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/,
      /sk-[a-zA-Z0-9]{20,}/,
      /ghp_[a-zA-Z0-9]{36}/,
      /AKIA[0-9A-Z]{16}/,
    ];
    for (let i = 0; i < lines.length; i++) {
      for (const p of patterns) {
        if (p.test(lines[i])) {
          matches.push({
            line: i + 1, snippet: lines[i].trim().substring(0, 80) + "...",
            fix: "// Move secrets to environment variables or a secrets manager",
            extra: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
          }); break;
        }
      }
    }
    return matches;
  },
};

// ==================== XSS RULES ====================

const xssVulnerability: Rule = {
  id: "XSS",
  category: "xss",
  severity: "high",
  description: "Cross-Site Scripting (XSS) - unescaped user input in output",
  pattern: (code: string, lines: string[]): RuleMatch[] => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /innerHTML\s*=\s*(?:req|request|params|query|body|input|location)/i,
      /innerHTML\s*=\s*\w+(?!\s*["'])/i,
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
            line: i + 1, snippet: lines[i].trim(),
            fix: "// Sanitize/escape user input before rendering. Use textContent instead of innerHTML.",
            extra: "https://owasp.org/www-community/attacks/xss/",
          }); break;
        }
      }
    }
    return matches;
  },
};

// ==================== CRYPTO RULES ====================

const weakCrypto: Rule = {
  id: "WEAK_CRYPTO",
  category: "crypto",
  severity: "high",
  description: "Weak cryptographic algorithms",
  pattern: (code: string, lines: string[]): RuleMatch[] => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /(?:DES|3DES|RC4|RC2|Blowfish)\s*\/(?:ECB|CBC)/i,
      /AES.*\/ECB/i,
      /Cipher\.getInstance\s*\(\s*["']DES/i,
      /CryptoJS\.(?:MD5|SHA1)\s*\(/i,
      /Math\.random\s*\(\s*\)/,
      /hashlib\.(?:md5|sha1)\s*\(/i,
      /MD5(?:CryptoServiceProvider|Create|Digest|Hash)\s*\(/i,
      /MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']/i,
    ];
    for (let i = 0; i < lines.length; i++) {
      for (const p of patterns) {
        if (p.test(lines[i])) {
          matches.push({
            line: i + 1, snippet: lines[i].trim(),
            fix: "// Use AES-256-GCM, ChaCha20-Poly1305. Use SHA-256+ for hashing.",
            extra: "https://owasp.org/www-community/vulnerabilities/Insecure_Cryptographic_Storage",
          }); break;
        }
      }
    }
    return matches;
  },
};

// ==================== AUTHENTICATION ====================

const weakAuth: Rule = {
  id: "WEAK_AUTH",
  category: "authentication",
  severity: "high",
  description: "Weak authentication patterns",
  pattern: (code: string, lines: string[]): RuleMatch[] => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /password\s*[:=]\s*["'][a-zA-Z0-9]{1,6}["']/i,
      /bcrypt.*rounds\s*[:=]\s*[1-9]\b/,
      /compare\s*\(\s*\w+\s*,\s*\w+\s*\)/,
    ];
    for (let i = 0; i < lines.length; i++) {
      for (const p of patterns) {
        if (p.test(lines[i])) {
          matches.push({
            line: i + 1, snippet: lines[i].trim(),
            fix: "// Use strong hashing (bcrypt with cost≥12, argon2). Use constant-time comparison for secrets.",
            extra: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/",
          }); break;
        }
      }
    }
    return matches;
  },
};

// ==================== MISCONFIGURATION ====================

const corsMisconfiguration: Rule = {
  id: "CORS_MISCONFIG",
  category: "misconfiguration",
  severity: "medium",
  description: "CORS misconfiguration - overly permissive origins",
  pattern: (code: string, lines: string[]): RuleMatch[] => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /Access-Control-Allow-Origin\s*[:=]\s*["']\*["']/i,
      /cors\s*\(\s*\{[^}]*origin\s*[:=]\s*["']\*["']/i,
      /@CrossOrigin\s*\(\s*origins\s*=\s*["']\*["']/i,
    ];
    for (let i = 0; i < lines.length; i++) {
      for (const p of patterns) {
        if (p.test(lines[i])) {
          matches.push({
            line: i + 1, snippet: lines[i].trim(),
            fix: "// Specify exact allowed origins. Avoid wildcard '*' in production.",
            extra: "https://owasp.org/www-community/attacks/CORS_OriginScrutiny",
          }); break;
        }
      }
    }
    return matches;
  },
};

// ==================== DoS ====================

const regexDoS: Rule = {
  id: "REGEX_DOS",
  category: "dos",
  severity: "medium",
  description: "Potential ReDoS - dangerous regex patterns",
  pattern: (code: string, lines: string[]): RuleMatch[] => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /\([^)]*[+*][^)]*\)[+*{]/,
      /new RegExp\s*\(\s*["'][^"']*\([^)]*[+*][^)]*\)[+*{]/,
    ];
    for (let i = 0; i < lines.length; i++) {
      for (const p of patterns) {
        if (p.test(lines[i])) {
          matches.push({
            line: i + 1, snippet: lines[i].trim(),
            fix: "// Avoid nested quantifiers in regex. Use atomic groups or possessive quantifiers.",
            extra: "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS",
          }); break;
        }
      }
    }
    return matches;
  },
};

// ==================== INFO EXPOSURE ====================

const infoExposure: Rule = {
  id: "INFO_EXPOSURE",
  category: "misconfiguration",
  severity: "medium",
  description: "Information Exposure - stack traces or errors exposed to users",
  pattern: (code: string, lines: string[]): RuleMatch[] => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /(?:printStackTrace|e\.printStackTrace)\s*\(\s*\)/i,
      /return\s+["'].*Error.*["']\s*\+\s*e\b/i,
      /return\s+["'].*Exception.*["']\s*\+\s*e\b/i,
      /(?:response\.write|res\.send|res\.json).*\b(?:err|error|exception)\b.*(?:stack|message|toString)/i,
      /console\.(log|error)\s*\(\s*(?:err|error|e)\.(?:stack|message)/i,
    ];
    for (let i = 0; i < lines.length; i++) {
      for (const p of patterns) {
        if (p.test(lines[i])) {
          matches.push({
            line: i + 1, snippet: lines[i].trim(),
            fix: "// Log errors server-side only. Return generic error messages to users.",
            extra: "https://owasp.org/www-community/Improper_Error_Handling",
          }); break;
        }
      }
    }
    return matches;
  },
};

// ==================== LOG INJECTION ====================

const logInjection: Rule = {
  id: "LOG_INJECTION",
  category: "injection",
  severity: "medium",
  description: "Log Injection - unsanitized user input in log statements",
  pattern: (code: string, lines: string[]): RuleMatch[] => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /(?:console\.log|logger\.(?:info|debug|warn|error)|log\.(?:info|debug|warn|error)|LOG\.(?:info|debug|warn))\s*\([^)]*(?:req|request|params|query|body|input|user)/i,
      /(?:console\.log|logger\.info)\s*\(\s*["'].*["']\s*\+\s*(?:req|request|params|query|body|user)/i,
    ];
    for (let i = 0; i < lines.length; i++) {
      for (const p of patterns) {
        if (p.test(lines[i])) {
          matches.push({
            line: i + 1, snippet: lines[i].trim(),
            fix: "// Sanitize user input before logging. Remove newlines and control characters.",
            extra: "https://owasp.org/www-community/attacks/Log_Injection",
          }); break;
        }
      }
    }
    return matches;
  },
};

// ==================== INSECURE HTTP ====================

const insecureHttp: Rule = {
  id: "INSECURE_HTTP",
  category: "misconfiguration",
  severity: "medium",
  description: "Insecure HTTP connection - use HTTPS instead",
  pattern: (code: string, lines: string[]): RuleMatch[] => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /(?:fetch|axios|request|http\.get|HttpClient)\s*\(\s*["']http:\/\/[^"']+/i,
      /(?:http\.get|http\.request)\s*\(\s*["']http:\/\/[^"']+/i,
      /["']http:\/\/(?:api|www|service|internal|backend|server)[^"']*["']/i,
    ];
    for (let i = 0; i < lines.length; i++) {
      for (const p of patterns) {
        if (p.test(lines[i])) {
          matches.push({
            line: i + 1, snippet: lines[i].trim(),
            fix: "// Use HTTPS for all external and internal API calls.",
            extra: "https://owasp.org/www-community/Transport_Layer_Protection_Cheat_Sheet",
          }); break;
        }
      }
    }
    return matches;
  },
};

// ==================== PERFORMANCE ====================

const nplus1Query: Rule = {
  id: "N_PLUS_1_QUERY",
  category: "performance",
  severity: "medium",
  description: "Potential N+1 query pattern",
  pattern: (code: string, lines: string[]): RuleMatch[] => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /for\s*\(.*(?:findAll|list|get All|getAll|find).*(?:findById|getById|findOne|getOne)/i,
      /\.forEach\s*\(.*(?:findById|getById|query|execute|fetch)/i,
    ];
    for (let i = 0; i < lines.length; i++) {
      for (const p of patterns) {
        if (p.test(lines[i])) {
          matches.push({
            line: i + 1, snippet: lines[i].trim(),
            fix: "// Batch queries or use JOIN FETCH to avoid N+1 queries.",
          }); break;
        }
      }
    }
    return matches;
  },
};

// ==================== EXPORT ALL ====================

export const allRules: Rule[] = [
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
  ssrf,
  unvalidatedRedirect,
  infoExposure,
  logInjection,
  insecureHttp,
];

export { listRules } from "./lister.js";

export function getAllRules(): Rule[] {
  return allRules;
}
