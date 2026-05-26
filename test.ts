#!/usr/bin/env node
/**
 * CodeGuard MCP Server - Full Integration Test
 * Tests all 12 security rules with positive and negative cases
 */

import { scanCode } from "./src/scanner.js";
import { getAllRules } from "./src/rules/index.js";

interface TestCase {
  name: string;
  ruleId: string;
  code: string;
  language: string;
  shouldDetect: boolean;
  description: string;
}

const tests: TestCase[] = [
  // SQL Injection
  {
    name: "SQL Injection - Java string concat",
    ruleId: "SQL_INJECTION",
    code: `String query = "SELECT * FROM users WHERE id = " + request.getParameter("id");
ResultSet rs = statement.executeQuery(query);`,
    language: "java",
    shouldDetect: true,
    description: "Should detect string concatenation in SQL query with user input"
  },
  {
    name: "SQL Injection - Safe parameterized",
    ruleId: "SQL_INJECTION",
    code: `PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setString(1, userId);`,
    language: "java",
    shouldDetect: false,
    description: "Should NOT flag parameterized queries"
  },

  // Command Injection
  {
    name: "Command Injection - eval with user input",
    ruleId: "COMMAND_INJECTION",
    code: `const result = eval(request.body.expression);
console.log(result);`,
    language: "javascript",
    shouldDetect: true,
    description: "Should detect eval with user input"
  },
  {
    name: "Command Injection - Safe JSON.parse",
    ruleId: "COMMAND_INJECTION",
    code: `const data = JSON.parse(request.body);
console.log(data.name);`,
    language: "javascript",
    shouldDetect: false,
    description: "Should NOT flag JSON.parse"
  },

  // Hardcoded Secrets
  {
    name: "Hardcoded Secret - password",
    ruleId: "HARDCODED_SECRET",
    code: `const dbConfig = {
  host: "localhost",
  password: "super_secret_password_123"
};`,
    language: "typescript",
    shouldDetect: true,
    description: "Should detect hardcoded password"
  },
  {
    name: "Hardcoded Secret - safe env var",
    ruleId: "HARDCODED_SECRET",
    code: `const dbConfig = {
  host: process.env.DB_HOST,
  password: process.env.DB_PASSWORD
};`,
    language: "typescript",
    shouldDetect: false,
    description: "Should NOT flag environment variable usage"
  },

  // XSS
  {
    name: "XSS - innerHTML with user input",
    ruleId: "XSS",
    code: `document.getElementById("output").innerHTML = request.params.html;
element.innerHTML = userInput;`,
    language: "javascript",
    shouldDetect: true,
    description: "Should detect innerHTML with user input"
  },
  {
    name: "XSS - safe textContent",
    ruleId: "XSS",
    code: `document.getElementById("output").textContent = userInput;`,
    language: "javascript",
    shouldDetect: false,
    description: "Should NOT flag textContent"
  },

  // Path Traversal
  {
    name: "Path Traversal - readFile with user input",
    ruleId: "PATH_TRAVERSAL",
    code: `const filePath = path.join(__dirname, request.query.file);
const data = fs.readFileSync(filePath, "utf-8");`,
    language: "javascript",
    shouldDetect: true,
    description: "Should detect path traversal via user input"
  },

  // Insecure Deserialization
  {
    name: "Insecure Deserialization - pickle",
    ruleId: "INSECURE_DESERIALIZATION",
    code: `import pickle
data = pickle.loads(request.body)
print(data)`,
    language: "python",
    shouldDetect: true,
    description: "Should detect pickle deserialization of user input"
  },

  // Weak Crypto
  {
    name: "Weak Crypto - MD5",
    ruleId: "WEAK_CRYPTO",
    code: `import hashlib
hash = hashlib.md5(password.encode()).hexdigest()`,
    language: "python",
    shouldDetect: true,
    description: "Should detect MD5 usage"
  },
  {
    name: "Weak Crypto - safe SHA256",
    ruleId: "WEAK_CRYPTO",
    code: `import hashlib
hash = hashlib.sha256(password.encode()).hexdigest()`,
    language: "python",
    shouldDetect: false,
    description: "Should NOT flag SHA256"
  },

  // SSRF
  {
    name: "SSRF - fetch with user URL",
    ruleId: "SSRF",
    code: `const response = await fetch(request.body.url);
const data = await response.json();`,
    language: "typescript",
    shouldDetect: true,
    description: "Should detect SSRF via user-controlled URL"
  },

  // Unvalidated Redirect
  {
    name: "Unvalidated Redirect",
    ruleId: "UNVALIDATED_REDIRECT",
    code: `res.redirect(request.query.redirect_url);`,
    language: "javascript",
    shouldDetect: true,
    description: "Should detect open redirect"
  },

  // Information Exposure
  {
    name: "Information Exposure - stack trace",
    ruleId: "INFO_EXPOSURE",
    code: `} catch (Exception e) {
    e.printStackTrace();
    return "Error: " + e.toString();`,
    language: "java",
    shouldDetect: true,
    description: "Should detect stack trace exposure"
  },

  // Log Injection
  {
    name: "Log Injection",
    ruleId: "LOG_INJECTION",
    code: `console.log("User input: " + request.params.name);
logger.info("Login from: " + userInput);`,
    language: "javascript",
    shouldDetect: true,
    description: "Should detect log injection"
  },

  // Insecure HTTP
  {
    name: "Insecure HTTP",
    ruleId: "INSECURE_HTTP",
    code: `fetch("http://api.example.com/data")
axios.get("http://internal-service/users")`,
    language: "typescript",
    shouldDetect: true,
    description: "Should detect HTTP (non-HTTPS) URLs"
  },

  // Negative case - clean code
  {
    name: "Clean Code - no issues",
    ruleId: "",
    code: `function add(a: number, b: number): number {
  return a + b;
}

const result = add(1, 2);
console.log("Result:", result);`,
    language: "typescript",
    shouldDetect: false,
    description: "Should find zero issues in clean code"
  },
];

// Run tests
let passed = 0;
let failed = 0;
let totalRules = getAllRules().length;

console.log("=".repeat(60));
console.log("  CodeGuard MCP Server - Full Test Suite");
console.log("=".repeat(60));
console.log(`\nTotal rules registered: ${totalRules}`);
console.log(`Total test cases: ${tests.length}\n`);

for (const test of tests) {
  const results = scanCode(test.code, test.language, {
    severityThreshold: "low",
    rulesFilter: test.ruleId ? [test.ruleId] : undefined,
  });

  const detected = results.length > 0;
  const ok = detected === test.shouldDetect;

  if (ok) {
    passed++;
    console.log(`  ✅ PASS: ${test.name}`);
  } else {
    failed++;
    console.log(`  ❌ FAIL: ${test.name}`);
    console.log(`     Expected: ${test.shouldDetect ? 'detect' : 'no detection'}, Got: ${detected ? `detected ${results.length} issues` : 'no detection'}`);
    if (results.length > 0) {
      console.log(`     Issues: ${results.map(r => r.ruleId).join(', ')}`);
    }
  }
}

console.log("\n" + "=".repeat(60));
console.log(`  Results: ${passed}/${tests.length} passed, ${failed} failed`);
console.log(`  Rules coverage: ${totalRules} rules loaded`);
console.log("=".repeat(60));

if (failed > 0) {
  process.exit(1);
} else {
  console.log("\n  🎉 All tests passed! CodeGuard is ready for production.");
  process.exit(0);
}
