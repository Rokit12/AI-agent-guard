/**
 * Maps every rule to the frameworks security teams report against:
 *  - OWASP Top 10 for LLM Applications 2025 (LLM01-LLM10)
 *  - OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10, published December 2025)
 *  - OWASP Top 10:2025 for web applications (A01-A10)
 *  - MITRE ATT&CK (Enterprise, cloud) and MITRE ATLAS (attacks on AI systems)
 * so an alert can be filed under the control it belongs to, and coverage can be shown.
 */
export const NAMES: Record<string, string> = {
  T1496: "Resource Hijacking", T1557: "Adversary-in-the-Middle", "T1600": "Weaken Encryption", "T1552.005": "Cloud Instance Metadata API", T1059: "Command and Scripting Interpreter", "T1505.003": "Server Software Component: Web Shell", T1027: "Obfuscated Files or Information", T1105: "Ingress Tool Transfer", T1555: "Credentials from Password Stores", "T1036": "Masquerading", T1005: "Data from Local System", "T1552": "Unsecured Credentials",
  LLM04: "Data and Model Poisoning", LLM07: "System Prompt Leakage", LLM08: "Vector and Embedding Weaknesses", LLM09: "Misinformation", ASI06: "Memory & Context Poisoning", ASI07: "Insecure Inter-Agent Communication",
  LLM01: "Prompt Injection", LLM02: "Sensitive Information Disclosure", LLM03: "Supply Chain", LLM05: "Improper Output Handling", LLM06: "Excessive Agency", LLM10: "Unbounded Consumption",
  ASI01: "Agent Goal Hijack", ASI02: "Tool Misuse and Exploitation", ASI03: "Identity and Privilege Abuse", ASI04: "Agentic Supply Chain Vulnerabilities", ASI05: "Unexpected Code Execution", ASI08: "Cascading Failures", ASI09: "Human-Agent Trust Exploitation", ASI10: "Rogue Agents",
  "A01:2025": "Broken Access Control", "A02:2025": "Security Misconfiguration", "A03:2025": "Software Supply Chain Failures", "A04:2025": "Cryptographic Failures", "A05:2025": "Injection", "A06:2025": "Insecure Design", "A07:2025": "Authentication Failures", "A08:2025": "Software or Data Integrity Failures", "A09:2025": "Security Logging and Alerting Failures", "A10:2025": "Mishandling of Exceptional Conditions",
  "AML.T0051": "LLM Prompt Injection", "AML.T0010": "AI Supply Chain Compromise",
  T1110: "Brute Force: Password Spraying", "T1078.004": "Valid Accounts: Cloud Accounts", T1580: "Cloud Infrastructure Discovery", "T1059.009": "Command and Scripting: Cloud API", T1098: "Account Manipulation", "T1136.003": "Create Account: Cloud Account",
  "T1548.005": "Temporary Elevated Cloud Access", "T1555.006": "Cloud Secrets Management Stores", "T1562.008": "Disable or Modify Cloud Logs", T1537: "Transfer Data to Cloud Account", T1567: "Exfiltration Over Web Service",
  T1486: "Data Encrypted for Impact", T1485: "Data Destruction", T1490: "Inhibit System Recovery", "T1552.001": "Unsecured Credentials: Credentials in Files", "T1195.001": "Supply Chain Compromise: Software Dependencies", T1499: "Endpoint Denial of Service",
};

const MAP: [RegExp, string[]][] = [
  [/^(LLM-PROBE-MISS|PG2-MISS|FUZZ-GUARD-BYPASS|FIN-INJECTION-READ|LLM-UNFENCED-INPUT)/, ["LLM01", "ASI01", "AML.T0051", "A05:2025"]],
  [/^(LLM-PROBE-FALSE-POSITIVE|PG2-FALSE-POSITIVE)/, ["LLM01", "ASI09"]],
  [/^FUZZ-GUARD-REDOS/, ["LLM10", "T1499"]],
  [/^FUZZ-GUARD-CRASH/, ["LLM01", "A10:2025"]],
  [/^(SEMGREP-AGENT-MODEL-OUTPUT-TO-PAYMENT|LLM-OUTPUT-AS-AMOUNT)/, ["LLM05", "LLM06", "ASI02"]],
  [/^LLM-OUTPUT-REJECTED/, ["LLM05", "LLM09"]],
  [/^LLM-CARD-DATA/, ["LLM02", "A04:2025"]],
  [/^(SEMGREP-UNTRUSTED-TEXT-TO-PAYEE|FIN-TAINTED-PAYEE)/, ["LLM01", "ASI01", "ASI02"]],
  [/^(CODE-MONEY-NO-APPROVAL|FIN-UNAPPROVED|FIN-OVER-APPROVED|FIN-NEW-PAYEE)/, ["LLM06", "ASI02", "ASI09"]],
  [/^(CODE-MONEY-NO-IDEMPOTENCY|FIN-DOUBLE-PAY|FIN-DUPLICATE-AMOUNT|FIN-NO-IDEMPOTENCY|FIN-VELOCITY)/, ["ASI08", "LLM06"]],
  [/^(FIN-UNLOGGED-TRANSFER|FIN-RECON-MISMATCH)/, ["ASI10", "A09:2025"]],
  [/^FIN-WEBHOOK-REJECTED/, ["A08:2025"]],
  [/^(CODE-SECRET|SECRET-HISTORY|SEMGREP-SECRET-TO-LOG|SYS-SECRET-PERMS)/, ["LLM02", "A04:2025", "T1552.001"]],
  [/^CODE-TLS-DISABLED/, ["A04:2025"]],
  [/^CODE-EVAL/, ["ASI05", "A05:2025"]],
  [/^(SYS-VULN-DEPENDENCY|OSV-VULN|OWASP-DC-VULN)/, ["LLM03", "ASI04", "A03:2025", "T1195.001"]],
  [/^SUPPLY-/, ["LLM03", "ASI04", "A03:2025", "A08:2025", "AML.T0010", "T1195.001"]],
  [/^(ACC-SELF-APPROVAL|ACC-APPROVER-FROM-INPUT|ACC-NO-SEPARATION)/, ["ASI03", "ASI09", "A01:2025"]],
  [/^ACC-NO-IMMUTABLE-BACKUP/, ["T1490", "A02:2025"]],
  [/^ACC-/, ["ASI03", "A01:2025", "A02:2025"]],
  [/^(RANSOM-MASS-ENCRYPTION|RANSOM-EXTENSION|RANSOM-NOTE|RANSOM-BURST|RANSOM-PROCESS)/, ["T1486"]],
  [/^RANSOM-BACKUP-WIPE/, ["T1490"]],
  [/^ID-S3-MASS-DELETE/, ["T1485", "T1486"]],
  [/^ID-SPRAY/, ["T1110", "T1078.004", "A07:2025"]],
  [/^ID-NO-MFA-LOGIN/, ["T1078.004", "A07:2025"]],
  [/^(ID-PERMISSION-PROBE|ID-ENUMERATION)/, ["T1580"]],
  [/^ID-MACHINE-SPEED/, ["T1059.009"]],
  [/^ID-PERSISTENCE/, ["T1098", "T1136.003"]],
  [/^ID-ROLE-CHAIN/, ["T1548.005", "ASI03"]],
  [/^ID-SECRETS-BURST/, ["T1555.006"]],
  [/^ID-LOG-TAMPER/, ["T1562.008", "A09:2025"]],
  [/^ID-SNAPSHOT-SHARE/, ["T1537"]],
  [/^NET-WEBHOOK-EXFIL/, ["T1567"]],
  [/^NET-UNAPPROVED-AI/, ["T1567", "LLM02"]],
  [/^LLM-SYSPROMPT/, ["LLM07", "LLM02"]],
  [/^LLM-VECTOR/, ["LLM08", "ASI06"]],
  [/^(LLM-CONTEXT|LLM-TRAINING)/, ["LLM04", "ASI06"]],
  [/^(LLM-MISINFO|LLM-UNVALIDATED-OUTPUT)/, ["LLM09"]],
  [/^AGENT-X402/, ["ASI07", "ASI02"]],
  [/^AGENT-(MCP|A2A)/, ["ASI07", "ASI04"]],
  [/^ID-LOG-LIFECYCLE/, ["T1562.008", "T1485", "A09:2025"]],
  [/^ID-S3-SSEC-ENCRYPT/, ["T1486"]],
  [/^ID-LLMJACKING/, ["T1496", "LLM10", "T1078.004"]],
  [/^ID-INSTANCE-RECON/, ["T1580", "T1552.005"]],
  [/^CRYPTO-(PLAINTEXT-HTTP|CDN-HTTP-ORIGIN|BUCKET-NO-TLS|TLS-|NO-FORWARD-SECRECY|OLD-TLS-POLICY)/, ["A04:2025", "T1557"]],
  [/^CRYPTO-(HARDCODED-KEY|STORAGE-UNENCRYPTED)/, ["A04:2025", "LLM02", "T1552.001"]],
  [/^CRYPTO-/, ["A04:2025"]],
  [/^MAL-REVERSE-SHELL/, ["T1059", "A08:2025"]],
  [/^MAL-WEBSHELL/, ["T1505.003", "A05:2025"]],
  [/^MAL-MINER/, ["T1496"]],
  [/^MAL-OBFUSCATED-EXEC/, ["T1027", "A08:2025"]],
  [/^MAL-DROPPER/, ["T1105", "A08:2025", "T1195.001"]],
  [/^MAL-CREDENTIAL-STEALER/, ["T1555", "T1552.001", "LLM02"]],
  [/^MAL-(HIDDEN-EXECUTABLE|EXECUTABLE-IN-DATA)/, ["T1036"]],
  [/^MAL-/, ["A08:2025", "T1195.001"]],
  [/^LEAK-(CARD-NUMBER|BULK-PII|TEST-CARD)/, ["LLM02", "A04:2025", "T1005"]],
  [/^LEAK-SECRET-IN-LOGS/, ["LLM02", "A09:2025", "T1552.001"]],
  [/^LEAK-SENSITIVE-FILE-TRACKED/, ["A04:2025", "T1552.001"]],
  [/^OLD-/, ["A03:2025", "LLM03", "ASI04"]],
  [/^(WEB-|OWASP-SHP|OWASP-XSS-PROTECTION|ZAP-)/, ["A02:2025"]],
  [/^(SYS-OPEN-PORT|SYS-ROOT|SYS-SSH|SYS-WORLD-WRITABLE|SYS-NODE-EOL|FALCO-RUNTIME)/, ["A02:2025"]],
];

export function refsFor(rule: string): string[] {
  for (const [re, refs] of MAP) if (re.test(rule)) return refs;
  return [];
}

export const refLabel = (r: string) => {
  const kind = /^LLM/.test(r) ? "OWASP LLM" : /^ASI/.test(r) ? "OWASP Agentic" : /^A\d\d:/.test(r) ? "OWASP" : /^AML/.test(r) ? "ATLAS" : "ATT&CK";
  return { id: r, kind, name: NAMES[r] ?? r, url: /^T\d/.test(r) ? `https://attack.mitre.org/techniques/${r.replace(".", "/")}/` : /^AML/.test(r) ? `https://atlas.mitre.org/techniques/${r}` : undefined };
};

/** Which items of each framework have at least one rule watching them. */
export function coverage(rules: string[]) {
  const hit = new Set(rules.flatMap(refsFor));
  const all = { "OWASP LLM 2025": Array.from({ length: 10 }, (_, i) => `LLM${String(i + 1).padStart(2, "0")}`), "OWASP Agentic 2026": Array.from({ length: 10 }, (_, i) => `ASI${String(i + 1).padStart(2, "0")}`) };
  return Object.fromEntries(Object.entries(all).map(([k, ids]) => [k, { covered: ids.filter((i) => hit.has(i)), missing: ids.filter((i) => !hit.has(i)) }]));
}
