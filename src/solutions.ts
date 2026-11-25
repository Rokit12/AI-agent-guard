/**
 * Possible solutions for every kind of finding: a quick fix to contain it now, the proper fix,
 * and how to stop it coming back, with code where it helps and the reference to read.
 * The dashboard shows them in each alert's Solutions tab and in the Solutions view.
 */
export interface Option { kind: "Quick fix" | "Proper fix" | "Prevent it coming back"; steps: string[]; code?: string }
export interface Solution { id: string; match: RegExp; title: string; why: string; options: Option[]; refs: { label: string; url: string }[] }

const CWE = (n: number) => ({ label: `CWE-${n}`, url: `https://cwe.mitre.org/data/definitions/${n}.html` });
const CS = (name: string, file: string) => ({ label: `OWASP ${name} Cheat Sheet`, url: `https://cheatsheetseries.owasp.org/cheatsheets/${file}.html` });

export const SOLUTIONS: Solution[] = [
  // ---- cryptographic failures -------------------------------------------------------------
  { id: "crypto-hash", match: /^CRYPTO-(WEAK-HASH|WEAK-HMAC)/, title: "Replace MD5 and SHA-1", why: "Collisions in MD5 and SHA-1 can be produced on demand, so they cannot protect signatures, tokens or passwords.",
    options: [
      { kind: "Quick fix", steps: ["Change the algorithm name at the flagged line to sha256.", "If the hash is stored, keep accepting the old value only while you re-hash on next use."], code: "createHash('sha256').update(data).digest('hex')\ncreateHmac('sha256', key).update(body).digest('hex')" },
      { kind: "Proper fix", steps: ["Passwords: use Argon2id or bcrypt (cost 12), never a plain hash.", "Message authentication: HMAC-SHA-256 with a key from a secret store."] },
      { kind: "Prevent it coming back", steps: ["Keep the Cryptography scan in CI (npm run scan fails the build on high findings).", "Add a lint rule banning md5/sha1 in security code."] }],
    refs: [CS("Cryptographic Storage", "Cryptographic_Storage_Cheat_Sheet"), CWE(328)] },
  { id: "crypto-cipher", match: /^CRYPTO-(DEPRECATED-CIPHER|STATIC-IV)/, title: "Use AES-256-GCM with a fresh IV", why: "Broken ciphers, ECB mode and repeated IVs let an attacker read or alter encrypted data.",
    options: [
      { kind: "Proper fix", steps: ["Encrypt with AES-256-GCM.", "Generate a new 12-byte IV for every message; store IV and auth tag with the ciphertext.", "Re-encrypt data written with the old scheme."],
        code: "const iv = randomBytes(12);\nconst c = createCipheriv('aes-256-gcm', key, iv);\nconst data = Buffer.concat([c.update(plain), c.final()]);\nconst stored = Buffer.concat([iv, c.getAuthTag(), data]);" },
      { kind: "Prevent it coming back", steps: ["Wrap encryption in one helper module and forbid createCipheriv elsewhere.", "Better still, let AWS KMS or the database do the encryption."] }],
    refs: [CS("Cryptographic Storage", "Cryptographic_Storage_Cheat_Sheet"), CWE(327), CWE(329)] },
  { id: "crypto-random", match: /^CRYPTO-INSECURE-RANDOM/, title: "Generate secrets with a secure random source", why: "Math.random() output can be predicted, so tokens, IDs used as secrets, and codes made with it can be guessed.",
    options: [
      { kind: "Quick fix", steps: ["Replace Math.random() at the flagged line."], code: "import { randomBytes, randomUUID, randomInt } from 'node:crypto';\nconst token = randomBytes(32).toString('base64url');\nconst id = randomUUID();\nconst code = randomInt(100000, 1000000);" },
      { kind: "Prevent it coming back", steps: ["Use ESLint's no-restricted-properties rule to ban Math.random in non-UI code."] }],
    refs: [CWE(338)] },
  { id: "crypto-keys", match: /^CRYPTO-(HARDCODED-KEY|WEAK-KEY|CERT-WEAK-KEY)/, title: "Strong keys, kept out of the code", why: "A key in the code is known to everyone who can read it; a short key can be broken.",
    options: [
      { kind: "Quick fix", steps: ["Rotate the exposed key now: issue a new one and revoke the old.", "Move it to AWS Secrets Manager or KMS and read it at start-up."] },
      { kind: "Proper fix", steps: ["Use RSA 3072, ECDSA P-256 or Ed25519 for new keys.", "For signing and encryption, prefer KMS keys, which never leave AWS."] },
      { kind: "Prevent it coming back", steps: ["Secret scanning in CI (the Secrets in history scan) and pre-commit hooks."] }],
    refs: [CS("Secrets Management", "Secrets_Management_Cheat_Sheet"), CWE(321), CWE(326)] },
  { id: "crypto-jwt", match: /^CRYPTO-JWT-NONE/, title: "Pin JWT algorithms", why: "Accepting alg none, or whatever the token says, lets anyone mint a valid token.",
    options: [{ kind: "Proper fix", steps: ["Always pass the allowed algorithms when verifying."], code: "jwt.verify(token, publicKey, { algorithms: ['RS256'], issuer: ISS, audience: AUD });" }],
    refs: [CWE(347)] },
  { id: "crypto-timing", match: /^CRYPTO-TIMING-COMPARE/, title: "Compare signatures in constant time", why: "=== returns sooner the earlier the first wrong byte, so timing reveals the right signature byte by byte.",
    options: [{ kind: "Proper fix", steps: ["Compare buffers with timingSafeEqual after checking their lengths."], code: "const a = Buffer.from(given), b = Buffer.from(expected);\nconst ok = a.length === b.length && timingSafeEqual(a, b);" }],
    refs: [CWE(208)] },
  { id: "crypto-password", match: /^CRYPTO-WEAK-PASSWORD-HASH/, title: "Slow down password hashing", why: "Fast hashes let a stolen database be cracked at billions of guesses a second.",
    options: [
      { kind: "Proper fix", steps: ["Argon2id (19 MiB memory, 2 iterations), or bcrypt cost 12, or PBKDF2-SHA256 with 600,000 iterations.", "Re-hash each password at its next successful login."] }],
    refs: [CS("Password Storage", "Password_Storage_Cheat_Sheet"), CWE(916)] },
  { id: "crypto-transport", match: /^CRYPTO-(PLAINTEXT-HTTP|CDN-HTTP-ORIGIN|BUCKET-NO-TLS|TLS-OLD-PROTOCOL|TLS-WEAK-CIPHER|NO-FORWARD-SECRECY|OLD-TLS-POLICY|CERT-WEAK-SIGNATURE)/, title: "Encrypt every hop with modern TLS", why: "Plain HTTP or old TLS lets anyone on the path read or change requests, including tokens.",
    options: [
      { kind: "Quick fix", steps: ["Change http:// endpoints to https://.", "S3: enforceSSL: true. CloudFront: minimumProtocolVersion TLS_V1_2_2021. Load balancers: SslPolicy.RECOMMENDED_TLS."] },
      { kind: "Proper fix", steps: ["CDN to origin: give the origin an HTTPS listener with an ACM certificate and use HTTPS_ONLY, or use a CloudFront VPC origin with an internal load balancer so traffic never crosses the internet.", "Re-issue any certificate with a weak key or SHA-1 signature."],
        code: "new origins.HttpOrigin(albDomain, { protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY })\n// or: origins.VpcOrigin.withApplicationLoadBalancer(internalAlb)" },
      { kind: "Prevent it coming back", steps: ["Run the Cryptography scan after every infrastructure change."] }],
    refs: [CS("Transport Layer Security", "Transport_Layer_Security_Cheat_Sheet"), CWE(319)] },
  { id: "crypto-at-rest", match: /^CRYPTO-(STORAGE-UNENCRYPTED|KMS-NO-ROTATION)/, title: "Encrypt data at rest and rotate keys", why: "Unencrypted disks and snapshots, or keys that never change, turn one leak into a full breach.",
    options: [
      { kind: "Proper fix", steps: ["Turn on encryption (EBS, EFS, RDS: encrypted / storageEncrypted: true; S3: S3_MANAGED or KMS).", "Set enableKeyRotation: true on every customer-managed KMS key.", "Existing unencrypted volumes: snapshot, copy encrypted, restore."] }],
    refs: [CS("Cryptographic Storage", "Cryptographic_Storage_Cheat_Sheet"), CWE(311)] },

  // ---- website ----------------------------------------------------------------------------
  { id: "web-headers", match: /^(WEB-NO-|WEB-WEAK-|OWASP-SHP|OWASP-XSS-PROTECTION|WEB-VERSION-LEAK|ZAP-)/, title: "Add the browser security headers", why: "Headers tell browsers to refuse framing, script injection and protocol downgrades. They cost nothing and close whole classes of attack.",
    options: [
      { kind: "Quick fix", steps: ["CloudFront: attach a response headers policy (the managed SecurityHeadersPolicy, or a custom one with a CSP).", "Remove Server / X-Powered-By version strings and the legacy X-XSS-Protection header."],
        code: "new cloudfront.ResponseHeadersPolicy(this, 'Headers', { securityHeadersBehavior: {\n  contentSecurityPolicy: { contentSecurityPolicy: \"default-src 'self'; frame-ancestors 'none'\", override: true },\n  strictTransportSecurity: { accessControlMaxAge: Duration.days(365), includeSubdomains: true, override: true },\n  contentTypeOptions: { override: true }, frameOptions: { frameOption: cloudfront.HeadersFrameOption.DENY, override: true },\n  referrerPolicy: { referrerPolicy: cloudfront.HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN, override: true } } });" },
      { kind: "Proper fix", steps: ["Write a CSP that lists only the script and connect sources the page uses; start in Report-Only mode, then enforce."] }],
    refs: [CS("HTTP Headers", "HTTP_Headers_Cheat_Sheet"), CS("Content Security Policy", "Content_Security_Policy_Cheat_Sheet")] },
  { id: "web-exposure", match: /^WEB-(EXPOSED-FILE|SOURCE-MAP|CORS-|COOKIE-FLAGS|NO-HTTPS-REDIRECT|HTTP-ONLY|CERT-EXPIRING)/, title: "Close what the site exposes", why: "Public config files, source maps and permissive CORS hand attackers the map and the keys.",
    options: [
      { kind: "Quick fix", steps: ["Delete the exposed file and block the path at the CDN; rotate anything it contained.", "Stop uploading .map files to production.", "Allow only your own origins in CORS; set Secure; HttpOnly; SameSite on cookies."] },
      { kind: "Prevent it coming back", steps: ["Deploy from a build folder that contains only what should be public.", "Run the Website scan after every deploy."] }],
    refs: [CS("HTTP Headers", "HTTP_Headers_Cheat_Sheet"), CWE(538)] },

  // ---- malware, leaks, old software ----------------------------------------------------------
  { id: "malware", match: /^(MAL-|RANSOM-|FALCO-RUNTIME)/, title: "Contain, clean, and find the way in", why: "Malware found on a machine that runs a money-moving agent means its credentials and data may already be compromised.",
    options: [
      { kind: "Quick fix", steps: ["Isolate the machine or container (stop the task, remove it from the network).", "Quarantine the file: move it out, keep a copy for analysis, record its SHA-256.", "Rotate every credential the machine could read (AWS keys, Airwallex keys, tokens)."] },
      { kind: "Proper fix", steps: ["Rebuild from a clean image rather than cleaning in place.", "Find the entry point: the install script, upload or login that brought it in.", "Restore data from backups protected by S3 Object Lock."] },
      { kind: "Prevent it coming back", steps: ["Install packages with --ignore-scripts in CI; pin versions with a lockfile.", "Keep the on-access check on the folders the agent reads; add Falco on hosts."] }],
    refs: [{ label: "CISA #StopRansomware Guide", url: "https://www.cisa.gov/stopransomware" }, CWE(506)] },
  { id: "leak", match: /^(LEAK-|LLM-CARD-DATA)/, title: "Stop the leak, then clean up the copies", why: "Data written where it should not be gets copied into backups, log pipelines and support tickets.",
    options: [
      { kind: "Quick fix", steps: ["Rotate any leaked credential now.", "Delete or redact the affected logs and their copies (log groups, S3, backups).", "Remove committed secret files: git rm --cached, add to .gitignore, purge history."] },
      { kind: "Proper fix", steps: ["Mask before logging: card numbers to the last four digits, no secrets or full personal data.", "Shorten log retention for anything that could hold personal data."], code: "const mask = (pan: string) => pan.replace(/\\d(?=\\d{4})/g, '•');\nlogger.info({ card: mask(card) });" },
      { kind: "Prevent it coming back", steps: ["Keep the live leak check on agent logs; add a pre-commit secret scanner."] }],
    refs: [CS("Logging", "Logging_Cheat_Sheet"), { label: "GitHub: removing sensitive data", url: "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository" }, CWE(532)] },
  { id: "old", match: /^(OLD-|SYS-NODE-EOL)/, title: "Upgrade what no longer gets fixes", why: "Deprecated packages and end-of-life runtimes stay vulnerable to every bug found from now on.",
    options: [
      { kind: "Quick fix", steps: ["Runtimes: move to Node.js 22 or 24 (Lambda runtime, Docker base image, host).", "Deprecated packages: follow the publisher's message to the replacement."] },
      { kind: "Proper fix", steps: ["Upgrade far-behind packages one major version at a time, reading each changelog and running the tests."], code: "npm outdated\nnpm install nodemailer@latest\nnpm test" },
      { kind: "Prevent it coming back", steps: ["Enable Dependabot or Renovate for weekly update pull requests.", "Track end-of-life dates (endoflife.date) and plan upgrades a quarter ahead."] }],
    refs: [{ label: "endoflife.date", url: "https://endoflife.date/" }, CS("Vulnerable Dependency Management", "Vulnerable_Dependency_Management_Cheat_Sheet")] },
  { id: "vuln", match: /^(SYS-VULN-DEPENDENCY|OSV-VULN|OWASP-DC-VULN)/, title: "Patch the vulnerable package", why: "A published advisory gives attackers a recipe; exploited ones (CISA KEV) are being used now.",
    options: [
      { kind: "Quick fix", steps: ["Run npm audit fix, or upgrade the package named in the advisory.", "If the fix is in a dependency of a dependency, add an npm overrides entry."], code: "npm audit fix\n# or in package.json:\n\"overrides\": { \"body-parser\": \"^2.2.1\" }" },
      { kind: "Prevent it coming back", steps: ["Fail CI on high advisories; patch anything in CISA KEV within days."] }],
    refs: [CS("Vulnerable Dependency Management", "Vulnerable_Dependency_Management_Cheat_Sheet"), { label: "CISA Known Exploited Vulnerabilities", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" }] },
  { id: "supply", match: /^SUPPLY-/, title: "Trust only verified packages", why: "A package whose signature or source does not match may have been tampered with between the author and you.",
    options: [
      { kind: "Quick fix", steps: ["Delete node_modules and the lockfile entry, reinstall from the registry, and compare.", "Pin the last known-good version."] },
      { kind: "Prevent it coming back", steps: ["npm ci in CI with npm audit signatures; prefer packages with provenance; review install scripts."] }],
    refs: [{ label: "npm: verifying registry signatures", url: "https://docs.npmjs.com/verifying-registry-signatures" }, CWE(494)] },
  { id: "secrets", match: /^(SECRET-HISTORY|CODE-SECRET|SEMGREP-SECRET-TO-LOG|SYS-SECRET-PERMS)/, title: "Rotate the secret, then remove it", why: "Anything ever pushed to git stays in every clone, even after the file is deleted.",
    options: [
      { kind: "Quick fix", steps: ["Rotate the credential at its provider now; that is the only real fix for a leaked secret.", "Remove it from the code and load it from Secrets Manager."] },
      { kind: "Proper fix", steps: ["Purge it from history (git filter-repo), force-push, and ask collaborators to re-clone."] },
      { kind: "Prevent it coming back", steps: ["Pre-commit secret scanning and GitHub push protection."] }],
    refs: [CS("Secrets Management", "Secrets_Management_Cheat_Sheet"), CWE(798)] },

  // ---- agent, model and money ---------------------------------------------------------------
  { id: "injection", match: /^(LLM-PROBE-MISS|PG2-MISS|LLM-REDTEAM|LLM-GARAK|FUZZ-GUARD|FIN-INJECTION-READ|LLM-UNFENCED-INPUT|SEMGREP-UNTRUSTED|FIN-TAINTED-PAYEE|LLM-CONTEXT|LLM-TRAINING)/, title: "Treat outside text as data, never as instructions", why: "Invoices, emails and web pages can carry instructions; the agent must not obey them or let them pick a payee.",
    options: [
      { kind: "Quick fix", steps: ["Fence outside text in <document> tags and tell the model it is data.", "Normalise text before the guard (strip zero-width characters, map look-alike letters, decode base64), as the Fuzzing scan's hardened guard does."] },
      { kind: "Proper fix", steps: ["Never let model output choose a payee, an amount or an approver: take them from your own records.", "Add a model-based classifier (Llama Prompt Guard 2) beside the regex guard."] },
      { kind: "Prevent it coming back", steps: ["Run the fuzzing and red-team scans on every change to prompts or the guard."] }],
    refs: [{ label: "OWASP LLM01: Prompt Injection", url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/" }, CS("LLM Prompt Injection Prevention", "LLM_Prompt_Injection_Prevention_Cheat_Sheet")] },
  { id: "guard-false-positive", match: /^(LLM-PROBE-FALSE-POSITIVE|PG2-FALSE-POSITIVE)/, title: "Stop the guard blocking honest documents", why: "A guard that flags ordinary invoices gets switched off by busy people, which is worse than a weaker guard.",
    options: [{ kind: "Proper fix", steps: ["Look at which benign control was flagged and narrow the matching pattern (or raise the classifier threshold).", "Re-run the probes: every benign control must pass while attacks are still caught."] }],
    refs: [{ label: "OWASP LLM01: Prompt Injection", url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/" }] },
  { id: "money", match: /^(CODE-MONEY|FIN-|ACC-SELF-APPROVAL|ACC-APPROVER|ACC-NO-SEPARATION|LLM-OUTPUT-AS-AMOUNT|SEMGREP-AGENT-MODEL-OUTPUT|AGENT-X402)/, title: "Gate every payment", why: "Money moves should need an approval bound to the exact amount and payee, happen once, and leave a record.",
    options: [
      { kind: "Quick fix", steps: ["Unlogged or mismatched transfer: freeze the payee in Airwallex and contact the bank; check the audit log for who approved."] },
      { kind: "Proper fix", steps: ["Require a person's approval for new payees and amounts over the limit, bound to the exact terms.", "Send an idempotency key with every transfer (request_id), so a retry cannot pay twice.", "Separate requester and approver; take the approver from the signed-in user, never from the request."] },
      { kind: "Prevent it coming back", steps: ["Register the Airwallex webhook so every transfer is reconciled against the agent's log."] }],
    refs: [{ label: "OWASP LLM06: Excessive Agency", url: "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/" }, CWE(840)] },
  { id: "agentic", match: /^(LLM-SYSPROMPT|LLM-VECTOR|LLM-MISINFO|LLM-UNVALIDATED|LLM-OUTPUT-REJECTED|AGENT-MCP|AGENT-A2A|NET-UNAPPROVED-AI|ID-LLMJACKING)/, title: "Harden the agent's model, tools and memory", why: "Secrets in prompts leak, unauthenticated tools can be called by anyone, and unvalidated answers become actions.",
    options: [
      { kind: "Proper fix", steps: ["Keep secrets and approval rules out of system prompts; enforce them in code.", "MCP and A2A: HTTPS, authentication, pinned versions.", "Validate every model answer with a schema before using it.", "Filter retrieval by tenant; screen documents before embedding."] }],
    refs: [{ label: "OWASP Top 10 for LLM Applications", url: "https://genai.owasp.org/llm-top-10/" }] },

  // ---- cloud and identity -----------------------------------------------------------------
  { id: "intrusion", match: /^(ID-|NET-WEBHOOK-EXFIL)/, title: "Respond to a cloud intrusion", why: "Stopped logs, new keys and bursts of secret reads are how intruders take over a cloud account.",
    options: [
      { kind: "Quick fix", steps: ["Disable the access key or role session named in the alert (IAM console: make inactive; revoke active sessions).", "Turn logging back on and check nothing was deleted.", "Rotate secrets that were read."] },
      { kind: "Proper fix", steps: ["Review CloudTrail for everything that principal did since the first alert.", "Remove new users, keys, roles and policy changes it made."] },
      { kind: "Prevent it coming back", steps: ["Require MFA, use short-lived roles instead of user keys, protect the CloudTrail bucket with Object Lock, and send alerts to PagerDuty."] }],
    refs: [{ label: "AWS Security Incident Response Guide", url: "https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html" }] },
  { id: "access", match: /^ACC-/, title: "Narrow who and what can act", why: "Wildcard IAM, public buckets and open routes give an attacker more than they should ever have.",
    options: [
      { kind: "Proper fix", steps: ["Replace * actions and resources with the specific ones used.", "Block public access on buckets; require auth on every route.", "Turn on S3 Object Lock for backups and audit logs."] }],
    refs: [CWE(732), CWE(284)] },
  { id: "host", match: /^(SYS-OPEN-PORT|SYS-ROOT|SYS-SSH|SYS-WORLD-WRITABLE)/, title: "Harden the host", why: "Services open to the network, root processes and weak SSH settings widen what one bug can reach.",
    options: [{ kind: "Proper fix", steps: ["Bind internal services to 127.0.0.1 and close the rest with a security group.", "Run as a non-root user (the Docker image already does).", "SSH: keys only, no root login."] }],
    refs: [CWE(250)] },
  { id: "code", match: /^(CODE-EVAL|CODE-TLS-DISABLED|SEMGREP-)/, title: "Remove dangerous code paths", why: "eval runs any text as code; disabling TLS checks lets anyone impersonate the server.",
    options: [{ kind: "Proper fix", steps: ["Replace eval with a parser (JSON.parse) or a lookup table.", "Remove rejectUnauthorized: false / NODE_TLS_REJECT_UNAUTHORIZED=0; trust the right CA instead."] }],
    refs: [CWE(95), CWE(295)] },
];

/** The solution for a rule, or null; the alert's own fix stays the first step either way. */
export function solutionFor(rule: string): Solution | null { return SOLUTIONS.find((s) => s.match.test(rule)) ?? null; }

/** JSON for the dashboard (RegExp as its source). */
export const solutionsJson = () => SOLUTIONS.map((s) => ({ ...s, match: s.match.source }));
