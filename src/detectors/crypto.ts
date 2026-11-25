/**
 * Cryptographic failures scan (OWASP Top 10:2025 A04, the CWE-310 family).
 *
 *  Code (JavaScript, TypeScript, Python): weak hashes where security depends on them,
 *  deprecated or ECB ciphers, fixed IVs, Math.random() for secrets, hard-coded keys, short RSA
 *  keys, JWT "none", signature checks that are not constant-time, weak password hashing, and
 *  API calls over plain HTTP.
 *  Infrastructure code (CDK, CloudFormation, Terraform): storage with encryption off, KMS keys
 *  without rotation, old TLS policies, buckets that accept plain HTTP, CDN origins over HTTP.
 *  Live TLS on a site: TLS 1.0/1.1 still accepted, weak cipher suites (RC4, 3DES, NULL,
 *  export), no forward secrecy, short certificate keys, SHA-1 or MD5 certificate signatures.
 */
import { connect, type TLSSocket, type ConnectionOptions } from "node:tls";
import { X509Certificate } from "node:crypto";
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, relative, basename, resolve } from "node:path";
import type { Finding, Severity } from "../alerts.ts";

interface CodeRule { id: string; severity: Severity; re: RegExp; title: string; why: string; fix: string; cwe: string; infra?: boolean; when?: (line: string, text: string, idx: number) => boolean }

const SECRETISH = /pass(word|wd|phrase)?|secret|token|api[_-]?key|private|sign(ature)?|hmac|auth|session|nonce|salt|otp|credential|reset|verif/i;
/** The text of the construct call that starts at index i: up to its closing ");" (bounded). */
const callAt = (t: string, i: number) => { const e = t.indexOf(");", i); return t.slice(i, e < 0 ? i + 900 : Math.min(e + 2, i + 1500)); };
const notLocal = (u: string) => !/^http:\/\/(localhost|127\.|0\.0\.0\.0|\[::1\]|169\.254\.|host\.docker\.internal|[\w.-]+\.(local|internal|test|example)\b|example\.(com|org))/i.test(u);

export const CODE_RULES: CodeRule[] = [
  { id: "WEAK-HASH", severity: "high", cwe: "CWE-328", re: /createHash\(\s*['"`](md5|sha1|md4|ripemd160)['"`]\s*\)|hashlib\.(md5|sha1)\(|\bmd5\(|\bsha1\(/i,
    title: "Weak hash used where security depends on it", why: "MD5 and SHA-1 collisions are practical: an attacker can make two different inputs with the same hash.",
    fix: "Use SHA-256 or better for integrity, HMAC-SHA-256 for signatures, and a password hash (Argon2id, scrypt, bcrypt) for passwords.", when: (l) => SECRETISH.test(l) },
  { id: "WEAK-HMAC", severity: "medium", cwe: "CWE-328", re: /createHmac\(\s*['"`](md5|sha1)['"`]/i,
    title: "HMAC built on MD5 or SHA-1", why: "Still hard to forge today, but both are deprecated for new designs and fail most compliance reviews (PCI DSS, NIST SP 800-131A).", fix: "Switch to createHmac('sha256', key)." },
  { id: "DEPRECATED-CIPHER", severity: "high", cwe: "CWE-327", re: /\bcreateCipher\(|\bcreateDecipher\(|createCipheriv\(\s*['"`](des|des3|des-ede3?(-cbc)?|rc4|rc2|bf|blowfish|cast)[^'"`]*['"`]|createCipheriv\(\s*['"`][^'"`]*-ecb['"`]|AES\.new\([^)]*MODE_ECB|DES\.new\(|ARC4\.new\(/i,
    title: "Broken or deprecated cipher", why: "DES, 3DES, RC4 and Blowfish are breakable; ECB mode leaks patterns in the data; createCipher() derives the key with MD5 and no IV.", fix: "Use AES-256-GCM (createCipheriv('aes-256-gcm', key, randomIv)) and keep the auth tag." },
  { id: "STATIC-IV", severity: "high", cwe: "CWE-329", re: /createCipheriv\([^)]*,\s*(Buffer\.alloc\(\s*\d+\s*\)|Buffer\.from\(\s*['"`][^'"`]*['"`][^)]*\)|['"`][^'"`]{8,}['"`])\s*\)/,
    title: "Encryption uses a fixed IV", why: "Re-using an IV with the same key breaks AES-GCM completely and leaks equal plaintexts in CBC.", fix: "Generate a fresh IV for every message with crypto.randomBytes(12) and store it beside the ciphertext." },
  { id: "INSECURE-RANDOM", severity: "high", cwe: "CWE-338", re: /Math\.random\(\)|\brandom\.(random|randint|choice|getrandbits)\(/,
    title: "Predictable random numbers", why: "Math.random() and Python's random module are not cryptographically secure; their output can be predicted from earlier values.", fix: "Use crypto.randomBytes / crypto.randomUUID (Node) or the secrets module (Python).", when: (l) => SECRETISH.test(l) || /\b(id|key|code|pin)\b\s*[:=]/i.test(l) },
  { id: "HARDCODED-KEY", severity: "high", cwe: "CWE-321", re: /create(Cipheriv|Decipheriv|Hmac)\(\s*['"`][\w-]+['"`]\s*,\s*['"`][^'"`]{8,}['"`]|jwt\.(sign|verify)\([^,]+,\s*['"`][^'"`]{4,}['"`]/,
    title: "Encryption or signing key written in the code", why: "Anyone with the code (or the built bundle) has the key, and it cannot be rotated without a release.", fix: "Load the key from a secret store (AWS Secrets Manager, KMS) at run time, and rotate the one that was committed." },
  { id: "WEAK-KEY", severity: "high", cwe: "CWE-326", re: /modulusLength\s*:\s*(512|768|1024|1536)\b|generateKeyPair(Sync)?\(\s*['"`]rsa['"`][^)]*\b(512|768|1024)\b|RSA\.generate\(\s*(512|768|1024)\b/,
    title: "RSA key shorter than 2048 bits", why: "1024-bit RSA is within reach of well-funded attackers; NIST disallowed it after 2013.", fix: "Use RSA 3072 (or 2048 at minimum), or move to ECDSA P-256 / Ed25519." },
  { id: "JWT-NONE", severity: "critical", cwe: "CWE-347", re: /algorithms?\s*:\s*\[?\s*['"`]none['"`]|alg\s*:\s*['"`]none['"`]/i,
    title: "JWT accepts the \"none\" algorithm", why: "A token with alg none has no signature, so anyone can forge one.", fix: "Pin the algorithms: jwt.verify(token, key, { algorithms: ['RS256'] })." },
  { id: "TIMING-COMPARE", severity: "medium", cwe: "CWE-208", re: /\b\w*(signature|hmac|digest|mac|sig|token)\w*\s*(===|!==|==|!=)\s*\w+|\w+\s*(===|!==)\s*\w*(signature|hmac|digest|expectedSig)\w*/i,
    title: "Signature compared with ===, not in constant time", why: "An ordinary comparison stops at the first wrong byte, so response timing reveals how much of a forged signature is right.", fix: "Compare with crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) after checking lengths (hmac.compare_digest in Python).",
    when: (l) => /(createHmac|digest\(|signature|x-signature|hmac)/i.test(l) && !/timingSafeEqual|compare_digest|typeof|\.length|null|undefined|""|''|\bnew\b/.test(l) },
  { id: "WEAK-PASSWORD-HASH", severity: "medium", cwe: "CWE-916", re: /bcrypt\.(hash|hashSync|genSalt|genSaltSync)\([^)]*\b([4-9])\s*\)|pbkdf2(Sync)?\([^)]*,\s*([1-9]\d{0,4})\s*,|iterations\s*[:=]\s*([1-9]\d{0,4})\b/,
    title: "Password hashing is too fast", why: "A low bcrypt cost or under 100,000 PBKDF2 iterations lets a stolen hash database be cracked quickly on GPUs.", fix: "Use Argon2id (19 MiB, 2 passes), bcrypt cost 12, or PBKDF2-SHA256 with 600,000 iterations (OWASP 2023)." },
  { id: "PLAINTEXT-HTTP", severity: "medium", cwe: "CWE-319", re: /(fetch|axios(\.\w+)?|got|request|http\.(get|request)|requests\.(get|post|put|patch|delete))\(\s*['"`](http:\/\/[^'"`\s]+)|(baseURL|endpoint|apiUrl|url)\s*[:=]\s*['"`](http:\/\/[^'"`\s]+)/,
    title: "API called over plain HTTP", why: "Anything sent, including tokens and payment data, can be read or changed on the network.", fix: "Use https:// for every non-local endpoint.", when: (l) => { const u = /http:\/\/[^'"`\s]+/.exec(l)?.[0] ?? ""; return !!u && notLocal(u); } },
  // infrastructure as code
  { id: "STORAGE-UNENCRYPTED", severity: "high", cwe: "CWE-311", infra: true, re: /\b(encrypted|storageEncrypted|encryptionAtRest|kmsEncrypted)\s*[:=]\s*false\b|BucketEncryption\.UNENCRYPTED|StorageEncrypted\s*:\s*false|encrypted\s*=\s*false/,
    title: "Storage with encryption switched off", why: "Disks, databases and buckets without encryption at rest expose data in snapshots, backups and to anyone with raw access.", fix: "Turn encryption on (encrypted: true, storageEncrypted: true, BucketEncryption.S3_MANAGED or KMS)." },
  { id: "KMS-NO-ROTATION", severity: "medium", cwe: "CWE-320", infra: true, re: /new\s+(kms\.)?Key\(\s*this\s*,[^)]*\)|enableKeyRotation\s*:\s*false|enable_key_rotation\s*=\s*false/,
    title: "KMS key without automatic rotation", why: "A key that never rotates protects more data for longer, so one leak exposes everything it ever encrypted.", fix: "Set enableKeyRotation: true (yearly automatic rotation).", when: (l, t, i) => /false/.test(l) || !/enableKeyRotation\s*:\s*true/.test(callAt(t, i)) },
  { id: "OLD-TLS-POLICY", severity: "medium", cwe: "CWE-327", infra: true, re: /SecurityPolicyProtocol\.(SSL_V3|TLS_V1|TLS_V1_2016|TLS_V1_1_2016)\b|SslPolicy\.(TLS10|TLS11|LEGACY|RECOMMENDED|TLS12_EXT|FORWARD_SECRECY_TLS11)\b|ELBSecurityPolicy-(2015|2016-08|TLS-1-0|TLS-1-1)|minimum_protocol_version\s*=\s*"(SSLv3|TLSv1|TLSv1_2016|TLSv1\.1_2016)"/,
    title: "TLS policy still allows TLS 1.0 or 1.1", why: "TLS 1.0 and 1.1 were deprecated in 2021 (RFC 8996) and fail PCI DSS.", fix: "Use SecurityPolicyProtocol.TLS_V1_2_2021 on CloudFront and SslPolicy.RECOMMENDED_TLS (TLS 1.2+) on load balancers." },
  { id: "BUCKET-NO-TLS", severity: "low", cwe: "CWE-319", infra: true, re: /new\s+(s3\.)?Bucket\(\s*this\s*,/,
    title: "S3 bucket accepts requests over plain HTTP", why: "Without a bucket policy that requires TLS, a client can read or write the bucket unencrypted.", fix: "Set enforceSSL: true on the bucket.", when: (l, t, i) => !/enforceSSL\s*:\s*true/.test(callAt(t, i)) },
  { id: "CDN-HTTP-ORIGIN", severity: "medium", cwe: "CWE-319", infra: true, re: /OriginProtocolPolicy\.HTTP_ONLY|protocolPolicy\s*:\s*['"`]http-only['"`]|origin_protocol_policy\s*=\s*"http-only"/,
    title: "CDN talks to its origin over plain HTTP", why: "Traffic between the CDN edge and the origin crosses the internet unencrypted, including Authorization headers and API responses.", fix: "Give the origin an HTTPS listener (ACM certificate) and use HTTPS_ONLY, or use a CloudFront VPC origin so the traffic never leaves AWS's private network." },
];

const SKIP = new Set(["node_modules", ".git", "dist", "build", "cdk.out", "coverage", "state", "sandbox", "outbox", "logs", "runs", "scratch", "target", "test", "tests", "__tests__", "fixtures", ".next"]);
const CODE_EXT = /\.(m?[jt]sx?|cjs|py|tf|ya?ml|json)$/;
const isTestFile = (n: string) => /\.(test|spec)\.[cm]?[jt]sx?$/.test(n);

function* files(root: string, others: string[], depth = 0): Generator<string> {
  if (depth > 6 || (depth > 0 && others.includes(root))) return;
  let names: string[] = []; try { names = readdirSync(root); } catch { return; }
  for (const n of names) {
    if (SKIP.has(n)) continue;
    const p = join(root, n); let st; try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) yield* files(p, others, depth + 1);
    else if (CODE_EXT.test(n) && !isTestFile(n) && !/package(-lock)?\.json$|tsconfig|\.d\.ts$/.test(n) && st.size < 800_000) yield p;
  }
}

/** Scan one file's text (pure; used by the scan and the tests). */
export function cryptoInText(text: string, where: string): Finding[] {
  const out: Finding[] = [];
  const isInfra = /(infra|cdk|terraform|cloudformation|template|stack)/i.test(where) || /\.tf$|\.ya?ml$/.test(where) || /aws-cdk-lib|AWSTemplateFormatVersion|resource\s+"aws_/.test(text);
  const lines = text.split("\n");
  for (const rule of CODE_RULES) {
    if (rule.infra && !isInfra) continue;
    let offset = 0;
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      if (rule.re.test(l) && !/^\s*(\/\/|#|\*)/.test(l) && (!rule.when || rule.when(l, text, offset))) {
        // predictable IDs are a smaller problem than predictable secrets
        const severity: Severity = rule.id === "INSECURE-RANDOM" && !SECRETISH.test(l) ? "low" : rule.severity;
        out.push({ source: "code", rule: `CRYPTO-${rule.id}`, severity, where: `${where}:${i + 1}`, title: rule.title, detail: `${rule.why} Line ${i + 1}: ${l.trim().slice(0, 140)}`, fix: rule.fix, evidence: { cwe: rule.cwe, line: i + 1 } });
      }
      offset += l.length + 1;
    }
  }
  return out;
}

// ---- live TLS ---------------------------------------------------------------------------------
function handshake(host: string, port: number, o: Partial<ConnectionOptions>): Promise<TLSSocket | null> {
  return new Promise((res) => {
    let done = false;
    const s = connect({ host, port, servername: host, rejectUnauthorized: false, ...o }, () => { if (!done) { done = true; res(s); } });
    s.setTimeout(8000, () => { if (!done) { done = true; s.destroy(); res(null); } });
    s.on("error", () => { if (!done) { done = true; res(null); } });
  });
}

const OID = { sha1Rsa: Buffer.from("06092a864886f70d010105", "hex"), md5Rsa: Buffer.from("06092a864886f70d010104", "hex"), sha1Ecdsa: Buffer.from("06072a8648ce3d0401", "hex") };

/** TLS checks for one host. A handful of handshakes, nothing else, like SSL Labs or testssl.sh. */
export async function tlsFindings(host: string, port = 443): Promise<{ findings: Finding[]; passed: string[]; info: Record<string, unknown> }> {
  const findings: Finding[] = [], passed: string[] = [];
  const where = `${host}:${port}`;
  const f = (id: string, severity: Severity, title: string, detail: string, fix: string, cwe: string) =>
    findings.push({ source: "web", rule: `CRYPTO-${id}`, severity, where, title, detail, fix, key: `crypto:${host}:${id}:${title}`, evidence: { cwe } });
  const main = await handshake(host, port, {});
  if (!main) return { findings, passed, info: { reachable: false } };
  const proto = main.getProtocol(), cipher = main.getCipher();
  const peer = main.getPeerCertificate(true);
  main.destroy();
  const info: Record<string, unknown> = { protocol: proto, cipher: cipher?.standardName ?? cipher?.name };
  if (peer?.raw) {
    const x = new X509Certificate(peer.raw);
    const k = x.publicKey; const d = k.asymmetricKeyDetails ?? {};
    info.key = `${k.asymmetricKeyType} ${d.modulusLength ?? d.namedCurve ?? ""}`.trim();
    if (k.asymmetricKeyType === "rsa" && (d.modulusLength ?? 4096) < 2048) f("CERT-WEAK-KEY", "high", `Certificate key is RSA ${d.modulusLength}`, "Keys under 2048 bits can be factored by well-resourced attackers.", "Re-issue the certificate with RSA 2048+ or ECDSA P-256.", "CWE-326");
    else passed.push(`Certificate key: ${info.key}`);
    if (peer.raw.includes(OID.sha1Rsa) || peer.raw.includes(OID.md5Rsa) || peer.raw.includes(OID.sha1Ecdsa)) f("CERT-WEAK-SIGNATURE", "high", "Certificate is signed with SHA-1 or MD5", "Browsers reject these signatures because they can be forged.", "Re-issue the certificate (any current CA signs with SHA-256).", "CWE-328");
    else passed.push("Certificate signed with SHA-256 or better");
  }
  if (proto === "TLSv1.3") passed.push("TLS 1.3 negotiated");
  else if (proto === "TLSv1.2") { if (!/ECDHE|DHE/.test(cipher?.name ?? "")) f("NO-FORWARD-SECRECY", "low", "TLS without forward secrecy", `Negotiated ${cipher?.name}; recorded traffic could be decrypted later if the server key leaks.`, "Prefer ECDHE cipher suites (or enable TLS 1.3).", "CWE-327"); else passed.push(`TLS 1.2 with ${cipher?.name}`); }
  for (const v of ["TLSv1", "TLSv1.1"] as const) {
    const s = await handshake(host, port, { minVersion: v, maxVersion: v, ciphers: "DEFAULT@SECLEVEL=0" });
    if (s) { s.destroy(); f("TLS-OLD-PROTOCOL", "medium", `Server still accepts ${v === "TLSv1" ? "TLS 1.0" : "TLS 1.1"}`, "TLS 1.0 and 1.1 are deprecated (RFC 8996) and fail PCI DSS; downgrade attacks can force clients onto them.", "Allow only TLS 1.2 and 1.3 (CloudFront: TLSv1.2_2021; ALB: a TLS13 policy).", "CWE-327"); }
  }
  if (!findings.some((x) => x.rule === "CRYPTO-TLS-OLD-PROTOCOL")) passed.push("TLS 1.0 and 1.1 refused");
  const weak = await handshake(host, port, { maxVersion: "TLSv1.2", ciphers: "RC4:3DES:DES:NULL:EXPORT:aNULL:eNULL:MD5@SECLEVEL=0" });
  if (weak) { const c = weak.getCipher()?.name; weak.destroy(); f("TLS-WEAK-CIPHER", "high", `Server accepts a weak cipher suite (${c})`, "RC4, 3DES, NULL and export suites can be broken or give no encryption at all.", "Remove them from the server's cipher list; use the provider's current recommended TLS policy.", "CWE-327"); }
  else passed.push("No RC4, 3DES, NULL or export cipher suites");
  return { findings, passed, info };
}

export async function scanCrypto(projects: string[], sites: string[] = [], selfDir?: string) {
  const findings: Finding[] = [], passed: string[] = [];
  let scanned = 0;
  const roots = projects.filter(existsSync).map((p) => resolve(p));
  for (const root of roots) for (const p of files(root, roots)) {
    if (selfDir && (p.startsWith(join(resolve(selfDir), "src", "detectors") + "/") || p === join(resolve(selfDir), "src", "solutions.ts"))) continue; // its own rules and playbooks quote the patterns
    scanned++;
    findings.push(...cryptoInText(readFileSync(p, "utf8"), `${basename(root)}/${relative(root, p)}`));
  }
  const tls: Record<string, unknown> = {};
  for (const s of [...new Set(sites)]) {
    let u: URL; try { u = new URL(/^https?:\/\//.test(s) ? s : `https://${s}`); } catch { continue; }
    if (u.protocol !== "https:") continue;
    const r = await tlsFindings(u.hostname, Number(u.port || 443));
    findings.push(...r.findings); passed.push(...r.passed.map((x) => `${u.hostname}: ${x}`)); tls[u.hostname] = r.info;
  }
  const codeBad = findings.filter((x) => x.source === "code");
  if (!codeBad.some((x) => /WEAK-HASH|DEPRECATED-CIPHER|STATIC-IV/.test(x.rule))) passed.push("No weak hashes, broken ciphers or fixed IVs in code");
  if (!codeBad.some((x) => /INSECURE-RANDOM/.test(x.rule))) passed.push("Secrets are made with a secure random generator");
  if (!codeBad.some((x) => /TIMING-COMPARE/.test(x.rule))) passed.push("Signatures compared in constant time");
  if (!codeBad.some((x) => /STORAGE-UNENCRYPTED|KMS-NO-ROTATION/.test(x.rule))) passed.push("Storage encrypted at rest; KMS keys rotate");
  return { findings, passed, scanned, tls, summary: `${scanned} code and infrastructure files${sites.length ? ` · TLS on ${Object.keys(tls).length} site${Object.keys(tls).length === 1 ? "" : "s"}` : ""}` };
}
