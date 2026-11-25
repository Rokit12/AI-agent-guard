import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as httpServer } from "node:http";
import { createServer as httpsServer } from "node:https";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cryptoInText, tlsFindings } from "../src/detectors/crypto.ts";
import { scanWebsite } from "../src/detectors/web-scan.ts";
import { solutionFor, SOLUTIONS } from "../src/solutions.ts";
import { refsFor } from "../src/frameworks.ts";

const rules = (t: string, where = "src/a.ts") => cryptoInText(t, where).map((f) => f.rule);

test("crypto: weak hashing, ciphers, IVs, randomness, keys and JWT none are found in code", () => {
  assert.deepEqual(rules("const sig = createHash('md5').update(secret).digest('hex');"), ["CRYPTO-WEAK-HASH"]);
  assert.deepEqual(rules("const etag = createHash('md5').update(body).digest('hex');"), [], "an ETag checksum is not a security use");
  assert.deepEqual(rules("const c = createCipheriv('aes-256-ecb', key, null);"), ["CRYPTO-DEPRECATED-CIPHER"]);
  assert.deepEqual(rules("const c = createCipheriv('aes-256-gcm', key, Buffer.alloc(12));"), ["CRYPTO-STATIC-IV"]);
  assert.deepEqual(rules("const resetToken = Math.random().toString(36).slice(2);").sort(), ["CRYPTO-INSECURE-RANDOM"]);
  assert.equal(cryptoInText("const id = Math.random();", "a.ts")[0].severity, "low", "a predictable ID is less serious than a predictable secret");
  assert.deepEqual(rules("const h = createHmac('sha256', 'super-secret-key-123').update(b);"), ["CRYPTO-HARDCODED-KEY"]);
  assert.deepEqual(rules("generateKeyPairSync('rsa', { modulusLength: 1024 });"), ["CRYPTO-WEAK-KEY"]);
  assert.deepEqual(rules("jwt.verify(t, k, { algorithms: ['none'] });"), ["CRYPTO-JWT-NONE"]);
  assert.deepEqual(rules("if (signature === createHmac('sha256', k).update(b).digest('hex')) ok();"), ["CRYPTO-TIMING-COMPARE"]);
  assert.deepEqual(rules("const ok = a.length === b.length && timingSafeEqual(a, b);"), []);
  assert.deepEqual(rules("await bcrypt.hash(password, 8);"), ["CRYPTO-WEAK-PASSWORD-HASH"]);
  assert.deepEqual(rules("await fetch('http://api.partner-bank.com/v1/pay', opts);"), ["CRYPTO-PLAINTEXT-HTTP"]);
  assert.deepEqual(rules("await fetch('http://127.0.0.1:4600/healthz');"), [], "local calls are fine");
  assert.deepEqual(rules("const x = createHash('sha256').update(token).digest(); const id = randomUUID();"), []);
});

test("crypto: infrastructure code with encryption off, no key rotation, old TLS or an HTTP origin", () => {
  const cdk = [
    'import * as s3 from "aws-cdk-lib/aws-s3";',
    "new efs.FileSystem(this, 'F', { vpc, encrypted: false });",
    "new kms.Key(this, 'K', { description: 'x' });",
    "new kms.Key(this, 'K2', { enableKeyRotation: true });",
    "minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2016,",
    "new s3.Bucket(this, 'B', { versioned: true });",
    "new s3.Bucket(this, 'B2', { enforceSSL: true });",
    "new origins.HttpOrigin(alb, { protocolPolicy: cloudfront.OriginProtocolPolicy.HTTP_ONLY });",
  ].join("\n");
  assert.deepEqual(rules(cdk, "infra/app.ts").sort(), ["CRYPTO-BUCKET-NO-TLS", "CRYPTO-CDN-HTTP-ORIGIN", "CRYPTO-KMS-NO-ROTATION", "CRYPTO-OLD-TLS-POLICY", "CRYPTO-STORAGE-UNENCRYPTED"]);
  assert.deepEqual(rules("const opts = { encrypted: false };", "src/ui.ts"), [], "infrastructure rules only apply to infrastructure code");
  assert.ok(refsFor("CRYPTO-CDN-HTTP-ORIGIN").includes("A04:2025"));
});

test("crypto: live TLS checks catch a weak key, a SHA-1 signature and TLS 1.0/1.1", async () => {
  const d = mkdtempSync(join(tmpdir(), "tls-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:1024", "-sha1", "-nodes", "-keyout", `${d}/k`, "-out", `${d}/c`, "-days", "2", "-subj", "/CN=localhost"], { stdio: "ignore" });
  const srv = httpsServer({ key: readFileSync(`${d}/k`), cert: readFileSync(`${d}/c`), minVersion: "TLSv1", ciphers: "DEFAULT@SECLEVEL=0" }, (_q, r) => r.end("ok"));
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const port = (srv.address() as { port: number }).port;
  const r = await tlsFindings("127.0.0.1", port);
  srv.close();
  const got = r.findings.map((f) => f.rule).sort();
  assert.ok(got.includes("CRYPTO-CERT-WEAK-KEY") && got.includes("CRYPTO-CERT-WEAK-SIGNATURE"));
  assert.equal(got.filter((x) => x === "CRYPTO-TLS-OLD-PROTOCOL").length, 2, "TLS 1.0 and 1.1 are separate alerts");
  assert.equal(new Set(r.findings.map((f) => f.key)).size, r.findings.length);
});

test("website: a site that is not yours gets a passive check of the page only; yours gets the full check", async () => {
  const paths: string[] = [];
  const srv = httpServer((q, r) => { paths.push(q.url!); r.end("<html></html>"); });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.2", r));
  const port = (srv.address() as { port: number }).port;
  const p = await scanWebsite(`http://127.0.0.2:${port}/app`);
  assert.equal(p.mode, "passive"); assert.deepEqual(paths, ["/app"], "no probing for hidden files, maps or CORS");
  paths.length = 0;
  const f = await scanWebsite(`http://127.0.0.2:${port}/app`, { authorised: true });
  srv.close();
  assert.equal(f.mode, "full"); assert.ok(paths.length > 10);
});

test("solutions: every alert family has a playbook with options and references", () => {
  for (const r of ["CRYPTO-WEAK-HASH", "CRYPTO-TLS-OLD-PROTOCOL", "WEB-NO-CSP", "OWASP-SHP-MISSING", "MAL-DROPPER", "RANSOM-MASS-ENCRYPTION", "LEAK-CARD-NUMBER", "OLD-MAJOR-BEHIND", "SYS-VULN-DEPENDENCY", "SUPPLY-SIGNATURE-INVALID",
    "SECRET-HISTORY-AWS", "FUZZ-GUARD-BYPASS", "FIN-UNLOGGED-TRANSFER", "AGENT-MCP-NO-AUTH", "ID-LOG-TAMPER", "ACC-PUBLIC-BUCKET", "SYS-OPEN-PORT", "CODE-EVAL", "LLM-PROBE-FALSE-POSITIVE"]) assert.ok(solutionFor(r), r);
  for (const s of SOLUTIONS) { assert.ok(s.options.length && s.options.every((o) => o.steps.length), s.id); assert.ok(s.refs.every((x) => /^https:\/\//.test(x.url)), s.id); }
  assert.equal(new Set(SOLUTIONS.map((s) => s.id)).size, SOLUTIONS.length);
});
