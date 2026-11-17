import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createSign } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { verifyRegistrySignature, scanSupplyChain, readProvenance } from "../src/detectors/supply-chain.ts";
import { scanSecretsHistory, findSecretsInLog } from "../src/detectors/secrets-history.ts";
import { fuzzGuard, fuzzFindings } from "../src/detectors/fuzz.ts";
import { prioritise } from "../src/integrations/vuln-intel.ts";
import { osvFindings } from "../src/integrations/osv-scanner.ts";
import { refsFor, coverage } from "../src/frameworks.ts";
import { AlertBus } from "../src/alerts.ts";

const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const KEY = { keyid: "SHA256:test", key: publicKey.export({ type: "spki", format: "der" }).toString("base64"), expires: null };
const sign = (msg: string) => { const s = createSign("SHA256"); s.update(msg); return s.sign(privateKey).toString("base64"); };
const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json" } });

test("supply chain: npm registry signatures verify, and tampering is caught", () => {
  const sigs = [{ keyid: "SHA256:test", sig: sign("left-pad@1.3.0:sha512-abc") }];
  assert.equal(verifyRegistrySignature("left-pad", "1.3.0", "sha512-abc", sigs, [KEY]), "valid");
  assert.equal(verifyRegistrySignature("left-pad", "1.3.0", "sha512-EVIL", sigs, [KEY]), "invalid");
  assert.equal(verifyRegistrySignature("left-pad", "1.3.0", "sha512-abc", [], [KEY]), "missing");
  assert.equal(verifyRegistrySignature("left-pad", "1.3.0", "sha512-abc", [{ keyid: "other", sig: "x" }], [KEY]), "unknown-key");
});

test("supply chain: lockfile mismatch, bad signature, foreign provenance and install scripts", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sc-"));
  const integ = (n: string) => "sha512-" + Buffer.from(n.padEnd(64, "x")).toString("base64");
  writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ packages: {
    "": { name: "app" },
    "node_modules/good": { version: "1.0.0", integrity: integ("good") },
    "node_modules/swapped": { version: "1.0.0", integrity: integ("lock-says") },
    "node_modules/forged": { version: "2.0.0", integrity: integ("forged") },
    "node_modules/typo": { version: "1.0.0", integrity: integ("typo") },
    "node_modules/builder": { version: "1.0.0", integrity: integ("builder"), hasInstallScript: true },
    "node_modules/devonly": { version: "1.0.0", integrity: integ("dev"), dev: true },
  } }));
  const att = (repo: string, digestOf: string) => ({ attestations: [{ predicateType: "https://slsa.dev/provenance/v1", bundle: { dsseEnvelope: { payload: Buffer.from(JSON.stringify({ subject: [{ digest: { sha512: Buffer.from(integ(digestOf).slice(7), "base64").toString("hex") } }], predicate: { buildDefinition: { externalParameters: { workflow: { repository: repo } } } } })).toString("base64") } } }] });
  const docs: Record<string, any> = {
    "good/1.0.0": { name: "good", version: "1.0.0", repository: { url: "git+https://github.com/acme/good.git" }, dist: { integrity: integ("good"), signatures: [{ keyid: KEY.keyid, sig: sign(`good@1.0.0:${integ("good")}`) }], attestations: { url: "https://r.test/att/good" } } },
    "swapped/1.0.0": { name: "swapped", version: "1.0.0", dist: { integrity: integ("registry-says"), signatures: [{ keyid: KEY.keyid, sig: sign(`swapped@1.0.0:${integ("registry-says")}`) }] } },
    "forged/2.0.0": { name: "forged", version: "2.0.0", dist: { integrity: integ("forged"), signatures: [{ keyid: KEY.keyid, sig: sign(`forged@2.0.0:${integ("something-else")}`) }] } },
    "typo/1.0.0": { name: "typo", version: "1.0.0", repository: "github:acme/typo", dist: { integrity: integ("typo"), signatures: [{ keyid: KEY.keyid, sig: sign(`typo@1.0.0:${integ("typo")}`) }], attestations: { url: "https://r.test/att/typo" } } },
    "builder/1.0.0": { name: "builder", version: "1.0.0", dist: { integrity: integ("builder"), signatures: [{ keyid: KEY.keyid, sig: sign(`builder@1.0.0:${integ("builder")}`) }] } },
  };
  const fakeFetch = (async (u: string) => {
    if (u.endsWith("/-/npm/v1/keys")) return json({ keys: [KEY] });
    if (u === "https://r.test/att/good") return json(att("https://github.com/acme/good", "good"));
    if (u === "https://r.test/att/typo") return json(att("https://github.com/evil/typo", "typo"));
    const k = u.split("/").slice(-2).join("/");
    return docs[k] ? json(docs[k]) : json({}, 404);
  }) as unknown as typeof fetch;
  const r = await scanSupplyChain(dir, { fetch: fakeFetch });
  assert.equal(r.packages, 5, "dev dependencies are skipped");
  assert.deepEqual(r.findings.map((f) => f.rule).sort(), ["SUPPLY-INSTALL-SCRIPTS", "SUPPLY-INTEGRITY-MISMATCH", "SUPPLY-PROVENANCE-REPO", "SUPPLY-SIGNATURE-INVALID"]);
  assert.equal(r.signed, 4); assert.equal(r.withProvenance, 2);
  assert.match(r.findings.find((f) => f.rule === "SUPPLY-PROVENANCE-REPO")!.detail, /github\.com\/evil\/typo/);
  assert.equal(readProvenance({}), null);
});

test("secrets in history: a key committed then deleted is still found, placeholders are not", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sh-"));
  const git = (...a: string[]) => execFileSync("git", a, { cwd: dir, env: { ...process.env, GIT_AUTHOR_NAME: "dev", GIT_AUTHOR_EMAIL: "d@x", GIT_COMMITTER_NAME: "dev", GIT_COMMITTER_EMAIL: "d@x" } });
  git("init", "-q");
  writeFileSync(join(dir, "config.ts"), 'export const awsKey = "AKIAQWERTYUIOPASDFGH";\nexport const apiKey = "your-api-key-here-xxxxxxxx";\n');
  git("add", "."); git("commit", "-qm", "add config");
  writeFileSync(join(dir, "config.ts"), "export const awsKey = process.env.AWS_KEY;\n");
  git("add", "."); git("commit", "-qm", "remove key");
  const r = await scanSecretsHistory(dir);
  assert.equal(r.commits, 2);
  assert.equal(r.findings.length, 1);
  const f = r.findings[0];
  assert.equal(f.rule, "SECRET-HISTORY-AWS-ACCESS-KEY"); assert.equal(f.severity, "high", "deleted since: high, not critical");
  assert.match(f.title, /deleted since/); assert.ok(!f.detail.includes("AKIAQWERTYUIOPASDFGH"), "the full value is never shown");
  rmSync(dir, { recursive: true, force: true });
  assert.equal(findSecretsInLog('\u0001c1\u000220260101\u0002dev\n+++ b/a.ts\n+const token = "q8Zr2LmX9vK4pT7wN3sB6yHc"\n').map((h) => h.rule)[0], "generic-high-entropy");
});

test("fuzzing: finds crashes, catastrophic regexes and cheap bypasses", () => {
  const naive = (t: string) => /ignore (all )?previous instructions/i.test(t);
  const r = fuzzGuard(naive, { runs: 300 });
  assert.equal(r.crashes.length, 0);
  assert.ok(r.bypasses.some((b) => b.mutation === "double spaces"), "double spaces slip past a naive pattern");
  const crashy = (t: string) => { if (t.includes("\u0000")) throw new Error("bad byte"); return naive(t); };
  assert.ok(fuzzFindings(fuzzGuard(crashy, { runs: 800 }), "g").some((f) => f.rule === "FUZZ-GUARD-CRASH"));
  const redos = (t: string) => /^(a+)+$/.test(t.slice(-26)); // "aaaa…!" backtracks 2^25 times
  const slow = fuzzGuard(redos, { runs: 600, slowMs: 50 });
  assert.ok(slow.slow.length > 0, "nested quantifier is caught as slow");
  assert.ok(fuzzFindings(slow, "g").some((f) => f.rule === "FUZZ-GUARD-REDOS"));
});

test("prioritisation: CISA KEV makes it critical, EPSS raises likely ones, unreachable sources change nothing", async () => {
  const cache = mkdtempSync(join(tmpdir(), "intel-"));
  const base = [
    { source: "system" as const, rule: "SYS-VULN-DEPENDENCY", severity: "medium" as const, title: "lib-a: bug", detail: "d", evidence: { advisories: ["GHSA-aaaa-aaaa-aaaa"] } },
    { source: "system" as const, rule: "SYS-VULN-DEPENDENCY", severity: "low" as const, title: "lib-b: bug", detail: "d", evidence: { advisories: ["GHSA-bbbb-bbbb-bbbb"] } },
    { source: "system" as const, rule: "SYS-VULN-DEPENDENCY", severity: "low" as const, title: "lib-c: bug", detail: "d", evidence: { advisories: ["GHSA-cccc-cccc-cccc"] } },
  ];
  const fakeFetch = (async (u: string) => {
    if (u.includes("known_exploited")) return json({ catalogVersion: "2026.11.13", vulnerabilities: [{ cveID: "CVE-2099-0001", vendorProject: "x", product: "lib-a", vulnerabilityName: "n", dateAdded: "2026-11-01", dueDate: "2026-11-22", knownRansomwareCampaignUse: "Known", requiredAction: "Apply the vendor fix." }] });
    if (u.includes("/vulns/GHSA-aaaa")) return json({ aliases: ["CVE-2099-0001"] });
    if (u.includes("/vulns/GHSA-bbbb")) return json({ aliases: ["CVE-2099-0002"] });
    if (u.includes("/vulns/GHSA-cccc")) return json({ aliases: ["CVE-2099-0003"] });
    if (u.includes("epss")) return json({ data: [{ cve: "CVE-2099-0002", epss: "0.42", percentile: "0.98" }, { cve: "CVE-2099-0003", epss: "0.001", percentile: "0.2" }] });
    return json({}, 404);
  }) as unknown as typeof fetch;
  const p = await prioritise(base, cache, fakeFetch);
  assert.deepEqual(p.findings.map((f) => f.severity), ["critical", "high", "low"]);
  assert.match(p.findings[0].title, /^Known exploited/); assert.match(p.findings[0].detail, /ransomware/);
  assert.match(p.findings[1].detail, /42\.0% chance/);
  assert.equal(p.exploited, 1); assert.equal(p.likely, 1);
  const down = (async () => { throw new Error("blocked"); }) as unknown as typeof fetch;
  const q = await prioritise(base, mkdtempSync(join(tmpdir(), "intel2-")), down);
  assert.deepEqual(q.findings.map((f) => f.severity), ["medium", "low", "low"]); assert.equal(q.intel.sources.kev, "unreachable");
});

test("OSV-Scanner JSON becomes findings with CVE aliases and the fixed version", () => {
  const out = osvFindings(JSON.stringify({ results: [{ source: { path: "/app/package-lock.json" }, packages: [{ package: { name: "body-parser", version: "1.20.2", ecosystem: "npm" },
    vulnerabilities: [{ id: "GHSA-qwcr-r2fm-qrc7", aliases: ["CVE-2024-45590"], summary: "body-parser vulnerable to denial of service", affected: [{ ranges: [{ events: [{ introduced: "0" }, { fixed: "1.20.3" }] }] }] }],
    groups: [{ ids: ["GHSA-qwcr-r2fm-qrc7"], aliases: ["CVE-2024-45590", "GHSA-qwcr-r2fm-qrc7"], max_severity: "7.5" }] }] }] }), "/app");
  assert.equal(out.length, 1); assert.equal(out[0].severity, "high");
  assert.match(out[0].fix!, /1\.20\.3/); assert.ok((out[0].evidence!.advisories as string[]).includes("CVE-2024-45590"));
});

test("frameworks: rules map to OWASP and MITRE, and alerts carry them", () => {
  assert.ok(refsFor("LLM-PROBE-MISS-OBFUSCATION").includes("LLM01"));
  assert.ok(refsFor("ID-LOG-TAMPER").includes("T1562.008"));
  assert.ok(refsFor("SUPPLY-SIGNATURE-INVALID").includes("ASI04"));
  const c = coverage(["LLM-UNFENCED-INPUT", "CODE-EVAL"]);
  assert.ok(c["OWASP Agentic 2026"].covered.includes("ASI05"));
  const bus = new AlertBus(mkdtempSync(join(tmpdir(), "fw-")));
  assert.ok(bus.raise({ source: "ransomware", rule: "RANSOM-NOTE", severity: "critical", title: "t", detail: "d" })!.refs!.includes("T1486"));
});
