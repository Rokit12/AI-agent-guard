import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PaymentLedger, verifyAirwallexSignature } from "../src/detectors/reconcile.ts";
import { semgrepFindings, semgrepAvailable, runSemgrep } from "../src/integrations/semgrep.ts";
import { maliciousScore, promptGuardSummary, type GuardCompare } from "../src/integrations/prompt-guard.ts";
import { FalcoFeed } from "../src/integrations/falco.ts";
import { replayCoverage } from "../src/integrations/stratus.ts";
import { attachChannels, slackMessage, pagerDutyEvent } from "../src/notify/channels.ts";
import { auditAccess } from "../src/detectors/access-control.ts";
import { IdentityMonitor } from "../src/detectors/identity.ts";
import { AlertBus } from "../src/alerts.ts";
import { PROBES } from "../src/detectors/llm-probes.ts";

const sign = (secret: string, ts: string, body: string) => createHmac("sha256", secret).update(ts + body).digest("hex");

test("airwallex webhook: valid signature passes; tampered body, wrong secret and old timestamp fail", () => {
  const body = JSON.stringify({ id: "evt_1", name: "payout.transfer.paid" }), ts = String(Date.now());
  assert.equal(verifyAirwallexSignature(body, ts, sign("s3cret", ts, body), "s3cret").ok, true);
  assert.equal(verifyAirwallexSignature(body + " ", ts, sign("s3cret", ts, body), "s3cret").ok, false);
  assert.equal(verifyAirwallexSignature(body, ts, sign("other", ts, body), "s3cret").ok, false);
  const old = String(Date.now() - 10 * 60_000);
  assert.match(verifyAirwallexSignature(body, old, sign("s3cret", old, body), "s3cret").why, /replay/);
  assert.equal(verifyAirwallexSignature(body, undefined, undefined, "s3cret").ok, false);
});

test("reconciliation: matched transfer is quiet, altered amount and unlogged transfer are critical", () => {
  const l = new PaymentLedger(60_000);
  l.add({ kind: "call", method: "POST", path: "/transfers/create", status: 201, req: { request_id: "exp-1", transfer_amount: "86.40", transfer_currency: "USD", beneficiary_id: "ben_a" }, res: { id: "tr_1" } }, "run1");
  l.add({ kind: "call", method: "POST", path: "/transfers/create", status: 201, req: { request_id: "ref-1", transfer_amount: "120", transfer_currency: "USD", beneficiary_id: "ben_b" }, res: { id: "tr_2" } }, "run1");
  const ev = (name: string, o: Record<string, unknown>) => ({ id: `e-${o.id}`, name, data: { object: o } });
  assert.deepEqual(l.ingest(ev("payout.transfer.paid", { id: "tr_1", transfer_amount: 86.4, transfer_currency: "USD", beneficiary_id: "ben_a" })), []);
  assert.deepEqual(l.ingest(ev("payout.transfer.sent", { id: "tr_2", transfer_amount: 1200, transfer_currency: "USD", beneficiary_id: "ben_b" })).map((f) => f.rule), ["FIN-RECON-MISMATCH"]);
  const t0 = Date.now();
  assert.deepEqual(l.ingest(ev("payout.transfer.processing", { id: "tr_x", transfer_amount: 9800, transfer_currency: "USD" }), t0), [], "waits out the grace period");
  const late = l.sweep(t0 + 61_000);
  assert.deepEqual(late.map((f) => [f.rule, f.severity]), [["FIN-UNLOGGED-TRANSFER", "critical"]]);
  assert.deepEqual(l.ingest(ev("payout.transfer.in_approval", { id: "tr_y" })), [], "approval-stage events are not money moving");
});

test("reconciliation: a log line that arrives within the grace period clears the transfer", () => {
  const l = new PaymentLedger(60_000), t0 = Date.now();
  l.ingest({ name: "payout.transfer.sent", data: { object: { id: "tr_late", request_id: "r-late", transfer_amount: 50, transfer_currency: "USD" } } }, t0);
  l.add({ kind: "call", method: "POST", path: "/transfers/create", status: 201, req: { request_id: "r-late", transfer_amount: 50, transfer_currency: "USD" }, res: { id: "tr_late" } }, "run2");
  assert.deepEqual(l.sweep(t0 + 120_000), []);
});

test("semgrep: results map to findings, and an approval just before the payment lowers it to low", () => {
  const dir = mkdtempSync(join(tmpdir(), "sg-"));
  writeFileSync(join(dir, "a.ts"), "const a = await requestApproval(terms);\nif (a.approved) {\n  await awx.post('/transfers/create', body);\n}\n");
  const json = JSON.stringify({ results: [
    { check_id: "rules.agent-model-output-to-payment", path: "a.ts", start: { line: 3 }, extra: { message: "flows", severity: "ERROR", metadata: { "agent-shield-severity": "high" } } },
    { check_id: "rules.untrusted-text-to-payee", path: "b.ts", start: { line: 9 }, extra: { message: "payee", severity: "ERROR", metadata: { "agent-shield-severity": "critical" } } },
  ] });
  const f = semgrepFindings(json, dir);
  assert.deepEqual(f.map((x) => [x.rule, x.severity]), [["SEMGREP-AGENT-MODEL-OUTPUT-TO-PAYMENT", "low"], ["SEMGREP-UNTRUSTED-TEXT-TO-PAYEE", "critical"]]);
});

test("semgrep: the shipped rules catch model output, email text and secrets flowing to sinks", { skip: !semgrepAvailable() && "semgrep not installed" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "sgr-"));
  writeFileSync(join(dir, "bad.ts"), `declare const awx: any; declare function extract(...a: any[]): any; declare const email: { body: string };
export async function pay() {
  const { value } = await extract("payee", email.body, () => true, () => ({}));
  await awx.post("/transfers/create", { transfer_amount: value.amount, beneficiary_id: "ben_1" });
  await awx.post("/beneficiaries/create", { bank_details: { account_number: email.body.slice(0, 8) } });
  console.log("key", process.env.AWX_API_KEY);
}
`);
  const r = await runSemgrep(dir);
  const ids = new Set(r.findings.map((f) => f.rule));
  for (const id of ["SEMGREP-AGENT-MODEL-OUTPUT-TO-PAYMENT", "SEMGREP-UNTRUSTED-TEXT-TO-PAYEE", "SEMGREP-SECRET-TO-LOG"]) assert.ok(ids.has(id), id);
});

test("prompt guard: reads both response shapes and summarises against the probes", () => {
  assert.equal(maliciousScore([{ label: "MALICIOUS", score: 0.97 }, { label: "BENIGN", score: 0.03 }]), 0.97);
  assert.equal(maliciousScore([[{ label: "LABEL_0", score: 0.9 }, { label: "LABEL_1", score: 0.1 }]]), 0.1);
  const results: GuardCompare[] = PROBES.map((p) => ({ probe: p, score: p.family === "multilingual" ? 0.2 : p.attack ? 0.9 : 0.1, flagged: p.family !== "multilingual" && p.attack, ok: p.family !== "multilingual" }));
  const s = promptGuardSummary(results);
  assert.equal(s.attacks, 16); assert.equal(s.caught, 13); assert.deepEqual(s.missed, ["swahili", "french", "spanish"]);
});

test("falco: ransomware rule names the process and grows one incident", () => {
  const feed = new FalcoFeed();
  const a = { rule: "Agent Shield ransomware extension rename", priority: "Critical", hostname: "h1", tags: ["agent_shield", "ransomware"], output: "renamed", output_fields: { "proc.name": "syncd", "proc.pid": 42, "evt.arg.newpath": "/srv/x.locked" } };
  const f1 = feed.ingest(a), f2 = feed.ingest(a);
  assert.equal(f1[0].rule, "RANSOM-PROCESS"); assert.equal(f1[0].severity, "critical");
  assert.equal(f1[0].key, f2[0].key); assert.match(f2[0].title, /syncd .*\(2 events\)/);
  const other = feed.ingest({ rule: "Write below etc", priority: "Warning", hostname: "h1", output_fields: { "proc.name": "vi" } });
  assert.deepEqual([other[0].rule, other[0].severity], ["FALCO-RUNTIME", "medium"]);
});

test("stratus: every covered AWS technique fires its expected rule in replay", () => {
  const cov = replayCoverage();
  const failing = cov.filter((c) => c.covered === "yes" && !c.pass).map((c) => `${c.id} fired [${c.fired}]`);
  assert.deepEqual(failing, []);
  assert.ok(cov.filter((c) => c.pass).length >= 22);
});

test("identity: versioned Lambda names, foreign bucket policy, S3 mass delete and no-MFA login", () => {
  const me = { arn: "arn:aws:iam::111122223333:user/eve" }, t = Date.parse("2026-11-15T10:00:00Z");
  const r = (n: number, eventSource: string, eventName: string, requestParameters: Record<string, unknown> = {}, extra = {}) => ({ eventTime: new Date(t + n * 1000).toISOString(), eventSource, eventName, userIdentity: me, requestParameters, ...extra });
  const m = new IdentityMonitor();
  assert.ok(m.ingest(r(0, "lambda.amazonaws.com", "UpdateFunctionCode20150331v2", { functionName: "f" })).some((f) => f.rule === "ID-PERSISTENCE"));
  assert.ok(m.ingest(r(1, "s3.amazonaws.com", "PutBucketPolicy", { bucketName: "b", bucketPolicy: { Statement: [{ Principal: { AWS: "arn:aws:iam::999999999999:root" } }] } })).some((f) => f.rule === "ID-SNAPSHOT-SHARE"));
  assert.ok(!m.ingest(r(2, "s3.amazonaws.com", "PutBucketPolicy", { bucketName: "b", bucketPolicy: { Statement: [{ Principal: { AWS: "arn:aws:iam::111122223333:root" } }] } })).some((f) => f.rule === "ID-SNAPSHOT-SHARE"), "own account is fine");
  let del: string[] = [];
  for (let i = 0; i < 60; i++) del = del.concat(m.ingest(r(3 + i * 0.5, "s3.amazonaws.com", "DeleteObject", { bucketName: "statements", key: `k${i}` })).map((f) => f.rule));
  assert.ok(del.includes("ID-S3-MASS-DELETE"));
  assert.ok(m.ingest(r(100, "signin.amazonaws.com", "ConsoleLogin", {}, { responseElements: { ConsoleLogin: "Success" }, additionalEventData: { MFAUsed: "No" } })).some((f) => f.rule === "ID-NO-MFA-LOGIN"));
});

test("access: backup or audit bucket without Object Lock is flagged", () => {
  const f = auditAccess([{ path: "infra/app.ts", text: `import * as s3 from "aws-cdk-lib/aws-s3";\nnew s3.Bucket(this, "AuditArchive", {\n  versioned: true,\n});\nnew s3.Bucket(this, "LedgerBackup", {\n  objectLockEnabled: true,\n});\nnew s3.Bucket(this, "ConsoleSite", {\n});` }]);
  assert.deepEqual(f.filter((x) => x.rule === "ACC-NO-IMMUTABLE-BACKUP").map((x) => x.title), ['Bucket "AuditArchive" can be overwritten or deleted']);
});

test("channels: Slack and PagerDuty get high alerts once; PagerDuty is acknowledged on handle", async () => {
  const bus = new AlertBus(mkdtempSync(join(tmpdir(), "ch-")));
  const sent: { url: string; body: any }[] = [];
  const fakeFetch = (async (url: string, init: RequestInit) => { sent.push({ url, body: JSON.parse(String(init.body)) }); return new Response("ok"); }) as unknown as typeof fetch;
  attachChannels(bus, { slack: "https://hooks.slack.test/x", pagerduty: "pdkey", min: "high", dashboardUrl: "http://shield" }, { fetch: fakeFetch });
  const a = bus.raise({ source: "finance", rule: "FIN-UNLOGGED-TRANSFER", severity: "critical", title: "Unlogged", detail: "d", fix: "f" })!;
  bus.raise({ source: "web", rule: "WEB-NO-CSP", severity: "medium", title: "No CSP", detail: "d" });
  bus.acknowledge(a.id, "support");
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(sent.map((s) => [s.url.includes("slack") ? "slack" : "pd", s.body.event_action ?? "msg"]), [["slack", "msg"], ["pd", "trigger"], ["pd", "acknowledge"]]);
  assert.equal(sent[1].body.payload.severity, "critical"); assert.equal(sent[1].body.dedup_key, `agent-shield-${a.id}`);
  assert.match(slackMessage(a, "http://shield").text, /^Act now: Unlogged/);
  assert.equal(pagerDutyEvent(a, "k", "acknowledge").event_action, "acknowledge");
});
