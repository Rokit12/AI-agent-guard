import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { scanCode } from "../src/detectors/code-scan.ts";
import { auditAccess } from "../src/detectors/access-control.ts";
import { FinanceMonitor, scanLog } from "../src/detectors/finance-flow.ts";
import { entropy, scoreWindow, type FileEvent } from "../src/detectors/ransomware.ts";
import { runProbes, probeSummary, hardenGuard, PROBES } from "../src/detectors/llm-probes.ts";
import { AlertBus } from "../src/alerts.ts";
import { composeEmail } from "../src/notify/email.ts";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const rules = (fs: { rule: string }[]) => fs.map((f) => f.rule).sort();

test("code scan: unguarded payment, no idempotency, secret, eval", () => {
  const bad = { path: "agent/pay.ts", text: `const key = "sk-live_abcdefghijklmnopqrstuvwxyz1234";\nawait api.post("/transfers/create", { amount: llm.amount });\neval(x);` };
  const r = rules(scanCode([bad]));
  for (const id of ["CODE-SECRET", "CODE-MONEY-NO-APPROVAL", "CODE-MONEY-NO-IDEMPOTENCY", "CODE-EVAL"]) assert.ok(r.includes(id), id);
});

test("code scan: a gated, idempotent payment passes", () => {
  const good = { path: "agent/pay.ts", text: `const ok = await requireApproval(terms);\nawait api.post("/transfers/create", { request_id: invoiceId, amount });` };
  assert.deepEqual(scanCode([good]), []);
});

test("code scan: card numbers reaching the model, and the stripped version", () => {
  const leak = { path: "a.ts", text: `await extract("Read the email", email + " card 4111 1111 1111 1111");` };
  const safe = { path: "b.ts", text: `await extract("Read the email", email.replace(/\\b(?:\\d[ -]?){13,19}\\b/g, "[card number removed]") + " card_number");` };
  assert.ok(rules(scanCode([leak])).includes("LLM-CARD-DATA"));
  assert.ok(!rules(scanCode([safe])).includes("LLM-CARD-DATA"));
});

test("access audit: wildcard IAM, public bucket, open route, approver from body", () => {
  const infra = { path: "infra/stack.ts", text: `import * as cdk from "aws-cdk-lib";\nnew iam.PolicyStatement({ actions: ["*"], resources: ["*"] });\nnew s3.Bucket(this, "b", { publicReadAccess: true });` };
  const srv = { path: "src/server.ts", text: `app.post("/api/pay", async (req, res) => { const approvedBy = req.body.by; pay(); });` };
  const r = rules(auditAccess([infra, srv]));
  for (const id of ["ACC-IAM-ALL-ACTIONS", "ACC-PUBLIC-BUCKET", "ACC-ROUTE-NO-AUTH", "ACC-APPROVER-FROM-INPUT"]) assert.ok(r.includes(id), id);
});

const ev = (s: number, e: object) => JSON.stringify({ at: new Date(Date.UTC(2026, 10, 15, 12, 0, s)).toISOString(), ...e });

test("finance: injection then new payee, over approval, double pay, self-approval", () => {
  const log = [
    ev(0, { kind: "untrusted_email", findings: ["asks for money to go to an account named in the text"] }),
    ev(1, { kind: "call", method: "POST", path: "/beneficiaries/create", status: 201, res: { id: "ben_x" } }),
    ev(2, { kind: "approval", approved: true, by: "ana@co", proposedBy: "agent", terms: { amount: 400, currency: "USD", counterparty: "ben_x" } }),
    ev(3, { kind: "call", method: "POST", path: "/transfers/create", status: 201, req: { request_id: "r1", amount: 4200, currency: "USD", beneficiary_id: "ben_x" } }),
    ev(4, { kind: "call", method: "POST", path: "/transfers/create", status: 201, req: { request_id: "r1", amount: 4200, currency: "USD", beneficiary_id: "ben_x" } }),
    ev(5, { kind: "approval", approved: true, by: "agent", proposedBy: "agent", terms: { amount: 950 } }),
  ].join("\n");
  const r = rules(scanLog(log));
  for (const id of ["FIN-INJECTION-READ", "FIN-TAINTED-PAYEE", "FIN-OVER-APPROVED", "FIN-DOUBLE-PAY", "ACC-SELF-APPROVAL"]) assert.ok(r.includes(id), id);
});

test("finance: an approved payment to a known payee raises nothing", () => {
  const m = new FinanceMonitor();
  const out = [
    { kind: "call", method: "GET", path: "/beneficiaries", status: 200, res: { items: [{ id: "ben_ok" }] } },
    { kind: "approval", approved: true, by: "ana@co", proposedBy: "agent", terms: { amount: 500, currency: "USD" } },
    { kind: "call", method: "POST", path: "/transfers/create", status: 201, req: { request_id: "inv-1", amount: 500, currency: "USD", beneficiary_id: "ben_ok" } },
  ].flatMap((e, i) => m.ingest({ at: new Date(Date.UTC(2026, 10, 15, 12, 0, i)).toISOString(), ...e }));
  assert.deepEqual(out, []);
});

test("finance: a burst of payouts is flagged once", () => {
  const m = new FinanceMonitor({ autoLimit: 1e9, velocityCount: 5, velocityWindowMs: 60_000, taintWindowMs: 0 });
  const out = Array.from({ length: 9 }, (_, i) => m.ingest({ at: new Date(Date.UTC(2026, 10, 15, 12, 0, i)).toISOString(), kind: "call", method: "POST", path: "/payouts/create", status: 201, req: { request_id: "p" + i, amount: 10 + i, beneficiary_id: "b" + i } })).flat();
  assert.equal(out.filter((f) => f.rule === "FIN-VELOCITY").length, 1);
});

test("ransomware: entropy separates text from encrypted bytes", () => {
  assert.ok(entropy(Buffer.from("date,amount\n2026-11-01,12.50\n".repeat(100))) < 5);
  assert.ok(entropy(randomBytes(4096)) > 7.8);
});

test("ransomware: mass encryption plus a note is critical; a normal edit is quiet", () => {
  const t = Date.now();
  const enc: FileEvent[] = Array.from({ length: 12 }, (_, i) => ({ at: t, path: `/d/s${i}.csv.locked`, type: "write", entropy: 7.97 }));
  enc.push({ at: t, path: "/d/HOW_TO_RECOVER_FILES.txt", type: "write", entropy: 4.2 });
  const r = rules(scoreWindow(enc, "/d"));
  assert.ok(r.includes("RANSOM-MASS-ENCRYPTION") && r.includes("RANSOM-NOTE"));
  assert.deepEqual(scoreWindow([{ at: t, path: "/d/report.csv", type: "write", entropy: 4.5, prevEntropy: 4.4 }], "/d"), []);
});

test("probes: benign texts are controls; normalising raises the catch rate", () => {
  const naive = (s: string) => /ignore (all )?previous instructions/i.test(s);
  const before = probeSummary(runProbes(naive));
  const after = probeSummary(runProbes(hardenGuard(naive)));
  assert.equal(before.benign, PROBES.filter((p) => !p.attack).length);
  assert.ok(after.detectionRate > before.detectionRate);
  assert.equal(after.falsePositives, 0);
});

test("alerts: repeats are one alert; acknowledgement is kept", () => {
  const bus = new AlertBus(mkdtempSync(join(tmpdir(), "shield-")));
  const f = { source: "finance" as const, rule: "FIN-DOUBLE-PAY", severity: "critical" as const, title: "x", detail: "y", where: "run1" };
  const a = bus.raise(f)!;
  assert.equal(bus.raise(f), null);
  bus.acknowledge(a.id, "ana");
  assert.equal(bus.counts().critical, 0);
});

test("email: one subject line names the worst alert", () => {
  const base = { source: "ransomware" as const, rule: "R", detail: "d", id: "1", at: "2026-11-15T00:00:00Z" };
  const { subject } = composeEmail([{ ...base, severity: "high", title: "burst" }, { ...base, id: "2", severity: "critical", title: "Ransom note written" }], { to: "t", from: "f", minSeverity: "high", batchMs: 1, outbox: "o", dashboardUrl: "u" });
  assert.match(subject, /^\[CRITICAL\] 2 security alerts: Ransom note written/);
});

import { readFileSync } from "node:fs";
import { garakFindings } from "../src/integrations/garak.ts";
import { parsePromptfoo, redteamFindings } from "../src/integrations/promptfoo.ts";

test("garak: failed probes become alerts, clean probes do not", () => {
  const fs = garakFindings(readFileSync(new URL("./fixtures-garak.report.jsonl", import.meta.url), "utf8"));
  assert.equal(fs.length, 3); // dan.Dan_11_0 passed 5/5
  assert.equal(fs.find((f) => f.title.includes("latentinjection"))?.severity, "critical"); // 67% through
  assert.equal(fs.find((f) => f.title.includes("promptinject"))?.severity, "low"); // 8% through
});

test("promptfoo: obeying the attacker is serious, missing the signal is low", () => {
  const json = JSON.stringify({ results: { results: [
    { success: false, testCase: { description: "direct", metadata: { family: "direct", severity: "critical" } }, gradingResult: { componentResults: [{ pass: false, reason: "output carries the attacker's GB33" }] }, response: { output: "{}" }, provider: { id: "m" } },
    { success: false, testCase: { description: "hidden", metadata: { family: "hidden", severity: "high" } }, gradingResult: { componentResults: [{ pass: false, reason: "did not notice the request to pay a different account" }] }, provider: { id: "m" } },
    { success: true, testCase: { description: "ok", metadata: { family: "benign", severity: "low" } }, gradingResult: { componentResults: [] }, provider: { id: "m" } },
  ] } });
  const r = parsePromptfoo(json);
  assert.equal(r.passed, 1); assert.equal(r.failed, 2);
  const fs = redteamFindings(r);
  assert.deepEqual(fs.map((f) => f.severity), ["critical", "low"]);
});

test("garak: reads the newer report format (total_evaluated, fails)", () => {
  const line = JSON.stringify({ entry_type: "eval", probe: "encoding.InjectBase64", detector: "encoding.DecodeMatch", passed: 200, fails: 56, total_evaluated: 256 });
  const fs = garakFindings(line);
  assert.equal(fs.length, 1);
  assert.match(fs[0].title, /22% of the time/);
});

import { IdentityMonitor, DEFAULT_IDENTITY, type CloudTrailRecord } from "../src/detectors/identity.ts";

const T0 = Date.UTC(2026, 10, 15, 6, 0, 0);
const rec = (s: number, r: Partial<CloudTrailRecord>): CloudTrailRecord => ({ eventTime: new Date(T0 + s * 1000).toISOString(), eventSource: "iam.amazonaws.com", eventName: "ListUsers", sourceIPAddress: "203.0.113.9", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::111122223333:assumed-role/app-backup/i-1" }, ...r });
const runAll = (m: IdentityMonitor, rs: CloudTrailRecord[]) => rs.flatMap((r) => m.ingest(r));

test("identity: spray across accounts, then a success from a spraying address", () => {
  const m = new IdentityMonitor();
  const rs = Array.from({ length: 24 }, (_, i) => rec(i * 40, { eventSource: "cognito-idp.amazonaws.com", eventName: "InitiateAuth", errorCode: "NotAuthorizedException", sourceIPAddress: `198.51.100.${i % 6}`, additionalEventData: { userName: `user${i % 12}` }, userIdentity: { type: "Unknown" } }));
  rs.push(rec(1000, { eventSource: "cognito-idp.amazonaws.com", eventName: "InitiateAuth", sourceIPAddress: "198.51.100.3", additionalEventData: { userName: "dana.kim" }, userIdentity: { type: "Unknown" } }));
  const fs = runAll(m, rs);
  const r = rules(fs);
  assert.ok(r.includes("ID-SPRAY")); assert.ok(r.includes("ID-SPRAY-SUCCESS"));
  const spray = fs.filter((f) => f.rule === "ID-SPRAY");
  assert.equal(new Set(spray.map((f) => f.key)).size, 1, "one incident, updated as it grows");
  assert.match(spray.at(-1)!.title, /12 accounts/);
});

test("identity: denied-permission burst, enumeration and machine speed from one identity", () => {
  const m = new IdentityMonitor();
  const actions = ["ListUsers", "ListRoles", "ListPolicies", "GetAccountAuthorizationDetails", "ListGroups", "ListAccessKeys", "DescribeInstances", "DescribeSnapshots", "ListBuckets", "ListSecrets", "DescribeDBInstances", "ListFunctions", "DescribeUserPool", "ListUserPools", "DescribeTrails", "GetBucketPolicy", "ListKeys", "DescribeVpcs", "DescribeSecurityGroups", "ListAttachedRolePolicies", "ListRolePolicies", "GetRole", "GetUser", "ListInstanceProfiles", "DescribeLoadBalancers", "ListDistributions", "ListStacks", "DescribeLogGroups", "ListTopics", "ListQueues", "DescribeTable"];
  const rs = actions.flatMap((a, i) => [rec(i * 0.4, { eventName: a, errorCode: i % 2 ? "AccessDenied" : undefined }), rec(i * 0.4 + 0.2, { eventName: a, errorCode: "AccessDenied" })]);
  const r = rules(runAll(m, rs));
  for (const id of ["ID-PERMISSION-PROBE", "ID-ENUMERATION", "ID-MACHINE-SPEED"]) assert.ok(r.includes(id), id);
});

test("identity: persistence, log tampering, snapshot sharing, secrets harvesting", () => {
  const m = new IdentityMonitor();
  const r = rules(runAll(m, [
    rec(1, { eventName: "CreateAccessKey", requestParameters: { userName: "svc-reports" } }),
    rec(2, { eventName: "AttachUserPolicy", requestParameters: { userName: "svc-reports", policyArn: "arn:aws:iam::aws:policy/AdministratorAccess" } }),
    rec(3, { eventSource: "cloudtrail.amazonaws.com", eventName: "StopLogging", requestParameters: { name: "org-trail" } }),
    rec(4, { eventSource: "ec2.amazonaws.com", eventName: "ModifySnapshotAttribute", requestParameters: { snapshotId: "snap-1", createVolumePermission: { add: { items: [{ userId: "999988887777" }] } } } }),
    ...Array.from({ length: 6 }, (_, i) => rec(5 + i, { eventSource: "secretsmanager.amazonaws.com", eventName: "GetSecretValue", requestParameters: { secretId: `prod/key-${i}` } })),
  ]));
  for (const id of ["ID-PERSISTENCE", "ID-LOG-TAMPER", "ID-SNAPSHOT-SHARE", "ID-SECRETS-BURST"]) assert.ok(r.includes(id), id);
});

test("identity: the deploy pipeline changing IAM is not an alert", () => {
  const m = new IdentityMonitor();
  const out = m.ingest(rec(1, { eventName: "AttachRolePolicy", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::1:assumed-role/cdk-hnb659fds-cfn-exec-role-1/AWSCloudFormation" }, requestParameters: { roleName: "AgentDesk-Runtime" } }));
  assert.deepEqual(out, []);
});

test("network: webhook exfiltration and unapproved AI APIs; approved model API is quiet", () => {
  const m = new IdentityMonitor();
  const at = new Date(T0).toISOString();
  assert.equal(m.ingestEgress({ at, host: "abc123.webhook.site", bytes_out: 50_000, src: "10.0.1.7" })[0].rule, "NET-WEBHOOK-EXFIL");
  assert.equal(m.ingestEgress({ at, host: "api.deepseek.com", src: "10.0.1.7" })[0].rule, "NET-UNAPPROVED-AI");
  assert.deepEqual(m.ingestEgress({ at, host: "api.anthropic.com", src: "10.0.1.7" }), []);
  assert.deepEqual(m.ingestEgress({ at, query_name: "bedrock-runtime.us-west-2.amazonaws.com.", src: "10.0.1.7" }), []);
});
