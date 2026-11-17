/**
 * Safe attack simulations for demos and drills. Everything happens inside the
 * project's own sandbox/ folder; the functions refuse any other path.
 *
 *  - ransomware: writes 40 finance export files, then "encrypts" them the way ransomware
 *    does (random bytes, .locked extension) and drops a ransom note. Nothing outside
 *    sandbox/ is touched, and nothing is actually unrecoverable: the files were fake.
 *  - finance: writes an agent run log, event by event, in which an email with planted
 *    instructions leads to a new payee, an over-approval payment, a repeated request
 *    and a self-approval: the outcomes the finance monitor exists to catch.
 */
import { mkdirSync, writeFileSync, renameSync, rmSync, existsSync, appendFileSync, readdirSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { randomBytes } from "node:crypto";
import { replayRecords } from "./integrations/stratus.ts";

export const SANDBOX = resolve(process.cwd(), "sandbox");
const inside = (p: string) => { const r = resolve(p); if (r !== SANDBOX && !r.startsWith(SANDBOX + sep)) throw new Error(`refusing to touch ${r}: simulations only run inside ${SANDBOX}`); return r; };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function seedWatched(dir = join(SANDBOX, "watched")) {
  const d = inside(join(dir, "finance-exports"));
  mkdirSync(d, { recursive: true });
  for (let i = 1; i <= 40; i++) {
    const p = join(d, `statement-2026-${String(i).padStart(2, "0")}.csv`);
    if (!existsSync(p)) writeFileSync(p, ["date,description,amount,currency", ...Array.from({ length: 80 }, (_, k) => `2026-11-${String((k % 28) + 1).padStart(2, "0")},Payout to seller ${i}-${k},${(k * 13.37 + i).toFixed(2)},USD`)].join("\n"));
  }
  return inside(dir);
}

export async function simulateRansomware(dir = join(SANDBOX, "watched"), paceMs = 60) {
  const root = seedWatched(dir);
  const d = join(root, "finance-exports");
  await sleep(1500); // let the watcher record the starting state
  const files = readdirSync(d).filter((f) => f.endsWith(".csv"));
  for (const f of files) {
    const p = inside(join(d, f));
    writeFileSync(p, randomBytes(8192));
    renameSync(p, `${p}.locked`);
    await sleep(paceMs);
  }
  writeFileSync(inside(join(d, "HOW_TO_RECOVER_FILES.txt")), "Your files have been encrypted. To get the decryption key, pay 2 BTC within 72 hours via the Tor browser.\n(This is an Agent Shield drill. No real files were harmed.)\n");
  // What Falco would report for the same attack (its JSON alert format), so the drill shows the process behind it.
  const fd = inside(join(SANDBOX, "falco")); mkdirSync(fd, { recursive: true });
  const t = Date.now(), host = "agent-desk-runtime", proc = { "proc.name": "syncd", "proc.pid": 48213, "user.name": "agent", "container.name": "agent-desk" };
  appendFileSync(join(fd, `drill-${t}.jsonl`), [
    ...files.slice(0, 5).map((f, k) => ({ time: new Date(t + k * 60).toISOString(), rule: "Agent Shield ransomware extension rename", priority: "Critical", source: "syscall", hostname: host, tags: ["agent_shield", "ransomware", "mitre_impact", "T1486"],
      output: `File renamed to a ransomware extension (file=/srv/agent-desk/finance-exports/${f}.locked proc.name=syncd proc.pid=48213 user.name=agent container.name=agent-desk)`, output_fields: { ...proc, "evt.arg.newpath": `/srv/agent-desk/finance-exports/${f}.locked` } })),
    { time: new Date(t + 400).toISOString(), rule: "Agent Shield ransom note written", priority: "Critical", source: "syscall", hostname: host, tags: ["agent_shield", "ransomware", "mitre_impact", "T1486"],
      output: "Ransom note written (fd.name=/srv/agent-desk/finance-exports/HOW_TO_RECOVER_FILES.txt proc.name=syncd proc.pid=48213 user.name=agent container.name=agent-desk)", output_fields: { ...proc, "fd.name": "/srv/agent-desk/finance-exports/HOW_TO_RECOVER_FILES.txt" } },
  ].map((x) => JSON.stringify(x)).join("\n") + "\n");
  return { encrypted: files.length, folder: d };
}

export function resetSandbox() {
  rmSync(inside(join(SANDBOX, "watched", "finance-exports")), { recursive: true, force: true });
  seedWatched();
}

export async function simulateFinance(runsDir = join(SANDBOX, "runs"), paceMs = 700) {
  const dir = inside(runsDir);
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `kit13-drill-${Date.now()}.jsonl`);
  const t0 = Date.now();
  const at = (s: number) => new Date(t0 + s * 1000).toISOString();
  const events = [
    { kind: "call", method: "GET", path: "/beneficiaries", status: 200, res: { items: [{ id: "ben_halvorsen_on_file" }] } },
    { kind: "untrusted_email", source: "halvorsen_email", findings: ["asks for money to go to an account named in the text", "claims an approval that only a person can give"] },
    { kind: "call", method: "POST", path: "/beneficiaries/create", status: 201, req: { nickname: "Halvorsen (new bank)" }, res: { id: "ben_new_9921" } },
    { kind: "approval", approved: true, by: "finance@trailhead.example", proposedBy: "agent", terms: { action: "refund", amount: 400, currency: "USD", counterparty: "ben_new_9921" } },
    { kind: "call", method: "POST", path: "/transfers/create", status: 201, req: { request_id: "refund-HALV-1", amount: 4200, currency: "USD", beneficiary_id: "ben_new_9921" }, res: { id: "tr_1", status: "PAID" } },
    { kind: "call", method: "POST", path: "/transfers/create", status: 201, req: { request_id: "refund-HALV-1", amount: 4200, currency: "USD", beneficiary_id: "ben_new_9921" }, res: { id: "tr_2", status: "PAID" } },
    { kind: "approval", approved: true, by: "agent", proposedBy: "agent", terms: { action: "payout", amount: 950, currency: "USD", counterparty: "ben_new_9921" } },
  ];
  for (let i = 0; i < events.length; i++) {
    appendFileSync(file, JSON.stringify({ at: at(i), ...events[i] }) + "\n");
    await sleep(paceMs);
  }
  return { file, events: events.length };
}

/**
 * ARTEX-style intrusion drill: writes CloudTrail and egress records to sandbox/cloud/,
 * phase by phase, the way the FBI and vendor reports describe these attacks: a thin
 * password spray, one account falling, machine-speed permission probing and enumeration,
 * role hopping, secrets harvesting, new keys and an app client for persistence, logging
 * stopped, a snapshot shared out, and command output sent to webhook.site.
 */
export async function simulateArtex(dir = join(SANDBOX, "cloud"), paceMs = 900) {
  const ct = inside(join(dir, "cloudtrail")); const eg = inside(join(dir, "egress"));
  mkdirSync(ct, { recursive: true }); mkdirSync(eg, { recursive: true });
  const stamp = Date.now();
  const ctFile = join(ct, `artex-drill-${stamp}.jsonl`), egFile = join(eg, `artex-drill-${stamp}.jsonl`);
  let clock = stamp;
  const t = (stepMs: number) => new Date((clock += stepMs)).toISOString();
  const acct = "111122223333";
  const thief = { type: "AssumedRole", arn: `arn:aws:sts::${acct}:assumed-role/backup-connector-oauth/session-7f3`, sessionContext: { sessionIssuer: { userName: "backup-connector-oauth" } } };
  const write = (recs: object[]) => appendFileSync(ctFile, recs.map((r) => JSON.stringify(r)).join("\n") + "\n");
  const egress = (recs: object[]) => appendFileSync(egFile, recs.map((r) => JSON.stringify(r)).join("\n") + "\n");
  const ev = (eventName: string, extra: object = {}) => ({ eventTime: t(300), eventSource: "iam.amazonaws.com", eventName, awsRegion: "us-west-2", sourceIPAddress: "45.155.205.17", userAgent: "Go-http-client/2.0", userIdentity: thief, ...extra });

  // 1. Thin password spray against the console's user pool
  const users = ["judge", "dana.kim", "finance", "ops", "robinson", "support", "admin", "treasury", "payroll", "leo.brandt", "kai.moreno", "audit", "it", "billing", "hr"];
  write(Array.from({ length: 30 }, (_, i) => ({ eventTime: t(35_000), eventSource: "cognito-idp.amazonaws.com", eventName: "InitiateAuth", errorCode: "NotAuthorizedException", errorMessage: "Incorrect username or password.", sourceIPAddress: `185.220.101.${40 + (i % 6)}`, userAgent: "python-requests/2.32", userIdentity: { type: "Unknown" }, additionalEventData: { userName: users[i % users.length] } })));
  await sleep(paceMs);
  // 2. One account falls, from a spraying address
  write([{ eventTime: t(20_000), eventSource: "cognito-idp.amazonaws.com", eventName: "InitiateAuth", sourceIPAddress: "185.220.101.43", userAgent: "python-requests/2.32", userIdentity: { type: "Unknown" }, additionalEventData: { userName: "ops" } }]);
  await sleep(paceMs);
  // 3. Machine-speed probing and enumeration with a stolen app identity
  const actions = ["GetCallerIdentity", "ListUsers", "ListRoles", "ListPolicies", "GetAccountAuthorizationDetails", "ListGroups", "ListAccessKeys", "ListAttachedRolePolicies", "ListRolePolicies", "GetRole", "ListInstanceProfiles", "ListUserPools", "DescribeUserPool", "ListUserPoolClients", "ListSecrets", "ListBuckets", "GetBucketPolicy", "DescribeInstances", "DescribeSnapshots", "DescribeVpcs", "DescribeSecurityGroups", "DescribeDBInstances", "ListFunctions", "ListKeys", "DescribeTrails", "GetTrailStatus", "DescribeLogGroups", "ListStacks", "ListDistributions", "ListTopics", "ListQueues", "DescribeTable", "ListDetectors", "GetFindings"];
  write(actions.flatMap((a, i) => [ev(a, { eventTime: t(250), errorCode: i % 3 === 0 ? undefined : "AccessDenied" }), ev(a, { eventTime: t(200), errorCode: "AccessDenied" })]));
  egress([{ at: new Date(clock).toISOString(), host: "api.deepseek.com", src: "10.0.3.14", principal: "agentcore-runtime", bytes_out: 18_400 }]);
  await sleep(paceMs);
  // 4. Role hopping, 5. secrets harvesting
  write(["AgentDesk-Runtime", "AgentDesk-ConsoleApi", "AgentDesk-Merchant", "OrganizationAccountAccessRole", "ReadOnlyAudit", "BackupOperator"].map((r) => ev("AssumeRole", { eventSource: "sts.amazonaws.com", requestParameters: { roleArn: `arn:aws:iam::${acct}:role/${r}`, roleSessionName: "s" } })));
  write(["agent-desk/sandbox-keys", "agent-desk/metal-rpc", "agent-desk/model-key", "prod/db-password", "prod/stripe-webhook", "prod/smtp"].map((s) => ev("GetSecretValue", { eventSource: "secretsmanager.amazonaws.com", requestParameters: { secretId: s } })));
  await sleep(paceMs);
  // 6. Persistence
  write([
    ev("CreateUser", { requestParameters: { userName: "svc-backup-sync" } }),
    ev("CreateAccessKey", { requestParameters: { userName: "svc-backup-sync" } }),
    ev("AttachUserPolicy", { requestParameters: { userName: "svc-backup-sync", policyArn: "arn:aws:iam::aws:policy/AdministratorAccess" } }),
    ev("CreateUserPoolClient", { eventSource: "cognito-idp.amazonaws.com", requestParameters: { userPoolId: "us-west-2_AbC", ClientName: "sync-client" } }),
  ]);
  await sleep(paceMs);
  // 7. Logging stopped, 8. a snapshot shared out, 9. output sent to webhook.site
  write([ev("StopLogging", { eventSource: "cloudtrail.amazonaws.com", requestParameters: { name: "agent-desk-trail" } })]);
  write([ev("ModifySnapshotAttribute", { eventSource: "ec2.amazonaws.com", requestParameters: { snapshotId: "snap-0a1b2c3d", attributeType: "CREATE_VOLUME_PERMISSION", createVolumePermission: { add: { items: [{ userId: "444455556666" }] } } } })]);
  egress(Array.from({ length: 6 }, (_, i) => ({ at: new Date(clock + i * 4000).toISOString(), host: "a91f0c2e-6b7d.webhook.site", src: "10.0.3.14", principal: "agentcore-runtime", bytes_out: 420_000 + i * 1000, process: "node" })));
  return { cloudtrail: ctFile, egress: egFile };
}

/** Stratus Red Team replay: the CloudTrail records of 22 AWS attack techniques, written where the cloud monitor reads. */
export function simulateStratus(dir = join(SANDBOX, "cloud", "cloudtrail")) {
  const d = inside(dir); mkdirSync(d, { recursive: true });
  const recs = replayRecords();
  writeFileSync(inside(join(d, `stratus-replay-${Date.now()}.jsonl`)), recs.map((r) => JSON.stringify(r)).join("\n") + "\n");
  return recs.length;
}

/**
 * Payment reconciliation drill: the agent logs one transfer; Airwallex then reports that
 * transfer, the same transfer with a different amount, and a transfer the agent never made.
 * Returns the webhook events; the server signs and delivers them through its verifier.
 */
export function simulateUnloggedTransfer(runsDir = join(SANDBOX, "runs")) {
  const d = inside(runsDir); mkdirSync(d, { recursive: true });
  const now = new Date().toISOString(), n = Date.now();
  appendFileSync(inside(join(d, `recon-drill-${n}.jsonl`)), [
    { at: now, kind: "call", method: "POST", path: "/transfers/create", status: 201, req: { request_id: `exp-${n}`, transfer_amount: "86.40", transfer_currency: "USD", beneficiary_id: "ben_employee_on_file" }, res: { id: `tr_logged_${n}`, status: "PROCESSING" } },
    { at: now, kind: "call", method: "POST", path: "/transfers/create", status: 201, req: { request_id: `ref-${n}`, transfer_amount: "120.00", transfer_currency: "USD", beneficiary_id: "ben_customer_on_file" }, res: { id: `tr_refund_${n}`, status: "PROCESSING" } },
  ].map((x) => JSON.stringify(x)).join("\n") + "\n");
  const ev = (id: string, name: string, object: Record<string, unknown>) => ({ id, name, created_at: now, version: "2025-11-11", data: { object } });
  return [
    ev(`evt_ok_${n}`, "payout.transfer.paid", { id: `tr_logged_${n}`, request_id: `exp-${n}`, transfer_amount: 86.4, transfer_currency: "USD", beneficiary_id: "ben_employee_on_file", status: "PAID" }),
    ev(`evt_mm_${n}`, "payout.transfer.sent", { id: `tr_refund_${n}`, request_id: `ref-${n}`, transfer_amount: 1200, transfer_currency: "USD", beneficiary_id: "ben_customer_on_file", status: "SENT" }),
    ev(`evt_un_${n}`, "payout.transfer.processing", { id: `tr_unknown_${n}`, request_id: "manual-7731", transfer_amount: 9800, transfer_currency: "USD", beneficiary_id: "ben_9f31c2", status: "PROCESSING" }),
  ];
}
