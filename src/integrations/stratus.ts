/**
 * Detection tests with Stratus Red Team (Datadog, open source).
 *
 * Stratus detonates real attack techniques in a sandbox AWS account. This module says,
 * for each AWS technique, which Agent Shield rule should fire, and carries a replay: the
 * CloudTrail records the technique produces, so the mapping can be proven offline (in the
 * tests and in the dashboard drill) before anyone touches a live account.
 *
 * Live: `npm run stratus -- aws.persistence.iam-backdoor-role` detonates it with the
 * stratus CLI, waits for the expected alert (CloudTrail delivers in about 5 to 15 minutes),
 * and cleans up. Needs the stratus binary and AWS credentials for a sandbox account.
 */
import { IdentityMonitor, type CloudTrailRecord } from "../detectors/identity.ts";

export interface Technique { id: string; expects: string[]; covered: "yes" | "no"; note?: string; replay?: (t0: number) => CloudTrailRecord[] }

const ME = { type: "IAMUser", arn: "arn:aws:iam::111122223333:user/stratus-red-team", userName: "stratus-red-team" };
const rec = (t: number, eventSource: string, eventName: string, requestParameters: Record<string, unknown> = {}, extra: Partial<CloudTrailRecord> = {}): CloudTrailRecord =>
  ({ eventTime: new Date(t).toISOString(), eventSource, eventName, sourceIPAddress: "198.51.100.7", userAgent: "stratus-red-team", userIdentity: ME, requestParameters, ...extra });
const times = (n: number, t0: number, f: (i: number, t: number) => CloudTrailRecord) => Array.from({ length: n }, (_, i) => f(i, t0 + i * 1000));

export const TECHNIQUES: Technique[] = [
  { id: "aws.defense-evasion.cloudtrail-stop", expects: ["ID-LOG-TAMPER"], covered: "yes", replay: (t) => [rec(t, "cloudtrail.amazonaws.com", "StopLogging", { name: "stratus-trail" })] },
  { id: "aws.defense-evasion.cloudtrail-delete", expects: ["ID-LOG-TAMPER"], covered: "yes", replay: (t) => [rec(t, "cloudtrail.amazonaws.com", "DeleteTrail", { name: "stratus-trail" })] },
  { id: "aws.defense-evasion.cloudtrail-event-selectors", expects: ["ID-LOG-TAMPER"], covered: "yes", replay: (t) => [rec(t, "cloudtrail.amazonaws.com", "PutEventSelectors", { trailName: "stratus-trail" })] },
  { id: "aws.defense-evasion.vpc-remove-flow-logs", expects: ["ID-LOG-TAMPER"], covered: "yes", replay: (t) => [rec(t, "ec2.amazonaws.com", "DeleteFlowLogs", { flowLogIds: ["fl-1"] })] },
  { id: "aws.exfiltration.ec2-share-ebs-snapshot", expects: ["ID-SNAPSHOT-SHARE"], covered: "yes", replay: (t) => [rec(t, "ec2.amazonaws.com", "ModifySnapshotAttribute", { snapshotId: "snap-1", createVolumePermission: { add: { items: [{ userId: "012345678912" }] } } })] },
  { id: "aws.exfiltration.ec2-share-ami", expects: ["ID-SNAPSHOT-SHARE"], covered: "yes", replay: (t) => [rec(t, "ec2.amazonaws.com", "ModifyImageAttribute", { imageId: "ami-1", launchPermission: { add: { items: [{ userId: "012345678912" }] } } })] },
  { id: "aws.exfiltration.rds-share-snapshot", expects: ["ID-SNAPSHOT-SHARE"], covered: "yes", replay: (t) => [rec(t, "rds.amazonaws.com", "ModifyDBSnapshotAttribute", { dBSnapshotIdentifier: "stratus-snap", attributeName: "restore", valuesToAdd: ["012345678912"] })] },
  { id: "aws.exfiltration.s3-backdoor-bucket-policy", expects: ["ID-SNAPSHOT-SHARE"], covered: "yes", replay: (t) => [rec(t, "s3.amazonaws.com", "PutBucketPolicy", { bucketName: "stratus-bucket", bucketPolicy: { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::193672423079:root" }, Action: ["s3:GetObject", "s3:ListBucket"], Resource: ["arn:aws:s3:::stratus-bucket", "arn:aws:s3:::stratus-bucket/*"] }] } })] },
  { id: "aws.persistence.iam-backdoor-role", expects: ["ID-PERSISTENCE"], covered: "yes", replay: (t) => [rec(t, "iam.amazonaws.com", "UpdateAssumeRolePolicy", { roleName: "stratus-role" })] },
  { id: "aws.persistence.iam-backdoor-user", expects: ["ID-PERSISTENCE"], covered: "yes", replay: (t) => [rec(t, "iam.amazonaws.com", "CreateAccessKey", { userName: "stratus-user" })] },
  { id: "aws.persistence.iam-create-admin-user", expects: ["ID-PERSISTENCE"], covered: "yes", replay: (t) => [rec(t, "iam.amazonaws.com", "CreateUser", { userName: "malicious-iam-user" }), rec(t + 1000, "iam.amazonaws.com", "AttachUserPolicy", { userName: "malicious-iam-user", policyArn: "arn:aws:iam::aws:policy/AdministratorAccess" })] },
  { id: "aws.persistence.iam-create-backdoor-role", expects: ["ID-PERSISTENCE"], covered: "yes", replay: (t) => [rec(t, "iam.amazonaws.com", "CreateRole", { roleName: "stratus-backdoor" })] },
  { id: "aws.persistence.iam-create-user-login-profile", expects: ["ID-PERSISTENCE"], covered: "yes", replay: (t) => [rec(t, "iam.amazonaws.com", "CreateLoginProfile", { userName: "stratus-user" })] },
  { id: "aws.privilege-escalation.iam-update-user-login-profile", expects: ["ID-PERSISTENCE"], covered: "yes", replay: (t) => [rec(t, "iam.amazonaws.com", "UpdateLoginProfile", { userName: "stratus-user" })] },
  { id: "aws.persistence.lambda-overwrite-code", expects: ["ID-PERSISTENCE"], covered: "yes", replay: (t) => [rec(t, "lambda.amazonaws.com", "UpdateFunctionCode20150331v2", { functionName: "stratus-fn" })], note: "CloudTrail logs Lambda calls with a version suffix; the detector strips it." },
  { id: "aws.persistence.lambda-backdoor-function", expects: ["ID-PERSISTENCE"], covered: "yes", replay: (t) => [rec(t, "lambda.amazonaws.com", "AddPermission20150331v2", { functionName: "stratus-fn", principal: "*" })] },
  { id: "aws.credential-access.secretsmanager-retrieve-secrets", expects: ["ID-SECRETS-BURST"], covered: "yes", replay: (t) => times(20, t, (i, ti) => rec(ti, "secretsmanager.amazonaws.com", "GetSecretValue", { secretId: `stratus-secret-${i}` })) },
  { id: "aws.credential-access.secretsmanager-batch-retrieve-secrets", expects: ["ID-SECRETS-BURST"], covered: "yes", replay: (t) => [rec(t, "secretsmanager.amazonaws.com", "BatchGetSecretValue", { secretIdList: Array.from({ length: 20 }, (_, i) => `stratus-secret-${i}`) })] },
  { id: "aws.credential-access.ssm-retrieve-securestring-parameters", expects: ["ID-SECRETS-BURST"], covered: "yes", replay: (t) => times(10, t, (i, ti) => rec(ti, "ssm.amazonaws.com", "GetParameters", { names: [`/stratus/param-${i}`], withDecryption: true })) },
  { id: "aws.impact.s3-ransomware-batch-deletion", expects: ["ID-S3-MASS-DELETE"], covered: "yes", note: "Needs S3 data events enabled on the trail.", replay: (t) => times(2, t, (i, ti) => rec(ti, "s3.amazonaws.com", "DeleteObjects", { bucketName: "stratus-ransomware", delete: { Object: Array.from({ length: 50 }, (_, j) => ({ Key: `f${i}-${j}` })) } })) },
  { id: "aws.impact.s3-ransomware-individual-deletion", expects: ["ID-S3-MASS-DELETE"], covered: "yes", note: "Needs S3 data events enabled on the trail.", replay: (t) => times(60, t, (i, ti) => rec(ti, "s3.amazonaws.com", "DeleteObject", { bucketName: "stratus-ransomware", key: `f${i}` })) },
  { id: "aws.initial-access.console-login-without-mfa", expects: ["ID-NO-MFA-LOGIN"], covered: "yes", replay: (t) => [rec(t, "signin.amazonaws.com", "ConsoleLogin", {}, { responseElements: { ConsoleLogin: "Success" }, additionalEventData: { MFAUsed: "No" } })] },
  // Known gaps: listed so the dashboard shows them instead of implying full coverage.
  { id: "aws.defense-evasion.cloudtrail-lifecycle-rule", expects: [], covered: "no", note: "PutBucketLifecycle on the trail bucket is not watched yet." },
  { id: "aws.defense-evasion.dns-delete-logs", expects: [], covered: "no", note: "DeleteResolverQueryLogConfig is not watched yet." },
  { id: "aws.impact.s3-ransomware-client-side-encryption", expects: [], covered: "no", note: "Overwrites with client-side encryption look like normal PutObject calls in CloudTrail." },
  { id: "aws.impact.bedrock-invoke-model", expects: [], covered: "no", note: "Model use by an unusual identity is not baselined yet." },
  { id: "aws.discovery.ec2-enumerate-from-instance", expects: [], covered: "no", note: "Too few distinct calls for the enumeration threshold (30)." },
];

/** Replay every covered technique through a fresh detector; returns which rules fired per technique. */
export function replayCoverage(t0 = Date.parse("2026-11-15T12:00:00Z")) {
  return TECHNIQUES.map((tech, i) => {
    if (!tech.replay) return { id: tech.id, expects: tech.expects, covered: tech.covered, note: tech.note, fired: [] as string[], pass: false };
    const m = new IdentityMonitor();
    const fired = new Set<string>();
    for (const r of tech.replay(t0 + i * 3_600_000)) for (const f of m.ingest(r)) fired.add(f.rule);
    return { id: tech.id, expects: tech.expects, covered: tech.covered, note: tech.note, fired: [...fired], pass: tech.expects.every((e) => fired.has(e)) };
  });
}

/** All replay records, in time order, for the sandbox drill. */
export function replayRecords(t0 = Date.now() - 60 * 60_000) {
  return TECHNIQUES.flatMap((tech, i) => tech.replay?.(t0 + i * 130_000) ?? []);
}
