/**
 * Identity, cloud and network detector, built around how AI-driven intrusion frameworks
 * such as ARTEX behave (FBI FLASH, Nov 2026; Microsoft, Google/Mandiant, CrowdStrike, CSA).
 *
 * Those frameworks chain attack steps at machine speed and are noisy while doing it. The
 * signals they leave are in identity and network logs, not in the agent's own log:
 *
 *   ID-SPRAY             failed sign-ins spread across many accounts, low and slow per source
 *   ID-SPRAY-SUCCESS     a sign-in that succeeds in the middle of a spray
 *   ID-PERMISSION-PROBE  bursts of access-denied errors from one identity
 *   ID-ENUMERATION       many different List/Describe/Get calls from one identity in minutes
 *   ID-MACHINE-SPEED     a human or app identity making API calls faster than a person can
 *   ID-PERSISTENCE       new access keys, login profiles, app credentials, admin roles
 *   ID-ROLE-CHAIN        one identity assuming many roles in a short time
 *   ID-LOG-TAMPER        logging stopped or deleted
 *   ID-SNAPSHOT-SHARE    snapshots or buckets opened to other accounts or the public
 *   ID-SECRETS-BURST     many secrets read at once
 *   ID-S3-MASS-DELETE    one identity deleting S3 objects in bulk (cloud ransomware)
 *   ID-LOG-LIFECYCLE     a lifecycle rule that quietly expires audit logs or data
 *   ID-S3-SSEC-ENCRYPT   objects rewritten with a customer-provided key (SSE-C ransomware)
 *   ID-LLMJACKING        an unexpected identity calling or probing AI models
 *   ID-INSTANCE-RECON    a server's credentials used to map the account
 *   ID-NO-MFA-LOGIN      console sign-in with a password only
 *   NET-WEBHOOK-EXFIL    data sent to webhook/paste/tunnel services
 *   NET-UNAPPROVED-AI    calls to AI model APIs the company has not approved
 *
 * Input is AWS CloudTrail records (which include Cognito sign-ins) and egress records
 * (proxy, firewall, VPC DNS query logs) in a simple shape. Pure and stateful: feed events
 * in time order, get findings back.
 */
import type { Finding } from "../alerts.ts";

export interface CloudTrailRecord {
  eventTime: string;
  eventSource: string;
  eventName: string;
  errorCode?: string;
  errorMessage?: string;
  sourceIPAddress?: string;
  userAgent?: string;
  userIdentity?: { type?: string; arn?: string; userName?: string; principalId?: string; invokedBy?: string; sessionContext?: { sessionIssuer?: { userName?: string; arn?: string } } };
  requestParameters?: Record<string, any> | null;
  responseElements?: Record<string, any> | null;
  additionalEventData?: Record<string, any> | null;
}

export interface EgressRecord { at: string; host?: string; query_name?: string; bytes_out?: number; src?: string; principal?: string; process?: string }

export interface IdentityConfig {
  trustedPrincipals: RegExp;     // deploy pipelines and the runtime role, expected to change IAM
  modelCallers: RegExp;          // identities expected to call Bedrock models (the agent's runtime)
  trailBuckets: string[];        // buckets that hold audit logs (learned from CreateTrail/UpdateTrail too)
  approvedAiHosts: string[];     // model APIs the company has approved
  sprayAccounts: number;         // distinct accounts failing within the spray window
  sprayWindowMs: number;
  probeDenied: number;           // access-denied errors from one identity…
  probeWindowMs: number;         // …inside this window
  enumDistinct: number;          // distinct read actions from one identity…
  enumWindowMs: number;
  machineCalls: number;          // calls from one identity…
  machineWindowMs: number;       // …inside this window = faster than a person
  roleChain: number;             // distinct roles assumed by one identity in the probe window
  secretsBurst: number;          // distinct secrets read by one identity in the probe window
}

export const DEFAULT_IDENTITY: IdentityConfig = {
  trustedPrincipals: /cdk-|CloudFormation|cloudformation\.amazonaws\.com|AgentDesk-.*Deploy|github-actions/i,
  modelCallers: new RegExp(process.env.MODEL_CALLERS ?? "agentcore|AgentDesk|agent-desk|bedrock\\.amazonaws\\.com", "i"),
  trailBuckets: (process.env.CLOUDTRAIL_BUCKETS ?? "").split(",").filter(Boolean),
  approvedAiHosts: ["api.anthropic.com", "bedrock-runtime.", "bedrock-agentcore."],
  sprayAccounts: 10, sprayWindowMs: 60 * 60_000,
  probeDenied: 15, probeWindowMs: 120_000,
  enumDistinct: 30, enumWindowMs: 180_000,
  machineCalls: 40, machineWindowMs: 20_000,
  roleChain: 5,
  secretsBurst: 5,
};

const EXFIL_HOSTS = /(^|\.)(webhook\.site|requestbin\.(com|net)|pipedream\.(net|com)|ngrok(-free)?\.(io|app|dev)|interact\.sh|oast\.(fun|pro|live|site|online|me)|burpcollaborator\.net|transfer\.sh|file\.io|pastebin\.com|paste\.ee|hastebin\.com|anonfiles\.com|gofile\.io|trycloudflare\.com|discord(app)?\.com\/api\/webhooks|hooks\.slack\.com|requestcatcher\.com|beeceptor\.com)$/i;
const AI_HOSTS = /(^|\.)(api\.openai\.com|api\.deepseek\.com|open\.bigmodel\.cn|api\.x\.ai|openrouter\.ai|api\.mistral\.ai|api\.together\.(xyz|ai)|api\.groq\.com|generativelanguage\.googleapis\.com|dashscope\.aliyuncs\.com|api\.moonshot\.cn|api\.anthropic\.com|bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com|api\.perplexity\.ai|api\.fireworks\.ai)$/i;

const SIGNIN_FAIL = (r: CloudTrailRecord) =>
  (r.eventName === "ConsoleLogin" && (r.responseElements?.ConsoleLogin === "Failure" || r.errorMessage === "Failed authentication")) ||
  (/cognito-idp/.test(r.eventSource) && /InitiateAuth|RespondToAuthChallenge/.test(r.eventName) && /NotAuthorized|UserNotFound|PasswordResetRequired/.test(r.errorCode ?? ""));
const SIGNIN_OK = (r: CloudTrailRecord) =>
  (r.eventName === "ConsoleLogin" && r.responseElements?.ConsoleLogin === "Success") ||
  (/cognito-idp/.test(r.eventSource) && /InitiateAuth|RespondToAuthChallenge/.test(r.eventName) && !r.errorCode);
const DENIED = (r: CloudTrailRecord) => /AccessDenied|UnauthorizedOperation|Forbidden|NotAuthorized|AuthorizationError/i.test(r.errorCode ?? "") && !SIGNIN_FAIL(r);

const PERSIST: Record<string, string> = {
  CreateAccessKey: "created a new access key", CreateLoginProfile: "gave a user a console password", UpdateLoginProfile: "changed a console password",
  CreateUser: "created an IAM user", AttachUserPolicy: "attached a policy to a user", PutUserPolicy: "wrote an inline user policy",
  AttachRolePolicy: "attached a policy to a role", PutRolePolicy: "wrote an inline role policy", UpdateAssumeRolePolicy: "changed who can assume a role",
  AddUserToGroup: "added a user to a group", CreateRole: "created a role", CreateServiceSpecificCredential: "created a service credential",
  AdminAddUserToGroup: "added a Cognito user to a group", AdminCreateUser: "created a Cognito user", AdminSetUserPassword: "set a Cognito user's password",
  CreateUserPoolClient: "created a new app client", UpdateUserPoolClient: "changed an app client", CreateIdentityProvider: "added a sign-in provider",
  UpdateFunctionCode: "replaced a Lambda function's code", AddPermission: "let another principal invoke a function", PutSecretValue: "changed a stored secret",
};
const ADMIN_POLICY = /AdministratorAccess|IAMFullAccess|PowerUserAccess|"Action"\s*:\s*"\*"|\*:\*/;
const TAMPER = /^(StopLogging|DeleteTrail|UpdateTrail|PutEventSelectors|DeleteFlowLogs|DeleteDetector|DisassociateFromMasterAccount|DeleteLogGroup|DeleteLogStream|PutRetentionPolicy|DisableSecurityHub|DeleteConfigurationRecorder|StopConfigurationRecorder|DeleteResolverQueryLogConfig|DisassociateResolverQueryLogConfig)$/;
const LIFECYCLE = /^PutBucketLifecycle(Configuration)?$/;
const SSEC = /customer-algorithm|SSECustomerAlgorithm/i;
const MODEL_CALL = /^(InvokeModel|InvokeModelWithResponseStream|Converse|ConverseStream|InvokeAgent|InvokeInlineAgent)$/;
const MODEL_RECON = /^(ListFoundationModels|GetFoundationModelAvailability|ListFoundationModelAgreementOffers|PutFoundationModelEntitlement|PutUseCaseForModelAccess|CreateFoundationModelAgreement)$/;
const INSTANCE_CREDS = /assumed-role\/[^/]+\/i-[0-9a-f]{8,17}$/;
const SHARE = /^(ModifySnapshotAttribute|ModifyDBSnapshotAttribute|ModifyDBClusterSnapshotAttribute|PutBucketPolicy|PutBucketAcl|DeletePublicAccessBlock|DeleteBucketPublicAccessBlock|PutBucketPublicAccessBlock|ModifyImageAttribute)$/;

/** Secrets a call returned: Secrets Manager (single or batch) and SSM SecureString parameters read with decryption. */
const secretsRead = (r: CloudTrailRecord): string[] => {
  if (r.errorCode) return [];
  const p = r.requestParameters ?? {};
  if (r.eventName === "GetSecretValue") return [String(p.secretId ?? "?")];
  if (r.eventName === "BatchGetSecretValue") { const l = (p.secretIdList as string[] | undefined) ?? []; return l.length ? l.map(String) : [`batch:${r.eventTime}:${JSON.stringify(p.filters ?? "")}`]; }
  if ((r.eventName === "GetParameter" || r.eventName === "GetParameters" || r.eventName === "GetParametersByPath") && p.withDecryption) {
    const names = (p.names as string[] | undefined) ?? (p.name ? [p.name] : p.path ? [`${p.path}*`] : []);
    return names.map(String);
  }
  return [];
};
const S3_DELETE = /^(DeleteObject|DeleteObjects|DeleteObjectVersion)$/;
const deletedCount = (r: CloudTrailRecord) => {
  const d = r.requestParameters?.delete ?? r.requestParameters?.Delete;
  const objs = d?.Object ?? d?.objects ?? d?.Objects;
  return Array.isArray(objs) ? objs.length : 1;
};

const who = (r: CloudTrailRecord) => r.userIdentity?.arn ?? r.userIdentity?.sessionContext?.sessionIssuer?.arn ?? r.userIdentity?.userName ?? r.userIdentity?.principalId ?? "unknown";
const shortWho = (arn: string) => {
  const a = arn.replace(/^arn:aws:(iam|sts)::\d+:/, "");
  const role = /^assumed-role\/([^/]+)/.exec(a)?.[1];
  return role ? `Role ${role}` : a.replace(/^user\//, "User ").replace(/^role\//, "Role ");
};
const accountOf = (r: CloudTrailRecord) =>
  String(r.additionalEventData?.userName ?? r.requestParameters?.username ?? r.requestParameters?.userName ?? r.userIdentity?.userName ?? r.additionalEventData?.sub ?? "?");

interface Win<T> { at: number; v: T }
const prune = <T>(w: Win<T>[], now: number, ms: number) => { while (w.length && now - w[0].at > ms) w.shift(); return w; };

export class IdentityMonitor {
  private fails: Win<{ account: string; ip: string }>[] = [];
  private calls = new Map<string, Win<{ action: string; read: boolean; denied: boolean }>[]>();
  private roles = new Map<string, Win<string>[]>();
  private secrets = new Map<string, Win<string>[]>();
  private s3del = new Map<string, Win<string>[]>();
  private ssec = new Map<string, Win<string>[]>();
  private recon = new Map<string, Win<string>[]>();
  private trailBucketSet = new Set<string>();
  private egressBytes = new Map<string, number>();
  private fired = new Map<string, number>(); // rule:identity -> last time raised
  private peak = new Map<string, number>();  // incident key -> largest count seen
  private top(key: string, n: number) { const p = Math.max(this.peak.get(key) ?? 0, n); this.peak.set(key, p); return p; }

  constructor(private cfg: IdentityConfig = DEFAULT_IDENTITY) {}

  /** Once per identity and rule per window, so a burst is one alert. */
  private once(key: string, now: number, ms: number) {
    const last = this.fired.get(key);
    if (last !== undefined && now - last < ms) return false;
    this.fired.set(key, now); return true;
  }

  ingest(r: CloudTrailRecord): Finding[] {
    const now = Date.parse(r.eventTime);
    const out: Finding[] = [];
    const id = who(r);
    const trusted = this.cfg.trustedPrincipals.test(id) || this.cfg.trustedPrincipals.test(r.userAgent ?? "");
    const where = `${shortWho(id)} · ${r.sourceIPAddress ?? "?"}`;
    const day = new Date(now).toISOString().slice(0, 10);

    // --- sign-ins: password spraying, and a success in the middle of one
    if (SIGNIN_FAIL(r)) {
      this.fails.push({ at: now, v: { account: accountOf(r), ip: r.sourceIPAddress ?? "?" } });
      prune(this.fails, now, this.cfg.sprayWindowMs);
      const accounts = new Set(this.fails.map((f) => f.v.account));
      const ips = new Set(this.fails.map((f) => f.v.ip));
      if (accounts.size >= this.cfg.sprayAccounts) {
        const perIp = this.fails.length / Math.max(1, ips.size);
        out.push({ source: "identity", rule: "ID-SPRAY", severity: "high", where: `${r.eventSource}`, key: `spray:${day}`,
          title: `Password spray: ${this.top(`spray:${day}`, accounts.size)} accounts failing sign-in`,
          detail: `${this.fails.length} failed sign-ins across ${accounts.size} accounts from ${ips.size} address${ips.size === 1 ? "" : "es"} (${perIp.toFixed(1)} per address) in the last ${this.cfg.sprayWindowMs / 60_000} min. Spreading attempts thinly across sources is how AI attack frameworks avoid per-source lockouts.`,
          fix: "Require MFA on every account, block the source addresses, enable Cognito advanced security (adaptive auth), and check for any successful sign-in from the same addresses." });
      }
    } else if (SIGNIN_OK(r)) {
      const ip = r.sourceIPAddress ?? "?";
      const fromSprayIp = this.fails.some((f) => f.v.ip === ip && now - f.at < this.cfg.sprayWindowMs);
      const sprayOn = new Set(this.fails.filter((f) => now - f.at < this.cfg.sprayWindowMs).map((f) => f.v.account)).size >= this.cfg.sprayAccounts;
      if (fromSprayIp && sprayOn) out.push({ source: "identity", rule: "ID-SPRAY-SUCCESS", severity: "critical", where: `${accountOf(r)} · ${ip} · ${r.eventSource}`, key: `spray-ok:${accountOf(r)}:${day}`,
        title: `Sign-in succeeded during a password spray (${accountOf(r)})`,
        detail: `${accountOf(r)} signed in from ${ip}, an address that was failing sign-ins against other accounts minutes before.`,
        fix: "Disable the account's sessions and refresh tokens now (Cognito AdminUserGlobalSignOut), reset its password, and review everything it did since." });
    }

    // --- per-identity activity: probes, enumeration, machine speed
    const list = this.calls.get(id) ?? [];
    this.calls.set(id, list);
    const read = /^(List|Describe|Get|Lookup|Search|BatchGet|Scan|Query)/.test(r.eventName);
    list.push({ at: now, v: { action: `${r.eventSource.split(".")[0]}:${r.eventName}`, read, denied: DENIED(r) } });
    prune(list, now, Math.max(this.cfg.enumWindowMs, this.cfg.probeWindowMs, this.cfg.machineWindowMs));

    const denied = list.filter((c) => c.v.denied && now - c.at <= this.cfg.probeWindowMs);
    if (denied.length >= this.cfg.probeDenied) {
      const actions = [...new Set(denied.map((d) => d.v.action))];
      out.push({ source: "identity", rule: "ID-PERMISSION-PROBE", severity: "high", where, key: `probe:${id}:${day}`,
        title: `${shortWho(id)} hit ${this.top(`probe:${id}`, denied.length)} access-denied errors within ${Math.round(this.cfg.probeWindowMs / 1000)} s`,
        detail: `Testing what it is allowed to do across ${actions.length} actions (${actions.slice(0, 6).join(", ")}${actions.length > 6 ? "…" : ""}). Rapid sequences of permission checks are the clearest sign of an automated intruder.`,
        fix: "Revoke this identity's sessions and keys now, then find how it got credentials. Nothing legitimate fails this often this fast." });
    }
    const reads = new Set(list.filter((c) => c.v.read && now - c.at <= this.cfg.enumWindowMs).map((c) => c.v.action));
    if (reads.size >= this.cfg.enumDistinct && !trusted) out.push({
      source: "identity", rule: "ID-ENUMERATION", severity: "medium", where, key: `enum:${id}:${day}`,
      title: `${shortWho(id)} listed ${this.top(`enum:${id}`, reads.size)} different kinds of resources within ${Math.round(this.cfg.enumWindowMs / 60_000)} min`,
      detail: `Mapping the account: ${[...reads].slice(0, 8).join(", ")}…`,
      fix: "Confirm with the owner that this was an audit or inventory job; if not, treat the identity as compromised." });
    const recent = list.filter((c) => now - c.at <= this.cfg.machineWindowMs);
    const human = /IAMUser|Root/.test(r.userIdentity?.type ?? "") || r.additionalEventData?.MFAUsed !== undefined || /console\.amazonaws|signin\.amazonaws/.test(r.userAgent ?? "");
    if (recent.length >= this.cfg.machineCalls && !trusted) {
      const services = new Set(recent.map((c) => c.v.action.split(":")[0]));
      out.push({ source: "identity", rule: "ID-MACHINE-SPEED", severity: human ? "high" : "medium", where, key: `speed:${id}:${day}`,
        title: `${shortWho(id)} made ${this.top(`speed:${id}`, recent.length)} calls within ${this.cfg.machineWindowMs / 1000} s`,
        detail: `${human ? "A person's identity" : "This identity"} is acting at machine speed (${services.size} services: ${[...services].slice(0, 6).join(", ")}). AI-driven intrusions run in bursts of a few seconds like this.`,
        fix: "Check whether a known script uses this identity. If not, revoke its sessions and contain it." });
    }

    // --- persistence and privilege
    const evName = r.eventName.replace(/\d{8}(v\d+)?$/, ""); // Lambda logs versioned names, e.g. UpdateFunctionCode20150331v2
    if (PERSIST[evName] && !r.errorCode && !trusted) {
      const doc = JSON.stringify(r.requestParameters ?? {});
      const admin = ADMIN_POLICY.test(doc) || /admin/i.test(String(r.requestParameters?.groupName ?? r.requestParameters?.GroupName ?? ""));
      const target = r.requestParameters?.userName ?? r.requestParameters?.roleName ?? r.requestParameters?.functionName ?? r.requestParameters?.ClientName ?? r.requestParameters?.Username ?? r.requestParameters?.secretId ?? "";
      out.push({ source: "identity", rule: "ID-PERSISTENCE", severity: admin || r.eventName === "CreateAccessKey" || r.eventName === "UpdateAssumeRolePolicy" ? "critical" : "high", where,
        key: `persist:${id}:${r.eventName}:${target}:${r.eventTime}`,
        title: `${shortWho(id)} ${PERSIST[evName]}${target ? ` (${target})` : ""}${admin ? " with admin rights" : ""}`,
        detail: `${r.eventName} by an identity that is not one of the deploy pipelines. Attackers add credentials and roles so they keep access after the first way in is closed.`,
        fix: "Confirm the change with its owner. If unexpected, remove what was added (keys, policies, app clients, group memberships) and revoke the actor's sessions." });
    }

    // --- one identity assuming many roles: cross-account or role-chaining
    if (r.eventName === "AssumeRole" && !r.errorCode) {
      const roles = this.roles.get(id) ?? [];
      this.roles.set(id, roles);
      roles.push({ at: now, v: String(r.requestParameters?.roleArn ?? "?") });
      prune(roles, now, this.cfg.probeWindowMs);
      const distinct = new Set(roles.map((x) => x.v));
      if (distinct.size >= this.cfg.roleChain) out.push({
        source: "identity", rule: "ID-ROLE-CHAIN", severity: "high", where, key: `roles:${id}:${day}`,
        title: `${shortWho(id)} assumed ${this.top(`roles:${id}`, distinct.size)} different roles within ${this.cfg.probeWindowMs / 1000} s`,
        detail: `Roles: ${[...distinct].map(shortWho).slice(0, 5).join(", ")}. Testing which roles it can reach is how an intruder moves sideways and across accounts.`,
        fix: "Tighten the roles' trust policies to the principals that need them, and review what each assumed role did." });
    }

    // --- secrets read in bulk
    const secretNames = secretsRead(r);
    if (secretNames.length) {
      const s = this.secrets.get(id) ?? [];
      this.secrets.set(id, s);
      for (const v of secretNames) s.push({ at: now, v });
      prune(s, now, this.cfg.probeWindowMs);
      const distinct = new Set(s.map((x) => x.v));
      if (distinct.size >= this.cfg.secretsBurst) out.push({
        source: "identity", rule: "ID-SECRETS-BURST", severity: "critical", where, key: `secrets:${id}:${day}`,
        title: `${shortWho(id)} read ${this.top(`secrets:${id}`, distinct.size)} different secrets within ${this.cfg.probeWindowMs / 1000} s`,
        detail: `Secrets: ${[...distinct].slice(0, 5).join(", ")}. Applications read the few secrets they need; harvesting many at once is credential theft.`,
        fix: "Rotate every secret it read, and revoke the identity's sessions." });
    }

    // --- cloud ransomware: one identity deleting objects in bulk (S3 data events must be on in the trail)
    if (S3_DELETE.test(r.eventName) && !r.errorCode) {
      const s = this.s3del.get(id) ?? []; this.s3del.set(id, s);
      for (let i = 0; i < deletedCount(r); i++) s.push({ at: now, v: String(r.requestParameters?.bucketName ?? "?") });
      prune(s, now, this.cfg.probeWindowMs);
      if (s.length >= 50) out.push({
        source: "ransomware", rule: "ID-S3-MASS-DELETE", severity: "critical", where, key: `s3del:${id}:${day}`,
        title: `${shortWho(id)} deleted ${this.top(`s3del:${id}`, s.length)} S3 objects within ${this.cfg.probeWindowMs / 1000} s`,
        detail: `Buckets: ${[...new Set(s.map((x) => x.v))].slice(0, 4).join(", ")}. Bulk deletion from one identity is how cloud ransomware wipes data after copying or re-encrypting it.`,
        fix: "Revoke the identity's sessions now, then restore from versioning or the Object Lock / AWS Backup copy. Turn on MFA delete and Object Lock for these buckets." });
    }

    // --- audit log buckets: remember them, and catch log destruction by lifecycle rule
    if (/^(CreateTrail|UpdateTrail)$/.test(r.eventName) && r.requestParameters?.s3BucketName) this.trailBucketSet.add(String(r.requestParameters.s3BucketName));
    if (LIFECYCLE.test(r.eventName) && !r.errorCode) {
      const bucket = String(r.requestParameters?.bucketName ?? "?");
      const days = [...JSON.stringify(r.requestParameters ?? {}).matchAll(/"(?:Days|days)"\s*:\s*"?(\d+)/g)].map((m) => Number(m[1]));
      const shortest = days.length ? Math.min(...days) : undefined;
      const isTrail = this.trailBucketSet.has(bucket) || this.cfg.trailBuckets.includes(bucket) || /cloudtrail|trail|audit/i.test(bucket);
      if (shortest !== undefined && shortest <= 7 && (isTrail || !trusted))
        out.push({ source: "identity", rule: "ID-LOG-LIFECYCLE", severity: isTrail ? "critical" : "high", where, key: `lifecycle:${bucket}`,
          title: `${shortWho(id)} set ${bucket} to delete objects after ${shortest} day${shortest === 1 ? "" : "s"}`,
          detail: `${isTrail ? "This bucket holds audit logs. " : ""}A short expiration rule quietly destroys the evidence (or the data) without a single delete call showing up later.`,
          fix: "Remove the lifecycle rule, turn on S3 Object Lock for log buckets, and deny s3:PutLifecycleConfiguration on them except to the deployment role." });
    }

    // --- cloud ransomware with customer-provided keys (SSE-C): objects rewritten with a key only the attacker holds
    if (/^(PutObject|CopyObject|UploadPart|CreateMultipartUpload)$/.test(r.eventName) && !r.errorCode && SSEC.test(JSON.stringify({ q: r.requestParameters, a: r.additionalEventData }))) {
      const s = this.ssec.get(id) ?? []; this.ssec.set(id, s);
      s.push({ at: now, v: String(r.requestParameters?.bucketName ?? "?") });
      prune(s, now, this.cfg.probeWindowMs);
      out.push({ source: "ransomware", rule: "ID-S3-SSEC-ENCRYPT", severity: s.length >= 20 ? "critical" : "high", where, key: `ssec:${id}:${day}`,
        title: `${shortWho(id)} re-encrypted ${this.top(`ssec:${id}`, s.length)} S3 object${s.length === 1 ? "" : "s"} with a customer-provided key`,
        detail: `Buckets: ${[...new Set(s.map((x) => x.v))].slice(0, 4).join(", ")}. With SSE-C, only whoever holds the key can read the objects again: the technique used in the 2025 Codefinger ransomware campaign.`,
        fix: "Revoke the identity's keys and sessions now, block SSE-C with a bucket policy (deny s3:PutObject when s3:x-amz-server-side-encryption-customer-algorithm is present), and restore from versions or backups." });
    }

    // --- LLMjacking: someone else using the company's model access
    if ((MODEL_CALL.test(r.eventName) || MODEL_RECON.test(r.eventName)) && !this.cfg.modelCallers.test(id) && !trusted)
      out.push({ source: "identity", rule: "ID-LLMJACKING", severity: MODEL_CALL.test(r.eventName) ? "high" : "medium", where, key: `llmjack:${id}:${day}`,
        title: `${shortWho(id)} ${MODEL_CALL.test(r.eventName) ? "is calling AI models" : "is probing which AI models are enabled"} (${r.eventName})`,
        detail: `Only the agent's runtime is expected to use Bedrock. Stolen cloud keys are now resold to run AI models on the victim's bill ("LLMjacking"), often after checking which models are enabled.`,
        fix: "If this identity should not use AI models, revoke its keys, deny bedrock:Invoke* outside the agent role, and set a Bedrock budget alarm." });

    // --- instance credentials used for discovery: keys stolen from the metadata service
    if (INSTANCE_CREDS.test(id) && /^(List|Describe|Get|Lookup|Search|BatchGet)/.test(r.eventName)) {
      const s = this.recon.get(id) ?? []; this.recon.set(id, s);
      s.push({ at: now, v: `${r.eventSource}:${r.eventName}` });
      prune(s, now, this.cfg.enumWindowMs);
      const kinds = new Set(s.map((x) => x.v));
      if (kinds.size >= 8)
        out.push({ source: "identity", rule: "ID-INSTANCE-RECON", severity: "high", where, key: `irecon:${id}:${day}`,
          title: `A server's credentials are mapping the account (${this.top(`irecon:${id}`, kinds.size)} kinds of lookup)`,
          detail: `${shortWho(id)} ran ${[...kinds].slice(0, 6).map((k) => k.split(":")[1]).join(", ")}… within ${this.cfg.enumWindowMs / 60_000} min. Servers rarely explore the account; an attacker who took the instance's credentials from its metadata service does.`,
          fix: "Require IMDSv2 on every instance, check the instance for compromise, and scope its role to only what the application calls." });
    }

    // --- console sign-in without MFA
    if (r.eventName === "ConsoleLogin" && r.responseElements?.ConsoleLogin === "Success" && String(r.additionalEventData?.MFAUsed ?? "") === "No")
      out.push({ source: "identity", rule: "ID-NO-MFA-LOGIN", severity: "medium", where, key: `nomfa:${id}:${day}`,
        title: `${shortWho(id)} signed in to the console without MFA`,
        detail: "A password alone protects this account. Sprayed or phished passwords are the first step of ARTEX-style intrusions.",
        fix: "Require MFA for every console user (an IAM policy that denies actions when aws:MultiFactorAuthPresent is false)." });

    // --- covering tracks, opening data to the outside
    if (TAMPER.test(r.eventName) && !r.errorCode) out.push({ source: "identity", rule: "ID-LOG-TAMPER", severity: "critical", where, key: `tamper:${id}:${r.eventName}:${r.eventTime}`,
      title: `Security logging changed: ${r.eventName}`,
      detail: `${shortWho(id)} called ${r.eventName}${r.requestParameters?.name ? ` on ${r.requestParameters.name}` : ""}. Turning off logs comes right before the part of an attack they would record.`,
      fix: "Turn logging back on, lock it with an organisation-level trail and SCP, and treat the identity as compromised." });
    if (SHARE.test(r.eventName) && !r.errorCode) {
      const doc = JSON.stringify(r.requestParameters ?? {});
      const own = /arn:aws:(?:iam|sts)::(\d{12}):/.exec(who(r))?.[1];
      const foreign = [...doc.matchAll(/arn:aws:iam::(\d{12}):/g)].some((m) => m[1] !== own);
      const open = foreign || /"all"|"Principal"\s*:\s*"\*"|"Principal"\s*:\s*\{\s*"AWS"\s*:\s*"\*"|AllUsers|AuthenticatedUsers|createVolumePermission|launchPermission|DeletePublicAccessBlock|DeleteBucketPublicAccessBlock|"restore"|valuesToAdd/i.test(doc) || /Delete.*PublicAccessBlock/.test(r.eventName);
      if (open) out.push({ source: "identity", rule: "ID-SNAPSHOT-SHARE", severity: "critical", where, key: `share:${id}:${r.eventName}:${r.eventTime}`,
        title: `Data opened to other accounts or the public: ${r.eventName}`,
        detail: `${shortWho(id)} changed sharing on ${r.requestParameters?.snapshotId ?? r.requestParameters?.dBSnapshotIdentifier ?? r.requestParameters?.bucketName ?? "a resource"}. Sharing a snapshot or opening a bucket is a quiet way to take a copy of everything.`,
        fix: "Revert the sharing now, then check whether another account already copied it." });
    }
    return out;
  }

  ingestEgress(e: EgressRecord): Finding[] {
    const host = (e.host ?? e.query_name ?? "").replace(/\.$/, "").toLowerCase();
    if (!host) return [];
    const now = Date.parse(e.at);
    const who = e.principal ?? e.src ?? "unknown host";
    const out: Finding[] = [];
    if (EXFIL_HOSTS.test(host)) {
      const total = (this.egressBytes.get(`${who}|${host}`) ?? 0) + (e.bytes_out ?? 0);
      this.egressBytes.set(`${who}|${host}`, total);
      out.push({ source: "network", rule: "NET-WEBHOOK-EXFIL", severity: total > 1_000_000 || /webhook\.site|requestbin|pipedream|transfer\.sh|file\.io/.test(host) ? "critical" : "high",
        where: `${who} → ${host}`, key: `exfil:${who}:${host}`,
        title: `Data sent to ${host}`,
        detail: `${who} sent ${(total / 1024).toFixed(1)} KB to ${host}${e.process ? ` (process ${e.process})` : ""}. Throwaway webhook and paste services are how AI attack frameworks carry command output and stolen data out.`,
        fix: "Block the domain at the proxy or DNS firewall, isolate the source, and work out what it sent." });
    } else if (AI_HOSTS.test(host) && !this.cfg.approvedAiHosts.some((a) => host.startsWith(a) || host === a)) {
      if (this.once(`ai:${who}:${host}`, now, 3600_000)) out.push({ source: "network", rule: "NET-UNAPPROVED-AI", severity: "high",
        where: `${who} → ${host}`, key: `ai:${who}:${host}`,
        title: `Call to an unapproved AI model API: ${host}`,
        detail: `${who} called ${host}, which is not on the approved list (${this.cfg.approvedAiHosts.join(", ")}). Intruders drive their tools with whatever model they can reach, switching providers to dodge controls.`,
        fix: "If nobody owns this, block it and investigate the source. If it is legitimate, add it to APPROVED_AI_HOSTS." });
    }
    return out;
  }
}

/** CloudTrail delivers {"Records": [...]} files; also accept one record per line. */
export function parseCloudTrail(text: string): CloudTrailRecord[] {
  const t = text.trim();
  if (!t) return [];
  if (t.startsWith("{") && t.includes('"Records"')) {
    try { return (JSON.parse(t).Records ?? []) as CloudTrailRecord[]; } catch { /* fall through */ }
  }
  return t.split("\n").flatMap((l) => { try { const o = JSON.parse(l); return o.Records ?? (o.eventName ? [o] : []); } catch { return []; } });
}
