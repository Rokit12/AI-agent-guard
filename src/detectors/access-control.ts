/**
 * Access-control audit.
 *
 * Who can make the agent act, and with what rights? This reads the target's
 * infrastructure code (AWS CDK), its HTTP handlers and its approval module, and flags:
 * cloud permissions granted on "*", public buckets or functions, HTTP routes that act
 * without checking who is calling, wide-open CORS, approvals that can come from the agent
 * itself, and the approver taken from a request body rather than a verified login.
 */
import type { Finding } from "../alerts.ts";
import type { SourceFile } from "./code-scan.ts";

const lineOf = (text: string, index: number) => text.slice(0, index).split("\n").length;
const isTest = (p: string) => /(\.test\.|\.spec\.|__tests__|\/test\/)/.test(p);

export function auditAccess(files: SourceFile[]): Finding[] {
  const out: Finding[] = [];
  const add = (f: SourceFile, index: number, x: Omit<Finding, "source" | "where">) => out.push({ ...x, source: "access", where: `${f.path}:${lineOf(f.text, index)}` });

  for (const f of files) {
    if (isTest(f.path)) continue;
    const isInfra = /(^|\/)(infra|cdk|stack|terraform)/i.test(f.path) || /aws-cdk-lib|from "@aws-cdk/.test(f.text);

    if (isInfra) {
      // IAM: actions "*" or resources "*" on write actions
      for (const m of f.text.matchAll(/actions\s*:\s*\[([^\]]*)\]\s*,?\s*resources\s*:\s*\[([^\]]*)\]/g)) {
        const actions = m[1], resources = m[2];
        if (/["'`]\*["'`]/.test(actions)) add(f, m.index!, { rule: "ACC-IAM-ALL-ACTIONS", severity: "critical",
          title: "Cloud role can do anything", detail: `An IAM statement grants actions ["*"] (resources ${resources.trim()}).`,
          fix: "List only the API actions the agent needs." });
        else if (/["'`]\*["'`]/.test(resources) && /:(Put|Delete|Create|Update|Invoke|Pass|Attach)/.test(actions)) add(f, m.index!, { rule: "ACC-IAM-ALL-RESOURCES", severity: "high",
          title: "Write permission on every resource", detail: `Actions ${actions.trim().slice(0, 120)} are granted on resources ["*"].`,
          fix: "Scope the statement to the ARNs the agent uses." });
        else if (/["'`]\*["'`]/.test(resources)) add(f, m.index!, { rule: "ACC-IAM-READ-ALL", severity: "low",
          title: "Read or invoke permission on every resource", detail: `Actions ${actions.trim().slice(0, 120)} are granted on resources ["*"]. Some AWS actions (model invocation, metrics) need this; check that these do.`,
          fix: "Scope to specific ARNs where the service allows it." });
      }
      for (const m of f.text.matchAll(/publicReadAccess\s*:\s*true|BlockPublicAccess\.BLOCK_ACLS(?!_)|blockPublicAccess\s*:\s*undefined/g))
        add(f, m.index!, { rule: "ACC-PUBLIC-BUCKET", severity: "high", title: "Storage bucket readable by the public", detail: `"${m[0]}" leaves the bucket open to anyone with the URL.`, fix: "Block public access and serve through CloudFront with origin access control." });
      for (const m of f.text.matchAll(/authType\s*:\s*(?:lambda\.)?FunctionUrlAuthType\.NONE|authorizationType\s*:\s*(?:apigw\.)?AuthorizationType\.NONE/g))
        add(f, m.index!, { rule: "ACC-OPEN-ENDPOINT", severity: "medium", title: "Cloud endpoint with no authentication", detail: `"${m[0]}": anyone can call it.`, fix: "Put it behind an authorizer (Cognito, IAM or a signed key), or confirm it is meant to be public and only reads." });
      // Backups, audit logs and exports that ransomware or an intruder could overwrite or delete
      for (const m of f.text.matchAll(/new\s+s3\.Bucket\(\s*this\s*,\s*["'`]([^"'`]+)["'`]\s*,\s*\{/g)) {
        if (!/backup|archive|audit|export|statement|ledger|snapshot|log/i.test(m[1])) continue;
        const props = f.text.slice(m.index!, m.index! + 1200).split(/\n\s*\}\s*\)/)[0];
        if (!/objectLockEnabled\s*:\s*true/.test(props)) add(f, m.index!, { rule: "ACC-NO-IMMUTABLE-BACKUP", severity: "medium",
          title: `Bucket "${m[1]}" can be overwritten or deleted`, detail: "It holds backups, logs or exports, but S3 Object Lock is off, so ransomware or a stolen key can encrypt or wipe it along with everything else.",
          fix: "Set objectLockEnabled: true with a default retention (COMPLIANCE mode for audit records), or copy it to an AWS Backup vault with Vault Lock." });
      }
      for (const m of f.text.matchAll(/allowOrigins\s*:\s*(?:apigw\.)?Cors\.ALL_ORIGINS|allowOrigins\s*:\s*\[\s*["'`]\*["'`]\s*\]/g))
        add(f, m.index!, { rule: "ACC-CORS-ALL", severity: "medium", title: "Any website can call this API from a browser", detail: `"${m[0]}" lets a page on any site send requests with a signed-in user's browser.`, fix: "Allow only your console's origin." });
    }

    // HTTP handlers that change things without checking the caller
    const routeRe = /\b(?:app|router|server)\.(post|put|patch|delete)\(\s*["'`]([^"'`]+)["'`]/g;
    const hasAuth = /\b(auth|authorize|verify(Jwt|Token|IdToken)?|requireUser|cognito|jwt|bearer|session|signedIn|x-amzn-oidc)\b/i;
    for (const m of f.text.matchAll(routeRe)) {
      const handler = f.text.slice(m.index!, m.index! + 600);
      if (!hasAuth.test(handler) && !hasAuth.test(f.text.slice(0, m.index!).split("\n").slice(-15).join("\n")))
        add(f, m.index!, { rule: "ACC-ROUTE-NO-AUTH", severity: "high", title: `${m[1].toUpperCase()} ${m[2]} acts without checking who is calling`,
          detail: "No authentication check in or just before this handler. If it is reachable from the network, anyone can trigger it.",
          fix: "Verify the caller (a signed session or token) before doing anything, and log who it was." });
    }

    // Approver taken from the request instead of a verified identity
    const approverFromBody = /\b(?:approvedBy|approver|by)\s*[:=]\s*(?:req|request|body|payload|input)\.(?:body\.)?(?:by|approver|approvedBy|user)\b/.exec(f.text);
    if (approverFromBody) add(f, approverFromBody.index, { rule: "ACC-APPROVER-FROM-INPUT", severity: "high",
      title: "Approver name comes from the request, not a verified login",
      detail: `"${approverFromBody[0]}": a caller can approve as anyone by typing a name.`,
      fix: "Take the approver from the verified token (for example the Cognito id token's email)." });

    // Approval module that never checks approver != proposer
    if (/termsHash|hashTerms/.test(f.text) && /export (async )?function \w*[aA]pprov/.test(f.text) && !/proposer|proposedBy|separateApprover|PROPOSER/.test(f.text))
      add(f, f.text.search(/export (async )?function \w*[aA]pprov/), { rule: "ACC-NO-SEPARATION", severity: "high",
        title: "Approvals do not check that the approver is not the proposer",
        detail: "Nothing in the approval code stops the agent from approving its own action.",
        fix: "Reject any approval whose approver is the proposing agent or unset." });
  }
  return out;
}
