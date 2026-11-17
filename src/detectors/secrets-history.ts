/**
 * Secrets in git history (the gitleaks / TruffleHog approach).
 *
 * The code scanner sees today's files. A key that was committed once and deleted later is
 * still in every clone of the repository. This walks every commit's added lines
 * (`git log -p --all`) with provider-specific patterns plus a high-entropy check on
 * credential-looking assignments, and says which commit introduced each secret and whether
 * it is still in the current files.
 *
 * Values are never shown in full: an alert carries the first 8 characters and a hash.
 */
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Finding, Severity } from "../alerts.ts";

export const SECRET_RULES: { id: string; what: string; re: RegExp; severity: Severity }[] = [
  { id: "aws-access-key", what: "AWS access key", re: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g, severity: "critical" },
  { id: "aws-secret-key", what: "AWS secret access key", re: /aws.{0,20}?secret.{0,20}?['"`]?\s*[:=]\s*['"`]?([A-Za-z0-9/+]{40})\b/gi, severity: "critical" },
  { id: "airwallex-key", what: "Airwallex API key", re: /\b(?:AWX|AIRWALLEX)_API_KEY\s*[:=]\s*['"`]?([A-Za-z0-9]{32,})/g, severity: "critical" },
  { id: "model-api-key", what: "AI model API key", re: /\b(sk-(?:ant-api\d{2}-|proj-)?[A-Za-z0-9_-]{32,})\b/g, severity: "critical" },
  { id: "github-token", what: "GitHub token", re: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b/g, severity: "critical" },
  { id: "slack-token", what: "Slack token", re: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g, severity: "high" },
  { id: "slack-webhook", what: "Slack webhook URL", re: /(https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]{20,})/g, severity: "high" },
  { id: "stripe-key", what: "Stripe secret key", re: /\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b/g, severity: "critical" },
  { id: "google-api-key", what: "Google API key", re: /\b(AIza[0-9A-Za-z_-]{35})\b/g, severity: "high" },
  { id: "private-key", what: "private key", re: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----)/g, severity: "critical" },
  { id: "jwt", what: "signed JWT", re: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,})\b/g, severity: "medium" },
  { id: "evm-private-key", what: "wallet private key", re: /\b(?:private[_-]?key|PRIVATE_KEY|pk)\s*[:=]\s*['"`]?(0x[a-fA-F0-9]{64})\b/g, severity: "critical" },
];
const GENERIC = /\b(?:api[_-]?key|secret|token|passw(?:or)?d|client[_-]?secret)\w*\s*[:=]\s*['"`]([^'"`\s]{16,})['"`]/gi;
const PLACEHOLDER = /^(?:x+|\*+|<.*>|\$\{.*\}|your[_-]|example|changeme|test|dummy|placeholder|redacted|process\.env)/i;

export function entropy(s: string) {
  const c: Record<string, number> = {}; for (const ch of s) c[ch] = (c[ch] ?? 0) + 1;
  return -Object.values(c).reduce((h, n) => h + (n / s.length) * Math.log2(n / s.length), 0);
}

export interface SecretHit { rule: string; what: string; severity: Severity; value: string; commit: string; date: string; author: string; file: string; line: string }

/** Parse `git log -p` output (with the custom header below) into secret hits on added lines. */
export function findSecretsInLog(log: string): SecretHit[] {
  const hits: SecretHit[] = [];
  let commit = "", date = "", author = "", file = "";
  for (const line of log.split("\n")) {
    if (line.startsWith("\u0001")) { [commit, date, author] = line.slice(1).split("\u0002"); continue; }
    if (line.startsWith("+++ ")) { file = line.slice(4).replace(/^b\//, ""); continue; }
    if (!line.startsWith("+") || line.startsWith("+++")) continue;
    const text = line.slice(1);
    if (text.length > 2000 || /\.(lock|min\.js|map|svg|snap)$/.test(file) || /package-lock\.json$/.test(file)) continue;
    let matched = false;
    for (const r of SECRET_RULES) for (const m of text.matchAll(r.re)) {
      const v = m[1] ?? m[0]; if (PLACEHOLDER.test(v)) continue;
      matched = true; hits.push({ rule: r.id, what: r.what, severity: r.severity, value: v, commit, date, author, file, line: text.trim().slice(0, 120) });
    }
    if (!matched) for (const m of text.matchAll(GENERIC)) {
      const v = m[1]; if (PLACEHOLDER.test(v) || entropy(v) < 3.5) continue;
      hits.push({ rule: "generic-high-entropy", what: "credential-looking value", severity: "high", value: v, commit, date, author, file, line: text.trim().slice(0, 120) });
    }
  }
  return hits;
}

const fp = (v: string) => createHash("sha256").update(v).digest("hex").slice(0, 10);
const mask = (v: string) => `${v.slice(0, 8)}… (sha256 ${fp(v)})`;

function git(dir: string, args: string[]): Promise<string> {
  return new Promise((res, rej) => execFile("git", args, { cwd: dir, maxBuffer: 200_000_000, timeout: 300_000 }, (e, out) => (e && !out ? rej(e) : res(out))));
}

export async function scanSecretsHistory(dir: string): Promise<{ at: string; commits: number; findings: Finding[]; summary: string; passed: string[] }> {
  const at = new Date().toISOString();
  if (!existsSync(join(dir, ".git"))) return { at, commits: 0, findings: [], summary: "Not a git repository", passed: [] };
  const commits = Number((await git(dir, ["rev-list", "--all", "--count"])).trim()) || 0;
  const log = await git(dir, ["log", "--all", "-p", "--no-color", "--no-ext-diff", "-U0", "--format=%x01%H%x02%aI%x02%an"]);
  const hits = findSecretsInLog(log);
  // One alert per distinct secret value; note the first commit that added it and whether it is still present.
  const byValue = new Map<string, SecretHit[]>();
  for (const h of hits) (byValue.get(h.value) ?? byValue.set(h.value, []).get(h.value)!).push(h);
  const findings: Finding[] = [];
  for (const [value, hs] of byValue) {
    const first = hs.sort((a, b) => a.date.localeCompare(b.date))[0];
    let still = false;
    try { still = (await git(dir, ["grep", "-F", "-l", "-e", value, "HEAD", "--"])).trim().length > 0; } catch { still = false; }
    findings.push({
      source: "code", rule: `SECRET-HISTORY-${first.rule.toUpperCase()}`, severity: still ? first.severity : first.severity === "critical" ? "high" : first.severity,
      where: `${first.file} @ ${first.commit.slice(0, 8)}`, key: `secret-history:${dir}:${fp(value)}`,
      title: `${first.what} ${still ? "in the code and in git history" : "in git history (deleted since)"}`,
      detail: `${mask(value)} was added by ${first.author} on ${first.date.slice(0, 10)} in ${first.file} (commit ${first.commit.slice(0, 8)})${hs.length > 1 ? `, and appears in ${hs.length - 1} more change${hs.length > 2 ? "s" : ""}` : ""}. Anyone with a clone has it, even after the file was changed.`,
      fix: "Rotate the key now (deleting it from the code does not un-leak it). Then purge it from history with git filter-repo and force-push, and block new ones with a pre-commit secret hook.",
      evidence: { commit: first.commit, file: first.file, fingerprint: fp(value) },
    });
  }
  return { at, commits, findings, passed: findings.length ? [] : [`No secrets in ${commits} commits of history`],
    summary: findings.length ? `${findings.length} secret${findings.length === 1 ? "" : "s"} found in ${commits} commits` : `${commits} commits checked, no secrets` };
}
