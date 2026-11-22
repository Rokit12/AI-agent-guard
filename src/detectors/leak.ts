/**
 * Data-leak scan (data loss prevention).
 *
 * Looks where data should not be at rest: the agent's run logs, server logs, alert emails
 * and exports. Finds card numbers (checked with the Luhn algorithm, as PCI DSS scoping
 * tools do), live credentials written to logs, bulk personal data (many emails or IBANs in
 * one file), and sensitive files committed to the repository (.env, private keys, keystores).
 * Values are masked in every alert: card numbers show only their last four digits.
 */
import { execFile } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, basename } from "node:path";
import type { Finding, Severity } from "../alerts.ts";
import { SECRET_RULES } from "./secrets-history.ts";

export function luhn(d: string) {
  let s = 0, alt = false;
  for (let i = d.length - 1; i >= 0; i--) { let n = d.charCodeAt(i) - 48; if (alt) { n *= 2; if (n > 9) n -= 9; } s += n; alt = !alt; }
  return s % 10 === 0;
}
const BRAND: [RegExp, string][] = [[/^4\d{12}(?:\d{3}){0,2}$/, "Visa"], [/^(?:5[1-5]\d{14}|2(?:2[2-9]|[3-6]\d|7[01])\d{12}|2720\d{12})$/, "Mastercard"], [/^3[47]\d{13}$/, "American Express"], [/^6(?:011|5\d{2})\d{12,15}$/, "Discover"], [/^35(?:2[89]|[3-8]\d)\d{12,15}$/, "JCB"]];
/** Well-known test card numbers published by card schemes and payment providers. */
export const TEST_PANS = new Set(["4242424242424242", "4111111111111111", "4000056655665556", "5555555555554444", "5200828282828210", "2223003122003222", "378282246310005", "371449635398431", "6011111111111117", "3566002020360505", "4012888888881881", "4035501000000008", "4000000000000002"]);
const PAN_RE = /(?<![\d.])(?:\d[ -]?){12,18}\d(?![\d.])/g;

export function findCards(text: string) {
  const out: { last4: string; brand: string; test: boolean; index: number }[] = [];
  for (const m of text.matchAll(PAN_RE)) {
    const raw = m[0]; const d = raw.replace(/[ -]/g, "");
    if (d.length < 13 || d.length > 19) continue;
    if (/[ -]/.test(raw) && !/^\d{4}([ -])\d{4}\1\d{4}\1\d{1,7}$|^\d{4}([ -])\d{6}\2\d{5}$/.test(raw)) continue; // only card-style grouping
    const brand = BRAND.find(([re]) => re.test(d))?.[1]; if (!brand || !luhn(d)) continue;
    if (/^(\d)\1+$/.test(d)) continue;
    out.push({ last4: d.slice(-4), brand, test: TEST_PANS.has(d), index: m.index! });
  }
  return out;
}

const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const IBAN = /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}(?:[ ]?[A-Z0-9]{1,3})?\b/g;
const SENSITIVE_FILE = /(^|\/)(\.env(\.(?!example|sample|template)[\w.-]+)?|id_(?:rsa|dsa|ecdsa|ed25519)|[^/]+\.(?:pem|key|p12|pfx|jks|keystore)|credentials(?:\.json)?|\.npmrc|\.pypirc|\.git-credentials|secrets?\.(?:json|ya?ml)|service-account[^/]*\.json)$/i;
const SAFE_FILE = /\.(?:pub|example|sample|template)$|(^|\/)(?:test|fixtures?)\//i;

export interface LeakPlace { dir: string; kind: "logs" | "runs" | "emails" | "exports" }
const KIND_LABEL = { logs: "a log", runs: "an agent run log", emails: "an alert email", exports: "an export" } as const;

function* files(root: string): Generator<string> {
  let names: string[] = []; try { names = readdirSync(root); } catch { return; }
  for (const n of names) {
    if (n === "node_modules" || n === ".git") continue;
    const p = join(root, n); let st; try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) yield* files(p); else if (st.isFile() && st.size > 0 && st.size < 20_000_000) yield p;
  }
}

/** Scan one text for leaks (pure; used by the scan and tests). */
export function leaksInText(text: string, where: string, kind: LeakPlace["kind"]): Finding[] {
  const out: Finding[] = [];
  const label = KIND_LABEL[kind];
  const cards = findCards(text);
  const real = cards.filter((c) => !c.test), test = cards.filter((c) => c.test);
  if (real.length) {
    const sev: Severity = kind === "exports" ? "high" : "critical";
    out.push({ source: "leak", rule: "LEAK-CARD-NUMBER", severity: sev, where, title: `Full card number${real.length > 1 ? `s (${real.length})` : ""} stored in ${label}`,
      detail: `${[...new Set(real.map((c) => `${c.brand} ending ${c.last4}`))].slice(0, 5).join(", ")} written in full to ${where}. Card data must not be stored unmasked (PCI DSS requirement 3), and anyone who can read this file can use it.`,
      fix: "Mask the numbers to the last four digits where they are written, delete the stored copies, and find which step logs them.", evidence: { count: real.length, last4: [...new Set(real.map((c) => c.last4))].slice(0, 10) } });
  }
  if (test.length && kind !== "exports") out.push({ source: "leak", rule: "LEAK-TEST-CARD", severity: "low", where, title: `Test card number written to ${label}`,
    detail: `${test.length} published test card number${test.length > 1 ? "s" : ""} (ending ${[...new Set(test.map((c) => c.last4))].join(", ")}) appear in full. Harmless in the sandbox, but the same code path would log real cards in production.`,
    fix: "Mask card numbers before logging, whatever the environment.", evidence: { count: test.length } });
  if (kind !== "exports") {
    const secrets = new Map<string, string>();
    for (const r of SECRET_RULES) for (const m of text.matchAll(r.re)) { const v = m[1] ?? m[0]; if (!/^(?:x+|\*+|<.*>|\$\{.*\}|example|test|dummy|redacted)/i.test(v)) secrets.set(r.what, v); }
    for (const [what, v] of secrets) out.push({ source: "leak", rule: "LEAK-SECRET-IN-LOGS", severity: "critical", key: `leak-secret:${where}:${what}`, where, title: `${what[0].toUpperCase()}${what.slice(1)} written to ${label}`,
      detail: `A ${what} (${v.slice(0, 8)}…) is stored in plain text in ${where}. Logs are copied, shipped and read far more widely than secret stores.`,
      fix: "Rotate the credential now, delete or redact the log, and stop the code path that logs it.", evidence: { prefix: v.slice(0, 8) } });
  }
  const emails = new Set([...text.matchAll(EMAIL)].map((m) => m[0].toLowerCase()).filter((e) => !/@(example\.(com|org)|test\.|localhost)/.test(e)));
  const ibans = new Set([...text.matchAll(IBAN)].map((m) => m[0].replace(/ /g, "")));
  if ((emails.size >= 25 || ibans.size >= 10) && kind !== "exports") out.push({ source: "leak", rule: "LEAK-BULK-PII", severity: "medium", where, title: `Bulk personal data in ${label}`,
    detail: `${emails.size} distinct email addresses${ibans.size ? ` and ${ibans.size} IBANs` : ""} are stored in ${where}. Large amounts of personal data in logs widen the damage of any breach.`,
    fix: "Log identifiers rather than personal data, and set a short retention period on these logs.", evidence: { emails: emails.size, ibans: ibans.size } });
  return out;
}

function git(cwd: string, args: string[]): Promise<string> {
  return new Promise((res) => execFile("git", args, { cwd, maxBuffer: 50 * 1024 * 1024 }, (e, out) => res(e ? "" : String(out))));
}

export async function scanLeaks(places: LeakPlace[], repos: string[]) {
  const findings: Finding[] = [];
  let scanned = 0;
  for (const pl of places) {
    if (!existsSync(pl.dir)) continue;
    for (const p of files(pl.dir)) {
      if (/\.(png|jpe?g|gif|pdf|zip|gz|mp4|wav|enc|locked)$/i.test(p)) continue;
      scanned++;
      findings.push(...leaksInText(readFileSync(p, "utf8"), `${basename(pl.dir)}/${relative(pl.dir, p)}`, pl.kind));
    }
  }
  let tracked = 0;
  for (const repo of repos) {
    if (!existsSync(join(repo, ".git"))) continue;
    const list = (await git(repo, ["ls-files"])).split("\n").filter(Boolean); tracked += list.length;
    for (const f of list) if (SENSITIVE_FILE.test(f) && !SAFE_FILE.test(f)) {
      const key = /\.(pem|key|p12|pfx|jks|keystore)$|id_(rsa|dsa|ecdsa|ed25519)$/i.test(f);
      findings.push({ source: "leak", rule: "LEAK-SENSITIVE-FILE-TRACKED", severity: key || /\.env/.test(f) ? "critical" : "high", where: `${basename(repo)}/${f}`,
        title: `Sensitive file committed to the repository: ${f}`, detail: `${f} is tracked by git in ${basename(repo)}, so every clone and fork has a copy.`,
        fix: "Remove it from the repository (git rm --cached), add it to .gitignore, rotate anything it contains, and purge it from history.", evidence: { file: f } });
    }
  }
  const has = (r: string) => findings.some((f) => f.rule === r);
  const passed = [
    ...(has("LEAK-CARD-NUMBER") ? [] : [`No full card numbers in ${scanned} log, run, email and export files`]),
    ...(has("LEAK-SECRET-IN-LOGS") ? [] : ["No credentials written to logs"]),
    ...(has("LEAK-SENSITIVE-FILE-TRACKED") ? [] : [`No .env, key or credential files among ${tracked} tracked files`]),
    ...(has("LEAK-BULK-PII") ? [] : ["No bulk personal data in logs"]),
  ];
  return { findings, passed, scanned, tracked, summary: `${scanned} log, run, email and export files · ${tracked} tracked files checked` };
}
