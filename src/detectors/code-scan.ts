/**
 * AI-agent vulnerability scanner for source code.
 *
 * Reads a TypeScript/JavaScript codebase and flags the patterns that let an AI agent
 * lose money or leak data: money-moving calls without an approval gate or idempotency
 * key, untrusted text reaching a model without being fenced as data, model output used
 * as an amount, card data sent to a model, secrets in code, TLS turned off, eval.
 *
 * It is a fast first pass, not a proof: every finding names the file and line and says
 * what to check, so a person can confirm it in a minute.
 */
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, relative, extname } from "node:path";
import { execFileSync } from "node:child_process";
import type { Finding, Severity } from "../alerts.ts";

export interface SourceFile { path: string; text: string }

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "cdk.out", "runs", "state", "outbox", "sandbox", "coverage", "preview"]);
const CODE_EXT = new Set([".ts", ".mts", ".tsx", ".js", ".mjs", ".cjs"]);

export function loadSources(root: string): SourceFile[] {
  const out: SourceFile[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      if (SKIP_DIRS.has(name)) continue;
      const p = join(dir, name);
      const st = statSync(p);
      if (st.isDirectory()) walk(p);
      else if (CODE_EXT.has(extname(name)) && st.size < 1_000_000) out.push({ path: relative(root, p), text: readFileSync(p, "utf8") });
    }
  };
  walk(root);
  return out;
}

const isTest = (p: string) => /(\.test\.|\.spec\.|__tests__|\/test\/)/.test(p);
const lineOf = (text: string, index: number) => text.slice(0, index).split("\n").length;

// Endpoints that move money on Airwallex-style and generic payment APIs.
const MONEY_CALL = /["'`](?:\/api\/v1)?\/(?:transfers|payouts|payments?|payment_intents|refunds|charges|pa\/refunds)\/[^"'`]*?(?:create|capture|confirm)["'`]/;
/** HTTP client and adapter layers pass calls through; the gate belongs where the action is decided. */
const isPlumbing = (f: SourceFile) => /\b(?:async\s+)?call\s*<\w*[^>]*>?\s*\(|\bsuper\.call</.test(f.text) && /\bclass\s+\w+/.test(f.text);
const APPROVAL_GATE = /\b(requireApproval|requestApproval|approve[A-Z]\w*|approval\b|termsHash|assertApproved|confirmWithHuman|humanApproval)\b/;
const IDEMPOTENCY = /\b(request_id|requestId|idempotency[_-]?key|Idempotency-Key)\b/;

interface Rule {
  id: string; severity: Severity; title: string; fix: string;
  test(f: SourceFile): { index: number; detail: string }[];
}

const RULES: Rule[] = [
  {
    id: "CODE-SECRET",
    severity: "critical",
    title: "Secret written into source code",
    fix: "Move it to a secret store (AWS Secrets Manager, .env kept out of git) and rotate the key now, since it has been exposed.",
    test(f) {
      const hits: { index: number; detail: string }[] = [];
      const pats: [RegExp, string][] = [
        [/\bAKIA[0-9A-Z]{16}\b/g, "an AWS access key id"],
        [/\bsk-(?:ant-|proj-|live_)?[A-Za-z0-9_-]{24,}\b/g, "an API secret key"],
        [/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, "a private key"],
        [/\b(?:api[_-]?key|client[_-]?secret|password|secret)\s*[:=]\s*["'`][A-Za-z0-9/+_\-]{20,}["'`]/gi, "a hard-coded credential"],
      ];
      for (const [re, what] of pats) for (const m of f.text.matchAll(re)) hits.push({ index: m.index!, detail: `Found ${what}: ${m[0].slice(0, 12)}…` });
      return hits;
    },
  },
  {
    id: "CODE-MONEY-NO-APPROVAL",
    severity: "high",
    title: "Money moves without a human approval gate",
    fix: "Bind the action to an approval of its exact terms (amount, currency, counterparty) before the call, and refuse if the terms changed.",
    test(f) {
      if (isTest(f.path) || isPlumbing(f)) return [];
      const m = MONEY_CALL.exec(f.text);
      if (!m || APPROVAL_GATE.test(f.text)) return [];
      return [{ index: m.index, detail: `This file calls ${m[0]} but nothing in it checks an approval. An agent tricked by a document could move money on its own.` }];
    },
  },
  {
    id: "CODE-MONEY-NO-IDEMPOTENCY",
    severity: "high",
    title: "Payment call without an idempotency key",
    fix: "Send a request_id derived from the business event (invoice, case) so a retry or restart cannot pay twice.",
    test(f) {
      if (isTest(f.path) || isPlumbing(f)) return [];
      const m = MONEY_CALL.exec(f.text);
      if (!m || IDEMPOTENCY.test(f.text)) return [];
      return [{ index: m.index, detail: `${m[0]} is called with no request_id or idempotency key anywhere in the file. A timeout and retry can pay twice.` }];
    },
  },
  {
    id: "LLM-UNFENCED-INPUT",
    severity: "medium",
    title: "Untrusted text sent to a model without being marked as data",
    fix: "Wrap outside text in clear delimiters (for example <document>…</document>) and tell the model in the system prompt that it is data, never instructions.",
    test(f) {
      if (isTest(f.path)) return [];
      const hits: { index: number; detail: string }[] = [];
      const re = /(messages\s*:\s*\[|\.messages\.create\(|InvokeModel(?:Command)?\(|ConverseCommand\(|chat\.completions\.create\()/g;
      for (const m of f.text.matchAll(re)) {
        const window = f.text.slice(m.index!, m.index! + 900);
        const hasVar = /\$\{[^}]+\}|content\s*:\s*(?!["'`])[a-zA-Z_]/.test(window);
        const fenced = /<document>|<untrusted|<data>|```|BEGIN UNTRUSTED/i.test(f.text);
        if (hasVar && !fenced) hits.push({ index: m.index!, detail: "Text built from variables reaches the model with no data fence anywhere in the file. A planted instruction in an email or document would read like part of the prompt." });
      }
      return hits.slice(0, 1);
    },
  },
  {
    id: "LLM-OUTPUT-AS-AMOUNT",
    severity: "high",
    title: "Model output may set an amount that is paid",
    fix: "Use the model only to read and explain. Take amounts from the ledger or a pure function, and check any model-read value against the record before paying.",
    test(f) {
      if (isTest(f.path) || !MONEY_CALL.test(f.text)) return [];
      const m = /\b(?:amount|transfer_amount|payment_amount)\s*:\s*(?:\w+\.)*(?:llm|model|completion|response|extract(?:ed)?|ai)\w*\.(?:amount|value|total)\b/i.exec(f.text);
      return m ? [{ index: m.index, detail: `"${m[0]}" passes a value read by the model straight into a payment field.` }] : [];
    },
  },
  {
    id: "LLM-CARD-DATA",
    severity: "high",
    title: "Card numbers may reach the model",
    fix: "Strip card numbers (13–19 digits) from text before any model call, and keep card data out of prompts and logs.",
    test(f) {
      if (isTest(f.path)) return [];
      const hits: { index: number; detail: string }[] = [];
      const strip = /\\d\{13,19\}|\(\?:\\d\[ -\]\?\)\{13,19\}|card number removed|redactPan|maskPan|stripCard/i;
      for (const m of f.text.matchAll(/\b(?:extract|complete|messages\.create|InvokeModel\w*|Converse\w*)\s*\(/g)) {
        const arg = f.text.slice(m.index!, m.index! + 500);
        const cardish = /\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b|card_?number|cardNumber|\bpan\b/i.test(arg);
        if (cardish && !strip.test(arg)) hits.push({ index: m.index!, detail: "Text passed to the model here can carry a card number, and nothing removes it first." });
      }
      return hits;
    },
  },
  {
    id: "CODE-TLS-DISABLED",
    severity: "high",
    title: "TLS certificate checks turned off",
    fix: "Remove the override; trust a specific CA bundle instead if a proxy needs it.",
    test(f) {
      const m = /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["'`]?0|rejectUnauthorized\s*:\s*false/.exec(f.text);
      return m ? [{ index: m.index, detail: `"${m[0]}" lets anyone in the network path read or change payment traffic.` }] : [];
    },
  },
  {
    id: "CODE-EVAL",
    severity: "critical",
    title: "Dynamic code execution",
    fix: "Remove eval/new Function; parse data with JSON.parse and a schema check.",
    test(f) {
      if (isTest(f.path)) return [];
      const m = /(?<![\w.$])(?:eval\s*\(|new\s+Function\s*\()/.exec(f.text);
      return m ? [{ index: m.index, detail: "If any part of the evaluated string comes from a model or a document, an attacker can run code inside the agent." }] : [];
    },
  },
];

export function scanCode(files: SourceFile[]): Finding[] {
  const out: Finding[] = [];
  for (const f of files) {
    for (const r of RULES) {
      for (const hit of r.test(f)) {
        out.push({ source: r.id.startsWith("LLM") ? "llm" : "code", rule: r.id, severity: r.severity, title: r.title, detail: hit.detail, fix: r.fix, where: `${f.path}:${lineOf(f.text, hit.index)}` });
      }
    }
  }
  return out;
}

/** Secret files committed to git are critical whatever their content. */
export function scanRepoHygiene(root: string): Finding[] {
  if (!existsSync(join(root, ".git"))) return [];
  let tracked: string[] = [];
  try { tracked = execFileSync("git", ["-C", root, "ls-files"], { encoding: "utf8" }).split("\n"); } catch { return []; }
  const bad = tracked.filter((p) => /(^|\/)(\.env(\.[a-z]+)?|id_rsa|.*\.pem|credentials(\.json)?|\.aws\/credentials)$/.test(p) && !/\.example$|\.sample$/.test(p));
  return bad.map((p) => ({
    source: "code" as const, rule: "CODE-SECRET-FILE", severity: "critical" as const,
    title: "Secret file committed to git", where: p,
    detail: `${p} is tracked by git, so anyone with the repository has it.`,
    fix: "Remove it from git history, add it to .gitignore, and rotate every key it held.",
  }));
}
