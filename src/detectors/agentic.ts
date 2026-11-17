/**
 * Agentic-AI checks for the OWASP risks the other detectors do not reach.
 *
 *  - LLM07 System Prompt Leakage: secrets, internal addresses or authorisation rules
 *    written into system prompts (anything in a prompt should be safe to leak).
 *  - LLM08 Vector and Embedding Weaknesses: retrieval without a tenant or metadata filter,
 *    and untrusted documents embedded without screening.
 *  - LLM04 Data and Model Poisoning / ASI06 Memory and Context Poisoning: planted
 *    instructions in the agent's prompt, policy, knowledge, memory and training files, and
 *    changes to them that are not in version control.
 *  - LLM09 Misinformation: model answers used without validation, and (at run time) model
 *    answers failing validation often enough that the agent is acting on bad facts.
 *  - ASI07 Insecure Inter-Agent Communication: an agent that pays whatever another agent's
 *    x402 offer asks, MCP servers reached without TLS or credentials, and A2A agent cards
 *    that advertise no authentication.
 */
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, relative, extname, basename } from "node:path";
import { execFileSync } from "node:child_process";
import type { Finding } from "../alerts.ts";
import type { SourceFile } from "./code-scan.ts";
import { SECRET_RULES } from "./secrets-history.ts";
import { hardenGuard, type Guard } from "./llm-probes.ts";

const isTest = (p: string) => /(\.test\.|\.spec\.|__tests__|(^|\/)test\/|(^|\/)fixtures?\b|fixtures\.)/.test(p);
const lineOf = (text: string, i: number) => text.slice(0, i).split("\n").length;
const flagged = (r: unknown) => (Array.isArray(r) ? r.length > 0 : Boolean(r));

// ---- LLM07: what is written into system prompts --------------------------------------------
const PROMPT_SITES = [
  /\bcomplete\w*\(\s*(["'`])([\s\S]{20,4000}?)\1\s*,/g,                         // complete("system", user)
  /\bsystem\s*:\s*(["'`])([\s\S]{20,4000}?)\1/g,                                // { system: "..." }
  /\b(?:const|let|var)\s+\w*(?:SYSTEM|PROMPT|INSTRUCTION)\w*\s*=\s*(["'`])([\s\S]{20,4000}?)\1/gi,
];
const INTERNAL = /https?:\/\/(localhost|127\.|10\.\d|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|[\w.-]+\.(internal|local|corp|lan)\b)[^\s"'`]*/i;
const AUTHZ = /\b(you (may|can|are allowed to|are authori[sz]ed to)|approve (any|all|up to|payments?)|auto-?approve|limit is|up to)\b[^.\n]{0,80}(\$|USD|EUR|GBP|\d{3,})/i;
const ACCOUNT = /\b(?:account|iban|routing|card)[^.\n]{0,20}?\b(\d{8,}|[A-Z]{2}\d{2}[A-Z0-9]{10,30})\b/i;

export function promptFindings(files: SourceFile[]): { findings: Finding[]; prompts: number } {
  const out: Finding[] = []; let prompts = 0;
  for (const f of files) {
    if (isTest(f.path)) continue;
    for (const re of PROMPT_SITES) for (const m of f.text.matchAll(re)) {
      const text = m[2]; if (/\$\{/.test(text) && text.replace(/\$\{[^}]*\}/g, "").length < 20) continue;
      prompts++;
      const where = `${f.path}:${lineOf(f.text, m.index!)}`;
      const secret = SECRET_RULES.map((r) => ({ r, hit: text.match(new RegExp(r.re.source, r.re.flags.replace("g", ""))) })).find((x) => x.hit);
      if (secret) out.push({ source: "llm", rule: "LLM-SYSPROMPT-SECRET", severity: "critical", where, key: `sysprompt:${where}:secret`,
        title: `A ${secret.r.what} is written into a system prompt`, detail: "Anything in a system prompt can be coaxed out of the model by a user or a planted instruction.", fix: "Move the credential to the code that calls the API; the model never needs it." });
      const internal = INTERNAL.exec(text);
      if (internal) out.push({ source: "llm", rule: "LLM-SYSPROMPT-INTERNAL", severity: "medium", where, key: `sysprompt:${where}:internal`,
        title: "A system prompt reveals an internal address", detail: `${internal[0]} is in the prompt. Leaked prompts map the network for an attacker.`, fix: "Keep internal hostnames and URLs out of prompts." });
      const acct = ACCOUNT.exec(text);
      if (acct) out.push({ source: "llm", rule: "LLM-SYSPROMPT-SECRET", severity: "high", where, key: `sysprompt:${where}:account`,
        title: "A system prompt contains an account number", detail: "Payment details in a prompt can leak, and invite the model to use them.", fix: "Look accounts up in code from records on file." });
      const authz = AUTHZ.exec(text);
      if (authz) out.push({ source: "llm", rule: "LLM-SYSPROMPT-AUTHZ", severity: "medium", where, key: `sysprompt:${where}:authz`,
        title: "A spending or approval rule lives in the system prompt", detail: `"${authz[0].slice(0, 90)}". The model can be talked out of a rule written in its prompt; code cannot.`, fix: "Enforce limits and approvals in code, and tell the model only what it needs to do its task." });
    }
  }
  return { findings: out, prompts };
}

// ---- LLM08: vector stores ---------------------------------------------------------------
const VECTOR_IMPORT = /from\s+["'](@pinecone-database\/pinecone|chromadb|@qdrant\/js-client-rest|weaviate-ts-client|weaviate-client|pgvector[^"']*|@zilliz\/milvus2-sdk-node|faiss-node|@langchain\/[\w-]+\/vectorstores[^"']*|@langchain\/community\/vectorstores[^"']*|langchain\/vectorstores[^"']*|@lancedb\/lancedb|vectordb|@upstash\/vector|@aws-sdk\/client-bedrock-agent-runtime)["']/;

export function vectorFindings(files: SourceFile[]): { findings: Finding[]; uses: number } {
  const out: Finding[] = []; let uses = 0;
  for (const f of files) {
    if (isTest(f.path) || !VECTOR_IMPORT.test(f.text)) continue;
    uses++;
    for (const m of f.text.matchAll(/\.(similaritySearch\w*|query|search|retrieve|Retrieve\w*)\s*\(([^;]{0,400}?)\)\s*[;\n]/g)) {
      if (/filter|namespace|where|tenant|metadata|partition|customer|accountId|orgId/i.test(m[2])) continue;
      const where = `${f.path}:${lineOf(f.text, m.index!)}`;
      out.push({ source: "llm", rule: "LLM-VECTOR-NO-FILTER", severity: "medium", where, key: `vec:${where}:filter`,
        title: "Retrieval has no tenant or metadata filter", detail: `${m[1]}(…) searches the whole store, so one customer's documents can surface in another customer's answer.`, fix: "Filter every query by tenant (namespace, metadata filter or a store per customer)." });
    }
    for (const m of f.text.matchAll(/\.(addDocuments|addTexts|upsert|add|insert|fromDocuments|fromTexts)\s*\(([^;]{0,400}?)\)/g)) {
      if (!/email|inbound|upload|document|attachment|user|message|webhook|scrape|crawl/i.test(m[2]) || /screen|sanitiz|clean|guard|validate/i.test(f.text.slice(Math.max(0, m.index! - 400), m.index!))) continue;
      const where = `${f.path}:${lineOf(f.text, m.index!)}`;
      out.push({ source: "llm", rule: "LLM-VECTOR-UNSCREENED", severity: "medium", where, key: `vec:${where}:ingest`,
        title: "Untrusted documents are embedded without screening", detail: "Text from outside goes into the knowledge store as-is; a planted instruction will be retrieved later as trusted context.", fix: "Screen documents with the injection guard before embedding, and store their source so answers can be traced." });
    }
  }
  return { findings: out, uses };
}

// ---- LLM04 / ASI06: instructions, knowledge, memory and training data ----------------------
const CONTEXT_NAME = /(prompt|instruction|policy|policies|knowledge|examples?|few[-_]?shot|memory|memories|context|persona|playbook|guideline)/i;
const CONTEXT_EXT = new Set([".md", ".txt", ".json", ".jsonl", ".yaml", ".yml", ".prompt"]);
const SKIP = new Set(["node_modules", ".git", "dist", "cdk.out", "coverage", "preview", "docs", "sandbox", "outbox"]);

function contextFiles(root: string, extra: string[]): string[] {
  const out: string[] = [];
  const walk = (d: string, inMemory: boolean) => {
    if (!existsSync(d)) return;
    for (const n of readdirSync(d)) {
      if (SKIP.has(n)) continue;
      const p = join(d, n); let st; try { st = statSync(p); } catch { continue; }
      if (st.isDirectory()) walk(p, inMemory || /^(memory|memories|\.memory|knowledge|prompts?)$/i.test(n));
      else if (CONTEXT_EXT.has(extname(n)) && st.size < 2_000_000 && !/package(-lock)?\.json|tsconfig|\.eslintrc|README/i.test(n) && (inMemory || CONTEXT_NAME.test(n)) && !isTest(relative(root, p))) out.push(p);
    }
  };
  walk(root, false);
  for (const d of extra) walk(d, true);
  return [...new Set(out)];
}

export function contextFindings(root: string, guard: Guard | null, memoryDirs: string[] = []): { findings: Finding[]; files: number } {
  const out: Finding[] = [];
  const files = contextFiles(root, memoryDirs);
  const screen = guard ? hardenGuard(guard) : null;
  let dirty = new Set<string>();
  if (existsSync(join(root, ".git")) && files.length) {
    try {
      const st = execFileSync("git", ["status", "--porcelain", "--", ...files.map((f) => relative(root, f)).filter((f) => !f.startsWith(".."))], { cwd: root, encoding: "utf8" });
      dirty = new Set(st.split("\n").filter(Boolean).map((l) => l.slice(3).trim()));
    } catch { /* not fatal */ }
  }
  for (const p of files) {
    const rel = relative(root, p).startsWith("..") ? p : relative(root, p);
    const text = readFileSync(p, "utf8");
    const training = extname(p) === ".jsonl" && /"(messages|prompt|completion|instruction|output)"\s*:/.test(text.slice(0, 2000));
    if (dirty.has(rel)) out.push({ source: "llm", rule: "LLM-CONTEXT-UNTRACKED-CHANGE", severity: "medium", where: rel, key: `ctx:${rel}:dirty`,
      title: `Agent ${training ? "training data" : "instructions or knowledge"} changed outside version control: ${basename(p)}`,
      detail: "This file shapes what the agent believes or does, and it differs from the last reviewed commit.", fix: "Review the change, commit it through a pull request, or restore the committed version." });
    if (!screen) continue;
    const chunks = training ? text.split("\n").filter((l) => l.trim()) : text.split(/\n{2,}/);
    const hits = chunks.map((c, i) => ({ c, i })).filter(({ c }) => c.length < 20_000 && flagged(screen(c)));
    if (hits.length) out.push({ source: "llm", rule: training ? "LLM-TRAINING-POISONED" : "LLM-CONTEXT-POISONED", severity: "high", where: rel, key: `ctx:${rel}:poison`,
      title: `${hits.length} planted instruction${hits.length === 1 ? "" : "s"} in ${training ? "training data" : "agent memory or knowledge"}: ${basename(p)}`,
      detail: `First: "${hits[0].c.replace(/\s+/g, " ").trim().slice(0, 140)}". The agent reads this as trusted context, so the instruction persists across every run.`,
      fix: training ? "Remove the poisoned examples, retrain from a reviewed dataset, and screen new examples before they are added." : "Remove the entry, find how it got in (the source document or conversation), and screen what is written to memory." });
  }
  return { findings: out, files: files.length };
}

// ---- LLM09: model answers used without checks ----------------------------------------------
export function validationFindings(files: SourceFile[]): Finding[] {
  const out: Finding[] = [];
  for (const f of files) {
    if (isTest(f.path)) continue;
    for (const m of f.text.matchAll(/\bextract\w*\([^;]*?,\s*(\(\s*\w*\s*(?::\s*\w+)?\s*\)\s*(?::\s*\w+\s+is\s+\w+)?\s*=>\s*true)\s*[,)]/g)) {
      const where = `${f.path}:${lineOf(f.text, m.index!)}`;
      out.push({ source: "llm", rule: "LLM-UNVALIDATED-OUTPUT", severity: "medium", where, key: `misinfo:${where}`,
        title: "Model output is accepted without validation", detail: `The validator is ${m[1]}, so whatever the model states (amounts, dates, names) is taken as fact.`, fix: "Validate types and ranges, and cross-check figures against records before acting on them." });
    }
  }
  return out;
}

/** Run-time LLM09: how often model answers fail validation, per agent run. */
export class MisinfoMonitor {
  private runs = new Map<string, { ok: number; bad: number }>();
  ingest(e: { kind?: string; task?: string }, run: string): Finding[] {
    if (e.kind !== "llm_extract" && e.kind !== "llm_extract_rejected") return [];
    const r = this.runs.get(run) ?? { ok: 0, bad: 0 }; this.runs.set(run, r);
    e.kind === "llm_extract" ? r.ok++ : r.bad++;
    const total = r.ok + r.bad;
    if (r.bad >= 2 && r.bad / total >= 0.25)
      return [{ source: "llm", rule: "LLM-MISINFO", severity: r.bad / total >= 0.5 ? "high" : "medium", where: `run ${run}`, key: `misinfo:${run}`,
        title: `${r.bad} of ${total} model answers failed validation in this run`, detail: `The model is stating facts the checks reject (last task: ${e.task ?? "?"}). If the fallback rules were not there, the agent would act on them.`,
        fix: "Check the input documents for quality or tampering, and the model or prompt for a regression; keep the deterministic fallback on." }];
    return [];
  }
}

// ---- ASI07: talking to and paying other agents ---------------------------------------------
function callArgs(text: string, start: number): string[] | null {
  let depth = 0, cur = "", args: string[] = [], quote = "";
  for (let i = start; i < text.length && i < start + 3000; i++) {
    const c = text[i];
    if (quote) { cur += c; if (c === quote && text[i - 1] !== "\\") quote = ""; continue; }
    if (c === '"' || c === "'" || c === "`") { quote = c; cur += c; continue; }
    if ("([{".includes(c)) { depth++; if (depth === 1 && c === "(") continue; }
    if (")]}".includes(c)) { depth--; if (depth === 0) { if (cur.trim()) args.push(cur.trim()); return args; } }
    if (c === "," && depth === 1) { args.push(cur.trim()); cur = ""; continue; }
    if (depth >= 1) cur += c;
  }
  return null;
}

export function interAgentFindings(root: string, files: SourceFile[]): { findings: Finding[]; payCalls: number; guarded: number } {
  const out: Finding[] = []; let payCalls = 0, guarded = 0;
  for (const f of files) {
    if (isTest(f.path)) continue;
    for (const m of f.text.matchAll(/\bpayFetch\s*(?:<[^>]*>)?\s*\(/g)) {
      if (/function\s+payFetch/.test(f.text.slice(Math.max(0, m.index! - 20), m.index! + 20))) continue;
      const args = callArgs(f.text, m.index! + m[0].length - 1); if (!args) continue;
      payCalls++;
      if (args.length >= 3 && args[2] && args[2] !== "undefined") { guarded++; continue; }
      const where = `${f.path}:${lineOf(f.text, m.index!)}`;
      const capped = /\b(clearingPayment|exactPayment)\s*\(/.test(args[1] ?? "");
      out.push({ source: "code", rule: "AGENT-X402-NO-LIMIT", severity: capped ? "low" : "medium", where, key: `a2a:${where}:x402`,
        title: "This agent pays whatever the other agent's x402 offer asks",
        detail: `payFetch is called without a guard, so the price and payee come from the seller's 402 response unchecked.${capped ? " The on-chain mandate or clearing deposit caps the total loss, but within that cap a compromised seller agent sets its own price and payee." : " A compromised or malicious seller agent sets its own price."}`,
        fix: "Pass a guard that checks the payee against the expected seller and the price against a per-call cap." });
    }
  }
  const walk = (d: string): string[] => existsSync(d) ? readdirSync(d).flatMap((n) => { if (SKIP.has(n) && n !== "docs") return []; const p = join(d, n); try { return statSync(p).isDirectory() ? walk(p) : [p]; } catch { return []; } }) : [];
  for (const p of walk(root)) {
    const n = basename(p), rel = relative(root, p);
    if (/^\.?mcp(\.[\w-]+)?\.json$|^mcp[-_]?(config|servers)\.json$/i.test(n)) {
      let cfg: any; try { cfg = JSON.parse(readFileSync(p, "utf8")); } catch { continue; }
      for (const [name, sv] of Object.entries<any>(cfg.mcpServers ?? cfg.servers ?? {})) {
        const url: string = sv.url ?? sv.serverUrl ?? "";
        const local = /^https?:\/\/(localhost|127\.)/.test(url);
        if (url && url.startsWith("http://") && !local) out.push({ source: "code", rule: "AGENT-MCP-INSECURE", severity: "high", where: rel, key: `mcp:${rel}:${name}:tls`,
          title: `MCP server "${name}" is reached over plain HTTP`, detail: `${url}: tool calls and results can be read or changed on the way.`, fix: "Use https:// for every remote MCP server." });
        else if (url && !local && !sv.headers?.Authorization && !sv.headers?.authorization && !sv.auth && !sv.oauth && !JSON.stringify(sv).match(/token|api[-_]?key|bearer/i)) out.push({ source: "code", rule: "AGENT-MCP-NO-AUTH", severity: "medium", where: rel, key: `mcp:${rel}:${name}:auth`,
          title: `MCP server "${name}" is used without credentials`, detail: `${url} accepts the agent with no token, so anything that can reach it can impersonate the agent's tools.`, fix: "Require OAuth or a token for the MCP server, and pin which tools the agent may call." });
        const cmd = [sv.command, ...(sv.args ?? [])].join(" ");
        if (/\bnpx\b/.test(cmd) && !/@\d/.test(cmd)) out.push({ source: "code", rule: "AGENT-MCP-UNPINNED", severity: "low", where: rel, key: `mcp:${rel}:${name}:pin`,
          title: `MCP server "${name}" runs an unpinned package`, detail: `"${cmd.slice(0, 100)}" fetches the latest version on every start, so a hijacked release runs with the agent's access.`, fix: "Pin the package version (name@x.y.z)." });
      }
    }
    if (/^(agent|agent-card)\.json$/i.test(n) && /well-known/.test(rel)) {
      let card: any; try { card = JSON.parse(readFileSync(p, "utf8")); } catch { continue; }
      if (!card.securitySchemes && !card.authentication && !card.security) out.push({ source: "code", rule: "AGENT-A2A-NO-AUTH", severity: "medium", where: rel, key: `a2a:${rel}:card`,
        title: `Agent card "${card.name ?? n}" advertises no authentication`, detail: "Other agents are told they can call this agent without credentials.", fix: "Declare securitySchemes in the agent card and enforce them on every A2A request." });
    }
  }
  return { findings: out, payCalls, guarded };
}

/** All static agentic checks, with what passed. */
export function scanAgentic(root: string, files: SourceFile[], guard: Guard | null, memoryDirs: string[] = []) {
  const p = promptFindings(files), v = vectorFindings(files), c = contextFindings(root, guard, memoryDirs), m = validationFindings(files), a = interAgentFindings(root, files);
  const findings = [...p.findings, ...v.findings, ...c.findings, ...m, ...a.findings];
  const has = (prefix: string) => findings.some((f) => f.rule.startsWith(prefix));
  const passed = [
    ...(has("LLM-SYSPROMPT") ? [] : [`${p.prompts} system prompt${p.prompts === 1 ? "" : "s"}: no secrets, internal addresses or approval rules (LLM07)`]),
    ...(v.uses ? (has("LLM-VECTOR") ? [] : [`${v.uses} vector-store file${v.uses === 1 ? "" : "s"} filter by tenant and screen input (LLM08)`]) : ["No vector store or embeddings in use (LLM08 does not apply)"]),
    ...(has("LLM-CONTEXT") || has("LLM-TRAINING") ? [] : [c.files ? `${c.files} instruction, knowledge or memory file${c.files === 1 ? "" : "s"}: committed, no planted instructions (LLM04, ASI06)` : "No prompt, knowledge, memory or training files to poison; set MEMORY_DIRS if the agent keeps memory (LLM04, ASI06)"]),
    ...(has("LLM-UNVALIDATED") ? [] : ["Every model extraction has a validator (LLM09)"]),
    ...(has("AGENT-") ? [] : [`${a.payCalls} x402 payment call${a.payCalls === 1 ? "" : "s"} guarded; no insecure MCP or A2A config (ASI07)`]),
  ];
  return { findings, passed, stats: { prompts: p.prompts, vectorFiles: v.uses, contextFiles: c.files, payCalls: a.payCalls, guardedPayCalls: a.guarded } };
}
