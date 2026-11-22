/**
 * Agent Shield server: runs the scan, the live monitors and the dashboard.
 *
 *   GET  /                    dashboard
 *   GET  /api/state           alerts, counts, scan summary, monitor status
 *   GET  /api/stream          live events (Server-Sent Events): alert, ack, emailed, activity
 *   POST /api/scan            re-scan the target code
 *   POST /api/scan/:kind      code | website | system | deps | supply | secrets | fuzz | malware | leak | outdated | cloud | model   ({"url", "authorised"} for website)
 *   POST /api/autoscan        {"enabled": true|false} turn automatic follow-up scans on or off
 *   POST /api/ack             {"id"} acknowledge an alert
 *   POST /api/simulate/:what  ransomware | finance | artex | reset  (sandbox drills)
 *
 * It listens on 127.0.0.1 by default. With SHIELD_TOKEN set, every /api call needs
 * "Authorization: Bearer <token>" (the dashboard asks for it once): a security tool
 * should not be the easiest thing on the network to reach.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync, mkdirSync } from "node:fs";
import { join, basename } from "node:path";
import { timingSafeEqual } from "node:crypto";
import { AlertBus, fingerprint, type Alert, type Finding } from "./alerts.ts";
import { attachEmail, emailConfigFromEnv } from "./notify/email.ts";
import { scanTarget, targetFromEnv, loadGuard, type ScanReport } from "./scan.ts";
import { watchFolder } from "./detectors/ransomware.ts";
import { tailRuns } from "./tail.ts";
import { SANDBOX, seedWatched, simulateFinance, simulateRansomware, resetSandbox, simulateArtex } from "./simulate.ts";
import { feedCloud, pollCloudTrailLive, huntFolders } from "./cloud-feed.ts";
import { scanWebsite, allowedHosts } from "./detectors/web-scan.ts";
import { scanSystem, scanDependencies } from "./detectors/system-scan.ts";
import { runPromptfoo, redteamFindings, redteamReady, parsePromptfoo, RESULTS, type RedteamReport } from "./integrations/promptfoo.ts";
import { garakFindings, parseGarakReport } from "./integrations/garak.ts";
import { existsSync, readdirSync, statSync, openSync, readSync, closeSync } from "node:fs";
import { PaymentLedger, verifyAirwallexSignature, type WebhookEvent } from "./detectors/reconcile.ts";
import { runSemgrep, semgrepAvailable } from "./integrations/semgrep.ts";
import { promptGuardReady, runPromptGuard, promptGuardSummary, promptGuardFindings } from "./integrations/prompt-guard.ts";
import { FalcoFeed, type FalcoAlert } from "./integrations/falco.ts";
import { replayCoverage } from "./integrations/stratus.ts";
import { attachChannels, channelsFromEnv, enabledChannels } from "./notify/channels.ts";
import { simulateStratus, simulateUnloggedTransfer, simulateMalware, simulateLeak } from "./simulate.ts";
import { createHmac, randomBytes } from "node:crypto";
import { scanSupplyChain, sbom } from "./detectors/supply-chain.ts";
import { scanAgentic, MisinfoMonitor } from "./detectors/agentic.ts";
import { loadSources } from "./detectors/code-scan.ts";
import { scanSecretsHistory } from "./detectors/secrets-history.ts";
import { fuzzGuard, fuzzFindings } from "./detectors/fuzz.ts";
import { hardenGuard } from "./detectors/llm-probes.ts";
import { prioritise } from "./integrations/vuln-intel.ts";
import { runOsvScanner, osvScannerVersion } from "./integrations/osv-scanner.ts";
import { coverage, refLabel, NAMES as REF_NAMES } from "./frameworks.ts";
import { loadSecureHeaders, zapFindings, zapBaseline, runDependencyCheck, dependencyCheckFindings, dependencyCheckVersion, uploadToDependencyTrack, toDefectDojo, pushToDefectDojo, type SecureHeaderLists } from "./integrations/owasp.ts";
import { writeFileSync as writeFile, readFileSync as readFile, mkdirSync as mkdirp } from "node:fs";
import { scanMalware, scanFile, loadHashList } from "./detectors/malware.ts";
import { scanLeaks, leaksInText } from "./detectors/leak.ts";
import { scanOutdated } from "./detectors/outdated.ts";
import { AutoScanner, CATEGORY_LABEL, type AutoKind, type Round } from "./autoscan.ts";

const PORT = Number(process.env.PORT ?? 4600);
const HOST = process.env.HOST ?? "127.0.0.1";
const TOKEN = process.env.SHIELD_TOKEN ?? "";
const target = targetFromEnv();
const watchDir = process.env.WATCH_DIR ?? seedWatched();
const demoRuns = join(SANDBOX, "runs");
mkdirSync(demoRuns, { recursive: true });

const STATE = join(process.cwd(), "state");
const bus = new AlertBus(STATE);
const emailCfg = emailConfigFromEnv();
attachEmail(bus, emailCfg);
const channelCfg = channelsFromEnv();
attachChannels(bus, channelCfg);

let lastScan: ScanReport | null = null;
let redteam: (RedteamReport & { running?: boolean }) | null = existsSync(RESULTS) ? parsePromptfoo(readFileSync(RESULTS, "utf8")) : null;
let redteamRunning = false;
const garakRuns: { file: string; model?: string; probes: number; failed: number; at: string }[] = [];
const garakDir = join(process.cwd(), "state", "garak");
mkdirSync(garakDir, { recursive: true });
const activity = { cloudEvents: 0, egressEvents: 0, eventsRead: 0, runsSeen: new Set<string>(), fileWatch: watchDir, logFolders: [target.runs, demoRuns], startedAt: new Date().toISOString(), emails: [] as unknown[] };

// ---- integrations state ------------------------------------------------------------
const integ = {
  semgrep: semgrepAvailable(), semgrepLast: null as null | { at: string; findings: number; error?: string },
  promptGuard: null as null | { at: string; caught: number; attacks: number; falsePositives: number; missed: string[]; error?: string },
  falcoDirs: [process.env.FALCO_DIR ?? join(process.cwd(), "logs", "falco"), join(SANDBOX, "falco")],
  webhookSecret: Boolean(process.env.AIRWALLEX_WEBHOOK_SECRET), webhooksReceived: 0, webhooksRejected: 0,
  coverage: replayCoverage(),
  notified: 0, notifyErrors: [] as unknown[],
};

// ---- live stream -------------------------------------------------------------
const clients = new Set<ServerResponse>();
const push = (type: string, data: unknown) => {
  const msg = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const c of clients) c.write(msg);
};
bus.on("alert", (a: Alert) => push("alert", a));
bus.on("ack", (a: Alert) => push("ack", a));
bus.on("update", (a: Alert) => push("update", a));
bus.on("emailed", (e) => { activity.emails.unshift({ ...e, at: new Date().toISOString() }); activity.emails.length = Math.min(activity.emails.length, 20); push("emailed", e); });
bus.on("email_error", (e) => push("email_error", e));
bus.on("notified", (e) => { integ.notified++; push("notified", e); });
bus.on("notify_error", (e) => { integ.notifyErrors.unshift({ ...e, at: new Date().toISOString() }); integ.notifyErrors.length = Math.min(integ.notifyErrors.length, 5); push("notify_error", e); });
setInterval(() => push("activity", status()), 2000);

const raise = (fs: Finding[]) => bus.raiseAll(fs);

// ---- automatic scans: an intrusion, malware, leak or old-vulnerability alert starts follow-up scans ----
let raisingScan: string | null = null; // which scan is raising findings right now (null: a live monitor)
const auto = new AutoScanner({ enabled: process.env.AUTO_SCAN !== "0", cooldownMs: Number(process.env.AUTO_SCAN_COOLDOWN_MIN ?? 10) * 60_000, minGapMs: Number(process.env.AUTO_SCAN_MIN_GAP_S ?? 20) * 1000, graceMs: Number(process.env.AUTO_SCAN_GRACE_S ?? 30) * 1000 });
let autoTimer: NodeJS.Timeout | null = null;
let autoQueue: Promise<void> = Promise.resolve();
function startRound(r: Round | null) {
  if (!r) return;
  push("autoscan", r); push("auto_state", auto.state());
  const why = r.reason === "schedule" ? "Scheduled re-check" : `${CATEGORY_LABEL[r.triggers[0].category]}: ${r.triggers[0].title}${r.triggers.length > 1 ? ` (+${r.triggers.length - 1} more)` : ""}`;
  // one scan at a time, so an incident never floods the machine
  for (const k of r.kinds) autoQueue = autoQueue.then(() => runKind(k as Kind, { trigger: why })).catch(() => {});
}
const considerAlert = (a: Alert) => {
  if (!auto.consider(a, Date.now(), raisingScan ?? "live").length || autoTimer) return;
  autoTimer = setTimeout(flushAuto, Number(process.env.AUTO_SCAN_BATCH_MS ?? 4000));
};
function flushAuto() {
  autoTimer = null;
  startRound(auto.flush((k) => scans[k as Kind]?.running));
  const d = auto.retryDelay();
  if (d !== null && !autoTimer) autoTimer = setTimeout(flushAuto, d);
}
bus.on("alert", considerAlert);
bus.on("update", considerAlert);
setInterval(() => startRound(auto.due((k) => scans[k as Kind]?.running)), Number(process.env.AUTO_SCAN_SCHEDULE_CHECK_MS ?? 5 * 60_000));

async function runScan() {
  lastScan = await scanTarget(target);
  raise(lastScan.findings);
  push("scan", scanSummary());
  return scanSummary();
}

function scanSummary() {
  if (!lastScan) return null;
  return { at: lastScan.at, target: lastScan.target.name, dir: lastScan.target.dir, files: lastScan.files, findings: lastScan.findings.length, probes: lastScan.probes ?? null, passed: passedChecks(lastScan) };
}

const CHECKS: [string, string][] = [
  ["CODE-SECRET", "No secrets written in code"], ["CODE-SECRET-FILE", "No secret files committed to git"],
  ["CODE-MONEY-NO-APPROVAL", "Every money-moving call sits behind an approval"], ["CODE-MONEY-NO-IDEMPOTENCY", "Payment calls carry idempotency keys"],
  ["LLM-UNFENCED-INPUT", "Outside text is fenced as data before the model sees it"], ["LLM-OUTPUT-AS-AMOUNT", "Model output never sets a paid amount"],
  ["LLM-CARD-DATA", "Card numbers are removed before the model reads"], ["CODE-TLS-DISABLED", "TLS checks stay on"], ["CODE-EVAL", "No dynamic code execution"],
  ["ACC-IAM-ALL-ACTIONS", "No cloud role can do everything"], ["ACC-IAM-ALL-RESOURCES", "Write permissions are scoped to resources"],
  ["ACC-PUBLIC-BUCKET", "No public storage buckets"], ["ACC-CORS-ALL", "APIs accept browser calls only from known origins"],
  ["ACC-ROUTE-NO-AUTH", "Routes that change things check the caller"], ["ACC-APPROVER-FROM-INPUT", "Approver comes from a verified login"],
  ["ACC-NO-SEPARATION", "The agent cannot approve its own action"],
];
const passedChecks = (r: ScanReport) => CHECKS.filter(([id]) => !r.findings.some((f) => f.rule === id)).map(([, label]) => label);

function status() {
  return { cloudEvents: activity.cloudEvents, egressEvents: activity.egressEvents, cloudDirs: cloudtrailDirs, egressDirs, liveCloudTrail, eventsRead: activity.eventsRead, runsSeen: activity.runsSeen.size, fileWatch: activity.fileWatch, logFolders: activity.logFolders, counts: bus.counts(), clients: clients.size, integrations: integrations() };
}

const dcInstalled = Boolean(dependencyCheckVersion());
function frameworks() {
  const rules = [...new Set(["MAL-REVERSE-SHELL","MAL-WEBSHELL","MAL-MINER","MAL-OBFUSCATED-EXEC","MAL-DROPPER","MAL-CREDENTIAL-STEALER","MAL-HIDDEN-EXECUTABLE","MAL-KNOWN-HASH","LEAK-CARD-NUMBER","LEAK-SECRET-IN-LOGS","LEAK-BULK-PII","LEAK-SENSITIVE-FILE-TRACKED","OLD-DEPRECATED","OLD-MAJOR-BEHIND","OLD-UNMAINTAINED","OLD-RUNTIME","OLD-BASE-IMAGE","OLD-CLOUD-RUNTIME","OLD-OS-EOL","ACC-APPROVER-FROM-INPUT","ACC-SELF-APPROVAL","ACC-IAM-ALL-ACTIONS","CODE-EVAL","CODE-MONEY-NO-APPROVAL","CODE-MONEY-NO-IDEMPOTENCY","CODE-SECRET","FIN-UNLOGGED-TRANSFER","FIN-WEBHOOK-REJECTED","FUZZ-GUARD-BYPASS","FUZZ-GUARD-REDOS","FUZZ-GUARD-CRASH","LLM-CARD-DATA","LLM-OUTPUT-AS-AMOUNT","LLM-UNFENCED-INPUT","LLM-PROBE-FALSE-POSITIVE","SEMGREP-AGENT-MODEL-OUTPUT-TO-PAYMENT","SUPPLY-SIGNATURE-INVALID","SYS-VULN-DEPENDENCY","ID-LOG-TAMPER","RANSOM-NOTE","WEB-NO-CSP","LLM-SYSPROMPT-SECRET","LLM-VECTOR-NO-FILTER","LLM-CONTEXT-POISONED","LLM-TRAINING-POISONED","LLM-MISINFO","LLM-UNVALIDATED-OUTPUT","AGENT-X402-NO-LIMIT","AGENT-MCP-NO-AUTH","AGENT-A2A-NO-AUTH","ID-LLMJACKING","ID-S3-SSEC-ENCRYPT", ...bus.list().map((a) => a.rule)])];
  const open = bus.list().filter((a) => !a.acknowledged);
  const byRef: Record<string, number> = {};
  for (const a of open) for (const r of (a as any).refs ?? []) byRef[r] = (byRef[r] ?? 0) + 1;
  return { coverage: coverage(rules), open: Object.entries(byRef).sort((a, b) => b[1] - a[1]).map(([id, n]) => ({ ...refLabel(id), alerts: n })) };
}

function integrations() {
  const cov = integ.coverage;
  return {
    semgrep: { on: Boolean(integ.semgrep), version: integ.semgrep, last: integ.semgrepLast },
    promptGuard: { on: promptGuardReady(), last: integ.promptGuard },
    falco: { on: true, received: falco.received, dirs: integ.falcoDirs },
    airwallex: { on: integ.webhookSecret, received: integ.webhooksReceived, rejected: integ.webhooksRejected, ...ledger.stats() },
    stratus: { covered: cov.filter((c) => c.pass).length, total: cov.length, gaps: cov.filter((c) => c.covered === "no").map((c) => c.id), failing: cov.filter((c) => c.covered === "yes" && !c.pass).map((c) => c.id) },
    channels: { enabled: enabledChannels(channelCfg), sent: integ.notified, errors: integ.notifyErrors },
    intel: intel ?? { sources: { kev: "unused", osv: "unused", epss: "unused" }, osvScanner: osvScannerVersion() },
    frameworks: frameworks().coverage,
    owasp: { ...owaspState, zapApi: Boolean(process.env.ZAP_API_URL), dependencyCheckInstalled: dcInstalled, dependencyTrackOn: Boolean(process.env.DTRACK_URL && process.env.DTRACK_API_KEY), defectDojoOn: Boolean(process.env.DEFECTDOJO_URL && process.env.DEFECTDOJO_TOKEN) },
  };
}

// ---- model red-team (promptfoo) and garak reports ------------------------------
async function runRedteam() {
  if (redteamRunning) return;
  redteamRunning = true; push("redteam", redteamSummary());
  try { redteam = await runPromptfoo(); raise(redteamFindings(redteam)); }
  catch (e) { push("error", { error: (e as Error).message }); }
  finally { redteamRunning = false; push("redteam", redteamSummary()); }
}
function redteamSummary() {
  return { ready: redteamReady(), running: redteamRunning, mock: Boolean(process.env.SHIELD_REDTEAM_MOCK),
    last: redteam && { at: redteam.at, provider: redteam.provider, passed: redteam.passed, failed: redteam.failed, errors: redteam.errors, cases: redteam.cases.map((c) => ({ d: c.description, f: c.family, ok: c.passed, why: c.error ?? c.reasons.join("; ") })) },
    garak: garakRuns.slice(0, 5) };
}
// garak reports dropped into state/garak/ are imported automatically
const seenGarak = new Set<string>();
setInterval(() => {
  for (const name of readdirSync(garakDir)) {
    if (!name.endsWith(".jsonl") || seenGarak.has(name)) continue;
    const p = join(garakDir, name);
    if (Date.now() - statSync(p).mtimeMs < 2000) continue; // still being written
    seenGarak.add(name);
    const text = readFileSync(p, "utf8");
    const { model, results } = parseGarakReport(text);
    const fs = garakFindings(text, name);
    garakRuns.unshift({ file: name, model, probes: results.length, failed: fs.length, at: new Date().toISOString() });
    raise(fs); push("redteam", redteamSummary());
  }
}, 2000);

// ---- one-click scans -----------------------------------------------------------
type Kind = "code" | "website" | "system" | "deps" | "supply" | "secrets" | "fuzz" | "malware" | "leak" | "outdated" | "cloud" | "model";
interface ScanState { running: boolean; trigger?: string; startedAt?: string; ids?: string[]; at?: string; summary?: string; issues?: number; worst?: string; error?: string; passed?: string[]; detail?: Record<string, unknown> }
const scans: Record<Kind, ScanState> = { code: { running: false }, website: { running: false }, system: { running: false }, deps: { running: false }, supply: { running: false }, secrets: { running: false }, fuzz: { running: false }, malware: { running: false }, leak: { running: false }, outdated: { running: false }, cloud: { running: false }, model: { running: false } };
const DEFAULT_WEBSITE = process.env.WEBSITE_URL ?? "https://d1zoxhgak5pvwd.cloudfront.net/";
const worstOf = (fs: Finding[]) => ["critical", "high", "medium", "low", "info"].find((s) => fs.some((f) => f.severity === s)) ?? "none";

async function runKind(kind: Kind, opts: { url?: string; authorised?: boolean; trigger?: string } = {}) {
  const st = scans[kind];
  if (st.running) return;
  auto.ran(kind);
  st.running = true; st.trigger = opts.trigger; st.startedAt = new Date().toISOString(); st.error = undefined; push("scans", scanStates());
  try {
    let fs: Finding[] = [];
    if (kind === "code") {
      await runScan(); fs = lastScan!.findings;
      const extra: string[] = [];
      const ag = scanAgentic(target.dir, loadSources(target.dir), await loadGuard(target), (process.env.MEMORY_DIRS ?? "").split(",").filter(Boolean));
      fs = [...fs, ...ag.findings];
      const sg = await runSemgrep(target.dir);
      integ.semgrep = sg.version; integ.semgrepLast = { at: new Date().toISOString(), findings: sg.findings.length, error: sg.error };
      fs = [...fs, ...sg.findings];
      extra.push(sg.version ? `Semgrep taint: ${sg.findings.length} flow${sg.findings.length === 1 ? "" : "s"}` : "Semgrep not installed");
      if (promptGuardReady()) {
        try {
          const r = await runPromptGuard(); const sum = promptGuardSummary(r);
          integ.promptGuard = { at: new Date().toISOString(), ...sum };
          fs = [...fs, ...promptGuardFindings(r, process.env.PROMPT_GUARD_URL!)];
          extra.push(`Prompt Guard 2: ${sum.caught}/${sum.attacks} attacks`);
        } catch (e) { integ.promptGuard = { at: new Date().toISOString(), caught: 0, attacks: 0, falsePositives: 0, missed: [], error: (e as Error).message }; extra.push("Prompt Guard 2 unreachable"); }
      }
      Object.assign(st, { summary: `${lastScan!.files} source files checked · ${extra.join(" · ")}`, passed: [...passedChecks(lastScan!), ...ag.passed, ...(sg.version && !sg.findings.some((f) => f.severity !== "low") ? ["No untrusted text or model output reaches a payment unapproved (Semgrep taint)"] : [])] });
    } else if (kind === "website") {
      const shp = await loadSecureHeaders(join(STATE, "intel"));
      owaspState.secureHeaders = { source: shp.source, updated: shp.updated, remove: shp.remove.length, add: shp.add.length };
      const r = await scanWebsite(opts.url || DEFAULT_WEBSITE, { authorised: opts.authorised, secureHeaders: shp });
      fs = r.findings;
      if (process.env.ZAP_API_URL) {
        try { const rep = await zapBaseline(r.url); mkdirp(join(STATE, "zap"), { recursive: true }); writeFile(join(STATE, "zap", `baseline-${Date.now()}.json`), rep); const z = zapFindings(rep); fs = [...fs, ...z]; owaspState.zap = { mode: "api", at: new Date().toISOString(), alerts: z.length }; }
        catch (e) { owaspState.zap = { mode: "api", error: (e as Error).message }; }
      } Object.assign(st, { summary: `${new URL(r.url).host} · ${r.requests} read-only requests`, passed: r.passed, detail: { url: r.url } });
    } else if (kind === "system") {
      const r = scanSystem({ targetDir: target.dir, watchDirs: [watchDir] });
      fs = r.findings; Object.assign(st, { summary: `${r.host} · ${r.listening.length} listening service${r.listening.length === 1 ? "" : "s"} checked`, passed: r.passed, detail: { listening: r.listening } });
    } else if (kind === "deps") {
      const [a, b, o] = await Promise.all([scanDependencies(target.dir), scanDependencies(process.cwd()), runOsvScanner(target.dir)]);
      const dc = process.env.DEPENDENCY_CHECK === "1" ? await runDependencyCheck(target.dir, join(STATE, "dependency-check-run")) : { findings: [] as Finding[] };
      if (process.env.DEPENDENCY_CHECK === "1") owaspState.dependencyCheck = { mode: "run", findings: dc.findings.length, error: (dc as { error?: string }).error, at: new Date().toISOString() };
      const p = await prioritise([...a.findings, ...b.findings, ...o.findings, ...dc.findings], join(STATE, "intel"));
      intel = { at: new Date().toISOString(), sources: p.intel.sources, kevVersion: p.intel.kevVersion, kevSize: p.intel.kev.size, exploited: p.exploited, likely: p.likely, osvScanner: o.version };
      fs = p.findings;
      const prio = p.exploited ? ` · ${p.exploited} known exploited (CISA KEV)` : p.intel.sources.kev === "ok" && p.intel.sources.osv === "ok" ? " · none in CISA KEV" : p.intel.sources.osv === "unreachable" ? " · KEV check needs OSV (unreachable)" : "";
      Object.assign(st, { summary: `Agent Desk: ${a.summary.toLowerCase()} · Agent Shield: ${b.summary.toLowerCase()}${o.version ? ` · OSV-Scanner: ${o.findings.length}` : ""}${prio}`, passed: p.exploited ? [] : p.intel.sources.osv === "ok" ? ["No advisory is in CISA's Known Exploited list"] : [], detail: { agent: a.counts, shield: b.counts } });
    } else if (kind === "supply") {
      const r = await scanSupplyChain(target.dir);
      const b = await sbom(target.dir);
      if (b.json) { mkdirp(join(STATE, "sbom"), { recursive: true }); writeFile(join(STATE, "sbom", "agent.cdx.json"), b.json); }
      if (b.json && process.env.DTRACK_URL) {
        try { const u = await uploadToDependencyTrack(b.json); owaspState.dependencyTrack = { at: new Date().toISOString(), ok: true, token: u.token }; }
        catch (e) { owaspState.dependencyTrack = { at: new Date().toISOString(), ok: false, error: (e as Error).message }; }
      }
      fs = r.findings; Object.assign(st, { summary: `${r.summary}${b.components ? ` · SBOM: ${b.components} components` : ""}`, passed: r.passed, detail: { sbom: Boolean(b.json), components: b.components } });
    } else if (kind === "secrets") {
      const r = await scanSecretsHistory(target.dir);
      fs = r.findings; Object.assign(st, { summary: r.summary, passed: r.passed });
    } else if (kind === "fuzz") {
      const guard = await loadGuard(target);
      if (!guard) throw new Error(`Could not load the agent's guard (${target.guard})`);
      const r = fuzzGuard(guard), h = fuzzGuard(hardenGuard(guard));
      fs = fuzzFindings(r, `${target.guard}`);
      Object.assign(st, { summary: `${r.runs.toLocaleString()} inputs · ${r.crashes.length} crashes · ${r.slow.length} slow · ${r.bypasses.length} of ${r.mutated} rewrites bypass`,
        passed: [...(r.crashes.length ? [] : ["Never crashed"]), ...(r.slow.length ? [] : ["No input took over 100 ms (no ReDoS)"]), `Built-in normaliser: ${h.bypasses.length} of ${h.mutated} rewrites bypass`], detail: { seed: r.seed } });
    } else if (kind === "malware") {
      const r = await scanMalware({ codeDirs: [target.dir], dataDirs: [watchDir, ...cloudDataDirs()], packageDirs: [process.cwd()], hashList: join(STATE, "intel", "malware-hashes.txt"), selfDir: process.cwd() });
      fs = r.findings; Object.assign(st, { summary: r.summary, passed: r.passed, detail: { engines: r.engines } });
    } else if (kind === "leak") {
      const r = await scanLeaks([{ dir: target.runs, kind: "runs" }, { dir: demoRuns, kind: "runs" }, { dir: join(process.cwd(), "logs"), kind: "logs" }, { dir: join(process.cwd(), "outbox"), kind: "emails" }, { dir: watchDir, kind: "exports" },
        ...(process.env.LEAK_DIRS ?? "").split(",").filter(Boolean).map((d) => ({ dir: d, kind: "logs" as const }))], [target.dir, process.cwd()]);
      fs = r.findings; Object.assign(st, { summary: r.summary, passed: r.passed });
    } else if (kind === "outdated") {
      const r = await scanOutdated([target.dir, process.cwd()], join(STATE, "intel"));
      fs = r.findings; Object.assign(st, { summary: r.summary, passed: r.passed });
    } else if (kind === "cloud") {
      const r = huntFolders(cloudtrailDirs, egressDirs);
      fs = r.findings; Object.assign(st, { summary: `${r.events} cloud events and ${r.egress} traffic records hunted${liveCloudTrail ? " · live CloudTrail on" : ""}`, passed: [] });
    } else if (kind === "model") {
      if (!redteamReady()) throw new Error("Needs the model API key: set ANTHROPIC_API_KEY (and AGENT_MODEL), then restart.");
      await runRedteam(); fs = redteam ? redteamFindings(redteam) : [];
      Object.assign(st, { summary: redteam ? `${redteam.passed} held · ${redteam.failed} obeyed the attacker` : "no result", passed: [] });
    }
    raisingScan = kind; try { raise(fs); } finally { raisingScan = null; }
    Object.assign(st, { ids: [...new Set(fs.filter((f) => f.severity !== "info").map(fingerprint))], at: new Date().toISOString(), issues: new Set(fs.filter((f) => f.severity !== "info").map((f) => f.key ?? f.rule + f.where + f.title)).size, worst: worstOf(fs) });
  } catch (e) {
    st.error = (e as Error).message; st.at = new Date().toISOString();
  } finally { st.running = false; push("scans", scanStates()); }
}
const cloudDataDirs = () => (process.env.MALWARE_DIRS ?? "").split(",").filter(Boolean);
const scanStates = () => ({ ...scans, websiteDefault: DEFAULT_WEBSITE, allowedHosts: allowedHosts(), modelReady: redteamReady() });

let intel: Record<string, unknown> | null = null;
const owaspState: Record<string, any> = { secureHeaders: null, zap: process.env.ZAP_API_URL ? { mode: "api" } : null, dependencyCheck: null, dependencyTrack: null, defectDojo: null };
// Reports from OWASP ZAP and OWASP Dependency-Check runs elsewhere (CI, a laptop) are imported from these folders.
const importedReports = new Set<string>();
setInterval(() => {
  for (const [dir, kind] of [[join(STATE, "zap"), "zap"], [join(STATE, "dependency-check"), "dc"]] as const) {
    if (!existsSync(dir)) continue;
    for (const n of readdirSync(dir)) {
      const p = join(dir, n);
      if (!n.endsWith(".json") || importedReports.has(p) || Date.now() - statSync(p).mtimeMs < 1500) continue;
      importedReports.add(p);
      try {
        let fsx = kind === "zap" ? zapFindings(readFile(p, "utf8")) : dependencyCheckFindings(readFile(p, "utf8"), n);
        let confirmed = 0;
        if (kind === "zap") fsx = fsx.filter((z) => {
          // ZAP agrees with one of Agent Shield's own website alerts: count it as a confirmation, not a second alert.
          const host = (() => { try { return new URL(z.where ?? "").host; } catch { return z.where ?? ""; } })();
          const same = bus.list().find((a) => !a.acknowledged && a.source === "web" && !a.rule.startsWith("ZAP-") && String(a.evidence?.zapRule ?? "") === String(z.evidence?.zapRule) && (a.where ?? "").includes(host));
          if (same) { confirmed++; return false; } return true;
        });
        raise(fsx);
        if (kind === "zap") owaspState.zap = { ...(owaspState.zap ?? {}), mode: owaspState.zap?.mode ?? "import", imported: (owaspState.zap?.imported ?? 0) + 1, alerts: fsx.length, confirmed: (owaspState.zap?.confirmed ?? 0) + confirmed, at: new Date().toISOString() };
        else owaspState.dependencyCheck = { mode: "import", imported: (owaspState.dependencyCheck?.imported ?? 0) + 1, findings: fsx.length, at: new Date().toISOString() };
      } catch { /* not a report */ }
    }
  }
}, 3000);

// ---- monitors ----------------------------------------------------------------
let resettingUntil = 0; // the drill reset rewrites the sample files: not an attack
watchFolder(watchDir, (fs) => { if (Date.now() > resettingUntil) raise(fs); });
// On-access malware check: every file written to the watched folder is checked the moment it lands.
let malHashes = loadHashList(join(STATE, "intel", "malware-hashes.txt"));
setInterval(() => { malHashes = loadHashList(join(STATE, "intel", "malware-hashes.txt")); }, 3_600_000);
const onAccessStats = { checked: 0, detections: 0 };
// Polling, not fs.watch: a recursive watcher loses folders that are deleted and recreated (a restore, a reset).
const accessSeen = new Map<string, string>();
let accessPrimed = false;
function onAccessSweep() {
  const stack = [watchDir]; let n = 0;
  const now = new Set<string>();
  while (stack.length && n < 5000) {
    const d = stack.pop()!; let names: string[] = []; try { names = readdirSync(d); } catch { continue; }
    for (const name of names) {
      const p = join(d, name); let st; try { st = statSync(p); } catch { continue; }
      if (st.isDirectory()) { stack.push(p); continue; }
      n++; now.add(p);
      const sig = `${st.size}:${st.mtimeMs}`;
      if (accessSeen.get(p) === sig) continue;
      accessSeen.set(p, sig);
      if (!accessPrimed) continue; // files present at start are covered by the full malware scan
      const r = scanFile(p, `${basename(watchDir)}/${p.slice(watchDir.length + 1)}`, "data", malHashes);
      if (r.scanned) { onAccessStats.checked++; if (r.findings.length) { onAccessStats.detections++; raise(r.findings.map((f) => ({ ...f, evidence: { ...f.evidence, caught: "on access, as the file was written" } }))); } }
    }
  }
  for (const p of accessSeen.keys()) if (!now.has(p)) accessSeen.delete(p);
  accessPrimed = true;
}
onAccessSweep(); setInterval(onAccessSweep, 2000);
const cloudtrailDirs = [process.env.CLOUDTRAIL_DIR ?? join(process.cwd(), "logs", "cloudtrail"), join(SANDBOX, "cloud", "cloudtrail")];
const egressDirs = [process.env.EGRESS_DIR ?? join(process.cwd(), "logs", "egress"), join(SANDBOX, "cloud", "egress")];
const cloud = feedCloud({ cloudtrail: cloudtrailDirs, egress: egressDirs, onFindings: raise, onEvent: (k) => { if (k === "cloudtrail") activity.cloudEvents++; else activity.egressEvents++; } });
let liveCloudTrail = false;
pollCloudTrailLive(cloud.monitor, raise, () => activity.cloudEvents++).then((r) => { liveCloudTrail = Boolean(r); });
const ledger = new PaymentLedger(Number(process.env.RECON_GRACE_MS ?? 60_000));
ledger.indexFolders([target.runs, demoRuns]);
const misinfo = new MisinfoMonitor();
tailRuns([target.runs, demoRuns], raise, (run) => { activity.eventsRead++; activity.runsSeen.add(run); }, false, (e, run) => { ledger.add(e, run); raise(misinfo.ingest(e as { kind?: string; task?: string }, run)); raise(leaksInText(JSON.stringify(e), `runs/${run}.jsonl`, "runs").map((f) => ({ ...f, evidence: { ...f.evidence, caught: "live, as the agent wrote its log" } }))); });
setInterval(() => raise(ledger.sweep()), 5_000);

/** One Airwallex webhook: verify, then reconcile. Drills pass their own secret and skip the grace period. */
function handleAirwallex(raw: string, ts: string | undefined, sig: string | undefined, secret: string, drill = false) {
  const v = verifyAirwallexSignature(raw, ts, sig, secret);
  if (!v.ok) {
    integ.webhooksRejected++;
    raise([{ source: "finance", rule: "FIN-WEBHOOK-REJECTED", severity: "medium", key: `webhook-rejected:${new Date().toISOString().slice(0, 13)}`, where: "POST /api/webhooks/airwallex",
      title: "Rejected a payment webhook that failed verification", detail: `${v.why}. Someone may be sending forged Airwallex events, or the webhook secret changed.`,
      fix: "Check the secret in the Airwallex web app matches AIRWALLEX_WEBHOOK_SECRET; if it does, block the sender." }]);
    return { ok: false, why: v.why };
  }
  integ.webhooksReceived++;
  const ev = JSON.parse(raw) as WebhookEvent;
  raise(ledger.ingest(ev, drill ? Date.now() - Number(process.env.RECON_GRACE_MS ?? 60_000) - 1 : Date.now()));
  if (drill) raise(ledger.sweep(Date.now() + 1));
  return { ok: true };
}

const falco = new FalcoFeed();
const falcoOffsets = new Map<string, number>();
setInterval(() => {
  for (const d of integ.falcoDirs) {
    if (!existsSync(d)) continue;
    for (const n of readdirSync(d)) {
      if (!n.endsWith(".jsonl") && !n.endsWith(".json")) continue;
      const p = join(d, n), size = statSync(p).size, off = falcoOffsets.get(p) ?? 0;
      if (size <= off) continue;
      const fd = openSync(p, "r"), buf = Buffer.alloc(size - off); readSync(fd, buf, 0, buf.length, off); closeSync(fd);
      falcoOffsets.set(p, size);
      for (const line of buf.toString("utf8").split("\n")) { if (!line.trim()) continue; try { raise(falco.ingest(JSON.parse(line) as FalcoAlert)); } catch { /* skip */ } }
    }
  }
}, 1000);

// ---- http --------------------------------------------------------------------
const ui = () => readFileSync(join(import.meta.dirname, "..", "ui", "index.html"));

function authorised(req: IncomingMessage) {
  if (!TOKEN) return true;
  const h = req.headers.authorization ?? "";
  const q = new URL(req.url ?? "/", "http://x").searchParams.get("token") ?? ""; // EventSource cannot send headers
  const given = Buffer.from(h.startsWith("Bearer ") ? h.slice(7) : q);
  const want = Buffer.from(TOKEN);
  return given.length === want.length && timingSafeEqual(given, want);
}

const json = (res: ServerResponse, code: number, body: unknown) => { res.writeHead(code, { "content-type": "application/json", "cache-control": "no-store" }); res.end(JSON.stringify(body)); };
const header = (req: IncomingMessage, h: string) => { const v = req.headers[h]; return Array.isArray(v) ? v[0] : v; };
async function rawBody(req: IncomingMessage, max = 1_000_000) {
  const chunks: Buffer[] = []; let n = 0;
  for await (const c of req) { n += (c as Buffer).length; if (n > max) break; chunks.push(c as Buffer); }
  return Buffer.concat(chunks).toString("utf8");
}
async function body(req: IncomingMessage) {
  let s = ""; for await (const c of req) { s += c; if (s.length > 10_000) break; }
  try { return JSON.parse(s || "{}") as Record<string, unknown>; } catch { return {}; }
}

createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://x");
  res.setHeader("x-content-type-options", "nosniff");
  res.setHeader("referrer-policy", "no-referrer");
  if (url.pathname === "/" || url.pathname === "/index.html") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'" });
    return res.end(ui());
  }
  if (!url.pathname.startsWith("/api/")) { res.writeHead(404); return res.end(); }
  // Airwallex cannot send our token: this route is authenticated by the webhook signature instead.
  if (req.method === "POST" && url.pathname === "/api/webhooks/airwallex") {
    const secret = process.env.AIRWALLEX_WEBHOOK_SECRET;
    if (!secret) return json(res, 503, { error: "Set AIRWALLEX_WEBHOOK_SECRET to accept Airwallex webhooks" });
    const raw = await rawBody(req);
    const r = handleAirwallex(raw, header(req, "x-timestamp"), header(req, "x-signature"), secret);
    return json(res, r.ok ? 200 : 401, r);
  }
  if (!authorised(req)) return json(res, 401, { error: "token required" });

  try {
    if (req.method === "GET" && url.pathname === "/api/stream") {
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store", connection: "keep-alive" });
      res.write(`event: hello\ndata: ${JSON.stringify(status())}\n\n`);
      clients.add(res);
      req.on("close", () => clients.delete(res));
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/state")
      return json(res, 200, { autoScan: auto.state(), scans: scanStates(), redteam: redteamSummary(), target: target.name, alerts: bus.list(), refNames: REF_NAMES, counts: bus.counts(), scan: scanSummary(), status: status(), email: { to: emailCfg.to, minSeverity: emailCfg.minSeverity, mode: emailCfg.smtpUrl ? "smtp" : "outbox", recent: activity.emails } });
    if (req.method === "POST" && url.pathname === "/api/scan") return json(res, 200, await runScan());
    const kind = /^\/api\/scan\/(code|website|system|deps|supply|secrets|fuzz|malware|leak|outdated|cloud|model)$/.exec(url.pathname);
    if (req.method === "POST" && kind) {
      const b = await body(req);
      runKind(kind[1] as Kind, { url: b.url ? String(b.url) : undefined, authorised: b.authorised === true });
      return json(res, 202, { started: kind[1] });
    }
    if (req.method === "POST" && url.pathname === "/api/autoscan") {
      const b = await body(req);
      if (typeof b.enabled === "boolean") auto.enabled = b.enabled;
      push("auto_state", auto.state());
      return json(res, 200, auto.state());
    }
    if (req.method === "POST" && url.pathname === "/api/redteam") {
      if (!redteamReady()) return json(res, 409, { error: "Set ANTHROPIC_API_KEY (and AGENT_MODEL) before starting the server, or SHIELD_REDTEAM_MOCK=1 for a dry run." });
      runRedteam(); return json(res, 202, { started: true });
    }
    if (req.method === "POST" && url.pathname === "/api/ingest/falco") {
      const raw = await rawBody(req);
      let n = 0;
      for (const line of raw.split("\n")) { if (!line.trim()) continue; try { const v = JSON.parse(line); for (const a of Array.isArray(v) ? v : [v]) { raise(falco.ingest(a)); n++; } } catch { /* skip */ } }
      return json(res, 200, { received: n });
    }
    if (req.method === "GET" && url.pathname === "/api/sbom") {
      const f = join(STATE, "sbom", "agent.cdx.json");
      if (!existsSync(f)) return json(res, 404, { error: "Run the Supply chain scan first" });
      res.writeHead(200, { "content-type": "application/vnd.cyclonedx+json", "content-disposition": "attachment; filename=agent-desk.cdx.json" });
      return res.end(readFile(f));
    }
    if (req.method === "GET" && url.pathname === "/api/frameworks") return json(res, 200, frameworks());
    if (req.method === "GET" && url.pathname === "/api/export/defectdojo") {
      res.writeHead(200, { "content-type": "application/json", "content-disposition": "attachment; filename=agent-shield-defectdojo.json" });
      return res.end(JSON.stringify(toDefectDojo(bus.list(), REF_NAMES), null, 2));
    }
    if (req.method === "POST" && url.pathname === "/api/export/defectdojo") {
      try { const r = await pushToDefectDojo(toDefectDojo(bus.list(), REF_NAMES)); owaspState.defectDojo = { at: new Date().toISOString(), ok: true, test: r.test }; return json(res, 200, r); }
      catch (e) { owaspState.defectDojo = { at: new Date().toISOString(), ok: false, error: (e as Error).message }; return json(res, 409, { error: (e as Error).message }); }
    }
    if (req.method === "GET" && url.pathname === "/api/coverage") {
      const seen = new Set(bus.list().map((a) => a.rule));
      return json(res, 200, integ.coverage.map((c) => ({ ...c, seenLive: c.expects.some((e) => seen.has(e)) })));
    }
    if (req.method === "POST" && url.pathname === "/api/ack") {
      const b = await body(req);
      const a = bus.acknowledge(String(b.id ?? ""), String(b.by ?? "support"));
      return a ? json(res, 200, a) : json(res, 404, { error: "no such alert" });
    }
    const sim = /^\/api\/simulate\/(ransomware|finance|artex|stratus|recon|malware|leak|reset)$/.exec(url.pathname);
    if (req.method === "POST" && sim) {
      if (sim[1] === "malware") { simulateMalware().catch((e) => push("error", { error: String(e) })); return json(res, 202, { started: "malware drill: three harmless samples dropped in sandbox/watched" }); }
      if (sim[1] === "leak") { const f = simulateLeak(); return json(res, 202, { started: `data-leak drill: ${basename(f)}` }); }
      if (sim[1] === "ransomware") { simulateRansomware().catch((e) => push("error", { error: String(e) })); return json(res, 202, { started: "ransomware drill in sandbox/watched" }); }
      if (sim[1] === "artex") { simulateArtex().catch((e) => push("error", { error: String(e) })); return json(res, 202, { started: "ARTEX-style intrusion drill in sandbox/cloud" }); }
      if (sim[1] === "stratus") return json(res, 202, { started: `Stratus Red Team replay: ${simulateStratus()} CloudTrail records in sandbox/cloud` });
      if (sim[1] === "recon") {
        const events = simulateUnloggedTransfer(demoRuns);
        const secret = randomBytes(16).toString("hex"); // drill-only secret: exercises the same verifier as real webhooks
        setTimeout(() => { for (const ev of events) { const raw = JSON.stringify(ev), ts = String(Date.now()); handleAirwallex(raw, ts, createHmac("sha256", secret).update(ts + raw).digest("hex"), secret, true); } }, 1500);
        return json(res, 202, { started: "payment reconciliation drill: 1 matching, 1 altered and 1 unlogged transfer" });
      }
      if (sim[1] === "finance") { simulateFinance().catch((e) => push("error", { error: String(e) })); return json(res, 202, { started: "finance drill in sandbox/runs" }); }
      resettingUntil = Date.now() + 15_000; resetSandbox(); return json(res, 200, { reset: true });
    }
    return json(res, 404, { error: "not found" });
  } catch (err) {
    return json(res, 500, { error: (err as Error).message });
  }
}).listen(PORT, HOST, async () => {
  console.log(`Agent Shield on http://${HOST}:${PORT} · target ${target.name} (${target.dir})`);
  console.log(`watching files in ${watchDir} · following agent logs in ${target.runs} and ${demoRuns}`);
  console.log(`critical/high alerts → ${emailCfg.smtpUrl ? "email to " + emailCfg.to : "outbox/ (.eml files; set SMTP_URL to send)"}`);
  await runKind("code"); console.log(`code scan: ${scans.code.summary ?? scans.code.error}`);
  runKind("system");
});
