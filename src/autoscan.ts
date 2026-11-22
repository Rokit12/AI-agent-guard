/**
 * Automatic scans.
 *
 * When an alert shows signs of an intrusion, malware, a data leak or an old vulnerability,
 * Agent Shield starts the scans that answer the next question on its own, the way an
 * analyst would: an intrusion → what else did they touch (cloud, this computer, secrets,
 * malware, leaks); malware → is anything else infected (malware, computer, supply chain,
 * leaks); a leak → what else is exposed (leaks, git history, code, cloud); an old or
 * vulnerable component → what else is out of date (packages, supply chain, outdated).
 *
 * Alerts that arrive close together are batched into one round, each scan has a cooldown
 * so an incident cannot start a loop, and slow-moving risks (new advisories against old
 * packages, malware, leaks) are also re-checked on a schedule.
 */
import { rank, type Alert, type Severity } from "./alerts.ts";

export type Category = "intrusion" | "malware" | "leak" | "vulnerability";
export type AutoKind = "cloud" | "system" | "secrets" | "malware" | "leak" | "code" | "deps" | "supply" | "outdated";

export const CATEGORY_LABEL: Record<Category, string> = { intrusion: "Intrusion", malware: "Malware", leak: "Data leak", vulnerability: "Old or vulnerable software" };

const RULES: [Category, RegExp][] = [
  ["leak", /^(LEAK-|SECRET-HISTORY|CODE-SECRET|SEMGREP-SECRET-TO-LOG|LLM-CARD-DATA|LLM-SYSPROMPT-SECRET|ACC-PUBLIC-BUCKET|SYS-SECRET-PERMS|NET-WEBHOOK-EXFIL|NET-UNAPPROVED-AI|ID-SNAPSHOT-SHARE|ID-SECRETS-BURST|ID-S3-MASS-DELETE)/],
  ["malware", /^(MAL-|RANSOM-|SUPPLY-INTEGRITY-MISMATCH|SUPPLY-SIGNATURE-INVALID|SUPPLY-INSTALL-SCRIPTS|ID-S3-SSEC-ENCRYPT|ID-LLMJACKING)/],
  ["intrusion", /^(ID-|NET-|FALCO-RUNTIME|FIN-WEBHOOK-REJECTED|FIN-UNLOGGED-TRANSFER|FIN-RECON-MISMATCH|FIN-TAINTED-PAYEE|FIN-INJECTION-READ|SYS-OPEN-PORT|ACC-OPEN-ENDPOINT|AGENT-MCP-NO-AUTH|AGENT-A2A-NO-AUTH)/],
  ["vulnerability", /^(SYS-VULN-DEPENDENCY|OSV-VULN|OWASP-DC-VULN|OLD-|SYS-NODE-EOL)/],
];

/** Every category an alert belongs to (a webhook exfiltration is an intrusion and a leak). */
export function categorise(rule: string): Category[] {
  const out = RULES.filter(([, re]) => re.test(rule)).map(([c]) => c);
  if (out.includes("leak") && /^(NET-|ID-)/.test(rule) && !out.includes("intrusion")) out.push("intrusion");
  return out;
}

export const FOLLOW_UP: Record<Category, AutoKind[]> = {
  intrusion: ["cloud", "system", "secrets", "malware", "leak"],
  malware: ["malware", "system", "supply", "leak"],
  leak: ["leak", "secrets", "code", "cloud"],
  vulnerability: ["deps", "supply", "outdated"],
};
/** The lowest severity that starts scans, per category. Vulnerabilities wait for high: a medium advisory can wait for the schedule. */
export const MIN_SEVERITY: Record<Category, Severity> = { intrusion: "medium", malware: "medium", leak: "medium", vulnerability: "high" };

/** Background re-checks, in hours. */
export const SCHEDULE: Partial<Record<AutoKind, number>> = { deps: 24, outdated: 24, supply: 24, secrets: 24, malware: 6, leak: 6 };

/** origin: "live" for the always-on monitors (file access, agent logs, cloud logs, webhooks), or the scan that raised the alert. */
export interface Trigger { at: string; category: Category; rule: string; title: string; severity: Severity; alertId?: string; origin: string }
export interface Round { at: string; reason: "alert" | "schedule"; triggers: Trigger[]; kinds: AutoKind[]; skipped: { kind: AutoKind; why: string }[] }

export class AutoScanner {
  enabled: boolean;
  cooldownMs: number;
  minGapMs: number;
  lastRun = new Map<AutoKind, number>();
  rounds: Round[] = [];
  private pending: Trigger[] = [];
  /** Live evidence waiting for one scan's minimum gap to pass. */
  private carry: { t: Trigger; k: AutoKind }[] = [];
  private retryAt: number | null = null;
  private notBefore: number;

  constructor(o: { enabled?: boolean; cooldownMs?: number; minGapMs?: number; startedAt?: number; graceMs?: number } = {}) {
    this.enabled = o.enabled ?? true;
    this.cooldownMs = o.cooldownMs ?? 10 * 60_000;
    this.minGapMs = o.minGapMs ?? 20_000;
    this.notBefore = (o.startedAt ?? Date.now()) + (o.graceMs ?? 30_000);
  }

  /** Note that a scan ran (by hand, on a schedule or automatically); starts its cooldown. */
  ran(kind: string, at = Date.now()) { this.lastRun.set(kind as AutoKind, at); }

  /** Consider one new or worsened alert. Returns the trigger if it should start scans. */
  consider(a: Pick<Alert, "rule" | "title" | "severity" | "id" | "acknowledged">, now = Date.now(), origin = "live"): Trigger[] {
    if (!this.enabled || now < this.notBefore || a.acknowledged) return [];
    const t = categorise(a.rule).filter((c) => rank(a.severity) >= rank(MIN_SEVERITY[c]))
      .map((category) => ({ at: new Date(now).toISOString(), category, rule: a.rule, title: a.title, severity: a.severity, alertId: a.id, origin }));
    this.pending.push(...t);
    return t;
  }

  /** Turn the batched triggers into one round of scans; kinds still cooling down or already running are skipped. */
  flush(running: (k: AutoKind) => boolean, now = Date.now()): Round | null {
    if (!this.pending.length && !this.carry.length) return null;
    const fresh = this.pending, carried = this.carry; this.pending = []; this.carry = [];
    const order: AutoKind[] = [];
    for (const t of [...fresh].sort((x, y) => rank(y.severity) - rank(x.severity))) for (const k of FOLLOW_UP[t.category]) if (!order.includes(k)) order.push(k);
    for (const c of carried) if (!order.includes(c.k)) order.push(c.k);
    const kinds: AutoKind[] = [], skipped: Round["skipped"] = [];
    const ago = (ms: number) => ms < 60_000 ? "just now" : `${Math.round(ms / 60_000)} min ago`;
    for (const k of order) {
      const need = [...fresh.filter((t) => FOLLOW_UP[t.category].includes(k)), ...carried.filter((c) => c.k === k).map((c) => c.t)];
      const newest = Math.max(...need.map((t) => Date.parse(t.at)));
      const last = this.lastRun.get(k);
      const live = need.some((t) => t.origin === "live");
      if (running(k)) skipped.push({ kind: k, why: "already running" });
      else if (need.every((t) => t.origin === k)) skipped.push({ kind: k, why: "it raised this alert" });
      else if (last && last >= newest) skipped.push({ kind: k, why: `ran ${ago(now - last)}, after the alert` });
      else if (last && live && now - last < this.minGapMs) {
        // too soon after its last run: keep the live evidence and run it once the gap has passed
        skipped.push({ kind: k, why: `runs again in ${Math.ceil((last + this.minGapMs - now) / 1000)} s` });
        for (const t of need) if (t.origin === "live") this.carry.push({ t, k });
        this.retryAt = Math.min(this.retryAt ?? Infinity, last + this.minGapMs);
      }
      else if (last && !live && now - last < this.cooldownMs) skipped.push({ kind: k, why: `ran ${ago(now - last)}` });
      else { kinds.push(k); this.lastRun.set(k, now); }
    }
    if (!kinds.length) return null; // everything it would run has just run (or waits for its gap): nothing new to start now
    const used = [...fresh, ...carried.filter((c) => kinds.includes(c.k)).map((c) => c.t)];
    const round: Round = { at: new Date(now).toISOString(), reason: "alert", triggers: dedupe(used), kinds,
      skipped: skipped.filter((x) => !/after the alert|it raised/.test(x.why)) };
    this.remember(round);
    return round;
  }

  /** When deferred live evidence should be looked at again (ms from now), or null. */
  retryDelay(now = Date.now()): number | null {
    if (this.retryAt === null || !this.carry.length) { this.retryAt = null; return null; }
    const d = Math.max(0, this.retryAt - now) + 250; this.retryAt = null; return d;
  }

  /** Scans whose scheduled re-check is due. */
  due(running: (k: AutoKind) => boolean, now = Date.now()): Round | null {
    if (!this.enabled) return null;
    const kinds = (Object.entries(SCHEDULE) as [AutoKind, number][]).filter(([k, h]) => !running(k) && now - (this.lastRun.get(k) ?? 0) >= h * 3_600_000).map(([k]) => k);
    if (!kinds.length) return null;
    for (const k of kinds) this.lastRun.set(k, now);
    const round: Round = { at: new Date(now).toISOString(), reason: "schedule", triggers: [], kinds, skipped: [] };
    this.remember(round);
    return round;
  }

  private remember(r: Round) { this.rounds.unshift(r); this.rounds.length = Math.min(this.rounds.length, 25); }

  state() {
    return { enabled: this.enabled, cooldownMin: Math.round(this.cooldownMs / 60_000), followUp: FOLLOW_UP, minSeverity: MIN_SEVERITY, schedule: SCHEDULE,
      lastRun: Object.fromEntries([...this.lastRun].map(([k, v]) => [k, new Date(v).toISOString()])), rounds: this.rounds };
  }
}

function dedupe(ts: Trigger[]) {
  const seen = new Set<string>(); const out: Trigger[] = [];
  for (const t of [...ts].sort((x, y) => rank(y.severity) - rank(x.severity))) { const k = `${t.category}|${t.rule}`; if (!seen.has(k)) { seen.add(k); out.push(t); } }
  return out.slice(0, 12);
}
