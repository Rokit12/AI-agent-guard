/**
 * One alert model for every detector. Detectors are pure: they return findings.
 * The AlertBus turns findings into alerts, removes repeats, keeps an append-only
 * log, and tells listeners (the live dashboard, the email notifier) at once.
 */
import { EventEmitter } from "node:events";
import { appendFileSync, mkdirSync, readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { refsFor } from "./frameworks.ts";

export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];
export type Source = "code" | "llm" | "finance" | "access" | "ransomware" | "identity" | "network" | "web" | "system";

export interface Finding {
  source: Source;
  rule: string;        // stable rule id, e.g. FIN-DOUBLE-PAY
  severity: Severity;
  title: string;       // one line a support engineer reads first
  detail: string;      // what was seen and why it matters
  fix?: string;        // what to do about it
  where?: string;      // file:line, run log, folder, endpoint
  evidence?: Record<string, unknown>;
  /** Incident key: findings with the same key update one alert instead of raising new ones. */
  key?: string;
  /** Framework references (OWASP LLM / Agentic / Top 10, MITRE ATT&CK / ATLAS); filled from the rule when absent. */
  refs?: string[];
}

export interface Alert extends Finding {
  id: string;
  at: string;
  acknowledged?: { by: string; at: string };
  updatedAt?: string;
}

export const rank = (s: Severity) => SEVERITIES.indexOf(s);
/** A finding's identity: the same rule at the same place is one alert, however often it is seen. */
export const fingerprint = (f: Finding) => createHash("sha256").update(f.key ? `${f.source}|key|${f.key}` : `${f.source}|${f.rule}|${f.where ?? ""}|${f.title}`).digest("hex").slice(0, 16);

export class AlertBus extends EventEmitter {
  readonly alerts = new Map<string, Alert>();
  private readonly log: string;

  constructor(stateDir = join(process.cwd(), "state")) {
    super();
    mkdirSync(stateDir, { recursive: true });
    this.log = join(stateDir, "alerts.jsonl");
    if (existsSync(this.log)) {
      for (const line of readFileSync(this.log, "utf8").split("\n")) {
        if (!line.trim()) continue;
        const rec = JSON.parse(line) as { type: string; alert?: Alert; id?: string; by?: string; at?: string };
        if (rec.type === "alert" && rec.alert) this.alerts.set(rec.alert.id, rec.alert);
        if (rec.type === "ack" && rec.id && this.alerts.has(rec.id)) this.alerts.get(rec.id)!.acknowledged = { by: rec.by!, at: rec.at! };
      }
    }
  }

  /** Raise a finding. Returns the alert if it is new, or null if it was already raised. */
  raise(f: Finding): Alert | null {
    const id = fingerprint(f);
    const prev = this.alerts.get(id);
    if (prev) {
      // Same incident seen again: update it in place (it grew, or got worse) without a new alert or email.
      if (f.key && (f.title !== prev.title || f.detail !== prev.detail || rank(f.severity) > rank(prev.severity))) {
        Object.assign(prev, { title: f.title, detail: f.detail, evidence: f.evidence, severity: rank(f.severity) > rank(prev.severity) ? f.severity : prev.severity, updatedAt: new Date().toISOString() });
        appendFileSync(this.log, JSON.stringify({ type: "alert", alert: prev }) + "\n");
        this.emit("update", prev);
      }
      return null;
    }
    const alert: Alert = { ...f, refs: f.refs ?? refsFor(f.rule), id, at: new Date().toISOString() };
    this.alerts.set(id, alert);
    appendFileSync(this.log, JSON.stringify({ type: "alert", alert }) + "\n");
    this.emit("alert", alert);
    return alert;
  }

  raiseAll(fs: Finding[]): Alert[] {
    return fs.map((f) => this.raise(f)).filter((a): a is Alert => a !== null);
  }

  acknowledge(id: string, by: string): Alert | null {
    const a = this.alerts.get(id);
    if (!a || a.acknowledged) return a ?? null;
    a.acknowledged = { by, at: new Date().toISOString() };
    appendFileSync(this.log, JSON.stringify({ type: "ack", id, by, at: a.acknowledged.at }) + "\n");
    this.emit("ack", a);
    return a;
  }

  list(): Alert[] {
    return [...this.alerts.values()].sort((a, b) => rank(b.severity) - rank(a.severity) || b.at.localeCompare(a.at));
  }

  counts(): Record<Severity, number> {
    const c = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
    for (const a of this.alerts.values()) if (!a.acknowledged) c[a.severity]++;
    return c;
  }
}
