/**
 * Payment reconciliation: Airwallex's own record of money leaving, checked against the
 * agent's audit log.
 *
 * The finance-flow monitor only sees what the agent logs. Airwallex sends a signed webhook
 * for every transfer (payout.transfer.processing, .sent, .paid, .failed, ...). Each one is
 * matched to a logged payment by transfer id, then request_id, then amount + currency +
 * beneficiary. A transfer Airwallex reports and the agent never logged is the case that
 * matters most: someone (or something) moved money outside the agent's audited path.
 *
 * Signature (Airwallex docs, "Listen for webhook events"): x-signature is the hex
 * HMAC-SHA256, keyed with the webhook's secret, of the x-timestamp header value followed by
 * the raw request body. Verify before parsing.
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join, basename } from "node:path";
import type { Finding } from "../alerts.ts";
import type { AuditEvent } from "./finance-flow.ts";

export function verifyAirwallexSignature(rawBody: string, timestamp: string | undefined, signature: string | undefined, secret: string, toleranceMs = 5 * 60_000, now = Date.now()) {
  if (!timestamp || !signature) return { ok: false, why: "missing x-timestamp or x-signature header" };
  const expected = createHmac("sha256", secret).update(timestamp + rawBody).digest("hex");
  const a = Buffer.from(expected), b = Buffer.from(signature.trim().toLowerCase());
  if (a.length !== b.length || !timingSafeEqual(a, b)) return { ok: false, why: "signature does not match" };
  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || Math.abs(now - ts) > toleranceMs) return { ok: false, why: "timestamp outside the allowed window (possible replay)" };
  return { ok: true as const, why: "" };
}

export interface LoggedPayment { run: string; at: number; transferId?: string; requestId?: string; amount?: number; currency?: string; beneficiary?: string }
export interface WebhookEvent { id?: string; name?: string; created_at?: string; data?: { object?: Record<string, unknown> } }

const MONEY_OUT = /\/(transfers|payouts)\/create\b/;
const num = (v: unknown) => (typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" && !isNaN(Number(v)) ? Number(v) : undefined);
const low = (v: unknown) => (typeof v === "string" && v ? v.trim().toLowerCase() : undefined);
/** Events that mean money is leaving or has left. */
const MOVING = /^payout\.transfer\.(scheduled|processing|sent|paid)$/;

export class PaymentLedger {
  readonly payments: LoggedPayment[] = [];
  private pending = new Map<string, { ev: WebhookEvent; at: number }>();
  private settled = new Set<string>();

  constructor(private graceMs = 60_000) {}

  /** Add one audit-log event (Agent Desk format: kind "call", req, res). */
  add(e: AuditEvent, run: string) {
    if (e.kind !== "call" || String(e.method ?? "").toUpperCase() !== "POST" || !MONEY_OUT.test(String(e.path ?? ""))) return;
    if ((num(e.status) ?? 200) >= 300) return;
    const req = (e.req ?? {}) as Record<string, unknown>, res = (e.res ?? {}) as Record<string, unknown>;
    this.payments.push({ run, at: e.at ? Date.parse(e.at) : Date.now(), transferId: low(res.id), requestId: low(req.request_id),
      amount: num(req.amount) ?? num(req.transfer_amount) ?? num(res.amount) ?? num(res.transfer_amount),
      currency: low(req.currency ?? req.transfer_currency ?? res.transfer_currency), beneficiary: low(req.beneficiary_id ?? res.beneficiary_id) });
  }

  /** Read every audit log in the folders from the start (history matters here). */
  indexFolders(dirs: string[]) {
    for (const d of dirs) {
      if (!existsSync(d)) continue;
      for (const n of readdirSync(d)) {
        if (!n.endsWith(".jsonl")) continue;
        for (const line of readFileSync(join(d, n), "utf8").split("\n")) { if (!line.trim()) continue; try { this.add(JSON.parse(line), basename(n, ".jsonl")); } catch { /* skip */ } }
      }
    }
  }

  match(o: Record<string, unknown>) {
    const id = low(o.id), rid = low(o.request_id), amt = num(o.transfer_amount) ?? num(o.amount), cur = low(o.transfer_currency ?? o.currency), ben = low(o.beneficiary_id);
    return this.payments.find((p) => id && p.transferId === id) ?? this.payments.find((p) => rid && p.requestId === rid)
      ?? this.payments.find((p) => amt !== undefined && p.amount === amt && cur && p.currency === cur && ben && p.beneficiary === ben);
  }

  /** Take a verified webhook. Unmatched money-moving transfers wait out the grace period (the log line may still be on its way). */
  ingest(ev: WebhookEvent, now = Date.now()): Finding[] {
    const o = ev.data?.object ?? {};
    if (!ev.name || !MOVING.test(ev.name)) return [];
    const key = low(o.id) ?? low(o.request_id) ?? ev.id ?? String(now);
    if (this.settled.has(key)) return [];
    const m = this.match(o);
    if (m) { this.settled.add(key); this.pending.delete(key); return this.compare(o, m, ev); }
    if (!this.pending.has(key)) this.pending.set(key, { ev, at: now });
    return this.sweep(now);
  }

  /** Re-check waiting transfers; anything still unmatched after the grace period is raised. */
  sweep(now = Date.now()): Finding[] {
    const out: Finding[] = [];
    for (const [key, { ev, at }] of this.pending) {
      const o = ev.data?.object ?? {};
      const m = this.match(o);
      if (m) { this.pending.delete(key); this.settled.add(key); out.push(...this.compare(o, m, ev)); continue; }
      if (now - at < this.graceMs) continue;
      this.pending.delete(key); this.settled.add(key);
      const amt = num(o.transfer_amount) ?? num(o.amount), cur = String(o.transfer_currency ?? o.currency ?? "").toUpperCase();
      out.push({ source: "finance", rule: "FIN-UNLOGGED-TRANSFER", severity: "critical", key: `recon:${key}`, where: `Airwallex webhook ${ev.name}`,
        title: `Airwallex sent ${amt ?? "?"} ${cur} that the agent never logged`,
        detail: `Transfer ${o.id ?? "?"} (request_id ${o.request_id ?? "none"}, beneficiary ${o.beneficiary_id ?? "?"}) reached status ${String(o.status ?? (ev.name ?? "").split(".").pop())}, but no agent run recorded a matching payment. Money moved outside the agent's audited path.`,
        fix: "Check who created this transfer in the Airwallex web app (API key or user), cancel it if it has not settled, and rotate the API key if it was not a person on your team.",
        evidence: { webhookId: ev.id, transferId: o.id, requestId: o.request_id } });
    }
    return out;
  }

  private compare(o: Record<string, unknown>, m: LoggedPayment, ev: WebhookEvent): Finding[] {
    const amt = num(o.transfer_amount) ?? num(o.amount), ben = low(o.beneficiary_id);
    const issues: string[] = [];
    if (amt !== undefined && m.amount !== undefined && amt !== m.amount) issues.push(`amount ${amt} at Airwallex vs ${m.amount} in the log`);
    if (ben && m.beneficiary && ben !== m.beneficiary) issues.push(`beneficiary ${ben} at Airwallex vs ${m.beneficiary} in the log`);
    if (!issues.length) return [];
    return [{ source: "finance", rule: "FIN-RECON-MISMATCH", severity: "critical", key: `recon:${low(o.id) ?? low(o.request_id)}`, where: `${m.run} · Airwallex webhook ${ev.name}`,
      title: "A payment at Airwallex differs from what the agent logged",
      detail: `Transfer ${o.id ?? "?"}: ${issues.join("; ")}. Either the log was altered or the request was changed after the agent sent it.`,
      fix: "Hold the transfer if it has not settled, compare the API request in Airwallex with the agent's log, and check who had access to both." }];
  }

  stats() { return { logged: this.payments.length, waiting: this.pending.size, reconciled: this.settled.size }; }
}
