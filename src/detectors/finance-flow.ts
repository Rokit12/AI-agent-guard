/**
 * Finance-flow monitor.
 *
 * Reads an agent's audit log as it is written (one JSON event per line, Agent Desk's
 * format) and watches the money: every payment is checked against the approvals before
 * it, the accounts on file, the other payments in the same window and what the agent
 * read just before. It catches the outcomes attackers want, whatever route they took:
 * a double payment, a payment above what a person approved, money to an account that
 * appeared in an email, an approval given by the agent itself, a burst of payouts.
 */
import type { Finding } from "../alerts.ts";

export interface AuditEvent { at?: string; kind?: string; [k: string]: unknown }

interface Payment { at: number; path: string; requestId?: string; amount: number; currency?: string; counterparty?: string; run: string }
interface ApprovalRec { at: number; amount: number; currency?: string; counterparty?: string; approved: boolean; by?: string; proposedBy?: string; action?: string }

export interface FlowConfig {
  autoLimit: number;        // payments at or below this may run under policy without a person
  velocityCount: number;    // more than this many payments…
  velocityWindowMs: number; // …inside this window is a burst
  taintWindowMs: number;    // a new account paid within this time of reading an injection is suspicious
}
export const DEFAULT_FLOW: FlowConfig = { autoLimit: 100, velocityCount: 12, velocityWindowMs: 60_000, taintWindowMs: 15 * 60_000 };

const MONEY_PATH = /\/(transfers|payouts|refunds|payment_intents\/[^/]+\/(capture|confirm)|charges|pa\/refunds)\b.*(create|capture|confirm)?/;
const num = (v: unknown) => (typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" && !isNaN(Number(v)) ? Number(v) : undefined);
const norm = (s: unknown) => (typeof s === "string" ? s.trim().toLowerCase() : undefined);

/** Stateful monitor: feed it events in order; it returns findings as they appear. */
export class FinanceMonitor {
  private payments: Payment[] = [];
  private approvals: ApprovalRec[] = [];
  private injectionsAt: number[] = [];
  private knownAccounts = new Set<string>();
  private newAccounts = new Map<string, number>(); // beneficiary id -> created at
  private seenRequestIds = new Map<string, Payment>();

  constructor(private cfg: FlowConfig = DEFAULT_FLOW) {}

  ingest(e: AuditEvent, run = "run"): Finding[] {
    const at = e.at ? Date.parse(e.at) : Date.now();
    const out: Finding[] = [];
    const where = run;

    switch (e.kind) {
      case "prompt_injection_detected":
      case "untrusted_email":
      case "untrusted_reply": {
        const findings = (e.findings as unknown[] | undefined)?.length ?? (e.kind === "prompt_injection_detected" ? 1 : 0);
        if (findings) {
          this.injectionsAt.push(at);
          out.push({ source: "finance", rule: "FIN-INJECTION-READ", severity: "medium", where, key: `${run}:inject:${e.at}`,
            title: "Agent read a document carrying planted instructions",
            detail: `The agent flagged ${findings} instruction(s) in outside text (${String(e.case ?? e.source ?? e.subscriber ?? e.from ?? e.kind)}). Watching the next payments for an account taken from it.`,
            fix: "No action if nothing was paid; check the payments that follow in this run." });
        }
        break;
      }
      case "approval": {
        const t = (e.terms ?? {}) as Record<string, unknown>;
        const rec: ApprovalRec = { at, amount: num(t.amount) ?? 0, currency: norm(t.currency), counterparty: norm(t.counterparty), approved: Boolean(e.approved), by: e.by as string | undefined, proposedBy: e.proposedBy as string | undefined, action: t.action as string | undefined };
        this.approvals.push(rec);
        if (rec.approved && (!rec.by || rec.by === rec.proposedBy || /^(agent|assistant|model|llm|ai)$/i.test(rec.by))) {
          out.push({ source: "access", rule: "ACC-SELF-APPROVAL", severity: "critical", where, key: `${run}:self:${e.at}`,
            title: "An action was approved by the agent that proposed it",
            detail: `Approval of ${rec.action ?? "an action"} for ${rec.amount} ${rec.currency?.toUpperCase() ?? ""} to ${rec.counterparty ?? "?"} was recorded as by "${rec.by ?? "nobody"}", the same party that proposed it.`,
            fix: "Freeze the payment, and require approvals to come from a signed-in person through the approval channel only." });
        }
        break;
      }
      case "call": {
        const path = String(e.path ?? "");
        const method = String(e.method ?? "GET").toUpperCase();
        const status = num(e.status) ?? 200;
        const req = (e.req ?? {}) as Record<string, unknown>;
        const res = (e.res ?? {}) as Record<string, unknown>;
        if (method === "POST" && /beneficiar(y|ies)\/create/.test(path) && status < 300 && typeof res.id === "string") {
          this.newAccounts.set(res.id, at);
        }
        if (method === "GET" && /beneficiar/.test(path) && Array.isArray((res as { items?: unknown[] }).items)) {
          for (const b of (res as { items: { id?: string }[] }).items) if (b.id) this.knownAccounts.add(b.id);
        }
        if (method !== "POST" || !MONEY_PATH.test(path) || status >= 300) break;

        const amount = num(req.amount) ?? num(req.transfer_amount) ?? num(req.payment_amount) ?? num(res.amount) ?? 0;
        const counterparty = norm(req.beneficiary_id) ?? norm(req.counterparty) ?? norm(req.payment_intent_id) ?? norm(path.split("/")[path.split("/").indexOf("payment_intents") + 1]);
        const pay: Payment = { at, path, requestId: req.request_id as string | undefined, amount, currency: norm(req.currency ?? req.transfer_currency), counterparty, run };

        // 1. Same request id paid twice, or same amount to same counterparty twice in 10 minutes
        if (pay.requestId && this.seenRequestIds.has(pay.requestId)) {
          out.push({ source: "finance", rule: "FIN-DOUBLE-PAY", severity: "critical", where, key: `${run}:double:${pay.requestId}`,
            title: "Same payment request sent twice and accepted twice",
            detail: `request_id ${pay.requestId} was accepted again (${amount} ${pay.currency?.toUpperCase() ?? ""}). The API should have rejected the repeat; check whether money left twice.`,
            fix: "Check the provider for two settled payments and recall the second." });
          return out; // the first attempt was already checked; the repeat is the finding
        } else {
          const dup = this.payments.find((p) => p.amount === amount && amount > 0 && p.counterparty === counterparty && counterparty && p.requestId !== pay.requestId && at - p.at < 10 * 60_000);
          if (dup) out.push({ source: "finance", rule: "FIN-DUPLICATE-AMOUNT", severity: "high", where, key: `${run}:dup:${pay.requestId}`,
            title: "Two identical payments to the same counterparty within 10 minutes",
            detail: `${amount} ${pay.currency?.toUpperCase() ?? ""} to ${counterparty} twice, with different request ids (${dup.requestId ?? "none"} and ${pay.requestId ?? "none"}). A restart that made a new id can pay twice.`,
            fix: "Derive request ids from the business event (invoice or case), not from the clock." });
        }
        if (pay.requestId) this.seenRequestIds.set(pay.requestId, pay);
        if (!pay.requestId) out.push({ source: "finance", rule: "FIN-NO-IDEMPOTENCY", severity: "medium", where, key: `${run}:noid:${at}`,
          title: "Payment sent without an idempotency key", detail: `${method} ${path} for ${amount} carried no request_id.`, fix: "Send a request_id on every money-moving call." });

        // 2. Above what a person approved
        if (amount > this.cfg.autoLimit) {
          const ok = this.approvals.filter((a) => a.approved && a.at <= at && at - a.at < 24 * 3600_000);
          const covering = ok.find((a) => amount <= a.amount + 0.005 && (!a.currency || !pay.currency || a.currency === pay.currency));
          if (!ok.length) out.push({ source: "finance", rule: "FIN-UNAPPROVED", severity: "high", where, key: `${run}:unapproved:${pay.requestId ?? at}`,
            title: `Payment above the ${this.cfg.autoLimit} auto-limit with no approval`,
            detail: `${amount} ${pay.currency?.toUpperCase() ?? ""} via ${path} with no approval recorded before it in this run.`,
            fix: "Hold the payment and confirm with the owner of the run." });
          else if (!covering) out.push({ source: "finance", rule: "FIN-OVER-APPROVED", severity: "critical", where, key: `${run}:over:${pay.requestId ?? at}`,
            title: "Paid more than a person approved",
            detail: `${amount} ${pay.currency?.toUpperCase() ?? ""} paid; the largest approval before it was ${Math.max(...ok.map((a) => a.amount))}.`,
            fix: "Stop the agent, recall the difference, and check why the terms changed after approval." });
        }

        // 3. A new account, paid soon after reading planted instructions
        if (counterparty && this.newAccounts.has(counterparty) && !this.knownAccounts.has(counterparty)) {
          const created = this.newAccounts.get(counterparty)!;
          const recentInjection = this.injectionsAt.some((t) => t <= at && at - t < this.cfg.taintWindowMs);
          out.push({ source: "finance", rule: recentInjection ? "FIN-TAINTED-PAYEE" : "FIN-NEW-PAYEE",
            severity: recentInjection ? "critical" : "medium", where, key: `${run}:payee:${counterparty}`,
            title: recentInjection ? "Money sent to a new account right after the agent read planted instructions" : "Payment to an account created in this run",
            detail: `${amount} ${pay.currency?.toUpperCase() ?? ""} to ${counterparty}, created ${Math.round((at - created) / 1000)} s before.${recentInjection ? " The agent read outside text with injected instructions just before." : ""}`,
            fix: recentInjection ? "Recall the payment now and confirm the account by phone with a number you already had." : "Confirm the new account with the counterparty through a known channel." });
        }

        // 4. Velocity
        this.payments.push(pay);
        const recent = this.payments.filter((p) => at - p.at < this.cfg.velocityWindowMs);
        if (recent.length === this.cfg.velocityCount + 1) out.push({ source: "finance", rule: "FIN-VELOCITY", severity: "high", where, key: `${run}:velocity`,
          title: `More than ${this.cfg.velocityCount} payments in ${this.cfg.velocityWindowMs / 1000} s`,
          detail: `${recent.length} payments totalling ${recent.reduce((s, p) => s + p.amount, 0).toFixed(2)} in the window. Agents in a loop and attackers both look like this.`,
          fix: "Pause the agent's payment rights until someone checks the run." });
        break;
      }
      case "llm_extract_rejected":
        out.push({ source: "llm", rule: "LLM-OUTPUT-REJECTED", severity: "low", where,
          title: "Model output failed validation and was not used",
          detail: "The agent's schema check rejected what the model returned and fell back to rules. Working as designed; repeated rejections can mean the model is being steered.",
          fix: "No action unless it repeats in many runs." });
        break;
    }
    return out;
  }
}

export function scanLog(lines: string, run = "run", cfg = DEFAULT_FLOW): Finding[] {
  const m = new FinanceMonitor(cfg);
  const out: Finding[] = [];
  for (const line of lines.split("\n")) {
    if (!line.trim()) continue;
    try { out.push(...m.ingest(JSON.parse(line), run)); } catch { /* skip partial lines */ }
  }
  return out;
}
