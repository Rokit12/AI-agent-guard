/**
 * Emails the support team about high and critical alerts.
 * With SMTP_URL set (smtp://user:pass@host:587) the mail is sent; without it, each
 * message is written to outbox/ as an .eml file, so a demo never needs a mail server.
 * Repeats are already removed by the AlertBus; this also batches bursts (one mail per
 * 30 s window), so a ransomware incident does not send a hundred emails.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import nodemailer from "nodemailer";
import type { Alert, AlertBus, Severity } from "../alerts.ts";
import { rank } from "../alerts.ts";

export interface EmailConfig {
  to: string;
  from: string;
  smtpUrl?: string;
  minSeverity: Severity;
  batchMs: number;
  outbox: string;
  dashboardUrl?: string;
}

export function emailConfigFromEnv(): EmailConfig {
  return {
    to: process.env.ALERT_EMAIL_TO ?? "security-team@example.com",
    from: process.env.ALERT_EMAIL_FROM ?? "agent-shield@example.com",
    smtpUrl: process.env.SMTP_URL,
    minSeverity: (process.env.ALERT_EMAIL_MIN as Severity) ?? "high",
    batchMs: Number(process.env.ALERT_EMAIL_BATCH_MS ?? 30_000),
    outbox: join(process.cwd(), "outbox"),
    dashboardUrl: process.env.DASHBOARD_URL ?? `http://localhost:${process.env.PORT ?? 4600}`,
  };
}

const LABEL: Record<Severity, string> = { info: "INFO", low: "LOW", medium: "MEDIUM", high: "HIGH", critical: "CRITICAL" };

export function composeEmail(alerts: Alert[], cfg: EmailConfig) {
  const top = alerts.reduce((m, a) => (rank(a.severity) > rank(m.severity) ? a : m), alerts[0]);
  const subject = alerts.length === 1
    ? `[${LABEL[top.severity]}] ${top.title}`
    : `[${LABEL[top.severity]}] ${alerts.length} security alerts: ${top.title}`;
  const text = [
    `Agent Shield raised ${alerts.length} alert${alerts.length > 1 ? "s" : ""} that need${alerts.length > 1 ? "" : "s"} attention.`,
    "",
    ...alerts.flatMap((a) => [
      `${LABEL[a.severity]} · ${a.title}`,
      `  ${a.detail}`,
      ...(a.where ? [`  Where: ${a.where}`] : []),
      ...(a.fix ? [`  Do: ${a.fix}`] : []),
      `  Rule ${a.rule} · ${a.at}`,
      "",
    ]),
    `Open the dashboard: ${cfg.dashboardUrl}`,
  ].join("\n");
  return { subject, text };
}

export function attachEmail(bus: AlertBus, cfg = emailConfigFromEnv()) {
  const transport = cfg.smtpUrl ? nodemailer.createTransport(cfg.smtpUrl) : null;
  let pending: Alert[] = [];
  let timer: NodeJS.Timeout | null = null;

  const flush = async () => {
    timer = null;
    const batch = pending; pending = [];
    if (!batch.length) return;
    const { subject, text } = composeEmail(batch, cfg);
    try {
      if (transport) {
        await transport.sendMail({ from: cfg.from, to: cfg.to, subject, text });
      } else {
        mkdirSync(cfg.outbox, { recursive: true });
        const eml = `From: ${cfg.from}\nTo: ${cfg.to}\nSubject: ${subject}\nDate: ${new Date().toUTCString()}\nContent-Type: text/plain; charset=utf-8\n\n${text}\n`;
        writeFileSync(join(cfg.outbox, `${Date.now()}-${batch[0].id}.eml`), eml);
      }
      bus.emit("emailed", { to: cfg.to, subject, count: batch.length, delivered: Boolean(transport) });
    } catch (err) {
      bus.emit("email_error", { error: (err as Error).message });
    }
  };

  bus.on("alert", (a: Alert) => {
    if (rank(a.severity) < rank(cfg.minSeverity)) return;
    pending.push(a);
    // Critical goes out at once; high waits for the batch window.
    if (a.severity === "critical") { if (timer) clearTimeout(timer); timer = setTimeout(flush, 1500); }
    else if (!timer) timer = setTimeout(flush, cfg.batchMs);
  });
  return { flush };
}
