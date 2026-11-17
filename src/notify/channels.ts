/**
 * Alert fan-out beyond email: Slack, PagerDuty and Amazon SNS.
 *
 *   SLACK_WEBHOOK_URL       Slack incoming webhook
 *   PAGERDUTY_ROUTING_KEY   PagerDuty Events API v2 integration key (pages on-call; "Mark as handled" acknowledges)
 *   SNS_TOPIC_ARN           Amazon SNS topic (fan out to SMS, email, Lambda, chat), uses the AWS credentials present
 *   NOTIFY_MIN              lowest severity sent (default high)
 *
 * Each channel gets each alert once (the AlertBus already removes repeats). A failed send
 * is reported on the dashboard and never blocks detection.
 */
import type { Alert, AlertBus, Severity } from "../alerts.ts";
import { rank } from "../alerts.ts";

const LABEL: Record<Severity, string> = { critical: "Act now", high: "Today", medium: "This week", low: "When convenient", info: "For information" };
const PD_SEV: Record<Severity, string> = { critical: "critical", high: "error", medium: "warning", low: "info", info: "info" };

export interface ChannelConfig { slack?: string; pagerduty?: string; snsTopic?: string; min: Severity; dashboardUrl: string }
export const channelsFromEnv = (): ChannelConfig => ({
  slack: process.env.SLACK_WEBHOOK_URL, pagerduty: process.env.PAGERDUTY_ROUTING_KEY, snsTopic: process.env.SNS_TOPIC_ARN,
  min: (process.env.NOTIFY_MIN as Severity) ?? "high", dashboardUrl: process.env.DASHBOARD_URL ?? `http://localhost:${process.env.PORT ?? 4600}`,
});
export const enabledChannels = (c: ChannelConfig) => [c.slack && "Slack", c.pagerduty && "PagerDuty", c.snsTopic && "Amazon SNS"].filter(Boolean) as string[];

export function slackMessage(a: Alert, url: string) {
  return {
    text: `${LABEL[a.severity]}: ${a.title}`,
    blocks: [
      { type: "section", text: { type: "mrkdwn", text: `*${LABEL[a.severity]} · ${a.source}*\n*${a.title}*\n${a.detail}` } },
      ...(a.fix ? [{ type: "section", text: { type: "mrkdwn", text: `*What to do:* ${a.fix}` } }] : []),
      { type: "context", elements: [{ type: "mrkdwn", text: `${a.where ? `${a.where} · ` : ""}rule ${a.rule} · <${url}|Open Agent Shield>` }] },
    ],
  };
}

export function pagerDutyEvent(a: Alert, key: string, action: "trigger" | "acknowledge" = "trigger") {
  return action === "trigger"
    ? { routing_key: key, event_action: "trigger", dedup_key: `agent-shield-${a.id}`,
        payload: { summary: `${a.title}`.slice(0, 1024), source: a.where ?? "agent-shield", severity: PD_SEV[a.severity], component: a.source, class: a.rule, custom_details: { detail: a.detail, fix: a.fix } } }
    : { routing_key: key, event_action: "acknowledge", dedup_key: `agent-shield-${a.id}` };
}

export function attachChannels(bus: AlertBus, cfg: ChannelConfig, opts: { fetch?: typeof fetch; publishSns?: (topic: string, subject: string, message: string) => Promise<void> } = {}) {
  const f = opts.fetch ?? fetch;
  let sns = opts.publishSns;
  const post = async (name: string, url: string, body: unknown) => {
    try {
      const r = await f(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      if (!r.ok) throw new Error(`${r.status} ${(await r.text()).slice(0, 120)}`);
      bus.emit("notified", { channel: name });
    } catch (e) { bus.emit("notify_error", { channel: name, error: (e as Error).message }); }
  };
  bus.on("alert", async (a: Alert) => {
    if (rank(a.severity) < rank(cfg.min)) return;
    if (cfg.slack) post("Slack", cfg.slack, slackMessage(a, cfg.dashboardUrl));
    if (cfg.pagerduty) post("PagerDuty", "https://events.pagerduty.com/v2/enqueue", pagerDutyEvent(a, cfg.pagerduty));
    if (cfg.snsTopic) {
      try {
        if (!sns) {
          const { SNSClient, PublishCommand } = await import("@aws-sdk/client-sns");
          const client = new SNSClient({ region: cfg.snsTopic.split(":")[3] });
          sns = async (topic, subject, message) => { await client.send(new PublishCommand({ TopicArn: topic, Subject: subject.slice(0, 99), Message: message })); };
        }
        await sns(cfg.snsTopic, `[${LABEL[a.severity]}] ${a.title}`, `${a.title}\n\n${a.detail}\n\nWhat to do: ${a.fix ?? "-"}\nWhere: ${a.where ?? "-"}\nRule: ${a.rule}\n${cfg.dashboardUrl}`);
        bus.emit("notified", { channel: "Amazon SNS" });
      } catch (e) { bus.emit("notify_error", { channel: "Amazon SNS", error: (e as Error).message }); }
    }
  });
  bus.on("ack", (a: Alert) => { if (cfg.pagerduty && rank(a.severity) >= rank(cfg.min)) post("PagerDuty", "https://events.pagerduty.com/v2/enqueue", pagerDutyEvent(a, cfg.pagerduty, "acknowledge")); });
}
