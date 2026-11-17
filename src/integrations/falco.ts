/**
 * Falco runtime alerts.
 *
 * Agent Shield's ransomware detector sees files change; Falco (CNCF, eBPF) sees the system
 * calls behind them, so it can name the process, user and container doing the writes.
 * Falco posts each alert as one JSON object (json_output: true) either to
 * POST /api/ingest/falco (http_output) or into logs/falco/*.jsonl (file_output).
 * Falco's own fields: time, rule, priority, output, hostname, source, tags, output_fields.
 *
 * Repeats of the same rule by the same process on the same host grow one alert (with a
 * count) instead of raising hundreds.
 */
import type { Finding, Severity } from "../alerts.ts";

export interface FalcoAlert { time?: string; rule?: string; priority?: string; output?: string; hostname?: string; source?: string; tags?: string[]; output_fields?: Record<string, unknown> }

const PRIORITY: Record<string, Severity> = { emergency: "critical", alert: "critical", critical: "critical", error: "high", warning: "medium", notice: "low", informational: "info", info: "info", debug: "info" };

export class FalcoFeed {
  private counts = new Map<string, number>();
  received = 0;

  ingest(a: FalcoAlert): Finding[] {
    if (!a || !a.rule) return [];
    this.received++;
    const f = a.output_fields ?? {};
    const proc = String(f["proc.name"] ?? "unknown process"), pid = f["proc.pid"], user = f["user.name"], container = f["container.name"] ?? f["container.id"];
    const file = f["fd.name"] ?? f["evt.arg.newpath"] ?? f["fs.path.target"];
    const host = a.hostname ?? "host";
    const ours = (a.tags ?? []).includes("agent_shield");
    const ransom = (a.tags ?? []).some((t) => /ransomware|mitre_impact/.test(t));
    let severity = PRIORITY[String(a.priority ?? "warning").toLowerCase()] ?? "medium";
    if (ransom && severity !== "critical") severity = "high";
    const key = `falco:${host}:${a.rule}:${proc}`;
    const n = (this.counts.get(key) ?? 0) + 1; this.counts.set(key, n);
    return [{
      source: ransom ? "ransomware" : "system", rule: ransom ? "RANSOM-PROCESS" : "FALCO-RUNTIME", severity, key,
      where: `${host}${container && container !== "host" ? ` · container ${container}` : ""}`,
      title: ransom ? `${proc} is behind it: ${a.rule}${n > 1 ? ` (${n} events)` : ""}` : `Falco: ${a.rule}${n > 1 ? ` (${n} events)` : ""}`,
      detail: `${a.output ?? a.rule}${pid !== undefined ? ` · pid ${pid}` : ""}${user ? ` · user ${user}` : ""}${file ? ` · file ${file}` : ""}.`,
      fix: ransom ? `Isolate ${host}${container ? ` (or stop container ${container})` : ""} and kill ${proc}${pid !== undefined ? ` (pid ${pid})` : ""}, then restore the folder from the locked backup.`
        : ours ? "Check why this process touched agent files; block it if it is not part of the deployment." : "Review the event in Falco and tune the rule if it is expected.",
      evidence: { falcoRule: a.rule, priority: a.priority, count: n, time: a.time },
    }];
  }
}
