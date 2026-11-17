/**
 * Semgrep taint analysis for the agent's code (rules in rules/semgrep/).
 *
 * The built-in code scanner matches patterns inside one call. Semgrep's taint mode follows
 * data across a function: from what the model extracted, or from an email body, to the
 * amount or payee of a money-moving call. Runs when the semgrep CLI is installed
 * (pip install semgrep); otherwise the code scan says so and carries on.
 */
import { execFile, execFileSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { Finding, Severity } from "../alerts.ts";

export const SEMGREP_RULES = join(import.meta.dirname, "..", "..", "rules", "semgrep");
const BIN = process.env.SEMGREP_BIN ?? "semgrep";
// No update check or metrics: offline-safe, and the check alone can take over a minute behind a proxy.
const ENV = { ...process.env, SEMGREP_ENABLE_VERSION_CHECK: "0", SEMGREP_SEND_METRICS: "off" };

export function semgrepAvailable(): string | null {
  try { return execFileSync(BIN, ["--version"], { encoding: "utf8", timeout: 20_000, env: ENV }).trim(); } catch { return null; }
}

interface SgResult { check_id: string; path: string; start: { line: number }; extra: { message: string; severity: string; metadata?: Record<string, unknown> } }

/** Turn Semgrep JSON into findings. An approval call just before the sink lowers a payment finding to low: a person saw the value. */
export function semgrepFindings(json: string, dir: string): Finding[] {
  let d: { results?: SgResult[] } = {};
  try { d = JSON.parse(json); } catch { return []; }
  return (d.results ?? []).map((r) => {
    const id = r.check_id.split(".").pop()!;
    let severity = (r.extra.metadata?.["agent-shield-severity"] as Severity) ?? (r.extra.severity === "ERROR" ? "high" : "medium");
    let note = "";
    if (id === "agent-model-output-to-payment") {
      const file = join(dir, r.path);
      const before = existsSync(file) ? readFileSync(file, "utf8").split("\n").slice(Math.max(0, r.start.line - 12), r.start.line).join("\n") : "";
      if (/requestApproval\(|approve\(/.test(before)) { severity = "low"; note = " A person approves the payment just before this call; confirm the approval shows this exact amount and payee."; }
    }
    return {
      source: "code" as const, rule: `SEMGREP-${id.toUpperCase()}`, severity, where: `${r.path}:${r.start.line}`,
      title: id === "agent-model-output-to-payment" ? "Model-extracted data flows into a payment"
        : id === "untrusted-text-to-payee" ? "Email or document text flows into a payee"
        : id === "secret-to-log" ? "A secret flows into a log" : `Semgrep: ${id}`,
      detail: r.extra.message.trim() + note,
      fix: id === "secret-to-log" ? "Log a fingerprint or the last 4 characters, never the value." : "Recompute amounts in code from records, take payees from accounts on file, and gate the call on an approval of the exact values.",
      evidence: { semgrepRule: id },
    };
  });
}

export function runSemgrep(dir: string): Promise<{ findings: Finding[]; version: string | null; error?: string }> {
  const version = semgrepAvailable();
  if (!version) return Promise.resolve({ findings: [], version: null, error: "semgrep is not installed (pip install semgrep)" });
  return new Promise((resolve) => {
    execFile(BIN, ["scan", "--config", SEMGREP_RULES, "--json", "--quiet", "--metrics=off", "--exclude", "node_modules", "--exclude", "dist", "--exclude", "cdk.out", "."],
      { cwd: dir, env: ENV, maxBuffer: 50_000_000, timeout: 600_000 }, (err, stdout) => {
        if (!stdout && err) return resolve({ findings: [], version, error: err.message.slice(0, 200) });
        resolve({ findings: semgrepFindings(stdout, dir), version });
      });
  });
}
