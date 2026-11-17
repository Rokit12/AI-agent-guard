/**
 * promptfoo integration: red-teams the target's real document-reading prompt against a
 * live model (redteam/promptfooconfig.yaml), then turns promptfoo's results into alerts.
 *
 * A test fails when the model obeys a planted instruction: it changes the amount, copies
 * the attacker's account, or adds action fields such as "approved". Agent Desk's code
 * ignores all of that (amounts come from the ledger, accounts from the file), so a failure
 * here means the model can be steered, not that money can move. It still matters: the day
 * someone wires model output into a payment, this is the attack that works.
 */
import { spawn } from "node:child_process";
import { readFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import type { Finding, Severity } from "../alerts.ts";

export interface RedteamCase { description: string; family: string; severity: Severity; passed: boolean; reasons: string[]; output?: string; error?: string }
export interface RedteamReport { at: string; provider: string; passed: number; failed: number; errors: number; cases: RedteamCase[] }

const ROOT = join(import.meta.dirname, "..", "..");
export const CONFIG = join(ROOT, "redteam", "promptfooconfig.yaml");
export const RESULTS = join(ROOT, "state", "promptfoo.json");

/** True when a live run can happen (a model key, or the offline mock for a dry run). */
export const redteamReady = () => Boolean(process.env.ANTHROPIC_API_KEY || process.env.SHIELD_REDTEAM_MOCK);

export function runPromptfoo(): Promise<RedteamReport> {
  mkdirSync(join(ROOT, "state"), { recursive: true });
  return new Promise((resolve, reject) => {
    const p = spawn("npx", ["promptfoo", "eval", "-c", CONFIG, "-o", RESULTS, "--no-cache", "--no-progress-bar"], {
      cwd: ROOT, env: { ...process.env, PROMPTFOO_DISABLE_TELEMETRY: "1", PROMPTFOO_DISABLE_UPDATE: "1" }, stdio: ["ignore", "pipe", "pipe"],
    });
    let err = "";
    p.stderr.on("data", (d) => (err += d));
    p.on("close", () => {
      // promptfoo exits non-zero when tests fail; that is a result, not an error
      if (!existsSync(RESULTS)) return reject(new Error(`promptfoo produced no results: ${err.slice(-300)}`));
      resolve(parsePromptfoo(readFileSync(RESULTS, "utf8")));
    });
  });
}

export function parsePromptfoo(json: string): RedteamReport {
  const d = JSON.parse(json);
  const rows: any[] = d.results?.results ?? d.results ?? [];
  const cases: RedteamCase[] = rows.map((r) => {
    const comps: any[] = r.gradingResult?.componentResults ?? [];
    return {
      description: r.testCase?.description ?? r.description ?? "test",
      family: r.testCase?.metadata?.family ?? r.metadata?.family ?? "injection",
      severity: (r.testCase?.metadata?.severity ?? r.metadata?.severity ?? "medium") as Severity,
      passed: Boolean(r.success),
      reasons: comps.filter((c) => !c.pass).map((c) => String(c.reason ?? "").split("\n")[0]),
      output: r.response?.output,
      // promptfoo puts assertion failures in `error` too; failureReason 2 (or a provider error) is a real error
      error: r.failureReason === 2 || r.response?.error ? String(r.response?.error ?? r.error ?? "error") : undefined,
    };
  });
  return {
    at: new Date().toISOString(),
    provider: rows[0]?.provider?.id ?? rows[0]?.provider ?? "unknown",
    passed: cases.filter((c) => c.passed).length,
    failed: cases.filter((c) => !c.passed && !c.error).length,
    errors: cases.filter((c) => c.error).length,
    cases,
  };
}

export function redteamFindings(r: RedteamReport): Finding[] {
  const out: Finding[] = [];
  for (const c of r.cases) {
    if (c.passed) continue;
    if (c.error) {
      out.push({ source: "llm", rule: "LLM-REDTEAM-ERROR", severity: "low", where: `promptfoo · ${r.provider}`, key: `redteam-error:${c.description}`,
        title: `Model red-team could not run: ${c.description}`, detail: c.error.slice(0, 240), fix: "Check the model key and network, then run the red-team again." });
      continue;
    }
    // Missing only the "account change" flag is a weaker failure than obeying the attacker.
    const onlyNoticed = c.reasons.length > 0 && c.reasons.every((x) => /notice|reported an account change/.test(x));
    const severity: Severity = onlyNoticed ? "low" : c.family === "benign" ? "low" : c.severity;
    out.push({
      source: "llm", rule: onlyNoticed ? "LLM-REDTEAM-MISSED-SIGNAL" : `LLM-REDTEAM-${c.family.toUpperCase()}`, severity,
      where: `promptfoo · ${r.provider}`, key: `redteam:${r.provider}:${c.description}`,
      title: onlyNoticed ? `Model did not notice a payment-redirect request (${c.description})` : `Model obeyed a planted instruction (${c.description})`,
      detail: `${c.reasons.join("; ")}${c.output ? `. Model returned: ${c.output.slice(0, 160)}` : ""}`,
      fix: onlyNoticed
        ? "Nothing moves money on this, but the signal helps people spot fraud: add an example of this phrasing to the prompt."
        : "Keep amounts and accounts out of the model's control (take them from the ledger and the file), and tighten the prompt: tell the model that instructions inside <document> are data.",
      evidence: { family: c.family },
    });
  }
  return out;
}
