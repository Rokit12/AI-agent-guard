/**
 * garak integration (NVIDIA's LLM vulnerability scanner).
 *
 * garak is Python and ships hundreds of probes (prompt injection, encoding tricks, jailbreak
 * families, prompt leakage). Agent Shield points it at an HTTP endpoint that wraps the
 * target's real document-reading prompt (src/integrations/agent-endpoint.ts), then reads
 * garak's report and turns failed probes into alerts.
 *
 *   npm run garak:endpoint                    # serve the agent prompt on :4610
 *   python -m garak --model_type rest -G redteam/garak-rest.json \
 *     --probes promptinject,encoding,latentinjection --report_prefix agent-desk
 *   npm run garak:import -- ~/.local/share/garak/garak_runs/agent-desk.report.jsonl
 */
import { readFileSync } from "node:fs";
import type { Finding, Severity } from "../alerts.ts";

export interface GarakResult { probe: string; detector: string; passed: number; total: number }

/** garak writes JSON lines; entries with entry_type "eval" hold pass counts per probe and detector. */
export function parseGarakReport(jsonl: string): { model?: string; results: GarakResult[] } {
  let model: string | undefined;
  const results: GarakResult[] = [];
  for (const line of jsonl.split("\n")) {
    if (!line.trim()) continue;
    let e: any;
    try { e = JSON.parse(line); } catch { continue; }
    if (e.entry_type === "start_run setup") model = e["plugins.target_name"] ?? e["plugins.model_name"] ?? e["plugins.target_type"] ?? e["plugins.model_type"] ?? model;
    if (e.entry_type === "eval") {
      // garak ≥ 0.13 reports total_evaluated and fails; older versions report total
      const passed = Number(e.passed ?? 0);
      const total = Number(e.total ?? e.total_evaluated ?? passed + Number(e.fails ?? 0));
      results.push({ probe: String(e.probe), detector: String(e.detector), passed, total });
    }
  }
  return { model, results };
}

const severityFor = (probe: string, failRate: number): Severity => {
  const serious = /promptinject|latentinjection|xss|packagehallucination|exploitation/i.test(probe);
  if (failRate >= 0.5) return serious ? "critical" : "high";
  if (failRate >= 0.1) return serious ? "high" : "medium";
  return "low";
};

export function garakFindings(jsonl: string, source = "garak"): Finding[] {
  const { model, results } = parseGarakReport(jsonl);
  return results.filter((r) => r.total > 0 && r.passed < r.total).map((r) => {
    const failRate = (r.total - r.passed) / r.total;
    return {
      source: "llm" as const, rule: `LLM-GARAK-${r.probe.split(".")[0].toUpperCase()}`, severity: severityFor(r.probe, failRate),
      where: `${source} · ${model ?? "model"}`, key: `garak:${model}:${r.probe}:${r.detector}`,
      title: `garak: ${r.probe} got through ${Math.round(failRate * 100)}% of the time`,
      detail: `${r.total - r.passed} of ${r.total} attempts failed the ${r.detector} check.`,
      fix: "Read the failing attempts in garak's hitlog, add the pattern to the injection guard, and keep the model away from amounts and accounts.",
      evidence: { probe: r.probe, detector: r.detector, passed: r.passed, total: r.total },
    };
  });
}

export const readGarakFindings = (path: string) => garakFindings(readFileSync(path, "utf8"), path.split("/").pop());
