/**
 * Runs the static checks against a target agent codebase: code scan, repo hygiene,
 * access-control audit, and the prompt-injection probes against the target's guard.
 */
import { resolve, join } from "node:path";
import { existsSync } from "node:fs";
import { pathToFileURL } from "node:url";
import type { Finding } from "./alerts.ts";
import { loadSources, scanCode, scanRepoHygiene } from "./detectors/code-scan.ts";
import { auditAccess } from "./detectors/access-control.ts";
import { runProbes, probeFindings, probeSummary, hardenGuard, type Guard } from "./detectors/llm-probes.ts";

export interface Target { name: string; dir: string; guard?: string; runs: string }

export function targetFromEnv(): Target {
  const dir = resolve(process.env.TARGET_DIR ?? join(process.cwd(), "..", "airwallex"));
  return {
    name: process.env.TARGET_NAME ?? "Airwallex Agent Desk",
    dir,
    guard: process.env.TARGET_GUARD ?? "src/core/untrusted.ts#screenUntrusted",
    runs: resolve(process.env.TARGET_RUNS ?? join(dir, "runs")),
  };
}

export async function loadGuard(t: Target): Promise<Guard | null> {
  if (!t.guard) return null;
  const [file, name = "default"] = t.guard.split("#");
  const p = join(t.dir, file);
  if (!existsSync(p)) return null;
  const mod = await import(pathToFileURL(p).href);
  return typeof mod[name] === "function" ? (mod[name] as Guard) : null;
}

export interface ScanReport {
  target: Target; at: string; files: number; findings: Finding[];
  probes?: ReturnType<typeof probeSummary> & { hardened: ReturnType<typeof probeSummary> };
}

export async function scanTarget(t: Target): Promise<ScanReport> {
  if (!existsSync(t.dir)) throw new Error(`target folder not found: ${t.dir}`);
  const files = loadSources(t.dir);
  const findings: Finding[] = [...scanCode(files), ...scanRepoHygiene(t.dir), ...auditAccess(files)];
  const report: ScanReport = { target: t, at: new Date().toISOString(), files: files.length, findings };
  const guard = await loadGuard(t);
  if (guard) {
    const results = runProbes(guard);
    findings.push(...probeFindings(results, `${t.guard}`));
    report.probes = { ...probeSummary(results), hardened: probeSummary(runProbes(hardenGuard(guard))) };
  }
  return report;
}
