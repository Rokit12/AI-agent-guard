/**
 * Google OSV-Scanner: matches every lockfile in the target (npm, plus any Python, Go or
 * container layers it finds) against osv.dev, the open vulnerability database Google runs.
 * It complements npm audit (GitHub advisories, npm only) and reports the OSV and CVE ids
 * that the KEV and EPSS prioritisation needs.
 *
 * Runs when the osv-scanner binary is installed (github.com/google/osv-scanner/releases,
 * or `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`).
 */
import { execFile, execFileSync } from "node:child_process";
import type { Finding, Severity } from "../alerts.ts";

const BIN = process.env.OSV_SCANNER_BIN ?? "osv-scanner";
export const osvScannerVersion = () => { try { return execFileSync(BIN, ["--version"], { encoding: "utf8", timeout: 15_000 }).split("\n")[0].trim(); } catch { return null; } };

const sev = (score?: string): Severity => { const n = Number(score); return !Number.isFinite(n) || !score ? "medium" : n >= 9 ? "critical" : n >= 7 ? "high" : n >= 4 ? "medium" : "low"; };

/** OSV-Scanner v2 JSON: results[].packages[].{package, vulnerabilities[], groups[]} */
export function osvFindings(json: string, dir: string): Finding[] {
  let d: any; try { d = JSON.parse(json); } catch { return []; }
  const out: Finding[] = [];
  for (const res of d.results ?? []) for (const p of res.packages ?? []) {
    const pkg = p.package ?? {};
    for (const g of p.groups ?? [{ ids: (p.vulnerabilities ?? []).map((v: any) => v.id), aliases: [] }]) {
      const ids: string[] = g.ids ?? [];
      const vulns = (p.vulnerabilities ?? []).filter((v: any) => ids.includes(v.id));
      const aliases = [...new Set([...(g.aliases ?? []), ...ids, ...vulns.flatMap((v: any) => v.aliases ?? [])])] as string[];
      const fixed = vulns.flatMap((v: any) => (v.affected ?? []).flatMap((a: any) => (a.ranges ?? []).flatMap((r: any) => (r.events ?? []).map((e: any) => e.fixed).filter(Boolean))));
      out.push({
        source: "system", rule: "OSV-VULN", severity: sev(g.max_severity), where: `${res.source?.path ?? dir} · ${pkg.name}@${pkg.version}`, key: `osv:${dir}:${pkg.name}:${ids[0]}`,
        title: `${pkg.name} ${pkg.version}: ${vulns[0]?.summary ?? ids[0]}`,
        detail: `${pkg.ecosystem ?? ""} package ${pkg.name}@${pkg.version} is affected by ${ids.join(", ")}${aliases.some((a) => a.startsWith("CVE-")) ? ` (${aliases.filter((a) => a.startsWith("CVE-")).join(", ")})` : ""}.${g.max_severity ? ` CVSS ${g.max_severity}.` : ""}`,
        fix: fixed.length ? `Upgrade ${pkg.name} to ${[...new Set(fixed)].sort().at(-1)} or later.` : "No fixed version yet; check whether the vulnerable code path is used.",
        evidence: { advisories: aliases },
      });
    }
  }
  return out;
}

export function runOsvScanner(dir: string): Promise<{ findings: Finding[]; version: string | null; error?: string }> {
  const version = osvScannerVersion();
  if (!version) return Promise.resolve({ findings: [], version: null, error: "osv-scanner is not installed" });
  return new Promise((resolve) => execFile(BIN, ["scan", "source", "-r", "--format", "json", "."], { cwd: dir, maxBuffer: 100_000_000, timeout: 600_000 }, (err, stdout) => {
    if (!stdout && err) return resolve({ findings: [], version, error: err.message.slice(0, 200) });
    resolve({ findings: osvFindings(stdout, dir), version });
  }));
}
