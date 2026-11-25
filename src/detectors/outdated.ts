/**
 * Outdated-software scan: old and unsupported components that stop getting security fixes.
 *
 *  - npm packages the agent depends on directly: deprecated versions, two or more major
 *    versions behind, or no release for over two years (read from the npm registry)
 *  - runtimes past end of life, by date: Node.js on this host, Docker base images and
 *    AWS Lambda runtimes in the code, and the host operating system
 *
 * Known vulnerabilities in packages are covered by the Software packages scan; this one
 * finds the old components where the next vulnerability will never be fixed.
 */
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import { join, basename, relative, resolve } from "node:path";
import type { Finding, Severity } from "../alerts.ts";

/** End-of-life dates (last day of security fixes). */
export const NODE_EOL: Record<number, string> = { 12: "2022-04-30", 14: "2023-04-30", 16: "2023-09-11", 18: "2025-04-30", 20: "2026-04-30", 22: "2027-04-30", 24: "2028-04-30", 26: "2029-04-30" };
export const OS_EOL: Record<string, string> = { "ubuntu 16.04": "2021-04-30", "ubuntu 18.04": "2023-05-31", "ubuntu 20.04": "2025-05-31", "ubuntu 22.04": "2027-06-30", "ubuntu 24.04": "2029-06-30",
  "debian 9": "2022-06-30", "debian 10": "2024-06-30", "debian 11": "2026-08-31", "debian 12": "2028-06-30", "amzn 2": "2026-06-30", "amzn 2023": "2029-06-30", "alpine 3.17": "2024-11-22", "alpine 3.18": "2025-05-09", "alpine 3.19": "2025-11-01", "alpine 3.20": "2026-04-01" };
export const PY_EOL: Record<string, string> = { "3.7": "2023-06-27", "3.8": "2024-10-07", "3.9": "2025-10-31", "3.10": "2026-10-31", "3.11": "2027-10-31", "3.12": "2028-10-31" };

export function nodeStatus(major: number, now = new Date()) {
  const eol = NODE_EOL[major] ?? (major % 2 === 1 ? "odd" : undefined);
  if (eol === "odd") return { eol: true, date: "short-lived odd release" };
  if (!eol) return { eol: major < 12, date: major < 12 ? "long ago" : "unknown" };
  return { eol: new Date(eol) < now, date: eol, soon: !(new Date(eol) < now) && new Date(eol).getTime() - now.getTime() < 120 * 864e5 };
}

const major = (v: string) => Number(/^(\d+)/.exec(v.replace(/^[^\d]*/, ""))?.[1] ?? NaN);
const DAY = 864e5;

export interface PkgMeta { latest: string; latestDate?: string; deprecated?: Record<string, string>; time?: Record<string, string> }

/** Decide on one direct dependency (pure; used by the scan and tests). */
export function judgePackage(name: string, installed: string, meta: PkgMeta, project: string, now = new Date()): Finding[] {
  const out: Finding[] = [];
  const where = `${project}/package.json → ${name}@${installed}`;
  const dep = meta.deprecated?.[installed];
  if (dep) {
    const security = /secur|vulnerab|CVE-|malicious|compromis/i.test(dep);
    out.push({ source: "system", rule: "OLD-DEPRECATED", severity: security ? "high" : "medium", where, title: `${name}@${installed} is deprecated`,
      detail: `Its publisher marked this version deprecated: "${dep.slice(0, 160)}". Deprecated versions get no more fixes.`, fix: `Upgrade ${name} to ${meta.latest} or a replacement the publisher recommends.`, evidence: { latest: meta.latest } });
  }
  const behind = major(meta.latest) - major(installed);
  if (behind >= 2 && !meta.deprecated?.[meta.latest]) out.push({ source: "system", rule: "OLD-MAJOR-BEHIND", severity: behind >= 4 ? "high" : "medium", where, title: `${name} is ${behind} major versions behind (${installed} → ${meta.latest})`,
    detail: `Most projects fix security bugs only in their latest major versions, so ${name}@${installed} is likely to stay vulnerable to future advisories.`, fix: `Plan an upgrade to ${name}@${meta.latest}; read its changelog for breaking changes.`, evidence: { installed, latest: meta.latest, behind } });
  const last = meta.time?.[meta.latest] ?? meta.latestDate;
  if (last && now.getTime() - Date.parse(last) > 730 * DAY) {
    const years = Math.floor((now.getTime() - Date.parse(last)) / (365 * DAY));
    out.push({ source: "system", rule: "OLD-UNMAINTAINED", severity: "low", where, title: `${name} has had no release for ${years} years`,
      detail: `Its last release (${meta.latest}) was on ${last.slice(0, 10)}. An unmaintained package will not be fixed when the next vulnerability is found.`, fix: `Check whether ${name} is still maintained; consider a maintained alternative.`, evidence: { lastRelease: last.slice(0, 10) } });
  }
  return out;
}

async function fetchMeta(name: string): Promise<PkgMeta | null> {
  try {
    const r = await fetch(`https://registry.npmjs.org/${name.replace("/", "%2f")}`, { signal: AbortSignal.timeout(20_000) });
    if (!r.ok) return null;
    const j = await r.json() as { "dist-tags"?: { latest?: string }; time?: Record<string, string>; versions?: Record<string, { deprecated?: string }> };
    const deprecated: Record<string, string> = {};
    for (const [v, m] of Object.entries(j.versions ?? {})) if (m.deprecated) deprecated[v] = m.deprecated;
    const latest = j["dist-tags"]?.latest ?? "";
    return { latest, latestDate: j.time?.[latest], deprecated, time: latest && j.time ? { [latest]: j.time[latest] } : {} };
  } catch { return null; }
}

function installedVersion(project: string, name: string): string | null {
  const p = join(project, "node_modules", name, "package.json");
  if (existsSync(p)) try { return JSON.parse(readFileSync(p, "utf8")).version; } catch { /* fall through */ }
  const lock = join(project, "package-lock.json");
  if (existsSync(lock)) try { return JSON.parse(readFileSync(lock, "utf8")).packages?.[`node_modules/${name}`]?.version ?? null; } catch { /* none */ }
  return null;
}

function* textFiles(root: string, depth = 0, others: string[] = []): Generator<string> {
  if (depth > 4 || (depth > 0 && others.includes(root))) return; // another project nested inside this one is checked on its own
  let names: string[] = []; try { names = readdirSync(root); } catch { return; }
  for (const n of names) {
    if (["node_modules", ".git", "dist", "cdk.out", "state", "sandbox", "runs", "outbox", "coverage", "test", "tests", "__tests__", "fixtures", "scratch"].includes(n)) continue;
    const p = join(root, n); let st; try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) yield* textFiles(p, depth + 1, others);
    else if (/^(Dockerfile.*|.*\.(ts|js|mjs|json|ya?ml|tf))$/i.test(n) && !/package-lock\.json$|\.(test|spec)\.[cm]?[jt]s$/.test(n) && st.size < 1_000_000) yield p;
  }
}

/** Runtimes named in code and config: Docker base images and Lambda runtimes. */
export function runtimeFindings(text: string, where: string, now = new Date()): Finding[] {
  const out: Finding[] = [];
  for (const m of text.matchAll(/^\s*FROM\s+(?:--platform=\S+\s+)?(?:\S+\/)?node:(\d+)/gim)) {
    const s = nodeStatus(Number(m[1]), now);
    if (s.eol) out.push({ source: "system", rule: "OLD-BASE-IMAGE", severity: "high", where, title: `Docker image is built on Node.js ${m[1]}, which is past end of life`, detail: `Node.js ${m[1]} stopped getting security fixes (${s.date}). Every image built from it carries the unfixed bugs.`, fix: "Move the base image to node:22 or node:24 and rebuild." });
  }
  for (const m of text.matchAll(/\bRuntime\.NODEJS_(\d+)_X\b|["'`]nodejs(\d+)\.x["'`]|\bRuntime\.PYTHON_3_(\d+)\b|["'`]python3\.(\d+)["'`]/g)) {
    if (m[1] || m[2]) {
      const v = Number(m[1] ?? m[2]); const s = nodeStatus(v, now);
      if (s.eol) out.push({ source: "system", rule: "OLD-CLOUD-RUNTIME", severity: "high", where, title: `AWS Lambda runs on Node.js ${v}, which is past end of life`, detail: `Node.js ${v} stopped getting security fixes (${s.date}); AWS blocks updates to functions on deprecated runtimes.`, fix: "Change the function runtime to Node.js 22 or 24 and redeploy." });
    } else {
      const v = `3.${m[3] ?? m[4]}`; const eol = PY_EOL[v];
      if (eol && new Date(eol) < now) out.push({ source: "system", rule: "OLD-CLOUD-RUNTIME", severity: "high", where, title: `AWS Lambda runs on Python ${v}, which is past end of life`, detail: `Python ${v} stopped getting security fixes (${eol}).`, fix: "Move the function to Python 3.12 or later and redeploy." });
    }
  }
  return out;
}

export function osFinding(osRelease: string, now = new Date()): { finding?: Finding; pass?: string } {
  const id = /^ID="?([^"\n]+)/m.exec(osRelease)?.[1]?.toLowerCase(); const ver = /^VERSION_ID="?([^"\n]+)/m.exec(osRelease)?.[1];
  if (!id || !ver) return {};
  const key = `${id} ${id === "alpine" ? ver.split(".").slice(0, 2).join(".") : ver}`;
  const eol = OS_EOL[key]; const name = /^PRETTY_NAME="?([^"\n]+)/m.exec(osRelease)?.[1] ?? key;
  if (!eol) return { pass: `${name}: end-of-life date not in the table` };
  if (new Date(eol) < now) return { finding: { source: "system", rule: "OLD-OS-EOL", severity: "high", where: "/etc/os-release", title: `${name} is past end of life`, detail: `${name} stopped getting free security updates on ${eol}.`, fix: "Upgrade the operating system or move the service to a supported base image." } };
  return { pass: `${name} is supported until ${eol}` };
}

export async function scanOutdated(projects: string[], cacheDir?: string, now = new Date()) {
  const findings: Finding[] = [], passed: string[] = [];
  const cacheFile = cacheDir ? join(cacheDir, "npm-meta.json") : "";
  let cache: Record<string, { at: number; meta: PkgMeta }> = {};
  if (cacheFile && existsSync(cacheFile)) try { cache = JSON.parse(readFileSync(cacheFile, "utf8")); } catch { /* fresh */ }
  let checked = 0, unreachable = 0;
  for (const project of projects) {
    const pj = join(project, "package.json"); if (!existsSync(pj)) continue;
    const deps = Object.keys(JSON.parse(readFileSync(pj, "utf8")).dependencies ?? {});
    const queue = [...deps];
    await Promise.all(Array.from({ length: 6 }, async () => {
      for (let name = queue.shift(); name; name = queue.shift()) {
        const inst = installedVersion(project, name); if (!inst) continue;
        let meta = cache[name] && now.getTime() - cache[name].at < DAY ? cache[name].meta : null;
        if (!meta) { meta = await fetchMeta(name); if (meta) cache[name] = { at: now.getTime(), meta }; }
        if (!meta) { unreachable++; continue; }
        checked++; findings.push(...judgePackage(name, inst, meta, basename(project), now));
      }
    }));
    for (const f of textFiles(project, 0, projects.map((x) => resolve(x)))) findings.push(...runtimeFindings(readFileSync(f, "utf8"), `${basename(project)}/${relative(project, f)}`, now));
  }
  if (cacheFile) { mkdirSync(cacheDir!, { recursive: true }); writeFileSync(cacheFile, JSON.stringify(cache)); }
  const node = nodeStatus(Number(process.versions.node.split(".")[0]), now);
  if (node.eol) findings.push({ source: "system", rule: "OLD-RUNTIME", severity: "high", where: process.execPath, title: `This host runs Node.js ${process.versions.node}, which is past end of life`, detail: `Security fixes ended on ${node.date}.`, fix: "Upgrade to Node.js 22 or 24 LTS." });
  else passed.push(`Node.js ${process.versions.node} is supported until ${node.date}${node.soon ? " (ends within 4 months: plan the upgrade)" : ""}`);
  if (existsSync("/etc/os-release")) { const o = osFinding(readFileSync("/etc/os-release", "utf8"), now); if (o.finding) findings.push(o.finding); if (o.pass) passed.push(o.pass); }
  const has = (r: string) => findings.some((f) => f.rule === r);
  if (!has("OLD-DEPRECATED") && checked) passed.push(`None of ${checked} direct dependencies is deprecated`);
  if (!has("OLD-MAJOR-BEHIND") && checked) passed.push("No direct dependency is two or more major versions behind");
  if (!has("OLD-BASE-IMAGE") && !has("OLD-CLOUD-RUNTIME")) passed.push("Docker images and Lambda runtimes are supported");
  return { findings, passed, checked, unreachable, summary: `${checked} direct dependencies checked against the npm registry${unreachable ? ` (${unreachable} unreachable)` : ""} · runtimes and OS checked` };
}
