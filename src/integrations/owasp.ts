/**
 * OWASP tools, wired into Agent Shield.
 *
 *  - OWASP Secure Headers Project: the project's own machine-readable lists of headers to
 *    send (headers_add.json) and headers to remove because they leak information
 *    (headers_remove.json), fetched from the project's repository and cached daily.
 *  - OWASP ZAP (Zed Attack Proxy, now maintained under Checkmarx): import ZAP's
 *    Traditional JSON reports (zap-baseline.py -J), or, with ZAP_API_URL, drive a running
 *    ZAP daemon through a spider plus passive scan of an owned site. Agent Shield's own
 *    website rules carry the matching ZAP rule ids.
 *  - OWASP Dependency-Check: import its JSON report (NVD-based CVE matching for npm and
 *    other ecosystems), or run the CLI when installed.
 *  - OWASP CycloneDX + OWASP Dependency-Track: the SBOM from the Supply chain scan is a
 *    CycloneDX document; with DTRACK_URL and DTRACK_API_KEY it is uploaded to
 *    Dependency-Track, which then watches those components for new advisories.
 *  - OWASP DefectDojo: every alert can be exported in DefectDojo's Generic Findings
 *    Import format, or pushed to /api/v2/import-scan/ with DEFECTDOJO_URL and
 *    DEFECTDOJO_TOKEN, so findings join the team's vulnerability management.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { execFile, execFileSync } from "node:child_process";
import type { Alert, Finding, Severity } from "../alerts.ts";

// ---- OWASP Secure Headers Project --------------------------------------------------------
const SHP = "https://raw.githubusercontent.com/OWASP/www-project-secure-headers/master/ci";
export interface SecureHeaderLists { add: { name: string; value: string }[]; remove: string[]; updated?: string; source: "live" | "cache" | "built-in" }
const BUILT_IN: SecureHeaderLists = { source: "built-in", remove: ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-CF-Powered-By"],
  add: ["Cache-Control", "Content-Security-Policy", "Cross-Origin-Embedder-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy", "Permissions-Policy", "Referrer-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "X-Permitted-Cross-Domain-Policies"].map((name) => ({ name, value: "" })) };

export async function loadSecureHeaders(cacheDir: string, f: typeof fetch = fetch): Promise<SecureHeaderLists> {
  mkdirSync(cacheDir, { recursive: true });
  const file = join(cacheDir, "owasp-secure-headers.json");
  if (existsSync(file) && Date.now() - statSync(file).mtimeMs < 24 * 3600_000) return { ...JSON.parse(readFileSync(file, "utf8")), source: "cache" };
  try {
    const [a, r] = await Promise.all([f(`${SHP}/headers_add.json`, { signal: AbortSignal.timeout(20_000) }), f(`${SHP}/headers_remove.json`, { signal: AbortSignal.timeout(20_000) })]);
    if (!a.ok || !r.ok) throw new Error("not ok");
    const add = await a.json(), rem = await r.json();
    const lists = { add: add.headers, remove: rem.headers, updated: add.last_update_utc };
    writeFileSync(file, JSON.stringify(lists));
    return { ...lists, source: "live" };
  } catch { return existsSync(file) ? { ...JSON.parse(readFileSync(file, "utf8")), source: "cache" } : BUILT_IN; }
}

/** Headers OWASP recommends that Agent Shield's own web rules do not already cover. */
const COVERED = new Set(["content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "strict-transport-security"]);
const SITE_WIDE_ONLY = new Set(["clear-site-data"]); // meant for logout responses, not every page

export function checkSecureHeaders(h: Headers, lists: SecureHeaderLists, where: string): { findings: Finding[]; passed: string[] } {
  const findings: Finding[] = [], passed: string[] = [];
  const leaking = lists.remove.filter((n) => !n.startsWith("$") && h.get(n)).map((n) => `${n}: ${h.get(n)}`);
  if (leaking.length)
    findings.push({ source: "web", rule: "OWASP-SHP-REMOVE", severity: "low", where, key: `owasp-shp:${where}:remove`,
      title: `${leaking.length} header${leaking.length === 1 ? "" : "s"} OWASP recommends removing`,
      detail: `${leaking.join("; ")}. The OWASP Secure Headers Project lists these because they tell attackers what software runs the site${lists.updated ? ` (list of ${lists.updated.slice(0, 10)})` : ""}.`,
      fix: "Strip them at the edge (CloudFront response headers policy: remove headers), or blank them at the origin.", evidence: { owasp: "Secure Headers Project" } });
  else passed.push("No headers on OWASP's remove list");
  const xss = h.get("x-xss-protection");
  if (xss && xss.trim() !== "0")
    findings.push({ source: "web", rule: "OWASP-XSS-PROTECTION", severity: "low", where, key: `owasp-shp:${where}:xxp`,
      title: "Legacy X-XSS-Protection filter is switched on", detail: `X-XSS-Protection: ${xss}. OWASP's HTTP Headers Cheat Sheet advises turning it off: the old browser filter it controls could be abused to leak data, and modern browsers ignore it.`,
      fix: "Send X-XSS-Protection: 0 (or drop it) and rely on Content-Security-Policy.", evidence: { owasp: "HTTP Headers Cheat Sheet" } });
  const missing = lists.add.map((x) => x.name).filter((n) => !COVERED.has(n.toLowerCase()) && !SITE_WIDE_ONLY.has(n.toLowerCase()) && !h.get(n));
  if (missing.length) {
    const rec = Object.fromEntries(lists.add.map((x) => [x.name, x.value]));
    findings.push({ source: "web", rule: "OWASP-SHP-MISSING", severity: "low", where, key: `owasp-shp:${where}:missing`,
      title: `${missing.length} OWASP-recommended header${missing.length === 1 ? "" : "s"} not sent`,
      detail: `Missing: ${missing.join(", ")}. Cross-origin isolation headers stop other sites from reading this page's responses or windows.`,
      fix: missing.map((n) => `${n}: ${rec[n] || "(see OWASP Secure Headers Project)"}`).join(" · "), evidence: { owasp: "Secure Headers Project" } });
  } else passed.push("All OWASP-recommended headers are sent");
  return { findings, passed };
}

/** Agent Shield website rules and the OWASP ZAP passive scan rule that checks the same thing. */
export const ZAP_RULE: Record<string, string> = {
  "WEB-NO-CSP": "10038", "WEB-NO-FRAME-PROTECTION": "10020", "WEB-NO-NOSNIFF": "10021", "WEB-NO-HSTS": "10035", "WEB-WEAK-HSTS": "10035",
  "WEB-VERSION-LEAK": "10036", "WEB-COOKIE-FLAGS": "10010", "WEB-NO-PERMISSIONS-POLICY": "10063", "OWASP-SHP-REMOVE": "10037",
};

// ---- OWASP ZAP -------------------------------------------------------------------------
const ZAP_RISK: Record<string, Severity> = { "3": "high", "2": "medium", "1": "low", "0": "info" };
const strip = (html?: string) => (html ?? "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();

/** ZAP Traditional JSON report -> findings (one per alert type per site). */
export function zapFindings(json: string): Finding[] {
  let d: any; try { d = JSON.parse(json); } catch { return []; }
  const out: Finding[] = [];
  for (const site of d.site ?? []) for (const a of site.alerts ?? []) {
    const inst = a.instances ?? [];
    out.push({ source: "web", rule: `ZAP-${a.pluginid ?? a.alertRef}`, severity: ZAP_RISK[String(a.riskcode)] ?? "medium", where: site["@name"], key: `zap:${site["@name"]}:${a.alertRef ?? a.pluginid}`,
      title: `ZAP: ${a.name ?? a.alert}${inst.length > 1 ? ` (${inst.length} places)` : ""}`,
      detail: `${strip(a.desc).slice(0, 400)}${inst[0]?.uri ? ` First seen at ${inst[0].method ?? "GET"} ${inst[0].uri}${inst[0].param ? ` (parameter ${inst[0].param})` : ""}.` : ""}`,
      fix: strip(a.solution).slice(0, 300) || undefined, evidence: { zapRule: a.pluginid, cwe: a.cweid, confidence: a.confidence, instances: inst.length } });
  }
  return out;
}

/** Drive a running ZAP daemon: spider the site, wait for the passive scanner, return the report. Passive only. */
export async function zapBaseline(target: string, opts: { api?: string; key?: string; fetch?: typeof fetch; maxWaitMs?: number } = {}): Promise<string> {
  const api = (opts.api ?? process.env.ZAP_API_URL ?? "").replace(/\/$/, ""), key = opts.key ?? process.env.ZAP_API_KEY ?? "", f = opts.fetch ?? fetch;
  if (!api) throw new Error("Set ZAP_API_URL to a running ZAP daemon (zap.sh -daemon -port 8090)");
  const call = async (path: string, params: Record<string, string> = {}) => {
    const u = new URL(`${api}${path}`); for (const [k, v] of Object.entries({ ...params, ...(key ? { apikey: key } : {}) })) u.searchParams.set(k, v);
    const r = await f(u.href); if (!r.ok) throw new Error(`ZAP ${path}: ${r.status}`); return r;
  };
  const scanId = (await (await call("/JSON/spider/action/scan/", { url: target, maxChildren: "20", recurse: "true" })).json()).scan;
  const until = Date.now() + (opts.maxWaitMs ?? 180_000);
  while (Date.now() < until && Number((await (await call("/JSON/spider/view/status/", { scanId: String(scanId) })).json()).status) < 100) await new Promise((r) => setTimeout(r, 2000));
  while (Date.now() < until && Number((await (await call("/JSON/pscan/view/recordsToScan/")).json()).recordsToScan) > 0) await new Promise((r) => setTimeout(r, 1000));
  return (await call("/OTHER/core/other/jsonreport/")).text();
}

// ---- OWASP Dependency-Check ------------------------------------------------------------
const DC_SEV: Record<string, Severity> = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", MODERATE: "medium", LOW: "low" };
export function dependencyCheckFindings(json: string, dir: string): Finding[] {
  let d: any; try { d = JSON.parse(json); } catch { return []; }
  const out: Finding[] = [];
  for (const dep of d.dependencies ?? []) for (const v of dep.vulnerabilities ?? []) {
    const pkg = dep.packages?.[0]?.id ?? dep.fileName;
    out.push({ source: "system", rule: "OWASP-DC-VULN", severity: DC_SEV[String(v.severity).toUpperCase()] ?? "medium", where: `${dir} · ${pkg}`, key: `dc:${dir}:${pkg}:${v.name}`,
      title: `${pkg}: ${v.name}`, detail: `${String(v.description ?? "").slice(0, 300)}${v.cvssv3?.baseScore ? ` CVSS ${v.cvssv3.baseScore}.` : ""} (OWASP Dependency-Check, source ${v.source ?? "NVD"})`,
      fix: "Upgrade to a version outside the affected range.", evidence: { advisories: [v.name].filter((x: string) => /^(CVE|GHSA)-/.test(x)) } });
  }
  return out;
}
export const dependencyCheckVersion = () => { for (const b of [process.env.DEPENDENCY_CHECK_BIN, "dependency-check", "dependency-check.sh"].filter(Boolean) as string[]) { try { return { bin: b, version: execFileSync(b, ["--version"], { encoding: "utf8", timeout: 30_000 }).trim().split("\n")[0] }; } catch { /* next */ } } return null; };
export function runDependencyCheck(dir: string, outDir: string): Promise<{ findings: Finding[]; error?: string }> {
  const dc = dependencyCheckVersion();
  if (!dc) return Promise.resolve({ findings: [], error: "OWASP Dependency-Check is not installed" });
  mkdirSync(outDir, { recursive: true });
  const args = ["--scan", dir, "--format", "JSON", "--out", outDir, "--project", "agent", "--exclude", "**/node_modules/**/test/**", ...(process.env.NVD_API_KEY ? ["--nvdApiKey", process.env.NVD_API_KEY] : [])];
  return new Promise((resolve) => execFile(dc.bin, args, { timeout: 1_800_000, maxBuffer: 50_000_000 }, (err) => {
    const report = join(outDir, "dependency-check-report.json");
    if (!existsSync(report)) return resolve({ findings: [], error: err?.message.slice(0, 200) ?? "no report" });
    resolve({ findings: dependencyCheckFindings(readFileSync(report, "utf8"), dir) });
  }));
}

// ---- OWASP Dependency-Track ------------------------------------------------------------
export async function uploadToDependencyTrack(bomJson: string, opts: { url?: string; key?: string; project?: string; version?: string; fetch?: typeof fetch } = {}) {
  const url = (opts.url ?? process.env.DTRACK_URL ?? "").replace(/\/$/, ""), key = opts.key ?? process.env.DTRACK_API_KEY ?? "", f = opts.fetch ?? fetch;
  if (!url || !key) throw new Error("Set DTRACK_URL and DTRACK_API_KEY");
  const form = new FormData();
  form.set("projectName", opts.project ?? process.env.DTRACK_PROJECT ?? "agent-desk");
  form.set("projectVersion", opts.version ?? process.env.DTRACK_VERSION ?? "main");
  form.set("autoCreate", "true");
  form.set("bom", new Blob([bomJson], { type: "application/vnd.cyclonedx+json" }), "bom.cdx.json");
  const r = await f(`${url}/api/v1/bom`, { method: "POST", headers: { "X-Api-Key": key }, body: form });
  if (!r.ok) throw new Error(`Dependency-Track ${r.status}: ${(await r.text()).slice(0, 160)}`);
  const body = await r.text(); let token: string | undefined; try { token = JSON.parse(body).token; } catch { /* no token */ }
  return { ok: true, token };
}

// ---- OWASP DefectDojo ------------------------------------------------------------------
const DD_SEV: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
export function toDefectDojo(alerts: Alert[], refNames: Record<string, string> = {}) {
  return {
    name: "Agent Shield", type: "Agent Shield", version: "1",
    findings: alerts.filter((a) => !a.acknowledged).map((a) => {
      const m = /^(.+?):(\d+)$/.exec(a.where ?? "");
      const ev = a.evidence ?? {};
      return {
        title: a.title, severity: DD_SEV[a.severity], description: a.detail, mitigation: a.fix ?? "",
        references: (a.refs ?? []).map((r) => `${r} ${refNames[r] ?? ""}`.trim()).join("\n"),
        date: a.at.slice(0, 10), unique_id_from_tool: a.id, vuln_id_from_tool: a.rule,
        ...(m ? { file_path: m[1], line: Number(m[2]) } : {}),
        ...(Array.isArray(ev.cves) && ev.cves.length ? { vulnerability_ids: ev.cves } : {}),
        ...(typeof ev.epss === "number" ? { epss_score: ev.epss } : {}),
        ...(ev.kev ? { known_exploited: true } : {}),
        ...(ev.cwe ? { cwe: Number(ev.cwe) || undefined } : {}),
        static_finding: ["code", "llm", "access", "system"].includes(a.source), dynamic_finding: !["code", "access"].includes(a.source),
        tags: ["agent-shield", a.source, ...(a.refs ?? [])],
      };
    }),
  };
}

export async function pushToDefectDojo(report: object, opts: { url?: string; token?: string; product?: string; engagement?: string; fetch?: typeof fetch } = {}) {
  const url = (opts.url ?? process.env.DEFECTDOJO_URL ?? "").replace(/\/$/, ""), token = opts.token ?? process.env.DEFECTDOJO_TOKEN ?? "", f = opts.fetch ?? fetch;
  if (!url || !token) throw new Error("Set DEFECTDOJO_URL and DEFECTDOJO_TOKEN");
  const form = new FormData();
  form.set("scan_type", "Generic Findings Import");
  form.set("product_name", opts.product ?? process.env.DEFECTDOJO_PRODUCT ?? "Agent Desk");
  form.set("engagement_name", opts.engagement ?? process.env.DEFECTDOJO_ENGAGEMENT ?? "Agent Shield");
  form.set("auto_create_context", "true");
  form.set("minimum_severity", "Info");
  form.set("active", "true"); form.set("verified", "false");
  form.set("file", new Blob([JSON.stringify(report)], { type: "application/json" }), "agent-shield.json");
  const r = await f(`${url}/api/v2/import-scan/`, { method: "POST", headers: { Authorization: `Token ${token}` }, body: form });
  if (!r.ok) throw new Error(`DefectDojo ${r.status}: ${(await r.text()).slice(0, 160)}`);
  const j = await r.json().catch(() => ({}));
  return { ok: true, test: j.test ?? j.test_id };
}
