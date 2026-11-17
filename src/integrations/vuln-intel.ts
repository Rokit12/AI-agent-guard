/**
 * Risk-based prioritisation of dependency advisories (the approach CISA, FIRST and Google's
 * OSV project recommend): fix what is exploited first, not what scores highest.
 *
 *  - OSV (osv.dev, run by Google): resolves a GitHub advisory id (GHSA-...) to its CVE ids.
 *  - CISA KEV: the US government's list of vulnerabilities exploited in the wild, with a
 *    flag for use in ransomware campaigns. Read from CISA's GitHub mirror and cached daily.
 *  - FIRST EPSS v4: the probability a CVE is exploited in the next 30 days.
 *
 * An advisory in KEV becomes critical ("known exploited"); one with EPSS of 10% or more is
 * raised to at least high. Every source is optional: when one cannot be reached the
 * findings keep their original severity, and the dashboard says which sources answered.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync, statSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../alerts.ts";
import { rank } from "../alerts.ts";

const KEV_URLS = (process.env.KEV_URL ? [process.env.KEV_URL] : [])
  .concat(["https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"]);
const OSV = process.env.OSV_API ?? "https://api.osv.dev/v1";
const EPSS = process.env.EPSS_API ?? "https://api.first.org/data/v1/epss";

export interface KevEntry { cveID: string; vendorProject: string; product: string; vulnerabilityName: string; dateAdded: string; dueDate: string; knownRansomwareCampaignUse: string; requiredAction: string }
export interface Intel { kev: Map<string, KevEntry>; kevVersion?: string; sources: Record<"kev" | "osv" | "epss", "ok" | "unreachable" | "unused"> }

export async function loadKev(cacheDir: string, f: typeof fetch = fetch): Promise<{ map: Map<string, KevEntry>; version?: string; ok: boolean }> {
  mkdirSync(cacheDir, { recursive: true });
  const cache = join(cacheDir, "kev.json");
  let raw: string | undefined;
  const fresh = existsSync(cache) && Date.now() - statSync(cache).mtimeMs < 24 * 3600_000;
  if (!fresh) for (const u of KEV_URLS) {
    try { const r = await f(u, { signal: AbortSignal.timeout(30_000) }); if (r.ok) { raw = await r.text(); JSON.parse(raw); writeFileSync(cache, raw); break; } } catch { /* next */ }
  }
  if (!raw && existsSync(cache)) raw = readFileSync(cache, "utf8");
  if (!raw) return { map: new Map(), ok: false };
  const d = JSON.parse(raw);
  return { map: new Map((d.vulnerabilities as KevEntry[]).map((v) => [v.cveID, v])), version: d.catalogVersion, ok: true };
}

/** GHSA -> CVE aliases through OSV, cached on disk. */
export async function osvAliases(ids: string[], cacheDir: string, f: typeof fetch = fetch): Promise<{ map: Map<string, string[]>; ok: boolean }> {
  const cacheFile = join(cacheDir, "osv-aliases.json");
  const cache: Record<string, string[]> = existsSync(cacheFile) ? JSON.parse(readFileSync(cacheFile, "utf8")) : {};
  let ok = true, changed = false;
  for (const id of ids) {
    if (cache[id] || id.startsWith("CVE-")) continue;
    try {
      const r = await f(`${OSV}/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(15_000) });
      if (!r.ok) { ok = r.status === 404; continue; }
      cache[id] = ((await r.json()).aliases ?? []).filter((a: string) => a.startsWith("CVE-")); changed = true;
    } catch { ok = false; break; }
  }
  if (changed) { mkdirSync(cacheDir, { recursive: true }); writeFileSync(cacheFile, JSON.stringify(cache)); }
  return { map: new Map(ids.map((i) => [i, i.startsWith("CVE-") ? [i] : cache[i] ?? []])), ok };
}

export async function epssScores(cves: string[], f: typeof fetch = fetch): Promise<{ map: Map<string, { epss: number; percentile: number }>; ok: boolean }> {
  const map = new Map<string, { epss: number; percentile: number }>();
  if (!cves.length) return { map, ok: true };
  try {
    for (let i = 0; i < cves.length; i += 80) {
      const r = await f(`${EPSS}?cve=${cves.slice(i, i + 80).join(",")}`, { signal: AbortSignal.timeout(15_000) });
      if (!r.ok) return { map, ok: false };
      for (const x of (await r.json()).data ?? []) map.set(x.cve, { epss: Number(x.epss), percentile: Number(x.percentile) });
    }
    return { map, ok: true };
  } catch { return { map, ok: false }; }
}

/** Raise dependency findings that are exploited (KEV) or likely to be (EPSS). Findings carry advisory ids in evidence.advisories. */
export async function prioritise(findings: Finding[], cacheDir: string, f: typeof fetch = fetch): Promise<{ findings: Finding[]; intel: Intel; exploited: number; likely: number }> {
  const kev = await loadKev(cacheDir, f);
  const ids = [...new Set(findings.flatMap((x) => (x.evidence?.advisories as string[] | undefined) ?? []))];
  const aliases = ids.length ? await osvAliases(ids, cacheDir, f) : { map: new Map<string, string[]>(), ok: true };
  const cves = [...new Set([...aliases.map.values()].flat())];
  const epss = await epssScores(cves, f);
  let exploited = 0, likely = 0;
  const out = findings.map((x) => {
    const adv = (x.evidence?.advisories as string[] | undefined) ?? [];
    const myCves = [...new Set(adv.flatMap((a) => aliases.map.get(a) ?? []))];
    if (!myCves.length) return x;
    const k = myCves.map((c) => kev.map.get(c)).find(Boolean);
    const e = myCves.map((c) => epss.map.get(c)).filter(Boolean).sort((a, b) => b!.epss - a!.epss)[0];
    const y: Finding = { ...x, evidence: { ...x.evidence, cves: myCves, kev: Boolean(k), epss: e?.epss } };
    if (k) {
      exploited++;
      y.severity = "critical";
      y.title = `Known exploited: ${x.title}`;
      y.detail = `${x.detail} ${k.cveID} is in CISA's Known Exploited Vulnerabilities catalog (added ${k.dateAdded}${k.knownRansomwareCampaignUse === "Known" ? ", used in ransomware campaigns" : ""}).`;
      y.fix = `${k.requiredAction} ${x.fix ?? ""}`.trim();
    } else if (e && e.epss >= 0.1) {
      likely++;
      if (rank(y.severity) < rank("high")) y.severity = "high";
      y.detail = `${x.detail} EPSS: ${(e.epss * 100).toFixed(1)}% chance of exploitation in the next 30 days (higher than ${Math.round(e.percentile * 100)}% of CVEs).`;
    } else if (e) y.detail = `${x.detail} EPSS: ${(e.epss * 100).toFixed(2)}% chance of exploitation in the next 30 days.`;
    return y;
  });
  return { findings: out, exploited, likely, intel: { kev: kev.map, kevVersion: kev.version, sources: { kev: kev.ok ? "ok" : "unreachable", osv: ids.length ? (aliases.ok ? "ok" : "unreachable") : "unused", epss: cves.length ? (epss.ok ? "ok" : "unreachable") : "unused" } } };
}
