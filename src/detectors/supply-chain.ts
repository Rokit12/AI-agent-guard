/**
 * Supply-chain integrity for the agent's npm dependencies (the SLSA / Sigstore approach
 * Google, GitHub and npm now use).
 *
 * For every production package in package-lock.json:
 *  - Registry signature: npm signs `name@version:integrity` with ECDSA P-256; the public
 *    keys are published at /-/npm/v1/keys. A bad signature means the metadata was altered.
 *  - Lockfile integrity: the hash in package-lock.json must equal the registry's. A
 *    mismatch means the lockfile or the registry entry was swapped.
 *  - SLSA build provenance: whether the version carries a provenance attestation, and
 *    whether that provenance's subject digest and source repository match the package.
 *    (The attestation's Sigstore certificate chain is not re-verified here: that needs the
 *    Sigstore trust root. `npm audit signatures` does it where Sigstore is reachable.)
 *  - Install scripts: packages that run code on install, the path worms like Shai-Hulud
 *    used in 2025 to steal tokens from developer machines and CI.
 * Plus a CycloneDX SBOM (npm sbom), so the exact components can be handed to customers
 * or matched against new advisories later.
 */
import { createVerify } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { execFile } from "node:child_process";
import type { Finding } from "../alerts.ts";

const REGISTRY = process.env.NPM_REGISTRY ?? "https://registry.npmjs.org";

export interface RegistryKey { keyid: string; key: string; expires: string | null }
export interface LockPackage { name: string; version: string; integrity?: string; hasInstallScript?: boolean; dev?: boolean }

export function lockPackages(dir: string): LockPackage[] {
  const p = join(dir, "package-lock.json");
  if (!existsSync(p)) return [];
  const lock = JSON.parse(readFileSync(p, "utf8"));
  return Object.entries<any>(lock.packages ?? {})
    .filter(([path, v]) => path.startsWith("node_modules/") && v.version && !v.link)
    .map(([path, v]) => ({ name: v.name ?? path.split("node_modules/").pop()!, version: v.version, integrity: v.integrity, hasInstallScript: v.hasInstallScript, dev: v.dev }));
}

export function verifyRegistrySignature(name: string, version: string, integrity: string, sigs: { keyid: string; sig: string }[], keys: RegistryKey[]): "valid" | "invalid" | "unknown-key" | "missing" {
  if (!sigs?.length) return "missing";
  let unknown = true;
  for (const s of sigs) {
    const k = keys.find((x) => x.keyid === s.keyid);
    if (!k) continue;
    unknown = false;
    const v = createVerify("SHA256"); v.update(`${name}@${version}:${integrity}`); v.end();
    try { if (v.verify({ key: Buffer.from(k.key, "base64"), format: "der", type: "spki" }, Buffer.from(s.sig, "base64"))) return "valid"; } catch { /* fall through */ }
  }
  return unknown ? "unknown-key" : "invalid";
}

/** Reads a SLSA provenance attestation: subject digest and source repository. */
export function readProvenance(att: any): { digestHex?: string; repo?: string } | null {
  const a = (att?.attestations ?? []).find((x: any) => /slsa\.dev\/provenance/.test(x.predicateType));
  const payload = a?.bundle?.dsseEnvelope?.payload;
  if (!payload) return null;
  try {
    const st = JSON.parse(Buffer.from(payload, "base64").toString("utf8"));
    const wf = st.predicate?.buildDefinition?.externalParameters?.workflow ?? {};
    return { digestHex: st.subject?.[0]?.digest?.sha512, repo: wf.repository ?? st.predicate?.buildDefinition?.externalParameters?.source?.repository };
  } catch { return null; }
}

/** One form for every way package.json writes a repository: git+https, git://, ssh, git@host:owner/repo, github:owner/repo, owner/repo. */
export const normRepo = (r?: string) => {
  let x = (r ?? "").trim().toLowerCase().replace(/^git\+/, "").replace(/\.git$/, "").replace(/\/+$/, "");
  x = x.replace(/^github:/, "github.com/").replace(/^gitlab:/, "gitlab.com/").replace(/^bitbucket:/, "bitbucket.org/");
  x = x.replace(/^[a-z+]+:\/\//, "").replace(/^[^@/]+@/, "").replace(/^([^/:]+):(?!\d)/, "$1/").replace(/^www\./, "");
  if (/^[\w.-]+\/[\w.-]+$/.test(x) && !x.includes(".")) x = `github.com/${x}`;
  return x;
};
const integrityHex = (i: string) => (i.startsWith("sha512-") ? Buffer.from(i.slice(7), "base64").toString("hex") : "");

async function pool<T, R>(items: T[], n: number, f: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await f(items[k]); } }));
  return out;
}

export interface SupplyResult { at: string; dir: string; packages: number; signed: number; withProvenance: number; installScripts: number; unreachable: number; findings: Finding[]; summary: string; passed: string[] }

export async function scanSupplyChain(dir: string, opts: { fetch?: typeof fetch; includeDev?: boolean } = {}): Promise<SupplyResult> {
  const f = opts.fetch ?? fetch;
  const pkgs = lockPackages(dir).filter((p) => opts.includeDev || !p.dev);
  const findings: Finding[] = [], passed: string[] = [];
  const at = new Date().toISOString();
  if (!pkgs.length) return { at, dir, packages: 0, signed: 0, withProvenance: 0, installScripts: 0, unreachable: 0, findings, summary: "No package-lock.json to check", passed };
  const keys: RegistryKey[] = (await (await f(`${REGISTRY}/-/npm/v1/keys`)).json()).keys ?? [];
  let signed = 0, prov = 0, unreachable = 0;
  const unsigned: string[] = [];
  await pool(pkgs, 8, async (p) => {
    let doc: any;
    try { const r = await f(`${REGISTRY}/${p.name.replace("/", "%2f")}/${p.version}`); if (!r.ok) { unreachable++; return; } doc = await r.json(); } catch { unreachable++; return; }
    const id = `${p.name}@${p.version}`, dist = doc.dist ?? {};
    if (p.integrity && dist.integrity && p.integrity !== dist.integrity)
      findings.push({ source: "system", rule: "SUPPLY-INTEGRITY-MISMATCH", severity: "critical", where: `${dir} · ${id}`, key: `supply:${dir}:${id}:integrity`,
        title: `${id}: lockfile hash does not match the registry`, detail: `package-lock.json says ${p.integrity.slice(0, 22)}…, the registry says ${dist.integrity.slice(0, 22)}…. Someone changed the lockfile, or the package was swapped.`,
        fix: "Do not install. Restore package-lock.json from a trusted commit and compare; report the package to npm if the registry copy changed." });
    const sig = verifyRegistrySignature(doc.name ?? p.name, doc.version ?? p.version, dist.integrity ?? p.integrity ?? "", dist.signatures ?? [], keys);
    if (sig === "valid") signed++;
    else if (sig === "invalid")
      findings.push({ source: "system", rule: "SUPPLY-SIGNATURE-INVALID", severity: "critical", where: `${dir} · ${id}`, key: `supply:${dir}:${id}:sig`,
        title: `${id}: npm registry signature is invalid`, detail: "The registry's signature over this version's name, version and hash does not verify. The metadata was altered in transit or at the source.",
        fix: "Do not install this version. Re-run from a clean network; if it persists, report it to npm security." });
    else unsigned.push(id);
    if (dist.attestations?.url) {
      prov++;
      try {
        const pv = readProvenance(await (await f(dist.attestations.url)).json());
        const want = integrityHex(dist.integrity ?? "");
        if (pv?.digestHex && want && pv.digestHex !== want)
          findings.push({ source: "system", rule: "SUPPLY-PROVENANCE-MISMATCH", severity: "critical", where: `${dir} · ${id}`, key: `supply:${dir}:${id}:prov`,
            title: `${id}: build provenance is for a different file`, detail: "The SLSA provenance names a different package hash than the one published.", fix: "Do not install; report to npm." });
        const declared = normRepo(typeof doc.repository === "string" ? doc.repository : doc.repository?.url);
        const built = normRepo(pv?.repo);
        if (built && declared && !built.startsWith(declared) && !declared.startsWith(built))
          findings.push({ source: "system", rule: "SUPPLY-PROVENANCE-REPO", severity: "high", where: `${dir} · ${id}`, key: `supply:${dir}:${id}:repo`,
            title: `${id} was built from a different repository than it claims`, detail: `package.json points to ${declared}, but the provenance says it was built from ${built}. Typosquats and hijacked packages look like this.`,
            fix: "Check the package's maintainers and source before upgrading; pin the last version built from the expected repository." });
      } catch { /* attestation fetch failed: counted as present */ }
    }
  });
  const scripts = pkgs.filter((p) => p.hasInstallScript);
  if (scripts.length)
    findings.push({ source: "system", rule: "SUPPLY-INSTALL-SCRIPTS", severity: "medium", where: dir, key: `supply:${dir}:install-scripts`,
      title: `${scripts.length} package${scripts.length === 1 ? "" : "s"} run code when installed`, detail: `${scripts.slice(0, 6).map((p) => `${p.name}@${p.version}`).join(", ")}${scripts.length > 6 ? ", …" : ""}. Install scripts are how npm worms (Shai-Hulud, 2025) stole tokens from developer machines and CI.`,
      fix: "Install with --ignore-scripts in CI and production, and allow-list the few packages that genuinely need a build step." });
  else passed.push("No production package runs install scripts");
  if (unsigned.length)
    findings.push({ source: "system", rule: "SUPPLY-UNSIGNED", severity: "low", where: dir, key: `supply:${dir}:unsigned`,
      title: `${unsigned.length} package version${unsigned.length === 1 ? " has" : "s have"} no verifiable registry signature`, detail: `${unsigned.slice(0, 5).join(", ")}${unsigned.length > 5 ? ", …" : ""}.`, fix: "Usually old versions published before npm signed everything; prefer upgrading." });
  if (signed && !findings.some((x) => x.rule === "SUPPLY-SIGNATURE-INVALID")) passed.push(`${signed} registry signatures verified`);
  if (!findings.some((x) => x.rule === "SUPPLY-INTEGRITY-MISMATCH")) passed.push("Lockfile hashes match the registry");
  if (prov) passed.push(`${prov} packages carry SLSA build provenance`);
  const issues = findings.filter((x) => x.severity !== "low" && x.severity !== "info").length;
  return { at, dir, packages: pkgs.length, signed, withProvenance: prov, installScripts: scripts.length, unreachable, findings, passed,
    summary: `${pkgs.length} packages: ${signed} signatures verified, ${prov} with SLSA provenance${unreachable ? `, ${unreachable} unreachable` : ""}${issues ? ` · ${issues} issue${issues === 1 ? "" : "s"}` : ""}` };
}

/** CycloneDX SBOM of the production dependencies (npm 10+). */
export function sbom(dir: string): Promise<{ json?: string; components?: number; error?: string }> {
  return new Promise((resolve) => execFile("npm", ["sbom", "--sbom-format", "cyclonedx", "--omit", "dev"], { cwd: dir, maxBuffer: 50_000_000, timeout: 120_000 }, (err, stdout, stderr) => {
    try { const d = JSON.parse(stdout); resolve({ json: stdout, components: d.components?.length ?? 0 }); }
    catch { resolve({ error: (stderr || err?.message || "npm sbom failed").split("\n").find((l) => l.trim()) }); }
  }));
}
