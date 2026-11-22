/**
 * System scanner: checks the machine Agent Shield (and the agent) runs on, and the
 * agent's dependencies.
 *
 *  - services listening on every network interface (read from /proc/net/tcp, no tools needed)
 *  - running as root
 *  - Node.js past end of life
 *  - SSH allowing root or password logins
 *  - key and secret files readable by other users
 *  - monitored folders anyone can write to
 *  - known vulnerabilities in the agent's npm dependencies (npm audit)
 */
import { readFileSync, existsSync, statSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { execFile } from "node:child_process";
import type { Finding, Severity } from "../alerts.ts";
import { nodeStatus } from "./outdated.ts";

export interface SystemScanResult { at: string; host: string; findings: Finding[]; passed: string[]; summary: string; listening: { port: number; address: string }[] }

const WELL_KNOWN: Record<number, string> = { 22: "SSH", 23: "Telnet", 21: "FTP", 25: "SMTP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached", 2375: "Docker API (unauthenticated)", 5900: "VNC", 3389: "Remote Desktop", 8080: "web server", 4600: "Agent Shield dashboard", 4610: "agent prompt endpoint", 4320: "Agent Desk store", 9229: "Node.js debugger" };
const RISKY = new Set([23, 21, 2375, 6379, 27017, 9200, 11211, 5900, 9229, 3306, 5432]);

function listening(): { port: number; address: string }[] {
  const out: { port: number; address: string }[] = [];
  for (const file of ["/proc/net/tcp", "/proc/net/tcp6"]) {
    if (!existsSync(file)) continue;
    for (const line of readFileSync(file, "utf8").split("\n").slice(1)) {
      const p = line.trim().split(/\s+/);
      if (p[3] !== "0A") continue; // LISTEN
      const [hexAddr, hexPort] = p[1].split(":");
      const port = parseInt(hexPort, 16);
      const all = /^0+$/.test(hexAddr);
      const loop = hexAddr === "0100007F" || hexAddr === "00000000000000000000000001000000";
      out.push({ port, address: all ? (file.endsWith("6") ? "[::]" : "0.0.0.0") : loop ? "loopback" : "specific" });
    }
  }
  return [...new Map(out.map((x) => [`${x.port}:${x.address}`, x])).values()].sort((a, b) => a.port - b.port);
}

export function scanSystem(opts: { targetDir: string; watchDirs: string[] }): SystemScanResult {
  const out: Finding[] = [], passed: string[] = [];
  const host = (() => { try { return readFileSync("/etc/hostname", "utf8").trim(); } catch { return "this machine"; } })();
  const f = (rule: string, severity: Severity, title: string, detail: string, fix: string, where = host) => out.push({ source: "system", rule, severity, title, detail, fix, where, key: `sys:${host}:${rule}:${where}` });

  // Network exposure
  const ports = listening();
  const open = ports.filter((p) => p.address === "0.0.0.0" || p.address === "[::]");
  for (const p of open) {
    const name = WELL_KNOWN[p.port] ?? "a service";
    f("SYS-OPEN-PORT", RISKY.has(p.port) ? "high" : p.port === 22 ? "low" : "medium", `${name} on port ${p.port} is reachable from the network`,
      `Port ${p.port} listens on every interface (${p.address}).${RISKY.has(p.port) ? " This kind of service is a common first target." : ""}`,
      RISKY.has(p.port) ? "Bind it to 127.0.0.1 or put it behind a firewall rule that allows only known addresses." : "Confirm it needs to be reachable; otherwise bind it to 127.0.0.1.", `${host}:${p.port}`);
  }
  if (!open.length) passed.push(`No services open to the network (${ports.length} listening on this machine only)`);

  // Privileges and runtime
  if (process.getuid?.() === 0) f("SYS-ROOT", "medium", "Running as root", "If anything in this process is compromised, the attacker owns the whole machine.", "Run the agent and Agent Shield as an unprivileged user (or a container user).");
  else passed.push("Not running as root");
  const major = Number(process.versions.node.split(".")[0]);
  const ns = nodeStatus(major);
  if (ns.eol) f("SYS-NODE-EOL", "high", `Node.js ${process.versions.node} no longer gets security fixes`, `Security fixes ended (${ns.date}); end-of-life runtimes stay vulnerable to published bugs.`, "Upgrade to Node.js 22 or 24 LTS.");
  else passed.push(`Node.js ${process.versions.node} is supported until ${ns.date}`);

  // SSH
  if (existsSync("/etc/ssh/sshd_config")) {
    const cfg = readFileSync("/etc/ssh/sshd_config", "utf8");
    const val = (k: string) => new RegExp(`^\\s*${k}\\s+(\\S+)`, "mi").exec(cfg)?.[1]?.toLowerCase();
    if (val("PermitRootLogin") === "yes") f("SYS-SSH-ROOT", "high", "SSH allows root login", "Password sprays against root are constant on the internet.", "Set PermitRootLogin no.", "/etc/ssh/sshd_config");
    if (val("PasswordAuthentication") !== "no") f("SYS-SSH-PASSWORD", "medium", "SSH accepts passwords", "Passwords can be sprayed; keys cannot.", "Set PasswordAuthentication no and use keys.", "/etc/ssh/sshd_config");
    else passed.push("SSH uses keys only");
  } else passed.push("No SSH server configured");

  // Secret files readable by others
  const secrets = [".env", ".env.local", ".metal/operator.json", "infra/merchant.json", "id_rsa", ".aws/credentials"]
    .map((p) => join(opts.targetDir, p)).filter((p) => existsSync(p));
  let loose = 0;
  for (const p of secrets) {
    const mode = statSync(p).mode & 0o777;
    if (mode & 0o077) { loose++; f("SYS-SECRET-PERMS", "medium", `Secret file readable by other users: ${p.replace(opts.targetDir + "/", "")}`, `Permissions are ${mode.toString(8)}; any other account on this machine can read the keys.`, `chmod 600 ${p}`, p); }
  }
  if (secrets.length && !loose) passed.push(`${secrets.length} secret file${secrets.length === 1 ? " is" : "s are"} private (600)`);

  // Monitored folders anyone can write to
  for (const d of opts.watchDirs.filter((x) => existsSync(x))) {
    if (statSync(d).mode & 0o002) f("SYS-WORLD-WRITABLE", "medium", `Anyone on this machine can write to ${d}`, "A world-writable folder lets any process plant or replace files the agent trusts.", `chmod o-w ${d}`, d);
  }
  return { at: new Date().toISOString(), host, findings: out, passed, listening: ports, summary: out.length ? `${out.length} issue${out.length === 1 ? "" : "s"} on ${host}` : `No issues on ${host}` };
}

export interface DepScanResult { at: string; dir: string; findings: Finding[]; counts: Record<string, number>; summary: string }

/** npm audit of the target's dependencies. Needs the target's package-lock.json and the npm registry. */
export function scanDependencies(dir: string): Promise<DepScanResult> {
  return new Promise((resolve) => {
    if (!existsSync(join(dir, "package-lock.json"))) return resolve({ at: new Date().toISOString(), dir, findings: [], counts: {}, summary: "No package-lock.json to audit" });
    execFile("npm", ["audit", "--json", "--omit=dev"], { cwd: dir, maxBuffer: 20_000_000, timeout: 120_000 }, (_err, stdout) => {
      let data: any = {};
      try { data = JSON.parse(stdout || "{}"); } catch { /* keep empty */ }
      const vulns: Record<string, any> = data.vulnerabilities ?? {};
      const map: Record<string, Severity> = { critical: "critical", high: "high", moderate: "medium", low: "low", info: "info" };
      // A package's "via" names either an advisory or another vulnerable package; follow it to the advisories.
      const advisories = (name: string, seen = new Set<string>()): any[] => {
        if (seen.has(name) || !vulns[name]) return []; seen.add(name);
        return (vulns[name].via ?? []).flatMap((x: any) => (typeof x === "object" ? [x] : advisories(x, seen)));
      };
      const findings: Finding[] = Object.values(vulns).filter((v: any) => v.isDirect || v.severity === "critical" || v.severity === "high").map((v: any) => {
        const via = advisories(v.name);
        const root = [...new Set(via.map((a: any) => a.name))].filter((n) => n !== v.name);
        const title = `${via[0]?.title ?? "known vulnerability"}${root.length ? ` (in ${root.slice(0, 2).join(", ")})` : ""}`;
        return {
          source: "system" as const, rule: "SYS-VULN-DEPENDENCY", severity: map[v.severity] ?? "medium", where: `${dir} · ${v.name}`, key: `dep:${dir}:${v.name}`,
          title: `${v.name}: ${title}`,
          detail: `${v.name} ${v.range ?? ""} has a ${v.severity} vulnerability${via[0]?.url ? ` (${via[0].url})` : ""}.${v.isDirect ? " It is a direct dependency." : ` Pulled in by ${(v.effects ?? []).slice(0, 3).join(", ") || "another package"}.`}`,
          evidence: { advisories: [...new Set(via.map((x: any) => String(x.url ?? "").split("/").pop()).filter((x): x is string => /^(GHSA|CVE)-/.test(x ?? "")))], cvss: Math.max(0, ...via.map((x: any) => Number(x.cvss?.score) || 0)) },
          fix: v.fixAvailable ? (typeof v.fixAvailable === "object" ? `Upgrade ${v.fixAvailable.name} to ${v.fixAvailable.version}${v.fixAvailable.isSemVerMajor ? " (major version, test first)" : ""}.` : "Run npm audit fix.") : "No fix released yet; check whether the vulnerable code path is used, and watch for a patch.",
        };
      });
      // Many packages can carry the same advisory (one zod bug reaches six x402 packages): one alert per advisory.
      const byTitle = new Map<string, Finding & { pkgs: string[] }>();
      for (const f of findings) {
        const t = f.title.replace(/^[^:]+: /, "").replace(/ \(in [^)]+\)$/, "");
        const pkg = f.title.split(":")[0];
        const prev = byTitle.get(t);
        if (!prev) byTitle.set(t, { ...f, pkgs: [pkg] });
        else { prev.pkgs.push(pkg); prev.evidence = { ...prev.evidence, advisories: [...new Set([...((prev.evidence?.advisories as string[]) ?? []), ...((f.evidence?.advisories as string[]) ?? [])])] }; if (["critical", "high", "medium", "low", "info"].indexOf(f.severity) < ["critical", "high", "medium", "low", "info"].indexOf(prev.severity)) prev.severity = f.severity; }
      }
      findings.length = 0;
      for (const [t, f] of byTitle) findings.push({ ...f, pkgs: undefined, key: `dep:${dir}:${t}`, where: `${dir}`,
        title: f.pkgs.length > 1 ? `${t.replace(/ \(in [^)]+\)$/, "")}, through ${f.pkgs.length} packages` : `${f.pkgs[0]}: ${t}`,
        detail: f.pkgs.length > 1 ? `Affected: ${f.pkgs.join(", ")}. ${f.detail}` : f.detail } as Finding);
      const counts = data.metadata?.vulnerabilities ?? {};
      const total = Object.entries(counts).filter(([k]) => k !== "total").reduce((s, [, n]) => s + Number(n), 0);
      resolve({ at: new Date().toISOString(), dir, findings, counts, summary: total ? `${total} known vulnerabilit${total === 1 ? "y" : "ies"} (${counts.critical ?? 0} critical, ${counts.high ?? 0} high)` : "No known vulnerabilities" });
    });
  });
}

export const listDir = (d: string) => { try { return readdirSync(d); } catch { return []; } };
