/**
 * Website scanner: a passive, polite check of a site you own (for Agent Desk, the hosted
 * console). It only reads: about 25 GET requests, one at a time, no logins, no payloads.
 *
 * It checks what an automated attacker would look at first:
 *  - HTTPS: redirect from HTTP, HSTS, certificate expiry
 *  - browser protections: Content-Security-Policy, framing, MIME sniffing, referrer, permissions
 *  - cookies without Secure / HttpOnly / SameSite
 *  - files that should never be public: .env, .git, backups, config, server status pages
 *  - JavaScript source maps (ARTEX reads them to find API routes, then calls those routes)
 *  - CORS that reflects any origin with credentials
 *  - server software and versions given away in headers
 *
 * Sites you own (SCAN_ALLOWED_HOSTS, the console, localhost, or confirmed "I own or may test this
 * site") get the full check. Any other public site gets a passive check only: the page itself,
 * its HTTP-to-HTTPS redirect and TLS handshakes, the same requests a browser or SSL Labs makes,
 * and no probing for hidden files, source maps or CORS behaviour.
 */
import { tlsFindings } from "./crypto.ts";
import { connect } from "node:tls";
import type { Finding, Severity } from "../alerts.ts";
import { checkSecureHeaders, ZAP_RULE, type SecureHeaderLists } from "../integrations/owasp.ts";

export interface WebScanResult { url: string; at: string; requests: number; findings: Finding[]; passed: string[]; summary: string; mode: "full" | "passive" }

const UA = "AgentShield-WebScan/0.1 (+passive security check)";
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function allowedHosts(): string[] {
  return ["localhost", "127.0.0.1", "d1zoxhgak5pvwd.cloudfront.net", ...(process.env.SCAN_ALLOWED_HOSTS ?? "").split(",").map((s) => s.trim()).filter(Boolean)];
}

async function get(url: string, opts: { headers?: Record<string, string>; method?: string } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 12_000);
  try {
    const r = await fetch(url, { method: opts.method ?? "GET", redirect: "manual", headers: { "user-agent": UA, ...(opts.headers ?? {}) }, signal: ctrl.signal });
    const body = r.status === 200 ? (await r.text()).slice(0, 200_000) : "";
    return { status: r.status, headers: r.headers, body };
  } catch (e) {
    return { status: 0, headers: new Headers(), body: "", error: (e as Error).message };
  } finally { clearTimeout(t); }
}

function certDaysLeft(host: string, port = 443): Promise<number | null> {
  // Behind an intercepting proxy the certificate seen is the proxy's, so skip it there.
  if (process.env.HTTPS_PROXY || process.env.https_proxy) return Promise.resolve(null);
  return new Promise((resolve) => {
    const s = connect({ host, port, servername: host, timeout: 8000 }, () => {
      const c = s.getPeerCertificate(); s.end();
      resolve(c?.valid_to ? Math.floor((Date.parse(c.valid_to) - Date.now()) / 86_400_000) : null);
    });
    s.on("error", () => resolve(null)); s.on("timeout", () => { s.destroy(); resolve(null); });
  });
}

/** A page that answers 200 for every path (SPA fallback) is not an exposed file. */
const looksLike = (path: string, body: string, ct: string) => {
  if (/text\/html/.test(ct) && /<html|<!doctype/i.test(body)) return false;
  if (path.includes(".env")) return /^[A-Z0-9_]+\s*=/m.test(body);
  if (path.includes(".git/config")) return /\[core\]|\[remote/.test(body);
  if (path.includes(".git/HEAD")) return /^ref: refs\//.test(body);
  if (path.endsWith(".map")) return /"mappings"\s*:/.test(body);
  if (path.includes("server-status")) return /Apache Server Status|Server uptime/i.test(body);
  if (/\.(zip|tar|gz|sql|bak)$/.test(path)) return body.length > 100;
  return body.length > 0;
};

const SENSITIVE: [string, Severity, string][] = [
  ["/.env", "critical", "environment file with keys"],
  ["/.git/config", "high", "git repository config"],
  ["/.git/HEAD", "high", "git repository"],
  ["/config.json", "medium", "configuration file"],
  ["/backup.zip", "high", "backup archive"],
  ["/db.sql", "critical", "database dump"],
  ["/server-status", "medium", "server status page"],
  ["/.DS_Store", "low", "folder listing file"],
  ["/swagger.json", "low", "API description"],
];

export async function scanWebsite(input: string, opts: { authorised?: boolean; secureHeaders?: SecureHeaderLists } = {}): Promise<WebScanResult> {
  const url = new URL(/^https?:\/\//.test(input) ? input : `https://${input}`);
  const mode: "full" | "passive" = allowedHosts().includes(url.hostname) || opts.authorised ? "full" : "passive";
  const base = `${url.protocol}//${url.host}`;
  const out: Finding[] = [], passed: string[] = [];
  let requests = 0;
  const f = (rule: string, severity: Severity, title: string, detail: string, fix: string, where = base) =>
    out.push({ source: "web", rule, severity, title, detail, fix, where, key: `web:${url.host}:${rule}:${where}`, ...(ZAP_RULE[rule] ? { evidence: { zapRule: ZAP_RULE[rule] } } : {}) });
  const hit = async (u: string, o?: Parameters<typeof get>[1]) => { requests++; const r = await get(u, o); await sleep(150); return r; };

  // 1. The page itself
  const home = await hit(url.href);
  if (home.status === 0) throw new Error(`could not reach ${url.href}: ${(home as { error?: string }).error ?? "no answer"}`);
  const h = home.headers;

  // 2. HTTPS
  if (url.protocol === "https:") {
    const plain = await hit(`http://${url.host}${url.pathname}`);
    if (plain.status >= 200 && plain.status < 300) f("WEB-NO-HTTPS-REDIRECT", "medium", "Site also answers over plain HTTP", "The page loads over http:// without being sent to https://, so a network attacker can read or change it.", "Redirect all HTTP to HTTPS (CloudFront: viewer protocol policy “Redirect HTTP to HTTPS”).");
    else passed.push("HTTP redirects to HTTPS");
    const hsts = h.get("strict-transport-security");
    if (!hsts) f("WEB-NO-HSTS", "medium", "No HSTS header", "Browsers are not told to always use HTTPS for this site.", "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.");
    else if (Number(/max-age=(\d+)/.exec(hsts)?.[1] ?? 0) < 15_552_000) f("WEB-WEAK-HSTS", "low", "HSTS lasts less than 6 months", `Header: ${hsts}`, "Use max-age=31536000 or more.");
    else passed.push("HSTS is on");
    const days = await certDaysLeft(url.hostname, Number(url.port || 443));
    if (days !== null && days < 14) f("WEB-CERT-EXPIRING", days < 3 ? "critical" : "high", `TLS certificate expires in ${days} days`, "When it expires every visitor gets a security error.", "Renew it now; use automatic renewal (ACM renews CloudFront certificates on its own).");
    else if (days !== null) passed.push(`Certificate valid for ${days} more days`);
    // cryptographic checks on the TLS connection (A04:2025)
    const t = await tlsFindings(url.hostname, Number(url.port || 443));
    out.push(...t.findings); passed.push(...t.passed);
  } else f("WEB-HTTP-ONLY", "high", "Site is served over plain HTTP", "Everything, including any login, crosses the network unencrypted.", "Serve it over HTTPS only.");

  // 3. Browser protections
  const csp = h.get("content-security-policy");
  if (!csp) f("WEB-NO-CSP", "medium", "No Content-Security-Policy", "Without a CSP, one injected script (from a compromised library or an XSS bug) can read the page and the signed-in user's tokens.", "Add a Content-Security-Policy that lists the script and connect sources the page needs (CloudFront: a response headers policy).");
  else if (/unsafe-eval|script-src[^;]*\*/.test(csp)) f("WEB-WEAK-CSP", "low", "Content-Security-Policy allows unsafe scripts", `CSP: ${csp.slice(0, 160)}`, "Drop 'unsafe-eval' and wildcard script sources.");
  else passed.push("Content-Security-Policy is set");
  const frame = h.get("x-frame-options") ?? "";
  if (!frame && !/frame-ancestors/.test(csp ?? "")) f("WEB-NO-FRAME-PROTECTION", "medium", "Page can be framed by other sites", "Another site can load this page invisibly and trick a signed-in user into clicking approve.", "Send X-Frame-Options: DENY or CSP frame-ancestors 'none'.");
  else passed.push("Framing is restricted");
  if (!/nosniff/i.test(h.get("x-content-type-options") ?? "")) f("WEB-NO-NOSNIFF", "low", "Missing X-Content-Type-Options: nosniff", "Browsers may guess file types and run uploaded files as scripts.", "Send X-Content-Type-Options: nosniff."); else passed.push("MIME sniffing is off");
  if (!h.get("referrer-policy")) f("WEB-NO-REFERRER-POLICY", "low", "No Referrer-Policy", "Full URLs, which can carry tokens, may leak to other sites.", "Send Referrer-Policy: strict-origin-when-cross-origin or no-referrer."); else passed.push("Referrer-Policy is set");
  if (!h.get("permissions-policy")) f("WEB-NO-PERMISSIONS-POLICY", "info", "No Permissions-Policy", "The page does not switch off browser features it does not use (camera, microphone, location).", "Send Permissions-Policy: camera=(), microphone=(), geolocation=().");

  // 4. Information given away
  const server = [h.get("server"), h.get("x-powered-by"), h.get("x-aspnet-version")].filter(Boolean).join(", ");
  if (/\d+\.\d+/.test(server)) f("WEB-VERSION-LEAK", "low", "Server software version is public", `Headers say: ${server}. Attack tools match versions to known exploits.`, "Remove version numbers from Server and X-Powered-By headers.");

  // 4b. OWASP Secure Headers Project lists
  if (opts.secureHeaders) { const o = checkSecureHeaders(h, opts.secureHeaders, base); out.push(...o.findings); passed.push(...o.passed); }

  // 5. Cookies
  const cookies = (h as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() ?? [];
  for (const c of cookies) {
    const name = c.split("=")[0];
    const missing = [!/;\s*secure/i.test(c) && "Secure", !/;\s*httponly/i.test(c) && "HttpOnly", !/;\s*samesite/i.test(c) && "SameSite"].filter(Boolean);
    if (missing.length) f("WEB-COOKIE-FLAGS", missing.includes("Secure") ? "medium" : "low", `Cookie ${name} is missing ${missing.join(", ")}`, "Cookies without these flags can be read by scripts, sent over HTTP, or sent by other sites.", "Set Secure; HttpOnly; SameSite=Lax (or Strict) on session cookies.", `${base} · cookie ${name}`);
  }
  if (!cookies.length) passed.push("No cookies set without protection");

  if (mode === "passive") {
    const bad = out.filter((x) => x.severity !== "info").length;
    passed.push("Passive check: hidden-file, source-map and CORS probes skipped (not your site)");
    return { url: url.href, at: new Date().toISOString(), requests, findings: out, passed, mode, summary: `${bad ? `${bad} issue${bad === 1 ? "" : "s"}` : "No issues"} · passive check, ${requests} requests` };
  }

  // 6. Files that should never be public
  let exposed = 0;
  for (const [path, sev, what] of SENSITIVE) {
    const r = await hit(base + path);
    if (r.status === 200 && looksLike(path, r.body, r.headers.get("content-type") ?? "")) {
      exposed++;
      f("WEB-EXPOSED-FILE", sev, `Public ${what}: ${path}`, `${base}${path} answers 200 with real content.`, `Remove ${path} from the site and block it at the edge; if it held keys, rotate them.`, base + path);
    }
  }
  if (!exposed) passed.push(`None of ${SENSITIVE.length} sensitive paths are public`);

  // 7. Source maps (ARTEX extracts API routes from them)
  const scripts = [...home.body.matchAll(/<script[^>]+src=["']([^"']+\.js)["']/gi)].map((m) => new URL(m[1], url.href).href).filter((s) => new URL(s).host === url.host).slice(0, 5);
  let maps = 0;
  for (const s of scripts) {
    const js = await hit(s);
    const ref = /\/\/[#@]\s*sourceMappingURL=([^\s]+)/.exec(js.body)?.[1];
    const mapUrl = ref && !ref.startsWith("data:") ? new URL(ref, s).href : `${s}.map`;
    const m = await hit(mapUrl);
    if (m.status === 200 && looksLike(".map", m.body, m.headers.get("content-type") ?? "")) {
      maps++;
      f("WEB-SOURCE-MAP", "medium", `JavaScript source map is public: ${new URL(mapUrl).pathname}`, "Source maps hand over the original code, including every API route. AI attack frameworks read them and call those routes minutes later.", "Do not deploy .map files to production (or restrict them to your network).", mapUrl);
    }
  }
  if (scripts.length && !maps) passed.push("No public source maps");

  // 8. CORS: does the API trust any origin with credentials?
  for (const path of ["/api/state", "/api/", "/"]) {
    const r = await hit(base + path, { headers: { origin: "https://evil.example" } });
    const acao = r.headers.get("access-control-allow-origin");
    if (acao === "https://evil.example" && /true/i.test(r.headers.get("access-control-allow-credentials") ?? "")) {
      f("WEB-CORS-REFLECT", "high", `API trusts any website with credentials (${path})`, "The server echoes back any Origin and allows credentials, so any site a user visits can call the API as them.", "Allow only your own origins.", base + path); break;
    }
    if (acao === "*" && path.startsWith("/api")) { f("WEB-CORS-ANY", "low", `API allows requests from any website (${path})`, "Fine for public data; not for anything signed-in.", "Restrict Access-Control-Allow-Origin to your origins.", base + path); break; }
  }

  const bad = out.filter((x) => x.severity !== "info").length;
  return { url: url.href, at: new Date().toISOString(), requests, findings: out, passed, mode, summary: bad ? `${bad} issue${bad === 1 ? "" : "s"} in ${requests} requests` : `No issues in ${requests} requests` };
}
