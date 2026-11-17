import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkSecureHeaders, loadSecureHeaders, zapFindings, zapBaseline, dependencyCheckFindings, toDefectDojo, pushToDefectDojo, uploadToDependencyTrack, ZAP_RULE } from "../src/integrations/owasp.ts";
import { AlertBus } from "../src/alerts.ts";

const LISTS = { source: "live" as const, updated: "2026-10-18 07:04:36", remove: ["$wsep", "Server", "X-Powered-By"],
  add: [{ name: "Cache-Control", value: "no-store, max-age=0" }, { name: "Clear-Site-Data", value: "\"cache\"" }, { name: "Content-Security-Policy", value: "default-src 'self'" }, { name: "Cross-Origin-Opener-Policy", value: "same-origin" }] };

test("OWASP Secure Headers: leaking headers, missing headers and the legacy XSS filter", () => {
  const h = new Headers({ server: "nginx/1.25.3", "x-xss-protection": "1; mode=block", "cache-control": "no-store" });
  const r = checkSecureHeaders(h, LISTS, "site");
  assert.deepEqual(r.findings.map((f) => f.rule).sort(), ["OWASP-SHP-MISSING", "OWASP-SHP-REMOVE", "OWASP-XSS-PROTECTION"]);
  const miss = r.findings.find((f) => f.rule === "OWASP-SHP-MISSING")!;
  assert.match(miss.detail, /Cross-Origin-Opener-Policy/); assert.ok(!/Clear-Site-Data|Content-Security-Policy/.test(miss.detail), "logout-only and already-covered headers are skipped");
  const ok = checkSecureHeaders(new Headers({ "cache-control": "no-store", "cross-origin-opener-policy": "same-origin", "x-xss-protection": "0" }), LISTS, "site");
  assert.deepEqual(ok.findings, []); assert.equal(ok.passed.length, 2);
});

test("OWASP Secure Headers: live lists are cached, and a built-in list is used offline", async () => {
  const dir = mkdtempSync(join(tmpdir(), "shp-"));
  const live = (async (u: string) => new Response(JSON.stringify(u.endsWith("headers_add.json") ? { last_update_utc: "2026-10-18", headers: LISTS.add } : { headers: LISTS.remove }))) as unknown as typeof fetch;
  assert.equal((await loadSecureHeaders(dir, live)).source, "live");
  assert.equal((await loadSecureHeaders(dir, live)).source, "cache");
  const off = (async () => { throw new Error("offline"); }) as unknown as typeof fetch;
  const b = await loadSecureHeaders(mkdtempSync(join(tmpdir(), "shp2-")), off);
  assert.equal(b.source, "built-in"); assert.ok(b.remove.includes("Server"));
});

const ZAP_REPORT = JSON.stringify({ "@version": "2.16.1", site: [{ "@name": "https://console.example", "@host": "console.example", "@port": "443", "@ssl": "true", alerts: [
  { pluginid: "10038", alertRef: "10038-1", alert: "Content Security Policy (CSP) Header Not Set", name: "Content Security Policy (CSP) Header Not Set", riskcode: "2", confidence: "3", riskdesc: "Medium (High)", desc: "<p>Content Security Policy (CSP) is an added layer of security.</p>", solution: "<p>Ensure that your web server sets the CSP header.</p>", cweid: "693", wascid: "15", count: "2",
    instances: [{ uri: "https://console.example/", method: "GET", param: "", evidence: "" }, { uri: "https://console.example/kits", method: "GET" }] },
  { pluginid: "40012", alertRef: "40012", alert: "Cross Site Scripting (Reflected)", name: "Cross Site Scripting (Reflected)", riskcode: "3", confidence: "2", desc: "<p>XSS</p>", solution: "<p>Encode output.</p>", cweid: "79", instances: [{ uri: "https://console.example/search?q=x", method: "GET", param: "q" }] },
] }] });

test("OWASP ZAP: Traditional JSON reports become findings with risk mapped", () => {
  const f = zapFindings(ZAP_REPORT);
  assert.deepEqual(f.map((x) => [x.rule, x.severity]), [["ZAP-10038", "medium"], ["ZAP-40012", "high"]]);
  assert.match(f[0].title, /2 places/); assert.match(f[1].detail, /parameter q/); assert.equal(f[1].fix, "Encode output.");
  assert.equal(ZAP_RULE["WEB-NO-CSP"], "10038");
  assert.deepEqual(zapFindings("not json"), []);
});

test("OWASP ZAP: drives a daemon through spider, passive scan and report", async () => {
  const calls: string[] = []; let polls = 0;
  const f = (async (u: string) => {
    const p = new URL(u); calls.push(p.pathname); assert.equal(p.searchParams.get("apikey"), "k");
    if (p.pathname.endsWith("/spider/action/scan/")) return new Response(JSON.stringify({ scan: "1" }));
    if (p.pathname.endsWith("/spider/view/status/")) return new Response(JSON.stringify({ status: polls++ ? "100" : "50" }));
    if (p.pathname.endsWith("/pscan/view/recordsToScan/")) return new Response(JSON.stringify({ recordsToScan: "0" }));
    if (p.pathname.endsWith("/core/other/jsonreport/")) return new Response(ZAP_REPORT);
    return new Response("", { status: 404 });
  }) as unknown as typeof fetch;
  const rep = await zapBaseline("https://console.example", { api: "http://zap:8090", key: "k", fetch: f });
  assert.equal(zapFindings(rep).length, 2);
  assert.ok(!calls.some((c) => /ascan/.test(c)), "never starts an active scan");
});

test("OWASP Dependency-Check: JSON report becomes findings with CVE ids", () => {
  const f = dependencyCheckFindings(JSON.stringify({ dependencies: [{ fileName: "body-parser:1.20.2", packages: [{ id: "pkg:npm/body-parser@1.20.2" }],
    vulnerabilities: [{ source: "NVD", name: "CVE-2024-45590", severity: "HIGH", cvssv3: { baseScore: 7.5 }, description: "body-parser DoS" }] }, { fileName: "clean.js" }] }), "/app");
  assert.equal(f.length, 1); assert.equal(f[0].severity, "high"); assert.match(f[0].detail, /CVSS 7\.5/);
  assert.deepEqual(f[0].evidence!.advisories, ["CVE-2024-45590"]);
});

test("OWASP DefectDojo: Generic Findings Import format, and the push uses import-scan", async () => {
  const bus = new AlertBus(mkdtempSync(join(tmpdir(), "dd-")));
  bus.raise({ source: "code", rule: "CODE-SECRET", severity: "critical", title: "Secret in code", detail: "d", fix: "rotate", where: "src/a.ts:12" });
  const dep = bus.raise({ source: "system", rule: "SYS-VULN-DEPENDENCY", severity: "high", title: "lib", detail: "d", evidence: { cves: ["CVE-2099-1"], kev: true, epss: 0.4 } })!;
  bus.acknowledge(bus.raise({ source: "web", rule: "WEB-NO-CSP", severity: "medium", title: "no csp", detail: "d" })!.id, "me");
  const rep = toDefectDojo(bus.list(), { "LLM02": "Sensitive Information Disclosure" });
  assert.equal(rep.findings.length, 2, "handled alerts are not exported");
  const sec = rep.findings.find((x) => x.vuln_id_from_tool === "CODE-SECRET")!;
  assert.equal(sec.severity, "Critical"); assert.equal(sec.file_path, "src/a.ts"); assert.equal(sec.line, 12); assert.match(sec.references, /LLM02 Sensitive Information Disclosure/);
  const d = rep.findings.find((x) => x.unique_id_from_tool === dep.id)!;
  assert.deepEqual(d.vulnerability_ids, ["CVE-2099-1"]); assert.equal(d.known_exploited, true); assert.equal(d.epss_score, 0.4);
  let sent: { url: string; auth: string; form: FormData } | undefined;
  const f = (async (url: string, init: RequestInit) => { sent = { url, auth: (init.headers as Record<string, string>).Authorization, form: init.body as FormData }; return new Response(JSON.stringify({ test: 7 }), { status: 201 }); }) as unknown as typeof fetch;
  const r = await pushToDefectDojo(rep, { url: "https://dojo.example/", token: "t0k", fetch: f });
  assert.equal(r.test, 7); assert.equal(sent!.url, "https://dojo.example/api/v2/import-scan/"); assert.equal(sent!.auth, "Token t0k");
  assert.equal(sent!.form.get("scan_type"), "Generic Findings Import"); assert.equal(sent!.form.get("auto_create_context"), "true");
  await assert.rejects(pushToDefectDojo(rep, { url: "", token: "" }), /DEFECTDOJO_URL/);
});

test("OWASP Dependency-Track: SBOM upload with project auto-create", async () => {
  let sent: { url: string; key: string; form: FormData } | undefined;
  const f = (async (url: string, init: RequestInit) => { sent = { url, key: (init.headers as Record<string, string>)["X-Api-Key"], form: init.body as FormData }; return new Response(JSON.stringify({ token: "abc" })); }) as unknown as typeof fetch;
  const r = await uploadToDependencyTrack('{"bomFormat":"CycloneDX"}', { url: "https://dtrack.example", key: "k1", project: "agent-desk", version: "main", fetch: f });
  assert.equal(r.token, "abc"); assert.equal(sent!.url, "https://dtrack.example/api/v1/bom"); assert.equal(sent!.key, "k1");
  assert.equal(sent!.form.get("projectName"), "agent-desk"); assert.equal(sent!.form.get("autoCreate"), "true");
  assert.equal(await (sent!.form.get("bom") as Blob).text(), '{"bomFormat":"CycloneDX"}');
});
