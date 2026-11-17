/**
 * Live detection test with Stratus Red Team, in a SANDBOX AWS account only.
 *
 *   npm run stratus -- list                                   coverage map, with the offline replay result
 *   npm run stratus -- aws.persistence.iam-backdoor-role      warm up, detonate, wait for the alert, clean up
 *
 * Needs: the stratus CLI (github.com/DataDog/stratus-red-team), AWS credentials for a
 * sandbox account, and Agent Shield running with CLOUDTRAIL_LIVE=1 against that account.
 * CloudTrail delivers events in about 5 to 15 minutes, so the wait defaults to 20.
 */
import { execFileSync } from "node:child_process";
import { TECHNIQUES, replayCoverage } from "../src/integrations/stratus.ts";

const [arg] = process.argv.slice(2);
const SHIELD = process.env.SHIELD_URL ?? "http://127.0.0.1:4600";
const WAIT_MIN = Number(process.env.STRATUS_WAIT_MIN ?? 20);

if (!arg || arg === "list") {
  for (const r of replayCoverage()) console.log(`${r.covered === "no" ? "gap " : r.pass ? "ok  " : "FAIL"}  ${r.id.padEnd(62)} ${r.expects.join(", ") || "-"}${r.note ? `  (${r.note})` : ""}`);
  process.exit(0);
}
const tech = TECHNIQUES.find((t) => t.id === arg);
if (!tech) { console.error(`Unknown technique ${arg}. Run: npm run stratus -- list`); process.exit(2); }
if (tech.covered === "no") console.warn(`Note: ${arg} is a known gap (${tech.note}). Running it anyway shows what is missed.`);

const stratus = (...a: string[]) => execFileSync("stratus", a, { stdio: "inherit" });
try { execFileSync("stratus", ["version"], { stdio: "ignore" }); } catch { console.error("The stratus CLI is not installed: https://github.com/DataDog/stratus-red-team/releases"); process.exit(2); }

const headers: Record<string, string> = process.env.SHIELD_TOKEN ? { authorization: `Bearer ${process.env.SHIELD_TOKEN}` } : {};
const started = new Date().toISOString();
console.log(`Detonating ${arg} at ${started}; expecting ${tech.expects.join(", ") || "nothing (gap)"}.`);
stratus("detonate", arg);
let found: { rule: string; title: string } | undefined;
const until = Date.now() + WAIT_MIN * 60_000;
while (!found && Date.now() < until) {
  await new Promise((r) => setTimeout(r, 30_000));
  const s = (await (await fetch(`${SHIELD}/api/state`, { headers })).json()) as { alerts: { rule: string; title: string; at: string; updatedAt?: string }[] };
  found = s.alerts.find((a) => tech.expects.includes(a.rule) && (a.updatedAt ?? a.at) >= started);
  process.stdout.write(found ? "\n" : ".");
}
console.log(found ? `DETECTED: ${found.rule} — ${found.title}` : `NOT DETECTED within ${WAIT_MIN} min. Check CLOUDTRAIL_LIVE, the region and whether the trail logs these events.`);
stratus("cleanup", arg);
process.exit(found ? 0 : 1);
