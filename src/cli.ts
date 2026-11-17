/**
 * Command line: `npm run scan` prints the findings for the target and exits non-zero if
 * anything high or critical is open (so it can gate a CI pipeline). `npm run probe` prints
 * the prompt-injection probe results family by family.
 */
import { scanTarget, targetFromEnv, loadGuard } from "./scan.ts";
import { runProbes, hardenGuard, probeSummary } from "./detectors/llm-probes.ts";
import { rank, SEVERITIES } from "./alerts.ts";
import { runPromptfoo, redteamFindings, redteamReady } from "./integrations/promptfoo.ts";
import { readGarakFindings } from "./integrations/garak.ts";

const C = { critical: "\x1b[41;97m", high: "\x1b[31m", medium: "\x1b[33m", low: "\x1b[36m", info: "\x1b[90m" } as const;
const R = "\x1b[0m";

const cmd = process.argv[2] ?? "scan";
const t = targetFromEnv();

if (cmd === "scan") {
  const r = await scanTarget(t);
  console.log(`\nAgent Shield · ${t.name} · ${r.files} source files\n`);
  for (const f of r.findings.sort((a, b) => rank(b.severity) - rank(a.severity))) {
    console.log(`${C[f.severity]} ${f.severity.toUpperCase()} ${R} ${f.title}\n   ${f.where ?? ""}\n   ${f.detail}\n   → ${f.fix ?? ""}\n`);
  }
  const counts = SEVERITIES.map((s) => `${s} ${r.findings.filter((f) => f.severity === s).length}`).join(" · ");
  console.log(counts);
  if (r.probes) console.log(`injection guard: caught ${Math.round(r.probes.detectionRate * 100)}% of ${r.probes.attacks} attacks, ${r.probes.falsePositives} false alarms on ${r.probes.benign} benign texts · with normalisation: ${Math.round(r.probes.hardened.detectionRate * 100)}%`);
  process.exitCode = r.findings.some((f) => rank(f.severity) >= rank("high")) ? 1 : 0;
} else if (cmd === "probe") {
  const guard = await loadGuard(t);
  if (!guard) { console.error(`no guard found at ${t.guard}`); process.exit(2); }
  for (const [label, g] of [["as is", guard], ["normalised", hardenGuard(guard)]] as const) {
    const res = runProbes(g);
    console.log(`\n${label}:`);
    for (const r of res) console.log(`  ${r.ok ? "✓" : "✗"} ${r.probe.family.padEnd(13)} ${r.probe.id.padEnd(26)} ${r.probe.attack ? (r.flagged ? "caught" : "MISSED") : (r.flagged ? "FALSE ALARM" : "passed")}`);
    const s = probeSummary(res);
    console.log(`  → ${Math.round(s.detectionRate * 100)}% of attacks caught, ${s.falsePositives} false alarms`);
  }
}

else if (cmd === "redteam") {
  if (!redteamReady()) { console.error("Set ANTHROPIC_API_KEY (and AGENT_MODEL) to red-team the live model, or run `npm run redteam:dry` for an offline dry run."); process.exit(2); }
  const r = await runPromptfoo();
  console.log(`\npromptfoo red-team · ${r.provider} · ${r.passed} passed, ${r.failed} failed, ${r.errors} errors\n`);
  for (const c of r.cases) console.log(`  ${c.error ? "!" : c.passed ? "✓" : "✗"} ${c.family.padEnd(13)} ${c.description}${c.passed ? "" : `\n      ${c.error ?? c.reasons.join("; ")}`}`);
  const f = redteamFindings(r);
  process.exitCode = f.some((x) => rank(x.severity) >= rank("high")) ? 1 : 0;
} else if (cmd === "garak") {
  const path = process.argv[3];
  if (!path) { console.error("usage: npm run garak:import -- <garak report.jsonl>"); process.exit(2); }
  const fs = readGarakFindings(path);
  for (const f of fs) console.log(`${C[f.severity]} ${f.severity.toUpperCase()} ${R} ${f.title}\n   ${f.detail}`);
  if (!fs.length) console.log("garak: no failed probes in this report");
}
