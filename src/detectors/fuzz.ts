/**
 * Fuzzing the agent's injection guard (the OSS-Fuzz idea, with property-based testing).
 *
 * Three properties, each run on thousands of generated inputs with a fixed seed, so a
 * failure can be replayed exactly:
 *  1. Never crash: any text, in any script, of any length, returns an answer.
 *  2. Never hang: no input takes more than 100 ms. A slow regular expression (ReDoS) lets
 *     one crafted email stall the agent for every customer.
 *  3. No cheap bypass: take each attack the guard catches, apply small rewrites an attacker
 *     would try (case, spacing, punctuation, zero-width characters, wrapping it in a long
 *     friendly email), and count how many slip through.
 */
import fc from "fast-check";
import type { Finding } from "../alerts.ts";
import { PROBES, type Guard } from "./llm-probes.ts";

const flagged = (r: unknown) => (Array.isArray(r) ? r.length > 0 : Boolean(r));

/** Rewrites an attacker would try on a caught instruction. Each keeps the meaning. */
export const MUTATIONS: [string, (s: string, rnd: () => number) => string][] = [
  ["upper case", (s) => s.toUpperCase()],
  ["random case", (s, r) => [...s].map((c) => (r() < 0.5 ? c.toUpperCase() : c.toLowerCase())).join("")],
  ["double spaces", (s) => s.replace(/ /g, "  ")],
  ["line breaks", (s) => s.replace(/ (?=\w{4,})/g, "\n")],
  ["punctuation", (s) => s.replace(/ /g, " . ").replace(/\. \./g, ".")],
  ["zero-width joiner", (s, r) => [...s].map((c) => (/\w/.test(c) && r() < 0.25 ? c + "‍" : c)).join("")],
  ["non-breaking spaces", (s) => s.replace(/ /g, " ")],
  ["full-width letters", (s, r) => [...s].map((c) => (/[a-z]/i.test(c) && r() < 0.3 ? String.fromCharCode(c.charCodeAt(0) + 0xfee0) : c)).join("")],
  ["quoted", (s) => `> ${s.replace(/\n/g, "\n> ")}`],
  ["markdown", (s) => `**${s}**`],
  ["buried in a long email", (s) => `Hi team,\n\n${"Thanks again for the quick turnaround on last month's invoices. ".repeat(30)}\n\n${s}\n\nBest regards,\nAccounts`],
];

export interface FuzzResult { runs: number; crashes: { input: string; error: string }[]; slow: { input: string; ms: number }[]; bypasses: { probe: string; mutation: string; text: string }[]; mutated: number; seed: number }

export function fuzzGuard(guard: Guard, opts: { runs?: number; seed?: number; slowMs?: number } = {}): FuzzResult {
  const runs = opts.runs ?? 3000, seed = opts.seed ?? 20261117, slowMs = opts.slowMs ?? 100;
  const res: FuzzResult = { runs: 0, crashes: [], slow: [], bypasses: [], mutated: 0, seed };
  const call = (input: string) => {
    const t = performance.now();
    try { const r = guard(input); const ms = performance.now() - t; if (ms > slowMs) res.slow.push({ input, ms }); return r; }
    catch (e) { res.crashes.push({ input: input.slice(0, 200), error: (e as Error).message ?? String(e) }); return null; }
  };
  // 1 + 2: random text of many kinds, plus classic catastrophic-backtracking shapes
  const text = fc.oneof(
    fc.string({ maxLength: 400 }), fc.string({ unit: "grapheme", maxLength: 300 }), fc.string({ unit: "binary", maxLength: 300 }),
    fc.lorem({ maxCount: 60 }), fc.json(),
    fc.tuple(fc.constantFrom("a", " ", "ignore ", "\t", "0", "=", ".", "aa", "<!--", "{\"", "AAAA"), fc.integer({ min: 500, max: 20000 }), fc.constantFrom("!", "\u0000", "x", "", "-->", "\"}"))
      .map(([u, n, end]) => u.repeat(Math.ceil(n / u.length)) + end),
  );
  for (const input of fc.sample(text, { numRuns: runs, seed })) { res.runs++; call(input); }
  // 3: mutations of attacks the guard catches today
  let state = seed; const rnd = () => ((state = (state * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  for (const p of PROBES.filter((x) => x.attack)) {
    if (!flagged(call(p.text))) continue;
    for (const [name, m] of MUTATIONS) {
      if (p.family === "encoding" && /case|full-width/.test(name)) continue; // re-casing base64 destroys the payload: not a real bypass
      const t = m(p.text, rnd); res.mutated++; res.runs++;
      if (!flagged(call(t))) res.bypasses.push({ probe: p.id, mutation: name, text: t });
    }
  }
  return res;
}

export function fuzzFindings(r: FuzzResult, where: string): Finding[] {
  const out: Finding[] = [];
  if (r.crashes.length) out.push({ source: "llm", rule: "FUZZ-GUARD-CRASH", severity: "high", where, key: `fuzz:${where}:crash`,
    title: `The injection guard crashed on ${r.crashes.length} generated input${r.crashes.length === 1 ? "" : "s"}`,
    detail: `First: ${JSON.stringify(r.crashes[0].input.slice(0, 80))} → ${r.crashes[0].error}. A document that crashes the guard may skip screening altogether.`,
    fix: "Make the guard total: catch errors and treat the text as untrusted when screening fails. Replay with the same seed: " + r.seed });
  if (r.slow.length) {
    const worst = r.slow.sort((a, b) => b.ms - a.ms)[0];
    out.push({ source: "llm", rule: "FUZZ-GUARD-REDOS", severity: worst.ms > 1000 ? "high" : "medium", where, key: `fuzz:${where}:redos`,
      title: `The injection guard takes up to ${Math.round(worst.ms)} ms on crafted text (possible ReDoS)`,
      detail: `${r.slow.length} input${r.slow.length === 1 ? "" : "s"} took over 100 ms; the slowest is ${worst.input.length} characters starting ${JSON.stringify(worst.input.slice(0, 30))}. One such email can stall the agent.`,
      fix: "Cap input length before screening and remove nested or overlapping quantifiers from the guard's patterns (or use a linear-time regex engine such as RE2)." });
  }
  if (r.bypasses.length) {
    const by = new Map<string, number>(); for (const b of r.bypasses) by.set(b.mutation, (by.get(b.mutation) ?? 0) + 1);
    out.push({ source: "llm", rule: "FUZZ-GUARD-BYPASS", severity: "medium", where, key: `fuzz:${where}:bypass`,
      title: `${r.bypasses.length} of ${r.mutated} rewritten attacks slip past the guard`,
      detail: `Rewrites that worked: ${[...by].sort((a, b) => b[1] - a[1]).map(([m, n]) => `${m} (${n})`).join(", ")}. Example: "${r.bypasses[0].text.replace(/\s+/g, " ").trim().slice(0, 90)}".`,
      fix: "Normalise before screening (Unicode NFKC, strip zero-width and format characters, collapse whitespace, lower-case); llm-probes.ts has a normaliser that does this." });
  }
  return out;
}
