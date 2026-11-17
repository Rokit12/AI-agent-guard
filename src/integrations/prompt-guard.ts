/**
 * Llama Prompt Guard 2 as a second, model-based injection screen.
 *
 * The built-in probes test the agent's regex guard. Prompt Guard 2 (Meta, 22M or 86M
 * parameters) is a classifier trained on prompt injections and jailbreaks; the 86M model
 * covers English, French, German, Hindi, Italian, Portuguese, Spanish and Thai. Agent
 * Shield runs the same 20 probes through it, so the two guards can be compared attack by
 * attack, and reports where each one misses.
 *
 * PROMPT_GUARD_URL points at any Hugging Face text-classification endpoint serving the
 * model: Inference Endpoints, Text Embeddings Inference, or scripts/prompt-guard-server.py
 * on your own machine. Request {"inputs": text}; response [{label, score}] (or nested once).
 */
import type { Finding } from "../alerts.ts";
import { PROBES, type Probe } from "../detectors/llm-probes.ts";

export const promptGuardReady = () => Boolean(process.env.PROMPT_GUARD_URL);

export function maliciousScore(resp: unknown): number {
  const arr = (Array.isArray(resp) && Array.isArray(resp[0]) ? resp[0] : resp) as { label?: string; score?: number }[];
  if (!Array.isArray(arr)) throw new Error("unexpected classifier response");
  const hit = arr.find((x) => /malicious|injection|jailbreak|label_1|unsafe/i.test(String(x.label)));
  if (hit) return Number(hit.score ?? 0);
  const benign = arr.find((x) => /benign|label_0|safe/i.test(String(x.label)));
  return benign ? 1 - Number(benign.score ?? 0) : 0;
}

export interface GuardCompare { probe: Probe; score: number; flagged: boolean; ok: boolean }

export async function runPromptGuard(url = process.env.PROMPT_GUARD_URL!, threshold = Number(process.env.PROMPT_GUARD_THRESHOLD ?? 0.5), probes = PROBES): Promise<GuardCompare[]> {
  const headers: Record<string, string> = { "content-type": "application/json", ...(process.env.PROMPT_GUARD_TOKEN ? { authorization: `Bearer ${process.env.PROMPT_GUARD_TOKEN}` } : {}) };
  const out: GuardCompare[] = [];
  for (const probe of probes) {
    const r = await fetch(url, { method: "POST", headers, body: JSON.stringify({ inputs: probe.text }) });
    if (!r.ok) throw new Error(`Prompt Guard endpoint ${r.status}: ${(await r.text()).slice(0, 160)}`);
    const score = maliciousScore(await r.json());
    const flagged = score >= threshold;
    out.push({ probe, score, flagged, ok: flagged === probe.attack });
  }
  return out;
}

export function promptGuardSummary(results: GuardCompare[]) {
  const attacks = results.filter((r) => r.probe.attack), benign = results.filter((r) => !r.probe.attack);
  return { caught: attacks.filter((r) => r.flagged).length, attacks: attacks.length, falsePositives: benign.filter((r) => r.flagged).length, missed: attacks.filter((r) => !r.flagged).map((r) => r.probe.id) };
}

/** Misses become low alerts (the agent's code does not act on document text; this is about warning). */
export function promptGuardFindings(results: GuardCompare[], url: string): Finding[] {
  return results.filter((r) => !r.ok).map((r) => ({
    source: "llm" as const, rule: r.probe.attack ? "PG2-MISS" : "PG2-FALSE-POSITIVE", severity: "low" as const, where: `Prompt Guard 2 · ${new URL(url).host}`,
    title: r.probe.attack ? `Prompt Guard 2 missed a ${r.probe.family} attack (${r.probe.id})` : `Prompt Guard 2 flagged ordinary text (${r.probe.id})`,
    detail: `Malicious score ${r.score.toFixed(2)}. ${r.probe.attack ? "Pair it with the normalising regex guard: each catches what the other misses." : "Raise PROMPT_GUARD_THRESHOLD or allow-list this kind of business text."}`,
    fix: r.probe.family === "multilingual" ? "Prompt Guard 2 covers 8 languages; for others (such as Swahili), translate before screening." : "Screen with both guards and alert when either one fires.",
  }));
}
