/**
 * Ransomware detector for the folders an agent platform depends on (exports, statements,
 * evidence files, audit logs, backups).
 *
 * Encryption leaves a recognisable trail long before anyone sees a ransom demand: many
 * files rewritten in seconds, their content turning into random bytes (entropy near 8
 * bits per byte), new extensions such as .locked, and a note named like
 * HOW_TO_RECOVER_FILES.txt. The scorer is pure: it takes file events and returns findings,
 * so it is tested with plain data. The watcher feeds it real events from the disk.
 */
import { watch, readFileSync, readdirSync, statSync, existsSync, openSync, readSync, closeSync } from "node:fs";
import { join, extname, basename } from "node:path";
import type { Finding } from "../alerts.ts";

export interface FileEvent { at: number; path: string; type: "write" | "rename" | "delete"; entropy?: number; prevEntropy?: number }

export const RANSOM_EXT = new Set([".locked", ".encrypted", ".enc", ".crypt", ".crypted", ".crypto", ".lockbit", ".ryk", ".conti", ".akira", ".blackcat", ".pay", ".ransom", ".wncry", ".cerber", ".locky"]);
const NOTE_RE = /^(how[_ -]?to[_ -]?(recover|restore|decrypt)|readme[_ -]?(to[_ -]?)?(decrypt|restore|recover)|restore[_ -]?my[_ -]?files|decrypt[_ -]?instructions|!!!.*!!!|_readme).*\.(txt|html|hta|md)$/i;
const NOTE_TEXT = /\b(your (files|data|network) (have been|are|were) (encrypted|locked)|bitcoin|monero|tor browser|\.onion|decryption key|pay(ment)? within)\b/i;

/** Shannon entropy of a sample, in bits per byte (0 = constant, 8 = random). */
export function entropy(buf: Buffer): number {
  if (!buf.length) return 0;
  const counts = new Array<number>(256).fill(0);
  for (const b of buf) counts[b]++;
  let h = 0;
  for (const c of counts) if (c) { const p = c / buf.length; h -= p * Math.log2(p); }
  return h;
}

export function sampleEntropy(path: string, bytes = 4096): number | undefined {
  try {
    const fd = openSync(path, "r");
    const buf = Buffer.alloc(bytes);
    const n = readSync(fd, buf, 0, bytes, 0);
    closeSync(fd);
    return n >= 256 ? entropy(buf.subarray(0, n)) : undefined; // too small to judge
  } catch { return undefined; }
}

export interface RansomConfig { windowMs: number; burstFiles: number; highEntropy: number; minRewrites: number }
export const DEFAULT_RANSOM: RansomConfig = { windowMs: 10_000, burstFiles: 25, highEntropy: 7.5, minRewrites: 8 };

/** Score the events in one time window. */
export function scoreWindow(events: FileEvent[], folder: string, cfg = DEFAULT_RANSOM): Finding[] {
  const out: Finding[] = [];
  const files = new Set(events.map((e) => e.path));
  const encryptedRewrites = events.filter((e) => e.type === "write" && (e.entropy ?? 0) >= cfg.highEntropy && (e.prevEntropy === undefined || e.prevEntropy < 6.5));
  const ransomExt = events.filter((e) => (e.type === "rename" || e.type === "write") && RANSOM_EXT.has(extname(e.path).toLowerCase()));
  const notes = events.filter((e) => NOTE_RE.test(basename(e.path)));
  const deletes = events.filter((e) => e.type === "delete");
  const where = folder;
  const sample = (list: FileEvent[]) => list.slice(0, 5).map((e) => basename(e.path)).join(", ");

  if (notes.length) out.push({ source: "ransomware", rule: "RANSOM-NOTE", severity: "critical", where,
    title: "Ransom note written to a monitored folder",
    key: `note:${folder}`,
    detail: `${[...new Set(notes.map((n) => basename(n.path)))].join(", ")} appeared${encryptedRewrites.length ? ` alongside ${encryptedRewrites.length} files rewritten as random bytes` : ""}.`,
    fix: "Isolate the machine from the network now, keep it powered on for forensics, and restore from an offline backup. Do not pay or contact the attacker before your incident lead decides." });

  if (encryptedRewrites.length >= cfg.minRewrites || ransomExt.length >= cfg.minRewrites) out.push({ source: "ransomware", rule: "RANSOM-MASS-ENCRYPTION", severity: "critical", where,
    key: `encryption:${folder}`,
    title: `${Math.max(encryptedRewrites.length, ransomExt.length)} files encrypted in ${Math.round(cfg.windowMs / 1000)} seconds`,
    detail: `Files rewritten with near-random content (≥ ${cfg.highEntropy} bits/byte)${ransomExt.length ? ` and renamed to ${[...new Set(ransomExt.map((e) => extname(e.path)))].join(", ")}` : ""}: ${sample(encryptedRewrites.length ? encryptedRewrites : ransomExt)}…`,
    fix: "Stop the process writing these files (check which user and process has them open), cut network shares, and switch the agent platform to read-only." });
  else if (ransomExt.length >= 1 && ransomExt.length < cfg.minRewrites) out.push({ source: "ransomware", rule: "RANSOM-EXTENSION", severity: "high", where,
    key: `encryption:${folder}`, title: "Files renamed to a known ransomware extension", detail: sample(ransomExt), fix: "Check what renamed them; if unexpected, treat as the start of an attack." });

  if (files.size >= cfg.burstFiles && !out.some((f) => f.key?.startsWith("encryption:"))) out.push({ source: "ransomware", rule: "RANSOM-BURST", severity: "medium", where, key: `encryption:${folder}`,
    title: `${files.size} files changed in ${Math.round(cfg.windowMs / 1000)} seconds`,
    detail: `Unusual burst of changes (${deletes.length} deletions). Could be a deploy or sync; could be the start of encryption.`, fix: "Confirm a known job caused it." });

  if (deletes.length >= cfg.burstFiles && /backup|snapshot|archive/i.test(folder + deletes.map((d) => d.path).join(" "))) out.push({ source: "ransomware", rule: "RANSOM-BACKUP-WIPE", severity: "critical", where,
    title: "Backups being deleted in bulk", detail: `${deletes.length} backup files deleted in the window. Attackers remove backups before encrypting.`, fix: "Lock the backup store (object lock / immutable snapshots) and find who deleted them." });
  return out;
}

export function isRansomNoteText(text: string) { return NOTE_TEXT.test(text); }

/** Watch a folder recursively and report findings as they appear. */
export function watchFolder(folder: string, onFindings: (f: Finding[]) => void, cfg = DEFAULT_RANSOM) {
  if (!existsSync(folder)) throw new Error(`folder not found: ${folder}`);
  const known = new Map<string, number | undefined>(); // last entropy seen per file
  let events: FileEvent[] = [];
  const reported = new Set<string>();
  const encrypted = new Set<string>(); // every file seen encrypted during the incident
  let incident = 0, lastHit = 0; // an incident ends after 60 s with no findings

  const w = watch(folder, { recursive: true }, (type, name) => {
    if (!name) return;
    const path = join(folder, name.toString());
    const at = Date.now();
    if (!existsSync(path)) { events.push({ at, path, type: "delete" }); return; }
    try { if (!statSync(path).isFile()) return; } catch { return; }
    const e = sampleEntropy(path);
    const ev: FileEvent = { at, path, type: type === "rename" ? "rename" : "write", entropy: e, prevEntropy: known.get(path) };
    if (ev.type === "rename" && RANSOM_EXT.has(extname(path).toLowerCase())) ev.prevEntropy = undefined;
    known.set(path, e);
    events.push(ev);
    if (NOTE_RE.test(basename(path)) || (extname(path) === ".txt" && isRansomNoteTextSafe(path))) events.push({ at, path, type: "write", entropy: e });
  });

  const timer = setInterval(() => {
    const now = Date.now();
    events = events.filter((e) => now - e.at < cfg.windowMs);
    // de-duplicate events per file, keep the latest
    const latest = new Map<string, FileEvent>();
    for (const e of events) latest.set(`${e.type}:${e.path}`, e);
    if (now - lastHit > 60_000) encrypted.clear();
    for (const e of latest.values()) if ((e.entropy ?? 0) >= cfg.highEntropy || RANSOM_EXT.has(extname(e.path).toLowerCase())) encrypted.add(e.path.replace(/\.(locked|encrypted|enc|crypt\w*)$/i, ""));
    const scored = scoreWindow([...latest.values()], folder, cfg);
    if (scored.length) { if (now - lastHit > 60_000) { incident = now; encrypted.clear(); } lastHit = now; }
    const fs = scored.map((f) => (f.key ? { ...f, key: `${f.key}:${incident}` } : f)).map((f) =>
      f.rule === "RANSOM-MASS-ENCRYPTION" ? { ...f, title: `${encrypted.size} files encrypted so far`, detail: `${f.detail} Total since the incident began: ${encrypted.size} files.` } : f,
    ).filter((f) => {
      if (f.key) return true; // incidents update in place
      const key = `${f.rule}:${Math.floor(now / 60_000)}`; // at most one per rule per minute
      if (reported.has(key)) return false;
      reported.add(key); return true;
    });
    if (fs.length) onFindings(fs);
  }, 1000);

  // remember the starting entropy of existing files, so a rewrite can be compared
  const prime = (dir: string) => {
    for (const name of listDir(dir)) {
      const p = join(dir, name);
      try { const st = statSync(p); if (st.isDirectory()) prime(p); else known.set(p, sampleEntropy(p)); } catch { /* gone */ }
    }
  };
  prime(folder);
  return { close: () => { w.close(); clearInterval(timer); } };
}

const listDir = (d: string) => { try { return readdirSync(d); } catch { return []; } };
function isRansomNoteTextSafe(path: string) {
  try { return statSync(path).size < 50_000 && NOTE_TEXT.test(readFileSync(path, "utf8")); } catch { return false; }
}
