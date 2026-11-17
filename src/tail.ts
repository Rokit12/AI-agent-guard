/**
 * Follows every *.jsonl audit log in a folder as it grows, and feeds each new line to
 * a finance monitor kept per log file (one per agent run).
 */
import { readdirSync, statSync, openSync, readSync, closeSync, existsSync } from "node:fs";
import { join, basename } from "node:path";
import { FinanceMonitor, type AuditEvent } from "./detectors/finance-flow.ts";
import type { Finding } from "./alerts.ts";

export function tailRuns(dirs: string[], onFindings: (f: Finding[]) => void, onEvent?: (run: string) => void, fromStart = false, onRaw?: (e: AuditEvent, run: string) => void) {
  const offsets = new Map<string, number>();
  const partial = new Map<string, string>();
  const monitors = new Map<string, FinanceMonitor>();
  let first = true;

  const poll = () => {
    for (const dir of dirs) {
      if (!existsSync(dir)) continue;
      for (const name of readdirSync(dir)) {
        if (!name.endsWith(".jsonl")) continue;
        const p = join(dir, name);
        const size = statSync(p).size;
        // On start, existing logs are history: skip them unless asked, so old runs do not flood the feed.
        if (!offsets.has(p)) offsets.set(p, first && !fromStart ? size : 0);
        const off = offsets.get(p)!;
        if (size <= off) continue;
        const fd = openSync(p, "r");
        const buf = Buffer.alloc(size - off);
        readSync(fd, buf, 0, buf.length, off);
        closeSync(fd);
        offsets.set(p, size);
        const text = (partial.get(p) ?? "") + buf.toString("utf8");
        const lines = text.split("\n");
        partial.set(p, lines.pop() ?? "");
        const m = monitors.get(p) ?? new FinanceMonitor();
        monitors.set(p, m);
        const run = basename(name, ".jsonl");
        for (const line of lines) {
          if (!line.trim()) continue;
          let e: AuditEvent;
          try { e = JSON.parse(line); } catch { continue; }
          onEvent?.(run);
          onRaw?.(e, run);
          const fs = m.ingest(e, run);
          if (fs.length) onFindings(fs);
        }
      }
    }
    first = false;
  };
  poll();
  const timer = setInterval(poll, 500);
  return { close: () => clearInterval(timer) };
}
