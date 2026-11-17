/**
 * Feeds the identity and network detector.
 *
 *  - CloudTrail files in the cloudtrail folders: CloudTrail's own delivery format
 *    ({"Records": [...]}, optionally .json.gz as written to S3), or one record per line
 *    (.jsonl, followed as it grows). Sync the trail's bucket into the folder with
 *    `aws s3 sync s3://<trail-bucket>/AWSLogs/ logs/cloudtrail/`.
 *  - Egress records in the egress folders (.jsonl): proxy or firewall logs with a host,
 *    or Route 53 Resolver query logs with query_name.
 *  - Live: with CLOUDTRAIL_LIVE=1 and AWS credentials, polls CloudTrail LookupEvents
 *    every 60 s (management events, the last 15 minutes on start).
 */
import { readdirSync, readFileSync, statSync, existsSync, openSync, readSync, closeSync, mkdirSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { join } from "node:path";
import { IdentityMonitor, parseCloudTrail, type CloudTrailRecord, type EgressRecord } from "./detectors/identity.ts";
import type { Finding } from "./alerts.ts";

export function feedCloud(opts: { cloudtrail: string[]; egress: string[]; onFindings: (f: Finding[]) => void; onEvent?: (kind: "cloudtrail" | "egress") => void; monitor?: IdentityMonitor }) {
  const m = opts.monitor ?? new IdentityMonitor();
  const done = new Set<string>();                 // whole files already read
  const offsets = new Map<string, number>();      // growing .jsonl files
  const partial = new Map<string, string>();
  for (const d of [...opts.cloudtrail, ...opts.egress]) mkdirSync(d, { recursive: true });

  const newLines = (p: string) => {
    const size = statSync(p).size;
    const off = offsets.get(p) ?? 0;
    if (size <= off) return [];
    const fd = openSync(p, "r"); const buf = Buffer.alloc(size - off); readSync(fd, buf, 0, buf.length, off); closeSync(fd);
    offsets.set(p, size);
    const lines = ((partial.get(p) ?? "") + buf.toString("utf8")).split("\n");
    partial.set(p, lines.pop() ?? "");
    return lines.filter((l) => l.trim());
  };

  const files = (dir: string): string[] => {
    if (!existsSync(dir)) return [];
    return readdirSync(dir).flatMap((n) => { const p = join(dir, n); try { return statSync(p).isDirectory() ? files(p) : [p]; } catch { return []; } });
  };

  const poll = () => {
    for (const p of opts.cloudtrail.flatMap(files)) {
      let recs: CloudTrailRecord[] = [];
      if (p.endsWith(".jsonl")) recs = newLines(p).flatMap((l) => parseCloudTrail(l));
      else if ((p.endsWith(".json") || p.endsWith(".json.gz")) && !done.has(p)) {
        if (Date.now() - statSync(p).mtimeMs < 1500) continue; // still being written
        done.add(p);
        const raw = readFileSync(p);
        recs = parseCloudTrail((p.endsWith(".gz") ? gunzipSync(raw) : raw).toString("utf8"));
      }
      recs.sort((a, b) => a.eventTime.localeCompare(b.eventTime));
      for (const r of recs) { opts.onEvent?.("cloudtrail"); const f = m.ingest(r); if (f.length) opts.onFindings(f); }
    }
    for (const p of opts.egress.flatMap(files)) {
      if (!p.endsWith(".jsonl")) continue;
      for (const l of newLines(p)) {
        let e: EgressRecord; try { e = JSON.parse(l); } catch { continue; }
        opts.onEvent?.("egress"); const f = m.ingestEgress(e); if (f.length) opts.onFindings(f);
      }
    }
  };
  poll();
  const timer = setInterval(poll, 1000);
  return { monitor: m, close: () => clearInterval(timer) };
}

/** Live CloudTrail via LookupEvents. Needs cloudtrail:LookupEvents; returns null when off. */
export async function pollCloudTrailLive(m: IdentityMonitor, onFindings: (f: Finding[]) => void, onEvent?: () => void, log = console.log) {
  if (process.env.CLOUDTRAIL_LIVE !== "1") return null;
  const { CloudTrailClient, LookupEventsCommand } = await import("@aws-sdk/client-cloudtrail");
  const client = new CloudTrailClient({ region: process.env.AWS_REGION ?? "us-west-2" });
  let since = new Date(Date.now() - 15 * 60_000);
  const seen = new Set<string>();
  const tick = async () => {
    const until = new Date();
    try {
      const recs: CloudTrailRecord[] = [];
      let token: string | undefined;
      do {
        const r = await client.send(new LookupEventsCommand({ StartTime: since, EndTime: until, NextToken: token, MaxResults: 50 }));
        for (const e of r.Events ?? []) if (e.EventId && !seen.has(e.EventId) && e.CloudTrailEvent) { seen.add(e.EventId); recs.push(JSON.parse(e.CloudTrailEvent)); }
        token = r.NextToken;
      } while (token);
      recs.sort((a, b) => a.eventTime.localeCompare(b.eventTime));
      for (const r of recs) { onEvent?.(); const f = m.ingest(r); if (f.length) onFindings(f); }
      since = new Date(until.getTime() - 5 * 60_000); // CloudTrail can deliver a few minutes late; overlap, and de-duplicate by id
      if (seen.size > 50_000) seen.clear();
    } catch (err) { log(`CloudTrail live poll failed: ${(err as Error).message}`); }
  };
  await tick();
  const timer = setInterval(tick, 60_000);
  return { close: () => clearInterval(timer) };
}

/** One-off hunt: read every CloudTrail and egress file from the start, with a fresh detector. */
export function huntFolders(cloudtrail: string[], egress: string[]) {
  const m = new IdentityMonitor();
  const all = (dir: string): string[] => (existsSync(dir) ? readdirSync(dir).flatMap((n) => { const p = join(dir, n); try { return statSync(p).isDirectory() ? all(p) : [p]; } catch { return []; } }) : []);
  const recs: CloudTrailRecord[] = [];
  for (const p of cloudtrail.flatMap(all)) {
    if (!/\.(jsonl|json|json\.gz)$/.test(p)) continue;
    const raw = readFileSync(p);
    recs.push(...parseCloudTrail((p.endsWith(".gz") ? gunzipSync(raw) : raw).toString("utf8")));
  }
  recs.sort((a, b) => a.eventTime.localeCompare(b.eventTime));
  const findings: Finding[] = recs.flatMap((r) => m.ingest(r));
  let egressCount = 0;
  for (const p of egress.flatMap(all)) {
    if (!p.endsWith(".jsonl")) continue;
    for (const l of readFileSync(p, "utf8").split("\n")) { if (!l.trim()) continue; try { egressCount++; findings.push(...m.ingestEgress(JSON.parse(l))); } catch { /* skip */ } }
  }
  return { events: recs.length, egress: egressCount, findings };
}
