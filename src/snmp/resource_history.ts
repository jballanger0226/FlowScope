/** History of device resources (CPU, memory, swap, fullest disk, load, uptime), kept in the configuration database. */
import type { DatabaseSync } from 'node:sqlite';
import type { Resources } from './resources.js';

export const RAW_KEEP_MS = 3 * 86_400_000;
const HOUR = 3_600_000;
/** Readings closer together than this are the same reading (the poller reads about every 55 s). */
const MIN_GAP_MS = 20_000;

export interface ResPoint { ts: number; cpu: number | null; cpuMax: number | null; mem: number | null; memMax: number | null; swap: number | null; disk: number | null; load: number | null; loadMax: number | null }
export interface ResSeries { step: number; tier: 'raw' | 'h1'; points: ResPoint[]; /** Moments the uptime went backwards: the device restarted */ restarts: number[] }

const sample = (r: Resources) => ({
  cpu: r.cpuPct, mem: r.memPct, swap: r.swapPct, disk: r.disks.length ? Math.max(...r.disks.map(d => d.usedPct)) : null, load: r.load ? r.load[0] : null, up: r.uptimeSec,
});

export function recordResources(db: DatabaseSync, devId: number, r: Resources): void {
  const s = sample(r);
  if (s.cpu === null && s.mem === null && s.disk === null && s.load === null) return;
  const last = db.prepare('SELECT MAX(ts) AS t FROM resource_samples WHERE dev_id = ?').get(devId) as { t: number | null };
  if (last.t !== null && Math.abs(r.readAt - last.t) < MIN_GAP_MS) return;
  db.prepare('INSERT OR REPLACE INTO resource_samples(dev_id, ts, cpu, mem, swap, disk, load1, up) VALUES (?,?,?,?,?,?,?,?)').run(devId, r.readAt, s.cpu, s.mem, s.swap, s.disk, s.load, s.up);
  const hr = Math.floor(r.readAt / HOUR) * HOUR;
  const n = (v: number | null) => (v === null ? 0 : 1);
  db.prepare(`INSERT INTO resource_1h(dev_id, ts, n, cpu_sum, cpu_n, cpu_max, mem_sum, mem_n, mem_max, swap_sum, swap_n, swap_max, disk_sum, disk_n, disk_max, load_sum, load_n, load_max, up_min, up_max)
    VALUES (?,?,1, ?,?,?, ?,?,?, ?,?,?, ?,?,?, ?,?,?, ?,?)
    ON CONFLICT(dev_id, ts) DO UPDATE SET n = n + 1,
      cpu_sum = COALESCE(cpu_sum,0) + COALESCE(excluded.cpu_sum,0), cpu_n = cpu_n + excluded.cpu_n, cpu_max = MAX(COALESCE(cpu_max,0), COALESCE(excluded.cpu_max,0)),
      mem_sum = COALESCE(mem_sum,0) + COALESCE(excluded.mem_sum,0), mem_n = mem_n + excluded.mem_n, mem_max = MAX(COALESCE(mem_max,0), COALESCE(excluded.mem_max,0)),
      swap_sum = COALESCE(swap_sum,0) + COALESCE(excluded.swap_sum,0), swap_n = swap_n + excluded.swap_n, swap_max = MAX(COALESCE(swap_max,0), COALESCE(excluded.swap_max,0)),
      disk_sum = COALESCE(disk_sum,0) + COALESCE(excluded.disk_sum,0), disk_n = disk_n + excluded.disk_n, disk_max = MAX(COALESCE(disk_max,0), COALESCE(excluded.disk_max,0)),
      load_sum = COALESCE(load_sum,0) + COALESCE(excluded.load_sum,0), load_n = load_n + excluded.load_n, load_max = MAX(COALESCE(load_max,0), COALESCE(excluded.load_max,0)),
      up_min = MIN(COALESCE(up_min, excluded.up_min), COALESCE(excluded.up_min, up_min)), up_max = MAX(COALESCE(up_max,0), COALESCE(excluded.up_max,0))`)
    .run(devId, hr, s.cpu, n(s.cpu), s.cpu, s.mem, n(s.mem), s.mem, s.swap, n(s.swap), s.swap, s.disk, n(s.disk), s.disk, s.load, n(s.load), s.load, s.up, s.up);
}

/** Removes readings older than the raw keep time, and hourly summaries older than `hourlyDays`. */
export function pruneResources(db: DatabaseSync, hourlyDays: number, now = Date.now()): void {
  db.prepare('DELETE FROM resource_samples WHERE ts < ?').run(now - RAW_KEEP_MS);
  db.prepare('DELETE FROM resource_1h WHERE ts < ?').run(now - hourlyDays * 86_400_000);
}

export function forgetResources(db: DatabaseSync, devId: number): void {
  db.prepare('DELETE FROM resource_samples WHERE dev_id = ?').run(devId);
  db.prepare('DELETE FROM resource_1h WHERE dev_id = ?').run(devId);
}

const avg = (sum: number | null, n: number): number | null => (n > 0 && sum !== null ? sum / n : null);
const r1 = (v: number | null): number | null => (v === null ? null : Math.round(v * 10) / 10);

export function resourceSeries(db: DatabaseSync, devId: number, from: number, to: number, points: number, now = Date.now()): ResSeries {
  const raw = from >= now - RAW_KEEP_MS;
  const step = Math.max(raw ? 60_000 : HOUR, Math.ceil((to - from) / Math.max(1, points) / (raw ? 60_000 : HOUR)) * (raw ? 60_000 : HOUR));
  let pts: ResPoint[];
  let ups: { ts: number; up: number }[];
  if (raw) {
    const rows = db.prepare(`SELECT (ts / ${step}) * ${step} AS b, AVG(cpu) AS cpu, MAX(cpu) AS cpuMax, AVG(mem) AS mem, MAX(mem) AS memMax, AVG(swap) AS swap, MAX(disk) AS disk, AVG(load1) AS load, MAX(load1) AS loadMax
      FROM resource_samples WHERE dev_id = ? AND ts BETWEEN ? AND ? GROUP BY b ORDER BY b`).all(devId, from, to) as any[];
    pts = rows.map(x => ({ ts: x.b, cpu: r1(x.cpu), cpuMax: r1(x.cpuMax), mem: r1(x.mem), memMax: r1(x.memMax), swap: r1(x.swap), disk: r1(x.disk), load: x.load === null ? null : Math.round(x.load * 100) / 100, loadMax: x.loadMax === null ? null : Math.round(x.loadMax * 100) / 100 }));
    ups = (db.prepare('SELECT ts, up FROM resource_samples WHERE dev_id = ? AND ts BETWEEN ? AND ? AND up IS NOT NULL ORDER BY ts').all(devId, from, to) as any[]);
  } else {
    const rows = db.prepare(`SELECT (ts / ${step}) * ${step} AS b, SUM(cpu_sum) AS cs, SUM(cpu_n) AS cn, MAX(cpu_max) AS cm, SUM(mem_sum) AS ms, SUM(mem_n) AS mn, MAX(mem_max) AS mm, SUM(swap_sum) AS ss, SUM(swap_n) AS sn,
      MAX(disk_max) AS dm, SUM(load_sum) AS ls, SUM(load_n) AS ln, MAX(load_max) AS lm FROM resource_1h WHERE dev_id = ? AND ts BETWEEN ? AND ? GROUP BY b ORDER BY b`).all(devId, from, to) as any[];
    pts = rows.map(x => ({ ts: x.b, cpu: r1(avg(x.cs, x.cn)), cpuMax: r1(x.cm), mem: r1(avg(x.ms, x.mn)), memMax: r1(x.mm), swap: r1(avg(x.ss, x.sn)), disk: r1(x.dm), load: x.ln ? Math.round((x.ls / x.ln) * 100) / 100 : null, loadMax: x.lm === null ? null : Math.round(x.lm * 100) / 100 }));
    // A restart shows up inside an hour as a lower uptime than the hour before reached
    const h = db.prepare('SELECT ts, up_min, up_max FROM resource_1h WHERE dev_id = ? AND ts BETWEEN ? AND ? AND up_max IS NOT NULL ORDER BY ts').all(devId, from, to) as any[];
    ups = [];
    for (const x of h) { ups.push({ ts: x.ts, up: x.up_min }); ups.push({ ts: x.ts + HOUR - 1, up: x.up_max }); }
  }
  const restarts: number[] = [];
  // The restart happened `uptime` before the first reading that shows the lower value (to the hour for the hourly tier)
  for (let i = 1; i < ups.length; i++) if (ups[i].up + 5 < ups[i - 1].up) restarts.push(raw ? Math.max(from, ups[i].ts - ups[i].up * 1000) : ups[i].ts);
  return { step, tier: raw ? 'raw' : 'h1', points: pts, restarts };
}
