/**
 * History of the per-interface counters read every few minutes (frame errors by type, collisions, broadcast and multicast, and the IF-MIB error and
 * discard counters), kept in the configuration database: the change of each counter between two reads for a few days, and hourly sums after that.
 */
import type { DatabaseSync } from 'node:sqlite';
import { EXTRA_COUNTERS, type ExtraCounter, type IfExtra } from './health.js';
import { RAW_KEEP_MS } from './resource_history.js';

const HOUR = 3_600_000;
/** Column of each counter in iface_extra_samples and iface_extra_1h */
const COL: Record<ExtraCounter, string> = {
  fcs: 'fcs', align: 'align', symbol: 'symbol', late: 'late', excessive: 'excessive', collisions: 'collisions', carrier: 'carrier', tooLong: 'too_long', unknown: 'unknown_proto',
  inMc: 'in_mc', inBc: 'in_bc', outMc: 'out_mc', outBc: 'out_bc', inErr: 'in_err', outErr: 'out_err', inDisc: 'in_disc', outDisc: 'out_disc'
};
const COLS = EXTRA_COUNTERS.map(k => COL[k]);

/** One bucket of the series: the time and, for each counter the device publishes, how fast it grew (per second) over the bucket. */
export type IfExtraPoint = { ts: number } & Partial<Record<ExtraCounter, number>>;
export interface IfExtraSeries { step: number; tier: 'raw' | 'h1'; points: IfExtraPoint[] }

/** Stores what each counter went up by in the interval ending at `x.readAt` (nothing when there is no earlier read to compare with). */
export function recordIfExtra(db: DatabaseSync, devId: number, ifIndex: number, x: IfExtra): void {
  if (!x.delta || !x.dtSec) return;
  const vals = EXTRA_COUNTERS.map(k => x.delta![k] ?? null);
  if (vals.every(v => v === null)) return;
  const ph = vals.map(() => '?').join(',');
  db.prepare(`INSERT OR REPLACE INTO iface_extra_samples(dev_id, if_index, ts, dt, ${COLS.join(', ')}) VALUES (?,?,?,?,${ph})`).run(devId, ifIndex, x.readAt, x.dtSec, ...vals);
  const sums = COLS.map(c => `${c} = CASE WHEN ${c} IS NULL AND excluded.${c} IS NULL THEN NULL ELSE COALESCE(${c},0) + COALESCE(excluded.${c},0) END`).join(', ');
  db.prepare(`INSERT INTO iface_extra_1h(dev_id, if_index, ts, dt, ${COLS.join(', ')}) VALUES (?,?,?,?,${ph}) ON CONFLICT(dev_id, if_index, ts) DO UPDATE SET dt = dt + excluded.dt, ${sums}`)
    .run(devId, ifIndex, Math.floor(x.readAt / HOUR) * HOUR, x.dtSec, ...vals);
}

export function pruneIfExtra(db: DatabaseSync, hourlyDays: number, now = Date.now()): void {
  db.prepare('DELETE FROM iface_extra_samples WHERE ts < ?').run(now - RAW_KEEP_MS);
  db.prepare('DELETE FROM iface_extra_1h WHERE ts < ?').run(now - hourlyDays * 86_400_000);
}

export function forgetIfExtra(db: DatabaseSync, devId: number): void {
  db.prepare('DELETE FROM iface_extra_samples WHERE dev_id = ?').run(devId);
  db.prepare('DELETE FROM iface_extra_1h WHERE dev_id = ?').run(devId);
}

const r3 = (v: number): number => Math.round(v * 1000) / 1000;

export function ifExtraSeries(db: DatabaseSync, devId: number, ifIndex: number, from: number, to: number, points: number, now = Date.now()): IfExtraSeries {
  const raw = from >= now - RAW_KEEP_MS;
  const unit = raw ? 60_000 : HOUR;
  const step = Math.max(raw ? 180_000 : HOUR, Math.ceil((to - from) / Math.max(1, points) / unit) * unit);
  const sums = COLS.map(c => `SUM(${c}) AS ${c}`).join(', ');
  const rows = db.prepare(`SELECT (ts / ${step}) * ${step} AS b, SUM(dt) AS dt, ${sums} FROM ${raw ? 'iface_extra_samples' : 'iface_extra_1h'} WHERE dev_id = ? AND if_index = ? AND ts BETWEEN ? AND ? GROUP BY b ORDER BY b`)
    .all(devId, ifIndex, from, to) as any[];
  const pts: IfExtraPoint[] = rows.filter(r => r.dt > 0).map(r => {
    const p: IfExtraPoint = { ts: r.b };
    EXTRA_COUNTERS.forEach((k, i) => { const v = r[COLS[i]]; if (v !== null && v !== undefined) p[k] = r3(v / r.dt); });
    return p;
  });
  return { step, tier: raw ? 'raw' : 'h1', points: pts };
}
