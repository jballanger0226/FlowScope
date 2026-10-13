import type { Ctx } from '../server/http.js';
import { HttpError } from '../server/http.js';
import type { TimeRange } from '../store/types.js';

const UNIT: Record<string, number> = { s: 1000, m: 60_000, h: 3600_000, d: 86400_000, w: 7 * 86400_000 };

/** Reads a time range from `range=1h` (relative to now) or `from` and `to` (epoch ms or ISO date). */
export function parseRange(q: URLSearchParams, defaultRange = '1h'): TimeRange {
  const now = Date.now();
  const rel = q.get('range') ?? (q.get('from') ? null : defaultRange);
  let from: number, to = now;
  if (rel) {
    const m = /^(\d+)([smhdw])$/.exec(rel);
    if (!m) throw new HttpError(400, `range must look like 15m, 6h, 7d (got "${rel}")`);
    from = now - Number(m[1]) * UNIT[m[2]];
  } else {
    from = toMs(q.get('from')!, 'from');
    if (q.get('to')) to = toMs(q.get('to')!, 'to');
  }
  if (!(from < to)) throw new HttpError(400, 'The start of the range must be before its end');
  if (to - from > 800 * 86400_000) throw new HttpError(400, 'The range is limited to 800 days');
  return { from, to };
}

function toMs(v: string, name: string): number {
  const n = /^\d{10,}$/.test(v) ? Number(v) : Date.parse(v);
  if (!Number.isFinite(n)) throw new HttpError(400, `${name} is not a time`);
  return n;
}

export function int(v: unknown, d: number, min: number, max: number): number {
  if (v === null || v === undefined || v === '') return d;
  const n = Math.floor(Number(v));
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : d;
}

export function str(v: unknown, max = 500): string { return typeof v === 'string' ? v.slice(0, max) : ''; }

export function csvCell(v: unknown): string {
  let s = v === null || v === undefined ? '' : String(v);
  // spreadsheet formula injection: prefix cells that a spreadsheet would evaluate
  if (/^[=+\-@\t\r]/.test(s) && !/^-?\d+(\.\d+)?$/.test(s)) s = "'" + s;
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
export function toCsv(head: string[], rows: unknown[][]): string {
  return [head.map(csvCell).join(','), ...rows.map(r => r.map(csvCell).join(','))].join('\r\n') + '\r\n';
}

export function attachment(c: Ctx, name: string, type: string, body: string): void {
  c.text(body, type, 200, { 'Content-Disposition': `attachment; filename="${name}"` });
}

export function stamp(): string { return new Date().toISOString().replace(/[-:]/g, '').slice(0, 13).replace('T', '-'); }
