import { randomBytes } from 'node:crypto';
import type { SnmpClient } from './client.js';
import { formatValue } from './diagnose.js';

/*
 * Full-tree SNMP walks run as background jobs: a walk of a whole switch is tens of thousands of rows and takes a while, so the page
 * starts one, watches its progress, and reads it back a page at a time. Results stay in memory for a short time and are capped.
 */

export const MAX_ROWS = 250_000;
const MAX_RUNNING = 2;
const MAX_KEPT = 4;
const KEEP_MS = 30 * 60 * 1000;
const MAX_MS = 15 * 60 * 1000;
const MAX_TEXT = 4000;

export type Row = [oid: string, type: string, text: string];
export interface WalkJob {
  id: string; devId: number; device: string; address: string; startOid: string; user: string; startedAt: number; finishedAt: number | null;
  state: 'running' | 'done' | 'cancelled' | 'error'; error: string | null; truncated: boolean; rows: Row[]; stop: boolean;
}
export class WalkBusy extends Error {}

export class WalkJobs {
  private jobs = new Map<string, WalkJob>();

  private prune(now = Date.now()): void {
    for (const [id, j] of this.jobs) if (j.finishedAt && now - j.finishedAt > KEEP_MS) this.jobs.delete(id);
    const done = [...this.jobs.values()].filter(j => j.finishedAt).sort((a, b) => a.finishedAt! - b.finishedAt!);
    while (done.length > MAX_KEPT) this.jobs.delete(done.shift()!.id);
  }
  running(devId?: number): number { return [...this.jobs.values()].filter(j => !j.finishedAt && (devId === undefined || j.devId === devId)).length; }
  get(id: string): WalkJob | undefined { return this.jobs.get(id); }
  cancel(id: string): void { const j = this.jobs.get(id); if (j && !j.finishedAt) j.stop = true; }

  /** Starts a walk. `startOid` is empty for the whole tree. The client is closed when the walk ends, however it ends. */
  start(dev: { id: number; name: string; ip: string }, client: SnmpClient, startOid: string, user: string, opts: { maxMs?: number; maxRows?: number } = {}): WalkJob {
    this.prune();
    if (this.running(dev.id)) { client.close(); throw new WalkBusy('A walk is already running on this device. Wait for it to finish or cancel it.'); }
    if (this.running() >= MAX_RUNNING) { client.close(); throw new WalkBusy('Two walks are already running. Wait for one to finish.'); }
    const job: WalkJob = { id: randomBytes(12).toString('hex'), devId: dev.id, device: dev.name, address: dev.ip, startOid, user, startedAt: Date.now(), finishedAt: null, state: 'running', error: null, truncated: false, rows: [], stop: false };
    this.jobs.set(job.id, job);
    const deadline = job.startedAt + (opts.maxMs ?? MAX_MS), cap = opts.maxRows ?? MAX_ROWS;
    void (async () => {
      try {
        const why = await client.walkEach(startOid, batch => {
          if (job.stop) return true;
          for (const vb of batch) {
            if (job.rows.length >= cap) { job.truncated = true; return true; }
            const f = formatValue(vb.type, vb.value);
            job.rows.push([vb.oid, f.type, f.text.length > MAX_TEXT ? f.text.slice(0, MAX_TEXT) + '…' : f.text]);
          }
          if (Date.now() > deadline) { job.truncated = true; job.error = 'Stopped after the time limit; the rows so far are kept.'; return true; }
          return job.stop;
        });
        job.state = job.stop ? 'cancelled' : 'done';
        if (why === 'disorder') job.error = 'The device returned OIDs out of order, so the walk was stopped there. The rows so far are kept.';
      } catch (e) { job.state = 'error'; job.error = (e as Error).message + (job.rows.length ? ' The rows read before that are kept.' : ''); }
      finally { job.finishedAt = Date.now(); client.close(); }
    })();
    return job;
  }
}

/* ------------------------------------------------------------------ views and exports */

export interface JobView { id: string; device: string; address: string; startOid: string; state: WalkJob['state']; error: string | null; truncated: boolean; rows: number; startedAt: number; finishedAt: number | null; maxRows: number }
export const jobView = (j: WalkJob): JobView => ({ id: j.id, device: j.device, address: j.address, startOid: j.startOid, state: j.state, error: j.error, truncated: j.truncated, rows: j.rows.length, startedAt: j.startedAt, finishedAt: j.finishedAt, maxRows: MAX_ROWS });

/** Rows whose OID, type or value contain every word of the filter (case-insensitive). No filter returns the job's own array. */
export function filterRows(rows: Row[], q: string): Row[] {
  const words = q.toLowerCase().split(/\s+/).filter(Boolean).map(w => (/^\.\d/.test(w) ? w.slice(1) : w));   // OIDs are stored without the leading dot people usually type
  if (!words.length) return rows;
  return rows.filter(r => { const t = (r[0] + ' ' + r[1] + ' ' + r[2]).toLowerCase(); return words.every(w => t.includes(w)); });
}

export type ExportFormat = 'txt' | 'json' | 'csv' | 'xml';
export const EXPORT_FORMATS: ExportFormat[] = ['txt', 'json', 'csv', 'xml'];

const xmlText = (s: string): string => s.replace(/[^\t\n\r\u0020-\uD7FF\uE000-\uFFFD]/g, '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!));
const csvCell = (s: string): string => (/^[=+\-@\t\r]/.test(s) && !/^-?\d+(\.\d+)?$/.test(s) ? "'" + s : s);   // a value that starts like a formula must not become one in a spreadsheet

/** The rows as one downloadable document. `txt` is one line per row in the style of snmpwalk: `.1.3.6.1.2.1.1.1.0 = OctetString: text`. */
export function exportRows(j: WalkJob, rows: Row[], fmt: ExportFormat, q: string): { type: string; ext: string; body: string } {
  const meta = { device: j.device, address: j.address, startOid: j.startOid ? '.' + j.startOid : '(whole tree)', walkedAt: new Date(j.startedAt).toISOString(), rows: rows.length, filter: q || undefined, truncated: j.truncated || undefined, note: j.error ?? undefined };
  if (fmt === 'json') return { type: 'application/json', ext: 'json', body: JSON.stringify({ ...meta, results: rows.map(r => ({ oid: r[0], type: r[1], value: r[2] })) }, null, 1) };
  if (fmt === 'xml') {
    const lines = ['<?xml version="1.0" encoding="UTF-8"?>', `<snmpwalk device="${xmlText(j.device)}" address="${xmlText(j.address)}" startOid="${xmlText(meta.startOid)}" walkedAt="${meta.walkedAt}" rows="${rows.length}"${q ? ` filter="${xmlText(q)}"` : ''}${j.truncated ? ' truncated="true"' : ''}>`];
    for (const r of rows) lines.push(`  <varbind oid="${xmlText(r[0])}" type="${xmlText(r[1])}">${xmlText(r[2])}</varbind>`);
    lines.push('</snmpwalk>');
    return { type: 'text/xml; charset=utf-8', ext: 'xml', body: lines.join('\n') + '\n' };
  }
  if (fmt === 'csv') {
    const q2 = (x: string) => '"' + csvCell(x).replace(/"/g, '""') + '"';
    return { type: 'text/csv; charset=utf-8', ext: 'csv', body: ['oid,type,value', ...rows.map(r => r.map(q2).join(','))].join('\r\n') + '\r\n' };
  }
  const head = [`# SNMP walk of ${j.device} (${j.address}) from ${meta.startOid}, ${meta.walkedAt}`, `# ${rows.length} rows${q ? `, filtered by "${q.replace(/[\r\n]+/g, ' ')}"` : ''}${j.truncated ? ', TRUNCATED' : ''}${j.error ? ', ' + j.error : ''}`];
  return { type: 'text/plain; charset=utf-8', ext: 'txt', body: [...head, ...rows.map(r => `.${r[0]} = ${r[1]}: ${r[2].replace(/\r?\n/g, '\\n')}`)].join('\n') + '\n' };
}
