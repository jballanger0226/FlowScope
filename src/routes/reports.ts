import type { App } from '../app.js';
import { HttpError } from '../server/http.js';
import { parseQuery } from '../query/tokens.js';
import { appName, dscpName, protoName } from '../query/apps.js';
import type { Cond, ReportDim, ReportRow, ReportSpec, TimeRange } from '../store/types.js';
import { attachment, int, parseRange, stamp, str, toCsv } from './util.js';

type UiDim = ReportDim | 'app';
const DIMS: UiDim[] = ['srcMac', 'dstMac', 'vlan', 'inIf', 'srcIp', 'dstIp', 'proto', 'dscp', 'qos', 'sport', 'dport', 'svc', 'app', 'flags'];
const DIM_LABEL: Record<UiDim, string> = { srcMac: 'Source MAC', dstMac: 'Destination MAC', vlan: 'VLAN', inIf: 'Ingress interface', srcIp: 'Source IP', dstIp: 'Destination IP', proto: 'Protocol', dscp: 'DSCP', qos: 'QoS change', sport: 'Source port', dport: 'Destination port', svc: 'Service port', app: 'Application', flags: 'TCP flags' };

interface ReportBody {
  q?: string; f2?: string; f3?: string; f4?: string; dims?: string[]; prefix?: number; bidir?: boolean; topN?: number; sortBy?: string; tier?: string; exporter?: string; format?: string; range?: string; from?: string | number; to?: string | number;
}

function chooseTier(app: App, range: TimeRange, want: string | undefined): ReportSpec['tier'] {
  if (want === 'raw' || want === 'm1' || want === 'h1' || want === 'd1') return want;
  const r = app.settings.get('retention'); const now = Date.now();
  if (range.from >= now - r.raw * 86400_000) return range.to - range.from <= 6 * 3600_000 ? 'raw' : 'm1';
  if (range.from >= now - r.m1 * 86400_000) return 'm1';
  if (range.from >= now - r.h1 * 86400_000) return 'h1';
  return 'd1';
}

const TCP_FLAG = [['FIN', 1], ['SYN', 2], ['RST', 4], ['PSH', 8], ['ACK', 16], ['URG', 32]] as const;
function flagsText(n: number): string { return n ? TCP_FLAG.filter(([, b]) => n & b).map(([s]) => s).join('|') : '—'; }

async function run(app: App, c: { query: URLSearchParams }, b: ReportBody) {
  // the time range may come in the query string or in the body
  const rq = new URLSearchParams(c.query);
  if (typeof b.range === 'string') rq.set('range', b.range);
  if (b.from !== undefined) rq.set('from', String(b.from));
  if (b.to !== undefined) rq.set('to', String(b.to));
  const range = parseRange(rq, '24h');
  const dims = (b.dims ?? ['srcIp', 'dstIp', 'dport']).filter((d): d is UiDim => (DIMS as string[]).includes(d));
  if (!dims.length) throw new HttpError(400, 'Choose at least one thing to group by');
  if (dims.length > 6) throw new HttpError(400, 'Group by at most six things');
  const conds: Cond[] = []; const errors: string[] = [];
  for (const part of [b.q, b.f2, b.f3, b.f4]) { if (!part) continue; const p = parseQuery(str(part, 1000), app.resolver()); conds.push(...p.conds); errors.push(...p.errors); }
  const tier = chooseTier(app, range, b.tier);
  if (tier !== 'raw' && conds.some(c => c.kind === 'ttl')) throw new HttpError(400, 'The TTL filter needs individual flow records, which are only kept in the raw tier. Choose a shorter time range or the raw tier.');
  const topN = int(b.topN, 25, 1, 1000);
  const prefix = int(b.prefix, 32, 0, 32);
  const sortBy = (['bytes', 'pkts', 'flows'] as const).find(s => s === b.sortBy) ?? 'bytes';
  const hasApp = dims.includes('app');
  // "app" is derived from the protocol and the service port (the lower of the two ports, the same in both directions), so ask the store for those and group by service name here
  const storeDims: ReportDim[] = [];
  for (const d of dims) { if (d === 'app') { if (!storeDims.includes('proto')) storeDims.push('proto'); if (!storeDims.includes('svc')) storeDims.push('svc'); } else if (!storeDims.includes(d)) storeDims.push(d); }
  const res = await app.store.report({ range, tier, dims: storeDims, prefix, bidir: !!b.bidir, conds, sortBy, topN: hasApp ? 20000 : topN, exporter: b.exporter || undefined, localIps: app.localIps() });
  let rows: ReportRow[] = res.rows;
  let other = res.other;
  if (hasApp) {
    const m = new Map<string, ReportRow>();
    for (const r of rows) {
      const dm: Record<string, string | number | null> = {};
      for (const d of dims) dm[d] = d === 'app' ? appName(Number(r.dims.proto), Number(r.dims.svc), Number(r.dims.svc)) : r.dims[d];
      const key = JSON.stringify(dims.map(d => dm[d]));
      const e = m.get(key);
      if (e) { e.bytes += r.bytes; e.pkts += r.pkts; e.flows += r.flows; } else m.set(key, { dims: dm, bytes: r.bytes, pkts: r.pkts, flows: r.flows });
    }
    const sorted = [...m.values()].sort((a, z) => (sortBy === 'pkts' ? z.pkts - a.pkts : sortBy === 'flows' ? z.flows - a.flows : z.bytes - a.bytes));
    const top = sorted.slice(0, topN);
    const rest = sorted.slice(topN).reduce((a, r) => ({ bytes: a.bytes + r.bytes, pkts: a.pkts + r.pkts, flows: a.flows + r.flows, rows: a.rows + 1 }), { bytes: 0, pkts: 0, flows: 0, rows: 0 });
    rows = top; other = rest;
    res.totalRows = sorted.length;
  }
  // readable values
  const view = rows.map(r => {
    const d: Record<string, string | number | null> = {};
    for (const k of dims) {
      const v = r.dims[k];
      if (k === 'proto') d[k] = protoName(Number(v));
      else if (k === 'dscp') d[k] = dscpName(Number(v));
      else if (k === 'vlan') { const id = Number(v); d[k] = id ? (app.vlanName(id) ? `${id} ${app.vlanName(id)}` : String(id)) : 'untagged'; }
      else if (k === 'inIf') { const [ip, idx] = String(v).split('#'); d[k] = `${app.devices.deviceName(ip)} ${app.devices.ifName(ip, Number(idx))}`; }
      else if (k === 'qos') { const s = String(v); d[k] = s === 'unchanged' ? 'unchanged' : s.split('>').map(Number).map(dscpName).join(' → '); }
      else if (k === 'flags') d[k] = flagsText(Number(v));
      else if (k === 'srcMac' || k === 'dstMac') d[k] = v === '' || v === null ? '—' : v;
      else d[k] = v;
    }
    return { dims: d, bytes: r.bytes, pkts: r.pkts, flows: r.flows };
  });
  return { range, tier, dims: dims.map(d => ({ id: d, label: DIM_LABEL[d] })), rows: view, totalRows: res.totalRows, totals: res.totals, other, errors, bidir: !!b.bidir, prefix };
}

export function registerReports(app: App): void {
  const w = app.web;

  w.post('/api/reports', 'ro', async c => {
    const b = await c.body<ReportBody>(20_000);
    const r = await run(app, c, b);
    app.log.info('query', `Report by ${r.dims.map(d => d.label).join(', ')} (${r.rows.length} rows, ${r.tier} data)`, c.user().username);
    c.json(r);
  });

  w.post('/api/reports/export', 'ro', async c => {
    const b = await c.body<ReportBody>(20_000);
    const r = await run(app, c, b);
    const fmt = b.format === 'json' ? 'json' : 'csv';
    const name = `flowscope-report-${stamp()}.${fmt}`;
    app.log.info('query', `Exported report (${r.rows.length} rows, ${fmt.toUpperCase()})`, c.user().username);
    if (fmt === 'json') return attachment(c, name, 'application/json', JSON.stringify({ generatedAt: new Date().toISOString(), range: { from: new Date(r.range.from).toISOString(), to: new Date(r.range.to).toISOString() }, tier: r.tier, totals: r.totals, rows: r.rows.map(x => ({ ...x.dims, bytes: x.bytes, packets: x.pkts, flows: x.flows })), other: r.other }, null, 2));
    const head = [...r.dims.map(d => d.label), 'Bytes', 'Packets', 'Flows'];
    const rows = r.rows.map(x => [...r.dims.map(d => x.dims[d.id]), x.bytes, x.pkts, x.flows]);
    if (r.other.rows) rows.push([...r.dims.map((_, i) => (i === 0 ? `Other (${r.other.rows} more)` : '')), r.other.bytes, r.other.pkts, r.other.flows]);
    attachment(c, name, 'text/csv; charset=utf-8', '﻿' + toCsv(head, rows));
  });
}
