import type { App } from '../app.js';
import { HttpError } from '../server/http.js';
import { int, parseRange } from './util.js';
import type { ClassLatest, IfLatest } from '../store/types.js';
import { streamView } from './flows.js';

export const MIBS = [
  { name: 'IF-MIB · ifXTable, ifTable', what: 'Interface names, speed, status, 64-bit octet counters and discards.' },
  { name: 'IP-MIB · ipAddrTable', what: 'The addresses of each device, so flow exporters are matched to the right device.' },
  { name: 'Q-BRIDGE-MIB · dot1qVlanStaticName', what: 'VLAN numbers and their names, so flows and interfaces can be searched by either.' },
  { name: 'CISCO-CLASS-BASED-QOS-MIB', what: 'Output service-policy structure, per-class packets, bytes and drops, and queue depth. Used for devices that implement it.' }
];

interface Event { ts0: number; ts1: number; devId: number; dev: string; ifIndex: number; ifName: string; kind: 'drop' | 'util' | 'errors'; cls?: string; peak: number; text: string; severity: 'warn' | 'bad' }

export function registerLinks(app: App): void {
  const w = app.web;
  const alerts = () => app.settings.get('alerts');

  // Interfaces and QoS classes for every polled device, with the latest rates
  w.get('/api/links', 'ro', async c => {
    const minutes = int(c.query.get('minutes'), 10, 1, 1440);
    const since = Date.now() - minutes * 60_000;
    const [ifl, cll] = await Promise.all([app.store.ifLatest(since), app.store.classLatest(since)]);
    const ifBy = new Map<string, IfLatest>(ifl.map(i => [`${i.dev}/${i.ifIndex}`, i]));
    const clBy = new Map<string, ClassLatest[]>();
    for (const k of cll) { const key = `${k.dev}/${k.ifIndex}`; const a = clBy.get(key); if (a) a.push(k); else clBy.set(key, [k]); }
    const al = alerts();
    const devices = app.devices.list().map(d => ({
      id: d.id, name: d.name, ip: d.ip, role: d.role, status: d.status, lastOk: d.lastOk, lastError: d.lastError, profile: d.profile,
      interfaces: app.devices.interfaces(d.id).map(i => {
        const l = ifBy.get(`${d.id}/${i.ifIndex}`); const cls = clBy.get(`${d.id}/${i.ifIndex}`) ?? [];
        return {
          ifIndex: i.ifIndex, name: i.name, alias: i.alias, speedMbps: i.speedMbps, oper: i.oper, policy: i.policy,
          utilIn: l?.utilIn ?? null, utilOut: l?.utilOut ?? null, inBps: l?.inBps ?? null, outBps: l?.outBps ?? null, disc: l?.disc ?? 0, err: l?.err ?? 0,
          classes: i.classes.map(def => {
            const k = cls.find(x => x.cls === def.cls);
            return { cls: def.cls, dscps: def.dscps, bw: def.bw, queue: def.queue, dropPct: k?.dropPct ?? null, dropPkts: k?.dropPkts ?? 0, dropBytes: k?.dropBytes ?? 0, sentBps: k?.sentBps ?? null, qdepth: k?.qdepth ?? null };
          }),
          worstDropPct: cls.length ? Math.max(...cls.map(x => x.dropPct)) : null,
          flagged: (l && Math.max(l.utilIn, l.utilOut) >= al.util) || cls.some(x => x.dropPct >= al.drop)
        };
      })
    }));
    c.json({ devices, windowMinutes: minutes, thresholds: al, mibs: MIBS });
  });

  // Streams that left through one interface (found from the exporter and outgoing interface in the flow records)
  w.get('/api/links/streams', 'ro', async c => {
    const dev = int(c.query.get('dev'), 0, 0, 1e9), ifx = int(c.query.get('if'), 0, 0, 1e9);
    if (!app.devices.row(dev)) throw new HttpError(404, 'No such device');
    const range = parseRange(c.query, '1h');
    const page = await app.store.searchStreams({ range, conds: [{ kind: 'outif', ips: app.devices.exporterIpsForDevice(dev), ifIndex: ifx }], sort: 'bytes', dir: 'desc', limit: int(c.query.get('limit'), 8, 1, 50) });
    c.json({ rows: page.rows.map(r => streamView(app, r)), total: page.total });
  });

  // Time series for one interface: utilisation plus drop % and dropped bytes for each class
  w.get('/api/links/series', 'ro', async c => {
    const dev = int(c.query.get('dev'), 0, 0, 1e9), ifx = int(c.query.get('if'), 0, 0, 1e9);
    if (!app.devices.row(dev)) throw new HttpError(404, 'No such device');
    const range = parseRange(c.query, '6h');
    const points = int(c.query.get('points'), 120, 10, 600);
    const ret = app.settings.get('retention');
    const [u, k] = await Promise.all([app.store.ifSeries(dev, ifx, range, ret, points), app.store.classSeries(dev, ifx, range, ret, points)]);
    const defs = app.devices.interfaces(dev).find(i => i.ifIndex === ifx)?.classes ?? [];
    c.json({ range, util: u, classes: k.classes.map(cl => ({ ...cl, dscps: defs.find(d => d.cls === cl.cls)?.dscps ?? [], bw: defs.find(d => d.cls === cl.cls)?.bw ?? null })), step: u.step, tier: u.tier });
  });

  // Events: stretches where utilisation or drops were over the alert thresholds
  w.get('/api/links/events', 'ro', async c => {
    const range = parseRange(c.query, '24h');
    const al = alerts(); const ret = app.settings.get('retention');
    const out: Event[] = [];
    const maxIfs = 400;
    let scanned = 0;
    for (const d of app.devices.list()) {
      for (const i of app.devices.interfaces(d.id)) {
        if (scanned++ >= maxIfs) break;
        const [u, k] = await Promise.all([app.store.ifSeries(d.id, i.ifIndex, range, ret, 288), i.classes.length ? app.store.classSeries(d.id, i.ifIndex, range, ret, 288) : Promise.resolve(null)]);
        const merge = (pts: { ts: number; v: number }[], limit: number, step: number, mk: (peak: number) => Pick<Event, 'kind' | 'text' | 'cls'>) => {
          let cur: { a: number; b: number; peak: number } | null = null;
          const flush = () => { if (!cur) return; const m = mk(cur.peak); out.push({ ts0: cur.a, ts1: cur.b + step, devId: d.id, dev: d.name, ifIndex: i.ifIndex, ifName: i.name, peak: cur.peak, severity: cur.peak >= limit * 2.5 ? 'bad' : 'warn', ...m }); cur = null; };
          for (const p of pts) {
            if (p.v >= limit) { if (cur && p.ts - cur.b <= step * 1.5) { cur.b = p.ts; cur.peak = Math.max(cur.peak, p.v); } else { flush(); cur = { a: p.ts, b: p.ts, peak: p.v }; } }
          }
          flush();
        };
        merge(u.points.map(p => ({ ts: p.ts, v: Math.max(p.utilIn, p.utilOut) })), al.util, u.step, peak => ({ kind: 'util', text: `Utilisation reached ${peak.toFixed(0)}% on ${i.name}` }));
        for (const cl of k?.classes ?? []) {
          merge(cl.points.map(p => ({ ts: p.ts, v: p.dropPct })), al.drop, k!.step, peak => ({ kind: 'drop', cls: cl.cls, text: `Class ${cl.cls} dropped ${peak.toFixed(2)}% of packets on ${i.name}` }));
        }
        void u.points.length;
      }
    }
    out.sort((a, b) => b.ts1 - a.ts1);
    c.json({ events: out.slice(0, 500), range, thresholds: al, truncated: out.length > 500, scannedInterfaces: scanned });
  });
}
