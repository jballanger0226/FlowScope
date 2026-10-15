import { enrichPath } from '../analysis/path.js';
import { notExported } from '../analysis/exported.js';
import { pathEnv } from './pathenv.js';
import type { App } from '../app.js';
import { HttpError } from '../server/http.js';
import { parseQuery } from '../query/tokens.js';
import { appName, dscpName, protoName, service } from '../query/apps.js';
import { analyzeStream, type HopContext } from '../analysis/hops.js';
import type { StreamRow } from '../store/types.js';
import { int, parseRange, str } from './util.js';

export function streamView(app: App, r: StreamRow) {
  return {
    id: r.skey, srcIp: r.srcIp, dstIp: r.dstIp, sport: r.sport, dport: r.dport, proto: r.proto, protoName: protoName(r.proto), app: appName(r.proto, r.sport, r.dport), appPort: service(r.proto, r.sport, r.dport).port,
    vlan: r.vlan, vlanName: r.vlan ? app.vlanName(r.vlan) : '', t0: r.t0, t1: r.t1, bytes: r.bytes, pkts: r.pkts, fwdBytes: r.fwdBytes, revBytes: r.revBytes,
    hopCount: r.exporters.length, hops: r.exporters.map(e => app.devices.deviceName(e)), qosChanged: r.qosChanged,
    ttlExpired: r.ttlExpired, ttlReason: r.ttlReason, ttlLow: r.ttlLow,
    dscpIn: r.dscpIn, dscpInS: dscpName(r.dscpIn), dscpOut: r.dscpOut, dscpOutS: r.dscpOut === null ? null : dscpName(r.dscpOut), flags: r.flags
  };
}

/** Bytes per time bucket for each direction, using the first exporter's records only so nothing is counted twice. */
function activity(recs: { ts0: number; ts1: number; bytes: number; srcIp: string; sport: number; primary?: boolean }[], d: { initiator: { ip: string; port: number }; t0: number; t1: number }, n = 24) {
  const span = Math.max(1000, d.t1 - d.t0), step = span / n;
  const fwd = new Array<number>(n).fill(0), rev = new Array<number>(n).fill(0);
  for (const r of recs) {
    if (r.primary === false) continue;
    const arr = r.srcIp === d.initiator.ip && r.sport === d.initiator.port ? fwd : rev;
    const a = r.ts0, b = Math.max(r.ts1, r.ts0 + 1);
    for (let i = Math.max(0, Math.floor((a - d.t0) / step)); i < n && d.t0 + i * step < b; i++) {
      const lo = Math.max(a, d.t0 + i * step), hi = Math.min(b, d.t0 + (i + 1) * step);
      if (hi > lo) arr[i] += r.bytes * (hi - lo) / (b - a);
    }
  }
  return { t0: d.t0, t1: d.t0 + span, fwd: fwd.map(Math.round), rev: rev.map(Math.round) };
}

export function registerFlows(app: App): void {
  const w = app.web;

  w.get('/api/streams', 'ro', async c => {
    const q = str(c.query.get('q'), 1000);
    const range = parseRange(c.query, '1h');
    const parsed = parseQuery(q, app.resolver());
    const sort = (['time', 'bytes', 'pkts'] as const).find(s => s === c.query.get('sort')) ?? 'time';
    const dir = c.query.get('dir') === 'asc' ? 'asc' : 'desc';
    const limit = int(c.query.get('limit'), 200, 1, 2000);
    const page = await app.store.searchStreams({ range, conds: parsed.conds, sort, dir, limit, localIps: app.localIps() });
    const user = c.user().username;
    // health of the first rows: a quick hop analysis of each stream (loss between hops, slow links) without the SNMP lookups
    const localIps = new Set(app.localIps());
    const quick: HopContext = { localIps, deviceName: ip => app.devices.deviceName(ip), deviceRole: ip => app.devices.deviceRole(ip), ifName: (ip, i) => app.devices.ifName(ip, i) };
    const health = new Map<string, { kind: 'ok' | 'warn' | 'bad'; text: string }>();
    await Promise.all(page.rows.slice(0, 100).map(async r => {
      try {
        const recs = await app.store.streamRecords(r.skey, range);
        const d = analyzeStream(r.skey, recs, quick);
        if (!d) return;
        const obs = [...d.forward, ...d.reverse].flatMap(h => h.obs);
        const loss = obs.filter(o => o.kind === 'loss').map(o => Number(/^([\d.]+)%/.exec(o.text)?.[1] ?? 0));
        if (r.ttlExpired) health.set(r.skey, { kind: 'bad', text: 'TTL expired' });
        else if (loss.length) health.set(r.skey, { kind: Math.max(...loss) >= 5 ? 'bad' : 'warn', text: `Loss ${Math.max(...loss).toFixed(1)}%` });
        else if (obs.some(o => o.kind === 'slow')) health.set(r.skey, { kind: 'warn', text: 'High latency' });
        else health.set(r.skey, { kind: 'ok', text: 'Healthy' });
      } catch { /* leave the status blank */ }
    }));
    if (q.trim()) app.log.info('query', `Flow search: ${q.trim()} (${page.total} result${page.total === 1 ? '' : 's'})`, user);
    c.json({ rows: page.rows.map(r => ({ ...streamView(app, r), health: health.get(r.skey) ?? null })), total: page.total, truncated: page.truncated, errors: parsed.errors, range, tier: page.tier });
  });

  // One stream with its hops. The stream id contains punctuation, so it goes in the query string.
  w.get('/api/streams/detail', 'ro', async c => {
    const id = str(c.query.get('id'), 300);
    if (!id) throw new HttpError(400, 'id is required');
    const range = parseRange(c.query, '24h');
    const recs = await app.store.streamRecords(id, range);
    if (!recs.length) throw new HttpError(404, 'No records for that stream in this time range. It may have aged out.');
    // egress queue drops from SNMP for each exporter and outgoing interface the stream used
    const drops = new Map<string, { cls: string; dropPct: number; dropPkts: number; dscps: number[] }[]>();
    const t0 = Math.min(...recs.map(r => r.ts0)) - 180_000, t1 = Math.max(...recs.map(r => r.ts1)) + 180_000;
    const seen = new Set<string>();
    for (const r of recs) {
      const key = `${r.exporter}|${r.outIf}`;
      if (seen.has(key)) continue; seen.add(key);
      const devId = app.devices.deviceIdForExporter(r.exporter);
      if (devId === null || !r.outIf) continue;
      // only the output policy queues the stream; classes of an input policy ("in:") act on traffic arriving at the port
      const defs = (app.devices.interfaces(devId).find(i => i.ifIndex === r.outIf)?.classes ?? []).filter(c => !c.cls.startsWith('in:'));
      if (!defs.length) continue;
      try {
        const cs = await app.store.classSeries(devId, r.outIf, { from: t0, to: t1 }, app.settings.get('retention'), 1);
        const secs = Math.max(60, cs.step) / 1000;
        drops.set(key, cs.classes.filter(k => !k.cls.startsWith('in:')).map(k => {
          const pts = k.points; const pps = pts.length ? pts.reduce((a, p) => a + p.dropPps, 0) / pts.length : 0;
          const pct = pts.length ? Math.max(...pts.map(p => p.dropPct)) : 0;
          return { cls: k.cls, dropPct: pct, dropPkts: Math.round(pps * secs * Math.max(1, pts.length)), dscps: defs.find(d => d.cls === k.cls)?.dscps ?? [] };
        }));
      } catch { /* SNMP history is optional */ }
    }
    const detail = analyzeStream(id, recs, {
      localIps: new Set(app.localIps()),
      deviceName: ip => app.devices.deviceName(ip), deviceRole: ip => app.devices.deviceRole(ip), ifName: (ip, i) => app.devices.ifName(ip, i), policyOf: (ip, i) => app.devices.policyOf(ip, i),
      vlanName: id2 => app.vlanName(id2),
      classDrops: (ip, outIf, _a, _b, dscp) => (drops.get(`${ip}|${outIf}`) ?? []).filter(d => d.dscps.includes(dscp)).map(d => ({ cls: d.cls, dropPct: d.dropPct, dropPkts: d.dropPkts }))
    });
    if (!detail) throw new HttpError(404, 'No records for that stream');
    // Say which details an exporter never sends, so a blank MAC, VLAN or TTL is understood as not exported.
    for (const hp of [...detail.forward, ...detail.reverse]) {
      const f = app.collector.exporterFields(hp.exporter);
      if (f) { const n = notExported(f.version, f.ids); if (n.length) hp.notExported = n; }
    }
    // Fill in ports the exporter did not report and list the CDP/LLDP neighbour at each port; both are extras, so a failure leaves the plain path.
    try { enrichPath(detail, pathEnv(app), ip => app.devices.deviceIdForExporter(ip)); } catch (e) { app.log.warn('query', `Could not add neighbour detail to a stream: ${(e as Error).message}`); }
    let multicast: (NonNullable<typeof detail.multicast> & { location: ReturnType<typeof app.hosts.locate> | null }) | null = null;
    if (detail.multicast) {
      // The source of a multicast stream is not "behind" the first device that reported it: every switch on the tree reports the same packets.
      // Ask the SNMP data (MAC tables, ARP, LLDP/CDP) which switch port the source host is plugged into.
      const seen = new Map<string, number>();
      for (const r of recs) if (r.srcMac && r.srcIp === detail.multicast.source && app.devices.deviceRole(r.exporter) === 'switch') seen.set(r.srcMac, (seen.get(r.srcMac) ?? 0) + 1);
      const hint = [...seen].sort((a, b) => b[1] - a[1])[0]?.[0] ?? null;
      let location: ReturnType<typeof app.hosts.locate> | null = null;
      try { location = app.hosts.locate(detail.multicast.source, hint); } catch { /* host tracking is optional */ }
      if (location?.attach) {
        const at = location.attach;
        for (const hp of detail.forward) {
          if (hp.dev !== at.dev) continue;
          hp.sourcePort = at.ifName; hp.sourceConfirmed = hp.inIf === at.ifName;
        }
      }
      multicast = { ...detail.multicast, location };
    }
    c.json({ ...detail, multicast, activity: activity(recs, detail) });
  });
}
