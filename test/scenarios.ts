import test from 'node:test';
import assert from 'node:assert/strict';
import type { FlowRecord } from '../src/collector/types.js';
import type { Cond, ReportSpec, StreamQuery, StoreStats, TsStore } from '../src/store/types.js';
import { ipToN } from '../src/store/util.js';

export const NOW = Date.now();
export const HOUR = 3600_000;
export function rec(over: Partial<FlowRecord> = {}): FlowRecord {
  return {
    ts0: NOW - 30_000, ts1: NOW - 10_000, exporter: '10.255.0.1', inIf: 3, outIf: 7, srcIp: '10.1.4.21', dstIp: '198.51.100.40', proto: 6,
    sport: 51522, dport: 443, flags: 0x1b, tos: 184, postTos: 184, ttlMin: 62, ttlMax: 63, bytes: 1000, pkts: 10,
    srcMac: '00:50:56:01:04:15', dstMac: '00:1c:73:01:aa:bb', vlan: 140, natSrcIp: null, natDstIp: null, natSport: null, natDport: null,
    nextHop: null, sampling: 1, ...over
  };
}
export const range = { from: NOW - HOUR, to: NOW + 60_000 };
export const q = (conds: Cond[] = [], over: Partial<StreamQuery> = {}): StreamQuery => ({ range, conds, sort: 'time', dir: 'desc', limit: 100, ...over });
export const RET = { raw: 7, m1: 30, h1: 395, d1: 1095, sRaw: 30, sH: 395 };

/** Store contract: the same scenarios run against every backend. */
export interface Sut extends Omit<TsStore, 'kind' | 'streamRecords' | 'stats'> {
  streamRecords(skey: string, range: { from: number; to: number }): Promise<(FlowRecord & { primary?: boolean })[]>;
  stats(): Promise<Pick<StoreStats, 'rawDays' | 'rawRows' | 'm1Rows' | 'h1Rows'>>;
}
export type Mk = () => Promise<{ s: Sut; done: () => Promise<void> | void }>;

export function scenarios(label: string, mk: Mk): void {
  test(label + ': multi-exporter flows count bytes once and list all exporters', async () => {
    const t = await mk();
    try {
      await t.s.insertFlows([
        rec({ exporter: '10.255.0.1', bytes: 1000, pkts: 10 }),
        rec({ exporter: '10.255.0.2', inIf: 1, bytes: 1000, pkts: 10, ttlMin: 61, ttlMax: 61 }),
        rec({ exporter: '10.255.0.3', inIf: 2, bytes: 1000, pkts: 10, ttlMin: 60, ttlMax: 60 }),
        // reverse direction
        rec({ srcIp: '198.51.100.40', dstIp: '10.1.4.21', sport: 443, dport: 51522, bytes: 5000, pkts: 20 })
      ]);
      const r = await t.s.searchStreams(q());
      assert.equal(r.total, 1);
      const s = r.rows[0];
      assert.equal(s.srcIp, '10.1.4.21');
      assert.equal(s.dstIp, '198.51.100.40');
      assert.equal(s.fwdBytes, 1000);
      assert.equal(s.revBytes, 5000);
      assert.equal(s.bytes, 6000);
      assert.deepEqual(s.exporters.sort(), ['10.255.0.1', '10.255.0.2', '10.255.0.3']);
      const recs = await t.s.streamRecords(s.skey, range);
      assert.equal(recs.length, 4);
      assert.equal(recs.filter(x => x.primary).length, 2);
    } finally { await t.done(); }
  });

  test(label + ': stream search tokens', async () => {
    const t = await mk();
    try {
      await t.s.insertFlows([
        rec(),
        rec({ srcIp: '10.9.0.5', dstIp: '10.9.0.9', sport: 40000, dport: 5432, proto: 6, vlan: 200, srcMac: '00:50:56:09:00:05' }),
        rec({ srcIp: '10.1.4.77', dstIp: '8.8.8.8', sport: 5353, dport: 53, proto: 17, vlan: 140, tos: 0, postTos: 0 })
      ]);
      const n = async (conds: Cond[]) => (await t.s.searchStreams(q(conds))).total;
      assert.equal(await n([]), 3);
      assert.equal(await n([{ kind: 'src', m: [{ lo: ipToN('10.1.4.0')!, hi: ipToN('10.1.4.255')! }] }]), 2);
      assert.equal(await n([{ kind: 'dst', m: [{ lo: ipToN('10.1.4.0')!, hi: ipToN('10.1.4.255')! }] }]), 0);
      assert.equal(await n([{ kind: 'ip', m: [{ lo: ipToN('8.8.8.8')!, hi: ipToN('8.8.8.8')! }] }]), 1);
      assert.equal(await n([{ kind: 'dport', ports: [443] }]), 1);
      assert.equal(await n([{ kind: 'sport', ports: [443] }]), 0);
      assert.equal(await n([{ kind: 'port', ports: [443] }]), 1);
      assert.equal(await n([{ kind: 'proto', protos: [17] }]), 1);
      assert.equal(await n([{ kind: 'vlan', ids: [200] }]), 1);
      assert.equal(await n([{ kind: 'mac', text: '09:00' }]), 1);
      assert.equal(await n([{ kind: 'dscp', values: [46] }]), 2);
      assert.equal(await n([{ kind: 'proto', protos: [6] }, { kind: 'vlan', ids: [140] }]), 1);
      assert.equal(await n([{ kind: 'exporter', ips: ['10.255.0.1'] }]), 3);
      assert.equal(await n([{ kind: 'exporter', ips: ['1.1.1.1'] }]), 0);
      const lim = await t.s.searchStreams(q([], { limit: 2 }));
      assert.equal(lim.rows.length, 2); assert.equal(lim.total, 3); assert.equal(lim.truncated, true);
    } finally { await t.done(); }
  });

  test(label + ': src filter is exact on the initiator, port filter is either direction', async () => {
    const t = await mk();
    try {
      await t.s.insertFlows([
        rec({ ts0: NOW - 40_000, ts1: NOW - 30_000 }),
        rec({ srcIp: '198.51.100.40', dstIp: '10.1.4.21', sport: 443, dport: 51522, ts0: NOW - 29_000, ts1: NOW - 20_000 })
      ]);
      const server = [{ lo: ipToN('198.51.100.40')!, hi: ipToN('198.51.100.40')! }];
      assert.equal((await t.s.searchStreams(q([{ kind: 'src', m: server }]))).total, 0);
      assert.equal((await t.s.searchStreams(q([{ kind: 'dst', m: server }]))).total, 1);
      assert.equal((await t.s.searchStreams(q([{ kind: 'port', ports: [51522] }]))).total, 1);
    } finally { await t.done(); }
  });

  test(label + ': qos changed detection (DSCP re-marked between hops or by egress policy)', async () => {
    const t = await mk();
    try {
      await t.s.insertFlows([
        // stream A: same dscp, no remark
        rec({ srcIp: '10.0.0.1', dstIp: '10.0.0.2', sport: 1, dport: 1, tos: 184, postTos: 184 }),
        rec({ srcIp: '10.0.0.1', dstIp: '10.0.0.2', sport: 1, dport: 1, tos: 184, postTos: 184, exporter: '10.255.0.2' }),
        // stream B: dscp differs across hops
        rec({ srcIp: '10.0.0.3', dstIp: '10.0.0.4', sport: 2, dport: 2, tos: 184, postTos: null }),
        rec({ srcIp: '10.0.0.3', dstIp: '10.0.0.4', sport: 2, dport: 2, tos: 0, postTos: null, exporter: '10.255.0.2' }),
        // stream C: egress policy remarks
        rec({ srcIp: '10.0.0.5', dstIp: '10.0.0.6', sport: 3, dport: 3, tos: 184, postTos: 0 })
      ]);
      const ch = await t.s.searchStreams(q([{ kind: 'qos', mode: 'changed' }]));
      assert.deepEqual(ch.rows.map(r => r.srcIp).sort(), ['10.0.0.3', '10.0.0.5']);
      assert.ok(ch.rows.every(r => r.qosChanged));
      const un = await t.s.searchStreams(q([{ kind: 'qos', mode: 'unchanged' }]));
      assert.deepEqual(un.rows.map(r => r.srcIp), ['10.0.0.1']);
    } finally { await t.done(); }
  });

  test(label + ': sorting by bytes', async () => {
    const t = await mk();
    try {
      await t.s.insertFlows([rec({ sport: 1, bytes: 10 }), rec({ sport: 2, bytes: 300 }), rec({ sport: 3, bytes: 50 })]);
      const r = await t.s.searchStreams(q([], { sort: 'bytes', dir: 'desc' }));
      assert.deepEqual(r.rows.map(x => x.bytes), [300, 50, 10]);
      const a = await t.s.searchStreams(q([], { sort: 'bytes', dir: 'asc' }));
      assert.deepEqual(a.rows.map(x => x.bytes), [10, 50, 300]);
    } finally { await t.done(); }
  });

  test(label + ': raw report: group, top-N with other, bidirectional combine, prefix', async () => {
    const t = await mk();
    try {
      await t.s.insertFlows([
        rec({ srcIp: '10.1.4.21', dstIp: '198.51.100.40', bytes: 1000, pkts: 10 }),
        rec({ srcIp: '198.51.100.40', dstIp: '10.1.4.21', sport: 443, dport: 51522, bytes: 4000, pkts: 40 }),
        rec({ srcIp: '10.1.4.22', dstIp: '198.51.100.41', sport: 1, bytes: 500, pkts: 5 }),
        rec({ srcIp: '10.2.0.1', dstIp: '198.51.100.42', sport: 2, bytes: 100, pkts: 1 })
      ]);
      const base: ReportSpec = { range, tier: 'raw', dims: ['srcIp'], prefix: 32, bidir: false, conds: [], sortBy: 'bytes', topN: 2, };
      const r = await t.s.report(base);
      assert.equal(r.rows.length, 2);
      assert.equal(r.rows[0].dims.srcIp, '198.51.100.40');
      assert.equal(r.rows[0].bytes, 4000);
      assert.equal(r.totals.bytes, 5600);
      assert.equal(r.other.bytes, 600);
      assert.equal(r.other.rows, 2);
      assert.equal(r.rows.reduce((s, x) => s + x.bytes, 0) + r.other.bytes, 5600);
      // prefix /16 collapses 10.1.x
      const p = await t.s.report({ ...base, prefix: 16, topN: 10 });
      const m = new Map(p.rows.map(x => [String(x.dims.srcIp), x.bytes]));
      assert.equal(m.get('10.1.0.0/16'), 1500);
      assert.equal(m.get('10.2.0.0/16'), 100);
      // bidir: src+dst pair combined
      const b = await t.s.report({ ...base, dims: ['srcIp', 'dstIp'], bidir: true, topN: 10 });
      const pair = b.rows.find(x => x.bytes === 5000);
      assert.ok(pair, 'combined pair should have 5000 bytes');
      assert.equal(b.rows.length, 3);
      // filter by proto
      const f = await t.s.report({ ...base, topN: 10, conds: [{ kind: 'proto', protos: [17] }] });
      assert.equal(f.rows.length, 0);
    } finally { await t.done(); }
  });

  test(label + ': rollup tiers: 1m/1h/1d report agrees with raw', async () => {
    const t = await mk();
    try {
      const base = Math.floor((NOW - 3 * 24 * HOUR) / HOUR) * HOUR;
      const recs: FlowRecord[] = [];
      let total = 0;
      for (let h = 0; h < 30; h++) for (let k = 0; k < 4; k++) {
        const ts = base + h * HOUR + k * 600_000 + 5000;
        recs.push(rec({ ts0: ts - 2000, ts1: ts, srcIp: '10.1.4.' + (1 + (k % 2)), sport: 1000 + k, bytes: 100 + h, pkts: 1 }));
        total += 100 + h;
      }
      await t.s.insertFlows(recs);
      const wide = { from: base - HOUR, to: NOW };
      const rawRep = await t.s.report({ range: wide, tier: 'raw', dims: ['srcIp'], prefix: 32, bidir: false, conds: [], sortBy: 'bytes', topN: 10 });
      assert.equal(rawRep.totals.bytes, total);
      const res = await t.s.maintain(RET, NOW);
      assert.ok(Array.isArray(res.dropped));
      for (const tier of ['m1', 'h1'] as const) {
        const r = await t.s.report({ range: wide, tier, dims: ['srcIp'], prefix: 32, bidir: false, conds: [], sortBy: 'bytes', topN: 10 });
        assert.equal(r.totals.bytes, total, tier);
        assert.equal(r.totals.flows, 120, tier);
        assert.deepEqual(r.rows.map(x => [x.dims.srcIp, x.bytes]).sort(), rawRep.rows.map(x => [x.dims.srcIp, x.bytes]).sort(), tier);
      }
      // daily tier only has complete days; the sum over complete days must be <= total and > 0
      const d = await t.s.report({ range: wide, tier: 'd1', dims: ['srcIp'], prefix: 32, bidir: false, conds: [], sortBy: 'bytes', topN: 10 });
      assert.ok(d.totals.bytes > 0 && d.totals.bytes <= total);
      // idempotent
      await t.s.maintain(RET, NOW);
      const again = await t.s.report({ range: wide, tier: 'm1', dims: ['srcIp'], prefix: 32, bidir: false, conds: [], sortBy: 'bytes', topN: 10 });
      assert.equal(again.totals.bytes, total);
      const st = await t.s.stats();
      assert.equal(st.rawRows, 120); assert.ok(st.m1Rows > 0 && st.h1Rows > 0);
    } finally { await t.done(); }
  });

  test(label + ': retention drops old raw tables and rolled rows', async () => {
    const t = await mk();
    try {
      const old = NOW - 10 * 24 * HOUR;
      await t.s.insertFlows([rec({ ts0: old - 1000, ts1: old, bytes: 77 }), rec({ bytes: 5 })]);
      const before = await t.s.stats();
      assert.equal(before.rawDays, 2);
      await t.s.maintain({ ...RET, raw: 7 }, NOW);
      // 1m rollup of the old record exists, then it is the only one kept (raw table is dropped)
      const after = await t.s.stats();
      assert.equal(after.rawDays, 1);
      const r = await t.s.report({ range: { from: old - HOUR, to: old + HOUR }, tier: 'm1', dims: ['srcIp'], prefix: 32, bidir: false, conds: [], sortBy: 'bytes', topN: 5 });
      assert.equal(r.totals.bytes, 77);
      await t.s.maintain({ ...RET, raw: 7, m1: 5 }, NOW);
      const r2 = await t.s.report({ range: { from: old - HOUR, to: old + HOUR }, tier: 'm1', dims: ['srcIp'], prefix: 32, bidir: false, conds: [], sortBy: 'bytes', topN: 5 });
      assert.equal(r2.totals.bytes, 0);
    } finally { await t.done(); }
  });

  test(label + ': SNMP interface and class series, latest, hourly rollup, delete', async () => {
    const t = await mk();
    try {
      const ifs = [], cls = [];
      for (let i = 0; i < 20; i++) {
        const ts = NOW - (20 - i) * 60_000;
        ifs.push({ ts, dev: 1, ifIndex: 7, dt: 60, inBps: 1e6, outBps: 5e6, utilIn: 1, utilOut: 5, inDisc: 0, outDisc: i === 10 ? 40 : 0, inErr: 0, outErr: 0, oper: 1 });
        cls.push({ ts, dev: 1, ifIndex: 7, cls: 'voice', dt: 60, prePkts: 1000, preBytes: 1e6, postBytes: 1e6 - 1000, dropPkts: i === 10 ? 100 : 0, dropBytes: i === 10 ? 100000 : 0, qdepth: i });
        cls.push({ ts, dev: 1, ifIndex: 7, cls: 'bulk', dt: 60, prePkts: 1000, preBytes: 1e6, postBytes: 5e5, dropPkts: 50, dropBytes: 50000, qdepth: 3 });
      }
      await t.s.insertSnmp(ifs, cls);
      const rg = { from: NOW - 30 * 60_000, to: NOW };
      const s = await t.s.ifSeries(1, 7, rg, RET, 30);
      assert.equal(s.tier, 'raw');
      assert.equal(s.points.length, 20);
      assert.equal(s.points.reduce((a, p) => a + p.disc, 0), 40);
      const c = await t.s.classSeries(1, 7, rg, RET, 30);
      const voice = c.classes.find(x => x.cls === 'voice')!;
      const bulk = c.classes.find(x => x.cls === 'bulk')!;
      assert.ok(Math.max(...voice.points.map(p => p.dropPct)) === 10);
      assert.ok(bulk.points.every(p => Math.abs(p.dropPct - 5) < 1e-9));
      const lat = await t.s.classLatest(NOW - 3600_000);
      assert.equal(lat.length, 2);
      const lv = lat.find(x => x.cls === 'voice')!;
      assert.equal(lv.dropPkts, 100);
      assert.equal(lv.qdepth, 19);
      const il = await t.s.ifLatest(NOW - 3600_000);
      assert.equal(il.length, 1);
      assert.equal(il[0].disc, 40);
      // hourly rollup. now far in the future so the hour(s) are complete
      const future = NOW + 3 * HOUR;
      await t.s.maintain(RET, future);
      const h = await t.s.ifSeries(1, 7, { from: NOW - 30 * 24 * HOUR - HOUR, to: future }, { ...RET, sRaw: 1 }, 50);
      assert.equal(h.tier, 'h1');
      assert.equal(h.points.reduce((a, p) => a + p.disc, 0), 40);
      const hc = await t.s.classSeries(1, 7, { from: NOW - 30 * 24 * HOUR - HOUR, to: future }, { ...RET, sRaw: 1 }, 50);
      assert.ok(hc.classes.find(x => x.cls === 'bulk')!.points.every(p => Math.abs(p.dropPct - 5) < 1e-9));
      await t.s.deleteDevice(1);
      assert.equal((await t.s.ifLatest(NOW - 3600_000)).length, 0);
      assert.equal((await t.s.classSeries(1, 7, rg, RET, 30)).classes.length, 0);
    } finally { await t.done(); }
  });

  test(label + ': stream rows report dscp in/out', async () => {
    const t = await mk();
    try {
      await t.s.insertFlows([
        rec({ srcIp: '10.0.0.1', dstIp: '10.0.0.2', sport: 1, dport: 1, tos: 184, postTos: 184, ts0: NOW - 50_000, ts1: NOW - 40_000 }),
        rec({ srcIp: '10.0.0.1', dstIp: '10.0.0.2', sport: 1, dport: 1, tos: 0, postTos: 0, exporter: '10.255.0.2', ts0: NOW - 49_000, ts1: NOW - 39_000 }),
        rec({ srcIp: '10.0.0.3', dstIp: '10.0.0.4', sport: 2, dport: 2, tos: 184, postTos: 32 }),
        rec({ srcIp: '10.0.0.5', dstIp: '10.0.0.6', sport: 3, dport: 3, tos: 40, postTos: 40 })
      ]);
      const r = await t.s.searchStreams(q());
      const by = (ip: string) => r.rows.find(x => x.srcIp === ip)!;
      assert.deepEqual([by('10.0.0.1').dscpIn, by('10.0.0.1').dscpOut], [46, 0]);
      assert.deepEqual([by('10.0.0.3').dscpIn, by('10.0.0.3').dscpOut], [46, 8]);
      assert.deepEqual([by('10.0.0.5').dscpIn, by('10.0.0.5').dscpOut], [10, null]);
    } finally { await t.done(); }
  });

  test(label + ': rollups count records that arrive late or are loaded after the first run, exactly once', async () => {
    const t = await mk();
    try {
      await t.s.maintain(RET, NOW);                       // first run on an empty store must not set a time watermark
      const ts = NOW - 2 * HOUR - 17_000;
      await t.s.insertFlows([rec({ ts0: ts - 1000, ts1: ts, bytes: 500, pkts: 5, sport: 1111 })]);
      await t.s.maintain(RET, NOW);
      await t.s.insertFlows([rec({ ts0: ts - 3000, ts1: ts - 600_000, bytes: 700, pkts: 7, sport: 2222 })]);   // older than the data already rolled
      await t.s.maintain(RET, NOW);
      await t.s.maintain(RET, NOW);
      const wide = { from: NOW - 4 * HOUR, to: NOW };
      const spec = { range: wide, dims: [] as never[], prefix: 32, bidir: false, conds: [], sortBy: 'bytes' as const, topN: 10 };
      assert.equal((await t.s.report({ ...spec, tier: 'raw' })).totals.bytes, 1200);
      assert.equal((await t.s.report({ ...spec, tier: 'm1' })).totals.bytes, 1200);
    } finally { await t.done(); }
  });
}
