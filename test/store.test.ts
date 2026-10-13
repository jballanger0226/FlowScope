import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { SqliteOps, openTsDb, ipToN, skeyOf } from '../src/store/ops.js';
import type { FlowRecord } from '../src/collector/types.js';
import type { Cond, ReportSpec, StreamQuery } from '../src/store/types.js';

const NOW = Date.now();
const HOUR = 3600_000;
function rec(over: Partial<FlowRecord> = {}): FlowRecord {
  return {
    ts0: NOW - 30_000, ts1: NOW - 10_000, exporter: '10.255.0.1', inIf: 3, outIf: 7, srcIp: '10.1.4.21', dstIp: '198.51.100.40', proto: 6,
    sport: 51522, dport: 443, flags: 0x1b, tos: 184, postTos: 184, ttlMin: 62, ttlMax: 63, bytes: 1000, pkts: 10,
    srcMac: '00:50:56:01:04:15', dstMac: '00:1c:73:01:aa:bb', vlan: 140, natSrcIp: null, natDstIp: null, natSport: null, natDport: null,
    nextHop: null, sampling: 1, ...over
  };
}
function mk() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-store-'));
  const db = openTsDb({ dir });
  const ops = new SqliteOps(db, dir, true);
  return { dir, db, ops, done: () => { db.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}
const range = { from: NOW - HOUR, to: NOW + 60_000 };
const q = (conds: Cond[] = [], over: Partial<StreamQuery> = {}): StreamQuery => ({ range, conds, sort: 'time', dir: 'desc', limit: 100, ...over });
const RET = { raw: 7, m1: 30, h1: 395, d1: 1095, sRaw: 30, sH: 395 };

test('ip helpers and canonical stream key', () => {
  assert.equal(ipToN('10.0.0.1'), 167772161);
  assert.equal(ipToN('2001:db8::1'), null);
  const a = skeyOf({ srcIp: '10.1.1.1', dstIp: '10.2.2.2', sport: 1000, dport: 443, proto: 6 });
  const b = skeyOf({ srcIp: '10.2.2.2', dstIp: '10.1.1.1', sport: 443, dport: 1000, proto: 6 });
  assert.equal(a, b);
});

test('multi-exporter flows count bytes once and list all exporters', () => {
  const t = mk();
  try {
    t.ops.insertFlows([
      rec({ exporter: '10.255.0.1', bytes: 1000, pkts: 10 }),
      rec({ exporter: '10.255.0.2', inIf: 1, bytes: 1000, pkts: 10, ttlMin: 61, ttlMax: 61 }),
      rec({ exporter: '10.255.0.3', inIf: 2, bytes: 1000, pkts: 10, ttlMin: 60, ttlMax: 60 }),
      // reverse direction
      rec({ srcIp: '198.51.100.40', dstIp: '10.1.4.21', sport: 443, dport: 51522, bytes: 5000, pkts: 20 })
    ]);
    const r = t.ops.searchStreams(q());
    assert.equal(r.total, 1);
    const s = r.rows[0];
    assert.equal(s.srcIp, '10.1.4.21');
    assert.equal(s.dstIp, '198.51.100.40');
    assert.equal(s.fwdBytes, 1000);
    assert.equal(s.revBytes, 5000);
    assert.equal(s.bytes, 6000);
    assert.deepEqual(s.exporters.sort(), ['10.255.0.1', '10.255.0.2', '10.255.0.3']);
    const recs = t.ops.streamRecords(s.skey, range);
    assert.equal(recs.length, 4);
    assert.equal(recs.filter(x => x.primary).length, 2);
  } finally { t.done(); }
});

test('stream search tokens', () => {
  const t = mk();
  try {
    t.ops.insertFlows([
      rec(),
      rec({ srcIp: '10.9.0.5', dstIp: '10.9.0.9', sport: 40000, dport: 5432, proto: 6, vlan: 200, srcMac: '00:50:56:09:00:05' }),
      rec({ srcIp: '10.1.4.77', dstIp: '8.8.8.8', sport: 5353, dport: 53, proto: 17, vlan: 140, tos: 0, postTos: 0 })
    ]);
    const n = (conds: Cond[]) => t.ops.searchStreams(q(conds)).total;
    assert.equal(n([]), 3);
    assert.equal(n([{ kind: 'src', m: [{ lo: ipToN('10.1.4.0')!, hi: ipToN('10.1.4.255')! }] }]), 2);
    assert.equal(n([{ kind: 'dst', m: [{ lo: ipToN('10.1.4.0')!, hi: ipToN('10.1.4.255')! }] }]), 0);
    assert.equal(n([{ kind: 'ip', m: [{ lo: ipToN('8.8.8.8')!, hi: ipToN('8.8.8.8')! }] }]), 1);
    assert.equal(n([{ kind: 'dport', ports: [443] }]), 1);
    assert.equal(n([{ kind: 'sport', ports: [443] }]), 0);
    assert.equal(n([{ kind: 'port', ports: [443] }]), 1);
    assert.equal(n([{ kind: 'proto', protos: [17] }]), 1);
    assert.equal(n([{ kind: 'vlan', ids: [200] }]), 1);
    assert.equal(n([{ kind: 'mac', text: '09:00' }]), 1);
    assert.equal(n([{ kind: 'dscp', values: [46] }]), 2);
    assert.equal(n([{ kind: 'proto', protos: [6] }, { kind: 'vlan', ids: [140] }]), 1);
    assert.equal(n([{ kind: 'exporter', ips: ['10.255.0.1'] }]), 3);
    assert.equal(n([{ kind: 'exporter', ips: ['1.1.1.1'] }]), 0);
    const lim = t.ops.searchStreams(q([], { limit: 2 }));
    assert.equal(lim.rows.length, 2); assert.equal(lim.total, 3); assert.equal(lim.truncated, true);
  } finally { t.done(); }
});

test('src filter is exact on the initiator, port filter is either direction', () => {
  const t = mk();
  try {
    t.ops.insertFlows([
      rec({ ts0: NOW - 40_000, ts1: NOW - 30_000 }),
      rec({ srcIp: '198.51.100.40', dstIp: '10.1.4.21', sport: 443, dport: 51522, ts0: NOW - 29_000, ts1: NOW - 20_000 })
    ]);
    const server = [{ lo: ipToN('198.51.100.40')!, hi: ipToN('198.51.100.40')! }];
    assert.equal(t.ops.searchStreams(q([{ kind: 'src', m: server }])).total, 0);
    assert.equal(t.ops.searchStreams(q([{ kind: 'dst', m: server }])).total, 1);
    assert.equal(t.ops.searchStreams(q([{ kind: 'port', ports: [51522] }])).total, 1);
  } finally { t.done(); }
});

test('qos changed detection (DSCP re-marked between hops or by egress policy)', () => {
  const t = mk();
  try {
    t.ops.insertFlows([
      // stream A: same dscp, no remark
      rec({ srcIp: '10.0.0.1', dstIp: '10.0.0.2', sport: 1, dport: 1, tos: 184, postTos: 184 }),
      rec({ srcIp: '10.0.0.1', dstIp: '10.0.0.2', sport: 1, dport: 1, tos: 184, postTos: 184, exporter: '10.255.0.2' }),
      // stream B: dscp differs across hops
      rec({ srcIp: '10.0.0.3', dstIp: '10.0.0.4', sport: 2, dport: 2, tos: 184, postTos: null }),
      rec({ srcIp: '10.0.0.3', dstIp: '10.0.0.4', sport: 2, dport: 2, tos: 0, postTos: null, exporter: '10.255.0.2' }),
      // stream C: egress policy remarks
      rec({ srcIp: '10.0.0.5', dstIp: '10.0.0.6', sport: 3, dport: 3, tos: 184, postTos: 0 })
    ]);
    const ch = t.ops.searchStreams(q([{ kind: 'qos', mode: 'changed' }]));
    assert.deepEqual(ch.rows.map(r => r.srcIp).sort(), ['10.0.0.3', '10.0.0.5']);
    assert.ok(ch.rows.every(r => r.qosChanged));
    const un = t.ops.searchStreams(q([{ kind: 'qos', mode: 'unchanged' }]));
    assert.deepEqual(un.rows.map(r => r.srcIp), ['10.0.0.1']);
  } finally { t.done(); }
});

test('sorting by bytes', () => {
  const t = mk();
  try {
    t.ops.insertFlows([rec({ sport: 1, bytes: 10 }), rec({ sport: 2, bytes: 300 }), rec({ sport: 3, bytes: 50 })]);
    const r = t.ops.searchStreams(q([], { sort: 'bytes', dir: 'desc' }));
    assert.deepEqual(r.rows.map(x => x.bytes), [300, 50, 10]);
    const a = t.ops.searchStreams(q([], { sort: 'bytes', dir: 'asc' }));
    assert.deepEqual(a.rows.map(x => x.bytes), [10, 50, 300]);
  } finally { t.done(); }
});

test('raw report: group, top-N with other, bidirectional combine, prefix', () => {
  const t = mk();
  try {
    t.ops.insertFlows([
      rec({ srcIp: '10.1.4.21', dstIp: '198.51.100.40', bytes: 1000, pkts: 10 }),
      rec({ srcIp: '198.51.100.40', dstIp: '10.1.4.21', sport: 443, dport: 51522, bytes: 4000, pkts: 40 }),
      rec({ srcIp: '10.1.4.22', dstIp: '198.51.100.41', sport: 1, bytes: 500, pkts: 5 }),
      rec({ srcIp: '10.2.0.1', dstIp: '198.51.100.42', sport: 2, bytes: 100, pkts: 1 })
    ]);
    const base: ReportSpec = { range, tier: 'raw', dims: ['srcIp'], prefix: 32, bidir: false, conds: [], sortBy: 'bytes', topN: 2, };
    const r = t.ops.report(base);
    assert.equal(r.rows.length, 2);
    assert.equal(r.rows[0].dims.srcIp, '198.51.100.40');
    assert.equal(r.rows[0].bytes, 4000);
    assert.equal(r.totals.bytes, 5600);
    assert.equal(r.other.bytes, 600);
    assert.equal(r.other.rows, 2);
    assert.equal(r.rows.reduce((s, x) => s + x.bytes, 0) + r.other.bytes, 5600);
    // prefix /16 collapses 10.1.x
    const p = t.ops.report({ ...base, prefix: 16, topN: 10 });
    const m = new Map(p.rows.map(x => [String(x.dims.srcIp), x.bytes]));
    assert.equal(m.get('10.1.0.0/16'), 1500);
    assert.equal(m.get('10.2.0.0/16'), 100);
    // bidir: src+dst pair combined
    const b = t.ops.report({ ...base, dims: ['srcIp', 'dstIp'], bidir: true, topN: 10 });
    const pair = b.rows.find(x => x.bytes === 5000);
    assert.ok(pair, 'combined pair should have 5000 bytes');
    assert.equal(b.rows.length, 3);
    // filter by proto
    const f = t.ops.report({ ...base, topN: 10, conds: [{ kind: 'proto', protos: [17] }] });
    assert.equal(f.rows.length, 0);
  } finally { t.done(); }
});

test('rollup tiers: 1m/1h/1d report agrees with raw', () => {
  const t = mk();
  try {
    const base = Math.floor((NOW - 3 * 24 * HOUR) / HOUR) * HOUR;
    const recs: FlowRecord[] = [];
    let total = 0;
    for (let h = 0; h < 30; h++) for (let k = 0; k < 4; k++) {
      const ts = base + h * HOUR + k * 600_000 + 5000;
      recs.push(rec({ ts0: ts - 2000, ts1: ts, srcIp: '10.1.4.' + (1 + (k % 2)), sport: 1000 + k, bytes: 100 + h, pkts: 1 }));
      total += 100 + h;
    }
    t.ops.insertFlows(recs);
    const wide = { from: base - HOUR, to: NOW };
    const rawRep = t.ops.report({ range: wide, tier: 'raw', dims: ['srcIp'], prefix: 32, bidir: false, conds: [], sortBy: 'bytes', topN: 10 });
    assert.equal(rawRep.totals.bytes, total);
    const res = t.ops.maintain(RET, NOW);
    assert.ok(Array.isArray(res.dropped));
    for (const tier of ['m1', 'h1'] as const) {
      const r = t.ops.report({ range: wide, tier, dims: ['srcIp'], prefix: 32, bidir: false, conds: [], sortBy: 'bytes', topN: 10 });
      assert.equal(r.totals.bytes, total, tier);
      assert.equal(r.totals.flows, 120, tier);
      assert.deepEqual(r.rows.map(x => [x.dims.srcIp, x.bytes]).sort(), rawRep.rows.map(x => [x.dims.srcIp, x.bytes]).sort(), tier);
    }
    // daily tier only has complete days; the sum over complete days must be <= total and > 0
    const d = t.ops.report({ range: wide, tier: 'd1', dims: ['srcIp'], prefix: 32, bidir: false, conds: [], sortBy: 'bytes', topN: 10 });
    assert.ok(d.totals.bytes > 0 && d.totals.bytes <= total);
    // idempotent
    t.ops.maintain(RET, NOW);
    const again = t.ops.report({ range: wide, tier: 'm1', dims: ['srcIp'], prefix: 32, bidir: false, conds: [], sortBy: 'bytes', topN: 10 });
    assert.equal(again.totals.bytes, total);
    const st = t.ops.stats();
    assert.equal(st.rawRows, 120); assert.ok(st.m1Rows > 0 && st.h1Rows > 0);
  } finally { t.done(); }
});

test('retention drops old raw tables and rolled rows', () => {
  const t = mk();
  try {
    const old = NOW - 10 * 24 * HOUR;
    t.ops.insertFlows([rec({ ts0: old - 1000, ts1: old, bytes: 77 }), rec({ bytes: 5 })]);
    const before = t.ops.stats();
    assert.equal(before.rawDays, 2);
    t.ops.maintain({ ...RET, raw: 7 }, NOW);
    // 1m rollup of the old record exists, then it is the only one kept (raw table is dropped)
    const after = t.ops.stats();
    assert.equal(after.rawDays, 1);
    const r = t.ops.report({ range: { from: old - HOUR, to: old + HOUR }, tier: 'm1', dims: ['srcIp'], prefix: 32, bidir: false, conds: [], sortBy: 'bytes', topN: 5 });
    assert.equal(r.totals.bytes, 77);
    t.ops.maintain({ ...RET, raw: 7, m1: 5 }, NOW);
    const r2 = t.ops.report({ range: { from: old - HOUR, to: old + HOUR }, tier: 'm1', dims: ['srcIp'], prefix: 32, bidir: false, conds: [], sortBy: 'bytes', topN: 5 });
    assert.equal(r2.totals.bytes, 0);
  } finally { t.done(); }
});

test('SNMP interface and class series, latest, hourly rollup, delete', () => {
  const t = mk();
  try {
    const ifs = [], cls = [];
    for (let i = 0; i < 20; i++) {
      const ts = NOW - (20 - i) * 60_000;
      ifs.push({ ts, dev: 1, ifIndex: 7, dt: 60, inBps: 1e6, outBps: 5e6, utilIn: 1, utilOut: 5, inDisc: 0, outDisc: i === 10 ? 40 : 0, inErr: 0, outErr: 0, oper: 1 });
      cls.push({ ts, dev: 1, ifIndex: 7, cls: 'voice', dt: 60, prePkts: 1000, preBytes: 1e6, postBytes: 1e6 - 1000, dropPkts: i === 10 ? 100 : 0, dropBytes: i === 10 ? 100000 : 0, qdepth: i });
      cls.push({ ts, dev: 1, ifIndex: 7, cls: 'bulk', dt: 60, prePkts: 1000, preBytes: 1e6, postBytes: 5e5, dropPkts: 50, dropBytes: 50000, qdepth: 3 });
    }
    t.ops.insertSnmp(ifs, cls);
    const rg = { from: NOW - 30 * 60_000, to: NOW };
    const s = t.ops.ifSeries(1, 7, rg, RET, 30);
    assert.equal(s.tier, 'raw');
    assert.equal(s.points.length, 20);
    assert.equal(s.points.reduce((a, p) => a + p.disc, 0), 40);
    const c = t.ops.classSeries(1, 7, rg, RET, 30);
    const voice = c.classes.find(x => x.cls === 'voice')!;
    const bulk = c.classes.find(x => x.cls === 'bulk')!;
    assert.ok(Math.max(...voice.points.map(p => p.dropPct)) === 10);
    assert.ok(bulk.points.every(p => Math.abs(p.dropPct - 5) < 1e-9));
    const lat = t.ops.classLatest(NOW - 3600_000);
    assert.equal(lat.length, 2);
    const lv = lat.find(x => x.cls === 'voice')!;
    assert.equal(lv.dropPkts, 100);
    assert.equal(lv.qdepth, 19);
    const il = t.ops.ifLatest(NOW - 3600_000);
    assert.equal(il.length, 1);
    assert.equal(il[0].disc, 40);
    // hourly rollup. now far in the future so the hour(s) are complete
    const future = NOW + 3 * HOUR;
    t.ops.maintain(RET, future);
    const h = t.ops.ifSeries(1, 7, { from: NOW - 30 * 24 * HOUR - HOUR, to: future }, { ...RET, sRaw: 1 }, 50);
    assert.equal(h.tier, 'h1');
    assert.equal(h.points.reduce((a, p) => a + p.disc, 0), 40);
    const hc = t.ops.classSeries(1, 7, { from: NOW - 30 * 24 * HOUR - HOUR, to: future }, { ...RET, sRaw: 1 }, 50);
    assert.ok(hc.classes.find(x => x.cls === 'bulk')!.points.every(p => Math.abs(p.dropPct - 5) < 1e-9));
    t.ops.deleteDevice(1);
    assert.equal(t.ops.ifLatest(NOW - 3600_000).length, 0);
    assert.equal(t.ops.classSeries(1, 7, rg, RET, 30).classes.length, 0);
  } finally { t.done(); }
});

import { SqliteStore } from '../src/store/sqlite.js';
test('SqliteStore facade works across worker threads', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-facade-'));
  const s = await SqliteStore.open(dir);
  try {
    await s.insertFlows([rec(), rec({ exporter: '10.255.0.2' })]);
    const r = await s.searchStreams(q());
    assert.equal(r.total, 1);
    assert.equal(r.rows[0].bytes, 1000);
    await assert.rejects(() => s.searchStreams({ ...q(), range: null as any }));
    const st = await s.stats();
    assert.equal(st.backend, 'sqlite'); assert.equal(st.ingested, 2);
    await s.maintain(RET);
  } finally { await s.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

import { FlowCollector } from '../src/collector/listener.js';
import { buildV5, buildV9, buildIpfix } from '../src/sim/packets.js';
import dgram from 'node:dgram';
test('collector receives v5, v9 and IPFIX over UDP and stores them', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-coll-'));
  const store = await SqliteStore.open(dir);
  const log = { info() {}, warn() {}, error() {} };
  const c = new FlowCollector({ bind: '127.0.0.1', ports: [0], log, ingest: store, flushMs: 50 });
  await c.start();
  try {
    const port = c.boundPorts[0];
    const sock = dgram.createSocket('udp4');
    const send = (b: Buffer) => new Promise<void>(res => sock.send(b, port, '127.0.0.1', () => res()));
    const r1 = rec({ srcIp: '10.5.0.1', sport: 1111, vlan: null, srcMac: null, dstMac: null, postTos: null, ttlMin: null, ttlMax: null });
    await send(buildV5([r1], { uptime: 7_200_000, nowMs: NOW }));
    const r2 = rec({ srcIp: '10.5.0.2', sport: 2222 });
    await send(buildV9([r2], { uptime: 7_200_000, nowMs: NOW, domain: 1 }));
    const r3 = rec({ srcIp: '10.5.0.3', sport: 3333 });
    await send(buildIpfix([r3], { nowMs: NOW, domain: 1 }));
    await send(Buffer.from('garbage-garbage-garbage-garbage'));
    for (let i = 0; i < 50 && c.stats.records < 3; i++) await new Promise(r => setTimeout(r, 40));
    await c.flush();
    sock.close();
    assert.equal(c.stats.records, 3);
    assert.ok(c.stats.errors >= 1);
    assert.equal(c.exporters.size, 1);
    const res = await store.searchStreams({ range: { from: NOW - 3600_000, to: NOW + 3600_000 }, conds: [], sort: 'time', dir: 'desc', limit: 10 });
    assert.deepEqual(res.rows.map(r => r.srcIp).sort(), ['10.5.0.1', '10.5.0.2', '10.5.0.3']);
    // disabled => discarded
    c.enabled = false;
    const s2 = dgram.createSocket('udp4');
    await new Promise<void>(res => s2.send(buildV5([r1], { uptime: 7_200_000, nowMs: NOW }), port, '127.0.0.1', () => res()));
    for (let i = 0; i < 20 && c.stats.discarded < 1; i++) await new Promise(r => setTimeout(r, 25));
    s2.close();
    assert.equal(c.stats.discarded, 1);
  } finally { await c.stop(); await store.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
