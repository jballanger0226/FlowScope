import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { SqliteOps, openTsDb, ipToN, skeyOf } from '../src/store/ops.js';
import { scenarios, rec, q, RET, NOW, type Mk } from './scenarios.js';
import type { FlowRecord } from '../src/collector/types.js';
import type { ReportSpec, StreamQuery } from '../src/store/types.js';

const sqliteMk: Mk = async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-store-'));
  const db = openTsDb({ dir });
  const ops = new SqliteOps(db, dir, true);
  const s = {
    insertFlows: async (r: FlowRecord[]) => ops.insertFlows(r),
    insertSnmp: async (a: any, b: any) => ops.insertSnmp(a, b),
    searchStreams: async (x: StreamQuery) => ops.searchStreams(x),
    streamRecords: async (k: string, r: any) => ops.streamRecords(k, r),
    report: async (x: ReportSpec) => ops.report(x),
    ifSeries: async (...a: Parameters<SqliteOps['ifSeries']>) => ops.ifSeries(...a),
    classSeries: async (...a: Parameters<SqliteOps['classSeries']>) => ops.classSeries(...a),
    classLatest: async (x: number) => ops.classLatest(x),
    ifLatest: async (x: number) => ops.ifLatest(x),
    maintain: async (r: any, n?: number) => ops.maintain(r, n),
    deleteDevice: async (d: number) => ops.deleteDevice(d),
    stats: async () => ops.stats(),
    close: async () => undefined
  };
  return { s, done: () => { db.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
};
scenarios('sqlite', sqliteMk);

test('ip helpers and canonical stream key', () => {
  assert.equal(ipToN('10.0.0.1'), 167772161);
  assert.equal(ipToN('2001:db8::1'), null);
  const a = skeyOf({ srcIp: '10.1.1.1', dstIp: '10.2.2.2', sport: 1000, dport: 443, proto: 6 });
  const b = skeyOf({ srcIp: '10.2.2.2', dstIp: '10.1.1.1', sport: 443, dport: 1000, proto: 6 });
  assert.equal(a, b);
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

test('collector drops records whose flow times are outside the accepted window', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-coll-time-'));
  const store = await SqliteStore.open(dir);
  const warnings: string[] = [];
  const log = { info() {}, warn(_s: string, m: string) { warnings.push(m); }, error() {} };
  const c = new FlowCollector({ bind: '127.0.0.1', ports: [0], log, ingest: store, flushMs: 50 });
  await c.start();
  try {
    const port = c.boundPorts[0];
    const sock = dgram.createSocket('udp4');
    const send = (b: Buffer) => new Promise<void>(res => sock.send(b, port, '127.0.0.1', () => res()));
    const good = rec({ srcIp: '10.6.0.1', sport: 1111, vlan: null, srcMac: null, dstMac: null, postTos: null, ttlMin: null, ttlMax: null });
    const epoch = rec({ srcIp: '10.6.0.2', sport: 2222, vlan: null, srcMac: null, dstMac: null, postTos: null, ttlMin: null, ttlMax: null });
    await send(buildV5([epoch], { uptime: 7_200_000, nowMs: 86_400_000 + 1000 }));   // exporter clock never set: 1970
    await send(buildV5([good], { uptime: 7_200_000, nowMs: NOW }));
    for (let i = 0; i < 50 && c.stats.records < 1; i++) await new Promise(r => setTimeout(r, 40));
    await c.flush();
    sock.close();
    assert.equal(c.stats.records, 1);
    assert.equal(c.stats.badTime, 1);
    assert.ok(warnings.some(w => /clock/.test(w)));
    const res = await store.searchStreams({ range: { from: 0, to: NOW + 3600_000 }, conds: [], sort: 'time', dir: 'desc', limit: 10 });
    assert.deepEqual(res.rows.map(r => r.srcIp), ['10.6.0.1']);
  } finally { await c.stop(); await store.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('the store refuses flow times that would create unreadable tables', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-ts-'));
  const store = await SqliteStore.open(dir);
  try {
    const base = rec({});
    await store.insertFlows([{ ...base, ts0: 1e16, ts1: 1e16 }, { ...base, ts0: Number.NaN, ts1: Number.NaN }, { ...base, ts0: 3e14, ts1: 3e14 }, base]);
    const st = await store.stats();
    assert.equal(st.ingested, 4);   // counted as received
    const res = await store.searchStreams({ range: { from: 0, to: NOW + 3600_000 }, conds: [], sort: 'time', dir: 'desc', limit: 10 });
    assert.equal(res.rows.length, 1);
  } finally { await store.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('a storage worker that dies is restarted by the next call, and the data is still there', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-respawn-'));
  const notes: string[] = [];
  const s = await SqliteStore.open(dir, m => notes.push(m));
  const kill = async (which: 'writer' | 'reader') => {
    const w = (s as unknown as Record<string, { w: { terminate(): Promise<number> } }>)[which].w;
    await w.terminate();
  };
  try {
    await s.insertFlows([rec()]);
    await kill('writer'); await kill('reader');
    // right after a crash the call is refused rather than restarting in a tight loop
    await assert.rejects(() => s.insertFlows([rec({ exporter: '10.255.0.9' })]), /storage worker (exited|is restarting)/);
    await new Promise(r => setTimeout(r, 1100));
    await s.insertFlows([rec({ exporter: '10.255.0.2' })]);
    const r = await s.searchStreams(q());
    assert.equal(r.total, 1);
    assert.ok(notes.some(n => /Restarting the writing/.test(n)) && notes.some(n => /Restarting the reading/.test(n)), notes.join(' | '));
    assert.equal((await s.stats()).ingested, 2);
  } finally { await s.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('closing a store does not restart its workers', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-close-'));
  const notes: string[] = [];
  const s = await SqliteStore.open(dir, m => notes.push(m));
  await s.close();
  await assert.rejects(() => s.stats(), /closed/);
  await assert.rejects(() => s.insertFlows([rec()]), /closed/);
  assert.deepEqual(notes, []);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a slow read on one reader does not hold up another', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-readers-'));
  const s = await SqliteStore.open(dir);
  try {
    await s.insertFlows([rec()]);
    const readers = (s as unknown as { readers: { load: number }[] }).readers;
    assert.equal(readers.length, 2);
    const many = Promise.all(Array.from({ length: 20 }, () => s.searchStreams(q())));
    assert.ok(readers[0].load > 0 && readers[1].load > 0, 'both readers were given work: ' + readers.map(r => r.load).join(','));
    for (const r of await many) assert.equal(r.total, 1);
  } finally { await s.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
