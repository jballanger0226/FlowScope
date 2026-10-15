import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ConfigDb } from '../src/db/configdb.js';
import { apAsResources, forgetResources, pruneResources, recordResources, resourceSeries } from '../src/snmp/resource_history.js';
import type { Resources } from '../src/snmp/resources.js';

const res = (readAt: number, cpu: number, mem: number, up: number, disk = 40): Resources => ({
  uptimeSec: up, cpuPct: cpu, cores: null, load: [cpu / 10, 0, 0], memPct: mem, memTotal: null, memUsed: null, swapPct: null,
  disks: [{ name: '/', usedPct: disk, totalBytes: 1, usedBytes: 1 }], source: 't', readAt
});

function db() { const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-rh-')); return new ConfigDb(dir); }

test('readings are bucketed with the average and the peak, and a lower uptime is a restart', () => {
  const cdb = db(); const now = Date.now(); const m = 60_000;
  // 10 minutes of readings, a CPU spike in the middle, and a restart 4 minutes ago
  for (let i = 10; i >= 1; i--) recordResources(cdb.db, 1, res(now - i * m, i === 5 ? 90 : 10, 50, i > 4 ? 100_000 + (10 - i) * 60 : (4 - i) * 60 + 30));
  const s = resourceSeries(cdb.db, 1, now - 15 * m, now, 15, now);
  assert.equal(s.tier, 'raw');
  assert.equal(s.step, 60_000);
  assert.equal(s.points.length, 10);
  assert.equal(Math.max(...s.points.map(p => p.cpuMax ?? 0)), 90);
  assert.equal(s.restarts.length, 1);
  assert.ok(Math.abs(s.restarts[0] - (now - 4 * m)) < 2 * m, 'restart is placed near when it happened');
  // a wider step averages the readings and keeps the peak
  const wide = resourceSeries(cdb.db, 1, now - 15 * m, now, 1, now);
  assert.ok(wide.points.length <= 2);
  assert.equal(Math.max(...wide.points.map(p => p.cpuMax ?? 0)), 90);
  assert.ok(wide.points.every(p => p.cpu! < 90));
});

test('readings a few seconds apart are one reading, and a device with nothing to report adds nothing', () => {
  const cdb = db(); const now = Date.now();
  recordResources(cdb.db, 1, res(now, 5, 5, 10)); recordResources(cdb.db, 1, res(now + 3000, 6, 6, 13));
  assert.equal((cdb.db.prepare('SELECT COUNT(*) AS n FROM resource_samples').get() as any).n, 1);
  recordResources(cdb.db, 2, { ...res(now, 0, 0, 10), cpuPct: null, memPct: null, load: null, disks: [] });
  assert.equal((cdb.db.prepare('SELECT COUNT(*) AS n FROM resource_samples WHERE dev_id = 2').get() as any).n, 0);
});

test('old ranges come from the hourly summary, which keeps peaks, and pruning drops what has aged out', () => {
  const cdb = db(); const now = Date.now(); const d = 86_400_000;
  // five days ago, one hour with a spike; the raw tier only keeps three days
  const t0 = Math.floor((now - 5 * d) / 3_600_000) * 3_600_000;
  for (let i = 0; i < 30; i++) recordResources(cdb.db, 1, res(t0 + i * 60_000, i === 7 ? 95 : 20, 60, 1000 + i * 60));
  pruneResources(cdb.db, 395, now);
  assert.equal((cdb.db.prepare('SELECT COUNT(*) AS n FROM resource_samples').get() as any).n, 0, 'raw readings older than three days are gone');
  const s = resourceSeries(cdb.db, 1, now - 7 * d, now, 100, now);
  assert.equal(s.tier, 'h1');
  assert.equal(s.points.length, 1);
  assert.equal(s.points[0].cpuMax, 95);
  assert.ok(s.points[0].cpu! > 20 && s.points[0].cpu! < 30);
  pruneResources(cdb.db, 2, now);
  assert.equal(resourceSeries(cdb.db, 1, now - 7 * d, now, 100, now).points.length, 0);
  forgetResources(cdb.db, 1);
});

test('temperature and sessions are kept, and a device without them has none rather than zero', () => {
  const cdb = db(); const now = Date.now(); const m = 60_000;
  for (let i = 5; i >= 1; i--) recordResources(cdb.db, 1, { ...res(now - i * m, 10, 40, 1000 + i), tempC: 40 + i, sessions: 1000 * i });
  for (let i = 5; i >= 1; i--) recordResources(cdb.db, 2, res(now - i * m, 10, 40, 1000 + i));
  const a = resourceSeries(cdb.db, 1, now - 10 * m, now, 10, now);
  assert.equal(Math.max(...a.points.map(p => p.tempMax ?? 0)), 45); assert.equal(Math.max(...a.points.map(p => p.sessMax ?? 0)), 5000);
  const b = resourceSeries(cdb.db, 2, now - 10 * m, now, 10, now);
  assert.ok(b.points.every(p => p.temp === null && p.sess === null));
  // the hourly tier too
  const old = Math.floor((now - 5 * 86_400_000) / 3_600_000) * 3_600_000;
  for (let i = 0; i < 4; i++) { recordResources(cdb.db, 1, { ...res(old + i * m, 10, 40, 100 + i), tempC: 50 + i, sessions: 10 + i }); recordResources(cdb.db, 2, res(old + i * m, 10, 40, 100 + i)); }
  const h1 = resourceSeries(cdb.db, 1, now - 7 * 86_400_000, now - 4 * 86_400_000, 50, now), h2 = resourceSeries(cdb.db, 2, now - 7 * 86_400_000, now - 4 * 86_400_000, 50, now);
  assert.equal(h1.points[0].tempMax, 53); assert.equal(h1.points[0].sessMax, 13);
  assert.equal(h2.points[0].tempMax, null); assert.equal(h2.points[0].sessMax, null); assert.equal(h2.points[0].temp, null);
});

test('each access point of a device keeps its own history, apart from the device and from the others', () => {
  const cdb = db(); const now = Date.now(); const m = 60_000;
  const ap = (cpu: number, free: number) => apAsResources({ cpuPct: cpu, memFree: free, memTotal: 1000, uptimeSec: 500 }, 0);
  for (let i = 5; i >= 1; i--) {
    recordResources(cdb.db, 1, res(now - i * m, 10, 40, 1000 + i));
    recordResources(cdb.db, 1, { ...ap(30 + i, 400), readAt: now - i * m }, 'aa:01');
    recordResources(cdb.db, 1, { ...ap(60, 200), readAt: now - i * m }, 'aa:02');
  }
  const dev = resourceSeries(cdb.db, 1, now - 10 * m, now, 10, now), a1 = resourceSeries(cdb.db, 1, now - 10 * m, now, 10, now, 'aa:01'), a2 = resourceSeries(cdb.db, 1, now - 10 * m, now, 10, now, 'aa:02');
  assert.equal(dev.points.length, 5); assert.equal(dev.points[0].cpu, 10);
  assert.equal(a1.points.length, 5); assert.equal(a1.points[0].cpu, 35); assert.equal(a1.points[0].mem, 60);
  assert.equal(a2.points[0].cpu, 60); assert.equal(a2.points[0].mem, 80);
  assert.equal(resourceSeries(cdb.db, 1, now - 10 * m, now, 10, now, 'aa:03').points.length, 0);
  assert.deepEqual(apAsResources({ cpuPct: -1, memFree: 0, memTotal: 0, uptimeSec: 0 }, 5), { uptimeSec: null, cpuPct: null, cores: null, load: null, memPct: null, memTotal: null, memUsed: null, swapPct: null, disks: [], source: '', readAt: 5 });
  forgetResources(cdb.db, 1);
  assert.equal(resourceSeries(cdb.db, 1, now - 10 * m, now, 10, now, 'aa:01').points.length, 0);
});

test('history stored before access points had their own survives the migration as the device history', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-rh-')); const a = new ConfigDb(dir); const now = Date.now();
  recordResources(a.db, 4, res(now - 60_000, 12, 34, 100)); a.db.close();
  const b = new ConfigDb(dir);
  assert.equal(resourceSeries(b.db, 4, now - 600_000, now, 10, now).points[0].cpu, 12);
});
