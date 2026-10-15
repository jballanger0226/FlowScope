import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ConfigDb } from '../src/db/configdb.js';
import { diffExtra, type IfExtra } from '../src/snmp/health.js';
import { forgetIfExtra, ifExtraSeries, pruneIfExtra, recordIfExtra } from '../src/snmp/iface_history.js';

const read = (at: number, t: Record<string, number>): IfExtra => ({ duplex: 'full', admin: 1, delta: null, dtSec: null, readAt: at, totals: t });
const db = () => new ConfigDb(fs.mkdtempSync(path.join(os.tmpdir(), 'fs-ih-')));

test('counter changes between reads are stored and served as rates per second', () => {
  const cdb = db(); const now = Date.now(); const m = 60_000;
  let prev: IfExtra | undefined;
  for (let i = 10; i >= 0; i--) {
    const cur = diffExtra(prev, read(now - i * 3 * m, { inBc: 1000 * (10 - i) * 180, fcs: i === 5 ? 500 : 500 - (i > 5 ? 0 : 0), inErr: 7 }));
    prev = cur; recordIfExtra(cdb.db, 1, 3, cur);
  }
  const s = ifExtraSeries(cdb.db, 1, 3, now - 40 * m, now, 40, now);
  assert.equal(s.tier, 'raw');
  assert.equal(s.points.length, 10, 'the first read has nothing to compare with');
  assert.ok(s.points.every(p => p.inBc === 1000), 'each interval grew by 1000 packets a second');
  assert.equal(s.points[0].inErr, 0); assert.equal(s.points[0].outBc, undefined, 'a counter the device does not publish stays absent');
  assert.equal(ifExtraSeries(cdb.db, 1, 4, now - 40 * m, now, 40, now).points.length, 0);
  assert.equal(ifExtraSeries(cdb.db, 2, 3, now - 40 * m, now, 40, now).points.length, 0);
});

test('a counter that went backwards gives no figure, and older readings are summed by the hour', () => {
  const cdb = db(); const now = Date.now(); const old = Math.floor((now - 6 * 86_400_000) / 3_600_000) * 3_600_000 + 60_000;
  let prev: IfExtra | undefined;
  const reads = [100, 400, 50, 350];
  reads.forEach((v, i) => { const cur = diffExtra(prev, read(old + i * 180_000, { inMc: v })); prev = cur; recordIfExtra(cdb.db, 1, 1, cur); });
  const h = ifExtraSeries(cdb.db, 1, 1, old - 3_600_000, old + 3_600_000, 50, now);
  assert.equal(h.tier, 'h1'); assert.equal(h.points.length, 1);
  assert.equal(h.points[0].inMc, 1.667, 'two intervals of 300 packets over 360 seconds; the reset interval is skipped');
  pruneIfExtra(cdb.db, 3, now);
  assert.equal(ifExtraSeries(cdb.db, 1, 1, old - 3_600_000, old + 3_600_000, 50, now).points.length, 0);
});

test('forgetting a device removes its counter history', () => {
  const cdb = db(); const now = Date.now();
  recordIfExtra(cdb.db, 1, 1, diffExtra(read(now - 180_000, { fcs: 1 }), read(now, { fcs: 5 })));
  assert.equal(ifExtraSeries(cdb.db, 1, 1, now - 600_000, now + 1, 10, now).points.length, 1);
  forgetIfExtra(cdb.db, 1);
  assert.equal(ifExtraSeries(cdb.db, 1, 1, now - 600_000, now + 1, 10, now).points.length, 0);
});
