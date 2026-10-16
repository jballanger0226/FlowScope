import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import type { SnmpClient, SnmpValue } from '../src/snmp/client.js';
import { readBfd, readEigrp, readHealth } from '../src/snmp/health.js';

/** Rows from a real walk of a Catalyst 9300 stack: two EIGRP neighbours (AS 1971) and four BFD sessions, all up. */
const FIX = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, '..', '..', 'test', 'fixtures', 'eigrp-bfd-c9300.json'), 'utf8')) as Record<string, SnmpValue>;
function agent(rows: Record<string, SnmpValue>, asked: string[] = [], asBuffers = false): SnmpClient {
  return {
    column: async (col: string) => {
      asked.push(col);
      const m = new Map<string, SnmpValue>();
      for (const [o, v] of Object.entries(rows)) if (o.startsWith(col + '.')) m.set(o.slice(col.length + 1), asBuffers && typeof v === 'string' && /^\d+\.\d+\.\d+\.\d+$/.test(v) ? Buffer.from(v.split('.').map(Number)) : v);
      return m;
    },
    get: async () => { throw new Error('no get'); }
  } as unknown as SnmpClient;
}

test('EIGRP neighbours come with their AS, interface, uptime and retransmissions', async () => {
  const p = await readEigrp(agent(FIX));
  assert.equal(p.length, 2);
  assert.deepEqual(p.map(x => [x.as, x.address, x.ifIndex, x.upText, x.level]), [[1971, '10.201.168.73', 81, '1d13h', 'ok'], [1971, '10.201.168.77', 427, '3w1d', 'ok']]);
  assert.equal(p[1]!.retrans, 15);
  assert.equal(p[1]!.srttMs, 1);
});

test('an EIGRP neighbour that is retrying the current packet is flagged', async () => {
  const rows = { ...FIX, '1.3.6.1.4.1.9.9.449.1.4.1.1.13.65536.1971.0': 3 };
  const p = await readEigrp(agent(rows));
  const bad = p.find(x => x.address === '10.201.168.77')!;
  assert.equal(bad.level, 'warn'); assert.equal(bad.retries, 3);
});

test('BFD sessions give state, peer, interface, uptime and detection time', async () => {
  const b = await readBfd(agent(FIX));
  assert.equal(b.length, 4);
  assert.ok(b.every(x => x.state === 'up' && x.level === 'ok' && x.address && x.ifIndex));
  const s = b.find(x => x.id === 393217)!;
  assert.equal(s.address, '10.201.168.78'); assert.equal(s.ifIndex, 566);
  assert.equal(s.detectMs, 1500, 'the desired transmit interval (500 ms) times the detect multiplier (3)');
  assert.equal(s.diag, null);
});

test('a BFD session that is down is bad, with the reason it last failed', async () => {
  const rows = { ...FIX, '1.3.6.1.4.1.9.10.137.1.2.1.6.393217': 2, '1.3.6.1.4.1.9.10.137.1.3.1.5.393217': 1 };
  const s = (await readBfd(agent(rows))).find(x => x.id === 393217)!;
  assert.equal(s.level, 'bad'); assert.equal(s.upSec, null); assert.equal(s.diag, 'control detection time expired');
});

test('addresses delivered as raw bytes read the same', async () => {
  assert.deepEqual(await readEigrp(agent(FIX, [], true)), await readEigrp(agent(FIX)));
  assert.deepEqual(await readBfd(agent(FIX, [], true)), await readBfd(agent(FIX)));
});

test('only Cisco devices are asked for the Cisco routing MIBs', async () => {
  const cisco: string[] = [], other: string[] = [];
  const h = await readHealth(agent(FIX, cisco), '1.3.6.1.4.1.9.1.2');
  await readHealth(agent(FIX, other), '1.3.6.1.4.1.2636.1.1');
  assert.equal(h?.eigrp?.length, 2); assert.equal(h?.bfd?.length, 4);
  assert.ok(cisco.some(c => c.startsWith('1.3.6.1.4.1.9.9.449')));
  assert.ok(!other.some(c => c.startsWith('1.3.6.1.4.1.9.9.449') || c.startsWith('1.3.6.1.4.1.9.10.137')));
});
