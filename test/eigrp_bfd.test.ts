import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import type { SnmpClient, SnmpValue } from '../src/snmp/client.js';
import { p2pPeer, readBfd, readEigrp, readHealth } from '../src/snmp/health.js';

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

test('BFD sessions are listed once, with the neighbour and interface as `show bfd neighbors` gives them', async () => {
  const b = await readBfd(agent(FIX));
  // the walk lists each session twice (two clients registered it); the device itself shows two neighbours
  assert.equal(b.length, 2);
  assert.deepEqual(b.map(x => [x.address, x.local, x.ifIndex, x.state, x.level]), [['10.201.168.73', '10.201.168.74', 81, 'up', 'ok'], ['10.201.168.77', '10.201.168.78', 427, 'up', 'ok']]);
  assert.equal(b[1]!.detectMs, 1500, 'the desired transmit interval (500 ms) times the detect multiplier (3)');
  assert.equal(b[1]!.diag, null);
});

test('the other end of a /30 or /31, and nothing for wider subnets', () => {
  assert.equal(p2pPeer('10.201.168.74', '255.255.255.252'), '10.201.168.73');
  assert.equal(p2pPeer('10.201.168.77', '255.255.255.252'), '10.201.168.78');
  assert.equal(p2pPeer('10.0.0.1', '255.255.255.254'), '10.0.0.0');
  assert.equal(p2pPeer('10.0.0.1', '255.255.255.0'), null);
  assert.equal(p2pPeer('10.0.0.1', null), null);
});

test('a session whose subnet is wider shows this end instead of a guess; one that is down wins over its duplicate', async () => {
  const rows = { ...FIX, '1.3.6.1.2.1.4.20.1.3.10.201.168.78': '255.255.255.0', '1.3.6.1.4.1.9.10.137.1.2.1.6.983041': 2, '1.3.6.1.4.1.9.10.137.1.3.1.5.983041': 1 };
  const b = await readBfd(agent(rows));
  const s = b.find(x => x.local === '10.201.168.78')!;
  assert.equal(s.peerKnown, false); assert.equal(s.address, '10.201.168.78');
  assert.equal(s.level, 'bad'); assert.equal(s.diag, 'control detection time expired'); assert.equal(s.upSec, null);
});

test('addresses delivered as raw bytes read the same', async () => {
  assert.deepEqual(await readEigrp(agent(FIX, [], true)), await readEigrp(agent(FIX)));
  assert.deepEqual(await readBfd(agent(FIX, [], true)), await readBfd(agent(FIX)));
});

test('only Cisco devices are asked for the Cisco routing MIBs', async () => {
  const cisco: string[] = [], other: string[] = [];
  const h = await readHealth(agent(FIX, cisco), '1.3.6.1.4.1.9.1.2');
  await readHealth(agent(FIX, other), '1.3.6.1.4.1.2636.1.1');
  assert.equal(h?.eigrp?.length, 2); assert.equal(h?.bfd?.length, 2);
  assert.ok(cisco.some(c => c.startsWith('1.3.6.1.4.1.9.9.449')));
  assert.ok(!other.some(c => c.startsWith('1.3.6.1.4.1.9.9.449') || c.startsWith('1.3.6.1.4.1.9.10.137')));
});
