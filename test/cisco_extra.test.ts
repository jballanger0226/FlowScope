import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import type { SnmpClient, SnmpValue } from '../src/snmp/client.js';
import { daiReason, readDai, readNbar, readProcesses, readStack } from '../src/snmp/cisco_extra.js';

/** Rows from a real walk of a Catalyst 9300 stack: processes, the 8-member stack, ARP inspection of three VLANs and NBAR2 statistics of one interface. */
const FIX = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, '..', '..', 'test', 'fixtures', 'cisco-extra-c9300.json'), 'utf8')) as Record<string, SnmpValue>;
const MAC = '1.3.6.1.4.1.9.9.500.1.2.1.1.7.';
function agent(rows: Record<string, SnmpValue>): SnmpClient {
  const val = (o: string, v: SnmpValue): SnmpValue => (o.startsWith(MAC) && typeof v === 'string' ? Buffer.from(v, 'hex') : v);
  return {
    column: async (col: string) => { const m = new Map<string, SnmpValue>(); for (const [o, v] of Object.entries(rows)) if (o.startsWith(col + '.')) m.set(o.slice(col.length + 1), val(o, v)); return m; },
    get: async (oids: string[]) => { const m = new Map<string, { oid: string; value: SnmpValue }>(); for (const o of oids) if (o in rows) m.set(o, { oid: o, value: rows[o]! }); return m; }
  } as unknown as SnmpClient;
}

test('processes are listed busiest first, and the same process on several members is shown once', async () => {
  const p = (await readProcesses(agent(FIX), 5))!;
  assert.ok(p.top.length >= 2);
  assert.deepEqual(p.top.map(x => x.one), [...p.top.map(x => x.one)].sort((a, b) => b - a));
  assert.equal(new Set(p.top.map(x => x.name)).size, p.top.length);
  assert.equal(p.top.find(x => x.name === 'linux_iosd-imag')!.one, 69, 'the busiest of the two members, not their sum');
  assert.equal(p.snmpOne, null);
});

test('the SNMP engine is picked out so polling load can be seen', async () => {
  const rows = { ...FIX, '1.3.6.1.4.1.9.9.109.1.2.1.1.2.19.9999': 'SNMP ENGINE', '1.3.6.1.4.1.9.9.109.1.2.2.1.5.19.9999': 18, '1.3.6.1.4.1.9.9.109.1.2.2.1.6.19.9999': 12, '1.3.6.1.4.1.9.9.109.1.2.2.1.7.19.9999': 7 };
  const p = (await readProcesses(agent(rows), 5))!;
  assert.equal(p.snmpFive, 18); assert.equal(p.snmpOne, 12);
});

test('a healthy eight-member stack reports every member ready and every stack port up', async () => {
  const s = (await readStack(agent(FIX), 5))!;
  assert.equal(s.members.length, 8); assert.equal(s.ports.length, 16);
  assert.equal(s.members.filter(m => m.role === 'master').length, 1);
  assert.ok(s.members.every(m => m.state === 'ready' && m.mac.length === 17));
  assert.deepEqual(s.problems, []);
});

test('a stack port that is down, or a member that is not ready, is a problem in plain words', async () => {
  const rows = { ...FIX, '1.3.6.1.4.1.9.9.500.1.2.2.1.1.88': 2, '1.3.6.1.4.1.9.9.500.1.2.1.1.6.3000': 2 };
  const s = (await readStack(agent(rows), 5))!;
  assert.equal(s.problems.length, 2);
  assert.match(s.problems[0]!, /1 stack port is not up\. The stack ring is broken/);
  assert.match(s.problems[1]!, /Stack member 3 is progressing/);
});

test('ARP inspection lists only VLANs that dropped packets, with the reason', async () => {
  const d = (await readDai(agent(FIX), null, 1000))!;
  assert.deepEqual(d.vlans.map(v => v.vlan), [1236]);
  const v = d.vlans[0]!;
  assert.equal(v.dropped, 555705); assert.equal(v.dhcpDenied, 555705); assert.equal(v.droppedNow, null, 'no earlier read to compare with');
  assert.match(daiReason(v), /555,705 had no matching DHCP snooping binding/);
});

test('drops since the previous read are reported, and a reset counter gives no figure', async () => {
  const first = (await readDai(agent(FIX), null, 1000))!;
  const rows = { ...FIX, '1.3.6.1.4.1.9.9.374.1.4.1.1.3.1236': 555705 + 40, '1.3.6.1.4.1.9.9.374.1.4.1.1.3.2': 7 };
  const second = (await readDai(agent(rows), first, 301_000))!;
  assert.equal(second.dtSec, 300);
  assert.equal(second.vlans.find(v => v.vlan === 1236)!.droppedNow, 40);
  assert.equal(second.vlans.find(v => v.vlan === 2)!.droppedNow, 7, 'a VLAN not listed before had nothing dropped then');
  const reset = (await readDai(agent({ ...FIX, '1.3.6.1.4.1.9.9.374.1.4.1.1.3.1236': 5 }), first, 301_000))!;
  assert.equal(reset.vlans[0]!.droppedNow, null);
});

test('NBAR2 gives the applications seen on an interface, busiest first, without empty ones', async () => {
  const n = (await readNbar(agent(FIX), 5))!;
  const list = n.interfaces[9]!;
  assert.ok(list.length > 1 && list.length <= 8);
  assert.ok(list.every(x => x.inBytes + x.outBytes > 0));
  assert.ok(list.every(x => x.inBps === null && x.outBps === null), 'no rate from a single read');
  assert.ok(list.some(x => x.name === 'http'));
  assert.equal(await readNbar(agent({}), 5), null);
});

test('NBAR2 rates come from the byte counters between two reads, not the device rate column', async () => {
  const first = (await readNbar(agent(FIX), 1_000))!;
  const ssl = first.interfaces[9]!.find(x => x.name === 'ssl')!;
  // 300 seconds later 3,750,000 more bytes arrived and 750,000 left: 100 kbps in, 20 kbps out. The device's own rate column says 0 here.
  const later: Record<string, SnmpValue> = { ...FIX };
  for (const k of Object.keys(FIX)) if (k.startsWith('1.3.6.1.4.1.9.9.244.1.2.1.1.2.9.') && FIX[k] === 'ssl') {
    const id = k.split('.').pop();
    later[`1.3.6.1.4.1.9.9.244.1.2.1.1.9.9.${id}`] = ssl.inBytes + 3_750_000; later[`1.3.6.1.4.1.9.9.244.1.2.1.1.10.9.${id}`] = ssl.outBytes + 750_000;
  }
  const n = (await readNbar(agent(later), 301_000, first))!;
  const x = n.interfaces[9]!.find(y => y.name === 'ssl')!;
  assert.equal(x.inBps, 100_000);
  assert.equal(x.outBps, 20_000);
  assert.equal(n.interfaces[9]![0]!.name, 'ssl', 'the busiest by rate comes first');
});
