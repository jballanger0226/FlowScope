import test from 'node:test';
import assert from 'node:assert/strict';
import type { SnmpValue } from '../src/snmp/client.js';
import { parseEidIndex, rlocOf, readLisp } from '../src/snmp/lisp.js';
import { registrationCheck, conversations, byRloc } from '../src/analysis/lispcheck.js';

const L = '1.3.6.1.2.1.220.1';
// indexes as the Catalyst 9300 SD-Access edge returned them (instance 4097 is the default VRF, 4102 is MEDIA)
const E = (ip: string, pfx: number, iid = '0.16.1') => `14.14.64.3.10.2.${iid}.0.1.${ip}.${pfx}`;
const HOST = E('10.6.128.16', 32), NEG = E('10.6.128.0', 19), GONE = E('10.6.128.17', 32), REG1 = E('10.6.128.1', 32), REG2 = E('10.6.149.17', 32), MEDIA = E('10.7.1.9', 32, '0.16.6');
const RLOC = '8.8.0.1.4.10.10.160.221.32', MAC = '16.16.64.3.12.2.0.32.1.0.6.0.0.12.159.254.27.48';
const tables = (cache: string[], extra: Record<string, Record<string, SnmpValue>> = {}): Record<string, Record<string, SnmpValue>> => ({
  [`${L}.6.1.5`]: Object.fromEntries(cache.map(i => [i, i === NEG || i === GONE ? 2 : 1])), [`${L}.6.1.6`]: Object.fromEntries(cache.map(i => [i, 1])),
  [`${L}.6.1.3`]: Object.fromEntries(cache.map(i => [i, 937361])),
  [`${L}.7.1.7`]: { [`${HOST}.${RLOC}`]: 1 }, [`${L}.7.1.3`]: { [`${HOST}.${RLOC}`]: 10 }, [`${L}.7.1.4`]: { [`${HOST}.${RLOC}`]: 10 },
  [`${L}.4.1.3`]: { [REG1]: 1, [REG2]: 1, [GONE]: 1, [MAC]: 1 }, [`${L}.4.1.5`]: { [REG1]: 53, [REG2]: 53, [GONE]: 53, [MAC]: 53 },
  [`${L}.1.1.9`]: { '4097.1': 171, '4102.1': 41 }, [`${L}.1.1.10`]: { '4097.1': 40448, '4102.1': 40448 }, [`${L}.1.1.4`]: { '4097.1': 1 },
  [`${L}.3.1.2`]: { '4097.1': 5424, '4102.1': 6341 }, [`${L}.3.1.3`]: { '4097.1': 4081, '4102.1': 6226 }, [`${L}.3.1.6`]: { '4097.1': 282 },
  [`${L}.2.1.1`]: { '4097': Buffer.from('default'), '4102': Buffer.from('MEDIA') },
  [`${L}.12.1.3`]: { [E('10.10.10.7', 32)]: 1, [E('10.10.20.7', 32)]: 1 }, [`${L}.13.1.3`]: { [E('10.10.10.7', 32)]: 1 },
  ...extra
});
const fake = (t: Record<string, Record<string, SnmpValue>>) => ({
  column: async (oid: string) => new Map(Object.entries(t[oid] ?? {})),
  get: async () => new Map([['1.3.6.1.2.1.1.3.0', { oid: '', value: 956460 }]])
}) as never;

test('LISP indexes: instance ID, address and prefix come out of the LCAF encoding, and an RLOC after it', () => {
  assert.deepEqual(parseEidIndex(HOST), { iid: 4097, kind: 'ip', eid: '10.6.128.16', prefix: 32, rest: [] });
  assert.equal(parseEidIndex(E('10.7.1.9', 32, '0.16.6'))!.iid, 4102);
  assert.deepEqual(parseEidIndex(MAC), { iid: 8193, kind: 'mac', eid: '00:00:0c:9f:fe:1b', prefix: 48, rest: [] });
  assert.equal(rlocOf(parseEidIndex(`${HOST}.${RLOC}`)!.rest), '10.10.160.221');
  assert.equal(parseEidIndex('1.2.3'), null);
});

test('LISP read: cache entries with their RLOC, a negative entry has none, registrations, instances with their VRF, and server state', async () => {
  const l = (await readLisp(fake(tables([HOST, NEG, GONE])), null, 1000))!;
  assert.equal(l.cacheTotal, 3);
  const h1 = l.cache.find(e => e.eid === '10.6.128.16')!;
  assert.deepEqual([h1.active, h1.rlocs[0]!.rloc, h1.rlocs[0]!.priority, h1.ageSec], [true, '10.10.160.221', 10, 191]);   // (956460 - 937361) ticks of 10 ms
  assert.deepEqual([l.cache.find(e => e.prefix === 19)!.rlocs.length, l.cache.find(e => e.prefix === 19)!.active], [0, false]);
  assert.equal(l.registered.length, 4); assert.equal(l.registered.filter(r => r.kind === 'mac').length, 1);
  assert.deepEqual(l.instances.map(i => [i.iid, i.vrf, i.cacheSize]), [[4097, '', 171], [4102, 'MEDIA', 41]]);
  assert.deepEqual([l.mapServers.total, l.mapServers.down.length, l.mapResolvers.total], [2, 0, 1]);
  assert.equal(l.level, 'ok');
});

test('LISP churn: entries added and removed since the last read, a sudden loss and a dead map server are reported', async () => {
  const many = Array.from({ length: 60 }, (_, i) => E(`10.6.130.${i}`, 32));
  const first = (await readLisp(fake(tables(many)), null, 1000))!;
  const next = (await readLisp(fake(tables([...many.slice(0, 55), E('10.6.131.1', 32)])), first, 301_000))!;
  const p = next.history[next.history.length - 1]!; assert.deepEqual([p.cache, p.added, p.removed], [56, 1, 5]);
  const gone = (await readLisp(fake(tables(many.slice(0, 20), { [`${L}.12.1.3`]: { [E('10.10.10.7', 32)]: 1, [E('10.10.20.7', 32)]: 2 } })), first, 601_000))!;
  assert.equal(gone.history[gone.history.length - 1]!.removed, 40);
  assert.match(gone.problems.join(' '), /lost 40 of 60/); assert.match(gone.problems.join(' '), /1 of 2 map servers/); assert.equal(gone.level, 'warn');
  const dead = (await readLisp(fake(tables([HOST], { [`${L}.12.1.3`]: { [E('10.10.10.7', 32)]: 2 } })), null, 1))!; assert.equal(dead.level, 'bad');
  // map requests with no replies
  const first2 = (await readLisp(fake(tables([HOST])), null, 1))!;
  const noReply = (await readLisp(fake(tables([HOST], { [`${L}.3.1.2`]: { '4097.1': 5440, '4102.1': 6341 } })), first2, 2))!;
  assert.match(noReply.problems.join(' '), /sent 16 map requests since the last read and got no reply/);
});

test('LISP registration check: authenticated hosts that are not registered come first, own addresses and young registrations are left out', async () => {
  const l = (await readLisp(fake(tables([HOST, MEDIA])), null, 1000))!;
  const hosts = [
    { ip: '10.6.128.1', vrf: '', mac: 'aa:aa:aa:aa:aa:01', ifIndex: 5, lastSeen: 1, auth: false, user: '' },       // registered
    { ip: '10.6.150.44', vrf: '', mac: 'aa:aa:aa:aa:aa:02', ifIndex: 6, lastSeen: 1, auth: true, user: 'cam-01' },  // authenticated, not registered
    { ip: '10.6.150.45', vrf: '', mac: 'aa:aa:aa:aa:aa:03', ifIndex: 7, lastSeen: 1, auth: false, user: '' },      // seen, not registered
    { ip: '10.6.128.254', vrf: '', mac: 'aa:aa:aa:aa:aa:04', ifIndex: 8, lastSeen: 1, auth: false, user: '' }      // the node's own address
  ];
  const r = registrationCheck(l, hosts, new Set(['10.6.128.254']));
  assert.deepEqual(r.missing.map(m => [m.ip, m.authenticated, m.user]), [['10.6.150.44', true, 'cam-01'], ['10.6.150.45', false, '']]);
  assert.equal(r.matched, 1);
  assert.deepEqual(r.stale.map(s => s.ip).sort(), ['10.6.128.17', '10.6.149.17']);   // both registered since the node started 2.6 hours ago
  assert.equal(r.macEids, 1);
});

test('LISP conversations: only entries in use, the host and the fabric node behind them, volume from flows, border for a negative entry', async () => {
  const l = (await readLisp(fake(tables([HOST, NEG, MEDIA])), null, 1000))!;
  const c = conversations(l, ip => (ip === '10.6.128.16' ? { mac: 'aa:aa:aa:aa:aa:09', user: 'badge-7', sgt: { value: 74, name: 'DEVICE_CAMERA' } } : null), r => (r === '10.10.160.221' ? 'EDGE-C' : ''), new Map([['10.6.128.16', { bytes: 5000, flows: 3 }]]));
  assert.equal(c.length, 2);   // the /19 is not a host and is not in use
  assert.deepEqual([c[0]!.ip, c[0]!.rlocName, c[0]!.user, c[0]!.sgt!.value, c[0]!.bytes], ['10.6.128.16', 'EDGE-C', 'badge-7', 74, 5000]);
  assert.deepEqual([c[1]!.ip, c[1]!.viaBorder, c[1]!.vrf], ['10.7.1.9', true, 'MEDIA']);
  assert.deepEqual(byRloc(l, () => 'EDGE-C'), [{ rloc: '10.10.160.221', name: 'EDGE-C', active: 1, total: 1 }]);
});
