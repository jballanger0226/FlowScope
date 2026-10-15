import test from 'node:test';
import assert from 'node:assert/strict';
import type { SnmpClient, SnmpValue } from '../src/snmp/client.js';
import { discoverQos } from '../src/snmp/collect.js';
import { diffservPointer, diffservSource, juniperIndex, juniperSource } from '../src/snmp/qos_vendors.js';

function agent(rows: Record<string, SnmpValue>): SnmpClient {
  const column = async (col: string) => {
    const m = new Map<string, SnmpValue>();
    for (const [o, v] of Object.entries(rows)) if (o.startsWith(col + '.')) m.set(o.slice(col.length + 1), v);
    return m;
  };
  return { column, get: async () => new Map() } as unknown as SnmpClient;
}
const enc = (s: string, prefix = true) => (prefix ? [s.length] : []).concat([...s].map(c => c.charCodeAt(0))).join('.');
const J = (col: number) => `1.3.6.1.4.1.2636.3.15.1.1.${col}`;

test('Juniper CoS row indexes, with and without the length of the class name', () => {
  assert.deepEqual(juniperIndex(`5.${enc('best-effort')}`), { ifIndex: 5, fc: 'best-effort' });
  assert.deepEqual(juniperIndex(`5.${enc('ef', false)}`), { ifIndex: 5, fc: 'ef' });
  assert.equal(juniperIndex('5'), null);
});

test('Juniper CoS queues become classes with their counters, leaving out classes that carried nothing', async () => {
  const be = `5.${enc('best-effort')}`, ef = `5.${enc('expedited-forwarding')}`, nc = `5.${enc('network-control')}`;
  const rows: Record<string, SnmpValue> = {
    [`${J(3)}.${be}`]: 1000n, [`${J(5)}.${be}`]: 1_500_000n, [`${J(9)}.${be}`]: 1_400_000n, [`${J(11)}.${be}`]: 30n, [`${J(13)}.${be}`]: 20n, [`${J(23)}.${be}`]: 30_000n,
    [`${J(3)}.${ef}`]: 50n, [`${J(5)}.${ef}`]: 8000n, [`${J(9)}.${ef}`]: 8000n, [`${J(11)}.${ef}`]: 0n, [`${J(13)}.${ef}`]: 0n, [`${J(23)}.${ef}`]: 0n,
    [`${J(3)}.${nc}`]: 0n
  };
  const c = agent(rows);
  const pols = await juniperSource.read(c);
  assert.equal(pols.length, 1);
  assert.equal(pols[0].ifIndex, 5); assert.equal(pols[0].direction, 'output');
  assert.deepEqual(pols[0].classes.map(k => k.name), ['best-effort', 'expedited-forwarding'], 'the idle class is left out');
  const q = await juniperSource.poll(c, pols);
  const be1 = q.classes.get(`${pols[0].policyIdx}.1`)!;
  assert.equal(be1.pre, 1000n); assert.equal(be1.drop, 50n, 'tail drops and RED drops together'); assert.equal(be1.dropB, 30_000n); assert.equal(be1.postB, 1_400_000n);
  assert.equal(q.wide, true);
});

test('DIFFSERV row pointers name a table and a row', () => {
  assert.deepEqual(diffservPointer('1.3.6.1.2.1.97.1.2.2.1.1.10'), { table: 'clfr', row: '10' });
  assert.deepEqual(diffservPointer('.1.3.6.1.2.1.97.1.3.2.1.1.3'), { table: 'meter', row: '3' });
  assert.equal(diffservPointer('0.0'), null);
  assert.equal(diffservPointer('1.3.6.1.4.1.9.9.1.1.1'), null);
});

test('DIFFSERV data path walks classifier, meter, counter and drop elements', async () => {
  const P = (t: string, id: number) => `1.3.6.1.2.1.97.1.${t}.1.1.${id}`;
  const rows: Record<string, SnmpValue> = {
    '1.3.6.1.2.1.97.1.1.1.1.2.7.2': P('2.2', 10),                       // interface 7, outbound, starts at classifier 10
    '1.3.6.1.2.1.97.1.2.4.1.3.10.1': P('3.2', 3),                       // element 10.1 goes to meter 3
    '1.3.6.1.2.1.97.1.2.4.1.3.10.2': P('5.5', 5),                       // element 10.2 goes straight to counter 5
    '1.3.6.1.2.1.97.1.3.2.1.2.3': P('5.5', 4), '1.3.6.1.2.1.97.1.3.2.1.3.3': P('6.2', 9), // in profile to counter 4, out of profile to dropper 9
    '1.3.6.1.2.1.97.1.5.5.1.2.4': 9000n, '1.3.6.1.2.1.97.1.5.5.1.3.4': 90n,
    '1.3.6.1.2.1.97.1.5.5.1.2.5': 500n, '1.3.6.1.2.1.97.1.5.5.1.3.5': 5n,
    '1.3.6.1.2.1.97.1.6.2.1.7.9': 1000n, '1.3.6.1.2.1.97.1.6.2.1.8.9': 10n
  };
  const c = agent(rows);
  const pols = await diffservSource.read(c);
  assert.equal(pols.length, 1);
  assert.equal(pols[0].ifIndex, 7); assert.equal(pols[0].direction, 'output');
  assert.deepEqual(pols[0].classes.map(k => k.name), ['class 10.1', 'class 10.2']);
  const q = await diffservSource.poll(c, pols);
  const a = q.classes.get(`${pols[0].policyIdx}.1`)!, b = q.classes.get(`${pols[0].policyIdx}.2`)!;
  assert.equal(a.drop, 10n); assert.equal(a.dropB, 1000n); assert.equal(a.pre, 90n, 'the counter was before the dropper');
  assert.equal(b.pre, 5n); assert.equal(b.drop, 0n);
  // a pointer loop does not hang the walk
  const loop = agent({ '1.3.6.1.2.1.97.1.1.1.1.2.1.1': P('2.2', 1), '1.3.6.1.2.1.97.1.2.4.1.3.1.1': P('3.2', 1), '1.3.6.1.2.1.97.1.3.2.1.2.1': P('3.2', 1), '1.3.6.1.2.1.97.1.3.2.1.3.1': P('3.2', 1) });
  assert.deepEqual(await diffservSource.read(loop), []);
});

test('discovery picks the first MIB that has queues, and says what it looked for when none does', async () => {
  const jrows: Record<string, SnmpValue> = { [`${J(3)}.5.${enc('be')}`]: 10n };
  const j = await discoverQos(agent(jrows), '1.3.6.1.4.1.2636.1.1.1.2.5', [{ index: 5 }]);
  assert.equal(j.profile, 'juniper-cos'); assert.match(j.note, /Junos CoS/);
  const none = await discoverQos(agent({}), '1.3.6.1.4.1.30065.1.3011', [{ index: 1 }]);
  assert.equal(none.profile, 'generic'); assert.match(none.note, /DIFFSERV-MIB was looked for/);
  const jnone = await discoverQos(agent({}), '1.3.6.1.4.1.2636.1.1.1.2.5', [{ index: 1 }]);
  assert.match(jnone.note, /Juniper CoS and DIFFSERV-MIB/);
  const ds = await discoverQos(agent({ '1.3.6.1.2.1.97.1.1.1.1.2.7.2': '1.3.6.1.2.1.97.1.2.2.1.1.10', '1.3.6.1.2.1.97.1.2.4.1.3.10.1': '1.3.6.1.2.1.97.1.5.5.1.1.5', '1.3.6.1.2.1.97.1.5.5.1.3.5': 1n }), '1.3.6.1.4.1.1916.2.1', [{ index: 7 }]);
  assert.equal(ds.profile, 'diffserv');
});
