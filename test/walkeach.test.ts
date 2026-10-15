import test from 'node:test';
import assert from 'node:assert/strict';
import { SnmpClient, compareOid, type VarBind } from '../src/snmp/client.js';

/*
 * The walk is driven by GETBULK, and net-snmp hands that back as one array of varbinds per OID asked about, not as a flat list.
 * This fake session answers like net-snmp does, from a small sorted MIB, so the walk logic is tested without a device.
 */
const END = 130, NO_SUCH_INSTANCE = 129;
type Entry = [oid: string, type: number, value: unknown];
function fakeSession(mib: Entry[], o: { backwards?: boolean } = {}) {
  const sorted = [...mib].sort((a, b) => compareOid(a[0], b[0]));
  const after = (oid: string, n: number) => sorted.filter(e => compareOid(e[0], oid) > 0).slice(0, n);
  const vbOf = (e: Entry) => ({ oid: e[0], type: e[1], value: e[2] });
  const calls = { get: 0, getNext: 0, getBulk: 0 };
  return {
    calls,
    s: {
      get: (oids: string[], cb: (e: Error | null, v: unknown[]) => void) => { calls.get++; cb(null, oids.map(x => { const e = sorted.find(y => y[0] === x); return e ? vbOf(e) : { oid: x, type: NO_SUCH_INSTANCE, value: null }; })); },
      getNext: (oids: string[], cb: (e: Error | null, v: unknown[]) => void) => { calls.getNext++; const n = after(oids[0], 1); cb(null, n.length ? n.map(vbOf) : [{ oid: oids[0], type: END, value: null }]); },
      // one inner array per repeater OID, as net-snmp does
      getBulk: (oids: string[], _nonRep: number, maxRep: number, cb: (e: Error | null, v: unknown[]) => void) => {
        calls.getBulk++;
        const n = o.backwards ? [vbOf(sorted.find(e => e[0] === '1.3.6.1.2.1.1.1.0')!)] : after(oids[0], maxRep).map(vbOf);
        if (n.length < maxRep && !o.backwards) n.push({ oid: oids[0], type: END, value: null });
        cb(null, [n]);
      },
      close: () => undefined
    }
  };
}
function clientOver(f: ReturnType<typeof fakeSession>, version: 'v2c' | 'v1' = 'v2c'): SnmpClient {
  const c = new SnmpClient({ host: '127.0.0.1', port: 1, timeoutMs: 100, retries: 0 }, { version, community: 'public' });
  (c as unknown as { s: { close(): void } }).s.close();
  (c as unknown as { s: unknown }).s = f.s;
  return c;
}
const MIB: Entry[] = [
  ['1.0.8802.1.1.2.1.3.7.1.3.1', 4, Buffer.from('igb0')],
  ['1.3.6.1.2.1.1.1.0', 4, Buffer.from('OPNsense')],
  ['1.3.6.1.2.1.1.3.0', 67, 100],
  ['1.3.6.1.2.1.2.2.1.1.1', 2, 1], ['1.3.6.1.2.1.2.2.1.1.2', 2, 2], ['1.3.6.1.2.1.2.2.1.1.10', 2, 10],
  ['1.3.6.1.4.1.9.1.1', 2, 7]
];
const collect = async (c: SnmpClient, oid: string, stopAfter = Infinity) => {
  const rows: VarBind[] = [];
  const why = await c.walkEach(oid, b => { rows.push(...b); return rows.length >= stopAfter; }, 3);
  return { rows: rows.map(r => r.oid), why };
};

test('a blank OID walks everything, in OID order, across GETBULK batches', async () => {
  const f = fakeSession(MIB);
  const r = await collect(clientOver(f), '');
  assert.deepEqual(r.rows, MIB.map(e => e[0]).sort(compareOid));
  assert.equal(r.why, 'done');
  assert.ok(f.calls.getBulk >= 3);                 // 7 rows, 3 per batch
});

test('a subtree walk stops at the end of the subtree, and 2.10 sorts after 2.2', async () => {
  const r = await collect(clientOver(fakeSession(MIB)), '1.3.6.1.2.1.2.2.1.1');
  assert.deepEqual(r.rows, ['1.3.6.1.2.1.2.2.1.1.1', '1.3.6.1.2.1.2.2.1.1.2', '1.3.6.1.2.1.2.2.1.1.10']);
  assert.equal(r.why, 'done');
});

test('a leaf OID is returned as itself; an OID with nothing under it returns nothing', async () => {
  assert.deepEqual((await collect(clientOver(fakeSession(MIB)), '1.3.6.1.2.1.1.1.0')).rows, ['1.3.6.1.2.1.1.1.0']);
  assert.deepEqual((await collect(clientOver(fakeSession(MIB)), '1.3.6.1.2.1.99')).rows, []);
});

test('the caller can stop the walk', async () => {
  const r = await collect(clientOver(fakeSession(MIB)), '', 2);
  assert.equal(r.why, 'stopped'); assert.ok(r.rows.length >= 2 && r.rows.length < MIB.length + 1);
});

test('SNMPv1 walks with GETNEXT, never GETBULK', async () => {
  const f = fakeSession(MIB);
  const r = await collect(clientOver(f, 'v1'), '1.3.6.1.2.1.1');
  assert.deepEqual(r.rows, ['1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.1.3.0']);
  assert.equal(f.calls.getBulk, 0); assert.ok(f.calls.getNext >= 2);
});

test('a device that goes backwards ends the walk instead of looping', async () => {
  const r = await collect(clientOver(fakeSession(MIB, { backwards: true })), '1.3.6.1.2.1.1');
  assert.equal(r.why, 'disorder');
});
