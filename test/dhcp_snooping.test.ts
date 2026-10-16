import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import type { SnmpClient, SnmpValue } from '../src/snmp/client.js';
import { readDhcpBindings } from '../src/snmp/dhcp_snooping.js';

/** Rows from a real walk of a Catalyst 9300 stack (CISCO-DHCP-SNOOPING-MIB cdsBindingsTable): 12 of its 319 bindings. */
const FIX = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, '..', '..', 'test', 'fixtures', 'dhcp-c9300.json'), 'utf8')) as Record<string, SnmpValue>;
function agent(rows: Record<string, SnmpValue>, asBuffers = false): SnmpClient {
  return { column: async (col: string) => {
    const m = new Map<string, SnmpValue>();
    for (const [o, v] of Object.entries(rows)) if (o.startsWith(col + '.')) m.set(o.slice(col.length + 1), asBuffers && col.endsWith('.4') && typeof v === 'string' ? Buffer.from(v.split('.').map(Number)) : v);
    return m;
  } } as unknown as SnmpClient;
}

test('bindings give the MAC and VLAN from the row index, and the address, port and lease from the columns', async () => {
  const b = await readDhcpBindings(agent(FIX));
  assert.equal(b.length, 12);
  const one = b.find(x => x.mac === '00:60:74:e5:6e:bd')!;
  assert.ok(one);
  assert.deepEqual({ vlan: one.vlan, ip: one.ip, ifIndex: one.ifIndex, leaseSec: one.leaseSec }, { vlan: 1236, ip: '10.236.205.115', ifIndex: 549, leaseSec: 654411 });
});

test('addresses delivered as raw bytes read the same', async () => {
  assert.deepEqual(await readDhcpBindings(agent(FIX, true)), await readDhcpBindings(agent(FIX)));
});

test('bindings that are not active are left out, and a missing status column keeps them', async () => {
  const rows: Record<string, SnmpValue> = { ...FIX };
  const key = Object.keys(FIX).find(k => k.startsWith('1.3.6.1.4.1.9.9.380.1.4.1.1.7.'))!;
  rows[key] = 2;
  assert.equal((await readDhcpBindings(agent(rows))).length, 11);
  const noStatus = Object.fromEntries(Object.entries(FIX).filter(([k]) => !k.startsWith('1.3.6.1.4.1.9.9.380.1.4.1.1.7.')));
  assert.equal((await readDhcpBindings(agent(noStatus))).length, 12);
});

test('a switch without the table, or with malformed indexes, gives an empty list', async () => {
  assert.deepEqual(await readDhcpBindings(agent({})), []);
  assert.deepEqual(await readDhcpBindings(agent({ '1.3.6.1.4.1.9.9.380.1.4.1.1.4.1236.1.2.3': '10.0.0.1' })), []);
  assert.deepEqual(await readDhcpBindings(agent({ '1.3.6.1.4.1.9.9.380.1.4.1.1.4.1236.0.96.116.229.110.999': '10.0.0.1' })), []);
});
