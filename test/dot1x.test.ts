import test from 'node:test';
import assert from 'node:assert/strict';
import type { SnmpValue } from '../src/snmp/client.js';
import { readPae } from '../src/snmp/dot1x.js';

const T = '1.0.8802.1.1.1.1.2.1.1';
const tables: Record<string, Record<string, SnmpValue>> = {
  [`${T}.6`]: { '1': 2, '2': 2, '3': 3, '4': 1, 'x': 2 },
  [`${T}.5`]: { '1': 1, '2': 2, '3': 1, '4': 2 }
};
test('802.1X ports: the controlled port control and status per ifIndex, with only auto meaning the port authenticates', async () => {
  const p = await readPae({ column: async (oid: string) => new Map(Object.entries(tables[oid] ?? {})) } as never);
  assert.deepEqual(p.map(x => [x.ifIndex, x.control, x.authorized]), [[1, 'auto', true], [2, 'auto', false], [3, 'force-authorized', true], [4, 'force-unauthorized', false]]);
});
