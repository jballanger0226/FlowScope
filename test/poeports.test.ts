import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readPoePorts } from '../src/snmp/poeports.js';
import type { SnmpClient, SnmpValue } from '../src/snmp/client.js';

test('per-port PoE: reserved and drawn power mapped to the ifIndex through ENTITY-MIB', async () => {
  const T = '1.3.6.1.4.1.9.9.402.1.2.1';
  const cols: Record<string, [string, SnmpValue][]> = {
    [`${T}.7`]: [['1.1', 30000], ['1.2', 15400]], [`${T}.9`]: [['1.1', 6252], ['1.2', 0]], [`${T}.6`]: [['1.1', 90000], ['1.2', 90000]], [`${T}.3`]: [['1.1', 1], ['1.2', 2]], [`${T}.11`]: [['1.1', 1062], ['1.2', 1063]],
    '1.3.6.1.2.1.47.1.3.2.1.2': [['1062.0', '1.3.6.1.2.1.2.2.1.1.9'], ['1063.0', '1.3.6.1.2.1.2.2.1.1.10']]
  };
  const c = { column: async (oid: string) => new Map(cols[oid] ?? []) } as unknown as SnmpClient;
  const r = await readPoePorts(c);
  assert.deepEqual(r, [{ ifIndex: 9, allocW: 30, drawnW: 6.3, maxW: 90, detected: true }, { ifIndex: 10, allocW: 15.4, drawnW: 0, maxW: 90, detected: false }]);
  assert.deepEqual(await readPoePorts({ column: async () => new Map() } as unknown as SnmpClient), []);
});
