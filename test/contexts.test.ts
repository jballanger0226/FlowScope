import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readContexts, nameFromIndex } from '../src/snmp/contexts.js';
import type { SnmpClient, SnmpValue } from '../src/snmp/client.js';

test('SNMP contexts from the Cisco context mapping table, falling back to the standard one', async () => {
  assert.equal(nameFromIndex('7.118.114.102.45.80.67.73'), 'vrf-PCI');
  assert.equal(nameFromIndex('3.1'), null);
  const make = (cols: Record<string, [string, SnmpValue][]>) => ({ column: async (o: string) => new Map(cols[o] ?? []) }) as unknown as SnmpClient;
  assert.deepEqual(await readContexts(make({ '1.3.6.1.4.1.9.9.468.1.1.1.2': [['8.118.114.102.45.85.83.69.82', 'USER'], ['7.118.114.102.45.80.67.73', 'PCI']] })), [{ name: 'vrf-PCI', vrf: 'PCI' }, { name: 'vrf-USER', vrf: 'USER' }]);
  assert.deepEqual(await readContexts(make({ '1.3.6.1.6.3.16.1.1.1.1': [['0', ''], ['3.97.98.99', 'x']] })), [{ name: 'abc', vrf: '' }]);
});
