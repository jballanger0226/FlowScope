import test from 'node:test';
import assert from 'node:assert/strict';
import type { SnmpValue } from '../src/snmp/client.js';
import { parseSgtIndex, readSgt } from '../src/snmp/sgt.js';

const T = '1.3.6.1.4.1.9.9.713.1.4.1.1', N = '1.3.6.1.4.1.9.9.730.1.4.16.1.4';
// indexes and values as the C9300 SD-Access edge returned them
const DEV = '6.68.69.86.73.67.69.1.4.10.135.159.203.32', DFLT = '0.1.4.10.10.168.104.32', SUBNET = '6.68.69.86.73.67.69.1.4.10.135.0.0.16';
const tables: Record<string, Record<string, SnmpValue>> = {
  [`${T}.5`]: { [DEV]: 74, [DFLT]: 2, [SUBNET]: 74, '9.1.2': 5 },
  [`${T}.6`]: { [DEV]: 3, [DFLT]: 5 },
  [N]: { '74': Buffer.from('DEVICE_CAMERA'), '2': Buffer.from('TrustSec_Devices') }
};
test('security group tags: the VRF and address come from the index, only host bindings count, and tag names are read', async () => {
  assert.deepEqual(parseSgtIndex(DEV), { vrf: 'DEVICE', ip: '10.135.159.203', prefix: 32 });
  assert.deepEqual(parseSgtIndex(DFLT), { vrf: '', ip: '10.10.168.104', prefix: 32 });
  assert.equal(parseSgtIndex('9.1.2'), null);
  const r = await readSgt({ column: async (oid: string) => new Map(Object.entries(tables[oid] ?? {})) } as never);
  assert.deepEqual(r.bindings, [{ vrf: 'DEVICE', ip: '10.135.159.203', sgt: 74, source: 'authenticated' }, { vrf: '', ip: '10.10.168.104', sgt: 2, source: 'internal' }]);
  assert.equal(r.names.get(74), 'DEVICE_CAMERA');
});
