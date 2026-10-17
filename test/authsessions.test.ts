import test from 'node:test';
import assert from 'node:assert/strict';
import type { SnmpValue } from '../src/snmp/client.js';
import { readAuthSessions } from '../src/snmp/authsessions.js';

// rows as the C9500 SDA edge returned them: index is ifIndex.<session id as ASCII bytes>
const sid = (s: string) => [...s].map(c => c.charCodeAt(0)).join('.');
const A = `9.${sid('10300A0A000016B41F555247')}`, B = `90.${sid('10300A0A00000031110DBB04')}`, C = `11.${sid('10300A0A000016AB1F50746E')}`;
const T = '1.3.6.1.4.1.9.9.656.1.4.1.1';
const tables: Record<string, Record<string, SnmpValue>> = {
  [`${T}.2`]: { [A]: Buffer.from([0x00, 0x18, 0x85, 0x5d, 0x2b, 0xc9]), [B]: Buffer.from([0x24, 0x78, 0x23, 0x69, 0xd7, 0x1e]), [C]: Buffer.from([1, 2, 3]) },
  [`${T}.4`]: { [A]: Buffer.from([10, 135, 159, 187]), [B]: Buffer.from([0, 0, 0, 0]) },
  [`${T}.14`]: { [A]: 3074, [B]: 0 },
  [`${T}.10`]: { [A]: Buffer.from('IT-Camera') }, [`${T}.22`]: { [A]: Buffer.from('DEVICE_CAMERA') }
};
const client = { column: async (oid: string) => new Map(Object.entries(tables[oid] ?? {})) } as never;

test('authentication sessions give each client its port, address and the VLAN the server assigned (0 when none), and a malformed MAC is skipped', async () => {
  const s = await readAuthSessions(client);
  assert.equal(s.length, 2);
  assert.deepEqual(s.find(x => x.ifIndex === 9), { ifIndex: 9, mac: '00:18:85:5d:2b:c9', ip: '10.135.159.187', vlan: 3074, policy: 'IT-Camera', profile: 'DEVICE_CAMERA' });
  assert.deepEqual(s.find(x => x.ifIndex === 90), { ifIndex: 90, mac: '24:78:23:69:d7:1e', ip: '', vlan: 0, policy: '', profile: '' });
});
