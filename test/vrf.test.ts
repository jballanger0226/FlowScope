import test from 'node:test';
import assert from 'node:assert/strict';
import type { SnmpClient, SnmpValue } from '../src/snmp/client.js';
import { readMulticast } from '../src/snmp/multicast.js';
import { parseVrfIndex, readVrfs, contextOf } from '../src/snmp/vrf.js';
import { underlayMap } from '../src/snmp/underlay.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ConfigDb } from '../src/db/configdb.js';
import { DeviceService } from '../src/snmp/devices.js';

function agent(rows: Record<string, SnmpValue>): SnmpClient {
  const column = async (col: string) => {
    const m = new Map<string, SnmpValue>();
    for (const [o, v] of Object.entries(rows)) if (o.startsWith(col + '.')) m.set(o.slice(col.length + 1), v);
    return m;
  };
  return { column } as unknown as SnmpClient;
}

test('a VRF name and interface are taken from the MPLS-L3VPN index', () => {
  assert.deepEqual(parseVrfIndex('3.80.67.73.433'), { name: 'PCI', ifIndex: 433 });
  assert.deepEqual(parseVrfIndex('5.77.69.68.73.65.312'), { name: 'MEDIA', ifIndex: 312 });
  assert.equal(parseVrfIndex('3.80.67.433'), null, 'a length that does not fit the index');
  assert.equal(parseVrfIndex('3.80.67.73'), null);
  assert.equal(parseVrfIndex('0.5'), null);
});

test('VRFs are listed with their interfaces', async () => {
  const B = '1.3.6.1.2.1.10.166.11.1.2.1.1.2';
  const v = await readVrfs(agent({ [`${B}.3.80.67.73.433`]: 2, [`${B}.3.80.67.73.434`]: 2, [`${B}.4.85.83.69.82.436`]: 2 }));
  assert.deepEqual(v, [{ name: 'PCI', ifIndexes: [433, 434] }, { name: 'USER', ifIndexes: [436] }]);
  assert.equal(await readVrfs(agent({})), null);
  assert.equal(contextOf('MEDIA'), 'vrf-MEDIA');
});

// two sources of 239.202.29.2: one on this switch (sent into the fabric in underlay group 232.0.2.19), one arriving from the fabric
const R = '1.3.6.1.2.1.83.1.1.2.1', N = '1.3.6.1.2.1.83.1.1.3.1';
const local = '239.202.29.2.10.133.47.240.255.255.255.255', remote = '239.202.29.2.10.245.201.253.255.255.255.255';
const FIXVRF: Record<string, SnmpValue> = {
  [`${R}.5.${local}`]: 3035, [`${R}.5.${remote}`]: 312,
  [`${N}.6.${local}.335.232.0.2.19`]: 2, [`${N}.11.${local}.335.232.0.2.19`]: 185142,
  [`${N}.6.${remote}.3035.239.202.29.2`]: 2, [`${N}.11.${remote}.3035.239.202.29.2`]: 90
};

test('a LISP outgoing interface whose next hop is a 232 group names the underlay group; an ordinary one does not', async () => {
  const m = (await readMulticast(agent(FIXVRF), 1, false))!;
  const l = m.routes.find(r => r.source === '10.133.47.240')!, r = m.routes.find(r => r.source === '10.245.201.253')!;
  assert.equal(l.oifs[0]!.underlay, '232.0.2.19');
  assert.equal(r.oifs[0]!.underlay, undefined);
});

test('an overlay group is paired with its underlay group, and the pairing is read both ways', async () => {
  const mc = (await readMulticast(agent(FIXVRF), 1, false))!;
  const u = underlayMap([{ name: 'MEDIA', mc }]);
  assert.equal(u.forward.get('MEDIA|239.202.29.2'), '232.0.2.19');
  assert.deepEqual(u.reverse.get('232.0.2.19'), [{ vrf: 'MEDIA', group: '239.202.29.2' }]);
  assert.equal(u.forward.get('MEDIA|239.1.1.1'), undefined);
});

test('hosts that joined are kept per VRF, and a read of one VRF does not drop the hosts of another', () => {
  const cdb = new ConfigDb(fs.mkdtempSync(path.join(os.tmpdir(), 'vrf-')));
  const devs = new DeviceService(cdb, { list: () => [] } as never, {} as never, {} as never);
  const now = Date.now();
  devs.noteIgmp(1, [{ group: '239.202.29.2', ifIndex: 3035, reporter: '10.245.1.5' }], now, true, 'MEDIA');
  devs.noteIgmp(1, [{ group: '224.0.1.129', ifIndex: 99, reporter: '10.9.9.9' }], now, true);
  assert.deepEqual(devs.mcastMembers(1, 'MEDIA').map(x => x.ip), ['10.245.1.5'], 'the default read, complete, left the VRF host alone');
  assert.deepEqual(devs.mcastMembers(1).map(x => x.ip), ['10.9.9.9']);
  devs.noteIgmp(1, [], now, true, 'MEDIA');
  assert.equal(devs.mcastMembers(1, 'MEDIA').length, 0, 'a complete read of the VRF with the group gone removes it');
  assert.equal(devs.mcastMembers(1).length, 1);
});
