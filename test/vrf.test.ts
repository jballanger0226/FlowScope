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

import { vlanVrfMap, ifaceVrf } from '../src/snmp/vrfmap.js';
test('a port and its hosts are in the VRF of the SVI of their VLAN; a trunk is in the VRFs of the VLANs it carries', () => {
  const names: Record<number, string> = { 312: 'Vl3035', 313: 'Vlan3036', 400: 'Gi1/0/1', 500: 'Vl1' };
  const by = vlanVrfMap([{ name: 'MEDIA', ifIndexes: [312, 400] }, { name: 'PCI', ifIndexes: [313] }], ix => names[ix] ?? '');
  assert.deepEqual([...by], [[3035, 'MEDIA'], [3036, 'PCI']], 'a routed port in a VRF is not a VLAN interface');
  const direct = new Map([[312, 'MEDIA'], [400, 'MEDIA'], [313, 'PCI']]);
  const P = (o: Partial<{ ifIndex: number; portMode: string; vlan: number; voiceVlan: number; vlanList: string }>) => ({ ifIndex: 9, portMode: 'access', vlan: 0, voiceVlan: 0, vlanList: '', ...o });
  assert.deepEqual(ifaceVrf(P({ vlan: 3035 }), direct, by), { vrf: 'MEDIA', via: 'vlan' });
  assert.deepEqual(ifaceVrf(P({ vlan: 3035, voiceVlan: 3036 }), direct, by), { vrf: 'MEDIA, PCI', via: 'vlan' });
  assert.deepEqual(ifaceVrf(P({ ifIndex: 312, portMode: 'svi', vlan: 3035 }), direct, by), { vrf: 'MEDIA', via: 'interface' });
  assert.deepEqual(ifaceVrf(P({ ifIndex: 400, portMode: 'routed' }), direct, by), { vrf: 'MEDIA', via: 'interface' }, 'a routed port can be in a VRF itself');
  assert.deepEqual(ifaceVrf(P({ portMode: 'trunk', vlan: 1, vlanList: '3030-3040,3100' }), direct, by), { vrf: 'MEDIA, PCI', via: 'vlans' });
  assert.equal(ifaceVrf(P({ vlan: 77 }), direct, by), null, 'a VLAN with no SVI in a VRF is the default VRF');
});
