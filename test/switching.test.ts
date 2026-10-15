import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { VirtualDevice, type SimDevice } from '../src/sim/snmpagent.js';
import { SnmpClient, type SnmpValue } from '../src/snmp/client.js';
import { probe } from '../src/snmp/collect.js';
import { OID } from '../src/snmp/oids.js';
import {
  bitmapVlans, compressVlans, isVlanInterface, readArp, readFdb, readNeighbors, readPortVlans, sviVlan, vlanListHas, type Walker
} from '../src/snmp/ports.js';
import { HostTracker } from '../src/snmp/hosts.js';
import { ConfigDb } from '../src/db/configdb.js';
import { Secrets } from '../src/secrets.js';
import { Settings } from '../src/settings.js';
import { AppLog } from '../src/logger.js';
import { CredentialStore } from '../src/snmp/creds.js';
import { DeviceService } from '../src/snmp/devices.js';
import { SqliteStore } from '../src/store/sqlite.js';
import { analyzeStream, isMulticast } from '../src/analysis/hops.js';
import type { FlowRecord } from '../src/collector/types.js';

/** A table of OID -> (index suffix -> value). Reading an OID that is not listed gives an empty column; one listed as `null` fails like an unanswered request. */
function fake(tables: Record<string, Record<string, SnmpValue> | null>): Walker {
  return {
    async column(oid: string) {
      const t = tables[oid];
      if (t === null) throw new Error('no response');
      return new Map(Object.entries(t ?? {}));
    }
  };
}
const bitmap = (vlans: number[], base = 0): Buffer => {
  const b = Buffer.alloc(128);
  for (const v of vlans) { const n = v - base; if (n >= 0 && n < 1024) b[n >> 3] |= 0x80 >> (n & 7); }
  return b;
};
const mac = (s: string) => Buffer.from(s.split(':').map(x => parseInt(x, 16)));
const idx = (m: string) => m.split(':').map(x => parseInt(x, 16)).join('.');

test('VLAN list helpers', () => {
  assert.equal(compressVlans([140, 141, 142, 150, 1, 3]), '1,3,140-142,150');
  assert.equal(compressVlans([]), '');
  assert.ok(vlanListHas('1,3,140-142,150', 141));
  assert.ok(!vlanListHas('1,3,140-142,150', 143));
  assert.ok(vlanListHas('all', 99));
  assert.deepEqual(bitmapVlans(bitmap([1, 140, 4093].filter(v => v < 1024)), 0), [1, 140]);
  assert.deepEqual(bitmapVlans(bitmap([2048 + 5], 2048), 2048), [2053]);
});

test('VLAN and SVI interfaces are recognised by name, type and mode', () => {
  for (const n of ['Vlan140', 'Vl140', 'vlan 140', 'BDI140', 'irb.140', 'Vlan-interface140']) assert.equal(sviVlan(n), 140, n);
  assert.equal(sviVlan('Vlan0'), null);
  assert.equal(sviVlan('Gi1/0/1'), null);
  assert.equal(sviVlan('Vlan5000'), null);
  assert.ok(isVlanInterface({ name: 'Vl140' }));
  assert.ok(isVlanInterface({ name: 'Vlan140' }));
  assert.ok(isVlanInterface({ name: 'ae0.100', ifType: 53 }));
  assert.ok(isVlanInterface({ name: 'x', portMode: 'svi' }));
  assert.ok(!isVlanInterface({ name: 'Gi1/0/1', ifType: 6, portMode: 'access' }));
  assert.ok(!isVlanInterface({ name: 'Port-channel1', ifType: 161 }));
  assert.ok(isVlanInterface({ name: 'Te1/0/1.140', ifType: 135 }), 'an L2 VLAN sub-interface (ifType 135) is a VLAN interface');
});

test('port VLANs: Cisco access with voice VLAN, trunk with allowed list, SVI, Q-BRIDGE fallback and routed ports', async () => {
  const w = fake({
    [OID.vmVlan]: { '1': 140, '2': 150 },
    [OID.vmVoiceVlanId]: { '1': 160, '2': 4096 },
    [OID.vlanTrunkPortDynamicStatus]: { '3': 1, '4': 2 },
    [OID.vlanTrunkPortNativeVlan]: { '3': 1 },
    [OID.vlanTrunkPortVlansEnabled]: { '3': bitmap([1, 140, 141, 150]) },
    [OID.dot1qPvid]: { '1': 1, '9': 77 },
    [OID.dot1dBasePortIfIndex]: { '1': 5, '9': 6 }
  });
  const ifs = [
    { index: 1, name: 'Gi1/0/1' }, { index: 2, name: 'Gi1/0/2' }, { index: 3, name: 'Te1/0/49' }, { index: 4, name: 'Gi1/0/4' },
    { index: 5, name: 'Vlan140' }, { index: 6, name: 'eth9' }, { index: 7, name: 'Gi0/0' }, { index: 8, name: 'Lo0' }
  ];
  const r = await readPortVlans(w, ifs, [{ ifIndex: 7 }]);
  assert.deepEqual(r.get(1), { mode: 'access', vlan: 140, voice: 160, allowed: '' });
  assert.deepEqual(r.get(2), { mode: 'access', vlan: 150, voice: 0, allowed: '' }, 'a voice VLAN outside 1-4094 is ignored');
  assert.deepEqual(r.get(3), { mode: 'trunk', vlan: 1, voice: 0, allowed: '1,140-141,150' });
  assert.equal(r.get(4), undefined, 'a non-trunk port with no VLAN information has no VLAN');
  assert.deepEqual(r.get(5), { mode: 'svi', vlan: 140, voice: 0, allowed: '' });
  assert.deepEqual(r.get(6), { mode: 'pvid', vlan: 77, voice: 0, allowed: '' }, 'the standard port VLAN id is mapped through dot1dBasePortIfIndex');
  assert.equal(r.get(7)?.mode, 'routed');
  assert.equal(r.get(8), undefined);
});

test('neighbours: LLDP capabilities and CDP platform decide whether a port is an uplink', async () => {
  const w = fake({
    [OID.lldpRemSysName]: { '0.7.1': 'core-rtr-01', '0.8.1': 'SEP0050', '0.9.1': 'ap-4f', '0.99.1': 'ghost' },
    [OID.lldpRemSysCapEnabled]: { '0.7.1': Buffer.from([0x28]), '0.8.1': Buffer.from([0x24]), '0.9.1': Buffer.from([0x01]), '0.99.1': Buffer.from([0x28]) },
    [OID.lldpRemPortDesc]: { '0.7.1': 'Te0/0/0' },
    [OID.cdpCacheDeviceId]: { '11.1': 'dist-sw-02.example.net(FDO1234)', '12.1': 'SEP00505601' },
    [OID.cdpCacheDevicePort]: { '11.1': 'Te1/1/1' },
    [OID.cdpCachePlatform]: { '11.1': 'cisco WS-C9300X-48HX', '12.1': 'Cisco IP Phone 8851' },
    [OID.cdpCacheCapabilities]: { '11.1': Buffer.from([0, 0, 0, 0x28]), '12.1': Buffer.from([0, 0, 0, 0x90]) },
    [OID.cdpCacheAddress]: { '11.1': Buffer.from([10, 255, 0, 3]) }
  });
  const ifs = [7, 8, 9, 11, 12].map(i => ({ index: i, name: 'p' + i }));
  const n = await readNeighbors(w, ifs);
  const by = (proto: string, ifx: number) => n.find(x => x.proto === proto && x.ifIndex === ifx)!;
  assert.equal(by('lldp', 7).kind, 'infra');
  assert.equal(by('lldp', 7).name, 'core-rtr-01');
  assert.equal(by('lldp', 7).port, 'Te0/0/0');
  assert.equal(by('lldp', 8).kind, 'phone', 'a phone that also reports bridge is still a phone, not an uplink');
  assert.equal(by('lldp', 9).kind, 'host');
  assert.equal(n.find(x => x.name === 'ghost'), undefined, 'a neighbour on a port that is not an interface is skipped');
  assert.equal(by('cdp', 11).kind, 'infra');
  assert.equal(by('cdp', 11).name, 'dist-sw-02.example.net');
  assert.equal(by('cdp', 11).ip, '10.255.0.3');
  assert.equal(by('cdp', 12).kind, 'phone');
});

test('neighbours: the LLDP local port number is mapped through the local port table, not read as an ifIndex (Catalyst)', async () => {
  // Port numbers 1..N overlap real ifIndexes: LLDP port 44 is Gi1/0/44 even though ifIndex 44 is another interface
  const w = fake({
    [OID.lldpRemSysName]: { '0.44.1': 'RAP', '0.46.1': 'AP', '0.3.1': 'nomatch' },
    [OID.lldpRemPortId]: { '0.44.1': 'aa', '0.46.1': 'bb', '0.3.1': 'cc' },
    [OID.lldpLocPortId]: { '44': 'Gi1/0/44', '46': 'Gi1/0/46', '3': 'Gi9/9/9' },
    [OID.lldpLocPortDesc]: { '44': 'GigabitEthernet1/0/44', '46': 'GigabitEthernet1/0/46', '3': 'Gi9/9/9' }
  });
  const ifs = [{ index: 37, name: 'Gi1/0/37' }, { index: 44, name: 'Gi1/0/50' }, { index: 3, name: 'Gi1/0/3' }, { index: 10144, name: 'Gi1/0/44', descr: 'GigabitEthernet1/0/44' }, { index: 10146, name: 'Gi1/0/46', descr: 'GigabitEthernet1/0/46' }];
  const n = await readNeighbors(w, ifs);
  assert.equal(n.find(x => x.name === 'RAP')?.ifIndex, 10144);
  assert.equal(n.find(x => x.name === 'AP')?.ifIndex, 10146);
  assert.equal(n.find(x => x.name === 'nomatch'), undefined, 'a port the local table names but that matches no interface is not guessed from the number');
});

test('ARP: ipNetToPhysical for IPv4 and IPv6, falling back to ipNetToMedia', async () => {
  const v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
  const w = fake({
    [OID.ipNetToPhysicalPhysAddress]: {
      '4.1.4.10.1.4.21': mac('00:50:56:01:04:15'),
      ['4.2.16.' + v6.join('.')]: mac('00:50:56:01:04:16'),
      '4.1.4.10.1.4.99': mac('00:00:00:00:00:00'),
      '4.1.4.10.1.4.98': mac('00:50:56:01:04:98'),
      '4.2.16.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.1': mac('00:50:56:01:04:17')
    },
    [OID.ipNetToPhysicalType]: { '4.1.4.10.1.4.98': 2 }
  });
  const a = await readArp(w);
  assert.deepEqual(a.map(x => x.ip).sort(), ['10.1.4.21', '2001:db8::1']);
  assert.equal(a.find(x => x.ip === '10.1.4.21')!.mac, '00:50:56:01:04:15');
  assert.equal(a[0].ifIndex, 4);
  const old = await readArp(fake({ [OID.ipNetToMediaPhysAddress]: { '4.10.1.4.21': mac('00:50:56:01:04:15'), '4.10.1.4.22': mac('00:50:56:01:04:16') }, [OID.ipNetToMediaType]: { '4.10.1.4.22': 2 } }));
  assert.deepEqual(old.map(x => x.ip), ['10.1.4.21']);
});

test('MAC table: Q-BRIDGE reports every VLAN at once', async () => {
  const w = fake({
    [OID.dot1dBasePortIfIndex]: { '1': 10001, '2': 10002 },
    [OID.dot1qTpFdbPort]: { ['140.' + idx('00:50:56:01:04:15')]: 1, ['150.' + idx('00:50:56:01:07:58')]: 2, ['140.' + idx('00:00:00:00:00:00')]: 1 },
    [OID.dot1qTpFdbStatus]: { ['140.' + idx('00:50:56:01:04:15')]: 3, ['150.' + idx('00:50:56:01:07:58')]: 3 }
  });
  const r = await readFdb(w, { cisco: true, vlans: [140, 150] });
  assert.equal(r.method, 'Q-BRIDGE-MIB');
  assert.deepEqual(r.entries.map(e => [e.mac, e.vlan, e.ifIndex]).sort(), [['00:50:56:01:04:15', 140, 10001], ['00:50:56:01:07:58', 150, 10002]]);
});

test('MAC table: a Cisco Catalyst is read one VLAN at a time through the VLAN community or context', async () => {
  const asked: number[] = [];
  const perVlan: Record<number, Record<string, SnmpValue>> = {
    140: { [idx('00:50:56:01:04:15')]: 3, [idx('00:50:56:01:04:16')]: 4 },
    150: { [idx('00:50:56:01:07:58')]: 3 }
  };
  const base = fake({ [OID.dot1dTpFdbPort]: {} });
  const forVlan = (v: number): Walker => {
    asked.push(v);
    return {
      async column(oid: string) {
        if (v === 999) throw new Error('timeout');
        if (oid === OID.dot1dBasePortIfIndex) return new Map<string, SnmpValue>([['3', 10003], ['4', 10004]]);
        if (oid === OID.dot1dTpFdbPort) return new Map(Object.entries(perVlan[v] ?? {}));
        return new Map();
      }
    };
  };
  const r = await readFdb(base, { cisco: true, vlans: [140, 150, 999], forVlan });
  assert.equal(r.method, 'BRIDGE-MIB per VLAN');
  assert.deepEqual(r.entries.map(e => [e.mac, e.vlan, e.ifIndex]).sort(), [['00:50:56:01:04:15', 140, 10003], ['00:50:56:01:04:16', 140, 10004], ['00:50:56:01:07:58', 150, 10003]]);
  assert.equal(r.vlansFailed, 1, 'a VLAN that cannot be read is counted, not mistaken for an empty one');
  assert.deepEqual(asked.sort((a, b) => a - b), [140, 150, 999]);
});

test('MAC table: when no VLAN community answers, reading stops early instead of timing out for every VLAN', async () => {
  let asked = 0;
  const forVlan = (): Walker => { asked++; return { async column() { throw new Error('timeout'); } }; };
  const r = await readFdb(fake({}), { cisco: true, vlans: Array.from({ length: 60 }, (_, i) => 100 + i), forVlan, concurrency: 1 });
  assert.equal(r.entries.length, 0);
  assert.ok(asked <= 4, `asked ${asked} VLANs`);
  assert.ok(r.vlansFailed >= 3);
});

test('MAC table: a switch that is not Cisco falls back to the plain bridge table', async () => {
  const w = fake({ [OID.dot1dTpFdbPort]: { [idx('00:50:56:01:04:15')]: 5 }, [OID.dot1dBasePortIfIndex]: { '5': 25 } });
  const r = await readFdb(w, { cisco: false, vlans: [] });
  assert.equal(r.method, 'BRIDGE-MIB');
  assert.deepEqual(r.entries, [{ mac: '00:50:56:01:04:15', vlan: 0, ifIndex: 25 }]);
});

/* ------------------------------------------------------------------ a simulated switch, end to end */

const MAC_A = '00:50:56:01:04:15', MAC_PHONE = '00:50:56:01:08:15', MAC_C = '00:50:56:09:00:05', MAC_D = '00:50:56:01:04:33';

function switchSpec(port: number): SimDevice {
  const iface = (index: number, name: string, speedMbps = 1000) => ({ index, name, speedMbps, inBps: 1e6, outBps: 1e6 });
  return {
    name: 'acc-sw-01', descr: 'Cisco IOS XE Catalyst 9300X', objectId: '1.3.6.1.4.1.9.1.2000', address: '127.0.0.1', port,
    ifaces: [iface(1, 'Gi1/0/1'), iface(2, 'Gi1/0/2'), iface(3, 'Te1/1/1', 10000), iface(4, 'Vl140', 10000)],
    ips: [{ ip: '10.1.4.1', ifIndex: 4 }], vlans: [{ id: 140, name: 'CAMPUS-USERS' }, { id: 160, name: 'CAMPUS-VOICE' }],
    qos: [
      { ifIndex: 1, policy: 'ACCESS-IN', direction: 'input', ifType: 6, classes: [{ name: 'voice', dscps: [46], queue: '', bw: '', pps: 100, pktBytes: 200, dropPct: 0, qBytes: 0 }] },
      { ifIndex: 3, policy: 'UPLINK-OUT', direction: 'output', ifType: 6, classes: [{ name: 'voice', dscps: [46], queue: '', bw: '20%', pps: 100, pktBytes: 200, dropPct: 0, qBytes: 0 }] },
      { ifIndex: 0, policy: 'COPP', direction: 'input', ifType: 5, classes: [{ name: 'cp', dscps: [], queue: '', bw: '', pps: 1, pktBytes: 100, dropPct: 0, qBytes: 0 }] }
    ],
    ports: [{ ifIndex: 1, mode: 'access', vlan: 140, voice: 160 }, { ifIndex: 2, mode: 'access', vlan: 140 }, { ifIndex: 3, mode: 'trunk', vlan: 1, allowed: [140, 160] }],
    fdb: [
      { mac: MAC_A, vlan: 140, ifIndex: 1 }, { mac: MAC_PHONE, vlan: 160, ifIndex: 1 }, { mac: MAC_D, vlan: 140, ifIndex: 2 },
      // a far-away host, learned through the uplink
      { mac: MAC_C, vlan: 310, ifIndex: 3 }
    ],
    arp: [{ ip: '10.1.4.21', mac: MAC_A, ifIndex: 4 }, { ip: '10.1.4.33', mac: MAC_D, ifIndex: 4 }, { ip: '10.9.0.5', mac: MAC_C, ifIndex: 4 }],
    lldp: [{ ifIndex: 3, name: 'core-rtr-01', port: 'Te0/0/0', caps: 0x28 }, { ifIndex: 1, name: 'SEP0050', port: 'Port 1', caps: 0x04 }],
    auth: { community: 'public' }
  };
}

async function env() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-sw-'));
  const cdb = new ConfigDb(dir);
  const secrets = new Secrets(dir, 'test-key');
  const settings = new Settings(cdb);
  const log = new AppLog(cdb, settings, 'error'); log.quiet = true;
  const creds = new CredentialStore(cdb, secrets, settings);
  const store = await SqliteStore.open(path.join(dir, 'ts'));
  const devs = new DeviceService(cdb, creds, store, log, 1500);
  return { cdb, creds, store, devs, log, done: async () => { await store.close(); log.close(); cdb.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}

test('probe: input policies, control-plane policy skipped, interface types, 32-bit class counters when 64-bit are absent', async () => {
  const d = new VirtualDevice(switchSpec(36181));
  await d.start();
  const c = new SnmpClient({ host: '127.0.0.1', port: 36181, timeoutMs: 1500, retries: 0 }, { version: 'v2c', community: 'public' });
  try {
    const p = await probe(c);
    const dirs = p.qos.map(q => [q.policyName, q.direction, q.ifIndex]).sort();
    assert.deepEqual(dirs.filter(x => x[0] !== 'COPP'), [['ACCESS-IN', 'input', 1], ['UPLINK-OUT', 'output', 3]]);
    assert.equal(p.ports.get(1)?.vlan, 140);
    assert.equal(p.ports.get(1)?.voice, 160);
    assert.equal(p.ports.get(3)?.mode, 'trunk');
    assert.equal(p.ports.get(3)?.allowed, '140,160');
    assert.equal(p.ports.get(4)?.mode, 'svi');
    assert.ok(p.qosNote === null || typeof p.qosNote === 'string');
  } finally { c.close(); d.stop(); }
});

test('hosts: a simulated switch is added, its ports get VLANs and input policy, and a host is located on its access port', async () => {
  const e = await env();
  const d = new VirtualDevice(switchSpec(36182));
  // a second switch that sees the same host through its downlink to the first one
  const d2 = new VirtualDevice({ ...switchSpec(36183), name: 'dist-sw-02', address: '127.0.0.2', ips: [{ ip: '10.1.4.2', ifIndex: 4 }], qos: [], arp: [], fdb: [{ mac: MAC_A, vlan: 140, ifIndex: 3 }], lldp: [{ ifIndex: 3, name: 'acc-sw-01', port: 'Te1/1/1', caps: 0x28 }] });
  await d.start(); await d2.start();
  try {
    const cid = e.creds.create({ name: 'lab', version: 'v2c', community: 'public' });
    const dv = await e.devs.add({ ip: '127.0.0.1', port: 36182, credId: cid });
    const dv2 = await e.devs.add({ ip: '127.0.0.2', port: 36183, credId: cid });
    const ifs = e.devs.interfaces(dv.id);
    const gi1 = ifs.find(i => i.name === 'Gi1/0/1')!;
    assert.equal(gi1.vlan, 140); assert.equal(gi1.voiceVlan, 160); assert.equal(gi1.portMode, 'access');
    assert.equal(gi1.policyIn, 'ACCESS-IN');
    assert.ok(gi1.classes.every(c => c.cls.startsWith('in:')), 'input classes are marked so they are not mistaken for queue classes');
    const te = ifs.find(i => i.name === 'Te1/1/1')!;
    assert.equal(te.policy, 'UPLINK-OUT'); assert.equal(te.portMode, 'trunk'); assert.equal(te.vlanList, '140,160');
    assert.equal(ifs.find(i => i.name === 'Vl140')!.portMode, 'svi');
    assert.ok(!ifs.some(i => i.policy === 'COPP' || i.policyIn === 'COPP'), 'the control-plane policy does not belong to an interface');

    const tracker = new HostTracker(e.cdb, e.devs, e.log);
    const row = e.devs.row(dv.id)!;
    const cl = e.devs.open(row);
    try { const r = await tracker.refresh(row, cl); assert.equal(r.macs, 4); assert.equal(r.arp, 3); assert.ok(r.neighbors >= 2); } finally { cl.close(); }
    const row2 = e.devs.row(dv2.id)!; const cl2 = e.devs.open(row2);
    try { const r2 = await tracker.refresh(row2, cl2); assert.equal(r2.macs, 1); } finally { cl2.close(); }

    // a host seen on an access port and, through the uplink, on a trunk: the access port wins, with a high confidence because LLDP identified the uplink
    const a = tracker.locate('10.1.4.21');
    assert.equal(a.attach?.ifName, 'Gi1/0/1');
    assert.equal(a.attach?.vlan, 140);
    assert.equal(a.attach?.confidence, 'high');
    assert.equal(a.macSource, 'arp');
    assert.ok(a.others.some(o => o.dev === 'dist-sw-02' && o.ifName === 'Te1/1/1' && !o.edge), 'the other switch\'s uplink is listed as another place, but not as the attachment');

    // by MAC address, the phone behind the same port
    const ph = tracker.locate(MAC_PHONE);
    assert.equal(ph.attach?.ifName, 'Gi1/0/1'); assert.equal(ph.attach?.vlan, 160);

    // a host only ever seen through the uplink is not placed on that switch
    const far = tracker.locate('10.9.0.5');
    assert.equal(far.attach, null);
    assert.match(far.note, /lead to other switches|uplink|not in the device list/i);

    // no ARP entry and no MAC hint: honest "unknown"
    const none = tracker.locate('10.77.7.7');
    assert.equal(none.attach, null);
    assert.ok(none.note.length > 0);
    // a MAC hint from the flow records is used when ARP does not know the address
    const hinted = tracker.locate('10.77.7.7', MAC_D);
    assert.equal(hinted.attach?.ifName, 'Gi1/0/2');
    assert.notEqual(hinted.attach?.confidence, 'high', 'a MAC taken from flow records is less certain than one from ARP');

    // what is on a port
    const hosts = tracker.portHosts(dv.id, gi1.ifIndex);
    assert.deepEqual(hosts.map(h => h.mac).sort(), [MAC_A, MAC_PHONE].sort());
    assert.deepEqual(hosts.find(h => h.mac === MAC_A)!.ips, ['10.1.4.21']);
    assert.equal(tracker.neighborsOf(dv.id, gi1.ifIndex)[0].kind, 'phone');
    assert.equal(tracker.neighborsOf(dv.id, te.ifIndex)[0].kind, 'infra');
    assert.equal(tracker.portCounts().get(`${dv.id}/${gi1.ifIndex}`), 2);

    // removing the device removes what was learned from it
    await e.devs.remove(dv.id); await e.devs.remove(dv2.id);
    assert.equal((e.cdb.db.prepare('SELECT COUNT(*) AS n FROM fdb').get() as any).n, 0);
    assert.equal((e.cdb.db.prepare('SELECT COUNT(*) AS n FROM arp').get() as any).n, 0);
    assert.equal((e.cdb.db.prepare('SELECT COUNT(*) AS n FROM neighbors').get() as any).n, 0);
  } finally { d.stop(); d2.stop(); await e.done(); }
});

/* ------------------------------------------------------------------ multicast */

const mc: FlowRecord = {
  ts0: 1_000_000, ts1: 1_030_000, exporter: 'a', inIf: 1, outIf: 2, srcIp: '10.9.0.30', dstIp: '239.10.20.30', proto: 17, sport: 40500, dport: 5004,
  flags: 0, tos: 136, postTos: 136, ttlMin: 15, ttlMax: 15, bytes: 120000, pkts: 100, srcMac: 'aa:aa:aa:aa:aa:01', dstMac: '01:00:5e:0a:14:1e',
  vlan: 310, natSrcIp: null, natDstIp: null, natSport: null, natDport: null, nextHop: null, sampling: 1
};
const mctx = {
  deviceName: (ip: string) => 'dev-' + ip, deviceRole: () => 'switch', ifName: (_: string, i: number) => 'Eth1/' + i, vlanName: () => 'DC-APPS',
  classDrops: () => []
};

test('multicast: addresses in 224.0.0.0/4 and ff00::/8 are recognised', () => {
  for (const ip of ['224.0.0.251', '239.255.255.250', '232.1.1.1', 'ff02::fb', 'FF05::1']) assert.ok(isMulticast(ip), ip);
  for (const ip of ['223.255.255.255', '240.0.0.1', '10.1.1.1', '2001:db8::1', '198.51.100.1']) assert.ok(!isMulticast(ip), ip);
});

test('multicast: devices are an unordered set of observers, not a path', () => {
  // the TTLs and times would put 'c' first and 'a' last on a unicast path; for multicast the order is by name and nothing is compared between them
  const recs: FlowRecord[] = [
    { ...mc, exporter: 'c', ttlMin: 15, ttlMax: 15, ts0: 1_000_000, pkts: 100 },
    { ...mc, exporter: 'a', ttlMin: 13, ttlMax: 13, ts0: 1_000_900, pkts: 40, tos: 0, postTos: 0 },
    { ...mc, exporter: 'b', ttlMin: 14, ttlMax: 14, ts0: 1_000_300, pkts: 100, outIf: 3 },
    { ...mc, exporter: 'b', ttlMin: 14, ttlMax: 14, ts0: 1_000_300, pkts: 100, outIf: 4 }
  ];
  const d = analyzeStream('k', recs, mctx)!;
  assert.deepEqual(d.multicast, { group: '239.10.20.30', source: '10.9.0.30' });
  assert.deepEqual(d.forward.map(h => h.exporter), ['dev-a', 'dev-b', 'dev-c'].map(x => x.slice(4)), 'sorted by device name');
  assert.equal(d.reverse.length, 0);
  assert.equal(d.note, null, 'a missing return direction is normal for multicast');
  for (const h of d.forward) {
    assert.equal(h.linkMs, null, 'no latency between devices that are not in a line');
    assert.equal(h.cumMs, null);
    assert.ok(!h.obs.some(o => o.kind === 'loss' || o.kind === 'slow' || o.kind === 'remark'), 'nothing is compared with the previous device: ' + JSON.stringify(h.obs));
  }
  const b = d.forward.find(h => h.exporter === 'b')!;
  assert.deepEqual([...b.outIfs].sort(), ['Eth1/3', 'Eth1/4']);
  assert.ok(b.obs.some(o => /replicated to 2 interfaces/i.test(o.text)));
  assert.equal(d.qosChanged, false);
});

test('unicast streams are unaffected: still an ordered path with latency and loss', () => {
  const uni = { ...mc, dstIp: '10.9.2.30', dstMac: 'bb:bb:bb:bb:bb:01' };
  const recs: FlowRecord[] = [
    { ...uni, exporter: 'a', ttlMin: 63, ttlMax: 63 },
    { ...uni, exporter: 'b', ttlMin: 62, ttlMax: 62, ts0: 1_000_020, pkts: 90 }
  ];
  const d = analyzeStream('k', recs, mctx)!;
  assert.equal(d.multicast, null);
  assert.deepEqual(d.forward.map(h => h.exporter), ['a', 'b']);
  assert.equal(d.forward[1].linkMs, 20);
  assert.ok(d.forward[1].obs.some(o => o.kind === 'loss'));
});
