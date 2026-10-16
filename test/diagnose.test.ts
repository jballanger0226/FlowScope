import test from 'node:test';
import assert from 'node:assert/strict';
import { runChecks, cleanOid, expectFor, formatValue, vendorOf } from '../src/snmp/diagnose.js';
import { OID } from '../src/snmp/oids.js';
import type { SnmpValue } from '../src/snmp/client.js';

/** A device made of whole columns: the walker returns the rows registered under each OID, or an empty table. */
function fake(tables: Record<string, Record<string, SnmpValue>>, fail: string[] = [], scalars: Record<string, SnmpValue> = {}, asked: string[] = []) {
  return {
    column: async (oid: string) => { asked.push(oid); if (fail.includes(oid)) throw new Error('No response from the device (timeout).'); return new Map(Object.entries(tables[oid] ?? {})); },
    get: async (oids: string[]) => { asked.push(...oids); return new Map(oids.filter(o => scalars[o] !== undefined).map(o => [o, { oid: o, type: 2, value: scalars[o] }])) as never; }
  };
}
const byId = (cs: Awaited<ReturnType<typeof runChecks>>) => Object.fromEntries(cs.map(c => [c.id, c]));

test('a firewall that publishes no LLDP is reported as missing, with the AgentX hint', async () => {
  const c = byId(await runChecks(fake({ [OID.ifName]: { '1': 'igb0', '2': 'igb1' }, [OID.ifHCInOctets]: { '1': 5, '2': 6 } }), { role: 'router', cisco: false }));
  assert.equal(c.interfaces.state, 'ok'); assert.equal(c.interfaces.count, 2);
  assert.equal(c.lldp.state, 'fail');
  assert.match(c.lldp.hint ?? '', /AgentX/);
  assert.match(c.lldp.hint ?? '', /\.1\.0\.8802/);
  assert.equal(c.cdp, undefined);           // only Cisco devices publish CDP, so it is not asked for elsewhere
  assert.equal(c.mac, undefined);           // a router is not expected to have a MAC table
  assert.equal(c.arp.state, 'warn');        // but a router is expected to have an ARP cache
});

test('LLDP published with no neighbours is a warning, with neighbours it is ok and counts ports', async () => {
  const f = { role: 'device', cisco: false };
  const published = byId(await runChecks(fake({ [OID.ifName]: { '1': 'a' }, [OID.lldpLocPortId]: { '1': 'igb0' } }), f));
  assert.equal(published.lldp.state, 'warn');
  const seen = byId(await runChecks(fake({ [OID.ifName]: { '1': 'a' }, [OID.lldpLocPortId]: { '1': 'x' }, [OID.lldpRemChassisId]: { '0.1.1': 'aa', '0.1.2': 'bb', '0.3.1': 'cc' } }), f));
  assert.equal(seen.lldp.state, 'ok'); assert.equal(seen.lldp.count, 3);
  assert.match(seen.lldp.detail, /3 neighbours on 2 ports/);
});

test('MAC table: a switch without one fails, a Cisco switch is excused because its tables are per VLAN', async () => {
  const base = { [OID.ifName]: { '1': 'Gi1/0/1' } };
  assert.equal(byId(await runChecks(fake(base), { role: 'switch', cisco: false })).mac.state, 'fail');
  const cisco = byId(await runChecks(fake(base), { role: 'switch', cisco: true }));
  assert.equal(cisco.mac.state, 'na'); assert.match(cisco.mac.detail, /per VLAN/);
  assert.equal(byId(await runChecks(fake({ ...base, [OID.dot1dTpFdbPort]: { '1.2.3.4.5.6': 1 } }), { role: 'switch', cisco: false })).mac.state, 'ok');
});

test('only 32-bit counters is a warning; a timeout is quoted in the detail', async () => {
  const c = byId(await runChecks(fake({ [OID.ifName]: { '1': 'a' }, [OID.ifInOctets32]: { '1': 1 } }, [OID.lldpLocPortId]), { role: 'switch', cisco: false }));
  assert.equal(c.counters.state, 'warn');
  assert.equal(c.lldp.state, 'fail'); assert.match(c.lldp.detail, /timeout/);
});

test('cleanOid accepts numeric OIDs and refuses everything else', () => {
  assert.equal(cleanOid('1.0.8802.1.1.2.1.4'), '1.0.8802.1.1.2.1.4');
  assert.equal(cleanOid(' .1.3.6.1.2.1.1 '), '1.3.6.1.2.1.1');
  for (const bad of ['', '1', 'sysDescr', '1.3.6.1.2.1.1.x', '1..3', '3.1.2', '1.3.6.1.99999999999', '1.3.6.1.2.1;rm', '1.3.6.1.2.1.1\n.2']) assert.equal(cleanOid(bad), null, bad);
  assert.equal(cleanOid('1.' + Array(70).fill('1').join('.')), null);
});

test('formatValue prints text as text and binary as hex', () => {
  assert.deepEqual(formatValue(4, Buffer.from('OPNsense\0')), { type: 'OctetString', text: 'OPNsense' });
  assert.deepEqual(formatValue(4, Buffer.from([0x00, 0x1b, 0x21, 0xab, 0xcd, 0xef])), { type: 'OctetString', text: 'hex 00:1b:21:ab:cd:ef' });
  assert.deepEqual(formatValue(4, Buffer.alloc(0)), { type: 'OctetString', text: '' });
  assert.deepEqual(formatValue(70, 12345678901234567890n), { type: 'Counter64', text: '12345678901234567890' });
  assert.deepEqual(formatValue(2, 7), { type: 'Integer', text: '7' });
  assert.equal(formatValue(99, 1).type, 'type 99');
});

test('LLDP missing while lldpd runs on the device: named as an AgentX gap, with the neighbour count from its process title', async () => {
  const f = { role: 'router', cisco: false };
  const HR_NAME = '1.3.6.1.2.1.25.4.2.1.2', HR_PATH = '1.3.6.1.2.1.25.4.2.1.4';
  const on = byId(await runChecks(fake({ [OID.ifName]: { '1': 'igb0' }, [HR_NAME]: { '19497': 'lldpd', '21437': 'lldpd', '39852': 'snmpd' }, [HR_PATH]: { '19497': 'lldpd: monitor.', '21437': 'lldpd: 2 neighbors.', '39852': '/usr/local/sbin/snmpd' } }), f));
  assert.equal(on.lldp.state, 'fail');
  assert.match(on.lldp.detail, /lldpd is running on this device and sees 2 neighbours/);
  assert.match(on.lldp.hint ?? '', /-x/); assert.match(on.lldp.hint ?? '', /master agentx/);
  const one = byId(await runChecks(fake({ [OID.ifName]: { '1': 'igb0' }, [HR_NAME]: { '5': '/usr/sbin/lldpd' }, [HR_PATH]: { '5': '/usr/sbin/lldpd' } }), f));
  assert.match(one.lldp.detail, /lldpd is running on this device, but nothing is published/, 'no count in the title: still named, without a number');
  const off = byId(await runChecks(fake({ [OID.ifName]: { '1': 'igb0' }, [HR_NAME]: { '39852': 'snmpd' } }), f));
  assert.match(off.lldp.detail, /Nothing came back/, 'no lldpd process: the generic explanation');
  assert.match(off.lldp.detail, /lldpd is not running on it/, 'a readable process list without lldpd says so');
  const sw = byId(await runChecks(fake({ [OID.ifName]: { '1': 'Gi1' }, [HR_NAME]: { '1': 'x' } }), { role: 'switch', cisco: false }));
  assert.doesNotMatch(sw.lldp.detail, /lldpd is not running/, 'a switch is not expected to run lldpd');
  const noTable = byId(await runChecks(fake({ [OID.ifName]: { '1': 'igb0' } }, [HR_NAME]), f));
  assert.equal(noTable.lldp.state, 'fail', 'an unreadable process table does not break the check');
});

const OIDS = { ospf: '1.3.6.1.2.1.14.10.1.6', juniper: '1.3.6.1.4.1.2636.', huawei: '1.3.6.1.4.1.2011.', h3c: '1.3.6.1.4.1.25506.', fortinet: '1.3.6.1.4.1.12356.', pan: '1.3.6.1.4.1.25461.', aruba: '1.3.6.1.4.1.14823.', cisco: '1.3.6.1.4.1.9.' };

test('a Cisco switch is only asked for what a Cisco switch has: no Juniper, Huawei, Fortinet or Wi-Fi tables', async () => {
  const asked: string[] = [];
  const cs = await runChecks(fake({ [OID.ifName]: { '1': 'Gi1/0/1' } }, [], {}, asked), { role: 'switch', cisco: true, objectId: '1.3.6.1.4.1.9.1.2504', descr: 'Cisco IOS Software, Catalyst L3 Switch' });
  for (const v of ['juniper', 'huawei', 'h3c', 'fortinet', 'pan', 'aruba'] as const) assert.equal(asked.some(o => o.startsWith(OIDS[v])), false, v);
  assert.ok(asked.some(o => o.startsWith(OIDS.cisco)), 'Cisco MIBs were asked for');
  const ids = cs.map(c => c.id);
  for (const id of ['cdp', 'mac', 'vlans', 'sensors', 'poe', 'stp', 'quality', 'qos', 'resources']) assert.ok(ids.includes(id), id);
  assert.ok(!ids.includes('wifi'), 'a switch is not asked about Wi-Fi');
  const c = byId(cs);
  assert.equal(c.sensors.state, 'warn', 'a Cisco switch should have sensors');
  assert.match(c.sensors.hint ?? '', /CISCO-ENTITY-SENSOR/);
  assert.equal(c.poe.state, 'na'); assert.equal(c.qos.state, 'na'); assert.match(c.qos.title, /Cisco CBQoS/);
  assert.equal(c.resources.state, 'fail'); assert.match(c.resources.hint ?? '', /CISCO-PROCESS-MIB/);
});

test('a Juniper router is asked for Junos CoS and its own resource MIB, not Cisco CDP or CBQoS', async () => {
  const asked: string[] = [];
  const cs = await runChecks(fake({}, [], {}, asked), { role: 'router', cisco: false, objectId: '1.3.6.1.4.1.2636.1.1.1.2.21', descr: 'Juniper Networks MX204' });
  const ids = cs.map(c => c.id);
  assert.ok(!ids.includes('cdp') && !ids.includes('mac') && !ids.includes('vlans') && !ids.includes('poe') && !ids.includes('stp') && !ids.includes('wifi'));
  assert.ok(ids.includes('ospf') && ids.includes('bgp') && ids.includes('arp'));
  const c = byId(cs);
  assert.match(c.qos.title, /Juniper CoS/); assert.match(c.resources.hint ?? '', /jnxOperatingTable/);
  assert.equal(asked.some(o => o.startsWith('1.3.6.1.4.1.9.')), false, 'no Cisco MIBs');
  assert.equal(c.arp.state, 'warn');
});

test('an OPNsense firewall (net-snmp) is checked for UCD resources, ARP and link counters, and not for sensors, PoE, spanning tree or switch tables', async () => {
  const cs = await runChecks(fake({ [OID.ifName]: { '1': 'igb0' }, [OID.ipNetToMediaPhysAddress]: { '1.10.0.0.5': Buffer.from([0, 1, 2, 3, 4, 5]) }, '1.3.6.1.2.1.2.2.1.14': { '1': 0 }, '1.3.6.1.2.1.31.1.1.1.3': { '1': 5 } }, [],
    { '1.3.6.1.2.1.25.1.1.0': 8640000, '1.3.6.1.4.1.2021.11.11.0': 90, '1.3.6.1.4.1.2021.4.5.0': 1000000, '1.3.6.1.4.1.2021.4.6.0': 600000 }),
    { role: 'firewall', cisco: false, objectId: '1.3.6.1.4.1.8072.3.2.8', descr: 'FreeBSD OPNsense.local 14.1 amd64' });
  const c = byId(cs), ids = cs.map(x => x.id);
  assert.equal(c.resources.state, 'ok'); assert.match(c.resources.detail, /CPU 10%/); assert.match(c.resources.detail, /UCD-SNMP-MIB/);
  assert.equal(c.arp.state, 'ok'); assert.equal(c.arp.count, 1);
  assert.equal(c.quality.state, 'ok', 'a net-snmp agent has no EtherLike-MIB, which is normal');
  for (const id of ['sensors', 'poe', 'stp', 'mac', 'vlans', 'cdp', 'wifi']) assert.ok(!ids.includes(id), id);
  assert.ok(ids.includes('ospf') && ids.includes('bgp'));
  assert.equal(ids.includes('qos'), false, 'DiffServ is only listed when the device publishes it');
});

test('an empty ARP cache on a firewall is a warning, since a firewall is the router; an access point is asked for Wi-Fi tables and fails without them', async () => {
  assert.equal(byId(await runChecks(fake({ [OID.ifName]: { '1': 'igb0' } }), { role: 'firewall', cisco: false, objectId: '1.3.6.1.4.1.8072.3.2.8', descr: 'FreeBSD' })).arp.state, 'warn');
  const ap = byId(await runChecks(fake({ [OID.ifName]: { '1': 'eth0' } }), { role: 'ap', cisco: false, objectId: '1.3.6.1.4.1.14823.1.1.1', descr: 'ArubaOS Instant', ifaces: [{ index: 1, name: 'eth0' }] }));
  assert.equal(ap.wifi.state, 'fail'); assert.match(ap.wifi.hint ?? '', /AI-AP-MIB/);
  for (const id of ['sensors', 'poe', 'stp', 'ospf', 'bgp', 'qos', 'mac', 'cdp']) assert.equal(ap[id], undefined, id);
});

test('checks are listed by group, and vendors are told from the sysObjectID or the description', async () => {
  const cs = await runChecks(fake({ [OID.ifName]: { '1': 'a' } }), { role: 'switch', cisco: true, objectId: '1.3.6.1.4.1.9.1.1' });
  const order = ['basics', 'neighbours', 'hosts', 'hardware', 'routing', 'quality', 'wifi'];
  assert.deepEqual(cs.map(c => order.indexOf(c.group)), [...cs.map(c => order.indexOf(c.group))].sort((a, b) => a - b));
  assert.equal(vendorOf('1.3.6.1.4.1.12356.101.1.1', ''), 'fortinet');
  assert.equal(vendorOf('', 'FreeBSD pfSense 2.7'), 'netsnmp');
  assert.equal(vendorOf('1.3.6.1.4.1.99999.1', 'Some box'), 'other');
  assert.equal(expectFor({ role: 'switch', cisco: false, objectId: '1.3.6.1.4.1.2011.2.23.1' }).sensors, 'must');
});

/* ------------------------------------------------------------------ multicast routing check, run on rows of a real Catalyst 9300 walk */
import fs from 'node:fs';
import path from 'node:path';
const MC = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, '..', '..', 'test', 'fixtures', 'mcast-c9300.json'), 'utf8')) as Record<string, SnmpValue>;
function mcDevice(rows: Record<string, SnmpValue>) {
  return {
    column: async (col: string) => { const m = new Map<string, SnmpValue>(); for (const [o, v] of Object.entries(rows)) if (o.startsWith(col + '.')) m.set(o.slice(col.length + 1), v); return m; },
    get: async () => new Map() as never
  };
}
const CAT = { role: 'switch', cisco: true, objectId: '1.3.6.1.4.1.9.1.2504' };

test('multicast routing: a Layer 3 switch with the tables passes, with counts', async () => {
  const c = byId(await runChecks(mcDevice(MC), CAT)).mcast!;
  assert.equal(c.state, 'ok'); assert.equal(c.group, 'routing'); assert.equal(c.count, 25);
  assert.match(c.detail, /25 routes for 13 groups/); assert.match(c.detail, /19 PIM interfaces/);
});

test('multicast routing: without the Cisco table or PIM-MIB it warns and says what is lost', async () => {
  const noCisco = byId(await runChecks(mcDevice(Object.fromEntries(Object.entries(MC).filter(([o]) => !o.startsWith('1.3.6.1.4.1.9.10.')))), CAT)).mcast!;
  assert.equal(noCisco.state, 'warn'); assert.match(noCisco.detail, /no rates/); assert.match(noCisco.hint ?? '', /CISCO-IPMROUTE-MIB/);
  const noPim = byId(await runChecks(mcDevice(Object.fromEntries(Object.entries(MC).filter(([o]) => !o.startsWith('1.3.6.1.3.61.')))), CAT)).mcast!;
  assert.equal(noPim.state, 'warn'); assert.match(noPim.detail, /no rendezvous points/);
});

test('multicast routing: a device that routes no multicast is not applicable; access points are not asked', async () => {
  const none = byId(await runChecks(mcDevice({}), CAT)).mcast!;
  assert.equal(none.state, 'na'); assert.match(none.detail, /does not route multicast/);
  const ap = byId(await runChecks(mcDevice({}), { role: 'ap', cisco: false, objectId: '1.3.6.1.4.1.14823.1.1.1', descr: 'ArubaOS Instant' }));
  assert.equal(ap.mcast, undefined);
  assert.equal(expectFor({ role: 'switch', cisco: false, objectId: '1.3.6.1.4.1.8072.3.2.10', descr: 'Linux' }).mcast, false, 'a plain Layer 2 switch is not asked');
});
