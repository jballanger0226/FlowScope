import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ConfigDb } from '../src/db/configdb.js';
import { HostTracker } from '../src/snmp/hosts.js';
import { guessRole } from '../src/snmp/devices.js';
import { bandOf, readWlan, WLAN_OID } from '../src/snmp/wlan.js';
import type { SnmpValue } from '../src/snmp/client.js';
import type { Walker } from '../src/snmp/ports.js';

const mac = (s: string) => Buffer.from(s.split(':').map(x => parseInt(x, 16)));
const idx = (s: string) => s.split(':').map(x => parseInt(x, 16)).join('.');
const AP = 'd0:d3:e0:c2:39:b0';

/** The shape of a real ArubaOS 8.12 Instant AP (model 535): one AP, a 5 GHz and a 2.4 GHz radio, two SSIDs on each, and clients. */
function aruba(): Walker {
  const t: Record<string, Record<string, SnmpValue>> = {};
  const put = (base: string, col: number, key: string, v: SnmpValue) => { (t[`${base}.${col}`] ??= {})[key] = v; };
  const a = idx(AP);
  put(WLAN_OID.ap, 2, a, 'NICHOLAS-AP-BASEMENT-535'); put(WLAN_OID.ap, 3, a, Buffer.from([192, 168, 100, 200])); put(WLAN_OID.ap, 4, a, 'VNKSK9W43Y'); put(WLAN_OID.ap, 6, a, '535');
  put(WLAN_OID.ap, 7, a, 3); put(WLAN_OID.ap, 8, a, 1024708608); put(WLAN_OID.ap, 9, a, 14115800); put(WLAN_OID.ap, 10, a, 1785331712); put(WLAN_OID.ap, 13, a, 'cluster conductor');
  const radio = (i: number, m: string, chan: string, power: number, noise: number, u4: number, u64: number, clients: number) => {
    const k = `${a}.${i}`;
    put(WLAN_OID.radio, 3, k, mac(m)); put(WLAN_OID.radio, 2, k, i); put(WLAN_OID.radio, 4, k, chan); put(WLAN_OID.radio, 5, k, power); put(WLAN_OID.radio, 6, k, noise);
    put(WLAN_OID.radio, 7, k, u4); put(WLAN_OID.radio, 8, k, u64); put(WLAN_OID.radio, 20, k, 1); put(WLAN_OID.radio, 21, k, clients); put(WLAN_OID.radio, 22, k, 'access');
  };
  radio(0, 'd0:d3:e0:a3:9b:10', '36E', 27, 92, 1, 2, 2);
  radio(1, 'd0:d3:e0:a3:9b:00', '1', 18, 96, 39, 35, 3);
  ['d0:d3:e0:a3:9b:10:BallangerNet', 'd0:d3:e0:a3:9b:00:BallangerNet', 'd0:d3:e0:a3:9b:11:BallangerIOT', 'd0:d3:e0:a3:9b:01:BallangerIOT'].forEach((s, i) => {
    const m = s.split(':').slice(0, 6).join(':'), name = s.split(':')[6];
    put(WLAN_OID.ssid, 3, `${a}.${i}`, name); put(WLAN_OID.ssid, 4, `${a}.${i}`, mac(m));
  });
  const client = (m: string, bssid: string, ip: string, name: string, os: string, snr: number, txB: number, txR: number, rxB: number, rxR: number, up: number) => {
    const k = idx(m);
    put(WLAN_OID.client, 2, k, mac(bssid)); put(WLAN_OID.client, 3, k, Buffer.from(ip.split('.').map(Number))); put(WLAN_OID.client, 5, k, name); put(WLAN_OID.client, 6, k, os); put(WLAN_OID.client, 7, k, snr);
    put(WLAN_OID.client, 9, k, BigInt(txB)); put(WLAN_OID.client, 11, k, txR); put(WLAN_OID.client, 13, k, BigInt(rxB)); put(WLAN_OID.client, 15, k, rxR); put(WLAN_OID.client, 16, k, up);
    put(WLAN_OID.clientAp, 3, k, mac(AP)); put(WLAN_OID.clientAp, 4, k, 'NICHOLAS-AP-BASEMENT-535');
  };
  client('10:6f:d9:d9:84:01', 'd0:d3:e0:a3:9b:00', '192.168.10.92', 'MINNETONKA', 'Win 10', 34, 365546113, 103, 78418938, 172, 551100);
  client('16:0c:03:87:22:89', 'd0:d3:e0:a3:9b:10', '192.168.10.48', 'Mac', 'OS X', 11, 896523856, 216, 63819558, 204, 6069500);
  client('34:ab:95:12:f0:ea', 'd0:d3:e0:a3:9b:01', '192.168.150.33', 'kauf-plug-12f0ea', 'NOFP', 69, 1419262, 72, 2082121, 54, 14100000);
  return { async column(oid: string) { return new Map(Object.entries(t[oid] ?? {})); } };
}

test('wlan: an Aruba Instant AP gives its radios, SSIDs and clients', async () => {
  const w = await readWlan(aruba(), [{ index: 50, name: 'radio0_ssid_id0' }, { index: 51, name: 'radio0_ssid_id1' }, { index: 70, name: 'radio1_ssid_id0' }, { index: 71, name: 'radio1_ssid_id1' }]);
  assert.ok(w);
  assert.equal(w.aps.length, 1);
  assert.deepEqual({ ...w.aps[0] }, { mac: AP, name: 'NICHOLAS-AP-BASEMENT-535', ip: '192.168.100.200', serial: 'VNKSK9W43Y', model: '535', cpuPct: 3, memFree: 1024708608, memTotal: 1785331712, uptimeSec: 141158, role: 'cluster conductor' });
  const r5 = w.radios.find(r => r.idx === 0)!, r24 = w.radios.find(r => r.idx === 1)!;
  assert.equal(r5.channel, '36E'); assert.equal(r5.band, '5'); assert.equal(r24.band, '2.4');
  assert.equal(r24.noiseFloor, -96, 'the noise floor is published as a positive number');
  assert.equal(r24.util4, 39); assert.equal(r24.util64, 35); assert.equal(r24.txPower, 18); assert.equal(r5.clients, 2);
  assert.deepEqual(w.ssids.map(s => [s.name, s.radio, s.ssidId, s.clients, s.ifName]), [
    ['BallangerNet', 0, 0, 1, 'radio0_ssid_id0'], ['BallangerNet', 1, 0, 1, 'radio1_ssid_id0'], ['BallangerIOT', 0, 1, 0, 'radio0_ssid_id1'], ['BallangerIOT', 1, 1, 1, 'radio1_ssid_id1']
  ]);
  const m = w.clients.find(c => c.name === 'MINNETONKA')!;
  assert.deepEqual({ ...m }, { mac: '10:6f:d9:d9:84:01', apMac: AP, apName: 'NICHOLAS-AP-BASEMENT-535', bssid: 'd0:d3:e0:a3:9b:00', ssid: 'BallangerNet', radio: 1, ip: '192.168.10.92', name: 'MINNETONKA', os: 'Win 10', snr: 34, txRate: 103, rxRate: 172, txBytes: 365546113, rxBytes: 78418938, uptimeSec: 5511 });
  assert.equal(w.clients.find(c => c.name === 'kauf-plug-12f0ea')!.os, '', 'NOFP means no fingerprint, not an operating system');
  assert.equal(w.clients.find(c => c.name === 'kauf-plug-12f0ea')!.ssid, 'BallangerIOT');
});

test('wlan: a device without the Aruba tables gives null, and an interface name that does not exist is not invented', async () => {
  assert.equal(await readWlan({ async column() { return new Map(); } }), null);
  const w = await readWlan(aruba(), [{ index: 1, name: 'eth0' }]);
  assert.ok(w && w.ssids.every(s => s.ifName === null));
});

test('wlan: bands from the channel', () => {
  assert.equal(bandOf('36E'), '5'); assert.equal(bandOf('149'), '5'); assert.equal(bandOf('1'), '2.4'); assert.equal(bandOf('11'), '2.4'); assert.equal(bandOf(''), '');
});

test('role: Aruba APs are access points, Aruba switches and controllers are not', () => {
  assert.equal(guessRole('ArubaOS (MODEL: 535), Version 8.12.0.3-8.12.0.3 SSR', 'NICHOLAS-AP-BASEMENT-535', '1.3.6.1.4.1.14823.1.2.71'), 'ap');
  assert.equal(guessRole('ArubaOS (MODEL: 535), Version 8.12', 'lobby'), 'ap', 'the description alone is enough');
  assert.equal(guessRole('ArubaOS (MODEL: 303H), Version 8.10', 'x'), 'ap');
  assert.equal(guessRole('Some AP', 'office-ap-2'), 'ap');
  assert.equal(guessRole('ArubaOS (MODEL: Aruba7210), Version 8.10', 'ctrl', '1.3.6.1.4.1.14823.1.1.37'), 'switch');
  assert.equal(guessRole('Aruba JL725A 6100 Switch', 'core-1'), 'switch');
  assert.equal(guessRole('Cisco IOS Software [Fuji], Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 16.9.4', 'NICHOLAS-SW-BASEMENT-STP'), 'switch');
  assert.equal(guessRole('Cisco Adaptive Security Appliance Version 9.8', 'edge-fw-1'), 'firewall');
});

function tracker() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-wlan-'));
  const cdb = new ConfigDb(dir);
  const t = new HostTracker(cdb, {} as never, {} as never);
  cdb.db.prepare("INSERT INTO devices(id, name, ip, port, cred_id, interval_sec, polling, src, added_at, role) VALUES (1,'ap1','192.168.100.20',161,1,60,1,'t',0,'switch')").run();
  return { cdb, t, done: () => { cdb.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}

test('wlan: stored, returned, and a client is found by MAC with its IP when no router has it in ARP', async () => {
  const e = tracker();
  try {
    const w = (await readWlan(aruba(), [{ index: 70, name: 'radio1_ssid_id0' }]))!;
    (e.t as unknown as { storeWlan(id: number, w: unknown, now: number): void }).storeWlan(1, w, 1000);
    assert.equal((e.cdb.db.prepare('SELECT role FROM devices WHERE id = 1').get() as { role: string }).role, 'ap', 'a device with Wi-Fi tables becomes an access point');
    assert.equal(e.t.hasWlan(1), true); assert.equal(e.t.hasWlan(2), false);
    const r = e.t.wlanOf(1)!;
    assert.equal(r.aps.length, 1); assert.equal(r.radios.length, 2); assert.equal(r.ssids.length, 4); assert.equal(r.clients.length, 3);
    const f = e.t.wifiFor('10:6f:d9:d9:84:01')!;
    assert.equal(f.name, 'MINNETONKA'); assert.equal(f.ssid, 'BallangerNet'); assert.equal(f.band, '2.4'); assert.equal(f.channel, '1'); assert.equal(f.snr, 34);
    assert.equal(e.t.wifiFor('aa:aa:aa:aa:aa:aa'), null);
    // the MAC address table puts the client on the SSID interface; the AP supplies its name and address
    e.cdb.db.prepare('INSERT INTO fdb(dev_id, mac, vlan, if_index, first_seen, last_seen, since) VALUES (1, ?, 140, 70, ?, ?, ?)').run('10:6f:d9:d9:84:01', Date.now(), Date.now(), Date.now());
    const hosts = e.t.portHosts(1, 70);
    assert.equal(hosts.length, 1); assert.deepEqual(hosts[0].ips, ['192.168.10.92']); assert.equal(hosts[0].wifi?.name, 'MINNETONKA');
    // a second read replaces the first
    (e.t as unknown as { storeWlan(id: number, w: unknown, now: number): void }).storeWlan(1, { ...w, clients: w.clients.slice(0, 1) }, 2000);
    assert.equal(e.t.wlanOf(1)!.clients.length, 1);
    // old clients are forgotten with the other host records
    e.t.purge(2000 + 15 * 86_400_000);
    assert.equal(e.t.wlanOf(1)!.clients.length, 0);
  } finally { e.done(); }
});

/** A stub that serves table columns by their full OID, like the Aruba one above. */
function stub(rows: [string, string, SnmpValue][]): Walker {
  const t: Record<string, Record<string, SnmpValue>> = {};
  for (const [col, key, v] of rows) (t[col] ??= {})[key] = v;
  return { async column(oid: string) { return new Map(Object.entries(t[oid] ?? {})); } };
}

test('wlan vendors: which tables are tried for which device', async () => {
  const { wlanVendor } = await import('../src/snmp/wlan_vendors.js');
  assert.equal(wlanVendor('1.3.6.1.4.1.14823.1.2.113', ''), 'aruba');
  assert.equal(wlanVendor('1.3.6.1.4.1.41112.1.6.1.2.21', ''), 'unifi');
  assert.equal(wlanVendor('1.3.6.1.4.1.25053.3.1.5.15', ''), 'ruckus');
  assert.equal(wlanVendor('1.3.6.1.4.1.9.1.2530', 'Cisco IOS XE Software, C9800-CL Wireless Controller'), 'cisco');
  assert.equal(wlanVendor('1.3.6.1.4.1.9.1.2530', 'Cisco IOS Software, Catalyst L3 Switch'), null, 'a Cisco switch is not asked for wireless tables');
  assert.equal(wlanVendor('1.3.6.1.4.1.8072.3.2.10', 'Linux'), null);
});

test('wlan vendors: roles of access points from other vendors', () => {
  assert.equal(guessRole('UAP-AC-Pro-Gen2 6.5.28', 'office-ap', '1.3.6.1.4.1.41112.1.6.1.2.21'), 'ap');
  assert.equal(guessRole('Ruckus Wireless R510', 'ruckus-1', '1.3.6.1.4.1.25053.3.1.5.45'), 'ap');
  assert.equal(guessRole('Meraki MR36 Cloud Managed AP', 'mr36', ''), 'ap');
  assert.equal(guessRole('Cisco AP Software, (ap3g3-k9w8), C9120AXI', 'cap1', '1.3.6.1.4.1.9.1.2530'), 'ap');
  assert.equal(guessRole('Ruckus Wireless, Inc. ICX7150-48P Switch', 'icx', '1.3.6.1.4.1.1991.1.3.68'), 'switch', 'a Ruckus ICX is still a switch');
});

test('wlan vendors: a UniFi AP gives its SSIDs and channel use, and says nothing it does not know', async () => {
  const { readUnifi } = await import('../src/snmp/wlan_vendors.js');
  const U = '1.3.6.1.4.1.41112.1.6';
  const w = await readUnifi(stub([
    [`${U}.1.2.1.6`, '1', 'HomeNet'], [`${U}.1.2.1.6`, '2', 'HomeNet'], [`${U}.1.2.1.6`, '3', 'Guest'],
    [`${U}.1.2.1.2`, '1', mac('74:ac:b9:00:00:01')], [`${U}.1.2.1.2`, '2', mac('74:ac:b9:00:00:02')], [`${U}.1.2.1.2`, '3', mac('76:ac:b9:00:00:02')],
    [`${U}.1.2.1.4`, '1', 6], [`${U}.1.2.1.4`, '2', 36], [`${U}.1.2.1.4`, '3', 36],
    [`${U}.1.2.1.7`, '1', 'ath0'], [`${U}.1.2.1.7`, '2', 'ath1'], [`${U}.1.2.1.7`, '3', 'ath2'],
    [`${U}.1.2.1.8`, '1', 4], [`${U}.1.2.1.8`, '2', 7], [`${U}.1.2.1.8`, '3', 1],
    [`${U}.1.2.1.9`, '1', 'ng'], [`${U}.1.2.1.9`, '2', 'na'], [`${U}.1.2.1.9`, '3', 'na'],
    [`${U}.1.2.1.21`, '1', 20], [`${U}.1.2.1.21`, '2', 23], [`${U}.1.2.1.21`, '3', 23],
    [`${U}.1.2.1.22`, '1', 1], [`${U}.1.2.1.22`, '2', 1], [`${U}.1.2.1.22`, '3', 1],
    [`${U}.1.1.1.2`, '1', 'wifi0'], [`${U}.1.1.1.2`, '2', 'wifi1'], [`${U}.1.1.1.3`, '1', 'ng'], [`${U}.1.1.1.3`, '2', 'na'],
    [`${U}.1.1.1.6`, '1', 18], [`${U}.1.1.1.6`, '2', 6],
    [`${U}.3.1`, '0', Buffer.from([192, 168, 1, 9])], [`${U}.3.3`, '0', 'U7PG2'], [`${U}.3.5`, '0', 86400]
  ]));
  assert.ok(w);
  assert.equal(w.vendor, 'unifi');
  assert.deepEqual({ ...w.aps[0] }, { mac: '', name: '', ip: '192.168.1.9', serial: '', model: 'U7PG2', cpuPct: -1000, memFree: 0, memTotal: 0, uptimeSec: 86400, role: '' });
  assert.deepEqual(w.radios.map(r => [r.band, r.channel, r.txPower, r.util64, r.util4, r.clients]), [['2.4', '6', 20, 18, -1000, 4], ['5', '36', 23, 6, -1000, 8]]);
  assert.deepEqual(w.ssids.map(s => [s.name, s.radio, s.clients, s.ifName]), [['HomeNet', 0, 4, 'ath0'], ['HomeNet', 1, 7, 'ath1'], ['Guest', 1, 1, 'ath2']]);
  assert.equal(w.clients.length, 0);
  assert.equal(await readUnifi(stub([])), null, 'a device without the UniFi tables gives nothing');
});

test('wlan vendors: Ruckus gives its access points and WLANs', async () => {
  const { readRuckus } = await import('../src/snmp/wlan_vendors.js');
  const Z = '1.3.6.1.4.1.25053.1.2.2.1.1';
  const k = idx('c4:10:8a:11:22:33');
  const w = await readRuckus(stub([
    [`${Z}.2.1.1.2`, k, 'lobby-ap'], [`${Z}.2.1.1.4`, k, 'R510'], [`${Z}.2.1.1.5`, k, '502012345678'], [`${Z}.2.1.1.6`, k, 360000], [`${Z}.2.1.1.10`, k, Buffer.from([10, 0, 0, 5])], [`${Z}.2.1.1.29`, k, 7],
    [`${Z}.1.1.1.1`, '1', 'Staff'], [`${Z}.1.1.1.1`, '2', 'Guests'], [`${Z}.1.1.1.12`, '1', 9], [`${Z}.1.1.1.12`, '2', 3]
  ]));
  assert.ok(w);
  assert.deepEqual({ ...w.aps[0] }, { mac: 'c4:10:8a:11:22:33', name: 'lobby-ap', ip: '10.0.0.5', serial: '502012345678', model: 'R510', cpuPct: 7, memFree: 0, memTotal: 0, uptimeSec: 3600, role: '' });
  assert.deepEqual(w.ssids.map(s => [s.name, s.clients]), [['Staff', 9], ['Guests', 3]]);
  assert.equal(w.radios.length, 0); assert.equal(w.clients.length, 0);
});

test('wlan vendors: a Cisco controller gives its access points and clients', async () => {
  const { readCiscoWlc } = await import('../src/snmp/wlan_vendors.js');
  const AP = '1.3.6.1.4.1.9.9.513.1.1.1.1', CL = '1.3.6.1.4.1.9.9.599.1.3.1.1';
  const a = idx('00:11:22:33:44:55'), c1 = idx('aa:bb:cc:00:00:01'), c2 = idx('aa:bb:cc:00:00:02');
  const w = await readCiscoWlc(stub([
    [`${AP}.49`, a, 'ap-floor2'], [`${AP}.59`, a, 1234500], [`${AP}.56`, a, 12],
    [`${CL}.2`, c1, 3], [`${CL}.2`, c2, 3],
    [`${CL}.28`, c1, 'Corp'], [`${CL}.28`, c2, 'Corp'], [`${CL}.8`, c1, mac('00:11:22:33:44:55')], [`${CL}.8`, c2, mac('00:11:22:33:44:55')],
    [`${CL}.10`, c1, Buffer.from([10, 1, 1, 20])], [`${CL}.27`, c1, 'alice'], [`${CL}.44`, c1, 'Apple-iPhone'], [`${CL}.15`, c1, 600], [`${CL}.50`, c1, 144]
  ]));
  assert.ok(w);
  assert.equal(w.aps[0].name, 'ap-floor2'); assert.equal(w.aps[0].uptimeSec, 12345); assert.equal(w.aps[0].cpuPct, 12);
  const x = w.clients.find(c => c.mac === 'aa:bb:cc:00:00:01')!;
  assert.deepEqual({ ...x }, { mac: 'aa:bb:cc:00:00:01', apMac: '00:11:22:33:44:55', apName: 'ap-floor2', bssid: '', ssid: 'Corp', radio: null, ip: '10.1.1.20', name: 'alice', os: 'Apple-iPhone', snr: -1000, txRate: 144, rxRate: 0, txBytes: 0, rxBytes: 0, uptimeSec: 600 });
  assert.deepEqual(w.ssids.map(s => [s.name, s.clients]), [['Corp', 2]]);
});
