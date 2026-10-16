import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ConfigDb } from '../src/db/configdb.js';
import { DeviceService, guessRole, prefixLength } from '../src/snmp/devices.js';
import { macText, readInterfaces, speedMbpsOf } from '../src/snmp/collect.js';
import { readResources } from '../src/snmp/resources.js';
import type { SnmpClient, SnmpValue } from '../src/snmp/client.js';

/** A trimmed copy of a real net-snmp walk of an OPNsense firewall (FreeBSD 15, 12 cores, ZFS), with names and MAC addresses replaced. */
const WALK = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, '../../test/fixtures/opnsense-walk.json'), 'utf8')) as Record<string, [string, string]>;
const NET_SNMP_FREEBSD = '1.3.6.1.4.1.8072.3.2.8';

function value(t: string, v: string): SnmpValue {
  if (t === 'OctetString') return v.startsWith('hex ') ? Buffer.from(v.slice(4).split(':').map(x => parseInt(x, 16))) : v;
  if (t === 'OID' || t === 'Opaque') return v;
  return Number(v);
}

/** Answers get and column from a table of OIDs, the way an agent would. */
function agent(rows: Record<string, [string, string]>): SnmpClient {
  const get = async (oids: string[]) => {
    const m = new Map<string, { oid: string; type: number; value: SnmpValue }>();
    for (const o of oids) if (rows[o]) m.set(o, { oid: o, type: 0, value: value(...rows[o]) });
    return m;
  };
  const column = async (col: string) => {
    const m = new Map<string, SnmpValue>();
    for (const [o, r] of Object.entries(rows)) if (o.startsWith(col + '.')) m.set(o.slice(col.length + 1), value(...r));
    return m;
  };
  return { get, column } as unknown as SnmpClient;
}
const without = (prefixes: string[]) => Object.fromEntries(Object.entries(WALK).filter(([o]) => !prefixes.some(p => o.startsWith(p))));

test('OPNsense and pfSense are recognised as firewalls, plain FreeBSD is not guessed', () => {
  assert.equal(guessRole('FreeBSD fw.example.net 15.1-RELEASE-p3 FreeBSD 15.1-RELEASE-p3', 'fw.example.net', NET_SNMP_FREEBSD), 'device');
  assert.equal(guessRole('FreeBSD OPNsense.lan 15.1-RELEASE-p3', 'OPNsense.lan', NET_SNMP_FREEBSD), 'firewall');
  assert.equal(guessRole('pfSense.home.arpa 2.7.2-RELEASE', 'pfsense', ''), 'firewall');
});

test('a link speed wrapped by a 32-bit counter is put right', () => {
  // net-snmp on FreeBSD reports 10 Gbps as 1410065408 bps and ifHighSpeed 1410
  assert.equal(speedMbpsOf(1410, 1410065408), 10_000);
  assert.equal(speedMbpsOf(3528, (25_000 * 1e6) % 4294967296), 25_000);
  assert.equal(speedMbpsOf(1000, 1_000_000_000), 1000, 'a real gigabit port is left alone');
  assert.equal(speedMbpsOf(10_000, 4294967295), 10_000, 'ifSpeed at its ceiling defers to ifHighSpeed');
  assert.equal(speedMbpsOf(0, 100_000_000), 100, 'no ifHighSpeed: ifSpeed in Mbps');
  assert.equal(speedMbpsOf(0, 0), 0, 'wireguard, loopback: unknown');
});

test('interface MAC addresses and prefix lengths read cleanly', () => {
  assert.equal(macText(Buffer.from([0x20, 0x7c, 0x14, 0xf4, 0xa8, 0xe3])), '20:7c:14:f4:a8:e3');
  assert.equal(macText(Buffer.alloc(6)), '', 'all zero is no address');
  assert.equal(macText(Buffer.alloc(0)), '', 'tunnels have none');
  assert.equal(macText(undefined), '');
  assert.equal(prefixLength('255.255.255.0'), '24');
  assert.equal(prefixLength('255.255.254.0'), '23');
  assert.equal(prefixLength('255.255.255.255'), '32');
  assert.equal(prefixLength('0.0.0.0'), '0');
  assert.equal(prefixLength('255.0.255.0'), '255.0.255.0', 'a mask with gaps is shown as it came');
});

test('a firewall keeps its VLAN interfaces, a switch does not, and the 10G speed comes out right', async () => {
  const c = agent(WALK);
  const sw = await readInterfaces(c, false);
  assert.ok(!sw.some(i => i.name.startsWith('vlan0.')), 'VLAN interfaces without a description are hidden on a switch');
  const fw = await readInterfaces(c, true);
  const vlans = fw.filter(i => i.name.startsWith('vlan0.'));
  assert.deepEqual(vlans.map(i => i.name), ['vlan0.2150', 'vlan0.1000', 'vlan0.10', 'vlan0.3254']);
  assert.ok(vlans.every(i => i.speedMbps === 10_000), 'wrapped 1410 Mbps is really 10 Gbps');
  assert.ok(!fw.some(i => i.name === 'lo0'), 'the loopback stays hidden');
  const ix0 = fw.find(i => i.name === 'ix0')!;
  assert.equal(ix0.speedMbps, 10_000);
  assert.match(ix0.mac, /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/);
  assert.equal(vlans[0].mac, ix0.mac, 'VLAN subinterfaces share the MAC of their port');
  assert.equal(fw.find(i => i.name === 'wg0')!.speedMbps, 0, 'a tunnel with no speed stays unknown');
});

test('resources of a net-snmp firewall: uptime, CPU, memory without the cache, load, swap and disks', async () => {
  const r = await readResources(agent(WALK), NET_SNMP_FREEBSD, 1000);
  assert.ok(r);
  assert.equal(r.uptimeSec, 325650, 'hrSystemUptime, the host, not the 5 hour old SNMP agent');
  assert.equal(r.cpuPct, 5, '100 minus ssCpuIdle');
  assert.equal(r.cores, 12);
  assert.deepEqual(r.load, [0.54, 0.89, 0.83]);
  // 32 GB of RAM of which 23 GB is cache: used is the rest, not the 96% HOST-RESOURCES counts
  assert.ok(r.memPct !== null && r.memPct > 22 && r.memPct < 25, `memory ${r.memPct}%`);
  assert.equal(r.memTotal, 33473724 * 1024);
  assert.ok(r.swapPct !== null && r.swapPct < 1);
  assert.ok(r.disks.length >= 1 && r.disks.length <= 4);
  assert.ok(r.disks.some(d => d.name === '/'), 'the root filesystem is listed');
  assert.equal(new Set(r.disks.map(d => `${d.totalBytes}|${d.usedBytes}`)).size, r.disks.length, 'mounts of one pool are listed once');
  assert.match(r.source, /UCD-SNMP-MIB/);
  assert.match(r.source, /HOST-RESOURCES-MIB/);
});

test('resources fall back to HOST-RESOURCES when there is no UCD-SNMP-MIB', async () => {
  const r = await readResources(agent(without(['1.3.6.1.4.1.2021.'])), NET_SNMP_FREEBSD, 1000);
  assert.ok(r);
  assert.equal(r.cpuPct, 5, 'mean of the 12 hrProcessorLoad values (8 9 5 3 5 3 5 4 6 3 2 7)');
  assert.equal(r.load, null);
  assert.ok(r.memPct !== null && r.memPct > 22 && r.memPct < 25, `memory ${r.memPct}% leaves the cache and buffer rows out`);
  assert.equal(r.source, 'HOST-RESOURCES-MIB');
});

test('Cisco CPU and memory pool are read from the Cisco MIBs', async () => {
  const c = agent({
    '1.3.6.1.4.1.9.9.109.1.1.1.1.7.1': ['Gauge32', '17'], '1.3.6.1.4.1.9.9.109.1.1.1.1.6.1': ['Gauge32', '40'],
    '1.3.6.1.4.1.9.9.48.1.1.1.2.1': ['OctetString', 'Processor'], '1.3.6.1.4.1.9.9.48.1.1.1.5.1': ['Gauge32', '300'], '1.3.6.1.4.1.9.9.48.1.1.1.6.1': ['Gauge32', '700'],
    '1.3.6.1.4.1.9.9.48.1.1.1.2.2': ['OctetString', 'I/O'], '1.3.6.1.4.1.9.9.48.1.1.1.5.2': ['Gauge32', '50'], '1.3.6.1.4.1.9.9.48.1.1.1.6.2': ['Gauge32', '50'],
    '1.3.6.1.2.1.25.1.1.0': ['TimeTicks', '8640000']
  });
  const r = await readResources(c, '1.3.6.1.4.1.9.1.1745', 1000);
  assert.ok(r);
  assert.equal(r.cpuPct, 17, 'the one minute average, not the 5 second figure');
  assert.equal(r.memPct, 30, 'the Processor pool');
  assert.equal(r.memTotal, 1000);
  assert.equal(r.uptimeSec, 86400);
  assert.match(r.source, /CISCO-PROCESS-MIB/);
});

test('a device that publishes none of it gives null, so nothing is shown for it', async () => {
  assert.equal(await readResources(agent({}), '1.3.6.1.4.1.14823.1.1.37', 1000), null);
});

test('stored resources, interface MACs and subnets come back through the device service', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-res-'));
  const cdb = new ConfigDb(dir);
  try {
    const db = cdb.db;
    db.prepare("INSERT INTO credentials(name, version) VALUES ('c','v2c')").run?.();
  } catch { /* the credentials table shape is not needed here */ }
  const db = cdb.db;
  db.prepare("INSERT INTO devices(id, name, ip, cred_id, added_at) VALUES (1, 'fw', '10.0.0.1', 1, 0), (2, 'sw', '10.0.0.2', 1, 0)").run();
  const ins = db.prepare('INSERT INTO interfaces(dev_id, if_index, name, if_type, mac) VALUES (?,?,?,?,?)');
  ins.run(1, 6, 'ix0', 6, '02:00:00:00:00:01'); ins.run(1, 15, 'vlan0.10', 135, '02:00:00:00:00:01'); ins.run(1, 16, 'vlan0.20', 135, '02:00:00:00:00:01'); ins.run(2, 1, 'Gi1/0/1', 6, '02:00:00:00:00:02');
  db.prepare("INSERT INTO device_ips(dev_id, ip, if_index, mask) VALUES (1, '192.168.10.1', 15, '255.255.255.0'), (1, '10.1.0.1', 6, '255.255.254.0'), (1, '172.16.0.1', 16, '')").run();
  const devs = new DeviceService(cdb, { list: () => [] } as never, {} as never, {} as never);

  assert.equal(devs.macOwner('02:00:00:00:00:01'), 'fw · ix0, +2 more', 'the physical port is named and the VLANs counted');
  assert.equal(devs.macOwner('02:00:00:00:00:02'), 'sw · Gi1/0/1');
  assert.equal(devs.macOwner('02:00:00:00:00:99'), null);
  assert.equal(devs.macOwner(null), null);
  assert.equal(devs.macOwner('02:00:00:00:00:01'.toUpperCase()), 'fw · ix0, +2 more', 'case does not matter');

  const ifs = devs.interfaces(1);
  assert.deepEqual(ifs.find(i => i.name === 'vlan0.10')!.addresses, ['192.168.10.1/24']);
  assert.deepEqual(ifs.find(i => i.name === 'ix0')!.addresses, ['10.1.0.1/23']);
  assert.deepEqual(ifs.find(i => i.name === 'vlan0.20')!.addresses, ['172.16.0.1'], 'no mask: the bare address');
  assert.equal(ifs.find(i => i.name === 'ix0')!.mac, '02:00:00:00:00:01');

  assert.equal(devs.resources(1), null);
  devs.saveResources(1, { uptimeSec: 5, cpuPct: 9, cores: 4, load: null, memPct: 40, memTotal: 100, memUsed: 40, swapPct: null, disks: [], source: 'x', readAt: 7 });
  assert.equal(devs.resources(1)!.cpuPct, 9);
  devs.saveResources(1, { uptimeSec: 6, cpuPct: 11, cores: 4, load: null, memPct: 41, memTotal: 100, memUsed: 41, swapPct: null, disks: [], source: 'x', readAt: 8 });
  assert.equal(devs.resources(1)!.cpuPct, 11, 'each read replaces the last');
  assert.equal(devs.list().find(d => d.id === 1)!.resources!.uptimeSec, 6);
  assert.equal(devs.list().find(d => d.id === 2)!.resources, null);
  cdb.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a front-panel port is kept even when the device reports it with a virtual interface type', async () => {
  const rows: Record<string, SnmpValue> = {
    '1.3.6.1.2.1.2.2.1.2.78': 'TwentyFiveGigE1/1/14', '1.3.6.1.2.1.31.1.1.1.1.78': 'Twe1/1/14', '1.3.6.1.2.1.2.2.1.3.78': 53, '1.3.6.1.2.1.2.2.1.8.78': 1,
    '1.3.6.1.2.1.2.2.1.2.90': 'Vlan90', '1.3.6.1.2.1.31.1.1.1.1.90': 'Vl90', '1.3.6.1.2.1.2.2.1.3.90': 53, '1.3.6.1.2.1.2.2.1.8.90': 1,
    '1.3.6.1.2.1.2.2.1.2.91': 'Loopback0', '1.3.6.1.2.1.31.1.1.1.1.91': 'Lo0', '1.3.6.1.2.1.2.2.1.3.91': 24, '1.3.6.1.2.1.2.2.1.8.91': 1
  };
  const c = { column: async (col: string) => { const m = new Map<string, SnmpValue>(); for (const [o, v] of Object.entries(rows)) if (o.startsWith(col + '.')) m.set(o.slice(col.length + 1), v); return m; } } as unknown as SnmpClient;
  const hidden: { index: number; name: string }[] = [];
  const r = await readInterfaces(c, false, hidden);
  assert.deepEqual(r.map(i => i.name), ['Twe1/1/14'], 'the port stays; the VLAN and loopback interfaces are still hidden');
  assert.deepEqual(hidden.map(h => [h.index, h.name]).sort((a, b) => a[0] as number - (b[0] as number)), [[90, 'Vl90'], [91, 'Lo0']], 'but their names are kept, so a route or flow on one is not shown as ifNN');
});
