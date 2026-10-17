import test from 'node:test';
import assert from 'node:assert/strict';
import type { SnmpClient, SnmpValue } from '../src/snmp/client.js';
import { diffExtra, hottest, linkOptics, linkWarnings, readBgp, readHealth, readIfExtra, readOspf, readPoe, readSensors, readStp, sensorValue, thresholdLevel, type IfExtra } from '../src/snmp/health.js';
import { readResources } from '../src/snmp/resources.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ConfigDb } from '../src/db/configdb.js';
import { DeviceService } from '../src/snmp/devices.js';
import { EMPTY_HEALTH } from '../src/snmp/health.js';

/** An agent that answers get and column from a flat table of OID -> value. */
function agent(rows: Record<string, SnmpValue>): SnmpClient {
  const get = async (oids: string[]) => {
    const m = new Map<string, { oid: string; type: number; value: SnmpValue }>();
    for (const o of oids) if (o in rows) m.set(o, { oid: o, type: 0, value: rows[o] });
    return m;
  };
  const column = async (col: string) => {
    const m = new Map<string, SnmpValue>();
    for (const [o, v] of Object.entries(rows)) if (o.startsWith(col + '.')) m.set(o.slice(col.length + 1), v);
    return m;
  };
  return { get, column } as unknown as SnmpClient;
}
const CISCO = '1.3.6.1.4.1.9.1.2504';

test('sensor values apply precision and scale', () => {
  assert.equal(sensorValue(45, 9, 0), 45);
  assert.equal(sensorValue(-23, 9, 1), -2.3, 'one decimal place');
  assert.equal(sensorValue(12000, 8, 0), 12, 'milli volts to volts');
  assert.equal(sensorValue(3, 10, 0), 3000, 'kilo');
});

test('threshold relations map to warn and bad', () => {
  const t = [{ severity: 10, relation: 3, value: 60 }, { severity: 30, relation: 3, value: 75 }];
  assert.equal(thresholdLevel(50, t), 'ok');
  assert.equal(thresholdLevel(65, t), 'warn');
  assert.equal(thresholdLevel(80, t), 'bad');
  assert.equal(thresholdLevel(-9, [{ severity: 30, relation: 1, value: -12 }]), 'ok');
  assert.equal(thresholdLevel(-14, [{ severity: 30, relation: 1, value: -12 }]), 'bad');
});

test('Cisco ENTITY-SENSOR rows become temperature, fan and optic sensors with their thresholds applied', async () => {
  const E = '1.3.6.1.4.1.9.9.91.1.1.1.1', N = '1.3.6.1.2.1.47.1.1.1.1.7', T = '1.3.6.1.4.1.9.9.91.1.2.1.1';
  const rows: Record<string, SnmpValue> = {
    [`${N}.1001`]: 'Switch 1 - Mainboard Temperature Sensor', [`${E}.1.1001`]: 8, [`${E}.2.1001`]: 9, [`${E}.3.1001`]: 0, [`${E}.4.1001`]: 66, [`${E}.5.1001`]: 1,
    [`${T}.2.1001.1`]: 10, [`${T}.3.1001.1`]: 3, [`${T}.4.1001.1`]: 60,
    [`${N}.1002`]: 'TenGigabitEthernet1/1/1 Receive Power Sensor', [`${E}.1.1002`]: 14, [`${E}.2.1002`]: 9, [`${E}.3.1002`]: 1, [`${E}.4.1002`]: -52, [`${E}.5.1002`]: 1,
    [`${N}.1003`]: 'TenGigabitEthernet1/1/1 Transmit Power Sensor', [`${E}.1.1003`]: 14, [`${E}.2.1003`]: 9, [`${E}.3.1003`]: 1, [`${E}.4.1003`]: -21, [`${E}.5.1003`]: 1,
    [`${N}.1004`]: 'TenGigabitEthernet1/1/1 Module Temperature Sensor', [`${E}.1.1004`]: 8, [`${E}.2.1004`]: 9, [`${E}.3.1004`]: 0, [`${E}.4.1004`]: 38, [`${E}.5.1004`]: 1,
    [`${N}.1005`]: 'Switch 1 - FAN 1 Speed', [`${E}.1.1005`]: 10, [`${E}.2.1005`]: 9, [`${E}.3.1005`]: 0, [`${E}.4.1005`]: 4200, [`${E}.5.1005`]: 1,
    [`${N}.1006`]: 'Switch 1 - Power Supply B', [`${E}.1.1006`]: 12, [`${E}.2.1006`]: 9, [`${E}.3.1006`]: 0, [`${E}.4.1006`]: 2, [`${E}.5.1006`]: 1,
    [`${N}.1007`]: 'Unused slot sensor', [`${E}.1.1007`]: 8, [`${E}.2.1007`]: 9, [`${E}.3.1007`]: 0, [`${E}.4.1007`]: 0, [`${E}.5.1007`]: 2
  };
  const s = await readSensors(agent(rows), CISCO);
  const by = (n: string) => s.find(x => x.name.includes(n))!;
  assert.equal(by('Mainboard').kind, 'temperature');
  assert.equal(by('Mainboard').value, 66);
  assert.equal(by('Mainboard').state, 'warn', 'over the 60 degree minor threshold');
  assert.equal(by('Receive').kind, 'optic'); assert.equal(by('Receive').optic, 'rx'); assert.equal(by('Receive').value, -5.2); assert.equal(by('Receive').unit, 'dBm');
  assert.equal(by('Transmit').optic, 'tx'); assert.equal(by('Transmit').value, -2.1);
  assert.equal(by('Module Temperature').kind, 'optic'); assert.equal(by('Module Temperature').optic, 'temp');
  assert.equal(by('FAN 1').kind, 'fan'); assert.equal(by('FAN 1').value, 4200);
  assert.equal(by('Power Supply').kind, 'power'); assert.equal(by('Power Supply').state, 'bad', 'a truth value of 2 is a fault');
  assert.equal(by('Unused').state, 'off');
  assert.equal(hottest(s), 66, 'optic and unavailable sensors do not count as the chassis temperature');
  const linked = linkOptics(s, [{ index: 7, name: 'Te1/1/1', descr: 'TenGigabitEthernet1/1/1' }, { index: 8, name: 'Te1/1/10', descr: 'TenGigabitEthernet1/1/10' }]);
  assert.equal(linked.find(x => x.name.includes('Receive'))!.ifIndex, 7, '1/1/1 does not match 1/1/10');
});

test('standard ENTITY-SENSOR, CISCO-ENVMON and Juniper fallbacks', async () => {
  const E = '1.3.6.1.2.1.99.1.1.1', N = '1.3.6.1.2.1.47.1.1.1.1.7';
  const std = await readSensors(agent({ [`${N}.5`]: 'CPU temp', [`${E}.1.5`]: 8, [`${E}.2.5`]: 9, [`${E}.3.5`]: 0, [`${E}.4.5`]: 51, [`${E}.5.5`]: 1 }), '1.3.6.1.4.1.30065.1.3011');
  assert.equal(std.length, 1); assert.equal(std[0].value, 51);

  const env = await readSensors(agent({
    '1.3.6.1.4.1.9.9.13.1.3.1.2.1': 'SW#1, Sensor#1', '1.3.6.1.4.1.9.9.13.1.3.1.7.1': 41, '1.3.6.1.4.1.9.9.13.1.3.1.6.1': 1,
    '1.3.6.1.4.1.9.9.13.1.4.1.2.1': 'Switch#1, Fan#1', '1.3.6.1.4.1.9.9.13.1.4.1.3.1': 3,
    '1.3.6.1.4.1.9.9.13.1.5.1.2.1': 'Switch#1, PowerSupply#1', '1.3.6.1.4.1.9.9.13.1.5.1.3.1': 1
  }), CISCO);
  assert.deepEqual(env.map(s => [s.kind, s.state]), [['temperature', 'ok'], ['fan', 'bad'], ['power', 'ok']]);

  const jnx = await readSensors(agent({
    '1.3.6.1.4.1.2636.3.1.13.1.5.9.1.0.0': 'Routing Engine 0', '1.3.6.1.4.1.2636.3.1.13.1.7.9.1.0.0': 48, '1.3.6.1.4.1.2636.3.1.13.1.6.9.1.0.0': 2,
    '1.3.6.1.4.1.2636.3.1.13.1.5.2.1.0.0': 'PEM 0', '1.3.6.1.4.1.2636.3.1.13.1.6.2.1.0.0': 6,
    '1.3.6.1.4.1.2636.3.1.13.1.5.4.1.0.0': 'Top Fan 1', '1.3.6.1.4.1.2636.3.1.13.1.6.4.1.0.0': 2
  }), '1.3.6.1.4.1.2636.1.1.1.2.5');
  assert.deepEqual(jnx.map(s => [s.kind, s.state]).sort(), [['fan', 'ok'], ['power', 'bad'], ['temperature', 'ok']].sort());
});

test('PoE budget, spanning tree, OSPF and BGP', async () => {
  const poe = await readPoe(agent({
    '1.3.6.1.2.1.105.1.3.1.1.2.1': 740, '1.3.6.1.2.1.105.1.3.1.1.3.1': 1, '1.3.6.1.2.1.105.1.3.1.1.4.1': 185,
    '1.3.6.1.2.1.105.1.1.1.6.1.1': 3, '1.3.6.1.2.1.105.1.1.1.6.1.2': 3, '1.3.6.1.2.1.105.1.1.1.6.1.3': 2, '1.3.6.1.2.1.105.1.1.1.6.1.4': 4
  }));
  assert.deepEqual(poe, [{ group: 1, budgetW: 740, usedW: 185, usedPct: 25, allocW: null, remainingW: null, allocPct: null, status: 'on', portsDelivering: 2, portsFault: 1, portsTotal: 4 }]);

  // a Catalyst stack member (values from a 9300 walk): 474 W drawn, 1,956,760 mW reserved, 106,240 mW left of a 2063 W budget
  const cat = await readPoe(agent({
    '1.3.6.1.2.1.105.1.3.1.1.2.1': 2063, '1.3.6.1.2.1.105.1.3.1.1.3.1': 1, '1.3.6.1.2.1.105.1.3.1.1.4.1': 474,
    '1.3.6.1.4.1.9.9.402.1.3.1.4.1': 1956760, '1.3.6.1.4.1.9.9.402.1.3.1.5.1': 106240
  }));
  assert.deepEqual([cat[0]!.usedW, cat[0]!.usedPct, cat[0]!.allocW, cat[0]!.remainingW, cat[0]!.allocPct], [474, 23, 1956.8, 106.2, 94.9]);

  const stp = await readStp(agent({
    '1.3.6.1.2.1.17.1.1.0': Buffer.from([0, 0x1c, 0x73, 0, 0, 2]), '1.3.6.1.2.1.17.2.5.0': Buffer.from([0x80, 0x01, 0, 0x1c, 0x73, 0, 0, 1]),
    '1.3.6.1.2.1.17.2.4.0': 14, '1.3.6.1.2.1.17.2.3.0': 360000, '1.3.6.1.2.1.17.2.6.0': 4, '1.3.6.1.2.1.17.2.7.0': 3,
    '1.3.6.1.2.1.17.2.15.1.3.1': 5, '1.3.6.1.2.1.17.2.15.1.3.2': 2, '1.3.6.1.2.1.17.2.15.1.3.3': 5
  }));
  assert.equal(stp!.rootId, '32769/00:1c:73:00:00:01'); assert.equal(stp!.isRoot, false); assert.equal(stp!.topChanges, 14);
  assert.equal(stp!.sinceChangeSec, 3600); assert.equal(stp!.blockingPorts, 1); assert.equal(stp!.ports, 3);
  const root = await readStp(agent({ '1.3.6.1.2.1.17.1.1.0': Buffer.from([0, 0x1c, 0x73, 0, 0, 1]), '1.3.6.1.2.1.17.2.5.0': Buffer.from([0x80, 0x01, 0, 0x1c, 0x73, 0, 0, 1]) }));
  assert.equal(root!.isRoot, true);
  assert.equal(await readStp(agent({})), null);

  const ospf = await readOspf(agent({ '1.3.6.1.2.1.14.10.1.6.10.0.0.2.0': 8, '1.3.6.1.2.1.14.10.1.3.10.0.0.2.0': '2.2.2.2', '1.3.6.1.2.1.14.10.1.6.10.0.0.6.0': 3, '1.3.6.1.2.1.14.10.1.3.10.0.0.6.0': '3.3.3.3' }));
  assert.deepEqual(ospf.map(n => [n.address, n.id, n.state, n.level]), [['10.0.0.2', '2.2.2.2', 'full', 'ok'], ['10.0.0.6', '3.3.3.3', 'init', 'warn']]);

  const bgp = await readBgp(agent({
    '1.3.6.1.2.1.15.3.1.2.192.0.2.1': 6, '1.3.6.1.2.1.15.3.1.3.192.0.2.1': 2, '1.3.6.1.2.1.15.3.1.9.192.0.2.1': 64500, '1.3.6.1.2.1.15.3.1.16.192.0.2.1': 7200, '1.3.6.1.2.1.15.3.1.10.192.0.2.1': 900, '1.3.6.1.2.1.15.3.1.11.192.0.2.1': 40,
    '1.3.6.1.2.1.15.3.1.2.192.0.2.9': 3, '1.3.6.1.2.1.15.3.1.3.192.0.2.9': 2, '1.3.6.1.2.1.15.3.1.9.192.0.2.9': 64501,
    '1.3.6.1.2.1.15.3.1.2.192.0.2.20': 1, '1.3.6.1.2.1.15.3.1.3.192.0.2.20': 1, '1.3.6.1.2.1.15.2.0': 65000
  }));
  assert.equal(bgp.localAs, 65000);
  assert.deepEqual(bgp.peers.map(p => [p.address, p.state, p.level, p.upSec]), [['192.0.2.1', 'established', 'ok', 7200], ['192.0.2.9', 'active', 'warn', null], ['192.0.2.20', 'idle', 'off', null]]);
  assert.equal(await readHealth(agent({})), null, 'a device with none of it gives nothing');
});

test('interface link quality: totals, deltas and warnings', async () => {
  const rows: Record<string, SnmpValue> = {
    '1.3.6.1.2.1.2.2.1.7.5': 1, '1.3.6.1.2.1.10.7.2.1.19.5': 2, '1.3.6.1.2.1.10.7.2.1.3.5': 1000, '1.3.6.1.2.1.10.7.2.1.4.5': 3, '1.3.6.1.2.1.10.7.2.1.5.5': 4,
    '1.3.6.1.2.1.31.1.1.1.3.5': 10, '1.3.6.1.2.1.31.1.1.1.9.5': 900_000, '1.3.6.1.2.1.31.1.1.1.8.5': 5
  };
  const a = (await readIfExtra(agent(rows), 1_000_000)).get(5)!;
  assert.equal(a.duplex, 'half'); assert.equal(a.admin, 1);
  assert.equal(a.totals.fcs, 1000); assert.equal(a.totals.collisions, 7);
  assert.equal(a.totals.inBc, 900_000, 'the 64-bit counter wins over the 32-bit one');
  assert.equal(a.totals.align, undefined, 'a counter the device does not publish is absent');
  rows['1.3.6.1.2.1.10.7.2.1.3.5'] = 1250; rows['1.3.6.1.2.1.31.1.1.1.9.5'] = 900_000 + 120_000;
  const b = diffExtra(a, (await readIfExtra(agent(rows), 1_060_000)).get(5)!);
  assert.equal(b.dtSec, 60); assert.equal(b.delta!.fcs, 250); assert.equal(b.delta!.inBc, 120_000);
  const w = linkWarnings(b, 1, 1000);
  assert.deepEqual(w.map(x => x.level), ['bad', 'bad', 'warn']);
  assert.match(w[0].text, /Half duplex/); assert.match(w[1].text, /250 frame errors/); assert.match(w[2].text, /2,000 broadcast/);
  const wrapped = diffExtra(a, { ...a, readAt: a.readAt + 60_000, totals: { ...a.totals, fcs: 5 } });
  assert.equal(wrapped.delta!.fcs, undefined, 'a counter that went backwards gives no figure');
  assert.deepEqual(linkWarnings({ ...a, duplex: 'full', delta: null }, 1, 1000), []);
});

test('a busy multicast port is not flagged by its rate alone', () => {
  const x = { readAt: 1, totals: {}, delta: { inMc: 3_000_000, outMc: 3_000_000 }, dtSec: 60, duplex: 'full', admin: 1 } as unknown as IfExtra;   // 100,000 multicast packets per second
  assert.deepEqual(linkWarnings(x, 1, 10_000), []);
  // but storm control actually suppressing packets still is
  const w = linkWarnings({ ...x, delta: { ...x.delta, storm: 40 } } as IfExtra, 1, 10_000);
  assert.equal(w.length, 1); assert.match(w[0].text, /Storm control/);
});

test('vendor CPU, memory and session readers', async () => {
  const fg = await readResources(agent({ '1.3.6.1.4.1.12356.101.4.1.3.0': 23, '1.3.6.1.4.1.12356.101.4.1.4.0': 61, '1.3.6.1.4.1.12356.101.4.1.5.0': 4194304, '1.3.6.1.4.1.12356.101.4.1.8.0': 5120 }), '1.3.6.1.4.1.12356.101.1.1', 1);
  assert.equal(fg!.cpuPct, 23); assert.equal(fg!.memPct, 61); assert.equal(fg!.memTotal, 4294967296); assert.equal(fg!.sessions, 5120); assert.match(fg!.source, /FORTINET/);

  const pa = await readResources(agent({ '1.3.6.1.4.1.25461.2.1.2.3.3.0': 12000, '1.3.6.1.4.1.25461.2.1.2.3.2.0': 200000, '1.3.6.1.2.1.25.3.3.1.2.1': 14 }), '1.3.6.1.4.1.25461.2.3.30', 1);
  assert.equal(pa!.sessions, 12000); assert.equal(pa!.sessionsMax, 200000); assert.equal(pa!.cpuPct, 14, 'CPU still comes from HOST-RESOURCES');

  const jn = await readResources(agent({
    '1.3.6.1.4.1.2636.3.1.13.1.5.9.1.0.0': 'Routing Engine 0', '1.3.6.1.4.1.2636.3.1.13.1.8.9.1.0.0': 17, '1.3.6.1.4.1.2636.3.1.13.1.11.9.1.0.0': 42, '1.3.6.1.4.1.2636.3.1.13.1.15.9.1.0.0': 2048,
    '1.3.6.1.4.1.2636.3.1.13.1.5.7.1.0.0': 'FPC: MPC', '1.3.6.1.4.1.2636.3.1.13.1.8.7.1.0.0': 0
  }), '1.3.6.1.4.1.2636.1.1.1.2.21', 1);
  assert.equal(jn!.cpuPct, 17); assert.equal(jn!.memPct, 42); assert.equal(jn!.memTotal, 2048 * 1048576);

  const hw = await readResources(agent({ '1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5.1': 0, '1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5.16': 31, '1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7.16': 55 }), '1.3.6.1.4.1.2011.2.23.1', 1);
  assert.equal(hw!.cpuPct, 31); assert.equal(hw!.memPct, 55);

  const hp = await readResources(agent({ '1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0': 9, '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.5.1': 300, '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.6.1': 700, '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.7.1': 1000 }), '1.3.6.1.4.1.11.2.3.7.11.50', 1);
  assert.equal(hp!.cpuPct, 9); assert.equal(hp!.memPct, 30);
  const hpBad = await readResources(agent({ '1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0': 9, '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.5.1': 300, '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.6.1': 300, '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.7.1': 1000 }), '1.3.6.1.4.1.11.2.3.7.11.50', 1);
  assert.equal(hpBad!.memPct, null, 'memory columns that do not add up are not guessed at');
});

test('health and link quality are stored, optics are tied to their interface, and removal forgets them', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-health-'));
  const cdb = new ConfigDb(dir);
  const db = cdb.db;
  db.prepare("INSERT INTO devices(id, name, ip, cred_id, added_at) VALUES (1, 'sw', '10.0.0.2', 1, 0)").run();
  db.prepare("INSERT INTO interfaces(dev_id, if_index, name, descr, if_type, mac) VALUES (1, 7, 'Te1/1/1', 'TenGigabitEthernet1/1/1', 6, '')").run();
  const devs = new DeviceService(cdb, { list: () => [] } as never, {} as never, {} as never);
  assert.equal(devs.health(1), null);
  const h = EMPTY_HEALTH(1000);
  h.sensors = [{ id: 'cisco:1', kind: 'optic', name: 'TenGigabitEthernet1/1/1 Receive Power Sensor', value: -5.2, unit: 'dBm', state: 'ok', stateText: 'ok', optic: 'rx' }];
  devs.saveHealth(1, h);
  assert.equal(devs.health(1)!.sensors[0].ifIndex, 7);
  const x = (readAt: number, fcs: number): IfExtra => ({ duplex: 'full', admin: 1, totals: { fcs }, delta: null, dtSec: null, readAt });
  devs.saveIfExtra(1, new Map([[7, x(1_000_000, 10)]]));
  assert.equal(devs.ifExtra(1).get(7)!.delta, null, 'the first read has nothing to compare with');
  devs.saveIfExtra(1, new Map([[7, x(1_060_000, 25)]]));
  assert.equal(devs.ifExtra(1).get(7)!.delta!.fcs, 15);
  assert.equal(devs.ifExtra(1).get(7)!.dtSec, 60);
  devs.saveHealth(1, null);
  assert.equal(devs.health(1), null, 'a device that stops publishing health loses the stale record');
  cdb.close();
  fs.rmSync(dir, { recursive: true, force: true });
});
