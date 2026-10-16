import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { SnmpClient, SnmpValue } from '../src/snmp/client.js';
import { compareOut, expectationFor, readMulticast, withLoadRates } from '../src/snmp/multicast.js';
import { ConfigDb } from '../src/db/configdb.js';
import { DeviceService } from '../src/snmp/devices.js';

/**
 * Rows from a real walk of a Catalyst 9300 stack (IOS XE 17.18), cut down to 25 routes and the groups they belong to:
 * IPMROUTE-STD-MIB, CISCO-IPMROUTE-MIB, IGMP-STD-MIB cache, PIM-MIB interfaces, neighbours and RPs, and the ifName of the interfaces involved.
 */
const FIX = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, '..', '..', 'test', 'fixtures', 'mcast-c9300.json'), 'utf8')) as Record<string, SnmpValue>;

function agent(rows: Record<string, SnmpValue>): SnmpClient {
  const column = async (col: string) => {
    const m = new Map<string, SnmpValue>();
    for (const [o, v] of Object.entries(rows)) if (o.startsWith(col + '.')) m.set(o.slice(col.length + 1), v);
    return m;
  };
  return { column } as unknown as SnmpClient;
}
const only = (keep: (oid: string) => boolean) => Object.fromEntries(Object.entries(FIX).filter(([o]) => keep(o)));

test('reads routes, outgoing interfaces, rates and flags from the Cisco and standard tables', async () => {
  const m = (await readMulticast(agent(FIX), 1234))!;
  assert.ok(m);
  assert.equal(m.source, 'cisco');
  assert.equal(m.routes.length, 25);
  assert.equal(m.readAt, 1234);
  const r = m.routes.find(x => x.group === '224.0.1.129' && x.source === '10.13.192.136')!;
  assert.equal(r.inIfIndex, 735);
  assert.deepEqual(r.oifs.map(o => o.ifIndex), [104, 107, 110, 427]);
  assert.ok(r.oifs.every(o => o.forwarding));
  assert.equal(r.rp, '10.10.30.1', 'the rendezvous point comes from the PIM-MIB RP table, keyed by group');
  const star = m.routes.find(x => x.group === '224.0.1.22' && x.source === '0.0.0.0')!;
  assert.equal(star.inIfIndex, 427);
  assert.deepEqual(star.oifs.map(o => o.ifIndex), [104, 734, 736]);
  assert.equal(star.rp, '10.10.30.1');
  assert.ok(Array.isArray(star.flags));
});

test('IGMP cache gives the host that joined each group on each interface', async () => {
  const m = (await readMulticast(agent(FIX)))!;
  const j = m.receivers.find(x => x.group === '224.0.1.22' && x.ifIndex === 734)!;
  assert.equal(j.lastReporter, '10.243.212.34');
  assert.equal(j.self, false);
  const self = m.receivers.find(x => x.group === '224.0.1.40' && x.ifIndex === 737)!;
  assert.equal(self.self, true, 'the router itself is a member of 224.0.1.40');
  assert.equal(self.lastReporter, '10.7.227.97');
  assert.ok(j.expirySec !== null && j.expirySec > 0 && j.expirySec < 300);
});

test('PIM interfaces, designated routers and neighbours are read', async () => {
  const m = (await readMulticast(agent(FIX)))!;
  assert.equal(m.pimInterfaces.length, 19);
  const i81 = m.pimInterfaces.find(x => x.ifIndex === 81)!;
  assert.equal(i81.mode, 'sparse');
  assert.equal(i81.dr, '10.201.168.74');
  assert.equal(m.pimInterfaces.find(x => x.ifIndex === 92)!.dr, null, 'a DR of 0.0.0.0 is no DR');
  assert.deepEqual(m.neighbors.sort((a, b) => a.ifIndex - b.ifIndex), [{ address: '10.201.168.73', ifIndex: 81 }, { address: '10.201.168.77', ifIndex: 427 }]);
});

test('without the Cisco table the standard tables still give routes and receivers, just no rate', async () => {
  const m = (await readMulticast(agent(only(o => !o.startsWith('1.3.6.1.4.1.9.10.'))))!)!;
  assert.equal(m.source, 'standard');
  assert.equal(m.routes.length, 25);
  assert.ok(m.routes.every(r => r.bps === null && r.flags.length === 0));
  assert.ok(m.routes.some(r => r.oifs.length));
});

test('a device with no multicast tables gives null', async () => {
  assert.equal(await readMulticast(agent({})), null);
  assert.equal(await readMulticast(agent(only(o => o.startsWith('1.3.6.1.3.61.')))), null, 'PIM interfaces alone are not multicast state');
});

test('pruned interfaces are kept but not counted as where the traffic goes', async () => {
  const rows = { ...FIX };
  const k = '1.3.6.1.2.1.83.1.1.3.1.6.224.0.1.129.10.13.192.136.255.255.255.255.107.224.0.1.129';
  assert.equal(rows[k], 2);
  rows[k] = 1;
  const m = (await readMulticast(agent(rows)))!;
  const e = expectationFor(m, '224.0.1.129', '10.13.192.136');
  assert.deepEqual(e.expectedOut, [104, 110, 427]);
  assert.deepEqual(e.pruned, [107]);
});

test('the route for a stream is its (S,G) entry, else (*,G)', async () => {
  const m = (await readMulticast(agent(FIX)))!;
  assert.equal(expectationFor(m, '224.0.1.129', '10.13.192.136').route!.source, '10.13.192.136');
  const e = expectationFor(m, '224.0.1.22', '10.99.99.99');
  assert.equal(e.route!.source, '0.0.0.0', 'a source with no route of its own follows the shared tree');
  assert.deepEqual(e.expectedOut, [104, 734, 736]);
  assert.deepEqual(e.joined.map(j => j.ifIndex).sort(), [104, 734, 736]);
  assert.equal(expectationFor(m, '239.1.1.1', '10.1.1.1').route, null);
});

test('comparing NetFlow with the device: confirmed, not seen, unexpected, wrong ingress', async () => {
  const m = (await readMulticast(agent(FIX)))!;
  const e = expectationFor(m, '224.0.1.129', '10.13.192.136');
  assert.deepEqual(compareOut(e, 735, [104, 0]), { confirmed: [104], notSeen: [107, 110, 427], unexpected: [], inMismatch: null });
  const c = compareOut(e, 800, [104, 999]);
  assert.deepEqual(c.unexpected, [999]);
  assert.deepEqual(c.inMismatch, { flow: 800, route: 735 });
  assert.equal(compareOut(e, null, []).inMismatch, null);
});

test('the latest multicast state is stored per device and removed when the device stops publishing it', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mc-'));
  const cdb = new ConfigDb(dir);
  const devs = new DeviceService(cdb, { list: () => [] } as never, {} as never, {} as never);
  const m = (await readMulticast(agent(FIX), 5000))!;
  devs.saveMulticast(1, m);
  assert.equal(devs.multicast(1)!.routes.length, 25);
  assert.equal(devs.multicast(1)!.receivers.length, m.receivers.length);
  devs.saveMulticast(1, null);
  assert.equal(devs.multicast(1), null);
  cdb.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

/* ------------------------------------------------------------------ the plan: what the routers say beside what NetFlow saw */
import { buildPlan } from '../src/snmp/multicast_plan.js';

async function planFor(group: string, source: string, flows: Map<number, { inIfs: number[]; outIfs: number[] }>, mutate?: (r: Record<string, SnmpValue>) => void, readAgo = 0) {
  const rows = { ...FIX }; mutate?.(rows);
  const now = 10_000_000;
  const mc = (await readMulticast(agent(rows), now - readAgo))!;
  const names: Record<number, string> = { 104: 'Vl104', 107: 'Vl107', 110: 'Vl110', 427: 'Te1/1/1', 735: 'Vl735', 734: 'Vl734', 736: 'Vl736', 737: 'Vl737' };
  return buildPlan({ group, source, firstSeen: now - 60_000, lastSeen: now - 1000, now, devices: [{ devId: 1, name: 'SW-A', role: 'switch', mc, ifName: i => names[i] ?? `if${i}` }], flows });
}

test('a stream whose flows agree with the router is consistent and lists where it goes', async () => {
  const p = await planFor('224.0.1.129', '10.13.192.136', new Map([[1, { inIfs: [735], outIfs: [104] }]]));
  assert.equal(p.level, 'ok');
  const d = p.devices[0]!;
  assert.equal(d.exported, true);
  assert.equal(d.route!.inIf, 'Vl735');
  assert.deepEqual(d.outgoing.map(o => [o.name, o.seenInFlow]), [['Vl104', true], ['Vl107', false], ['Vl110', false], ['Te1/1/1', false]]);
  assert.equal(p.forwardingTo, 4);
  assert.equal(d.route!.sharedTree, false);
  assert.ok(d.findings.every(f => f.level !== 'warn'));
  assert.deepEqual(d.strayJoins, [], 'a join on the interface the stream arrives on is on the source\'s own segment, not a missing receiver');
  assert.match(d.findings.map(f => f.text).join(' '), /on Vl735 \(10\.13\.192\.169\) joined the group on the segment the stream arrives on/);
});

test('an ingress interface that differs from the route, and an egress the router does not list, are warnings', async () => {
  const p = await planFor('224.0.1.129', '10.13.192.136', new Map([[1, { inIfs: [800], outIfs: [999] }]]));
  assert.equal(p.level, 'warn');
  const t = p.devices[0]!.findings.filter(f => f.level === 'warn').map(f => f.text).join(' | ');
  assert.match(t, /arriving on if800, but the multicast route expects it on Vl735/);
  assert.match(t, /leaving if999/);
});

test('a host that joined on an interface the route does not forward to is flagged', async () => {
  const p = await planFor('224.0.1.22', '0.0.0.0', new Map(), rows => {
    delete rows['1.3.6.1.2.1.83.1.1.3.1.6.224.0.1.22.0.0.0.0.255.255.255.255.734.224.0.1.22'];
  });
  const d = p.devices[0]!;
  assert.equal(d.strayJoins.length, 1);
  assert.equal(d.strayJoins[0]!.name, 'Vl734');
  assert.equal(d.strayJoins[0]!.reporter, '10.243.212.34');
  assert.equal(p.level, 'warn');
});

test('a route nothing is joined to says the traffic ends at the device', async () => {
  const rows: Record<string, SnmpValue> = {};
  const noOif = Object.keys(FIX).filter(o => o.startsWith('1.3.6.1.2.1.83.1.1.2.1.5.')).map(o => o.slice('1.3.6.1.2.1.83.1.1.2.1.5.'.length)).find(k => !Object.keys(FIX).some(o => o.startsWith('1.3.6.1.2.1.83.1.1.3.1.6.' + k + '.')))!;
  assert.ok(noOif, 'the fixture has a route with no outgoing interfaces');
  const g = noOif.split('.').slice(0, 4).join('.'), s = noOif.split('.').slice(4, 8).join('.');
  void rows;
  const p = await planFor(g, s, new Map([[1, { inIfs: [], outIfs: [] }]]));
  const d = p.devices[0]!;
  assert.equal(d.outgoing.length, 0);
  assert.match(d.findings.map(f => f.text).join(' '), /forwarding it nowhere/);
  assert.equal(p.forwardingTo, 0);
});

test('a device that sent flows but has no route for the group is flagged; one that neither sent nor knows it is left out', async () => {
  const p = await planFor('239.9.9.9', '10.1.1.1', new Map([[1, { inIfs: [735], outIfs: [] }]]));
  assert.equal(p.devices.length, 1);
  assert.equal(p.devices[0]!.route, null);
  assert.match(p.devices[0]!.findings[0]!.text, /no multicast route for 239\.9\.9\.9/);
  const q = await planFor('239.9.9.9', '10.1.1.1', new Map());
  assert.equal(q.devices.length, 0);
  assert.equal(q.level, 'info');
});

test('state older than ten minutes is marked out of date', async () => {
  const p = await planFor('224.0.1.129', '10.13.192.136', new Map(), undefined, 15 * 60_000);
  assert.equal(p.devices[0]!.stale, true);
  assert.match(p.devices[0]!.findings.map(f => f.text).join(' '), /15 minutes ago/);
});

/** ipMRouteInterfaceTable rows from the same walk: 19 interfaces with multicast byte counters. */
const IFLOAD = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, '..', '..', 'test', 'fixtures', 'mcast-if-c9300.json'), 'utf8')) as Record<string, SnmpValue>;

test('per-interface multicast bytes are read, using the 64-bit counters', async () => {
  const m = (await readMulticast(agent({ ...FIX, ...IFLOAD }), 1000))!;
  assert.equal(m.interfaces!.length, 19);
  const i = m.interfaces!.find(x => x.ifIndex === 110)!;
  assert.equal(i.inOctets, 67536405); assert.equal(i.inBps, null, 'no earlier read yet');
});

test('rates come from the difference to the previous read, and a counter that went back gives none', async () => {
  const a = (await readMulticast(agent({ ...FIX, ...IFLOAD }), 1_000_000))!;
  const rows = { ...FIX, ...IFLOAD, '1.3.6.1.2.1.83.1.1.4.1.7.110': 67536405 + 7_500_000, '1.3.6.1.2.1.83.1.1.4.1.7.81': 100 };
  const b = withLoadRates((await readMulticast(agent(rows), 1_060_000))!, a);
  assert.equal(b.interfaces!.find(x => x.ifIndex === 110)!.inBps, 1_000_000, '7.5 MB in 60 s is 1 Mbit/s');
  assert.equal(b.interfaces!.find(x => x.ifIndex === 81)!.inBps, null);
  assert.equal(withLoadRates(b, { ...a, readAt: 1_060_000 }).interfaces!.find(x => x.ifIndex === 110)!.inBps, 1_000_000, 'an identical timestamp leaves the rates alone');
});

test('names of interfaces the multicast tables mention are asked of the device', async () => {
  const asked: string[] = [];
  const c = { get: async (oids: string[]) => {
    asked.push(...oids);
    const m = new Map<string, { oid: string; type: number; value: SnmpValue }>();
    for (const o of oids) if (o === '1.3.6.1.2.1.31.1.1.1.1.78') m.set(o, { oid: o, type: 4, value: 'Vl78' as unknown as SnmpValue });
    return m;
  } } as unknown as SnmpClient;
  const { interfaceNames } = await import('../src/snmp/multicast.js');
  const n = await interfaceNames(c, [78, 78, 0, 79]);
  assert.equal(n[78], 'Vl78');
  assert.equal(n[79], undefined, 'an interface the device does not name is left out');
  assert.ok(asked.every(o => !o.endsWith('.0')), 'ifIndex 0 is never asked for');
  assert.deepEqual(await interfaceNames({} as SnmpClient, [78]), {}, 'a client without get gives no names');
});

test('interfaces whose link is not up are found, so a route is not shown as forwarding out of a dead port', async () => {
  const c = { get: async (oids: string[]) => new Map(oids.map(o => [o, { oid: o, type: 2, value: (o.endsWith('.78') ? 2 : 1) as unknown as SnmpValue }])) } as unknown as SnmpClient;
  const { interfacesDown } = await import('../src/snmp/multicast.js');
  assert.deepEqual(await interfacesDown(c, [78, 80, 0]), [78]);
  assert.deepEqual(await interfacesDown({} as SnmpClient, [78]), []);
});

test('reads the RPF route and failure counter of each route from the real walk', async () => {
  const m = (await readMulticast(agent(FIX), 1))!;
  const r = m.routes.find(x => x.group === '224.0.1.129' && x.source === '0.0.0.0')!;
  assert.deepEqual(r.rpf, { prefix: '10.10.30.1', mask: '255.255.255.255', proto: r.rpf!.proto });
  assert.equal(typeof r.rpfFail, 'number');
});

test('reads the IGMP querier per interface and the rendezvous point mappings', async () => {
  const I = '1.3.6.1.2.1.85.1.1.1', S = '1.3.6.1.3.61.1.1.6.1', C = '1.3.6.1.3.61.1.1.11.1';
  const rows: Record<string, SnmpValue> = {
    ...FIX,
    [`${I}.4.735`]: 2, [`${I}.5.735`]: '10.1.1.2', [`${I}.2.735`]: 125, [`${I}.7.735`]: 360000, [`${I}.8.735`]: 25000,
    [`${I}.4.736`]: 3, [`${I}.5.736`]: '0.0.0.0',
    [`${S}.4.1.224.0.0.0.240.0.0.0.10.10.30.1`]: 150, [`${S}.5.1.224.0.0.0.240.0.0.0.10.10.30.1`]: 12000,
    [`${C}.3.239.0.0.0.255.0.0.0`]: '10.1.1.1'
  };
  const m = (await readMulticast(agent(rows), 1))!;
  assert.deepEqual(m.igmpInterfaces, [
    { ifIndex: 735, querier: '10.1.1.2', version: 2, queryIntervalSec: 125, querierUpSec: 3600, querierExpirySec: 250 },
    { ifIndex: 736, querier: null, version: 3, queryIntervalSec: null, querierUpSec: null, querierExpirySec: null }]);
  assert.deepEqual(m.rpSet, [{ group: '224.0.0.0', mask: '240.0.0.0', rp: '10.10.30.1', holdSec: 150, expirySec: 120 }]);
  assert.deepEqual(m.candidateRps, [{ group: '239.0.0.0', mask: '255.0.0.0', rp: '10.1.1.1' }]);
});

test('reads the IGMP querier of every interface from real walks of a Catalyst 9300 stack and a second switch', async () => {
  const { readIgmpInterfaces } = await import('../src/snmp/multicast.js');
  for (const [file, n] of [['igmpif-c9300.json', 19], ['igmpif-c3850.json', 10]] as const) {
    const rows = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, '..', '..', 'test', 'fixtures', file), 'utf8')) as Record<string, SnmpValue>;
    const list = await readIgmpInterfaces(agent(rows));
    assert.equal(list.length, n, file + ' (a row whose status is notInService is left out)');
    assert.ok(list.every(i => i.version === 2 || i.version === 3), 'version is column 4');
    assert.ok(list.every(i => i.queryIntervalSec === 60), 'the query interval is column 2, in seconds');
    assert.ok(list.some(i => i.querier && i.querierUpSec !== null && i.querierUpSec > 0), 'querier uptime is column 7, in timeticks');
    if (file === 'igmpif-c9300.json') assert.ok(list.some(i => i.querier === null), 'a querier of 0.0.0.0 is no querier');
    assert.ok(list.some(i => (i.querierExpirySec ?? 0) > 0) && list.some(i => i.querierExpirySec === 0), 'expiry is 0 where this router is the querier, and counts down where another router is');
  }
});

test('an NX-OS switch: routes from PIM-MIB, only running PIM and IGMP interfaces, RP set, and multicast load from the IP counters', async () => {
  const rows = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, '..', '..', 'test', 'fixtures', 'nxos-c93180.json'), 'utf8')) as Record<string, SnmpValue>;
  const m = (await readMulticast(agent(rows), 1))!;
  assert.equal(m.routeSource, 'pim', 'no IPMROUTE-STD-MIB on NX-OS');
  assert.equal(m.routes.length, 27);
  assert.ok(m.routes.every(r => r.oifs.length === 0 && r.inIfIndex === null));
  assert.equal(m.routes.filter(r => r.source === '0.0.0.0').length, 1);
  assert.deepEqual(m.routes.find(r => r.source === '0.0.0.0')!.flags, ['rpt']);
  assert.equal(m.pimInterfaces.length, 31, '54 PIM interfaces are listed and 23 are notInService');
  assert.ok(m.pimInterfaces.every(p => p.mode === 'sparse'));
  assert.equal(m.igmpInterfaces!.length, 31);
  assert.deepEqual(m.rpSet!.map(x => [x.group, x.mask, x.rp]), [['224.0.0.0', '240.0.0.0', '10.10.94.254'], ['239.130.0.0', '255.255.0.0', '10.10.30.1']]);
  assert.equal(m.routes.find(r => r.group === '224.0.1.129')!.rp, '10.10.94.254', 'the RP of a group is the closest range that covers it');
  assert.ok(m.neighbors.length === 6);
  const load = m.interfaces!.find(i => i.ifIndex === 436207616)!;
  assert.equal(load.inOctets, 76746524); assert.equal(load.outOctets, 981180);
});

test('an NX-OS chassis row gives the model', async () => {
  const { readEntity, modelText } = await import('../src/snmp/entity.js');
  const rows = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, '..', '..', 'test', 'fixtures', 'nxos-c93180.json'), 'utf8')) as Record<string, SnmpValue>;
  const client = { column: agent(rows).column, get: async (oids: string[]) => new Map(oids.filter(o => o in rows).map(o => [o, { oid: o, type: 4, value: rows[o]! }])) } as unknown as SnmpClient;
  assert.equal(modelText(await readEntity(client, 1)), 'N9K-C93180YC-FX3');
});
