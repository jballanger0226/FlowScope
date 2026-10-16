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
