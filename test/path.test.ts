import test from 'node:test';
import assert from 'node:assert/strict';
import { enrichPath, matchDevice, neighborViews, portKey, type PathEnv, type PathNeighbor, type PathDevice } from '../src/analysis/path.js';
import type { HopView, StreamDetail } from '../src/analysis/hops.js';

// OPNsense (dev 1) -- Te1/1/3 -- basement switch (dev 2) -- Gi1/0/46 -- access point (not polled) -- the destination host
const DEVS: PathDevice[] = [
  { id: 1, name: 'OPNsense.net.ballanger.org', sysName: 'OPNsense', ips: ['192.168.254.1'] },
  { id: 2, name: 'NICHOLAS-SW-BASEMENT-STP.net.ballanger.org', sysName: '', ips: ['192.168.100.10'] }
];
const IFS: Record<number, Record<number, string>> = { 1: { 17: 'if17', 18: 'if18' }, 2: { 1: 'Te1/1/3', 46: 'Gi1/0/46', 47: 'Gi1/0/47' } };
const NB: Record<number, PathNeighbor[]> = {
  1: [{ ifIndex: 17, proto: 'lldp', name: 'NICHOLAS-SW-BASEMENT-STP', port: 'TenGigabitEthernet1/1/3', ip: '', kind: 'infra', caps: 'bridge,router' }],
  2: [
    { ifIndex: 1, proto: 'cdp', name: 'OPNsense.net.ballanger.org', port: 'igb1', ip: '192.168.254.1', kind: 'infra', caps: 'router' },
    { ifIndex: 46, proto: 'cdp', name: 'AP-LIVING', port: 'GigabitEthernet0', ip: '192.168.10.5', kind: 'ap', caps: 'switch' },
    { ifIndex: 46, proto: 'lldp', name: 'AP-LIVING', port: 'GigabitEthernet0', ip: '', kind: 'ap', caps: 'wlan-ap' }
  ]
};
function env(over: Partial<PathEnv> = {}): PathEnv {
  return {
    devices: () => DEVS,
    ifName: (d, i) => IFS[d]?.[i] ?? `if${i}`,
    ifIndexByName: (d, n) => { const e = Object.entries(IFS[d] ?? {}).find(([, v]) => portKey(v) === portKey(n)); return e ? Number(e[0]) : null; },
    neighborsOf: (d, i) => (NB[d] ?? []).filter(n => n.ifIndex === i),
    neighborsOfDevice: d => NB[d] ?? [],
    locate: () => null,
    ...over
  };
}
const hop = (n: number, exporter: string, inIx: number, outIx: number, devId: number, extra: Partial<HopView> = {}): HopView => ({
  n, exporter, dev: devId === 1 ? 'OPNsense' : 'switch', role: 'device', inIf: IFS[devId]?.[inIx] ?? '—', outIf: IFS[devId]?.[outIx] ?? '—', inIfIndex: inIx, outIfIndex: outIx, outIfs: outIx ? [IFS[devId]?.[outIx] ?? ''] : [],
  frameSrc: null, frameDst: null, vlan: null, vlanName: '', ttl: null, ttlExpired: null, dscpIn: 0, dscpOut: null, dscpInS: 'CS0', dscpOutS: 'not reported', qosChanged: false,
  pkts: 10, bytes: 100, firstSeen: 0, lastSeen: 1, linkMs: null, cumMs: null, policy: null, obs: [], ...extra
});
const exporterDev = (ip: string) => ({ '192.168.254.1': 1, '192.168.100.10': 2 } as Record<string, number>)[ip] ?? null;
function detail(forward: HopView[], reverse: HopView[], dst = '192.168.10.39'): StreamDetail {
  return {
    skey: 'k', initiator: { ip: '192.168.254.248', port: 56270 }, responder: { ip: dst, port: 554 }, proto: 6, protoName: 'TCP', app: 'RTSP', t0: 0, t1: 1,
    forward, reverse, qosChanged: false, ttlExpired: false, totals: { fwdBytes: 0, revBytes: 0, fwdPkts: 0, revPkts: 0 }, note: null, multicast: null
  };
}

test('port names match however the device spells them', () => {
  assert.equal(portKey('GigabitEthernet1/0/46'), portKey('Gi1/0/46'));
  assert.equal(portKey('TenGigabitEthernet1/1/3'), portKey('te 1/1/3'));
  assert.notEqual(portKey('Gi1/0/46'), portKey('Gi1/0/47'));
  assert.equal(portKey('Port-channel2'), portKey('Po2'));
});

test('a missing out port is taken from where the reply came in', () => {
  const d = detail(
    [hop(1, '192.168.254.1', 18, 17, 1), hop(2, '192.168.100.10', 1, 0, 2)],
    [hop(1, '192.168.100.10', 46, 1, 2), hop(2, '192.168.254.1', 17, 18, 1)]);
  enrichPath(d, env(), exporterDev);
  const sw = d.forward[1];
  assert.equal(sw.outIf, 'Gi1/0/46'); assert.equal(sw.outIfIndex, 46); assert.equal(sw.outFrom, 'reverse'); assert.deepEqual(sw.outIfs, ['Gi1/0/46']);
  assert.equal(sw.inFrom, 'flow', 'a port the exporter reported is left alone');
  assert.equal(d.forward[0].outIf, 'if17'); assert.equal(d.forward[0].outFrom, 'flow');
});

test('without the other direction, the neighbour table finds the port toward the next device, and the host table the last port', () => {
  // OPNsense exported no out port; the next hop is the switch, which is its CDP/LLDP neighbour on if17
  const a = detail([hop(1, '192.168.254.1', 18, 0, 1), hop(2, '192.168.100.10', 0, 0, 2)], []);
  enrichPath(a, env({ locate: ip => (ip === '192.168.10.39' ? { devId: 2, ifIndex: 46 } : null) }), exporterDev);
  assert.equal(a.forward[0].outIf, 'if17'); assert.equal(a.forward[0].outFrom, 'neighbor');
  assert.equal(a.forward[1].inIf, 'Te1/1/3'); assert.equal(a.forward[1].inFrom, 'neighbor');
  assert.equal(a.forward[1].outIf, 'Gi1/0/46'); assert.equal(a.forward[1].outFrom, 'host');
});

test('a host that tracking places on a different switch does not fill the port', () => {
  const a = detail([hop(1, '192.168.100.10', 1, 0, 2)], []);
  enrichPath(a, env({ locate: () => ({ devId: 1, ifIndex: 17 }) }), exporterDev);
  assert.equal(a.forward[0].outIfIndex, 0); assert.equal(a.forward[0].outIf, '—'); assert.equal(a.forward[0].outFrom, undefined);
});

test('two ports toward the same neighbour are not guessed between', () => {
  const nb: Record<number, PathNeighbor[]> = { ...NB, 1: [...NB[1], { ...NB[1][0], ifIndex: 18 }] };
  const a = detail([hop(1, '192.168.254.1', 0, 0, 1), hop(2, '192.168.100.10', 1, 0, 2)], []);
  enrichPath(a, env({ neighborsOf: (d, i) => (nb[d] ?? []).filter(n => n.ifIndex === i), neighborsOfDevice: d => nb[d] ?? [] }), exporterDev);
  assert.equal(a.forward[0].outIfIndex, 0);
});

test('CDP and LLDP for one neighbour are shown once, linked to the polled device when it is one', () => {
  const a = detail([hop(1, '192.168.254.1', 18, 17, 1), hop(2, '192.168.100.10', 1, 46, 2)], []);
  enrichPath(a, env(), exporterDev);
  // OPNsense's LLDP neighbour on if17 has no domain and no address: matched on the first label of its name, and its port to Te1/1/3
  const n = a.forward[0].outNeighbors!;
  assert.equal(n.length, 1);
  assert.deepEqual(n[0].device, { id: 2, name: 'NICHOLAS-SW-BASEMENT-STP.net.ballanger.org' });
  assert.deepEqual(n[0].devicePort, { ifIndex: 1, name: 'Te1/1/3' });
  // the AP on Gi1/0/46 reports over both protocols and is not an SNMP target
  const ap = a.forward[1].outNeighbors!;
  assert.equal(ap.length, 1);
  assert.deepEqual(ap[0].protos, ['cdp', 'lldp']);
  assert.equal(ap[0].ip, '192.168.10.5'); assert.equal(ap[0].device, null); assert.equal(ap[0].kind, 'ap');
  assert.deepEqual(ap[0].caps.sort(), ['switch', 'wlan-ap']);
  assert.equal(a.forward[1].inNeighbors![0].device?.id, 1, 'matched on the management address');
});

test('a neighbour name that fits two devices is not linked to either', () => {
  const devs: PathDevice[] = [{ id: 5, name: 'core-a.site1.example', sysName: '', ips: ['10.0.0.5'] }, { id: 6, name: 'core-a.site2.example', sysName: '', ips: ['10.0.0.6'] }];
  assert.equal(matchDevice({ name: 'core-a', ip: '' }, devs), null);
  assert.equal(matchDevice({ name: 'core-a.site2.example', ip: '' }, devs)?.id, 6);
  assert.equal(matchDevice({ name: 'x', ip: '10.0.0.5' }, devs)?.id, 5);
  assert.equal(matchDevice({ name: 'ab', ip: '' }, [{ id: 7, name: 'ab', sysName: '', ips: [] }])?.id, 7, 'an exact name still matches');
  assert.equal(matchDevice({ name: 'ab.x', ip: '' }, [{ id: 7, name: 'ab.y', sysName: '', ips: [] }]), null, 'very short first labels are not matched loosely');
});

test('multicast streams keep their ports but still list neighbours', () => {
  const d = detail([hop(1, '192.168.100.10', 1, 0, 2)], [], '239.1.1.1');
  enrichPath(d, env({ locate: () => ({ devId: 2, ifIndex: 46 }) }), exporterDev);
  assert.equal(d.forward[0].outIfIndex, 0, 'no port is worked out for a multicast stream');
  assert.equal(d.forward[0].inNeighbors![0].name, 'OPNsense.net.ballanger.org');
});

test('exporters that are not polled devices are left as they are', () => {
  const d = detail([hop(1, '10.9.9.9', 3, 0, 9)], []);
  enrichPath(d, env(), exporterDev);
  assert.equal(d.forward[0].devId, null); assert.equal(d.forward[0].outIfIndex, 0); assert.equal(d.forward[0].inNeighbors, undefined);
});

test('neighborViews is stable for an empty list', () => {
  assert.deepEqual(neighborViews([], env(), DEVS), []);
});
