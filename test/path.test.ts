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
    skey: 'k', initiator: { ip: '192.168.254.248', port: 56270 }, responder: { ip: dst, port: 554 }, proto: 6, protoName: 'TCP', app: 'RTSP', appPort: 554, t0: 0, t1: 1,
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

/* ---- a switch that exports on input and on output reports each packet twice, each half knowing only one port */
import { analyzeStream } from '../src/analysis/hops.js';
import type { FlowRecord } from '../src/collector/types.js';

const rec = (over: Partial<FlowRecord>): FlowRecord => ({
  ts0: 1_000_000, ts1: 1_030_000, exporter: 'sw', inIf: 0, outIf: 0, srcIp: '192.168.254.248', dstIp: '192.168.10.39', proto: 6, sport: 58146, dport: 554,
  flags: 0x1b, tos: 0, postTos: null, ttlMin: null, ttlMax: null, bytes: 1000, pkts: 10, srcMac: null, dstMac: null, vlan: null,
  natSrcIp: null, natDstIp: null, natSport: null, natDport: null, nextHop: null, sampling: 1, ...over
});
const hctx = { deviceName: (ip: string) => ip, deviceRole: () => 'switch', ifName: (_: string, i: number) => (i ? `if${i}` : '—') };

test('input-only and output-only records from one exporter are one hop with both ports, counted once', () => {
  const d = analyzeStream('k', [
    rec({ inIf: 1, outIf: 0, bytes: 5000, pkts: 50 }),
    rec({ inIf: 0, outIf: 46, bytes: 5000, pkts: 50, ts0: 1_000_002 }),
    rec({ inIf: 1, outIf: 0, bytes: 100, pkts: 1, ts0: 1_010_000 })
  ], hctx)!;
  const h = d.forward[0];
  assert.equal(h.inIfIndex, 1); assert.equal(h.outIfIndex, 46);
  assert.equal(h.pkts, 51, 'the larger half, not the sum of both'); assert.equal(h.bytes, 5100);
  assert.ok(!h.obs.some(o => o.kind === 'path'), 'not reported as load sharing');
});

test('records that carry both ports are left alone, and a one-sided exporter stays one-sided', () => {
  const full = analyzeStream('k', [rec({ inIf: 1, outIf: 2, bytes: 700, pkts: 7 })], hctx)!.forward[0];
  assert.equal(full.inIfIndex, 1); assert.equal(full.outIfIndex, 2); assert.equal(full.pkts, 7);
  const half = analyzeStream('k', [rec({ inIf: 1, outIf: 0, bytes: 700, pkts: 7 })], hctx)!.forward[0];
  assert.equal(half.inIfIndex, 1); assert.equal(half.outIfIndex, 0); assert.equal(half.outIf, '—');
  const mixed = analyzeStream('k', [rec({ inIf: 1, outIf: 2 }), rec({ inIf: 3, outIf: 4, bytes: 50 })], hctx)!.forward[0];
  assert.ok(mixed.obs.some(o => o.kind === 'path'), 'two full pairs are still reported as two paths');
});

test('a multicast switch counts its input side, not the replicas', () => {
  const g = '239.1.1.1';
  const d = analyzeStream('k', [
    rec({ dstIp: g, inIf: 1, outIf: 0, bytes: 1000, pkts: 10 }),
    rec({ dstIp: g, inIf: 0, outIf: 5, bytes: 1000, pkts: 10 }), rec({ dstIp: g, inIf: 0, outIf: 6, bytes: 1000, pkts: 10 }), rec({ dstIp: g, inIf: 0, outIf: 7, bytes: 1000, pkts: 10 })
  ], hctx)!.forward[0];
  assert.equal(d.pkts, 10); assert.equal(d.inIfIndex, 1);
});

/* ---- why a MAC, VLAN or TTL is blank: the exporter never sent it */
import { notExported } from '../src/analysis/exported.js';
import { TemplateDecoder } from '../src/collector/decode.js';
import { buildV9 } from '../src/sim/packets.js';

test('what an exporter does not send is read from its templates', () => {
  assert.deepEqual(notExported('IPFIX', new Set([8, 12, 56, 80, 58, 52])), []);
  assert.deepEqual(notExported('IPFIX', new Set([8, 12])), ['MAC addresses', 'VLAN', 'TTL']);
  assert.deepEqual(notExported('IPFIX', new Set([8, 12, 57, 81, 59, 53])), ['MAC addresses (only the output-side fields are sent)', 'VLAN (only the output-side field is sent)']);
  assert.equal(notExported('v5', null).length, 3);
  assert.deepEqual(notExported('v9', null), [], 'nothing is claimed when no template has been seen');
});

test('the decoder reports the fields in an exporter\'s data templates', () => {
  const dec = new TemplateDecoder();
  assert.equal(dec.fieldsOf('10.0.0.1'), null);
  const f: [number, number][] = [[8, 4], [12, 4], [1, 4], [2, 4], [10, 4], [14, 4], [4, 1], [7, 2], [11, 2]];
  dec.decode(buildV9([rec({})], { nowMs: Date.now(), domain: 1, fields: f }), '10.0.0.1');
  const ids = dec.fieldsOf('10.0.0.1')!;
  assert.ok(ids.has(8) && ids.has(10) && ids.has(14));
  assert.ok(!ids.has(56) && !ids.has(58) && !ids.has(52));
  assert.equal(dec.fieldsOf('10.0.0.11'), null, 'another exporter whose address starts the same is not confused with it');
});

test('the MAC addresses and VLAN of a merged hop come from whichever half has them', () => {
  const h = analyzeStream('k', [
    rec({ inIf: 1, outIf: 0, bytes: 5000, pkts: 50 }),
    rec({ inIf: 0, outIf: 46, bytes: 5000, pkts: 50, srcMac: 'aa:aa:aa:aa:aa:01', dstMac: 'aa:aa:aa:aa:aa:02', vlan: 150 })
  ], hctx)!.forward[0];
  assert.equal(h.frameSrc, 'aa:aa:aa:aa:aa:01'); assert.equal(h.frameDst, 'aa:aa:aa:aa:aa:02'); assert.equal(h.vlan, 150);
});

test('queue drops: a huge count at a tiny rate is noted, not flagged; a real rate is flagged', () => {
  const recs = [rec({ inIf: 1, outIf: 2 })];
  const withDrops = (dropPct: number, dropPkts: number) => analyzeStream('k', recs, { ...hctx, classDrops: () => [{ cls: 'class-default', dropPct, dropPkts }] })!.forward[0].obs.find(o => o.kind === 'qdrop')!;
  const tiny = withDrops(0.0003, 6_681_644);
  assert.equal(tiny.severity, 'info');
  assert.match(tiny.text, /6,681,644 packets/); assert.match(tiny.text, /<0\.01%/); assert.match(tiny.text, /whole class/);
  const real = withDrops(2.5, 900);
  assert.equal(real.severity, 'bad'); assert.match(real.text, /2\.50%/);
  assert.equal(withDrops(0.3, 900).severity, 'warn');
});
