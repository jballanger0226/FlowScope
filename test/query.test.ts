import test from 'node:test';
import assert from 'node:assert/strict';
import { parseQuery, parseIpMatch, splitTokens } from '../src/query/tokens.js';
import { analyzeStream } from '../src/analysis/hops.js';
import { appName } from '../src/query/apps.js';
import { ipToN } from '../src/store/ops.js';
import type { FlowRecord } from '../src/collector/types.js';

const res = {
  vlanIdsByName: (t: string) => ('campus'.includes(t.toLowerCase()) ? [140] : []),
  exporterIpsByName: (t: string) => (t.toLowerCase() === 'fw-edge-01' ? ['10.255.0.3'] : [])
};

test('ip matching forms', () => {
  assert.deepEqual(parseIpMatch('10.1.4.0/24'), { lo: ipToN('10.1.4.0'), hi: ipToN('10.1.4.255') });
  assert.deepEqual(parseIpMatch('10.1.4.5'), { lo: ipToN('10.1.4.5'), hi: ipToN('10.1.4.5') });
  assert.deepEqual(parseIpMatch('10.1'), { lo: ipToN('10.1.0.0'), hi: ipToN('10.1.255.255') });
  assert.equal(parseIpMatch('300.1.1.1'), null);
  assert.deepEqual(parseIpMatch('2001:db8::/32'), { text: '2001:db8::' });
});

test('query parser', () => {
  const p = parseQuery('src:10.1.4.0/24 app:https hop:fw-edge-01 vlan:campus qos:changed proto:tcp dscp:EF "my text"', res);
  assert.deepEqual(p.errors, []);
  const kinds = p.conds.map(c => c.kind);
  assert.deepEqual(kinds, ['src', 'port', 'exporter', 'vlan', 'qos', 'proto', 'dscp', 'text']);
  const bad = parseQuery('proto:nope app:nothing vlan:zzz hop:ghost', res);
  assert.equal(bad.errors.length, 4);
  assert.deepEqual(splitTokens('a b:"c d" e'), ['a', 'b:"c d"', 'e']);
  const t = parseQuery('443 campus 10.9.0.5', res);
  assert.equal(t.conds[0].kind, 'text');
  assert.deepEqual((t.conds[1] as any).vlans, [140]);
  assert.equal(t.conds[2].kind, 'ip');
});

test('app names', () => {
  assert.equal(appName(6, 51522, 443), 'https');
  assert.equal(appName(17, 5353, 53), 'dns');
  assert.equal(appName(1, 0, 0), 'icmp');
});

const base: FlowRecord = {
  ts0: 1_000_000, ts1: 1_030_000, exporter: 'a', inIf: 1, outIf: 2, srcIp: '10.1.4.21', dstIp: '198.51.100.40', proto: 6, sport: 51522, dport: 443,
  flags: 0x1b, tos: 184, postTos: 184, ttlMin: 62, ttlMax: 62, bytes: 12000, pkts: 100, srcMac: 'aa:aa:aa:aa:aa:01', dstMac: 'aa:aa:aa:aa:aa:02',
  vlan: 140, natSrcIp: null, natDstIp: null, natSport: null, natDport: null, nextHop: null, sampling: 1
};
const ctx = {
  deviceName: (ip: string) => 'dev-' + ip, deviceRole: () => 'router', ifName: (_: string, i: number) => 'Gi0/' + i, vlanName: () => 'campus',
  classDrops: (ip: string) => (ip === 'c' ? [{ cls: 'voice', dropPct: 2.5, dropPkts: 12 }] : [])
};

test('hop analysis: order by TTL, loss, remark, slow link, NAT, queue drops', () => {
  const recs: FlowRecord[] = [
    { ...base, exporter: 'c', ttlMax: 60, ttlMin: 60, ts0: 1_000_080, tos: 32, postTos: 32, pkts: 90, bytes: 10800, natSrcIp: '203.0.113.5', natSport: 40001 },
    { ...base, exporter: 'a', ttlMax: 62, ttlMin: 62 },
    { ...base, exporter: 'b', ttlMax: 61, ttlMin: 61, ts0: 1_000_002, postTos: 0 },
    // reverse
    { ...base, exporter: 'c', srcIp: base.dstIp, dstIp: base.srcIp, sport: 443, dport: 51522, ttlMax: 62, ttlMin: 62, ts0: 1_000_010 },
    { ...base, exporter: 'b', srcIp: base.dstIp, dstIp: base.srcIp, sport: 443, dport: 51522, ttlMax: 61, ttlMin: 61, ts0: 1_000_020 },
    { ...base, exporter: 'a', srcIp: base.dstIp, dstIp: base.srcIp, sport: 443, dport: 51522, ttlMax: 60, ttlMin: 60, ts0: 1_000_030 }
  ];
  const d = analyzeStream('k', recs, ctx)!;
  assert.deepEqual(d.forward.map(h => h.exporter), ['a', 'b', 'c']);
  assert.deepEqual(d.reverse.map(h => h.exporter), ['c', 'b', 'a']);
  assert.equal(d.initiator.ip, '10.1.4.21');
  const [a, b, c] = d.forward;
  assert.equal(a.linkMs, null);
  assert.equal(b.linkMs, 2);
  assert.equal(c.linkMs, 78);
  assert.equal(c.cumMs, 80);
  assert.ok(b.qosChanged && b.obs.some(o => o.kind === 'remark'));
  assert.ok(c.obs.some(o => o.kind === 'remark'), 'next hop sees different DSCP');
  assert.ok(c.obs.some(o => o.kind === 'slow'));
  assert.ok(c.obs.some(o => o.kind === 'loss'));
  assert.ok(c.obs.some(o => o.kind === 'nat'));
  assert.ok(c.obs.some(o => o.kind === 'qdrop'));
  assert.ok(d.qosChanged);
  assert.equal(d.app, 'https');
  assert.equal(d.note, null);
});

test('one-directional stream gets a note', () => {
  const d = analyzeStream('k', [base], ctx)!;
  assert.equal(d.reverse.length, 0);
  assert.ok(d.note);
});

test('ttl search token', () => {
  assert.deepEqual(parseQuery('ttl:expired', res).conds, [{ kind: 'ttl', mode: 'expired' }]);
  assert.deepEqual(parseQuery('ttl:ok', res).conds, [{ kind: 'ttl', mode: 'ok' }]);
  assert.equal(parseQuery('ttl:maybe', res).errors.length, 1);
});

test('hop detail points at the router where the TTL ran out', () => {
  const base = { ts0: 1000, ts1: 2000, inIf: 1, outIf: 2, srcIp: '10.1.4.60', dstIp: '198.51.100.40', proto: 17, sport: 40001, dport: 33434, flags: 0, tos: 0, postTos: null, ttlMax: null, bytes: 180, pkts: 3,
    srcMac: null, dstMac: null, vlan: null, natSrcIp: null, natDstIp: null, natSport: null, natDport: null, nextHop: null, sampling: 1 } as FlowRecord;
  const recs: FlowRecord[] = [
    { ...base, exporter: '10.255.0.2', ttlMin: 3, ttlMax: 3 },
    { ...base, exporter: '10.255.0.1', ts0: 1001, ttlMin: 2, ttlMax: 2 },
    { ...base, exporter: '10.255.0.5', ts0: 1002, ttlMin: 1, ttlMax: 1 }
  ];
  const ctx = { deviceName: (ip: string) => 'dev-' + ip.split('.').pop(), deviceRole: () => 'router', ifName: (_ip: string, i: number) => 'if' + i };
  const d = analyzeStream('k', recs, ctx)!;
  assert.equal(d.ttlExpired, true);
  assert.deepEqual(d.forward.map(h => h.ttlExpired), [null, null, 'ttl']);
  assert.match(d.forward[2].obs.find(o => o.kind === 'ttl')!.text, /TTL expired at dev-5: packets arrived with TTL 1/);
  const healthy = analyzeStream('k', recs.map(r => ({ ...r, ttlMin: 60, ttlMax: 60 })), ctx)!;
  assert.equal(healthy.ttlExpired, false);
  // multicast discovery with TTL 1 is not a problem
  const mdns = analyzeStream('k', recs.slice(0, 1).map(r => ({ ...r, dstIp: '224.0.0.251', ttlMin: 1, ttlMax: 1 })), ctx)!;
  assert.equal(mdns.ttlExpired, false);
});

test('well-known ports below 1024 are named, and the name and the number both search', async () => {
  const { wellKnownName, wellKnownPorts } = await import('../src/query/wellknown.js');
  assert.equal(appName(6, 40000, 119), 'nntp');
  assert.equal(appName(6, 119, 40000), 'nntp', 'either side can be the server port');
  assert.equal(appName(17, 40000, 520), 'router', 'UDP 520 is RIP');
  assert.equal(appName(6, 40000, 520), 'efs', 'and TCP 520 is not');
  assert.equal(appName(6, 40000, 514), 'syslog', 'a port the app list already knows keeps that name');
  assert.equal(appName(17, 40000, 319), 'ptp-event');
  assert.equal(appName(6, 40000, 1000), '1000', 'a port below 1024 with no registered service shows as its number');
  assert.equal(appName(6, 40000, 51000), 'tcp/40000', 'above 1023 nothing changes');
  assert.equal(wellKnownName(119, 6), 'nntp'); assert.equal(wellKnownName(65000, 6), null);
  assert.deepEqual(wellKnownPorts('NNTP'), [119]); assert.deepEqual(wellKnownPorts('www'), [80]); assert.deepEqual(wellKnownPorts('netbios'), [137, 138, 139]);
  assert.equal(wellKnownPorts('nothing'), null);

  const ok = parseQuery('port:nntp app:ftp-data 119 microsoft-ds port:domain,22 dport:ptp', res);
  assert.deepEqual(ok.errors, []);
  assert.deepEqual((ok.conds[0] as any).ports, [119]);
  assert.deepEqual(ok.conds[1], { kind: 'port', ports: [20] });
  assert.deepEqual((ok.conds[2] as any).ports, [119], 'the bare number still searches');
  assert.deepEqual((ok.conds[3] as any).ports, [445], 'a bare service name searches its port');
  assert.deepEqual((ok.conds[4] as any).ports, [53, 22]);
  assert.deepEqual((ok.conds[5] as any).ports, [319, 320]);
  assert.equal(parseQuery('port:notaservice', res).errors.length, 1);
  assert.deepEqual(parseQuery('app:https', res).conds[0], { kind: 'port', ports: [443, 8443] }, 'the app list is still consulted first');
});
