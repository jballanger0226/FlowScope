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
