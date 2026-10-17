import test from 'node:test';
import assert from 'node:assert/strict';
import { pimIssues, type PimPeer } from '../src/snmp/pimcheck.js';
import type { Multicast, McPimIf } from '../src/snmp/multicast.js';

const mc = (pim: McPimIf[], extra: Partial<Multicast> = {}): Multicast => ({ readAt: 1, source: 'standard', routes: [], receivers: [], pimInterfaces: pim, neighbors: [], interfaces: [], truncated: false, ...extra }) as Multicast;
const nm = (ix: number): string => (ix === 99 ? 'Loopback0' : 'Eth' + ix);
const peer = (mode: McPimIf['mode']): PimPeer => ({ name: 'leaf', mc: mc([{ ifIndex: 5, mode, dr: null }]), ips: new Map([['10.0.0.2', 5]]), ifName: nm });

test('dense against sparse on a link is a warning, sparse against sparse-dense only a note, equal modes nothing', () => {
  const me = mc([{ ifIndex: 1, mode: 'sparse', dr: null }], { neighbors: [{ address: '10.0.0.2', ifIndex: 1 }] });
  const a = pimIssues(me, nm, [peer('dense')]);
  assert.equal(a.length, 1); assert.equal(a[0]!.level, 'warn'); assert.match(a[0]!.text, /Eth1 runs PIM sparse, but leaf runs dense on Eth5/);
  assert.equal(pimIssues(me, nm, [peer('sparse-dense')])[0]!.level, 'info');
  assert.deepEqual(pimIssues(me, nm, [peer('sparse')]), []);
  assert.deepEqual(pimIssues(me, nm, []), [], 'a neighbour that is not polled is not guessed at');
});

test('mixed modes are noted but a loopback does not count', () => {
  assert.deepEqual(pimIssues(mc([{ ifIndex: 1, mode: 'sparse', dr: null }, { ifIndex: 99, mode: 'dense', dr: null }]), nm, []), []);
  const x = pimIssues(mc([{ ifIndex: 1, mode: 'sparse', dr: null }, { ifIndex: 2, mode: 'dense', dr: null }]), nm, []);
  assert.equal(x.length, 1); assert.equal(x[0]!.kind, 'mixed'); assert.equal(x[0]!.level, 'info');
});

test('a dense group on a sparse-dense interface with no RP is a warning, Auto-RP groups are not', () => {
  const r = (group: string, rp: string | null) => ({ group, source: '0.0.0.0', inIfIndex: 1, upstream: null, protocol: 9, pkts: null, bps: null, expirySec: null, flags: [], rp, oifs: [] });
  const x = pimIssues(mc([{ ifIndex: 1, mode: 'sparse-dense', dr: null }], { routes: [r('239.1.1.1', null), r('224.0.1.40', null), r('239.2.2.2', '10.0.0.9')] as never }), nm, []);
  assert.equal(x.length, 1); assert.equal(x[0]!.kind, 'no-rp'); assert.match(x[0]!.text, /239\.1\.1\.1/); assert.ok(!/224\.0\.1\.40|239\.2\.2\.2/.test(x[0]!.text));
});

test('no querier where hosts joined, RPF failures and a missing RP are reported', () => {
  const route = { group: '239.1.1.1', source: '10.1.1.1', inIfIndex: 1, upstream: null, protocol: 8, pkts: null, bps: null, expirySec: null, flags: [], rp: null, oifs: [], rpfFail: 1234 };
  const x = pimIssues(mc([{ ifIndex: 1, mode: 'sparse', dr: null }], {
    igmpInterfaces: [{ ifIndex: 2, querier: null, version: 2, queryIntervalSec: 125, querierUpSec: null, querierExpirySec: null }, { ifIndex: 3, querier: null, version: 2, queryIntervalSec: 125, querierUpSec: null, querierExpirySec: null }],
    receivers: [{ group: '239.1.1.1', ifIndex: 2, lastReporter: '10.0.0.5', expirySec: 10, self: false }], routes: [route] as never, rpSet: [], candidateRps: []
  }), nm, []);
  const k = x.map(i => i.kind).sort();
  assert.deepEqual(k, ['no-querier', 'rp-unknown', 'rpf']);
  assert.match(x.find(i => i.kind === 'no-querier')!.text, /Eth2/); assert.ok(!/Eth3/.test(x.find(i => i.kind === 'no-querier')!.text));
  assert.match(x.find(i => i.kind === 'rpf')!.text, /1,234/);
});

test('multicast lost on a link: the neighbour sends clearly more than this router receives', async () => {
  const { multicastLoss } = await import('../src/snmp/pimcheck.js');
  const load = (ifIndex: number, inBps: number | null, outBps: number | null) => ({ ifIndex, inOctets: null, outOctets: null, inBps, outBps, ttl: null, rateLimit: null });
  const me = (inBps: number) => mc([{ ifIndex: 1, mode: 'sparse', dr: null }], { neighbors: [{ address: '10.0.0.2', ifIndex: 1 }], interfaces: [load(1, inBps, 0)] });
  const peerSending = (outBps: number): PimPeer => ({ name: 'leaf', mc: mc([{ ifIndex: 5, mode: 'sparse', dr: null }], { interfaces: [load(5, 0, outBps)] }), ips: new Map([['10.0.0.2', 5]]), ifName: nm });
  const lost = multicastLoss(me(2_000_000), [peerSending(10_000_000)]);
  assert.equal(lost.length, 1); assert.equal(lost[0]!.peer, 'leaf'); assert.equal(lost[0]!.peerIf, 'Eth5');
  assert.equal(pimIssues(me(2_000_000), nm, [peerSending(10_000_000)]).filter(i => i.kind === 'link-loss').length, 1);
  assert.deepEqual(multicastLoss(me(9_800_000), [peerSending(10_000_000)]), [], 'a small gap is two reads taken at different moments');
  assert.deepEqual(multicastLoss(me(0), [peerSending(100_000)]), [], 'a trickle is ignored');
  assert.deepEqual(multicastLoss(me(0), []), [], 'an unpolled neighbour is not guessed at');
});

test('wrong-interface drops are a warning only while the counter grows, history otherwise', async () => {
  const { withLoadRates } = await import('../src/snmp/multicast.js');
  const route = (fail: number) => ({ group: '239.1.1.1', source: '10.1.1.1', inIfIndex: 1, upstream: null, protocol: 8, pkts: null, bps: null, expirySec: null, flags: [], rp: null, oifs: [], rpfFail: fail });
  const at = (t: number, fail: number) => ({ ...mc([{ ifIndex: 1, mode: 'sparse', dr: null }]), readAt: t, routes: [route(fail)] as never });
  const same = withLoadRates(at(120_000, 4), at(0, 4));
  assert.equal(same.routes[0]!.rpfNew, 0);
  let x = pimIssues(same, nm, []).find(i => i.kind === 'rpf')!;
  assert.equal(x.level, 'info'); assert.match(x.text, /history/);
  const grew = withLoadRates(at(240_000, 19), at(120_000, 4));
  assert.equal(grew.routes[0]!.rpfNew, 15);
  x = pimIssues(grew, nm, []).find(i => i.kind === 'rpf')!;
  assert.equal(x.level, 'warn'); assert.match(x.text, /right now/); assert.match(x.text, /15 since the last read/);
  assert.equal(withLoadRates(at(240_000, 2), at(120_000, 4)).routes[0]!.rpfNew, null, 'a counter that went backwards was reset');
  assert.equal(withLoadRates(at(120_000, 4), null).routes[0]!.rpfNew, undefined);
});

test('a few wrong-interface drops against a busy route are minor, a large share is a warning', async () => {
  const { rpfSignificant } = await import('../src/snmp/multicast.js');
  assert.equal(rpfSignificant({ rpfNew: 4, pktsNew: 100 }), false, 'under 10 packets in a read');
  assert.equal(rpfSignificant({ rpfNew: 40, pktsNew: 100_000 }), false, 'a tiny share of a busy stream: an equal-cost path');
  assert.equal(rpfSignificant({ rpfNew: 40, pktsNew: 200 }), true, 'a sixth of the stream');
  assert.equal(rpfSignificant({ rpfNew: 400, pktsNew: 0 }), true, 'nothing forwarded, everything dropped');
  assert.equal(rpfSignificant({ rpfNew: 40, pktsNew: null }), true, 'no packet counter to compare with');
  assert.equal(rpfSignificant({ rpfNew: 0, pktsNew: 0 }), false);
  const route = (fail: number, pkts: number) => ({ group: '239.1.1.1', source: '10.1.1.1', inIfIndex: 1, upstream: null, protocol: 8, pkts, bps: null, expirySec: null, flags: [], rp: null, oifs: [], rpfFail: fail });
  const { withLoadRates } = await import('../src/snmp/multicast.js');
  const at = (t: number, fail: number, pkts: number) => ({ ...mc([{ ifIndex: 1, mode: 'sparse', dr: null }]), readAt: t, routes: [route(fail, pkts)] as never });
  const minor = withLoadRates(at(120_000, 50, 1_000_000), at(0, 10, 0));
  assert.equal(minor.routes[0]!.pktsNew, 1_000_000);
  const x = pimIssues(minor, nm, []).find(i => i.kind === 'rpf')!;
  assert.equal(x.level, 'info'); assert.match(x.text, /equal-cost/);
});
