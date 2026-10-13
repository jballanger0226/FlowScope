import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeV5, TemplateDecoder } from '../src/collector/decode.js';
import { buildV5, buildV9, buildIpfix } from '../src/sim/packets.js';
import type { FlowRecord } from '../src/collector/types.js';

const now = Date.UTC(2026, 9, 13, 16, 0, 0);
function rec(over: Partial<FlowRecord> = {}): FlowRecord {
  return {
    ts0: now - 30_000, ts1: now - 1000, exporter: '10.255.0.1', inIf: 3, outIf: 7, srcIp: '10.1.4.21', dstIp: '198.51.100.40', proto: 6,
    sport: 51522, dport: 443, flags: 0x1b, tos: 184, postTos: 0, ttlMin: 62, ttlMax: 63, bytes: 123456, pkts: 120,
    srcMac: '00:50:56:01:04:15', dstMac: '00:1c:73:01:aa:bb', vlan: 140, natSrcIp: null, natDstIp: null, natSport: null, natDport: null,
    nextHop: '10.255.0.9', sampling: 1, ...over
  };
}

test('NetFlow v5 round trip', () => {
  const r = rec({ vlan: null, srcMac: null, dstMac: null, postTos: null, ttlMin: null, ttlMax: null });
  const pkt = buildV5([r, rec({ srcIp: '10.9.0.5', sport: 5432 })], { uptime: 7_200_000, nowMs: now });
  const out = decodeV5(pkt, '10.255.0.1');
  assert.equal(out.length, 2);
  assert.equal(out[0].srcIp, '10.1.4.21'); assert.equal(out[0].dport, 443); assert.equal(out[0].bytes, 123456);
  assert.equal(out[0].tos, 184); assert.equal(out[0].flags, 0x1b); assert.equal(out[0].inIf, 3);
  assert.ok(Math.abs(out[0].ts1 - r.ts1) <= 1);
  assert.equal(out[1].srcIp, '10.9.0.5');
});

test('NetFlow v9 with template, then data only', () => {
  const dec = new TemplateDecoder();
  const first = dec.decode(buildV9([rec()], { nowMs: now, domain: 7 }), '10.255.0.1');
  assert.equal(first.length, 1);
  const a = first[0];
  assert.equal(a.srcMac, '00:50:56:01:04:15'); assert.equal(a.vlan, 140); assert.equal(a.postTos, 0);
  assert.equal(a.ttlMax, 63); assert.equal(a.ts0, now - 30_000); assert.equal(a.bytes, 123456);
  const second = dec.decode(buildV9([rec({ bytes: 5 })], { nowMs: now, domain: 7, withTemplate: false }), '10.255.0.1');
  assert.equal(second.length, 1); assert.equal(second[0].bytes, 5);
});

test('IPFIX data before template is held, then released', () => {
  const dec = new TemplateDecoder();
  const early = dec.decode(buildIpfix([rec()], { nowMs: now, withTemplate: false }), '10.255.0.2');
  assert.equal(early.length, 0);
  assert.equal(dec.stats.missingTemplate, 1);
  const released = dec.decode(buildIpfix([], { nowMs: now, withTemplate: true }), '10.255.0.2');
  assert.equal(released.length, 1);
  assert.equal(released[0].dstIp, '198.51.100.40');
});

test('templates are per exporter and domain', () => {
  const dec = new TemplateDecoder();
  dec.decode(buildIpfix([rec()], { nowMs: now, domain: 1 }), '10.255.0.1');
  const other = dec.decode(buildIpfix([rec()], { nowMs: now, domain: 2, withTemplate: false }), '10.255.0.1');
  assert.equal(other.length, 0);
});

test('malformed packets throw instead of crashing', () => {
  const dec = new TemplateDecoder();
  assert.throws(() => dec.decode(Buffer.from([0, 9, 0, 1]), 'x'));
  const sh = Buffer.alloc(30); sh.writeUInt16BE(5, 0); sh.writeUInt16BE(3, 2);
  assert.throws(() => decodeV5(sh, 'x'));
  const bad = buildIpfix([rec()], { nowMs: now });
  bad.writeUInt16BE(bad.length + 50, 2);
  assert.throws(() => dec.decode(bad, 'x'));
});
