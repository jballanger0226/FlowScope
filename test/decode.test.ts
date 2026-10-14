import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeV5, TemplateDecoder, TEMPLATE_LIMITS } from '../src/collector/decode.js';
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

// --- memory caps (audit C1) ---
function ipfixMsg(sets: Buffer[], domain = 1): Buffer {
  const body = Buffer.concat(sets);
  const h = Buffer.alloc(16); h.writeUInt16BE(10, 0); h.writeUInt16BE(16 + body.length, 2); h.writeUInt32BE(1_700_000_000, 4); h.writeUInt32BE(domain, 12);
  return Buffer.concat([h, body]);
}
function set(id: number, body: Buffer): Buffer { const h = Buffer.alloc(4); h.writeUInt16BE(id, 0); h.writeUInt16BE(4 + body.length, 2); return Buffer.concat([h, body]); }
/** Template set announcing ids first..first+count-1, each with `fields` copies of sourceIPv4Address. */
function tplSet(first: number, count: number, fields = 1): Buffer {
  const parts: Buffer[] = [];
  for (let i = 0; i < count; i++) {
    const t = Buffer.alloc(4 + fields * 4); t.writeUInt16BE(first + i, 0); t.writeUInt16BE(fields, 2);
    for (let f = 0; f < fields; f++) { t.writeUInt16BE(8, 4 + f * 4); t.writeUInt16BE(4, 6 + f * 4); }
    parts.push(t);
  }
  return set(2, Buffer.concat(parts));
}
const ids = (first: number, n: number): Buffer => tplSet(first, n);   // readability
const dataSet = (id: number, ip: number[]): Buffer => set(id, Buffer.from(ip));

test('a sender cannot hold more than the per-exporter template limit', () => {
  const dec = new TemplateDecoder();
  const per = TEMPLATE_LIMITS.perExporter;
  // 64 KiB datagram limit: send in several messages of 1000 templates (8 bytes each)
  for (let first = 256; first < 256 + per; first += 1000) dec.decode(ipfixMsg([ids(first, Math.min(1000, 256 + per - first))]), '203.0.113.9');
  assert.equal(dec.stats.templates, per);
  assert.equal(dec.stats.templatesRejected, 0);
  dec.decode(ipfixMsg([ids(256 + per, 10)]), '203.0.113.9');
  assert.equal(dec.stats.templates, per);
  assert.equal(dec.stats.templatesRejected, 10);
  // an existing template can still be refreshed while the exporter is full
  dec.decode(ipfixMsg([ids(256, 1)]), '203.0.113.9');
  assert.equal(dec.stats.templatesRejected, 10);
  // and other exporters are not affected
  dec.decode(ipfixMsg([ids(256, 1)]), '203.0.113.10');
  assert.equal(dec.stats.templatesRejected, 10);
  assert.equal(dec.decode(ipfixMsg([dataSet(256, [10, 0, 0, 1])]), '203.0.113.10').length, 0); // fields too few for a flow, but no throw
});

test('templates with absurd field counts are refused', () => {
  const dec = new TemplateDecoder();
  dec.decode(ipfixMsg([tplSet(300, 1, TEMPLATE_LIMITS.fields + 1)]), '203.0.113.9');
  assert.equal(dec.stats.templates, 0);
  assert.equal(dec.stats.templatesRejected, 1);
  dec.decode(ipfixMsg([tplSet(300, 1, TEMPLATE_LIMITS.fields)]), '203.0.113.9');
  assert.equal(dec.stats.templates, 1);
});

test('the total template count is bounded and the oldest goes first', () => {
  const dec = new TemplateDecoder();
  const total = TEMPLATE_LIMITS.total;
  let n = 0;
  for (let e = 0; n < total + 50; e++) {
    for (let first = 256; first < 256 + 1000 && n < total + 50; first += 500) { const c = Math.min(500, total + 50 - n); dec.decode(ipfixMsg([ids(first, c)]), '198.51.100.' + (e % 250) + '.' + e); n += c; }
  }
  // size is private; observable effect: first exporter's templates were evicted, so its data is now held, not decoded
  const before = dec.stats.missingTemplate;
  dec.decode(ipfixMsg([dataSet(256, [1, 2, 3, 4])]), '198.51.100.0.0');
  assert.equal(dec.stats.missingTemplate, before + 1);
  assert.equal(dec.stats.templatesRejected, 0);
});

test('held data is bounded by bytes and by distinct keys', () => {
  const dec = new TemplateDecoder();
  // many different (exporter, template) pairs, each holding one small set
  for (let i = 0; i < TEMPLATE_LIMITS.heldKeys + 500; i++) dec.decode(ipfixMsg([dataSet(256, [1, 2, 3, 4])], i), '203.0.113.50');
  assert.equal(dec.stats.heldRecords, TEMPLATE_LIMITS.heldKeys);
  // released data decrements the counter
  dec.decode(ipfixMsg([tplSet(256, 1)], TEMPLATE_LIMITS.heldKeys + 499), '203.0.113.50');
  assert.equal(dec.stats.heldRecords, TEMPLATE_LIMITS.heldKeys - 1);
});

test('held data is bounded in bytes', () => {
  const dec = new TemplateDecoder();
  const big = Buffer.alloc(60_000, 7);
  const per = Math.floor(TEMPLATE_LIMITS.heldBytes / big.length);
  for (let i = 0; i < per + 200; i++) dec.decode(ipfixMsg([set(256, big)], i), '203.0.113.51');
  assert.ok(dec.stats.heldRecords <= per, 'held ' + dec.stats.heldRecords + ' > ' + per);
  assert.ok(dec.stats.heldRecords > per - 5);
});

test('data held for a template is still released when it arrives', () => {
  const dec = new TemplateDecoder();
  dec.decode(ipfixMsg([dataSet(256, [10, 1, 2, 3])]), '203.0.113.52');
  assert.equal(dec.stats.heldRecords, 1);
  dec.decode(ipfixMsg([tplSet(256, 1)]), '203.0.113.52');
  assert.equal(dec.stats.heldRecords, 0);
});
