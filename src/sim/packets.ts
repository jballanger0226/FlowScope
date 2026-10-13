import type { FlowRecord } from '../collector/types.js';

/** Builders for NetFlow v5, v9 and IPFIX datagrams. Used by the tests and by the demo traffic generator. */

function ip4(s: string): Buffer { return Buffer.from(s.split('.').map(Number)); }
function macb(s: string): Buffer { return Buffer.from(s.split(':').map(h => parseInt(h, 16))); }
function u(n: number, len: number): Buffer {
  const b = Buffer.alloc(len);
  let v = BigInt(Math.max(0, Math.floor(n)));
  for (let i = len - 1; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n; }
  return b;
}

export function buildV5(records: FlowRecord[], opts: { uptime: number; nowMs: number; seq?: number; sampling?: number }): Buffer {
  const h = Buffer.alloc(24);
  h.writeUInt16BE(5, 0); h.writeUInt16BE(records.length, 2); h.writeUInt32BE(opts.uptime >>> 0, 4);
  h.writeUInt32BE(Math.floor(opts.nowMs / 1000), 8); h.writeUInt32BE((opts.nowMs % 1000) * 1e6, 12);
  h.writeUInt32BE(opts.seq ?? 0, 16); h.writeUInt16BE(opts.sampling ?? 0, 22);
  const body = Buffer.alloc(records.length * 48);
  records.forEach((r, i) => {
    const o = i * 48;
    ip4(r.srcIp).copy(body, o); ip4(r.dstIp).copy(body, o + 4); ip4(r.nextHop || '0.0.0.0').copy(body, o + 8);
    body.writeUInt16BE(r.inIf, o + 12); body.writeUInt16BE(r.outIf, o + 14);
    body.writeUInt32BE(r.pkts, o + 16); body.writeUInt32BE(r.bytes, o + 20);
    body.writeUInt32BE((opts.uptime - (opts.nowMs - r.ts0)) >>> 0, o + 24); body.writeUInt32BE((opts.uptime - (opts.nowMs - r.ts1)) >>> 0, o + 28);
    body.writeUInt16BE(r.sport, o + 32); body.writeUInt16BE(r.dport, o + 34);
    body[o + 37] = r.flags; body[o + 38] = r.proto; body[o + 39] = r.tos;
  });
  return Buffer.concat([h, body]);
}

/** The field set used for v9 and IPFIX data records produced by the simulator. [ie id, length] */
export const SIM_FIELDS: [number, number][] = [
  [8, 4], [12, 4], [7, 2], [11, 2], [4, 1], [5, 1], [55, 1], [6, 1], [10, 4], [14, 4], [1, 8], [2, 8],
  [152, 8], [153, 8], [56, 6], [80, 6], [58, 2], [52, 1], [53, 1], [15, 4]
];

function encodeRecord(r: FlowRecord, fields: [number, number][]): Buffer {
  const parts: Buffer[] = [];
  for (const [id, len] of fields) {
    switch (id) {
      case 8: parts.push(ip4(r.srcIp)); break;
      case 12: parts.push(ip4(r.dstIp)); break;
      case 7: parts.push(u(r.sport, len)); break;
      case 11: parts.push(u(r.dport, len)); break;
      case 4: parts.push(u(r.proto, len)); break;
      case 5: parts.push(u(r.tos, len)); break;
      case 55: parts.push(u(r.postTos ?? r.tos, len)); break;
      case 6: parts.push(u(r.flags, len)); break;
      case 10: parts.push(u(r.inIf, len)); break;
      case 14: parts.push(u(r.outIf, len)); break;
      case 1: parts.push(u(r.bytes, len)); break;
      case 2: parts.push(u(r.pkts, len)); break;
      case 152: parts.push(u(r.ts0, len)); break;
      case 153: parts.push(u(r.ts1, len)); break;
      case 56: parts.push(macb(r.srcMac || '00:00:00:00:00:00')); break;
      case 80: parts.push(macb(r.dstMac || '00:00:00:00:00:00')); break;
      case 58: parts.push(u(r.vlan ?? 0, len)); break;
      case 52: parts.push(u(r.ttlMin ?? 0, len)); break;
      case 53: parts.push(u(r.ttlMax ?? 0, len)); break;
      case 15: parts.push(ip4(r.nextHop || '0.0.0.0')); break;
      default: parts.push(Buffer.alloc(len));
    }
  }
  return Buffer.concat(parts);
}

function templateSet(ipfix: boolean, tplId: number, fields: [number, number][]): Buffer {
  const body = Buffer.alloc(4 + fields.length * 4);
  body.writeUInt16BE(tplId, 0); body.writeUInt16BE(fields.length, 2);
  fields.forEach(([id, len], i) => { body.writeUInt16BE(id, 4 + i * 4); body.writeUInt16BE(len, 6 + i * 4); });
  const h = Buffer.alloc(4); h.writeUInt16BE(ipfix ? 2 : 0, 0); h.writeUInt16BE(4 + body.length, 2);
  return Buffer.concat([h, body]);
}

function dataSet(tplId: number, recs: Buffer[]): Buffer {
  let body = Buffer.concat(recs);
  const pad = (4 - (body.length % 4)) % 4;
  if (pad) body = Buffer.concat([body, Buffer.alloc(pad)]);
  const h = Buffer.alloc(4); h.writeUInt16BE(tplId, 0); h.writeUInt16BE(4 + body.length, 2);
  return Buffer.concat([h, body]);
}

export interface PacketOpts { nowMs: number; uptime?: number; seq?: number; domain?: number; withTemplate?: boolean; tplId?: number; fields?: [number, number][] }

export function buildV9(records: FlowRecord[], o: PacketOpts): Buffer {
  const fields = o.fields || SIM_FIELDS, tplId = o.tplId ?? 256;
  const sets: Buffer[] = [];
  let count = 0;
  if (o.withTemplate !== false) { sets.push(templateSet(false, tplId, fields)); count++; }
  if (records.length) { sets.push(dataSet(tplId, records.map(r => encodeRecord(r, fields)))); count += records.length; }
  const h = Buffer.alloc(20);
  h.writeUInt16BE(9, 0); h.writeUInt16BE(count, 2); h.writeUInt32BE((o.uptime ?? 3600_000) >>> 0, 4);
  h.writeUInt32BE(Math.floor(o.nowMs / 1000), 8); h.writeUInt32BE(o.seq ?? 0, 12); h.writeUInt32BE(o.domain ?? 0, 16);
  return Buffer.concat([h, ...sets]);
}

export function buildIpfix(records: FlowRecord[], o: PacketOpts): Buffer {
  const fields = o.fields || SIM_FIELDS, tplId = o.tplId ?? 256;
  const sets: Buffer[] = [];
  if (o.withTemplate !== false) sets.push(templateSet(true, tplId, fields));
  if (records.length) sets.push(dataSet(tplId, records.map(r => encodeRecord(r, fields))));
  const body = Buffer.concat(sets);
  const h = Buffer.alloc(16);
  h.writeUInt16BE(10, 0); h.writeUInt16BE(16 + body.length, 2); h.writeUInt32BE(Math.floor(o.nowMs / 1000), 4);
  h.writeUInt32BE(o.seq ?? 0, 8); h.writeUInt32BE(o.domain ?? 0, 12);
  return Buffer.concat([h, body]);
}
