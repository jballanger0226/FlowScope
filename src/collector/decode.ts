import type { FlowRecord } from './types.js';

/* ------------------------------------------------------------------ helpers */

export function ipv4(b: Buffer, o: number): string { return `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`; }

export function ipv6(b: Buffer, o: number): string {
  const g: number[] = [];
  for (let i = 0; i < 8; i++) g.push(b.readUInt16BE(o + i * 2));
  // find the longest run of zero groups (length >= 2) to compress
  let bestS = -1, bestL = 0;
  for (let i = 0; i < 8;) {
    if (g[i] !== 0) { i++; continue; }
    let j = i; while (j < 8 && g[j] === 0) j++;
    if (j - i > bestL) { bestS = i; bestL = j - i; }
    i = j;
  }
  if (bestL < 2) return g.map(x => x.toString(16)).join(':');
  const left = g.slice(0, bestS).map(x => x.toString(16)).join(':');
  const right = g.slice(bestS + bestL).map(x => x.toString(16)).join(':');
  return left + '::' + right;
}

export function mac(b: Buffer, o: number): string {
  let s = '';
  for (let i = 0; i < 6; i++) s += (i ? ':' : '') + b[o + i].toString(16).padStart(2, '0');
  return s;
}

/** Reads an unsigned big-endian integer of 1..8 bytes. Values above 2^53 lose precision, which is far beyond any flow counter. */
export function uint(b: Buffer, o: number, len: number): number {
  if (len === 1) return b[o];
  if (len === 2) return b.readUInt16BE(o);
  if (len === 4) return b.readUInt32BE(o);
  if (len === 3 || len === 5 || len === 6) return b.readUIntBE(o, len);
  if (len === 8) return Number(b.readBigUInt64BE(o));
  if (len === 7) return b.readUIntBE(o, 3) * 2 ** 32 + b.readUInt32BE(o + 3);
  let v = 0;
  for (let i = 0; i < len; i++) v = v * 256 + b[o + i];
  return v;
}

const NTP_TO_UNIX_SEC = 2208988800;

/* ------------------------------------------------------------------ NetFlow v5 */

export function decodeV5(b: Buffer, exporter: string): FlowRecord[] {
  if (b.length < 24) throw new Error('short v5 header');
  const count = b.readUInt16BE(2);
  if (count > 30 || b.length < 24 + count * 48) throw new Error('bad v5 record count');
  const uptime = b.readUInt32BE(4);
  const secs = b.readUInt32BE(8), nsecs = b.readUInt32BE(12);
  const exportMs = secs * 1000 + Math.floor(nsecs / 1e6);
  const sampInt = b.readUInt16BE(22) & 0x3fff;
  const sampling = sampInt > 0 ? sampInt : 1;
  const out: FlowRecord[] = [];
  for (let i = 0; i < count; i++) {
    const o = 24 + i * 48;
    const first = b.readUInt32BE(o + 24), last = b.readUInt32BE(o + 28);
    const rel = (t: number) => { let d = uptime - t; if (d < 0) d += 2 ** 32; return exportMs - d; };
    out.push({
      ts0: rel(first), ts1: rel(last), exporter,
      inIf: b.readUInt16BE(o + 12), outIf: b.readUInt16BE(o + 14),
      srcIp: ipv4(b, o), dstIp: ipv4(b, o + 4), nextHop: ipv4(b, o + 8),
      pkts: b.readUInt32BE(o + 16) * sampling, bytes: b.readUInt32BE(o + 20) * sampling,
      sport: b.readUInt16BE(o + 32), dport: b.readUInt16BE(o + 34),
      flags: b[o + 37], proto: b[o + 38], tos: b[o + 39], postTos: null,
      ttlMin: null, ttlMax: null, srcMac: null, dstMac: null, vlan: null,
      natSrcIp: null, natDstIp: null, natSport: null, natDport: null, sampling
    });
  }
  return out;
}

/* ------------------------------------------------------------------ NetFlow v9 and IPFIX */

interface Field { id: number; len: number; pen: number }
interface Template { id: number; fields: Field[]; scopeCount: number; options: boolean; fixedLen: number; hasVar: boolean }

/** Raw value fields of one record, before they are folded into a FlowRecord. */
interface Raw {
  bytes?: number; pkts?: number; proto?: number; tos?: number; postTos?: number; flags?: number;
  sport?: number; dport?: number; srcIp?: string; dstIp?: string; srcIp6?: string; dstIp6?: string;
  inIf?: number; outIf?: number; nextHop?: string; nextHop6?: string; icmp?: number;
  ttlMin?: number; ttlMax?: number; srcMac?: string; dstMac?: string; vlan?: number;
  first?: number; last?: number; startMs?: number; endMs?: number; startSec?: number; endSec?: number;
  startUs?: number; endUs?: number; initMs?: number;
  natSrc?: string; natDst?: string; natSport?: number; natDport?: number; sampling?: number; tcpOctets?: number;
}

export interface V9Stats { templates: number; missingTemplate: number; heldRecords: number; unknownVersion: number; templatesRejected: number }

/** Limits on what a sender can make the decoder remember. Exporters send tens of templates of up to ~100 fields, so these leave room. */
export const TEMPLATE_LIMITS = { perExporter: 1024, total: 10_000, fields: 256, heldBytes: 32 * 1024 * 1024, heldKeys: 2000 };

/** Decodes NetFlow v9 and IPFIX packets. Templates are cached per exporter and observation domain. */
export class TemplateDecoder {
  private templates = new Map<string, Template>();
  private sampling = new Map<string, number>();
  private pending = new Map<string, { buf: Buffer; hdr: Hdr }[]>();
  private perExporter = new Map<string, number>();
  private heldBytes = 0;
  readonly stats: V9Stats = { templates: 0, missingTemplate: 0, heldRecords: 0, unknownVersion: 0, templatesRejected: 0 };

  private dropTemplate(key: string): void {
    if (!this.templates.delete(key)) return;
    const ex = key.slice(0, key.indexOf('|'));
    const n = (this.perExporter.get(ex) ?? 1) - 1;
    if (n > 0) this.perExporter.set(ex, n); else this.perExporter.delete(ex);
  }

  /** Stores a template unless the sender is over its share. The oldest template overall goes first when the total limit is reached. */
  private storeTemplate(key: string, exporter: string, t: Template): boolean {
    const known = this.templates.has(key);
    if (!known) {
      if ((this.perExporter.get(exporter) ?? 0) >= TEMPLATE_LIMITS.perExporter) { this.stats.templatesRejected++; return false; }
      if (this.templates.size >= TEMPLATE_LIMITS.total) this.dropTemplate(this.templates.keys().next().value as string);
      this.perExporter.set(exporter, (this.perExporter.get(exporter) ?? 0) + 1);
    } else this.templates.delete(key);   // re-insert so a refreshed template counts as newest
    this.templates.set(key, t);
    return true;
  }

  private forgetHeld(key: string): { buf: Buffer; hdr: Hdr }[] | undefined {
    const held = this.pending.get(key);
    if (!held) return undefined;
    this.pending.delete(key);
    for (const h of held) { this.stats.heldRecords--; this.heldBytes -= h.buf.length; }
    return held;
  }

  private hold(key: string, body: Buffer, hdr: Hdr): void {
    let q = this.pending.get(key);
    if (!q) {
      while (this.pending.size >= TEMPLATE_LIMITS.heldKeys) this.forgetHeld(this.pending.keys().next().value as string);
      q = [];
    }
    if (q.length >= 64) return;
    while (this.heldBytes + body.length > TEMPLATE_LIMITS.heldBytes && this.pending.size) {
      const oldest = this.pending.keys().next().value as string;
      if (oldest === key) return;
      this.forgetHeld(oldest);
    }
    q.push({ buf: Buffer.from(body), hdr }); this.heldBytes += body.length;
    this.pending.set(key, q); this.stats.heldRecords++;
  }

  decode(b: Buffer, exporter: string): FlowRecord[] {
    const ver = b.readUInt16BE(0);
    if (ver === 9) return this.decodeMessage(b, exporter, false);
    if (ver === 10) return this.decodeMessage(b, exporter, true);
    this.stats.unknownVersion++;
    throw new Error('unsupported version ' + ver);
  }

  private decodeMessage(b: Buffer, exporter: string, ipfix: boolean): FlowRecord[] {
    let hdr: Hdr; let pos: number;
    if (ipfix) {
      if (b.length < 16) throw new Error('short IPFIX header');
      const len = b.readUInt16BE(2);
      if (len > b.length) throw new Error('IPFIX length exceeds datagram');
      b = b.subarray(0, len);
      hdr = { ipfix, exportMs: b.readUInt32BE(4) * 1000, uptime: 0, domain: b.readUInt32BE(12) };
      pos = 16;
    } else {
      if (b.length < 20) throw new Error('short v9 header');
      hdr = { ipfix, exportMs: b.readUInt32BE(8) * 1000, uptime: b.readUInt32BE(4), domain: b.readUInt32BE(16) };
      pos = 20;
    }
    const out: FlowRecord[] = [];
    while (pos + 4 <= b.length) {
      const setId = b.readUInt16BE(pos), setLen = b.readUInt16BE(pos + 2);
      if (setLen < 4 || pos + setLen > b.length) throw new Error('bad set length');
      const body = b.subarray(pos + 4, pos + setLen);
      const tplSet = ipfix ? 2 : 0, optSet = ipfix ? 3 : 1;
      if (setId === tplSet) this.readTemplates(body, exporter, hdr, false, out);
      else if (setId === optSet) this.readTemplates(body, exporter, hdr, true, out);
      else if (setId >= 256) this.readData(setId, body, exporter, hdr, out);
      pos += setLen;
    }
    return out;
  }

  private key(exporter: string, domain: number, id: number): string { return exporter + '|' + domain + '|' + id; }

  private readTemplates(body: Buffer, exporter: string, hdr: Hdr, options: boolean, out: FlowRecord[]): void {
    let p = 0;
    while (p + 4 <= body.length) {
      const id = body.readUInt16BE(p);
      let scopeCount = 0; const fields: Field[] = [];
      if (!options) {
        const n = body.readUInt16BE(p + 2); p += 4;
        if (n === 0) { this.dropTemplate(this.key(exporter, hdr.domain, id)); continue; }
        p = this.readFields(body, p, n, fields, hdr.ipfix);
      } else if (hdr.ipfix) {
        const n = body.readUInt16BE(p + 2); scopeCount = body.readUInt16BE(p + 4); p += 6;
        p = this.readFields(body, p, n, fields, true);
      } else {
        const scopeBytes = body.readUInt16BE(p + 2), optBytes = body.readUInt16BE(p + 4); p += 6;
        scopeCount = scopeBytes / 4;
        p = this.readFields(body, p, (scopeBytes + optBytes) / 4, fields, false);
      }
      if (p < 0) return;
      if (fields.length > TEMPLATE_LIMITS.fields) { this.stats.templatesRejected++; continue; }
      let fixedLen = 0, hasVar = false;
      for (const f of fields) { if (f.len === 65535) hasVar = true; else fixedLen += f.len; }
      if (!this.storeTemplate(this.key(exporter, hdr.domain, id), exporter, { id, fields, scopeCount, options, fixedLen, hasVar })) continue;
      this.stats.templates++;
      // release data sets that arrived before this template
      const held = this.forgetHeld(this.key(exporter, hdr.domain, id));
      if (held) for (const h of held) this.readData(id, h.buf, exporter, h.hdr, out);
    }
  }

  private readFields(b: Buffer, p: number, n: number, into: Field[], ipfix: boolean): number {
    for (let i = 0; i < n; i++) {
      if (p + 4 > b.length) return -1;
      let id = b.readUInt16BE(p); const len = b.readUInt16BE(p + 2); p += 4;
      let pen = 0;
      if (ipfix && (id & 0x8000)) { id &= 0x7fff; if (p + 4 > b.length) return -1; pen = b.readUInt32BE(p); p += 4; }
      into.push({ id, len, pen });
    }
    return p;
  }

  private readData(setId: number, body: Buffer, exporter: string, hdr: Hdr, out: FlowRecord[]): void {
    const k = this.key(exporter, hdr.domain, setId);
    const t = this.templates.get(k);
    if (!t) {
      this.stats.missingTemplate++;
      this.hold(k, body, hdr);
      return;
    }
    let p = 0;
    const minLen = t.fixedLen + (t.hasVar ? t.fields.filter(f => f.len === 65535).length : 0);
    while (p + (minLen || 1) <= body.length) {
      const raw: Raw = {};
      const start = p;
      for (const f of t.fields) {
        let len = f.len;
        if (len === 65535) {
          len = body[p++];
          if (len === 255) { len = body.readUInt16BE(p); p += 2; }
        }
        if (p + len > body.length) { p = body.length; break; }
        if (f.pen === 0) this.field(raw, f.id, body, p, len, hdr.ipfix);
        p += len;
      }
      if (p === start) break;
      if (t.options) this.optionRecord(raw, exporter);
      else { const r = this.build(raw, exporter, hdr); if (r) out.push(r); }
      // trailing padding is shorter than one record
    }
  }

  private optionRecord(raw: Raw, exporter: string): void {
    if (raw.sampling && raw.sampling > 0) this.sampling.set(exporter, raw.sampling);
  }

  private field(r: Raw, id: number, b: Buffer, o: number, len: number, _ipfix: boolean): void {
    switch (id) {
      case 1: case 85: if (r.bytes === undefined || id === 1) r.bytes = uint(b, o, len); break;
      case 2: case 86: if (r.pkts === undefined || id === 2) r.pkts = uint(b, o, len); break;
      case 4: r.proto = uint(b, o, len); break;
      case 5: r.tos = uint(b, o, len); break;
      case 55: r.postTos = uint(b, o, len); break;
      case 6: r.flags = uint(b, o, len); break;
      case 7: r.sport = uint(b, o, len); break;
      case 11: r.dport = uint(b, o, len); break;
      case 8: if (len === 4) r.srcIp = ipv4(b, o); break;
      case 12: if (len === 4) r.dstIp = ipv4(b, o); break;
      case 27: if (len === 16) r.srcIp6 = ipv6(b, o); break;
      case 28: if (len === 16) r.dstIp6 = ipv6(b, o); break;
      case 10: r.inIf = uint(b, o, len); break;
      case 14: r.outIf = uint(b, o, len); break;
      case 15: if (len === 4) r.nextHop = ipv4(b, o); break;
      case 62: if (len === 16) r.nextHop6 = ipv6(b, o); break;
      case 32: case 139: r.icmp = uint(b, o, len); break;
      case 52: r.ttlMin = uint(b, o, len); break;
      case 53: r.ttlMax = uint(b, o, len); break;
      case 56: if (len === 6) r.srcMac = mac(b, o); break;
      case 80: if (len === 6) r.dstMac = mac(b, o); break;
      case 58: case 243: r.vlan = uint(b, o, len); break;
      case 22: r.first = uint(b, o, len); break;
      case 21: r.last = uint(b, o, len); break;
      case 150: r.startSec = uint(b, o, len); break;
      case 151: r.endSec = uint(b, o, len); break;
      case 152: r.startMs = uint(b, o, len); break;
      case 153: r.endMs = uint(b, o, len); break;
      case 154: case 156: r.startUs = ntpToUnixMs(b, o, len); break;
      case 155: case 157: r.endUs = ntpToUnixMs(b, o, len); break;
      case 160: r.initMs = uint(b, o, len); break;
      case 225: if (len === 4) r.natSrc = ipv4(b, o); break;
      case 226: if (len === 4) r.natDst = ipv4(b, o); break;
      case 227: r.natSport = uint(b, o, len); break;
      case 228: r.natDport = uint(b, o, len); break;
      case 34: case 305: r.sampling = uint(b, o, len); break;
      default: break;
    }
  }

  private build(r: Raw, exporter: string, hdr: Hdr): FlowRecord | null {
    const srcIp = r.srcIp ?? r.srcIp6, dstIp = r.dstIp ?? r.dstIp6;
    if (!srcIp || !dstIp) return null;
    let ts0 = hdr.exportMs, ts1 = hdr.exportMs;
    const rel = (t: number) => { let d = hdr.uptime - t; if (d < 0) d += 2 ** 32; return hdr.exportMs - d; };
    if (r.startMs !== undefined) ts0 = r.startMs;
    else if (r.startUs !== undefined) ts0 = r.startUs;
    else if (r.startSec !== undefined) ts0 = r.startSec * 1000;
    else if (r.first !== undefined) ts0 = hdr.ipfix ? (r.initMs !== undefined ? r.initMs + r.first : hdr.exportMs) : rel(r.first);
    if (r.endMs !== undefined) ts1 = r.endMs;
    else if (r.endUs !== undefined) ts1 = r.endUs;
    else if (r.endSec !== undefined) ts1 = r.endSec * 1000;
    else if (r.last !== undefined) ts1 = hdr.ipfix ? (r.initMs !== undefined ? r.initMs + r.last : hdr.exportMs) : rel(r.last);
    if (ts1 < ts0) ts0 = ts1;
    const proto = r.proto ?? 0;
    let sport = r.sport ?? 0, dport = r.dport ?? 0;
    if ((proto === 1 || proto === 58) && r.icmp !== undefined) { sport = 0; dport = r.icmp; }
    const sampling = this.sampling.get(exporter) ?? (r.sampling && r.sampling > 0 ? r.sampling : 1);
    const nh = r.nextHop ?? r.nextHop6 ?? null;
    return {
      ts0, ts1, exporter, inIf: r.inIf ?? 0, outIf: r.outIf ?? 0, srcIp, dstIp, proto, sport, dport,
      flags: r.flags ?? 0, tos: r.tos ?? 0, postTos: r.postTos ?? null, ttlMin: r.ttlMin ?? null, ttlMax: r.ttlMax ?? null,
      bytes: (r.bytes ?? 0) * sampling, pkts: (r.pkts ?? 0) * sampling, srcMac: r.srcMac ?? null, dstMac: r.dstMac ?? null,
      vlan: r.vlan && r.vlan > 0 ? r.vlan : null, natSrcIp: r.natSrc ?? null, natDstIp: r.natDst ?? null,
      natSport: r.natSport ?? null, natDport: r.natDport ?? null, nextHop: nh && nh !== '0.0.0.0' ? nh : null, sampling
    };
  }
}

interface Hdr { ipfix: boolean; exportMs: number; uptime: number; domain: number }

function ntpToUnixMs(b: Buffer, o: number, len: number): number {
  if (len < 8) return 0;
  const secs = b.readUInt32BE(o), frac = b.readUInt32BE(o + 4);
  return (secs - NTP_TO_UNIX_SEC) * 1000 + Math.round(frac / 2 ** 32 * 1000);
}
