/** Minimal DER writer for building X.509 certificates and PKCS#10 requests. */
export type Der = Buffer;

function len(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const b: number[] = [];
  let x = n;
  while (x > 0) { b.unshift(x & 0xff); x = Math.floor(x / 256); }
  return Buffer.from([0x80 | b.length, ...b]);
}

export function tlv(tag: number, ...content: Buffer[]): Der {
  const body = Buffer.concat(content);
  return Buffer.concat([Buffer.from([tag]), len(body.length), body]);
}

export const seq = (...c: Buffer[]) => tlv(0x30, ...c);
export const set = (...c: Buffer[]) => tlv(0x31, ...c);
export const ctx = (n: number, ...c: Buffer[]) => tlv(0xa0 | n, ...c);
export const ctxPrim = (n: number, c: Buffer) => tlv(0x80 | n, c);
export const nul = () => Buffer.from([0x05, 0x00]);
export const octets = (b: Buffer) => tlv(0x04, b);
export const bool = (v: boolean) => tlv(0x01, Buffer.from([v ? 0xff : 0x00]));
export const utf8 = (s: string) => tlv(0x0c, Buffer.from(s, 'utf8'));
export const printable = (s: string) => tlv(0x13, Buffer.from(s, 'ascii'));
export const ia5 = (s: string) => tlv(0x16, Buffer.from(s, 'ascii'));

export function int(v: number | bigint | Buffer): Der {
  let b: Buffer;
  if (Buffer.isBuffer(v)) b = v;
  else {
    let x = BigInt(v);
    if (x === 0n) b = Buffer.from([0]);
    else { const bytes: number[] = []; while (x > 0n) { bytes.unshift(Number(x & 0xffn)); x >>= 8n; } b = Buffer.from(bytes); }
  }
  // strip redundant leading zeros, then add one if the high bit is set
  let i = 0; while (i < b.length - 1 && b[i] === 0 && !(b[i + 1] & 0x80)) i++;
  b = b.subarray(i);
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
}

export function bitString(b: Buffer, unused = 0): Der { return tlv(0x03, Buffer.from([unused]), b); }

export function oid(s: string): Der {
  const p = s.split('.').map(Number);
  const out: number[] = [p[0] * 40 + p[1]];
  for (const n of p.slice(2)) {
    const t: number[] = [n & 0x7f];
    let x = Math.floor(n / 128);
    while (x > 0) { t.unshift((x & 0x7f) | 0x80); x = Math.floor(x / 128); }
    out.push(...t);
  }
  return tlv(0x06, Buffer.from(out));
}

function two(n: number): string { return String(n).padStart(2, '0'); }
/** UTCTime up to 2049, GeneralizedTime after that. */
export function time(d: Date): Der {
  const y = d.getUTCFullYear();
  const rest = two(d.getUTCMonth() + 1) + two(d.getUTCDate()) + two(d.getUTCHours()) + two(d.getUTCMinutes()) + two(d.getUTCSeconds()) + 'Z';
  if (y < 2050) return tlv(0x17, Buffer.from(String(y).slice(2) + rest, 'ascii'));
  return tlv(0x18, Buffer.from(String(y) + rest, 'ascii'));
}

export function toPem(label: string, der: Buffer): string {
  const b64 = der.toString('base64').replace(/(.{64})/g, '$1\n');
  return `-----BEGIN ${label}-----\n${b64}${b64.endsWith('\n') ? '' : '\n'}-----END ${label}-----\n`;
}

export function fromPem(pem: string): Buffer[] {
  const out: Buffer[] = [];
  const re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(pem))) out.push(Buffer.from(m[2].replace(/\s+/g, ''), 'base64'));
  return out;
}

/* ---- tiny reader, used to inspect extensions we did not create ---- */
export interface Node { tag: number; start: number; hdr: number; end: number; buf: Buffer }
export function read(buf: Buffer, off = 0): Node {
  const tag = buf[off]; let l = buf[off + 1]; let hdr = 2;
  if (l & 0x80) { const n = l & 0x7f; l = 0; for (let i = 0; i < n; i++) l = l * 256 + buf[off + 2 + i]; hdr = 2 + n; }
  return { tag, start: off, hdr, end: off + hdr + l, buf };
}
export function children(n: Node): Node[] {
  const out: Node[] = []; let o = n.start + n.hdr;
  while (o < n.end) { const c = read(n.buf, o); out.push(c); o = c.end; }
  return out;
}
export function body(n: Node): Buffer { return n.buf.subarray(n.start + n.hdr, n.end); }
