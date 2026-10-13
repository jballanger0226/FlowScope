import type { FlowRecord } from '../collector/types.js';

export function ymd(ts: number): string {
  const d = new Date(ts);
  return d.getUTCFullYear().toString() + String(d.getUTCMonth() + 1).padStart(2, '0') + String(d.getUTCDate()).padStart(2, '0');
}

export function ipToN(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m || +m[1] > 255 || +m[2] > 255 || +m[3] > 255 || +m[4] > 255) return null;
  return ((+m[1] * 256 + +m[2]) * 256 + +m[3]) * 256 + +m[4];
}
export function nToIp(n: number): string {
  return [Math.floor(n / 16777216) % 256, Math.floor(n / 65536) % 256, Math.floor(n / 256) % 256, n % 256].join('.');
}


export function skeyOf(r: Pick<FlowRecord, 'srcIp' | 'dstIp' | 'sport' | 'dport' | 'proto'>): string {
  const icmp = r.proto === 1 || r.proto === 58;
  const a = r.srcIp + '|' + (icmp ? 0 : r.sport), b = r.dstIp + '|' + (icmp ? 0 : r.dport);
  return (a <= b ? a + '|' + b : b + '|' + a) + '|' + r.proto;
}
