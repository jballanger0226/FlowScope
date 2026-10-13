import type { Cond, IpMatch } from '../store/types.js';
import { appByName, dscpByName, PROTOS } from './apps.js';
import { ipToN } from '../store/ops.js';

export interface Resolver {
  /** VLAN ids whose name contains the text (case-insensitive). */
  vlanIdsByName(text: string): number[];
  /** Exporter IPs of devices whose name or address matches the text. */
  exporterIpsByName(text: string): string[];
}

export interface ParsedQuery { conds: Cond[]; errors: string[] }

const KEYS = new Set(['src', 'dst', 'ip', 'port', 'sport', 'dport', 'proto', 'app', 'vlan', 'mac', 'hop', 'dev', 'device', 'exporter', 'qos', 'dscp']);

/** Splits on whitespace but keeps quoted phrases together. */
export function splitTokens(q: string): string[] {
  const out: string[] = [];
  const re = /(?:[^\s"]+:)?"[^"]*"|\S+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(q))) out.push(m[0]);
  return out;
}

export function parseIpMatch(v: string): IpMatch | null {
  const s = v.trim();
  if (!s) return null;
  if (s.includes(':')) {
    // IPv6: match the text prefix. CIDR on v6 is not expanded.
    const base = s.split('/')[0].toLowerCase();
    return /^[0-9a-f:.]+$/.test(base) ? { text: base } : null;
  }
  const dash = s.match(/^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/);
  if (dash) { const a = ipToN(dash[1]), b = ipToN(dash[2]); return a !== null && b !== null && a <= b ? { lo: a, hi: b } : null; }
  const cidr = s.match(/^(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?$/);
  if (cidr) {
    const n = ipToN(cidr[1]);
    if (n === null) return null;
    const bits = cidr[2] === undefined ? 32 : Number(cidr[2]);
    if (bits < 0 || bits > 32) return null;
    const size = 2 ** (32 - bits);
    const lo = Math.floor(n / size) * size;
    return { lo, hi: lo + size - 1 };
  }
  // partial dotted prefix like 10.1.4 or 10.1.
  const part = s.match(/^(\d{1,3})(\.\d{1,3}){0,2}\.?$/);
  if (part) {
    const segs = s.replace(/\.$/, '').split('.').map(Number);
    if (segs.some(x => x > 255)) return null;
    const bits = segs.length * 8;
    const lo = segs.reduce((a, x, i) => a + x * 256 ** (3 - i), 0);
    return { lo, hi: lo + 2 ** (32 - bits) - 1 };
  }
  return null;
}

function ports(v: string, errors: string[], key: string): number[] {
  const out: number[] = [];
  for (const p of v.split(',').filter(Boolean)) {
    const range = p.match(/^(\d+)-(\d+)$/);
    if (range) { const a = Number(range[1]), b = Number(range[2]); if (a <= b && b - a <= 2000 && b < 65536) { for (let i = a; i <= b; i++) out.push(i); continue; } }
    if (/^\d+$/.test(p) && Number(p) < 65536) { out.push(Number(p)); continue; }
    const app = appByName(p);
    if (app) { out.push(...app.ports); continue; }
    errors.push(`${key}: "${p}" is not a port or service name`);
  }
  return out;
}

/** Parses the search box into conditions. Unknown words become a free-text condition that matches addresses, MACs, device names, VLAN names and service names. */
export function parseQuery(q: string, res: Resolver): ParsedQuery {
  const conds: Cond[] = [];
  const errors: string[] = [];
  for (const raw of splitTokens(q.trim())) {
    const idx = raw.indexOf(':');
    const key = idx > 0 ? raw.slice(0, idx).toLowerCase() : '';
    if (key && KEYS.has(key) && raw.slice(idx + 1) !== '') {
      let val = raw.slice(idx + 1);
      if (val.startsWith('"') && val.endsWith('"') && val.length >= 2) val = val.slice(1, -1);
      switch (key) {
        case 'src': case 'dst': case 'ip': {
          const m: IpMatch[] = [];
          for (const part of val.split(',')) { const x = parseIpMatch(part); if (x) m.push(x); else errors.push(`${key}: "${part}" is not an address, range or prefix`); }
          if (m.length) conds.push({ kind: key, m });
          break;
        }
        case 'port': case 'sport': case 'dport': {
          const p = ports(val, errors, key);
          if (p.length) conds.push({ kind: key, ports: p });
          break;
        }
        case 'app': {
          const names = val.split(',');
          const ps: number[] = [];
          for (const n of names) { const a = appByName(n); if (a) ps.push(...a.ports); else errors.push(`app: unknown service "${n}"`); }
          if (ps.length) conds.push({ kind: 'port', ports: ps });
          break;
        }
        case 'proto': {
          const ids: number[] = [];
          for (const p of val.split(',')) {
            const n = PROTOS[p.toLowerCase()] ?? (/^\d+$/.test(p) && Number(p) < 256 ? Number(p) : undefined);
            if (n === undefined) errors.push(`proto: unknown protocol "${p}"`); else ids.push(n);
          }
          if (ids.length) conds.push({ kind: 'proto', protos: ids });
          break;
        }
        case 'vlan': {
          const ids: number[] = [];
          for (const p of val.split(',')) {
            if (/^\d+$/.test(p) && Number(p) <= 4094) ids.push(Number(p));
            else { const r = res.vlanIdsByName(p); if (r.length) ids.push(...r); else errors.push(`vlan: no VLAN named "${p}"`); }
          }
          conds.push({ kind: 'vlan', ids });
          break;
        }
        case 'mac': conds.push({ kind: 'mac', text: val.toLowerCase().replace(/[-.]/g, ':') }); break;
        case 'hop': case 'dev': case 'device': case 'exporter': {
          const ips = new Set<string>();
          for (const p of val.split(',')) { for (const ip of res.exporterIpsByName(p)) ips.add(ip); }
          if (!ips.size) errors.push(`${key}: no device matches "${val}"`);
          conds.push({ kind: 'exporter', ips: [...ips] });
          break;
        }
        case 'qos': {
          const v = val.toLowerCase();
          if (v === 'changed' || v === 'remarked') conds.push({ kind: 'qos', mode: 'changed' });
          else if (v === 'unchanged' || v === 'same') conds.push({ kind: 'qos', mode: 'unchanged' });
          else errors.push('qos: use qos:changed or qos:unchanged');
          break;
        }
        case 'dscp': {
          const vals: number[] = [];
          for (const p of val.split(',')) {
            const n = /^\d+$/.test(p) ? Number(p) : dscpByName(p);
            if (n === null || n > 63) errors.push(`dscp: unknown value "${p}"`); else vals.push(n);
          }
          if (vals.length) conds.push({ kind: 'dscp', values: vals });
          break;
        }
      }
      continue;
    }
    // bare token
    let text = raw.startsWith('"') && raw.endsWith('"') && raw.length >= 2 ? raw.slice(1, -1) : raw;
    const ipm = parseIpMatch(text);
    if (ipm && /[./]/.test(text)) { conds.push({ kind: 'ip', m: [ipm] }); continue; }
    if (/^\d+$/.test(text) && Number(text) < 65536) { conds.push({ kind: 'text', text, ips: [], vlans: Number(text) <= 4094 ? [Number(text)] : [], ports: [Number(text)] }); continue; }
    const app = appByName(text);
    const ps = app ? app.ports : [];
    conds.push({ kind: 'text', text, ips: res.exporterIpsByName(text), vlans: res.vlanIdsByName(text), ports: ps });
  }
  return { conds, errors };
}
