/**
 * Authentication sessions (802.1X, MAB, web auth) from CISCO-AUTH-FRAMEWORK-MIB cafSessionTable (1.3.6.1.4.1.9.9.656.1.4.1.1): for each
 * authenticated client its MAC address, IP address, the port, and the VLAN the authentication server put it in. A port that authenticates
 * its clients is not in the VLAN configured on it, so this is where the VLAN, and often the IP address, of those hosts comes from.
 *
 * Layout, checked against a walk of a Catalyst 9500 SDA edge (69 sessions): index is <ifIndex>.<session id as ASCII bytes>, with
 * col 2 client MAC, 6 domain (1 unknown, 2 data, 3 voice, as the CLI's Domain column: UNKNOWN is a client the switch saw that did not authenticate), 4 client IP (4 raw bytes), 14 VLAN assigned by the server (0 when it assigned none), 10 the user name (what
 * `show authentication sessions ... details` calls User-Name, e.g. IT-Camera), 22 a name the server gave (DEVICE_CAMERA, which is both the name of VLAN 3074
 * and of security group tag 74 here, so which of the two it is cannot be told; empty when none was assigned). The tag number is not in this table: see sgt.ts.
 */
import { toNum, type SnmpClient, type SnmpValue } from './client.js';
import { ipOf } from './multicast.js';

export type AuthDomain = 'data' | 'voice' | 'unknown';
export interface AuthSession { ifIndex: number; mac: string; ip: string; vlan: number; domain: AuthDomain; user: string; vlanName: string }

const T = '1.3.6.1.4.1.9.9.656.1.4.1.1';
const DOMAIN: Record<number, AuthDomain> = { 1: 'unknown', 2: 'data', 3: 'voice' };
const EMPTY = new Map<string, SnmpValue>();
const col = (c: SnmpClient, n: number) => c.column(`${T}.${n}`, 50).catch(() => EMPTY);
const text = (v: SnmpValue | undefined): string => (v === undefined || v === null ? '' : Buffer.isBuffer(v) ? v.toString('utf8').replace(/[^\x20-\x7e]/g, '') : String(v)).trim();

export function macOf(v: SnmpValue | undefined): string | null {
  return Buffer.isBuffer(v) && v.length === 6 ? [...v].map(b => b.toString(16).padStart(2, '0')).join(':') : null;
}

export async function readAuthSessions(c: SnmpClient): Promise<AuthSession[]> {
  const [mac, ip, domain, vlan, user, vlanName] = await Promise.all([2, 4, 6, 14, 10, 22].map(n => col(c, n)));
  const out: AuthSession[] = [];
  for (const [idx, v] of mac) {
    const m = macOf(v); if (!m) continue;
    const ifIndex = Number(idx.split('.')[0]); if (!Number.isInteger(ifIndex) || ifIndex <= 0) continue;
    const vl = toNum(vlan.get(idx) ?? null) ?? 0;
    out.push({ ifIndex, mac: m, ip: ipOf(ip.get(idx)) ?? '', vlan: vl >= 1 && vl <= 4094 ? vl : 0, domain: DOMAIN[toNum(domain.get(idx) ?? null) ?? 1] ?? 'unknown', user: text(user.get(idx)), vlanName: text(vlanName.get(idx)) });
  }
  return out;
}
