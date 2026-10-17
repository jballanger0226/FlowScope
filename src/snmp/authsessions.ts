/**
 * Authentication sessions (802.1X, MAB, web auth) from CISCO-AUTH-FRAMEWORK-MIB cafSessionTable (1.3.6.1.4.1.9.9.656.1.4.1.1): for each
 * authenticated client its MAC address, IP address, the port, and the VLAN the authentication server put it in. A port that authenticates
 * its clients is not in the VLAN configured on it, so this is where the VLAN, and often the IP address, of those hosts comes from.
 *
 * Layout, checked against a full walk of a Catalyst 9300 SDA edge (69 sessions, 36 authorized) with the object names the walk carries: index is
 * <ifIndex>.<session id as ASCII bytes>; col 2 cafSessionClientMacAddress, 4 cafSessionClientAddress (4 raw bytes), 5 cafSessionStatus (1 idle, 6
 * authorizationSuccess, 7 authorizationFailed), 6 cafSessionDomain (1 other, 2 data, 3 voice), 7 cafSessionAuthHostMode (3 multiAuth), 10
 * cafSessionAuthUserName (the RADIUS user name, e.g. IT-Camera), 14 cafSessionAuthVlan (the VLAN the server assigned, 0 when none), 22
 * cafSessionVlanGroupName (the VLAN name or group the server sent, e.g. DEVICE_CAMERA; it is NOT the security group tag). The tag is a separate RADIUS
 * attribute and is not in this table: it comes from the IP-to-tag bindings (sgt.ts). A session that is not authorizationSuccess has domain other,
 * which is how "authenticated" is told here.
 */
import { toNum, type SnmpClient, type SnmpValue } from './client.js';
import { ipOf } from './multicast.js';

export type AuthDomain = 'data' | 'voice' | 'unknown';
export interface AuthSession { ifIndex: number; mac: string; ip: string; vlan: number; domain: AuthDomain; user: string; vlanGroup: string }

const T = '1.3.6.1.4.1.9.9.656.1.4.1.1';
const DOMAIN: Record<number, AuthDomain> = { 1: 'unknown', 2: 'data', 3: 'voice' };
const EMPTY = new Map<string, SnmpValue>();
const col = (c: SnmpClient, n: number) => c.column(`${T}.${n}`, 50).catch(() => EMPTY);
const text = (v: SnmpValue | undefined): string => (v === undefined || v === null ? '' : Buffer.isBuffer(v) ? v.toString('utf8').replace(/[^\x20-\x7e]/g, '') : String(v)).trim();

export function macOf(v: SnmpValue | undefined): string | null {
  return Buffer.isBuffer(v) && v.length === 6 ? [...v].map(b => b.toString(16).padStart(2, '0')).join(':') : null;
}

export async function readAuthSessions(c: SnmpClient): Promise<AuthSession[]> {
  const [mac, ip, domain, vlan, user, vlanGroup] = await Promise.all([2, 4, 6, 14, 10, 22].map(n => col(c, n)));
  const out: AuthSession[] = [];
  for (const [idx, v] of mac) {
    const m = macOf(v); if (!m) continue;
    const ifIndex = Number(idx.split('.')[0]); if (!Number.isInteger(ifIndex) || ifIndex <= 0) continue;
    const vl = toNum(vlan.get(idx) ?? null) ?? 0;
    out.push({ ifIndex, mac: m, ip: ipOf(ip.get(idx)) ?? '', vlan: vl >= 1 && vl <= 4094 ? vl : 0, domain: DOMAIN[toNum(domain.get(idx) ?? null) ?? 1] ?? 'unknown', user: text(user.get(idx)), vlanGroup: text(vlanGroup.get(idx)) });
  }
  return out;
}
