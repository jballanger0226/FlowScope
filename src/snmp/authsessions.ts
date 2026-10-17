/**
 * Authentication sessions (802.1X, MAB, web auth) from CISCO-AUTH-FRAMEWORK-MIB cafSessionTable (1.3.6.1.4.1.9.9.656.1.4.1.1): for each
 * authenticated client its MAC address, IP address, the port, and the VLAN the authentication server put it in. A port that authenticates
 * its clients is not in the VLAN configured on it, so this is where the VLAN, and often the IP address, of those hosts comes from.
 *
 * Layout, checked against a walk of a Catalyst 9500 SDA edge (69 sessions): index is <ifIndex>.<session id as ASCII bytes>, with
 * col 2 client MAC, 4 client IP (4 raw bytes), 14 VLAN assigned by the server (0 when it assigned none), 10 and 22 names the policy
 * server gave the session (for example IT-Camera and DEVICE_CAMERA); their MIB meaning is not confirmed, so they are shown as given.
 */
import { toNum, type SnmpClient, type SnmpValue } from './client.js';
import { ipOf } from './multicast.js';

export interface AuthSession { ifIndex: number; mac: string; ip: string; vlan: number; policy: string; profile: string }

const T = '1.3.6.1.4.1.9.9.656.1.4.1.1';
const EMPTY = new Map<string, SnmpValue>();
const col = (c: SnmpClient, n: number) => c.column(`${T}.${n}`, 50).catch(() => EMPTY);
const text = (v: SnmpValue | undefined): string => (v === undefined || v === null ? '' : Buffer.isBuffer(v) ? v.toString('utf8').replace(/[^\x20-\x7e]/g, '') : String(v)).trim();

export function macOf(v: SnmpValue | undefined): string | null {
  return Buffer.isBuffer(v) && v.length === 6 ? [...v].map(b => b.toString(16).padStart(2, '0')).join(':') : null;
}

export async function readAuthSessions(c: SnmpClient): Promise<AuthSession[]> {
  const [mac, ip, vlan, policy, profile] = await Promise.all([2, 4, 14, 10, 22].map(n => col(c, n)));
  const out: AuthSession[] = [];
  for (const [idx, v] of mac) {
    const m = macOf(v); if (!m) continue;
    const ifIndex = Number(idx.split('.')[0]); if (!Number.isInteger(ifIndex) || ifIndex <= 0) continue;
    const vl = toNum(vlan.get(idx) ?? null) ?? 0;
    out.push({ ifIndex, mac: m, ip: ipOf(ip.get(idx)) ?? '', vlan: vl >= 1 && vl <= 4094 ? vl : 0, policy: text(policy.get(idx)), profile: text(profile.get(idx)) });
  }
  return out;
}
