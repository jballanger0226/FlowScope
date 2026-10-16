/**
 * DHCP snooping bindings from CISCO-DHCP-SNOOPING-MIB (1.3.6.1.4.1.9.9.380): for each lease the switch saw, the client's MAC address, IP address,
 * VLAN, the port it was learned on and the lease time. A binding is made on the access port the client's request arrived on, so it names the port a
 * host is plugged into without guessing from MAC tables, and it gives an IP address to a host that no router has in its ARP table.
 *
 * Layout, checked against a walk of a Catalyst 9300 stack (319 bindings): cdsBindingsTable .1.4.1.1.<col>.<vlan>.<six MAC bytes>
 * with col 4 address, 5 interface (ifIndex), 6 lease time (seconds), 7 status (1 active).
 */
import { toNum, type SnmpClient, type SnmpValue } from './client.js';
import { ipOf } from './multicast.js';

export interface DhcpBinding { mac: string; vlan: number; ip: string; ifIndex: number; leaseSec: number | null }

const T = '1.3.6.1.4.1.9.9.380.1.4.1.1';
const EMPTY = new Map<string, SnmpValue>();
const col = (c: SnmpClient, n: number) => c.column(`${T}.${n}`, 50).catch(() => EMPTY);

export async function readDhcpBindings(c: SnmpClient): Promise<DhcpBinding[]> {
  const [ip, ifx, lease, status] = await Promise.all([4, 5, 6, 7].map(n => col(c, n)));
  const out: DhcpBinding[] = [];
  for (const [idx, v] of ip) {
    const p = idx.split('.'); if (p.length !== 7) continue;
    const vlan = Number(p[0]), bytes = p.slice(1).map(Number);
    if (!Number.isInteger(vlan) || bytes.some(b => !Number.isInteger(b) || b < 0 || b > 255)) continue;
    const addr = ipOf(v); if (!addr) continue;
    const st = status.get(idx); if (st !== undefined && st !== null && toNum(st) !== 1) continue;   // only active bindings
    out.push({ mac: bytes.map(b => b.toString(16).padStart(2, '0')).join(':'), vlan, ip: addr, ifIndex: toNum(ifx.get(idx) ?? null) ?? 0, leaseSec: toNum(lease.get(idx) ?? null) });
  }
  return out;
}
