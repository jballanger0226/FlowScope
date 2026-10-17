/**
 * Power over Ethernet per port, from CISCO-POWER-ETHERNET-EXT-MIB cpeExtPsePortTable .1.3.6.1.4.1.9.9.402.1.2.1 (index group.port):
 * .7 cpeExtPsePortPwrAllocated, the power the switch has reserved for the device (mW), .9 cpeExtPsePortPwrConsumption, what it draws now (mW),
 * .6 cpeExtPsePortPwrMax, the ceiling set for the port (mW), .3 cpeExtPsePortDeviceDetected, and .11 cpeExtPsePortEntPhyIndex, the physical entity of the port.
 * The entity is turned into an ifIndex through ENTITY-MIB entAliasMappingIdentifier (.1.3.6.1.2.1.47.1.3.2.1.2.<entity>.0, whose value ends in the ifIndex).
 *
 * Checked against a walk of a Catalyst 9300 stack: 96 ports in two groups of 48, entity 1062 is ifIndex 9, allocated 30000 mW and drawn 6252 mW on port 1.1.
 * The denied counter is POWER-ETHERNET-MIB pethPsePortPowerDeniedCounter (.1.3.6.1.2.1.105.1.1.1.12), indexed group.port like the Cisco table; it is 0 on every port of the walk, so
 * its use here is untested against a port that was really refused. The allocated figure is what counts against the budget, the drawn figure is what the device really uses.
 */
import { toNum, type SnmpClient, type SnmpValue } from './client.js';

/** denied is pethPsePortPowerDeniedCounter, the number of times the switch refused the port power (its class asked for more than was left, or the budget was full). deniedAt is when it was last seen to go up. */
export interface PoePort { ifIndex: number; allocW: number; drawnW: number; maxW: number | null; detected: boolean; denied: number | null; deniedAt: number | null }

const T = '1.3.6.1.4.1.9.9.402.1.2.1', ALIAS = '1.3.6.1.2.1.47.1.3.2.1.2';
const EMPTY = new Map<string, SnmpValue>();
const watts = (mw: number | null): number | null => (mw === null ? null : Math.round(mw / 100) / 10);

export async function readPoePorts(c: SnmpClient, prev: PoePort[] | null = null, now = Date.now()): Promise<PoePort[]> {
  const col = (oid: string) => c.column(oid, 50).catch(() => EMPTY);
  const [alloc, drawn, max, det, phy, den] = await Promise.all([`${T}.7`, `${T}.9`, `${T}.6`, `${T}.3`, `${T}.11`, '1.3.6.1.2.1.105.1.1.1.12'].map(col));
  const before = new Map((prev ?? []).map(p => [p.ifIndex, p]));
  if (!alloc!.size) return [];
  const alias = await col(ALIAS);
  const ifOf = new Map<number, number>();
  for (const [k, v] of alias) {
    const e = Number(k.split('.')[0]); const m = typeof v === 'string' ? /\.(\d+)$/.exec(v) : null;
    if (Number.isInteger(e) && m && (typeof v === 'string' && v.includes('2.2.1.1') || /ifIndex/i.test(String(v)))) ifOf.set(e, Number(m[1]));
  }
  const out: PoePort[] = [];
  for (const [k, a] of alloc!) {
    const ifIndex = ifOf.get(toNum(phy!.get(k) ?? null) ?? -1);
    const allocW = watts(toNum(a)), drawnW = watts(toNum(drawn!.get(k) ?? null));
    if (ifIndex === undefined || allocW === null || drawnW === null) continue;
    const denied = toNum(den!.get(k) ?? null), old = before.get(ifIndex);
    const deniedAt = denied !== null && old?.denied != null && denied > old.denied ? now : old?.deniedAt ?? null;
    out.push({ ifIndex, allocW, drawnW, maxW: watts(toNum(max!.get(k) ?? null)), detected: toNum(det!.get(k) ?? null) === 1, denied, deniedAt });
  }
  return out.sort((x, y) => x.ifIndex - y.ifIndex);
}
