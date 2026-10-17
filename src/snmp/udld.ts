/**
 * UDLD (CISCO-UDLDP-MIB .1.3.6.1.4.1.9.9.118.1.2.1.1): per port, cudldpInterfaceOperMode .5 (1 enabled, 2 disabled, 3 aggressive) and cudldpInterfaceOperStatus .2
 * (2 indeterminant: no neighbour heard yet, 3 bidirectional, 4 not applicable: UDLD is off here). Only ports where UDLD is running are listed. A state other than
 * bidirectional or indeterminant (a one-way link, a neighbour mismatch, a loop) is the fault UDLD exists to find; those enum values are not in any walk, so they are
 * shown as their number and always count as a fault.
 *
 * Checked against seven Catalyst walks: UDLD enabled in aggressive mode on 64 ports of one device with every state "indeterminant" (nothing connected, or the other end
 * does not run UDLD) and bidirectional on four.
 */
import { toNum, type SnmpClient, type SnmpValue } from './client.js';

type Level = 'ok' | 'warn' | 'bad' | 'off';
export interface UdldPort { ifIndex: number; mode: 'enabled' | 'aggressive'; state: string; level: Level }
const T = '1.3.6.1.4.1.9.9.118.1.2.1.1', EMPTY = new Map<string, SnmpValue>();
const STATE: Record<number, [string, Level]> = { 1: ['unknown', 'warn'], 2: ['no neighbour heard', 'off'], 3: ['bidirectional', 'ok'] };

export async function readUdld(c: SnmpClient): Promise<UdldPort[]> {
  const col = (o: string) => c.column(o, 50).catch(() => EMPTY);
  const [mode, status] = await Promise.all([col(`${T}.5`), col(`${T}.2`)]);
  const out: UdldPort[] = [];
  for (const [k, v] of mode) {
    const m = toNum(v), ifIndex = Number(k), s = toNum(status.get(k) ?? null);
    if ((m !== 1 && m !== 3) || !Number.isInteger(ifIndex) || s === null || s === 4) continue;
    const [state, level] = STATE[s] ?? [`state ${s} (a UDLD fault)`, 'bad' as Level];
    out.push({ ifIndex, mode: m === 3 ? 'aggressive' : 'enabled', state, level });
  }
  return out.sort((a, b) => a.ifIndex - b.ifIndex);
}
