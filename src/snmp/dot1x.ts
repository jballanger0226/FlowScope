/**
 * Ports that run 802.1X, from the standard IEEE8021-PAE-MIB (1.0.8802.1.1.1), which every vendor that does 802.1X implements: dot1xAuthConfigTable
 * (.1.2.1.1.<col>.<port>) with col 5 dot1xAuthAuthControlledPortStatus (1 authorized, 2 unauthorized) and col 6 dot1xAuthAuthControlledPortControl
 * (1 force-unauthorized, 2 auto, 3 force-authorized). A port in `auto` is one that authenticates its clients.
 *
 * Columns and index checked against a full walk of a Catalyst 9300 (151 ports, all `auto`, all `unauthorized` because it runs multi-auth host mode: the status is per port, so with several clients authenticating separately it is not a measure of who is in). Not yet seen on any other vendor (see docs/verification.md). The port number is the ifIndex.
 * Unlike the Cisco session table this gives no client, address or VLAN, only which ports authenticate and whether they are open.
 */
import { toNum, type SnmpClient, type SnmpValue } from './client.js';

export interface PaePort { ifIndex: number; control: 'auto' | 'force-unauthorized' | 'force-authorized' | 'other'; authorized: boolean }

const T = '1.0.8802.1.1.1.1.2.1.1';
const EMPTY = new Map<string, SnmpValue>();
const CONTROL: Record<number, PaePort['control']> = { 1: 'force-unauthorized', 2: 'auto', 3: 'force-authorized' };

export async function readPae(c: SnmpClient): Promise<PaePort[]> {
  const [status, control] = await Promise.all([5, 6].map(n => c.column(`${T}.${n}`, 50).catch(() => EMPTY)));
  const out: PaePort[] = [];
  for (const [idx, v] of control) {
    const ifIndex = Number(idx); if (!Number.isInteger(ifIndex) || ifIndex <= 0) continue;
    out.push({ ifIndex, control: CONTROL[toNum(v) ?? 0] ?? 'other', authorized: toNum(status.get(idx) ?? null) === 1 });
  }
  return out.sort((a, b) => a.ifIndex - b.ifIndex);
}
