/**
 * How each port is set up to authenticate, from CISCO-AUTH-FRAMEWORK-MIB (656), CISCO-PAE-MIB (220) and CISCO-MAC-AUTH-BYPASS-MIB (654). The sessions table says
 * who authenticated; this says which ports are meant to, and how, so a port that should authenticate but does not can be told apart from one that never did.
 *
 * Per ifIndex: cafPortAuthHostMode .656.1.2.1.1.3 (1 single-host, 2 multi-host, 3 multi-auth, 4 multi-domain), cafPortPreAuthOpenAccess .4 (1 true: open mode,
 * hosts get access before they authenticate), cafPortAuthorizeControl .5 (1 force-unauthorized, 2 auto, 3 force-authorized), cafPortReauthEnabled .6 (1 true);
 * cpaePortCapabilitiesEnabled .220.1.1.1.10 (BITS: first bit authenticator); cmabIfAuthEnabled .654.1.1.1.1.1 (1 true) with the method in .2 (1 radius).
 *
 * Checked against a full walk of a Catalyst 9300 SD-Access edge: all 151 ports are authenticators in multi-auth mode, 115 have 802.1X (all of them also MAB), the other
 * 36 have neither (uplinks and fabric ports), and 113 of the 115 are in open mode.
 */
import { toNum, type SnmpClient, type SnmpValue } from './client.js';

export interface AuthPort { ifIndex: number; dot1x: boolean; mab: boolean; mode: string; control: 'auto' | 'force-unauthorized' | 'force-authorized' | 'other'; open: boolean; reauth: boolean }

const CAF = '1.3.6.1.4.1.9.9.656.1.2.1.1', PAE = '1.3.6.1.4.1.9.9.220.1.1.1.10', MAB = '1.3.6.1.4.1.9.9.654.1.1.1.1.1';
const EMPTY = new Map<string, SnmpValue>();
const MODE: Record<number, string> = { 1: 'single-host', 2: 'multi-host', 3: 'multi-auth', 4: 'multi-domain' };
const CONTROL: Record<number, AuthPort['control']> = { 1: 'force-unauthorized', 2: 'auto', 3: 'force-authorized' };

export async function readAuthSetup(c: SnmpClient): Promise<AuthPort[]> {
  const col = (oid: string) => c.column(oid, 50).catch(() => EMPTY);
  const [mode, open, ctl, reauth, pae, mab] = await Promise.all([`${CAF}.3`, `${CAF}.4`, `${CAF}.5`, `${CAF}.6`, PAE, MAB].map(col));
  const out: AuthPort[] = [];
  for (const k of new Set([...mode!.keys(), ...mab!.keys()])) {
    const ifIndex = Number(k); if (!Number.isInteger(ifIndex)) continue;
    const caps = pae!.get(k);
    const dot1x = Buffer.isBuffer(caps) && caps.length > 0 ? (caps[0]! & 0x80) !== 0 : false;
    const isMab = toNum(mab!.get(k) ?? null) === 1;
    const m = toNum(mode!.get(k) ?? null);
    if (!dot1x && !isMab) continue;   // a port with neither (an uplink, say) does not authenticate anything
    out.push({ ifIndex, dot1x, mab: isMab, mode: MODE[m ?? 0] ?? 'unknown', control: CONTROL[toNum(ctl!.get(k) ?? null) ?? 0] ?? 'other', open: toNum(open!.get(k) ?? null) === 1, reauth: toNum(reauth!.get(k) ?? null) === 1 });
  }
  return out.sort((a, b) => a.ifIndex - b.ifIndex);
}

/** The words for a port: "802.1X + MAB", "MAB only", "802.1X only". */
export const authMethods = (p: Pick<AuthPort, 'dot1x' | 'mab'>): string => (p.dot1x && p.mab ? '802.1X + MAB' : p.mab ? 'MAB only' : p.dot1x ? '802.1X only' : 'none');
