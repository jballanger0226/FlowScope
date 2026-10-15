import { toNum, toStr, type SnmpValue } from './client.js';
import { macText, type Walker } from './ports.js';

/*
 * Aruba Instant access points: radios, SSIDs and wireless clients.
 *
 * An Instant AP publishes its Wi-Fi state in Aruba's own AI-AP-MIB (enterprise 14823, .2.3.3). The AP and the cluster's other APs are rows of
 * the AP table (indexed by AP MAC address); radios, SSIDs and clients hang off it. The standard MIBs say nothing about clients, so this is
 * where the client's name, IP address, operating system and signal come from.
 *
 * The column meanings below were worked out from a real AP (ArubaOS 8.12, model 535) by reading the values, not from the MIB file. Where a
 * column could not be pinned down it is not read. See docs/verification.md.
 */

const AI = '1.3.6.1.4.1.14823.2.3.3.1';
export const WLAN_OID = {
  ap: AI + '.2.1.1',       // aiAccessPointTable
  radio: AI + '.2.2.1',    // aiRadioTable: index apMac.radioIndex
  ssid: AI + '.2.3.1',     // aiSSIDTable: index apMac.row
  client: AI + '.2.4.1',   // aiClientTable: index clientMac
  clientAp: AI + '.2.5.1'  // client to AP
};

export interface WlanAp { mac: string; name: string; ip: string; serial: string; model: string; cpuPct: number; memFree: number; memTotal: number; uptimeSec: number; role: string }
export interface WlanRadio {
  apMac: string; idx: number; mac: string; channel: string; band: '2.4' | '5' | ''; txPower: number; noiseFloor: number;
  /** Channel busy, averaged over the last 4 seconds and the last 64 seconds. */
  util4: number; util64: number; clients: number; mode: string; up: boolean
}
export interface WlanSsid { apMac: string; name: string; bssid: string; radio: number | null; ssidId: number | null; clients: number; ifName: string | null }
export interface WlanClient {
  mac: string; apMac: string; apName: string; bssid: string; ssid: string; radio: number | null; ip: string; name: string; os: string;
  /** Signal to noise ratio in dB. */
  snr: number; txRate: number; rxRate: number; txBytes: number; rxBytes: number; uptimeSec: number
}
/** A value the device does not report. Stored as is and shown as a dash. */
export const NA = -1000;
export interface WlanData { aps: WlanAp[]; radios: WlanRadio[]; ssids: WlanSsid[]; clients: WlanClient[]; vendor?: 'aruba' | 'unifi' | 'ruckus' | 'cisco' }

const num = (v: SnmpValue | undefined, d = 0): number => (v === undefined ? d : toNum(v) ?? d);
const str = (v: SnmpValue | undefined): string => (v === undefined ? '' : toStr(v).trim());
const macOf = (v: SnmpValue | undefined): string => (Buffer.isBuffer(v) && v.length === 6 ? macText(v) : '');
const ipOf = (v: SnmpValue | undefined): string => (Buffer.isBuffer(v) && v.length === 4 ? [...v].join('.') : typeof v === 'string' && /^\d+\.\d+\.\d+\.\d+$/.test(v) ? v : '');
const macFromIndex = (parts: string[]): string => (parts.length >= 6 && parts.slice(0, 6).every(p => /^\d+$/.test(p) && Number(p) < 256) ? macText(parts.slice(0, 6).map(Number)) : '');

/** 5 GHz channels are 36 and up and 2.4 GHz channels are 1 to 14. A 6 GHz radio reuses the low numbers and cannot be told apart here. */
export function bandOf(channel: string): '2.4' | '5' | '' {
  const n = Number(/^\d+/.exec(channel)?.[0] ?? NaN);
  return !Number.isFinite(n) ? '' : n >= 36 ? '5' : n >= 1 && n <= 14 ? '2.4' : '';
}

/** Which radio a BSSID belongs to: the same address with the last octet's low nibble holding the SSID number. */
function radioOfBssid(bssid: string, radios: WlanRadio[]): WlanRadio | null {
  const b = bssid.split(':'); if (b.length !== 6) return null;
  return radios.find(r => { const m = r.mac.split(':'); return m.length === 6 && m.slice(0, 5).join(':') === b.slice(0, 5).join(':') && (parseInt(m[5], 16) & 0xf0) === (parseInt(b[5], 16) & 0xf0); }) ?? null;
}

/** Reads the Aruba Instant tables. Returns null when the device does not publish them (not an Instant AP). */
export async function readWlan(c: Walker, ifaces: { index: number; name: string }[] = []): Promise<WlanData | null> {
  const rd = (oid: string) => c.column(oid, 20).catch(() => new Map<string, SnmpValue>());
  const col = (base: string, n: number) => rd(`${base}.${n}`);
  const apName = await col(WLAN_OID.ap, 2);
  if (!apName.size) return null;
  const [apIp, apSerial, apModel, apCpu, apMemFree, apUp, apMemTotal, apRole] = await Promise.all([3, 4, 6, 7, 8, 9, 10, 13].map(n => col(WLAN_OID.ap, n)));
  const aps: WlanAp[] = [];
  for (const [k, v] of apName) {
    const mac = macFromIndex(k.split('.')); if (!mac) continue;
    aps.push({ mac, name: str(v), ip: ipOf(apIp.get(k)), serial: str(apSerial.get(k)), model: str(apModel.get(k)), cpuPct: num(apCpu.get(k)), memFree: num(apMemFree.get(k)), memTotal: num(apMemTotal.get(k)), uptimeSec: Math.floor(num(apUp.get(k)) / 100), role: str(apRole.get(k)) });
  }

  const [rMac, rIdx, rChan, rPower, rNoise, rU4, rU64, rStatus, rClients, rMode] = await Promise.all([3, 2, 4, 5, 6, 7, 8, 20, 21, 22].map(n => col(WLAN_OID.radio, n)));
  const radios: WlanRadio[] = [];
  for (const [k, v] of rMac) {
    const p = k.split('.'); const apMac = macFromIndex(p); const mac = macOf(v); if (!apMac || !mac) continue;
    const channel = str(rChan.get(k));
    // the noise floor is published as a positive number (92 means -92 dBm)
    radios.push({ apMac, idx: num(rIdx.get(k), Number(p[6] ?? 0)), mac, channel, band: bandOf(channel), txPower: num(rPower.get(k)), noiseFloor: -Math.abs(num(rNoise.get(k))), util4: num(rU4.get(k)), util64: num(rU64.get(k)), clients: num(rClients.get(k)), mode: str(rMode.get(k)), up: num(rStatus.get(k), 1) === 1 });
  }

  const [sName, sBssid] = await Promise.all([3, 4].map(n => col(WLAN_OID.ssid, n)));
  const [cBssid, cIp, cName, cOs, cSnr, cTxB, cTxRate, cRxB, cRxRate, cUp, cAp, cApName] = await Promise.all([
    col(WLAN_OID.client, 2), col(WLAN_OID.client, 3), col(WLAN_OID.client, 5), col(WLAN_OID.client, 6), col(WLAN_OID.client, 7), col(WLAN_OID.client, 9), col(WLAN_OID.client, 11), col(WLAN_OID.client, 13),
    col(WLAN_OID.client, 15), col(WLAN_OID.client, 16), col(WLAN_OID.clientAp, 3), col(WLAN_OID.clientAp, 4)
  ]);
  const ssidOfBssid = new Map<string, string>();
  for (const [k, v] of sBssid) { const b = macOf(v); if (b) ssidOfBssid.set(b, str(sName.get(k))); }

  const clients: WlanClient[] = [];
  for (const [k] of cBssid) {
    const mac = macFromIndex(k.split('.')); if (!mac) continue;
    const bssid = macOf(cBssid.get(k));
    const r = radioOfBssid(bssid, radios);
    const os = str(cOs.get(k));
    clients.push({
      mac, apMac: macOf(cAp.get(k)) || r?.apMac || '', apName: str(cApName.get(k)), bssid, ssid: ssidOfBssid.get(bssid) ?? '', radio: r ? r.idx : null, ip: ipOf(cIp.get(k)), name: str(cName.get(k)),
      os: os === 'NOFP' ? '' : os,   // NOFP: no fingerprint was possible
      snr: num(cSnr.get(k)), txRate: num(cTxRate.get(k)), rxRate: num(cRxRate.get(k)), txBytes: num(cTxB.get(k)), rxBytes: num(cRxB.get(k)), uptimeSec: Math.floor(num(cUp.get(k)) / 100)
    });
  }

  // an SSID on one radio is a row of the SSID table; its interface (radioN_ssid_idM) is only known when this is a single AP, since every AP has the same names
  const ifByName = new Map(ifaces.map(i => [i.name, i.name]));
  const ssids: WlanSsid[] = [];
  for (const [k, v] of sBssid) {
    const apMac = macFromIndex(k.split('.')); const bssid = macOf(v); if (!apMac || !bssid) continue;
    const r = radioOfBssid(bssid, radios); const id = parseInt(bssid.split(':')[5], 16) & 0x0f;
    const ifn = aps.length === 1 && r ? `radio${r.idx}_ssid_id${id}` : null;
    ssids.push({ apMac, name: str(sName.get(k)), bssid, radio: r ? r.idx : null, ssidId: r ? id : null, clients: clients.filter(x => x.bssid === bssid).length, ifName: ifn && ifByName.has(ifn) ? ifn : null });
  }
  return { aps, radios, ssids, clients };
}
