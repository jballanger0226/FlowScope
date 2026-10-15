import { toNum, toStr, type SnmpValue } from './client.js';
import { macText, type Walker } from './ports.js';
import { bandOf, NA, readWlan, type WlanAp, type WlanClient, type WlanData, type WlanRadio, type WlanSsid } from './wlan.js';

/*
 * Wi-Fi tables of other access point and controller vendors.
 *
 * Unlike the Aruba reader these were written from the vendors' published MIB definitions (UBNT-UniFi-MIB, RUCKUS-ZD-WLAN-MIB,
 * CISCO-LWAPP-AP-MIB and CISCO-LWAPP-DOT11-CLIENT-MIB), not checked against a real device. A column that is not in the MIB is not read, and a
 * value the device does not report is stored as NA so the page shows a dash instead of a made-up number. See docs/verification.md.
 */

export type WlanVendor = 'aruba' | 'unifi' | 'ruckus' | 'cisco';

const num = (v: SnmpValue | undefined, d = 0): number => (v === undefined ? d : toNum(v) ?? d);
const str = (v: SnmpValue | undefined): string => (v === undefined ? '' : toStr(v).trim());
const macOf = (v: SnmpValue | undefined): string => (Buffer.isBuffer(v) && v.length === 6 ? macText(v) : '');
const ipOf = (v: SnmpValue | undefined): string => (Buffer.isBuffer(v) && v.length === 4 ? [...v].join('.') : typeof v === 'string' && /^\d+\.\d+\.\d+\.\d+$/.test(v) ? v : '');
const macFromIndex = (parts: string[]): string => (parts.length >= 6 && parts.slice(0, 6).every(p => /^\d+$/.test(p) && Number(p) < 256) ? macText(parts.slice(0, 6).map(Number)) : '');
const rd = (c: Walker, oid: string) => c.column(oid, 20).catch(() => new Map<string, SnmpValue>());

/** Which vendor's Wi-Fi tables to try for a device, from its sysObjectID and description. Null for devices that are not known to have any. */
export function wlanVendor(objectId: string, descr: string): WlanVendor | null {
  const t = descr.toLowerCase();
  if (objectId.startsWith('1.3.6.1.4.1.14823.')) return 'aruba';
  if (objectId.startsWith('1.3.6.1.4.1.41112.')) return 'unifi';
  if (objectId.startsWith('1.3.6.1.4.1.25053.')) return 'ruckus';
  // Cisco: only wireless controllers (and their embedded kind) publish the LWAPP tables, so a switch is not asked
  if (objectId.startsWith('1.3.6.1.4.1.9.') && /\bc9800\b|air-ct|aireos|wireless lan controller|wireless controller|\bwlc\b|catalyst 9800|virtual wireless/.test(t)) return 'cisco';
  return null;
}

/** What each vendor's own MIB says is and is not available, for the Wi-Fi panel. */
export const WLAN_VENDOR_NOTE: Record<WlanVendor, string> = {
  aruba: '',
  unifi: 'UniFi access points publish their SSIDs and channel use over SNMP, but not their individual wireless clients.',
  ruckus: 'Ruckus publishes its access points and WLANs over SNMP; per-client and per-radio detail was not available to read.',
  cisco: 'Cisco wireless controllers publish their access points and clients over SNMP; signal strength, radios and traffic per client are not available in a table.'
};

/** Ubiquiti UniFi (UBNT-UniFi-MIB, enterprise 41112, .1.6). One access point per device. */
export async function readUnifi(c: Walker): Promise<WlanData | null> {
  const U = '1.3.6.1.4.1.41112.1.6';
  const vap = (n: number) => rd(c, `${U}.1.2.1.${n}`);
  const rad = (n: number) => rd(c, `${U}.1.1.1.${n}`);
  const sys = (n: number) => rd(c, `${U}.3.${n}`);
  const vEss = await vap(6);
  if (!vEss.size) return null;
  const [vBss, vChan, vName, vSta, vRadio, vPow, vUp, rName, rRadio, rCu, sIp, sModel, sUp] = await Promise.all([
    vap(2), vap(4), vap(7), vap(8), vap(9), vap(21), vap(22), rad(2), rad(3), rad(6), sys(1), sys(3), sys(5)
  ]);
  const ap: WlanAp = { mac: '', name: '', ip: ipOf(sIp.get('0')), serial: '', model: str(sModel.get('0')), cpuPct: NA, memFree: 0, memTotal: 0, uptimeSec: num(sUp.get('0')), role: '' };
  // radios: "ng" is 2.4 GHz and "na" is 5 GHz; the channel is a property of the SSID (VAP) rows
  const radios: WlanRadio[] = []; const ssids: WlanSsid[] = [];
  const chanOfRadio = new Map<string, string>(); const powOfRadio = new Map<string, number>(); const staOfRadio = new Map<string, number>(); const upOfRadio = new Map<string, boolean>();
  for (const [k] of vEss) {
    const r = str(vRadio.get(k)); if (!r) continue;
    if (!chanOfRadio.has(r) && num(vChan.get(k))) chanOfRadio.set(r, String(num(vChan.get(k))));
    if (!powOfRadio.has(r)) powOfRadio.set(r, num(vPow.get(k), NA));
    staOfRadio.set(r, (staOfRadio.get(r) ?? 0) + num(vSta.get(k)));
    upOfRadio.set(r, (upOfRadio.get(r) ?? false) || num(vUp.get(k), 1) === 1);
  }
  let i = 0;
  for (const [k, name] of rRadio) {
    const r = str(name); const channel = chanOfRadio.get(r) ?? '';
    const cu = num(rCu.get(k), NA);
    // one "channel utilisation" figure is published, not a 4 and a 64 second average
    radios.push({ apMac: '', idx: i++, mac: '', channel, band: r === 'ng' ? '2.4' : r === 'na' ? '5' : bandOf(channel), txPower: powOfRadio.get(r) ?? NA, noiseFloor: NA, util4: NA, util64: cu, clients: staOfRadio.get(r) ?? 0, mode: str(rName.get(k)), up: upOfRadio.get(r) ?? true });
  }
  const radioIdx = new Map(radios.map(r => [r.band === '2.4' ? 'ng' : r.band === '5' ? 'na' : '', r.idx]));
  for (const [k, essid] of vEss) {
    const bssid = macOf(vBss.get(k)); if (!bssid) continue;
    const r = str(vRadio.get(k));
    ssids.push({ apMac: '', name: str(essid), bssid, radio: radioIdx.get(r) ?? null, ssidId: null, clients: num(vSta.get(k)), ifName: str(vName.get(k)) || null });
  }
  if (!radios.length && !ssids.length) return null;
  return { aps: [ap], radios, ssids, clients: [], vendor: 'unifi' };
}

/** Ruckus ZoneDirector and Unleashed (RUCKUS-ZD-WLAN-MIB, enterprise 25053, .1.2.2.1.1): the access points and the WLANs (SSIDs). */
export async function readRuckus(c: Walker): Promise<WlanData | null> {
  const Z = '1.3.6.1.4.1.25053.1.2.2.1.1';
  const apc = (n: number) => rd(c, `${Z}.2.1.1.${n}`);
  const wl = (n: number) => rd(c, `${Z}.1.1.1.${n}`);
  const [aDesc, wSsid] = await Promise.all([apc(2), wl(1)]);
  if (!aDesc.size && !wSsid.size) return null;
  const [aModel, aSerial, aUp, aIp, aCpu] = await Promise.all([4, 5, 6, 10, 29].map(apc));
  const [wSta, wDesc] = await Promise.all([wl(12), wl(2)]);
  const aps: WlanAp[] = [];
  for (const [k, v] of aDesc) {
    const mac = macFromIndex(k.split('.')); if (!mac) continue;
    aps.push({ mac, name: str(v), ip: ipOf(aIp.get(k)), serial: str(aSerial.get(k)), model: str(aModel.get(k)), cpuPct: aCpu.has(k) ? num(aCpu.get(k)) : NA, memFree: 0, memTotal: 0, uptimeSec: Math.floor(num(aUp.get(k)) / 100), role: '' });
  }
  const ssids: WlanSsid[] = [];
  for (const [k, v] of wSsid) ssids.push({ apMac: '', name: str(v) || str(wDesc.get(k)), bssid: `wlan-${k}`, radio: null, ssidId: null, clients: num(wSta.get(k)), ifName: null });
  return { aps, radios: [], ssids, clients: [], vendor: 'ruckus' };
}

/** Cisco wireless controllers (CISCO-LWAPP-AP-MIB and CISCO-LWAPP-DOT11-CLIENT-MIB): the access points and the clients associated to them. */
export async function readCiscoWlc(c: Walker): Promise<WlanData | null> {
  const AP = '1.3.6.1.4.1.9.9.513.1.1.1.1', CL = '1.3.6.1.4.1.9.9.599.1.3.1.1';
  const ap = (n: number) => rd(c, `${AP}.${n}`);
  const cl = (n: number) => rd(c, `${CL}.${n}`);
  const aName = await ap(49);
  const cMac = await cl(2);   // client status; its index is the client's MAC address
  if (!aName.size && !cMac.size) return null;
  const [aUp, aCpu] = await Promise.all([ap(59), ap(56)]);
  const aps: WlanAp[] = []; const apNames = new Map<string, string>();
  for (const [k, v] of aName) {
    const mac = macFromIndex(k.split('.')); if (!mac) continue;
    apNames.set(mac, str(v));
    aps.push({ mac, name: str(v), ip: '', serial: '', model: '', cpuPct: aCpu.has(k) ? num(aCpu.get(k)) : NA, memFree: 0, memTotal: 0, uptimeSec: Math.floor(num(aUp.get(k)) / 100), role: '' });
  }
  const [cSsid, cAp, cIp, cUser, cUp, cDev, cRate] = await Promise.all([28, 8, 10, 27, 15, 44, 50].map(cl));
  const clients: WlanClient[] = [];
  for (const [k] of cMac) {
    const mac = macFromIndex(k.split('.')); if (!mac) continue;
    const apMac = macOf(cAp.get(k));
    clients.push({ mac, apMac, apName: apNames.get(apMac) ?? '', bssid: '', ssid: str(cSsid.get(k)), radio: null, ip: ipOf(cIp.get(k)), name: str(cUser.get(k)), os: str(cDev.get(k)),
      snr: NA, txRate: num(cRate.get(k)), rxRate: 0, txBytes: 0, rxBytes: 0, uptimeSec: num(cUp.get(k)) });
  }
  const bySsid = new Map<string, number>();
  for (const x of clients) if (x.ssid) bySsid.set(x.ssid, (bySsid.get(x.ssid) ?? 0) + 1);
  const ssids: WlanSsid[] = [...bySsid].map(([name, n]) => ({ apMac: '', name, bssid: `ssid-${name}`, radio: null, ssidId: null, clients: n, ifName: null }));
  return { aps, radios: [], ssids, clients, vendor: 'cisco' };
}

/** Reads whichever vendor's Wi-Fi tables the device is known for. Null when it has none. */
export async function readWlanFor(c: Walker, ifaces: { index: number; name: string }[], objectId: string, descr: string): Promise<WlanData | null> {
  switch (wlanVendor(objectId, descr)) {
    case 'aruba': { const w = await readWlan(c, ifaces); return w ? { ...w, vendor: 'aruba' } : null; }
    case 'unifi': return readUnifi(c);
    case 'ruckus': return readRuckus(c);
    case 'cisco': return readCiscoWlc(c);
    default: return null;
  }
}
