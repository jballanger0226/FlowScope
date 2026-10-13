import type { SnmpClient, SnmpValue } from './client.js';
import { toNum, toStr } from './client.js';
import { OID } from './oids.js';

/*
 * Switch-port information read over SNMP: which VLAN a port is in, who is plugged into it (LLDP / CDP neighbours),
 * which MAC addresses the switch has learned on it, and the ARP table that turns those MAC addresses into IP addresses.
 * Together these say which switch port a host is connected to, which flow records alone cannot tell for multicast.
 *
 * The readers only need `column()`, so tests can feed them a small in-memory table instead of a device.
 */

export interface Walker { column(oid: string, maxRep?: number): Promise<Map<string, SnmpValue>> }

const empty = (): Map<string, SnmpValue> => new Map();
const num = (v: SnmpValue | undefined, d = 0): number => (v === undefined ? d : toNum(v) ?? d);
const rd = (c: Walker, oid: string, maxRep = 20) => c.column(oid, maxRep).catch(empty);

/* ------------------------------------------------------------------ helpers */

export function macText(b: Buffer | number[]): string { return [...b].map(x => x.toString(16).padStart(2, '0')).join(':'); }
/** The MAC address in an SNMP index suffix such as "140.0.80.86.10.1.4" (the first parts may be a VLAN) or an OctetString value. */
export function macFromParts(parts: number[]): string | null {
  if (parts.length < 6) return null;
  const m = parts.slice(parts.length - 6);
  if (m.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return macText(m);
}
export function macFromValue(v: SnmpValue | undefined): string | null {
  if (!Buffer.isBuffer(v) || v.length !== 6) return null;
  return macText(v);
}
const isZeroMac = (m: string) => m === '00:00:00:00:00:00';

/** Turns a set of VLAN ids into "1,10-20,30". */
export function compressVlans(ids: Iterable<number>): string {
  const a = [...new Set(ids)].filter(n => n >= 1 && n <= 4094).sort((x, y) => x - y);
  if (!a.length) return '';
  if (a.length >= 4094) return 'all';
  const out: string[] = [];
  for (let i = 0; i < a.length;) {
    let j = i; while (j + 1 < a.length && a[j + 1] === a[j] + 1) j++;
    out.push(j > i ? `${a[i]}-${a[j]}` : String(a[i])); i = j + 1;
  }
  return out.join(',');
}
/** True when the VLAN is one of the ids in a compressVlans() string. */
export function vlanListHas(list: string, vlan: number): boolean {
  if (!list || !vlan) return false;
  if (list === 'all') return true;
  return list.split(',').some(p => { const [a, b] = p.split('-').map(Number); return b === undefined ? a === vlan : vlan >= a && vlan <= b; });
}
/** The VLAN ids set in one of the 128-byte trunk bitmaps. The most significant bit of the first byte is VLAN `base`. */
export function bitmapVlans(v: SnmpValue | undefined, base: number): number[] {
  if (!Buffer.isBuffer(v)) return [];
  const out: number[] = [];
  for (let i = 0; i < v.length; i++) { const byte = v[i]; if (!byte) continue; for (let b = 0; b < 8; b++) if (byte & (0x80 >> b)) out.push(base + i * 8 + b); }
  return out;
}

/** "Vlan140", "Vl140", "BDI140", "irb.140", "Vlan-interface140": a switched virtual interface. Returns the VLAN id. */
export function sviVlan(name: string, descr = ''): number | null {
  for (const t of [name, descr]) {
    const m = /^(?:vlan|vl|bdi|irb)[\s._-]*(\d{1,4})$/i.exec(t.trim()) ?? /^vlan-interface\s*(\d{1,4})$/i.exec(t.trim());
    if (m) { const n = Number(m[1]); if (n >= 1 && n <= 4094) return n; }
  }
  return null;
}
/** A VLAN or SVI interface: these carry routed traffic for a whole subnet and are left out of "needs attention". */
export function isVlanInterface(i: { name: string; descr?: string; ifType?: number; portMode?: string }): boolean {
  return i.portMode === 'svi' || sviVlan(i.name, i.descr ?? '') !== null || i.ifType === 53 || i.ifType === 135 || i.ifType === 136;
}

/* ------------------------------------------------------------------ port VLANs */

export interface PortVlan {
  /** access: untagged in one VLAN; trunk: tagged VLANs plus a native one; pvid: a standard bridge port (native VLAN, trunk state unknown); svi: a VLAN interface; routed: a Layer 3 port */
  mode: 'access' | 'trunk' | 'pvid' | 'svi' | 'routed';
  vlan: number; voice: number; allowed: string;
}

/**
 * VLAN of every port. Cisco switches report it in CISCO-VLAN-MEMBERSHIP-MIB (access) and CISCO-VTP-MIB (trunks), which is what
 * Catalyst switches implement; other vendors fall back to the standard Q-BRIDGE-MIB port VLAN id.
 */
export async function readPortVlans(c: Walker, ifaces: { index: number; name: string; descr?: string }[], ips: { ifIndex: number }[] = []): Promise<Map<number, PortVlan>> {
  const [vm, voice, tStatus, tNative, e0, e1, e2, e3, pvid, basePort] = await Promise.all([
    rd(c, OID.vmVlan), rd(c, OID.vmVoiceVlanId), rd(c, OID.vlanTrunkPortDynamicStatus), rd(c, OID.vlanTrunkPortNativeVlan),
    rd(c, OID.vlanTrunkPortVlansEnabled), rd(c, OID.vlanTrunkPortVlansEnabled2k), rd(c, OID.vlanTrunkPortVlansEnabled3k), rd(c, OID.vlanTrunkPortVlansEnabled4k),
    rd(c, OID.dot1qPvid), rd(c, OID.dot1dBasePortIfIndex)
  ]);
  const pvidByIf = new Map<number, number>();
  for (const [bp, v] of pvid) { const ifx = basePort.size ? num(basePort.get(bp), 0) : Number(bp); if (ifx > 0 && num(v) > 0) pvidByIf.set(ifx, num(v)); }
  const routedIf = new Set(ips.map(i => i.ifIndex));
  const out = new Map<number, PortVlan>();
  for (const i of ifaces) {
    const k = String(i.index);
    const svi = sviVlan(i.name, i.descr ?? '');
    const vv = num(voice.get(k));
    const voiceVlan = vv >= 1 && vv <= 4094 ? vv : 0;
    if (svi !== null) { out.set(i.index, { mode: 'svi', vlan: svi, voice: 0, allowed: '' }); continue; }
    if (num(tStatus.get(k)) === 1) {
      const allowed = compressVlans([...bitmapVlans(e0.get(k), 0), ...bitmapVlans(e1.get(k), 1024), ...bitmapVlans(e2.get(k), 2048), ...bitmapVlans(e3.get(k), 3072)]);
      out.set(i.index, { mode: 'trunk', vlan: num(tNative.get(k), 1), voice: voiceVlan, allowed });
      continue;
    }
    const acc = num(vm.get(k));
    if (acc >= 1 && acc <= 4094) { out.set(i.index, { mode: 'access', vlan: acc, voice: voiceVlan, allowed: '' }); continue; }
    const pv = pvidByIf.get(i.index);
    if (pv) { out.set(i.index, { mode: 'pvid', vlan: pv, voice: voiceVlan, allowed: '' }); continue; }
    if (routedIf.has(i.index)) out.set(i.index, { mode: 'routed', vlan: 0, voice: 0, allowed: '' });
  }
  return out;
}

/* ------------------------------------------------------------------ neighbours (LLDP, CDP) */

export type NeighborKind = 'infra' | 'phone' | 'ap' | 'host' | 'other';
export interface Neighbor { ifIndex: number; proto: 'lldp' | 'cdp'; key: string; name: string; port: string; ip: string; kind: NeighborKind; caps: string[] }

const LLDP_CAPS = ['other', 'repeater', 'bridge', 'wlan-ap', 'router', 'telephone', 'docsis', 'station'];
export function lldpCaps(v: SnmpValue | undefined): string[] {
  if (!Buffer.isBuffer(v) || !v.length) return [];
  return LLDP_CAPS.filter((_, i) => v[0] & (0x80 >> i));
}
/** A neighbour is infrastructure (the port is an uplink to another switch or router) unless it is a phone, an access point or an end host. */
export function lldpKind(caps: string[]): NeighborKind {
  if (caps.includes('telephone')) return 'phone';
  if (caps.includes('wlan-ap')) return 'ap';
  if (caps.includes('bridge') || caps.includes('router') || caps.includes('repeater')) return 'infra';
  if (caps.includes('station')) return 'host';
  return 'other';
}
const CDP_CAPS: [number, string][] = [[0x01, 'router'], [0x02, 'trans-bridge'], [0x04, 'source-route-bridge'], [0x08, 'switch'], [0x10, 'host'], [0x20, 'igmp'], [0x40, 'repeater']];
export function cdpCaps(v: SnmpValue | undefined): string[] {
  if (!Buffer.isBuffer(v) || !v.length) return [];
  let n = 0; for (const b of v) n = n * 256 + b;
  return CDP_CAPS.filter(([bit]) => n & bit).map(([, name]) => name);
}
export function cdpKind(caps: string[], platform: string): NeighborKind {
  if (/phone/i.test(platform)) return 'phone';
  if (/\bAIR-|aironet|\bAP\d|C9[1-9]\d\dAX|CW9\d|MR\d\d/i.test(platform)) return 'ap';
  if (caps.some(c => c === 'router' || c === 'switch' || c === 'source-route-bridge' || c === 'repeater')) return 'infra';
  if (caps.includes('trans-bridge')) return 'ap';
  if (caps.includes('host')) return 'host';
  return 'other';
}

export async function readNeighbors(c: Walker, ifaces: { index: number; name: string; descr?: string }[]): Promise<Neighbor[]> {
  const out: Neighbor[] = [];
  const known = new Set(ifaces.map(i => i.index));
  // LLDP: index is timeMark.localPortNum.remoteIndex. localPortNum is the ifIndex on most devices; otherwise match the local port id or description to an interface name.
  const [lName, lCap, lChassis, lPortId, lPortDesc, locId, locDesc] = await Promise.all([
    rd(c, OID.lldpRemSysName), rd(c, OID.lldpRemSysCapEnabled), rd(c, OID.lldpRemChassisId), rd(c, OID.lldpRemPortId), rd(c, OID.lldpRemPortDesc),
    rd(c, OID.lldpLocPortId), rd(c, OID.lldpLocPortDesc)
  ]);
  const byName = new Map<string, number>();
  for (const i of ifaces) { byName.set(i.name.toLowerCase(), i.index); if (i.descr) byName.set(i.descr.toLowerCase(), i.index); }
  const localIf = (port: number): number | null => {
    if (known.has(port)) return port;
    for (const t of [locDesc.get(String(port)), locId.get(String(port))]) { const s = toStr(t ?? null).toLowerCase(); if (s && byName.has(s)) return byName.get(s)!; }
    return null;
  };
  const keys = new Set([...lName.keys(), ...lCap.keys(), ...lChassis.keys(), ...lPortId.keys()]);
  for (const k of keys) {
    const [, port] = k.split('.').map(Number);
    const ifx = localIf(port); if (ifx === null) continue;
    const caps = lldpCaps(lCap.get(k));
    const chassis = lChassis.get(k);
    const chassisText = Buffer.isBuffer(chassis) ? (chassis.length === 6 ? macText(chassis) : toStr(chassis)) : toStr(chassis ?? null);
    const name = toStr(lName.get(k) ?? null) || chassisText;
    out.push({ ifIndex: ifx, proto: 'lldp', key: k, name, port: toStr(lPortDesc.get(k) ?? null) || toStr(lPortId.get(k) ?? null), ip: '', kind: lldpKind(caps), caps });
  }
  // CDP: index is ifIndex.deviceIndex
  const [dId, dPort, dPlat, dCap, dAddr] = await Promise.all([rd(c, OID.cdpCacheDeviceId), rd(c, OID.cdpCacheDevicePort), rd(c, OID.cdpCachePlatform), rd(c, OID.cdpCacheCapabilities), rd(c, OID.cdpCacheAddress)]);
  for (const [k, v] of dId) {
    const ifx = Number(k.split('.')[0]); if (!known.has(ifx)) continue;
    const platform = toStr(dPlat.get(k) ?? null), caps = cdpCaps(dCap.get(k));
    const a = dAddr.get(k);
    out.push({ ifIndex: ifx, proto: 'cdp', key: k, name: toStr(v).replace(/\(.*\)$/, ''), port: toStr(dPort.get(k) ?? null), ip: Buffer.isBuffer(a) && a.length === 4 ? [...a].join('.') : '', kind: cdpKind(caps, platform), caps });
  }
  return out;
}

/* ------------------------------------------------------------------ ARP / neighbour cache */

export interface ArpEntry { ip: string; mac: string; ifIndex: number }

function ipv6Text(b: number[]): string | null {
  if (b.length !== 16) return null;
  const g: string[] = []; for (let i = 0; i < 16; i += 2) g.push(((b[i] << 8) | b[i + 1]).toString(16));
  try { return new URL('http://[' + g.join(':') + ']').hostname.slice(1, -1); } catch { return null; }
}

export async function readArp(c: Walker): Promise<ArpEntry[]> {
  const out: ArpEntry[] = [];
  const [phys, type, state] = await Promise.all([rd(c, OID.ipNetToPhysicalPhysAddress), rd(c, OID.ipNetToPhysicalType), rd(c, OID.ipNetToPhysicalState)]);
  for (const [k, v] of phys) {
    // ifIndex.addressType.length.address bytes
    const p = k.split('.').map(Number);
    const ifIndex = p[0], t = p[1], len = p[2], addr = p.slice(3);
    if (addr.length !== len) continue;
    const mac = macFromValue(v); if (!mac || isZeroMac(mac)) continue;
    const ty = num(type.get(k), 3), st = num(state.get(k), 1);
    if (ty === 2 || ty === 5 || st === 5 || st === 6 || st === 7) continue;   // invalid, the device's own address, or no answer yet
    let ip: string | null = null;
    if (t === 1 && len === 4) ip = addr.join('.');
    else if (t === 2 && len === 16) ip = ipv6Text(addr);
    if (!ip || /^fe[89ab]/i.test(ip)) continue;
    out.push({ ip, mac, ifIndex });
  }
  if (out.length) return out;
  const [mp, mt] = await Promise.all([rd(c, OID.ipNetToMediaPhysAddress), rd(c, OID.ipNetToMediaType)]);
  for (const [k, v] of mp) {
    const p = k.split('.').map(Number);
    if (p.length !== 5) continue;
    const mac = macFromValue(v); if (!mac || isZeroMac(mac)) continue;
    if (num(mt.get(k), 3) === 2) continue;
    out.push({ ip: p.slice(1).join('.'), mac, ifIndex: p[0] });
  }
  return out;
}

/* ------------------------------------------------------------------ MAC address table */

export interface FdbEntry { mac: string; vlan: number; ifIndex: number }
export interface FdbResult { entries: FdbEntry[]; method: string; vlansTried: number; vlansFailed: number }

/** Entries a bridge reports for itself or as invalid are not hosts. */
const learned = (status: SnmpValue | undefined) => { const s = status === undefined ? 3 : num(status, 3); return s === 3 || s === 1 || s === 5; };

async function bridgeTable(c: Walker, strict = false): Promise<{ qbridge: FdbEntry[]; dot1d: FdbEntry[] }> {
  // in strict mode (one VLAN of a Cisco switch) a failure to read the MAC table is an error, so an unusable community or context is noticed instead of looking like an empty VLAN
  const [baseIf, qPort, qStatus, dPort, dStatus] = await Promise.all([rd(c, OID.dot1dBasePortIfIndex), strict ? empty() : rd(c, OID.dot1qTpFdbPort, 50), strict ? empty() : rd(c, OID.dot1qTpFdbStatus, 50), strict ? c.column(OID.dot1dTpFdbPort, 50) : rd(c, OID.dot1dTpFdbPort, 50), rd(c, OID.dot1dTpFdbStatus, 50)]);
  const toIf = (bp: number): number => (baseIf.size ? num(baseIf.get(String(bp))) : bp);
  const qbridge: FdbEntry[] = [], dot1d: FdbEntry[] = [];
  for (const [k, v] of qPort) {
    const p = k.split('.').map(Number); const mac = macFromParts(p); const bp = num(v);
    if (!mac || bp <= 0 || !learned(qStatus.get(k)) || isZeroMac(mac)) continue;
    const ifx = toIf(bp); if (ifx > 0) qbridge.push({ mac, vlan: p.length > 6 ? p[p.length - 7] : 0, ifIndex: ifx });
  }
  for (const [k, v] of dPort) {
    const p = k.split('.').map(Number); const mac = macFromParts(p); const bp = num(v);
    if (!mac || bp <= 0 || !learned(dStatus.get(k)) || isZeroMac(mac)) continue;
    const ifx = toIf(bp); if (ifx > 0) dot1d.push({ mac, vlan: 0, ifIndex: ifx });
  }
  return { qbridge, dot1d };
}

/**
 * Reads the MAC address table. Switches that implement Q-BRIDGE-MIB report every VLAN in one table. Cisco Catalyst switches do not:
 * their BRIDGE-MIB table holds one VLAN at a time, chosen by reading it as "community@vlan" (SNMPv1/v2c) or in the context "vlan-N" (SNMPv3),
 * so each VLAN that has access ports is read in turn.
 */
export async function readFdb(c: Walker, o: { cisco: boolean; vlans: number[]; forVlan?: (vlan: number) => Walker | null; budgetMs?: number; concurrency?: number }): Promise<FdbResult> {
  const first = await bridgeTable(c);
  if (first.qbridge.length) return { entries: first.qbridge, method: 'Q-BRIDGE-MIB', vlansTried: 0, vlansFailed: 0 };
  const perVlan = o.cisco && !!o.forVlan && o.vlans.length > 0;
  if (!perVlan) return { entries: first.dot1d, method: first.dot1d.length ? 'BRIDGE-MIB' : 'none', vlansTried: 0, vlansFailed: 0 };
  const out = new Map<string, FdbEntry>();
  let tried = 0, failed = 0;
  const deadline = Date.now() + (o.budgetMs ?? 90_000);
  const queue = [...new Set(o.vlans)].filter(v => v >= 1 && v <= 4094);
  let ok = 0;
  const worker = async () => {
    for (;;) {
      // when the first few VLANs all fail the device is not accepting VLAN-indexed access, so stop instead of waiting for a timeout per VLAN
      const v = queue.shift(); if (v === undefined || Date.now() > deadline || (!ok && failed >= 3)) return;
      const w = o.forVlan!(v); if (!w) { failed++; continue; }
      tried++;
      try {
        const t = await bridgeTable(w, true);
        ok++;
        for (const e of t.dot1d) out.set(`${e.mac}|${v}`, { ...e, vlan: v });
      } catch { failed++; } finally { (w as Partial<{ close(): void }>).close?.(); }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, o.concurrency ?? 3) }, worker));
  return { entries: [...out.values()], method: 'BRIDGE-MIB per VLAN', vlansTried: tried, vlansFailed: failed };
}

export type { SnmpClient };
