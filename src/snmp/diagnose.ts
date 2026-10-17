import { readMulticast } from './multicast.js';
import type { SnmpValue } from './client.js';
import { OID } from './oids.js';
import type { Walker } from './ports.js';
import type { SnmpClient } from './client.js';
import { ciscoSource } from './collect.js';
import { juniperSource, diffservSource, type QosSource } from './qos_vendors.js';
import { readResources } from './resources.js';
import { readIfExtra, readSensors, readPoe, readStp, readOspf, readBgp, readEigrp, readBfd } from './health.js';
import { readFib } from './fib.js';
import { readEntity, modelText } from './entity.js';
import { readDhcpBindings } from './dhcp_snooping.js';
import { readAuthSessions } from './authsessions.js';
import { readPae } from './dot1x.js';
import { readVrfs, contextOf } from './vrf.js';
import { readDai, readNbar, readProcesses, readStack } from './cisco_extra.js';
import { readWlanFor, wlanVendor } from './wlan_vendors.js';

/*
 * Diagnostics for one SNMP device: what it publishes (so a missing LLDP table is explained rather than silent) and a
 * read-only look at any OID. The checks only need `column()`, so tests feed them an in-memory table.
 */

export type CheckState = 'ok' | 'warn' | 'fail' | 'na';
export type CheckGroup = 'basics' | 'neighbours' | 'hosts' | 'hardware' | 'routing' | 'quality' | 'wifi';
export interface Check { id: string; title: string; group: CheckGroup; state: CheckState; count: number; detail: string; hint?: string }
export interface CheckFacts {
  role: string; cisco: boolean;
  /** sysObjectID and sysDescr, which tell what the device is and so which MIBs it can be expected to publish */
  objectId?: string; descr?: string;
  /** The device's interfaces, which the Wi-Fi reader needs to name radios */
  ifaces?: { index: number; name: string }[];
}

export type Vendor = 'cisco' | 'juniper' | 'huawei' | 'h3c' | 'hp' | 'fortinet' | 'paloalto' | 'arista' | 'aruba' | 'unifi' | 'ruckus' | 'mikrotik' | 'netsnmp' | 'other';
const VENDOR_PREFIX: [string, Vendor][] = [['1.3.6.1.4.1.9.', 'cisco'], ['1.3.6.1.4.1.2636.', 'juniper'], ['1.3.6.1.4.1.2011.', 'huawei'], ['1.3.6.1.4.1.25506.', 'h3c'], ['1.3.6.1.4.1.11.', 'hp'], ['1.3.6.1.4.1.12356.', 'fortinet'],
  ['1.3.6.1.4.1.25461.', 'paloalto'], ['1.3.6.1.4.1.30065.', 'arista'], ['1.3.6.1.4.1.14823.', 'aruba'], ['1.3.6.1.4.1.47196.', 'aruba'], ['1.3.6.1.4.1.41112.', 'unifi'], ['1.3.6.1.4.1.25053.', 'ruckus'], ['1.3.6.1.4.1.14988.', 'mikrotik'], ['1.3.6.1.4.1.8072.', 'netsnmp']];
/** Whose device this is, from its sysObjectID (a net-snmp agent on FreeBSD or Linux, such as OPNsense, pfSense or a server, is told by its description when the ID is generic). */
export function vendorOf(objectId = '', descr = '', cisco = false): Vendor {
  const id = objectId.replace(/^\./, '');
  for (const [p, v] of VENDOR_PREFIX) if (id.startsWith(p)) return v;
  if (cisco) return 'cisco';
  return /freebsd|linux|opnsense|pfsense|net-snmp/i.test(descr) ? 'netsnmp' : 'other';
}

/**
 * Where to see the full IGMP snooping membership on a switch, which SNMP does not give. Only commands known to be right are listed; any other
 * vendor gets none, and the page then points at the switch's IGMP snooping table in general.
 */
export function igmpHint(vendor: Vendor, descr = ''): { vendor: Vendor; platform: string; command: string | null } {
  switch (vendor) {
    case 'cisco': return { vendor, platform: /nx-os/i.test(descr) ? 'NX-OS' : /ios[ -]?xe|iosxe/i.test(descr) ? 'IOS XE' : 'IOS', command: 'show ip igmp snooping groups' };
    case 'juniper': return { vendor, platform: 'Junos', command: 'show igmp snooping membership' };
    case 'arista': return { vendor, platform: 'EOS', command: 'show ip igmp snooping groups' };
    case 'h3c': return { vendor, platform: 'Comware', command: 'display igmp-snooping group' };
    default: return { vendor, platform: '', command: null };
  }
}

/** Which MIBs this kind of device should be expected to publish. Everything else is not looked for, so a Cisco switch is never asked about Juniper's MIBs. */
export interface Expect {
  vendor: Vendor; ap: boolean; l2: boolean; l3: boolean;
  cdp: boolean; mac: boolean; arp: boolean; vlans: boolean;
  /** 'must' when the vendor's boxes always have sensors, 'maybe' when the standard MIB may be there */
  sensors: 'must' | 'maybe' | null; poe: boolean; stp: boolean; ospf: boolean; bgp: boolean; mcast: boolean;
  /** Cisco-only tables: forwarding table, EIGRP and BFD (routing devices and L3 switches), and for switches DHCP snooping, stack, ARP inspection */
  cRouting: boolean; cSwitch: boolean; cAny: boolean;
  qos: 'cisco-cbqos' | 'juniper-cos' | 'diffserv' | null; wifi: boolean;
}
export function expectFor(f: CheckFacts): Expect {
  const vendor = vendorOf(f.objectId, f.descr, f.cisco);
  const wl = wlanVendor(f.objectId ?? '', f.descr ?? '') !== null;
  const ap = f.role === 'ap' || (wl && f.role !== 'switch' && f.role !== 'router' && f.role !== 'firewall');
  const l2 = f.role === 'switch', l3 = f.role === 'router' || f.role === 'firewall';
  const strong = ['cisco', 'juniper', 'huawei', 'h3c'].includes(vendor);
  const capable = strong || ['hp', 'arista'].includes(vendor);
  return {
    vendor, ap, l2, l3, cdp: vendor === 'cisco', mac: l2, arp: l3 || l2, vlans: l2,
    sensors: ap || vendor === 'netsnmp' ? null : strong && (l2 || l3) ? 'must' : capable || l2 || f.role === 'router' ? 'maybe' : null,
    poe: l2, stp: l2, ospf: l3 || (l2 && (strong || vendor === 'arista')), bgp: l3 || (l2 && (strong || vendor === 'arista')),
    mcast: l3 || (l2 && (strong || vendor === 'arista')),
    cRouting: vendor === 'cisco' && (l3 || l2), cSwitch: vendor === 'cisco' && l2, cAny: vendor === 'cisco' && (l2 || l3),
    qos: ap ? null : vendor === 'cisco' ? 'cisco-cbqos' : vendor === 'juniper' ? 'juniper-cos' : 'diffserv', wifi: ap || wl
  };
}

const LLDP_HINT = 'Switches publish LLDP over SNMP themselves. Firewalls and servers (OPNsense, pfSense, Linux) only do it through the lldpd AgentX subagent: install lldpd, turn on AgentX in the SNMP service (the master agent needs "master agentx"), and start lldpd with -x. Then check that the community or SNMPv3 user may read .1.0.8802, which lies outside .1.3.6.1 and is often cut off by a restricted view.';

/** hrSWRunName and hrSWRunPath (HOST-RESOURCES-MIB). On FreeBSD the "path" of lldpd is its process title, which includes "N neighbors". */
const HR_SWRUN_NAME = '1.3.6.1.2.1.25.4.2.1.2', HR_SWRUN_PATH = '1.3.6.1.2.1.25.4.2.1.4';
const LLDPD_RUNNING_HINT = 'lldpd learns the neighbours but keeps them to itself; it reaches SNMP only through the AgentX socket of the SNMP agent. Both ends need switching on: start lldpd with -x (on OPNsense look for an SNMP / AgentX option in the LLDPd plugin settings), and make the agent a master agent ("master agentx" in snmpd.conf; the OPNsense Net-SNMP plugin writes it when its AgentX option is on). Then restart snmpd first and lldpd after it, and run this check again. If the rest of the device reads fine with this credential, the credential is not the problem.';

type Col = { map: Map<string, SnmpValue>; error: string | null };
async function col(c: Walker, oid: string): Promise<Col> {
  try { return { map: await c.column(oid, 20), error: null }; } catch (e) { return { map: new Map(), error: (e as Error).message }; }
}
const plural = (n: number, one: string, many = one + 's') => `${n} ${n === 1 ? one : many}`;
const ports = (m: Map<string, SnmpValue>, at: number) => new Set([...m.keys()].map(k => k.split('.')[at])).size;

const NONE: Col = { map: new Map(), error: null };
/** What each vendor's own MIB is called and where it lives, for the hint when a device that should publish it does not. */
const RESOURCE_HINT: Record<Vendor, string> = {
  cisco: 'Cisco publishes CPU in CISCO-PROCESS-MIB (.1.3.6.1.4.1.9.9.109) and memory in CISCO-MEMORY-POOL-MIB (.1.3.6.1.4.1.9.9.48). Check that the SNMP view of this credential includes them.',
  juniper: 'Juniper publishes CPU and memory in the jnxOperatingTable of JUNIPER-MIB (.1.3.6.1.4.1.2636.3.1.13). Check the SNMP view of this credential.',
  huawei: 'Huawei publishes CPU and memory in HUAWEI-ENTITY-EXTENT-MIB (.1.3.6.1.4.1.2011.5.25.31.1.1.1). Check the SNMP view of this credential.',
  h3c: 'H3C and HPE Comware publish CPU and memory in HH3C-ENTITY-EXT-MIB (.1.3.6.1.4.1.25506.2.6.1.1.1). Check the SNMP view of this credential.',
  hp: 'HP ProCurve publishes CPU in STATISTICS-MIB (.1.3.6.1.4.1.11.2.14.11.5.1.9) and memory in HP-ICF-CHASSIS. Check the SNMP view of this credential.',
  fortinet: 'FortiGate publishes CPU, memory and sessions in FORTINET-FORTIGATE-MIB (.1.3.6.1.4.1.12356.101.4.1). Check the SNMP view of this credential.',
  paloalto: 'Palo Alto publishes CPU, memory and sessions in PAN-COMMON-MIB (.1.3.6.1.4.1.25461.2.1.2). Check the SNMP view of this credential.',
  netsnmp: 'A net-snmp agent (OPNsense, pfSense, Linux) publishes these in UCD-SNMP-MIB (.1.3.6.1.4.1.2021) and HOST-RESOURCES-MIB (.1.3.6.1.2.1.25). Make sure the community or user may read the whole tree, not just the system and interface groups.',
  arista: 'Arista publishes CPU and memory in HOST-RESOURCES-MIB (.1.3.6.1.2.1.25) and UCD-SNMP-MIB. Check the SNMP view of this credential.',
  aruba: 'Access points publish them in their own MIB; check the SNMP view of this credential.', unifi: 'UniFi access points publish them in UCD-SNMP-MIB and HOST-RESOURCES-MIB; check the SNMP view of this credential.',
  ruckus: 'Check the SNMP view of this credential.', mikrotik: 'MikroTik publishes them in HOST-RESOURCES-MIB (.1.3.6.1.2.1.25). Check the SNMP view of this credential.', other: 'Devices publish these in HOST-RESOURCES-MIB (.1.3.6.1.2.1.25) or UCD-SNMP-MIB. Check the SNMP view of this credential.'
};
const SENSOR_HINT: Partial<Record<Vendor, string>> = {
  cisco: 'Cisco publishes sensors in ENTITY-SENSOR-MIB (.1.3.6.1.2.1.99), CISCO-ENTITY-SENSOR-MIB (.1.3.6.1.4.1.9.9.91) and CISCO-ENVMON-MIB (.1.3.6.1.4.1.9.9.13).',
  juniper: 'Juniper publishes temperatures and fan and power state in the jnxOperatingTable (.1.3.6.1.4.1.2636.3.1.13).',
  huawei: 'Huawei publishes temperature in hwEntityTemperature (.1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11) and sensors in ENTITY-SENSOR-MIB.',
  h3c: 'H3C and HPE Comware publish temperature in hh3cEntityExtTemperature (.1.3.6.1.4.1.25506.2.6.1.1.1.1.12) and sensors in ENTITY-SENSOR-MIB.'
};
const WIFI_HINT: Record<string, string> = {
  aruba: 'Aruba Instant access points publish radios and clients in AI-AP-MIB (.1.3.6.1.4.1.14823.2.3.3). Check the SNMP view of this credential.',
  unifi: 'UniFi access points publish radios and clients in UBNT-UniFi-MIB (.1.3.6.1.4.1.41112.1.6). Check the SNMP view of this credential.',
  ruckus: 'Ruckus publishes radios and clients in RUCKUS-WLAN-MIB (.1.3.6.1.4.1.25053.1). Check the SNMP view of this credential.',
  cisco: 'Cisco wireless controllers publish access points and clients in CISCO-LWAPP-AP-MIB (.1.3.6.1.4.1.9.9.513) and CISCO-LWAPP-DOT11-CLIENT-MIB (.1.3.6.1.4.1.9.9.599).'
};
const GROUP: Record<string, CheckGroup> = { interfaces: 'basics', counters: 'basics', resources: 'basics', lldp: 'neighbours', cdp: 'neighbours', mac: 'hosts', arp: 'hosts', vlans: 'hosts',
  sensors: 'hardware', optics: 'hardware', poe: 'hardware', stp: 'routing', ospf: 'routing', bgp: 'routing', mcast: 'routing', fib: 'routing', eigrp: 'routing', bfd: 'routing', dhcp: 'hosts', auth: 'hosts', dot1x: 'hosts', vrf: 'routing', dai: 'hosts', stack: 'hardware', entity: 'hardware', procs: 'hardware', nbar: 'quality', quality: 'quality', qos: 'quality', wifi: 'wifi' };
const GROUP_ORDER: CheckGroup[] = ['basics', 'neighbours', 'hosts', 'hardware', 'routing', 'quality', 'wifi'];

async function attempt<T>(fn: () => Promise<T>, empty: T): Promise<{ v: T; error: string | null }> {
  try { return { v: await fn(), error: null }; } catch (e) { return { v: empty, error: (e as Error).message }; }
}

/**
 * Looks at what one device publishes. Only the MIBs a device of this kind should have are asked for (see expectFor): a Cisco switch is not asked
 * about Juniper's MIBs, a switch is not asked about Wi-Fi, and an access point is not asked about spanning tree. Checks that are optional for the kind of
 * device (PoE, spanning tree, routing neighbours) are listed as "not applicable" when empty, and checks that do not apply are left out.
 */
export async function runChecks(c: Walker & Partial<Pick<SnmpClient, 'get'>>, f: CheckFacts): Promise<Check[]> {
  const ex = expectFor(f);
  const ask = (on: boolean, oid: string) => (on ? col(c, oid) : Promise.resolve(NONE));
  const [ifName, ifDescr, hc, in32, locPort, lldpRem, cdp, fdbQ, fdbD, arpP, arpM, vq, vtp, pvid] = await Promise.all([
    col(c, OID.ifName), col(c, OID.ifDescr), col(c, OID.ifHCInOctets), col(c, OID.ifInOctets32),
    col(c, OID.lldpLocPortId), col(c, OID.lldpRemChassisId), ask(ex.cdp, OID.cdpCacheDeviceId),
    ask(ex.mac, OID.dot1qTpFdbPort), ask(ex.mac, OID.dot1dTpFdbPort), ask(ex.arp, OID.ipNetToPhysicalPhysAddress), ask(ex.arp, OID.ipNetToMediaPhysAddress),
    ask(ex.vlans, OID.dot1qVlanStaticName), ask(ex.vlans, OID.vtpVlanName), ask(ex.vlans, OID.dot1qPvid)
  ]);
  const out: (Omit<Check, 'group'> & { group?: CheckGroup })[] = [];
  const err = (...cs: Col[]) => cs.map(x => x.error).find(Boolean) ?? null;

  const nIf = Math.max(ifName.map.size, ifDescr.map.size);
  out.push(nIf ? { id: 'interfaces', title: 'Interfaces', state: 'ok', count: nIf, detail: `${plural(nIf, 'interface')} listed.` }
    : { id: 'interfaces', title: 'Interfaces', state: 'fail', count: 0, detail: err(ifName, ifDescr) ?? 'The interface table is empty or not readable with this credential.', hint: 'Nothing can be graphed without it. Check that the credential may read IF-MIB (.1.3.6.1.2.1.2 and .1.3.6.1.2.1.31).' });

  out.push(hc.map.size ? { id: 'counters', title: 'Traffic counters', state: 'ok', count: hc.map.size, detail: '64-bit counters are available, so fast links will not wrap.' }
    : in32.map.size ? { id: 'counters', title: 'Traffic counters', state: 'warn', count: in32.map.size, detail: 'Only 32-bit counters are published. They wrap in about 34 seconds at 1 Gbps, so utilisation on fast links can read low.', hint: 'The device needs to publish ifXTable (IF-MIB ifHCInOctets).' }
      : { id: 'counters', title: 'Traffic counters', state: 'fail', count: 0, detail: err(hc, in32) ?? 'No interface traffic counters were returned.' });

  const nLoc = locPort.map.size, nRem = lldpRem.map.size;
  // With no LLDP table at all, see whether lldpd is running on the device: that turns "not published" into the real cause.
  let lldpd: { running: boolean; neighbours: number | null; procsRead: boolean } = { running: false, neighbours: null, procsRead: false };
  if (!nLoc && !nRem) {
    const [names, paths] = await Promise.all([col(c, HR_SWRUN_NAME), col(c, HR_SWRUN_PATH)]);
    lldpd.procsRead = names.map.size > 0;
    for (const [k, v] of names.map) {
      if (!/(^|\/)lldpd$/.test(String(v).trim())) continue;
      lldpd.running = true;
      const m = /(\d+) neighbou?rs?/i.exec(String(paths.map.get(k) ?? ''));
      if (m) lldpd.neighbours = Math.max(lldpd.neighbours ?? 0, Number(m[1]));
    }
  }
  out.push(nRem ? { id: 'lldp', title: 'LLDP neighbours', state: 'ok', count: nRem, detail: `${plural(nRem, 'neighbour')} on ${plural(ports(lldpRem.map, 1), 'port')}.` }
    : nLoc ? { id: 'lldp', title: 'LLDP neighbours', state: 'warn', count: 0, detail: `The device publishes LLDP (${plural(nLoc, 'local port')}) but has no neighbours yet.`, hint: 'Check that the other end sends LLDP and that LLDP is enabled on this port. On a firewall or server, lldpctl shows what lldpd has heard.' }
      : lldpd.running ? { id: 'lldp', title: 'LLDP neighbours', state: 'fail', count: 0, detail: `lldpd is running on this device${lldpd.neighbours !== null ? ` and sees ${plural(lldpd.neighbours, 'neighbour')}` : ''}, but nothing is published for the LLDP-MIB (.1.0.8802.1.1.2). It is not connected to the SNMP agent.`, hint: LLDPD_RUNNING_HINT }
      : { id: 'lldp', title: 'LLDP neighbours', state: 'fail', count: 0, detail: err(locPort, lldpRem) ?? 'Nothing came back for the LLDP-MIB (.1.0.8802.1.1.2). Either the device does not publish it over SNMP, or this credential may not read it.' + (lldpd.procsRead && f.role !== 'switch' ? ' The device\'s process list was readable and lldpd is not running on it, so there is nothing to publish: start lldpd (with -x) first.' : ''), hint: LLDP_HINT });

  out.push(cdp.map.size ? { id: 'cdp', title: 'CDP neighbours', state: 'ok', count: cdp.map.size, detail: `${plural(cdp.map.size, 'neighbour')} on ${plural(ports(cdp.map, 0), 'port')}.` }
    : { id: 'cdp', title: 'CDP neighbours', state: 'na', count: 0, detail: 'No CDP table. Only Cisco devices publish it, so this is normal elsewhere.' });

  const nFdb = Math.max(fdbQ.map.size, fdbD.map.size);
  const isSwitch = f.role === 'switch';
  out.push(nFdb ? { id: 'mac', title: 'MAC address table', state: 'ok', count: nFdb, detail: `${plural(nFdb, 'learned address')}.` }
    : f.cisco ? { id: 'mac', title: 'MAC address table', state: 'na', count: 0, detail: 'Empty with the plain credential. Cisco switches keep one table per VLAN, and FlowScope reads them per VLAN when it tracks hosts.' }
      : { id: 'mac', title: 'MAC address table', state: isSwitch ? 'fail' : 'na', count: 0, detail: err(fdbQ, fdbD) ?? (isSwitch ? 'No learned MAC addresses were returned, so hosts cannot be placed on ports.' : 'Not published. Routers and firewalls do not keep one.'), hint: isSwitch ? 'The device needs to publish BRIDGE-MIB or Q-BRIDGE-MIB.' : undefined });

  const nArp = Math.max(arpP.map.size, arpM.map.size);
  out.push(nArp ? { id: 'arp', title: 'ARP / neighbour cache', state: 'ok', count: nArp, detail: `${plural(nArp, 'entry', 'entries')}.` }
    : { id: 'arp', title: 'ARP / neighbour cache', state: ex.l3 ? 'warn' : 'na', count: 0, detail: err(arpP, arpM) ?? 'No ARP entries were returned, so MAC addresses cannot be turned into IP addresses from this device.' });

  const nVlan = Math.max(vq.map.size, vtp.map.size, pvid.map.size);
  out.push(nVlan ? { id: 'vlans', title: 'VLANs', state: 'ok', count: nVlan, detail: `${plural(nVlan, 'VLAN entry', 'VLAN entries')}.` }
    : { id: 'vlans', title: 'VLANs', state: 'na', count: 0, detail: 'No VLAN information published. Normal for routers and firewalls without VLAN tables.' });

  // Checks that do not apply to this kind of device are left out; an optional one that is empty reads "not applicable"
  const drop = new Set<string>();
  if (!ex.cdp) drop.add('cdp');
  if (!ex.mac) drop.add('mac');
  if (!ex.arp || (!ex.l3 && !nArp)) drop.add('arp');
  if (!ex.vlans) drop.add('vlans');

  // Everything below reads with the same readers the poller uses, so "published" here means FlowScope will really get the data
  const cl = c as unknown as SnmpClient;
  const oid = f.objectId ?? '', descr = f.descr ?? '';
  const none = <T,>(v: T) => Promise.resolve({ v, error: null as string | null });
  const [res, sens, poe, stp, ospf, bgp, mcast, extra, wifi] = await Promise.all([
    attempt(() => readResources(cl, oid), null),
    ex.sensors ? attempt(() => readSensors(cl, oid), []) : none([] as Awaited<ReturnType<typeof readSensors>>),
    ex.poe ? attempt(() => readPoe(cl), []) : none([] as Awaited<ReturnType<typeof readPoe>>),
    ex.stp ? attempt(() => readStp(cl), null) : none(null as Awaited<ReturnType<typeof readStp>>),
    ex.ospf ? attempt(() => readOspf(cl), []) : none([] as Awaited<ReturnType<typeof readOspf>>),
    ex.bgp ? attempt(() => readBgp(cl), { peers: [], localAs: null }) : none({ peers: [], localAs: null as number | null }),
    ex.mcast ? attempt(() => readMulticast(cl, Date.now(), ex.vendor === 'cisco'), null) : none(null as Awaited<ReturnType<typeof readMulticast>>),
    attempt(() => readIfExtra(cl, Date.now(), ex.vendor === 'cisco'), new Map<number, never>() as unknown as Awaited<ReturnType<typeof readIfExtra>>),
    ex.wifi ? attempt(() => readWlanFor(c, f.ifaces ?? [], oid, descr), null) : none(null as Awaited<ReturnType<typeof readWlanFor>>)
  ]);
  const hdOf = (r: NonNullable<typeof res.v>) => [
    r.uptimeSec !== null ? `uptime ${Math.floor(r.uptimeSec / 86400)} d ${Math.floor(r.uptimeSec % 86400 / 3600)} h` : null, r.cpuPct !== null ? `CPU ${Math.round(r.cpuPct)}%` : null, r.memPct !== null ? `memory ${Math.round(r.memPct)}%` : null,
    r.disks.length ? plural(r.disks.length, 'disk') : null, r.sessions !== null && r.sessions !== undefined ? `${r.sessions.toLocaleString('en-US')} sessions` : null, r.tempC !== null && r.tempC !== undefined ? `${Math.round(r.tempC)} °C` : null].filter(Boolean) as string[];
  const rv = res.v;
  const rCount = rv ? [rv.uptimeSec, rv.cpuPct, rv.memPct].filter(x => x !== null).length + rv.disks.length : 0;
  out.push(rv && rv.cpuPct !== null && rv.memPct !== null ? { id: 'resources', title: 'Uptime, CPU and memory', group: 'basics', state: 'ok', count: rCount, detail: `${hdOf(rv).join(', ')} (${rv.source || 'standard MIBs'}).` }
    : rv && rCount ? { id: 'resources', title: 'Uptime, CPU and memory', group: 'basics', state: 'warn', count: rCount, detail: `Only part is published: ${hdOf(rv).join(', ')} (${rv.source || 'standard MIBs'}). ${rv.cpuPct === null ? 'CPU is missing.' : 'Memory is missing.'}`, hint: RESOURCE_HINT[ex.vendor] }
      : { id: 'resources', title: 'Uptime, CPU and memory', group: 'basics', state: 'fail', count: 0, detail: res.error ?? 'No uptime, CPU or memory figures were returned.', hint: RESOURCE_HINT[ex.vendor] });

  // Sensors and optics (ENTITY-SENSOR-MIB and the vendors' own)
  if (ex.sensors) {
    const sn = sens.v.filter(x => x.kind !== 'optic'), op = sens.v.filter(x => x.kind === 'optic');
    const kinds = new Map<string, number>(); for (const x of sn) kinds.set(x.kind, (kinds.get(x.kind) ?? 0) + 1);
    out.push(sn.length ? { id: 'sensors', title: 'Temperature, fans and power', group: 'hardware', state: 'ok', count: sn.length, detail: `${plural(sn.length, 'sensor')}: ${[...kinds].map(([k, n]) => `${n} ${k}`).join(', ')}.` }
      : { id: 'sensors', title: 'Temperature, fans and power', group: 'hardware', state: ex.sensors === 'must' ? 'warn' : 'na', count: 0, detail: sens.error ?? (ex.sensors === 'must' ? 'No sensors were returned.' : 'No sensor tables. Not every device publishes them.'), hint: SENSOR_HINT[ex.vendor] });
    if (op.length) { const n = new Set(op.map(x => x.name.replace(/\s*(transmit|receive|tx|rx|temperature|bias|power|sensor|lane \d+).*$/i, '').trim() || x.name)).size; out.push({ id: 'optics', title: 'Optic light levels', group: 'hardware', state: 'ok', count: n, detail: `${plural(n, 'optic')} with transmit and receive light levels and module temperature.` }); }
  }
  if (ex.poe) out.push(poe.v.length ? { id: 'poe', title: 'Power over Ethernet', group: 'hardware', state: 'ok', count: poe.v.length, detail: `${plural(poe.v.length, 'power source')}${poe.v[0].usedW !== null && poe.v[0].budgetW ? `: ${poe.v[0].usedW} of ${poe.v[0].budgetW} W in use` : ''}.` }
    : { id: 'poe', title: 'Power over Ethernet', group: 'hardware', state: 'na', count: 0, detail: poe.error ?? 'No PoE information (POWER-ETHERNET-MIB). Normal for a switch without PoE ports.' });

  // Spanning tree and routing neighbours
  if (ex.stp) out.push(stp.v ? { id: 'stp', title: 'Spanning tree', group: 'routing', state: 'ok', count: stp.v.ports, detail: `${stp.v.isRoot ? 'This switch is the root bridge' : `Root bridge ${stp.v.rootId}`}, ${plural(stp.v.ports, 'bridge port')}${stp.v.blockingPorts ? `, ${stp.v.blockingPorts} blocking` : ''}.` }
    : { id: 'stp', title: 'Spanning tree', group: 'routing', state: 'na', count: 0, detail: stp.error ?? 'No BRIDGE-MIB spanning tree information. It is normal when spanning tree is off or the switch keeps it per VLAN.' });
  if (ex.ospf) out.push(ospf.v.length ? { id: 'ospf', title: 'OSPF neighbours', group: 'routing', state: ospf.v.some(n => n.level === 'bad') ? 'warn' : 'ok', count: ospf.v.length, detail: `${plural(ospf.v.length, 'neighbour')}, ${ospf.v.filter(n => n.level === 'ok').length} fully adjacent.` }
    : { id: 'ospf', title: 'OSPF neighbours', group: 'routing', state: 'na', count: 0, detail: ospf.error ?? 'No OSPF neighbours (OSPF-MIB). Normal when this device does not run OSPF.' });
  if (ex.bgp) out.push(bgp.v.peers.length ? { id: 'bgp', title: 'BGP peers', group: 'routing', state: bgp.v.peers.some(p => p.level === 'bad') ? 'warn' : 'ok', count: bgp.v.peers.length, detail: `${plural(bgp.v.peers.length, 'peer')}, ${bgp.v.peers.filter(p => p.level === 'ok').length} established.` }
    : { id: 'bgp', title: 'BGP peers', group: 'routing', state: 'na', count: 0, detail: bgp.error ?? 'No BGP peers (BGP4-MIB). Normal when this device does not run BGP.' });
  if (ex.mcast) {
    const m = mcast.v;
    const groups = m ? new Set(m.routes.map(r => r.group)).size : 0;
    const missing = m ? [m.routeSource === 'pim' ? 'IPMROUTE-STD-MIB (as on NX-OS), so routes come from PIM-MIB with no interfaces or RPF' : null, m.source === 'standard' ? 'the Cisco rate and flags table (CISCO-IPMROUTE-MIB), so no rates' : null, m.pimInterfaces.length ? null : 'PIM-MIB, so no rendezvous points or neighbours', m.receivers.length ? null : 'any IGMP cache entry, so no joined hosts', (m.igmpInterfaces?.length ?? 0) || !m.receivers.length ? null : 'the IGMP interface table (IGMP-STD-MIB), so no queriers', m.routes.some(r => r.inIfIndex || r.upstream || r.rpf) ? null : 'any RPF interface or neighbour, so no RPF information'].filter(Boolean) as string[] : [];
    out.push(m ? { id: 'mcast', title: 'Multicast routing', group: 'routing', state: missing.length ? 'warn' : 'ok', count: m.routes.length,
      detail: `${plural(m.routes.length, 'route')} for ${plural(groups, 'group')}, ${plural(m.receivers.length, 'IGMP join')}${m.pimInterfaces.length ? `, ${plural(m.pimInterfaces.length, 'PIM interface')}` : ''}${m.igmpInterfaces?.length ? `, ${plural(m.igmpInterfaces.filter(i => i.querier).length, 'IGMP querier')} on ${plural(m.igmpInterfaces.length, 'interface')}` : ''}${(m.rpGroups?.length ?? 0) + (m.rpSet?.length ?? 0) ? `, ${plural(new Set([...(m.rpGroups ?? []).map(r => r.rp), ...(m.rpSet ?? []).map(r => r.rp)]).size, 'rendezvous point')}` : ''}${m.routes.some(r => r.rpf) ? `, RPF for ${plural(m.routes.filter(r => r.rpf).length, 'route')}` : ''}.${missing.length ? ` Missing: ${missing.join('; ')}.` : ''}`,
      hint: missing.length ? 'Multicast tables are IPMROUTE-STD-MIB (.1.3.6.1.2.1.83), IGMP-STD-MIB (.1.3.6.1.2.1.85, queriers in igmpInterfaceTable), PIM-MIB (.1.3.6.1.3.61) and Cisco CISCO-IPMROUTE-MIB (.1.3.6.1.4.1.9.10.2). Check the SNMP view of this credential includes them.' : undefined }
      : { id: 'mcast', title: 'Multicast routing', group: 'routing', state: 'na', count: 0, detail: mcast.error ?? 'No multicast routes (IPMROUTE-STD-MIB). Normal when this device does not route multicast.',
        hint: mcast.error ? 'Multicast tables are IPMROUTE-STD-MIB (.1.3.6.1.2.1.83). Check the SNMP view of this credential includes them.' : undefined });
  }

  // Cisco-only tables, read with the readers the poller uses. Each is "not applicable" when empty: a table appears only when the feature is in use.
  if (ex.cAny) {
    const [fib, eigrp, bfd, dhcp, auth, vrfs, stack, dai, procs, nbar] = await Promise.all([
      ex.cRouting ? attempt(() => readFib(cl), null) : none(null as Awaited<ReturnType<typeof readFib>>),
      ex.cRouting ? attempt(() => readEigrp(cl), []) : none([] as Awaited<ReturnType<typeof readEigrp>>),
      ex.cRouting ? attempt(() => readBfd(cl), []) : none([] as Awaited<ReturnType<typeof readBfd>>),
      ex.cSwitch ? attempt(() => readDhcpBindings(cl), []) : none([] as Awaited<ReturnType<typeof readDhcpBindings>>),
      ex.cSwitch ? attempt(() => readAuthSessions(cl), []) : none([] as Awaited<ReturnType<typeof readAuthSessions>>),
      ex.cRouting || ex.cSwitch ? attempt(() => readVrfs(cl), null) : none(null as Awaited<ReturnType<typeof readVrfs>>),
      ex.cSwitch ? attempt(() => readStack(cl), null) : none(null as Awaited<ReturnType<typeof readStack>>),
      ex.cSwitch ? attempt(() => readDai(cl, null), null) : none(null as Awaited<ReturnType<typeof readDai>>),
      attempt(() => readProcesses(cl), null),
      attempt(() => readNbar(cl), null)
    ]);
    const view = 'Check the SNMP view of this credential includes it.';
    const row = (id: string, title: string, count: number, okText: string, naText: string, error: string | null, hint: string): void => {
      out.push(count ? { id, title, group: GROUP[id], state: 'ok', count, detail: okText } : { id, title, group: GROUP[id], state: 'na', count: 0, detail: error ?? naText, hint: error ? `${hint} ${view}` : undefined });
    };
    if (ex.cRouting) {
      row('fib', 'Forwarding table (CEF)', fib.v?.entries.length ?? 0, `${plural(fib.v?.entries.length ?? 0, 'prefix', 'prefixes')} with their outgoing interfaces${fib.v?.truncated ? ' (cut off at the most that FlowScope keeps)' : ''}. ${(() => { const n = fib.v?.entries.filter(e => e.paths.filter(p => p.kind !== 'receive').length > 1).length ?? 0; return n ? ` ${plural(n, 'prefix', 'prefixes')} have equal-cost paths, which the multicast page uses to read RPF drops.` : ''; })()} Used to check that a flow left the interface the routing table says it should.`,
        'No forwarding table (CISCO-CEF-MIB). It needs CEF, which is on by default on routers and Layer 3 switches.', fib.error, 'CISCO-CEF-MIB is .1.3.6.1.4.1.9.9.492.');
      row('eigrp', 'EIGRP neighbours', eigrp.v.length, `${plural(eigrp.v.length, 'neighbour')}, ${eigrp.v.filter(p => p.level === 'ok').length} without retransmissions.`, 'No EIGRP neighbours (CISCO-EIGRP-MIB). Normal when this device does not run EIGRP.', eigrp.error, 'CISCO-EIGRP-MIB is .1.3.6.1.4.1.9.9.449.');
      row('bfd', 'BFD sessions', bfd.v.length, `${plural(bfd.v.length, 'session')}, ${bfd.v.filter(b => b.level === 'ok').length} up.`, 'No BFD sessions (CISCO-IETF-BFD-MIB). Normal when BFD is not configured.', bfd.error, 'CISCO-IETF-BFD-MIB is .1.3.6.1.4.1.9.10.137.');
    }
    // VRFs, and whether each can be read in its own SNMP context (multicast, PIM and IGMP are scoped per context)
    if (ex.cRouting || ex.cSwitch) {
      const names = vrfs.v ?? [];
      const ctx: { name: string; routes: number; ok: boolean }[] = [];
      if (ex.mcast) for (const v of names.slice(0, 12)) {
        const cc = cl.forContext(contextOf(v.name));
        try { const m = await readMulticast(cc, Date.now(), true); ctx.push({ name: v.name, routes: m?.routes.length ?? 0, ok: !!m && m.routes.length > 0 }); } catch { ctx.push({ name: v.name, routes: 0, ok: false }); } finally { cc.close(); }
      }
      const bad = ctx.filter(x => !x.ok).map(x => x.name);
      out.push(names.length ? { id: 'vrf', title: 'VRFs and SNMP contexts', group: 'routing', state: ctx.length && bad.length ? 'warn' : 'ok', count: names.length,
        detail: `${plural(names.length, 'VRF')}: ${names.map(v => v.name).join(', ')}.${ctx.length ? ` Multicast is read in each VRF's own context (${contextOf('<NAME>')}): ${plural(ctx.length - bad.length, 'VRF')} answered with routes${bad.length ? `, ${bad.join(', ')} gave nothing (no multicast there, or the context is not set up)` : ''}.` : ''}`,
        hint: bad.length ? 'Needs "snmp-server context vrf-<NAME>" and "snmp context vrf-<NAME>" under the VRF address family, and for SNMPv3 a group that may read the context (context vrf- match prefix). VRFs are listed from MPLS-L3VPN-STD-MIB (.1.3.6.1.2.1.10.166.11).' : undefined }
        : { id: 'vrf', title: 'VRFs and SNMP contexts', group: 'routing', state: 'na', count: 0, detail: vrfs.error ?? 'No VRFs (MPLS-L3VPN-STD-MIB). Normal when the device has only the default routing table.', hint: vrfs.error ? 'MPLS-L3VPN-STD-MIB is .1.3.6.1.2.1.10.166.11. Check the SNMP view of this credential includes it.' : undefined });
    }
    if (ex.cSwitch) {
      row('dhcp', 'DHCP snooping bindings', dhcp.v.length, `${plural(dhcp.v.length, 'binding')}: each gives a host's MAC address, IP address, VLAN and port without needing an ARP entry.`, 'No DHCP snooping bindings (CISCO-DHCP-SNOOPING-MIB). Normal when DHCP snooping is off.', dhcp.error, 'CISCO-DHCP-SNOOPING-MIB is .1.3.6.1.4.1.9.9.380.');
      row('auth', 'Authentication sessions (802.1X / MAB)', auth.v.length, `${plural(auth.v.length, 'session')}: ${auth.v.filter(a => a.domain !== 'unknown').length} authenticated (${auth.v.filter(a => a.vlan).length} with a VLAN assigned by the authentication server) and ${auth.v.filter(a => a.domain === 'unknown').length} clients seen that did not authenticate; ${auth.v.filter(a => a.ip).length} have an IP address. Ports that authenticate their clients are shown in the VLAN the clients are really in.`, 'No authentication sessions (CISCO-AUTH-FRAMEWORK-MIB). Normal when no port uses 802.1X, MAB or web authentication.', auth.error, 'CISCO-AUTH-FRAMEWORK-MIB is .1.3.6.1.4.1.9.9.656.');
      row('stack', 'Stack members and ports', stack.v?.members.length ?? 0, `${plural(stack.v?.members.length ?? 0, 'member')}, ${stack.v?.ports.filter(p => p.level === 'ok').length ?? 0} of ${stack.v?.ports.length ?? 0} stack ports up${stack.v?.problems.length ? '. ' + stack.v.problems[0] : ''}.`, 'No stack information (CISCO-STACKWISE-MIB). Normal for a switch that is not stacked.', stack.error, 'CISCO-STACKWISE-MIB is .1.3.6.1.4.1.9.9.500.');
      row('dai', 'ARP inspection drops', dai.v ? 1 : 0, dai.v && dai.v.vlans.length ? `ARP packets were dropped on ${plural(dai.v.vlans.length, 'VLAN')}.` : 'The statistics are published and no VLAN has dropped an ARP packet.', 'No ARP inspection statistics (CISCO-DYNAMIC-ARP-INSPECTION-MIB). Normal when it is not configured.', dai.error, 'CISCO-DYNAMIC-ARP-INSPECTION-MIB is .1.3.6.1.4.1.9.9.374.');
    }
    {
      const ent = await attempt(() => readEntity(cl, Date.now()), null);
      const parts = (ent.v?.chassis.length ?? 0) + (ent.v?.modules.length ?? 0);
      out.push(parts && modelText(ent.v) ? { id: 'entity', title: 'Hardware model', group: 'hardware', state: 'ok', count: parts, detail: `${modelText(ent.v)} (${plural(parts, 'chassis or module row')}).` }
        : { id: 'entity', title: 'Hardware model', group: 'hardware', state: 'na', count: 0, detail: ent.error ?? 'No model name (ENTITY-MIB entPhysicalModelName). FlowScope shows the model next to the device name when this is published.', hint: ent.error ? 'ENTITY-MIB is .1.3.6.1.2.1.47. Check the SNMP view of this credential includes it.' : undefined });
    }
    row('procs', 'Process CPU', procs.v?.top.length ?? 0, `The busiest of the device's processes${procs.v?.snmpOne !== null && procs.v?.snmpOne !== undefined ? `; the SNMP engine uses ${procs.v.snmpOne}% over a minute` : ''}.`, 'No per-process CPU (CISCO-PROCESS-MIB).', procs.error, 'CISCO-PROCESS-MIB is .1.3.6.1.4.1.9.9.109.');
    row('nbar', 'Application statistics (NBAR2)', nbar.v ? Object.keys(nbar.v.interfaces).length : 0, `Recognised applications on ${plural(Object.keys(nbar.v?.interfaces ?? {}).length, 'interface')}.`, 'No NBAR2 statistics (CISCO-NBAR-PROTOCOL-DISCOVERY-MIB). Normal when protocol discovery is not switched on.', nbar.error, 'CISCO-NBAR-PROTOCOL-DISCOVERY-MIB is .1.3.6.1.4.1.9.9.244.');
  }

  // Standard tables that any vendor's switch or router may publish, and that the Cisco-only block above does not cover
  if (ex.vendor !== 'cisco' && (ex.l2 || ex.l3) && !ex.ap) {
    const [pae, vrfs] = await Promise.all([ex.l2 ? attempt(() => readPae(cl), []) : none([] as Awaited<ReturnType<typeof readPae>>), attempt(() => readVrfs(cl), null)]);
    if (ex.l2) {
      const auto = pae.v.filter(p => p.control === 'auto');
      out.push(auto.length ? { id: 'dot1x', title: '802.1X ports', group: 'hosts', state: 'ok', count: auto.length, detail: `${plural(auto.length, 'port')} authenticate their clients (IEEE8021-PAE-MIB), ${auto.filter(p => p.authorized).length} open. The standard MIB gives no client, address or VLAN, so hosts are placed from the MAC table (the standard bridge MIB reports it across all VLANs, unlike Cisco).` }
        : { id: 'dot1x', title: '802.1X ports', group: 'hosts', state: 'na', count: 0, detail: pae.error ?? (pae.v.length ? 'The 802.1X table is published and no port is set to authenticate.' : 'No 802.1X table (IEEE8021-PAE-MIB). Normal when 802.1X is not configured, or when the vendor keeps session data in its own MIB.'), hint: pae.error ? 'IEEE8021-PAE-MIB is .1.0.8802.1.1.1, which lies outside .1.3.6.1 and is often cut off by a restricted SNMP view.' : undefined });
    }
    out.push(vrfs.v?.length ? { id: 'vrf', title: 'VRFs', group: 'routing', state: 'ok', count: vrfs.v.length, detail: `${plural(vrfs.v.length, 'VRF')}: ${vrfs.v.map(v => v.name).join(', ')} (MPLS-L3VPN-STD-MIB). Their interfaces are labelled. Reading each VRF's own multicast state needs an SNMP context, which FlowScope only knows the naming of on Cisco.` }
      : { id: 'vrf', title: 'VRFs', group: 'routing', state: 'na', count: 0, detail: vrfs.error ?? 'No VRFs (MPLS-L3VPN-STD-MIB). Normal when the device has only the default routing table, or when the vendor does not implement this MIB.', hint: vrfs.error ? 'MPLS-L3VPN-STD-MIB is .1.3.6.1.2.1.10.166.11. Check the SNMP view of this credential includes it.' : undefined });
  }

  // Link quality: IF-MIB errors and discards, broadcast and multicast, and the EtherLike-MIB frame errors
  const ifx = [...extra.v.values()];
  const nErr = ifx.filter(x => x.totals.inErr !== undefined).length, nCast = ifx.filter(x => x.totals.inBc !== undefined).length, nDot3 = ifx.filter(x => x.totals.fcs !== undefined).length;
  const nQ = ifx.filter(x => x.totals.outQDrops !== undefined).length;
  const wantDot3 = (ex.l2 || ex.l3) && ex.vendor !== 'netsnmp';
  out.push(!ifx.length ? { id: 'quality', title: 'Interface errors and link quality', group: 'quality', state: 'fail', count: 0, detail: extra.error ?? 'No error, discard or broadcast counters were returned.', hint: 'Errors and discards come from IF-MIB (.1.3.6.1.2.1.2.2), broadcast and multicast from ifXTable (.1.3.6.1.2.1.31.1.1) and frame errors from EtherLike-MIB (.1.3.6.1.2.1.10.7).' }
    : wantDot3 && !nDot3 ? { id: 'quality', title: 'Interface errors and link quality', group: 'quality', state: 'warn', count: nErr, detail: `Errors and discards on ${plural(nErr, 'interface')}${nCast ? `, broadcast and multicast on ${nCast}` : ''}, but no EtherLike-MIB: CRC, alignment and collision counts and duplex are not available.`, hint: 'EtherLike-MIB is .1.3.6.1.2.1.10.7. Some devices publish it only for physical ports, or leave it out of the SNMP view.' }
      : { id: 'quality', title: 'Interface errors and link quality', group: 'quality', state: 'ok', count: nErr, detail: `Errors and discards on ${plural(nErr, 'interface')}${nCast ? `, broadcast and multicast on ${nCast}` : ''}${nDot3 ? `, frame errors and duplex on ${nDot3}` : ''}${nQ ? `, queue drops, resets, storm control and port security on ${nQ}` : ''}.` });

  // Queue statistics, from the one MIB this kind of device uses
  if (ex.qos) {
    const sources: [QosSource, string][] = ex.qos === 'cisco-cbqos' ? [[ciscoSource, 'Cisco CBQoS']] : ex.qos === 'juniper-cos' ? [[juniperSource, 'Juniper CoS'], [diffservSource, 'DiffServ']] : [[diffservSource, 'DiffServ']];
    let hit: { name: string; policies: number; classes: number } | null = null, qerr: string | null = null;
    for (const [src, name] of sources) {
      const r = await attempt(() => src.read(cl), []);
      if (r.error && !qerr) qerr = r.error;
      if (r.v.length) { hit = { name, policies: r.v.length, classes: r.v.reduce((a, p) => a + p.classes.length, 0) }; break; }
    }
    const first = sources[0][1];
    if (hit) out.push({ id: 'qos', title: `Queue statistics (${hit.name})`, group: 'quality', state: 'ok', count: hit.policies, detail: `${plural(hit.policies, 'policy', 'policies')} with ${plural(hit.classes, 'class', 'classes')}.` });
    else if (ex.qos !== 'diffserv') out.push({ id: 'qos', title: `Queue statistics (${first})`, group: 'quality', state: 'na', count: 0, detail: qerr ?? (ex.qos === 'cisco-cbqos' ? 'No class-based QoS policies. A Cisco device publishes these only when a service policy is applied to an interface.' : 'No CoS queue statistics. Junos publishes them only for interfaces with a scheduler map.') });
  }

  // Wi-Fi tables of access points and wireless controllers
  if (ex.wifi) {
    const w = wifi.v;
    out.push(w ? { id: 'wifi', title: 'Wi-Fi radios and clients', group: 'wifi', state: 'ok', count: w.aps.length, detail: `${plural(w.aps.length, 'access point')}, ${plural(w.radios.length, 'radio')}, ${plural(w.clients.length, 'client')}.` }
      : { id: 'wifi', title: 'Wi-Fi radios and clients', group: 'wifi', state: ex.ap ? 'fail' : 'na', count: 0, detail: wifi.error ?? 'No Wi-Fi tables were returned.', hint: WIFI_HINT[wlanVendor(oid, descr) ?? ''] ?? 'Access points publish radios and clients in a vendor MIB. Check the SNMP view of this credential.' });
  }

  return out.filter(k => !drop.has(k.id)).map(k => ({ ...k, group: k.group ?? GROUP[k.id] ?? 'basics' }))
    .sort((a, b) => GROUP_ORDER.indexOf(a.group) - GROUP_ORDER.indexOf(b.group));
}

/* ------------------------------------------------------------------ OID walk */

/** A numeric OID typed by a person: leading dot allowed, at least two arcs, each arc a plain number. Returns it without the dot, or null. */
export function cleanOid(text: string): string | null {
  const t = text.trim().replace(/^\./, '');
  if (!/^\d+(\.\d+){1,63}$/.test(t) || t.length > 255) return null;
  const arcs = t.split('.');
  if (arcs.some(a => a.length > 10 || Number(a) > 4294967295)) return null;
  if (Number(arcs[0]) > 2) return null;
  return t;
}

const TYPES: Record<number, string> = { 2: 'Integer', 4: 'OctetString', 5: 'Null', 6: 'OID', 64: 'IpAddress', 65: 'Counter32', 66: 'Gauge32', 67: 'TimeTicks', 68: 'Opaque', 70: 'Counter64' };

/** A value as a person would read it in snmpwalk: text when it is printable, otherwise hex. */
export function formatValue(type: number, v: SnmpValue): { type: string; text: string } {
  const name = TYPES[type] ?? `type ${type}`;
  if (v === null) return { type: name, text: '' };
  if (Buffer.isBuffer(v)) {
    const body = v.length > 1 && v[v.length - 1] === 0 ? v.subarray(0, -1) : v;   // agents often send a trailing NUL
    const printable = body.length > 0 && [...body].every(b => (b >= 0x20 && b < 0x7f) || b === 0x0a || b === 0x09);
    if (printable) return { type: name, text: v.toString('utf8').replace(/\0+$/, '') };
    return { type: name, text: v.length ? 'hex ' + [...v].map(b => b.toString(16).padStart(2, '0')).join(':') : '' };
  }
  return { type: name, text: String(v) };
}
