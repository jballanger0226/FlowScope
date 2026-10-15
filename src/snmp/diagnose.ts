import type { SnmpValue } from './client.js';
import { OID } from './oids.js';
import type { Walker } from './ports.js';

/*
 * Diagnostics for one SNMP device: what it publishes (so a missing LLDP table is explained rather than silent) and a
 * read-only look at any OID. The checks only need `column()`, so tests feed them an in-memory table.
 */

export type CheckState = 'ok' | 'warn' | 'fail' | 'na';
export interface Check { id: string; title: string; state: CheckState; count: number; detail: string; hint?: string }
export interface CheckFacts { role: string; cisco: boolean }

const LLDP_HINT = 'Switches publish LLDP over SNMP themselves. Firewalls and servers (OPNsense, pfSense, Linux) only do it through the lldpd AgentX subagent: install lldpd, turn on AgentX in the SNMP service (the master agent needs "master agentx"), and start lldpd with -x. Then check that the community or SNMPv3 user may read .1.0.8802, which lies outside .1.3.6.1 and is often cut off by a restricted view.';

type Col = { map: Map<string, SnmpValue>; error: string | null };
async function col(c: Walker, oid: string): Promise<Col> {
  try { return { map: await c.column(oid, 20), error: null }; } catch (e) { return { map: new Map(), error: (e as Error).message }; }
}
const plural = (n: number, one: string, many = one + 's') => `${n} ${n === 1 ? one : many}`;
const ports = (m: Map<string, SnmpValue>, at: number) => new Set([...m.keys()].map(k => k.split('.')[at])).size;

export async function runChecks(c: Walker, f: CheckFacts): Promise<Check[]> {
  const [ifName, ifDescr, hc, in32, locPort, lldpRem, cdp, fdbQ, fdbD, arpP, arpM, vq, vtp, pvid, cbqos] = await Promise.all([
    col(c, OID.ifName), col(c, OID.ifDescr), col(c, OID.ifHCInOctets), col(c, OID.ifInOctets32),
    col(c, OID.lldpLocPortId), col(c, OID.lldpRemChassisId), col(c, OID.cdpCacheDeviceId),
    col(c, OID.dot1qTpFdbPort), col(c, OID.dot1dTpFdbPort), col(c, OID.ipNetToPhysicalPhysAddress), col(c, OID.ipNetToMediaPhysAddress),
    col(c, OID.dot1qVlanStaticName), col(c, OID.vtpVlanName), col(c, OID.dot1qPvid), col(c, OID.cbQosPolicyMapName)
  ]);
  const out: Check[] = [];
  const err = (...cs: Col[]) => cs.map(x => x.error).find(Boolean) ?? null;

  const nIf = Math.max(ifName.map.size, ifDescr.map.size);
  out.push(nIf ? { id: 'interfaces', title: 'Interfaces', state: 'ok', count: nIf, detail: `${plural(nIf, 'interface')} listed.` }
    : { id: 'interfaces', title: 'Interfaces', state: 'fail', count: 0, detail: err(ifName, ifDescr) ?? 'The interface table is empty or not readable with this credential.', hint: 'Nothing can be graphed without it. Check that the credential may read IF-MIB (.1.3.6.1.2.1.2 and .1.3.6.1.2.1.31).' });

  out.push(hc.map.size ? { id: 'counters', title: 'Traffic counters', state: 'ok', count: hc.map.size, detail: '64-bit counters are available, so fast links will not wrap.' }
    : in32.map.size ? { id: 'counters', title: 'Traffic counters', state: 'warn', count: in32.map.size, detail: 'Only 32-bit counters are published. They wrap in about 34 seconds at 1 Gbps, so utilisation on fast links can read low.', hint: 'The device needs to publish ifXTable (IF-MIB ifHCInOctets).' }
      : { id: 'counters', title: 'Traffic counters', state: 'fail', count: 0, detail: err(hc, in32) ?? 'No interface traffic counters were returned.' });

  const nLoc = locPort.map.size, nRem = lldpRem.map.size;
  out.push(nRem ? { id: 'lldp', title: 'LLDP neighbours', state: 'ok', count: nRem, detail: `${plural(nRem, 'neighbour')} on ${plural(ports(lldpRem.map, 1), 'port')}.` }
    : nLoc ? { id: 'lldp', title: 'LLDP neighbours', state: 'warn', count: 0, detail: `The device publishes LLDP (${plural(nLoc, 'local port')}) but has no neighbours yet.`, hint: 'Check that the other end sends LLDP and that LLDP is enabled on this port. On a firewall or server, lldpctl shows what lldpd has heard.' }
      : { id: 'lldp', title: 'LLDP neighbours', state: 'fail', count: 0, detail: err(locPort, lldpRem) ?? 'Nothing came back for the LLDP-MIB (.1.0.8802.1.1.2). Either the device does not publish it over SNMP, or this credential may not read it.', hint: LLDP_HINT });

  out.push(cdp.map.size ? { id: 'cdp', title: 'CDP neighbours', state: 'ok', count: cdp.map.size, detail: `${plural(cdp.map.size, 'neighbour')} on ${plural(ports(cdp.map, 0), 'port')}.` }
    : { id: 'cdp', title: 'CDP neighbours', state: 'na', count: 0, detail: 'No CDP table. Only Cisco devices publish it, so this is normal elsewhere.' });

  const nFdb = Math.max(fdbQ.map.size, fdbD.map.size);
  const isSwitch = f.role === 'switch';
  out.push(nFdb ? { id: 'mac', title: 'MAC address table', state: 'ok', count: nFdb, detail: `${plural(nFdb, 'learned address')}.` }
    : f.cisco ? { id: 'mac', title: 'MAC address table', state: 'na', count: 0, detail: 'Empty with the plain credential. Cisco switches keep one table per VLAN, and FlowScope reads them per VLAN when it tracks hosts.' }
      : { id: 'mac', title: 'MAC address table', state: isSwitch ? 'fail' : 'na', count: 0, detail: err(fdbQ, fdbD) ?? (isSwitch ? 'No learned MAC addresses were returned, so hosts cannot be placed on ports.' : 'Not published. Routers and firewalls do not keep one.'), hint: isSwitch ? 'The device needs to publish BRIDGE-MIB or Q-BRIDGE-MIB.' : undefined });

  const nArp = Math.max(arpP.map.size, arpM.map.size);
  out.push(nArp ? { id: 'arp', title: 'ARP / neighbour cache', state: 'ok', count: nArp, detail: `${plural(nArp, 'entry', 'entries')}.` }
    : { id: 'arp', title: 'ARP / neighbour cache', state: f.role === 'router' ? 'warn' : 'na', count: 0, detail: err(arpP, arpM) ?? 'No ARP entries were returned, so MAC addresses cannot be turned into IP addresses from this device.' });

  const nVlan = Math.max(vq.map.size, vtp.map.size, pvid.map.size);
  out.push(nVlan ? { id: 'vlans', title: 'VLANs', state: 'ok', count: nVlan, detail: `${plural(nVlan, 'VLAN entry', 'VLAN entries')}.` }
    : { id: 'vlans', title: 'VLANs', state: 'na', count: 0, detail: 'No VLAN information published. Normal for routers and firewalls without VLAN tables.' });

  out.push(cbqos.map.size ? { id: 'qos', title: 'Queue statistics (Cisco CBQoS)', state: 'ok', count: cbqos.map.size, detail: `${plural(cbqos.map.size, 'policy map')} found.` }
    : { id: 'qos', title: 'Queue statistics (Cisco CBQoS)', state: 'na', count: 0, detail: 'No class-based QoS policies. Only Cisco devices with a service policy publish this.' });
  return out;
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
