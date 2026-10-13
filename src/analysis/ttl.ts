import type { FlowRecord } from '../collector/types.js';
import { ipToN } from '../store/util.js';

/*
 * "TTL expired" detection.
 *
 * A router that receives a packet with TTL 1 (or 0) must drop it and answer with ICMP Time Exceeded. When an exporter reports that
 * the lowest TTL it saw for a flow was 1 or less, the flow's packets could not have been forwarded any further, so they did not
 * reach their destination. That is the main signal ("ttl"). The second signal ("icmp") is an ICMP Time Exceeded / IPv6 Hop Limit
 * Exceeded message in the flow data, which is a router telling a sender its packet ran out of TTL.
 *
 * Some traffic is built to travel one hop and so legitimately has TTL 1, and must never be flagged: multicast and broadcast
 * discovery (mDNS, SSDP, LLMNR...), link-local addresses, routing and redundancy protocols (OSPF, EIGRP, PIM, IGMP, VRRP, HSRP, RIP) and
 * traffic addressed to a router itself. TTL is only available when the exporter reports it (IPFIX / NetFlow v9 minimumTTL), not in NetFlow v5.
 */

/** Lowest TTL at an exporter that means the next router would have to drop the packet. */
export const TTL_EXPIRED_AT = 1;

/** IP protocols that are sent with TTL 1 (or are link-local) by design: IGMP, EIGRP, OSPF, PIM, VRRP. */
export const TTL1_PROTOCOLS = [2, 88, 89, 103, 112];
/** UDP ports of link-local discovery and routing protocols: NetBIOS name/datagram, SSDP, WS-Discovery, mDNS, LLMNR, RIP, RIPng, DHCPv6, HSRP, GLBP. */
export const TTL1_UDP_PORTS = [137, 138, 520, 521, 546, 547, 1900, 1985, 2029, 3222, 3702, 5353, 5355];

const MCAST_LO = 224 * 16777216, ALL_ONES = 4294967295;              // 224.0.0.0 and up: multicast, reserved and the limited broadcast
const LL4_LO = (169 * 256 + 254) * 65536, LL4_HI = LL4_LO + 65535;   // 169.254.0.0/16
const LL6 = ['fe8', 'fe9', 'fea', 'feb'];                            // fe80::/10

export type TtlReason = 'ttl' | 'icmp';

/** True for ICMPv4 Time Exceeded (type 11) code 0 (TTL in transit) and ICMPv6 Time Exceeded (type 3) code 0 (hop limit). Flow exporters put type*256+code in the port field. */
export function isTimeExceeded(r: Pick<FlowRecord, 'proto' | 'dport'>): boolean {
  return (r.proto === 1 && r.dport === 11 * 256) || (r.proto === 58 && r.dport === 3 * 256);
}

function linkLocal6(ip: string): boolean { return LL6.some(p => ip.startsWith(p)); }

/** True when this traffic is expected to have TTL 1 and must not be reported. `local` holds addresses owned by our own routers. */
export function ttl1ByDesign(r: Pick<FlowRecord, 'srcIp' | 'dstIp' | 'proto' | 'sport' | 'dport' | 'exporter'>, local: ReadonlySet<string>): boolean {
  const d = ipToN(r.dstIp), s = ipToN(r.srcIp);
  if (d !== null && d >= MCAST_LO && d <= ALL_ONES) return true;
  if (r.dstIp.startsWith('ff')) return true;
  if ((d !== null && d >= LL4_LO && d <= LL4_HI) || (s !== null && s >= LL4_LO && s <= LL4_HI)) return true;
  if (linkLocal6(r.dstIp) || linkLocal6(r.srcIp)) return true;
  if (r.dstIp === r.exporter || local.has(r.dstIp)) return true;
  if (TTL1_PROTOCOLS.includes(r.proto)) return true;
  if (r.proto === 17 && (TTL1_UDP_PORTS.includes(r.sport) || TTL1_UDP_PORTS.includes(r.dport))) return true;
  return false;
}

/** Why a single flow record shows an expired TTL, or null. */
export function ttlEvidence(r: FlowRecord, local: ReadonlySet<string>): TtlReason | null {
  if (r.ttlMin !== null && r.ttlMin <= TTL_EXPIRED_AT && !ttl1ByDesign(r, local)) return 'ttl';
  if (isTimeExceeded(r)) return 'icmp';
  return null;
}

/* ------------------------------------------------------------------ the same rules as SQL, for the stores */

export interface SqlDialect {
  /** Wraps a boolean expression so that NULL counts as false. */
  nn(e: string): string;
  startsWith(col: string, prefix: string): string;
  str(s: string): string;
}
export interface TtlCols { ttl: string; srcIp: string; dstIp: string; srcN: string; dstN: string; proto: string; sport: string; dport: string; exporter: string }

/** SQL boolean expressions over the raw flow columns: `expired` (TTL ran out at an exporter), `icmp` (a Time Exceeded message) and `any`. */
export function ttlSql(d: SqlDialect, c: TtlCols, local: readonly string[]): { expired: string; icmp: string; any: string } {
  const between = (n: string, lo: number, hi: number) => d.nn(`${n} BETWEEN ${lo} AND ${hi}`);
  const byDesign = [
    between(c.dstN, MCAST_LO, ALL_ONES),
    d.startsWith(c.dstIp, 'ff'),
    between(c.dstN, LL4_LO, LL4_HI), between(c.srcN, LL4_LO, LL4_HI),
    ...LL6.flatMap(p => [d.startsWith(c.dstIp, p), d.startsWith(c.srcIp, p)]),
    `${c.dstIp} = ${c.exporter}`,
    ...(local.length ? [`${c.dstIp} IN (${local.map(d.str).join(',')})`] : []),
    `${c.proto} IN (${TTL1_PROTOCOLS.join(',')})`,
    `(${c.proto} = 17 AND (${c.sport} IN (${TTL1_UDP_PORTS.join(',')}) OR ${c.dport} IN (${TTL1_UDP_PORTS.join(',')})))`
  ].map(x => d.nn(x)).join(' OR ');
  const expired = `(${d.nn(`${c.ttl} <= ${TTL_EXPIRED_AT}`)} AND NOT (${byDesign}))`;
  const icmp = `((${c.proto} = 1 AND ${c.dport} = ${11 * 256}) OR (${c.proto} = 58 AND ${c.dport} = ${3 * 256}))`;
  return { expired, icmp, any: `(${expired} OR ${icmp})` };
}
