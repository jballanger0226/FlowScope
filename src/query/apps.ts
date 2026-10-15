import { wellKnownName, wellKnownPorts } from './wellknown.js';

/** Well-known services. Used for the app: search token and to label streams. Ports 0-1023 that are not listed here are named from wellknown.ts. */
export interface AppDef { name: string; ports: number[]; proto: number[] }

const TCP = 6, UDP = 17;
export const APPS: AppDef[] = [
  { name: 'https', ports: [443, 8443], proto: [TCP, UDP] }, { name: 'http', ports: [80, 8080], proto: [TCP] },
  { name: 'ssh', ports: [22], proto: [TCP] }, { name: 'telnet', ports: [23], proto: [TCP] }, { name: 'ftp', ports: [21, 20], proto: [TCP] },
  { name: 'dns', ports: [53], proto: [UDP, TCP] }, { name: 'dhcp', ports: [67, 68], proto: [UDP] }, { name: 'tftp', ports: [69], proto: [UDP] },
  { name: 'ntp', ports: [123], proto: [UDP] }, { name: 'snmp', ports: [161, 162], proto: [UDP] }, { name: 'syslog', ports: [514], proto: [UDP, TCP] },
  { name: 'smb', ports: [445, 139], proto: [TCP] }, { name: 'rdp', ports: [3389], proto: [TCP, UDP] }, { name: 'vnc', ports: [5900], proto: [TCP] },
  { name: 'ldap', ports: [389, 636, 3268, 3269], proto: [TCP, UDP] }, { name: 'kerberos', ports: [88], proto: [TCP, UDP] },
  { name: 'smtp', ports: [25, 587, 465], proto: [TCP] }, { name: 'imap', ports: [143, 993], proto: [TCP] }, { name: 'pop3', ports: [110, 995], proto: [TCP] },
  { name: 'postgres', ports: [5432], proto: [TCP] }, { name: 'mysql', ports: [3306], proto: [TCP] }, { name: 'mssql', ports: [1433], proto: [TCP] },
  { name: 'oracle', ports: [1521], proto: [TCP] }, { name: 'redis', ports: [6379], proto: [TCP] }, { name: 'mongodb', ports: [27017], proto: [TCP] },
  { name: 'kafka', ports: [9092], proto: [TCP] }, { name: 'elasticsearch', ports: [9200, 9300], proto: [TCP] }, { name: 'nfs', ports: [2049], proto: [TCP, UDP] },
  { name: 'sip', ports: [5060, 5061], proto: [UDP, TCP] }, { name: 'rtp', ports: [5004], proto: [UDP] }, { name: 'bgp', ports: [179], proto: [TCP] },
  { name: 'radius', ports: [1812, 1813], proto: [UDP] }, { name: 'netflow', ports: [2055, 4739, 9995], proto: [UDP] }, { name: 'vxlan', ports: [4789], proto: [UDP] },
  { name: 'ike', ports: [500, 4500], proto: [UDP] }, { name: 'wireguard', ports: [51820], proto: [UDP] }, { name: 'mqtt', ports: [1883, 8883], proto: [TCP] },
  { name: 'iscsi', ports: [3260], proto: [TCP] }, { name: 'quic', ports: [443], proto: [UDP] }
];

export const PROTOS: Record<string, number> = { icmp: 1, igmp: 2, tcp: 6, udp: 17, gre: 47, esp: 50, ah: 51, icmp6: 58, ospf: 89, eigrp: 88, pim: 103, vrrp: 112, sctp: 132 };
export const PROTO_NAMES: Record<number, string> = Object.fromEntries(Object.entries(PROTOS).map(([k, v]) => [v, k.toUpperCase()]));

export function protoName(p: number): string { return PROTO_NAMES[p] ?? String(p); }

/** Names the service for a stream. Looks at the server (lower or well-known) port. */
export function appName(proto: number, sport: number, dport: number): string {
  if (proto !== TCP && proto !== UDP) return protoName(proto).toLowerCase();
  for (const p of [dport, sport]) {
    for (const a of APPS) if (a.ports.includes(p) && a.proto.includes(proto)) return a.name;
  }
  // the other well-known ports: the server side is the lower port, and only a port below 1024 is read as a service
  const lo = Math.min(sport, dport), hi = Math.max(sport, dport);
  for (const p of [lo, hi]) { if (p > 0 && p < 1024) { const n = wellKnownName(p, proto); if (n) return n; } }
  return lo > 0 && lo < 1024 ? String(lo) : (proto === TCP ? 'tcp/' : 'udp/') + Math.min(sport, dport);
}

/** The ports a service name stands for: the app list first (https, dns, ...), then any well-known service name (nntp, ftp-data, ...). */
export function servicePorts(name: string): number[] | null {
  const a = appByName(name);
  return a ? a.ports : wellKnownPorts(name);
}

export function appByName(name: string): AppDef | undefined {
  const n = name.toLowerCase();
  return APPS.find(a => a.name === n);
}

export const DSCP_NAMES: Record<number, string> = {
  0: 'CS0', 8: 'CS1', 10: 'AF11', 12: 'AF12', 14: 'AF13', 16: 'CS2', 18: 'AF21', 20: 'AF22', 22: 'AF23', 24: 'CS3', 26: 'AF31', 28: 'AF32', 30: 'AF33',
  32: 'CS4', 34: 'AF41', 36: 'AF42', 38: 'AF43', 40: 'CS5', 46: 'EF', 48: 'CS6', 56: 'CS7'
};
export function dscpName(d: number): string { return DSCP_NAMES[d] ? `${DSCP_NAMES[d]} (${d})` : String(d); }
export function dscpByName(n: string): number | null {
  const u = n.toUpperCase();
  for (const [k, v] of Object.entries(DSCP_NAMES)) if (v === u) return Number(k);
  return null;
}
