/**
 * Well-known ports (0-1023) and the service names registered for them, so a flow to port 119 reads "nntp" and not just "119", and
 * "nntp" can be searched as well as 119. Names follow the IANA service name registry (service-names-port-numbers); a few widely used
 * aliases are added (www, domain, microsoft-ds, ...). The list is written out here, not fetched, so it needs no network and does not change
 * under you. It holds the assignments people actually meet on a network, not every row of the registry, and the display name of a port that
 * query/apps.ts already knows (https, ssh, dns, dhcp, smb, ...) is that one, not the registry's.
 *
 * A port with different services over TCP and UDP is given as [port, tcpName, udpName]. Everything else is [port, name].
 */
type Entry = [port: number, name: string, udpName?: string];
const ENTRIES: Entry[] = [
  [1, 'tcpmux'], [5, 'rje'], [7, 'echo'], [9, 'discard'], [11, 'systat'], [13, 'daytime'], [15, 'netstat'], [17, 'qotd'], [18, 'msp'],
  [19, 'chargen'], [20, 'ftp-data'], [21, 'ftp'], [22, 'ssh'], [23, 'telnet'], [25, 'smtp'], [37, 'time'], [42, 'nameserver'], [43, 'whois'],
  [49, 'tacacs'], [53, 'domain'], [67, 'bootps'], [68, 'bootpc'], [69, 'tftp'], [70, 'gopher'], [79, 'finger'], [80, 'http'], [88, 'kerberos'],
  [95, 'supdup'], [101, 'hostname'], [102, 'iso-tsap'], [104, 'acr-nema'], [105, 'csnet-ns'], [107, 'rtelnet'], [109, 'pop2'], [110, 'pop3'],
  [111, 'sunrpc'], [113, 'auth'], [115, 'sftp'], [117, 'uucp-path'], [119, 'nntp'], [123, 'ntp'], [135, 'epmap'], [137, 'netbios-ns'],
  [138, 'netbios-dgm'], [139, 'netbios-ssn'], [143, 'imap'], [161, 'snmp'], [162, 'snmptrap'], [163, 'cmip-man'], [164, 'cmip-agent'],
  [174, 'mailq'], [177, 'xdmcp'], [179, 'bgp'], [191, 'prospero'], [194, 'irc'], [199, 'smux'], [201, 'at-rtmp'], [202, 'at-nbp'], [204, 'at-echo'],
  [206, 'at-zis'], [209, 'qmtp'], [210, 'z39.50'], [213, 'ipx'], [220, 'imap3'], [245, 'link'], [319, 'ptp-event'], [320, 'ptp-general'],
  [347, 'fatserv'], [363, 'rsvp_tunnel'], [369, 'rpc2portmap'], [370, 'codaauth2'], [371, 'clearcase'], [372, 'ulistproc'], [389, 'ldap'],
  [427, 'svrloc'], [434, 'mobileip-agent'], [435, 'mobilip-mn'], [443, 'https'], [444, 'snpp'], [445, 'microsoft-ds'], [464, 'kpasswd'],
  [465, 'submissions'], [468, 'photuris'], [487, 'saft'], [488, 'gss-http'], [496, 'pim-rp-disc'], [500, 'isakmp'], [502, 'mbap'],
  [512, 'exec', 'biff'], [513, 'login', 'who'], [514, 'shell', 'syslog'], [515, 'printer'], [517, 'talk'], [518, 'ntalk'], [520, 'efs', 'router'],
  [521, 'ripng'], [525, 'timed'], [526, 'tempo'], [530, 'courier'], [531, 'conference'], [532, 'netnews'], [533, 'netwall'], [538, 'gdomap'],
  [540, 'uucp'], [543, 'klogin'], [544, 'kshell'], [546, 'dhcpv6-client'], [547, 'dhcpv6-server'], [548, 'afpovertcp'], [554, 'rtsp'],
  [556, 'remotefs'], [563, 'nntps'], [587, 'submission'], [591, 'http-alt'], [593, 'http-rpc-epmap'], [607, 'nqs'], [623, 'asf-rmcp'], [628, 'qmqp'],
  [631, 'ipp'], [636, 'ldaps'], [639, 'msdp'], [646, 'ldp'], [647, 'dhcp-failover'], [648, 'rrp'], [653, 'repscmd'], [654, 'aodv'], [655, 'tinc'],
  [657, 'rmc'], [660, 'mac-srvr-admin'], [666, 'doom'], [674, 'acap'], [691, 'resvc'], [694, 'ha-cluster'], [695, 'ieee-mms-ssl'], [698, 'olsr'],
  [700, 'epp'], [701, 'lmp'], [702, 'iris-beep'], [706, 'silc'], [711, 'cisco-tdp'], [712, 'tbrpf'], [713, 'iris-xpc'], [714, 'iris-xpcs'],
  [715, 'iris-lwz'], [749, 'kerberos-adm'], [750, 'kerberos-iv'], [751, 'kerberos-master'], [752, 'passwd-server'], [782, 'conserver'],
  [783, 'spamd'], [829, 'pkix-3-ca-ra'], [853, 'domain-s'], [871, 'supfilesrv'], [873, 'rsync'], [989, 'ftps-data'], [990, 'ftps'], [992, 'telnets'],
  [993, 'imaps'], [994, 'ircs'], [995, 'pop3s']
];

/** Other names people type for the same port. They find the port in a search but are not shown as its label. */
const ALIASES: Record<string, number | number[]> = {
  www: 80, 'http-alt': 591, dns: 53, nameserver: 42, ident: 113, 'ms-rpc': 135, msrpc: 135, 'ms-ds': 445, smtps: 465, 'ssh-sftp': 22, ike: 500, ntp: 123,
  netbios: [137, 138, 139], 'dhcp-server': 67, 'dhcp-client': 68, bootp: 67, rip: 520, 'rip-ng': 521, 'kerberos-passwd': 464, lpd: 515, 'lpr': 515, printer: 515, 'ftp-control': 21, dicom: 104, wais: 210, z3950: 210, ptp: [319, 320], ipmi: 623
};

const TCP = 6, UDP = 17;
const BY_PORT = new Map<number, Entry>(ENTRIES.map(e => [e[0], e]));
const BY_NAME = new Map<string, number[]>();
const add = (name: string, port: number) => { const k = name.toLowerCase(); const l = BY_NAME.get(k) ?? []; if (!l.includes(port)) l.push(port); BY_NAME.set(k, l); };
for (const [port, name, udp] of ENTRIES) { add(name, port); if (udp) add(udp, port); }
for (const [name, port] of Object.entries(ALIASES)) for (const p of [port].flat()) add(name, p);

/** The registered name of a port below 1024, for this IP protocol (TCP 6 or UDP 17); null when none is known. */
export function wellKnownName(port: number, proto: number): string | null {
  const e = BY_PORT.get(port);
  if (!e) return null;
  return proto === UDP && e[2] ? e[2] : e[1];
}

/** The ports a service name stands for ("nntp" -> [119], "syslog" -> [514]); null when the name is not a well-known service. */
export function wellKnownPorts(name: string): number[] | null {
  return BY_NAME.get(name.trim().toLowerCase()) ?? null;
}

export const WELL_KNOWN_COUNT = ENTRIES.length;
export const WELL_KNOWN_PROTOS = { TCP, UDP };
