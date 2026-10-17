type Level = 'ok' | 'warn' | 'bad' | 'off';
/** The parts of the health read the Overview looks at, kept structural so this file has no dependency on the browser code. */
interface OvHealth {
  extras?: { stack: null | { problems: string[] }; dai: null | { vlans: { vlan: number; droppedNow: number | null; dhcpDenied: number; why: string }[] }; procs: null | { snmpOne: number | null }; aaa?: null | { servers: { address: string; kind: string; up: boolean; level: Level; problems: string[] }[] }; config?: null | { unsaved: boolean; changedAt: number | null }; lisp?: null | { level: Level; problems: string[] } };
  ifExtra: { ifIndex: number; warnings: { level: Level; text: string }[] }[];
  health: null | {
    sensors: { kind: string; name: string; state: Level; stateText: string; ifIndex?: number }[];
    poe: { status: string; portsFault: number; usedPct: number | null }[];
    stp: null | { sinceChangeSec: number | null; topChanges: number | null };
    ospf: { id: string; address: string; state: string; level: Level }[];
    bgp: { address: string; as: number | null; state: string; level: Level }[];
    eigrp?: { as: number; address: string; level: Level; retries: number | null }[];
    bfd?: { address: string; state: string; level: Level; diag: string | null }[];
  };
}

/** Where an issue is explained in detail: a tab of the device, and for interface problems, the interface and its section. */
export type Target = { tab: 'interfaces' | 'hardware' | 'network' | 'wifi'; ifIndex?: number; section?: 'traffic' | 'quality'; /** Open the Multicast page of this device instead of a tab */ multicast?: true };
export interface Issue { level: 'bad' | 'warn'; title: string; detail: string; target?: Target }
export interface Card { tab: Target['tab']; label: string; level: Level; headline: string; lines: string[] }

interface OvIface { ifIndex: number; name: string; alias: string; oper: string; isVlanIf: boolean; flagged: boolean; utilIn: number | null; utilOut: number | null; worstDropPct: number | null; priorityPct?: number | null; mcastPct?: number | null }
export interface OvDev { rpfNow?: { routes: number; drops: number; top: string } | null; status: string; lastError: string | null; resources: { cpuPct: number | null; memPct: number | null; swapPct: number | null; disks: { name: string; usedPct: number }[]; tempC?: number | null } | null; interfaces: OvIface[]; hasWlan: boolean }
export interface OvWlan { aps: { name: string; mac: string }[]; radios: { apMac: string; idx: number; band: string; up: boolean }[]; clients: unknown[] }
export interface OvInput { dev: OvDev; health: OvHealth | null; wlan: OvWlan | null; neighbours: number | null; arp: number | null; hasHardware: boolean; thresholds: { util: number; drop: number; mcast?: number; priority?: number } }

const plural = (n: number, one: string, many = one + 's'): string => `${n} ${n === 1 ? one : many}`;
const pct = (n: number | null): string => (n === null ? '–' : `${Math.round(n)}%`);

/** Everything on one device that is outside its limits, worst first, each with the place to look at it. */
export function issues(o: OvInput): Issue[] {
  const out: Issue[] = [];
  const { dev, health } = o;
  const names = new Map(dev.interfaces.map(i => [i.ifIndex, i.alias ? `${i.name} (${i.alias})` : i.name]));
  if (dev.rpfNow) out.push({ level: 'warn', title: `${plural(dev.rpfNow.routes, 'multicast route')} dropping packets that arrive on the wrong interface`, detail: `${dev.rpfNow.drops.toLocaleString('en-US')} packets since the last read, most on ${dev.rpfNow.top}. The Multicast page lists the routes and graphs the drops over the last day.`, target: { tab: 'network', multicast: true } });
  const r = dev.resources;
  if (r) {
    if (r.cpuPct !== null && r.cpuPct >= 85) out.push({ level: r.cpuPct >= 95 ? 'bad' : 'warn', title: `CPU at ${pct(r.cpuPct)}`, detail: 'The history graphs on the Hardware tab show when it rose.', target: { tab: 'hardware' } });
    if (r.memPct !== null && r.memPct >= 90) out.push({ level: r.memPct >= 95 ? 'bad' : 'warn', title: `Memory at ${pct(r.memPct)}`, detail: 'The resource graphs below show the trend.' });
    for (const d of r.disks) if (d.usedPct >= 90) out.push({ level: d.usedPct >= 95 ? 'bad' : 'warn', title: `Disk ${d.name} ${pct(d.usedPct)} full`, detail: 'Free space before it runs out.', target: { tab: 'hardware' } });
  }
  for (const i of dev.interfaces) if (i.flagged) {
    const bits: string[] = [];
    if (i.worstDropPct !== null && i.worstDropPct >= o.thresholds.drop) bits.push(`queue drops ${i.worstDropPct.toFixed(1)}%`);
    if (i.priorityPct != null && i.priorityPct >= (o.thresholds.priority ?? 80)) bits.push(`priority queue ${Math.round(i.priorityPct)}% of its limit (traffic above it is dropped)`);
    if (i.mcastPct != null && i.mcastPct >= (o.thresholds.mcast ?? 50)) bits.push(`multicast ${Math.round(i.mcastPct)}% of the link`);
    const u = Math.max(i.utilIn ?? 0, i.utilOut ?? 0); if (u >= o.thresholds.util) bits.push(`utilisation ${Math.round(u)}%`);
    out.push({ level: 'warn', title: `${names.get(i.ifIndex)}: over its limits`, detail: bits.join(', ') || 'Over a threshold in the last window.', target: { tab: 'interfaces', ifIndex: i.ifIndex, section: 'traffic' } });
  }
  /** Link problems and optic readings of one interface are one item, so a bad port is not listed three times. */
  const perIf = new Map<number, { level: 'bad' | 'warn'; texts: string[] }>();
  const addIf = (ifIndex: number, level: 'bad' | 'warn', text: string): void => {
    const e = perIf.get(ifIndex) ?? { level, texts: [] };
    if (level === 'bad') e.level = 'bad';
    if (!e.texts.includes(text)) e.texts.push(text);
    perIf.set(ifIndex, e);
  };
  for (const x of health?.ifExtra ?? []) if (names.has(x.ifIndex)) for (const w of x.warnings) if (w.level === 'bad' || w.level === 'warn') addIf(x.ifIndex, w.level, w.text);
  for (const s of health?.health?.sensors ?? []) if (s.kind === 'optic' && s.ifIndex !== undefined && names.has(s.ifIndex) && (s.state === 'bad' || s.state === 'warn')) addIf(s.ifIndex, s.state, `${s.name}: ${s.stateText}`);
  for (const [ifIndex, e] of perIf) out.push({ level: e.level, title: `${names.get(ifIndex)}: ${e.texts.length === 1 ? e.texts[0]! : plural(e.texts.length, 'link problem')}`, detail: e.texts.length === 1 ? 'See the error counters and optic readings for this interface.' : e.texts.join(' · '), target: { tab: 'interfaces', ifIndex, section: 'quality' } });
  const ex = health?.extras;
  for (const t of ex?.stack?.problems ?? []) out.push({ level: 'warn', title: 'Stack problem', detail: t, target: { tab: 'hardware' } });
  for (const v of ex?.dai?.vlans ?? []) if ((v.droppedNow ?? 0) > 0) out.push({ level: 'warn', title: `ARP packets dropped on VLAN ${v.vlan}`, detail: `${plural(v.droppedNow!, 'packet')} since the last read. ${v.why}.`, target: { tab: 'network' } });
  if ((ex?.procs?.snmpOne ?? 0) >= 10) out.push({ level: 'warn', title: 'SNMP engine is using the CPU', detail: `${ex!.procs!.snmpOne}% over the last minute. Polling is part of this device's load.`, target: { tab: 'hardware' } });
  for (const sv of ex?.aaa?.servers ?? []) if (sv.level !== 'ok') out.push({ level: sv.level === 'bad' ? 'bad' : 'warn', title: `${sv.kind === 'tacacs' ? 'TACACS+' : 'RADIUS'} server ${sv.address} ${sv.up ? 'is struggling' : 'is dead'}`, detail: sv.problems.join(' '), target: { tab: 'hardware' } });
  if (ex?.config?.unsaved && ex.config.changedAt && Date.now() - ex.config.changedAt >= 3600_000) out.push({ level: 'warn', title: 'Configuration not saved', detail: 'The running configuration differs from startup and has for over an hour. A reload would lose the change.', target: { tab: 'hardware' } });
  if (ex?.lisp && ex.lisp.level !== 'ok') for (const t of ex.lisp.problems) out.push({ level: ex.lisp.level === 'bad' ? 'bad' : 'warn', title: 'LISP fabric', detail: t, target: { tab: 'network' } });
  const hl = health?.health;
  if (hl) {
    for (const s of hl.sensors) {
      if (s.state !== 'bad' && s.state !== 'warn') continue;
      if (s.kind === 'optic' && s.ifIndex !== undefined && names.has(s.ifIndex)) continue;
      out.push({ level: s.state, title: `${s.name}: ${s.stateText}`, detail: s.kind === 'optic' ? 'Optic light level or temperature outside its limits.' : `A ${s.kind} sensor is outside its limits.`, target: { tab: 'hardware' } });
    }
    for (const p of hl.poe) {
      if (p.status === 'faulty' || p.portsFault) out.push({ level: 'bad', title: 'PoE fault', detail: p.status === 'faulty' ? 'The power source is faulty.' : plural(p.portsFault, 'port') + ' in fault.', target: { tab: 'hardware' } });
      if (p.usedPct !== null && p.usedPct >= 90) out.push({ level: 'warn', title: `PoE budget ${p.usedPct}% used`, detail: 'New powered devices may be refused.', target: { tab: 'hardware' } });
    }
    for (const n of hl.ospf) if (n.level !== 'ok' && n.level !== 'off') out.push({ level: n.level === 'bad' ? 'bad' : 'warn', title: `OSPF neighbour ${n.id || n.address} is ${n.state}`, detail: n.address, target: { tab: 'network' } });
    for (const p of hl.bgp) if (p.level === 'bad' || p.level === 'warn') out.push({ level: p.level, title: `BGP peer ${p.address} is ${p.state}`, detail: p.as !== null ? `AS ${p.as}` : '', target: { tab: 'network' } });
    for (const p of hl.eigrp ?? []) if (p.level === 'warn' || p.level === 'bad') out.push({ level: 'warn', title: `EIGRP neighbour ${p.address} is retransmitting`, detail: `AS ${p.as}${p.retries ? `, ${p.retries} retries on the current packet` : ''}. Packets to it are being lost.`, target: { tab: 'network' } });
    for (const b of hl.bfd ?? []) if (b.level === 'bad' || b.level === 'warn') out.push({ level: b.level, title: `BFD session to ${b.address} is ${b.state}`, detail: b.diag ?? 'The fast failure detector for this neighbour is not up.', target: { tab: 'network' } });
    if (hl.stp && hl.stp.sinceChangeSec !== null && hl.stp.sinceChangeSec < 600 && hl.stp.topChanges) out.push({ level: 'warn', title: 'Spanning tree topology changed', detail: `${Math.round(hl.stp.sinceChangeSec / 60)} min ago, ${plural(hl.stp.topChanges, 'change')} in total.`, target: { tab: 'network' } });
  }
  if (o.wlan) for (const rd of o.wlan.radios) if (!rd.up) out.push({ level: 'warn', title: `Radio ${rd.band || rd.idx} is down`, detail: o.wlan.aps.find(a => a.mac === rd.apMac)?.name || rd.apMac, target: { tab: 'wifi' } });
  return out.sort((a, b) => (a.level === b.level ? 0 : a.level === 'bad' ? -1 : 1));
}

/** One summary per other tab, so the Overview says what each holds without opening it. */
export function cards(o: OvInput, all: Issue[]): Card[] {
  const out: Card[] = [];
  const count = (t: Target['tab']): { level: Level; n: number } => { const l = all.filter(i => i.target?.tab === t); return { level: l.some(i => i.level === 'bad') ? 'bad' : l.length ? 'warn' : 'ok', n: l.length }; };
  const real = o.dev.interfaces.filter(i => !i.isVlanIf);
  const up = real.filter(i => i.oper === 'up').length;
  const ie = count('interfaces');
  const ifIssues = all.filter(i => i.target?.tab === 'interfaces' && i.target.ifIndex !== undefined).length;
  out.push({ tab: 'interfaces', label: 'Interfaces', level: ifIssues ? ie.level : 'ok', headline: ifIssues ? `${plural(ifIssues, 'issue')}` : 'No issues', lines: [`${up} of ${real.length} up`, `${plural(real.filter(i => i.flagged).length, 'over its limits', 'over their limits')}`] });
  {
    const hl = o.health?.health; const sensors = hl?.sensors.filter(s => s.kind !== 'optic') ?? [];
    const c = count('hardware');
    out.push({ tab: 'hardware', label: 'Hardware', level: c.level, headline: c.n ? plural(c.n, 'issue') : 'All within limits', lines: [sensors.length ? plural(sensors.length, 'sensor') : '', hl?.poe.length ? 'PoE monitored' : ''].filter(Boolean) });
  }
  const hl = o.health?.health; const c = count('network');
  const lines = [o.neighbours !== null ? plural(o.neighbours, 'neighbour') : '', o.arp !== null ? plural(o.arp, 'ARP entry', 'ARP entries') : '', hl?.ospf.length ? plural(hl.ospf.length, 'OSPF neighbour') : '', hl?.bgp.length ? plural(hl.bgp.length, 'BGP peer') : '', hl?.eigrp?.length ? plural(hl.eigrp.length, 'EIGRP neighbour') : '', hl?.bfd?.length ? plural(hl.bfd.length, 'BFD session') : '', hl?.stp ? 'spanning tree' : ''].filter(Boolean);
  out.push({ tab: 'network', label: 'Neighbours and routing', level: c.level, headline: c.n ? plural(c.n, 'issue') : 'No issues', lines });
  if (o.dev.hasWlan && o.wlan) { const w = count('wifi'); out.push({ tab: 'wifi', label: 'Wi-Fi', level: w.level, headline: w.n ? plural(w.n, 'issue') : 'No issues', lines: [plural(o.wlan.aps.length, 'access point'), plural(o.wlan.clients.length, 'client')] }); }
  return out;
}

