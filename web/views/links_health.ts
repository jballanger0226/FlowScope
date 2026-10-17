/** Hardware and protocol health on the Network health page: sensors and optics, PoE, spanning tree, OSPF and BGP, and the link quality of one interface. */
import { h, type VNode } from '../vdom.js';
import { btn, chip, note, stat, status as statusEl } from '../components.js';
import { bps, dayClock, dur, num } from '../util.js';

export type Level = 'ok' | 'warn' | 'bad' | 'off';
export interface Sensor { id: string; kind: string; name: string; value: number | null; unit: string; state: Level; stateText: string; optic?: 'tx' | 'rx' | 'temp' | 'other'; ifIndex?: number }
export interface Poe { group: number; budgetW: number | null; usedW: number | null; usedPct: number | null; allocW?: number | null; remainingW?: number | null; allocPct?: number | null; status: string; portsDelivering: number; portsFault: number; portsTotal: number }
export interface Stp { rootId: string; isRoot: boolean; rootPort: number; rootCost: number; topChanges: number | null; sinceChangeSec: number | null; blockingPorts: number; ports: number }
export interface OspfNeighbor { id: string; address: string; state: string; level: Level }
export interface BgpFamily { name: string; accepted: number | null; denied: number | null; advertised: number | null }
export interface BgpPeer { families?: BgpFamily[]; address: string; as: number | null; state: string; level: Level; admin: string; upSec: number | null; updatesIn: number | null; updatesOut: number | null }
export interface EigrpPeer { as: number; address: string; ifIndex: number; holdSec: number | null; upText: string; srttMs: number | null; retrans: number | null; retries: number | null; level: Level }
export interface BfdSession { id: number; address: string; local?: string; peerKnown?: boolean; ifIndex: number | null; state: string; level: Level; upSec: number | null; upCount: number | null; diag: string | null; detectMs: number | null }
export interface Health { readAt: number; sensors: Sensor[]; poe: Poe[]; stp: Stp | null; ospf: OspfNeighbor[]; bgp: BgpPeer[]; bgpLocalAs: number | null; eigrp?: EigrpPeer[]; bfd?: BfdSession[] }
export interface IfExtra {
  ifIndex: number; duplex: 'full' | 'half' | 'unknown' | null; admin: number | null; totals: Record<string, number | undefined>; delta: Record<string, number | undefined> | null; dtSec: number | null; readAt: number;
  warnings: { level: Level; text: string }[];
}
export interface ProcessCpu { name: string; pid: number; five: number; one: number; fiveMin: number }
export interface Processes { readAt: number; top: ProcessCpu[]; snmpFive: number | null; snmpOne: number | null }
export interface StackMember { index: number; number: number | null; role: string; state: string; level: Level; mac: string }
export interface StackPort { ifIndex: number; status: string; level: Level; neighbor: number | null; name?: string; neighborName?: string }
export interface SvlBundle { switch: number; bundle: number; status: string; level: Level }
export interface Stack { readAt: number; members: StackMember[]; ports: StackPort[]; bundles?: SvlBundle[]; svl?: boolean; problems: string[] }
export interface Redundancy { readAt: number; unitState: string; peerState: string; configured: string; operating: string; lastSwitchover: string | null; sinceFailoverSec: number | null; level: Level; problems: string[] }
export interface NtpSource { id: number; address: string; stratum: number | null; offsetMs: number | null; jitterMs: number | null; delayMs: number | null; reach: number | null; refId: string; active: boolean; level: Level }
export interface Ntp { readAt: number; mode: string; synced: boolean; stratum: number | null; offsetMs: number | null; dispersionMs: number | null; sources: NtpSource[]; level: Level; problems: string[] }
export interface LagMember { ifIndex: number; bundled: boolean; collecting: boolean; distributing: boolean; level: Level; why: string }
export interface Channel { ifIndex: number; key: number; partnerMac: string; members: LagMember[]; level: Level; problems: string[] }
export interface DaiVlan { vlan: number; forwarded: number; dropped: number; dhcpDenied: number; aclDenied: number; srcMac: number; dstMac: number; ip: number; invalid: number; droppedNow: number | null; why: string }
export interface Dai { readAt: number; vlans: DaiVlan[]; dtSec: number | null }
export interface NbarProto { name: string; inBps: number | null; outBps: number | null; inBytes: number; outBytes: number }
export interface Nbar { readAt: number; interfaces: Record<number, NbarProto[]> }
export interface AaaServer { key: string; address: string; kind: 'radius' | 'tacacs'; port: number; priority: number; up: boolean; stateSec: number; deadCount: number; authReq: number; authTimeouts: number; authFail: number; authMs: number; acctReq: number; acctTimeouts: number; newReq: number | null; newTimeouts: number | null; newFail: number | null; newDead: number | null; level: 'ok' | 'warn' | 'bad'; problems: string[] }
export interface Aaa { readAt: number; dtSec: number; servers: AaaServer[] }
export interface ConfigEvent { at: number; what: string; user: string; via: string }
export interface ConfigState { readAt: number; changedAt: number | null; savedAt: number | null; unsaved: boolean; unsavedSec: number; events: ConfigEvent[] }
/** Cisco-only reads, each null when the device does not publish the table */
export interface Extras { procs: Processes | null; stack: Stack | null; dai: Dai | null; nbar: Nbar | null; aaa?: Aaa | null; rf?: Redundancy | null; ntp?: Ntp | null; lag?: Channel[] | null; config?: ConfigState | null; lisp?: { readAt: number; level: 'ok' | 'warn' | 'bad'; problems: string[]; instances: number; cache: number; active: number; registered: number } | null }
/** A configuration that has differed from the saved one for this long is worth a mention; a change a minute ago is just a change being made. */
const UNSAVED_WARN_MS = 3600_000;
export const unsavedFor = (c: ConfigState | null | undefined, now = Date.now()): number => (c?.unsaved && c.changedAt ? now - c.changedAt : 0);
export interface HealthRes { health: Health | null; ifExtra: IfExtra[]; extras?: Extras }
const NO_HEALTH: Health = { readAt: 0, sensors: [], poe: [], stp: null, ospf: [], bgp: [], bgpLocalAs: null };

const colour = (l: Level): string | undefined => (l === 'bad' ? 'color:var(--bad)' : l === 'warn' ? 'color:var(--warn)' : undefined);
const worst = (ls: Level[]): Level => (ls.includes('bad') ? 'bad' : ls.includes('warn') ? 'warn' : ls.length && ls.every(l => l === 'off') ? 'off' : 'ok');
const reading = (s: Sensor): string => (s.value === null ? s.stateText : `${Math.abs(s.value) < 100 && s.unit !== 'RPM' ? (Math.round(s.value * 10) / 10).toString() : Math.round(s.value).toString()}${s.unit ? (s.unit === '°C' ? ' °C' : ' ' + s.unit) : ''}`);
const SENSOR_GROUPS: [string, string][] = [['temperature', 'Temperatures'], ['fan', 'Fans'], ['power', 'Power supplies'], ['voltage', 'Voltages'], ['current', 'Currents'], ['humidity', 'Humidity'], ['status', 'Status'], ['other', 'Other']];

function sensorTile(s: Sensor): VNode {
  const sub = s.state === 'ok' ? (s.value === null ? undefined : undefined) : s.stateText;
  return h('div', { key: s.id, class: 'stat', style: 'min-width:0;padding:10px 14px' },
    h('div', { class: 'slabel', title: s.name, style: 'overflow:hidden;text-overflow:ellipsis;white-space:nowrap' }, s.name),
    h('div', { class: 'svalue', style: `font-size:17px;${colour(s.state) ?? ''}` }, s.value === null ? statusEl(s.state === 'off' ? 'off' : s.state, s.stateText) : reading(s)),
    sub && s.value !== null ? h('div', { class: 'ssub', style: colour(s.state) }, sub) : null);
}

/** The optic of one interface: its transmit and receive light levels and module temperature, and the worst state among them. */
export interface OpticInfo { tx?: Sensor; rx?: Sensor; temp?: Sensor; level: Level }
export function opticMap(sensors: Sensor[]): Map<number, OpticInfo> {
  const by = new Map<number, Sensor[]>();
  for (const s of sensors) if (s.kind === 'optic' && s.ifIndex !== undefined) (by.get(s.ifIndex) ?? by.set(s.ifIndex, []).get(s.ifIndex)!).push(s);
  const m = new Map<number, OpticInfo>();
  for (const [ix, list] of by) m.set(ix, { tx: list.find(x => x.optic === 'tx'), rx: list.find(x => x.optic === 'rx'), temp: list.find(x => x.optic === 'temp'), level: worst(list.map(x => x.state)) });
  return m;
}
/** The light levels for the interface table: "Rx -4.7 · Tx -1.9 dBm", coloured by the worst state. */
export function opticCell(o: OpticInfo | undefined): VNode {
  if (!o || (!o.tx && !o.rx)) return h('span', { class: 'dim' }, '—');
  const v = (s: Sensor | undefined) => (s && s.value !== null ? String(Math.round(s.value * 10) / 10) : '—');
  return h('span', { class: 'mono', style: `font-size:12px;${colour(o.level) ?? ''}`, title: `Receive ${v(o.rx)} dBm, transmit ${v(o.tx)} dBm${o.level === 'ok' ? '' : '. A reading is outside its limits.'}` }, `${v(o.rx)} / ${v(o.tx)}`);
}

const STP_TEXT = (s: Stp): string => (s.isRoot ? 'This device is the root bridge' : `Root bridge ${s.rootId}`);

/** What deserves a second look, as short chips, so a quick glance tells whether to open the details. */
export function attention(hl: Health | null): { level: Level; text: string }[] {
  if (!hl) return [];
  const out: { level: Level; text: string }[] = [];
  const bad = hl.sensors.filter(s => s.state === 'bad' && s.kind !== 'optic'), warn = hl.sensors.filter(s => s.state === 'warn' && s.kind !== 'optic');
  for (const s of bad) out.push({ level: 'bad', text: `${s.name}: ${s.stateText}` });
  for (const s of warn) out.push({ level: 'warn', text: `${s.name}: ${s.stateText}` });
  const opt = hl.sensors.filter(s => s.kind === 'optic' && (s.state === 'bad' || s.state === 'warn'));
  if (opt.length) out.push({ level: opt.some(s => s.state === 'bad') ? 'bad' : 'warn', text: `${opt.length} optic reading${opt.length === 1 ? '' : 's'} outside limits` });
  for (const p of hl.poe) if (p.status === 'faulty' || p.portsFault) out.push({ level: 'bad', text: `PoE: ${p.status === 'faulty' ? 'power source faulty' : p.portsFault + ' port' + (p.portsFault === 1 ? '' : 's') + ' in fault'}` });
  for (const p of hl.poe) { const l = poeLevel(p); if (l !== 'ok' && l !== 'off' && p.status !== 'faulty') out.push({ level: l, text: p.allocPct != null && p.allocPct >= 90 ? `PoE ${p.allocPct}% reserved` : `PoE budget ${p.usedPct}% used` }); }
  const nb = hl.ospf.filter(n => n.level !== 'ok'); if (nb.length) out.push({ level: nb.some(n => n.level === 'bad') ? 'bad' : 'warn', text: `${nb.length} OSPF neighbour${nb.length === 1 ? '' : 's'} not full` });
  const bp = hl.bgp.filter(p => p.level === 'bad' || p.level === 'warn'); if (bp.length) out.push({ level: bp.some(p => p.level === 'bad') ? 'bad' : 'warn', text: `${bp.length} BGP peer${bp.length === 1 ? '' : 's'} not established` });
  const ep = (hl.eigrp ?? []).filter(p => p.level !== 'ok'); if (ep.length) out.push({ level: 'warn', text: `${ep.length} EIGRP neighbour${ep.length === 1 ? '' : 's'} retransmitting` });
  const bf = (hl.bfd ?? []).filter(b => b.level === 'bad' || b.level === 'warn'); if (bf.length) out.push({ level: bf.some(b => b.level === 'bad') ? 'bad' : 'warn', text: `${bf.length} BFD session${bf.length === 1 ? '' : 's'} not up` });
  if (hl.stp && hl.stp.sinceChangeSec !== null && hl.stp.sinceChangeSec < 600 && hl.stp.topChanges) out.push({ level: 'warn', text: `Spanning tree changed ${dur(hl.stp.sinceChangeSec * 1000)} ago` });
  return out;
}

/** What the Overview shows of the hardware and protocol reads: whether anything is outside its limits, in one row of chips. */
export function extrasAttention(ex: Extras | undefined): { level: Level; text: string }[] {
  const out: { level: Level; text: string }[] = [];
  if (!ex) return out;
  if (ex.stack?.problems.length) out.push({ level: 'warn', text: ex.stack.problems.length === 1 ? 'Stack problem' : `${ex.stack.problems.length} stack problems` });
  if (ex.rf && ex.rf.level !== 'ok') out.push({ level: ex.rf.level, text: ex.rf.problems.length === 1 ? 'Supervisor redundancy problem' : `${ex.rf.problems.length} redundancy problems` });
  if (ex.ntp && ex.ntp.level !== 'ok') out.push({ level: ex.ntp.level === 'bad' ? 'warn' : ex.ntp.level, text: ex.ntp.synced ? 'Time source problem' : 'Clock not synchronised' });
  const badCh = (ex.lag ?? []).filter(c => c.level !== 'ok'); if (badCh.length) out.push({ level: badCh.some(c => c.level === 'bad') ? 'bad' : 'warn', text: `${badCh.length} port-channel${badCh.length === 1 ? '' : 's'} with a problem` });
  const dai = (ex.dai?.vlans ?? []).filter(v => (v.droppedNow ?? 0) > 0); if (dai.length) out.push({ level: 'warn', text: `ARP packets dropped on ${dai.length} VLAN${dai.length === 1 ? '' : 's'}` });
  if ((ex.procs?.snmpOne ?? 0) >= 10) out.push({ level: 'warn', text: `SNMP engine using ${ex.procs!.snmpOne}% of the CPU` });
  for (const a of ex.aaa?.servers ?? []) if (a.level !== 'ok') out.push({ level: a.level, text: `${a.kind === 'tacacs' ? 'TACACS+' : 'RADIUS'} ${a.address}: ${a.up ? 'slow or dropping requests' : 'dead'}` });
  if (unsavedFor(ex.config) >= UNSAVED_WARN_MS) out.push({ level: 'warn', text: 'Configuration not saved' });
  if (ex.lisp && ex.lisp.level !== 'ok') out.push({ level: ex.lisp.level, text: ex.lisp.problems.length === 1 ? 'LISP fabric problem' : `${ex.lisp.problems.length} LISP fabric problems` });
  return out;
}

export function healthSummary(data: HealthRes | null): VNode | null {
  const hl0 = data?.health ?? null;
  const hl = hl0 ?? (data?.extras && (data.extras.stack || data.extras.rf || data.extras.ntp || data.extras.lag?.length || data.extras.procs || data.extras.dai?.vlans.length || data.extras.aaa?.servers.length || data.extras.config) ? NO_HEALTH : null);
  if (!hl || (!hl.sensors.length && !hl.poe.length && !hl.stp && !hl.ospf.length && !hl.bgp.length && !hl.eigrp?.length && !hl.bfd?.length && !data?.extras?.stack && !data?.extras?.rf && !data?.extras?.ntp && !data?.extras?.lag?.length && !data?.extras?.procs && !data?.extras?.aaa?.servers.length && !data?.extras?.config)) return null;
  const att = [...attention(hl), ...extrasAttention(data?.extras)];
  const parts: string[] = [];
  const others = hl.sensors.filter(s => s.kind !== 'optic'), optics = hl.sensors.filter(s => s.kind === 'optic');
  if (others.length) parts.push(`${others.length} sensor${others.length === 1 ? '' : 's'}`);
  if (optics.length) { const n = new Set(optics.map(s => s.ifIndex ?? s.name)).size; parts.push(`${n} optic${n === 1 ? '' : 's'}`); }
  if (hl.poe.length) parts.push('PoE');
  if (hl.stp) parts.push('spanning tree');
  if (hl.ospf.length) parts.push(`${hl.ospf.length} OSPF neighbour${hl.ospf.length === 1 ? '' : 's'}`);
  if (hl.bgp.length) parts.push(`${hl.bgp.length} BGP peer${hl.bgp.length === 1 ? '' : 's'}`);
  if (hl.eigrp?.length) parts.push(`${hl.eigrp.length} EIGRP neighbour${hl.eigrp.length === 1 ? '' : 's'}`);
  if (hl.bfd?.length) parts.push(`${hl.bfd.length} BFD session${hl.bfd.length === 1 ? '' : 's'}`);
  return h('div', { class: 'col', style: 'gap:6px' },
    h('span', { class: 'muted', style: 'font-size:12px' }, `Hardware and protocols: ${parts.join(', ')}. Read every few minutes.`),
    att.length ? h('div', { class: 'row', style: 'gap:6px;flex-wrap:wrap' }, att.slice(0, 8).map(a => chip(a.text, a.level === 'bad' ? 'bad' : 'warn')), att.length > 8 ? chip(`+${att.length - 8} more`, 'default') : null)
      : h('div', { class: 'row', style: 'gap:6px' }, chip('Nothing outside its limits', 'ok')));
}
export const hasHardware = (data: HealthRes | null): boolean => (!!data?.health && (data.health.sensors.some(s => s.kind !== 'optic') || data.health.poe.length > 0)) || !!data?.extras?.procs || !!data?.extras?.stack || !!data?.extras?.rf || !!data?.extras?.ntp || !!data?.extras?.lag?.length || !!data?.extras?.aaa?.servers.length || !!data?.extras?.config;
export const hasOptics = (data: HealthRes | null): boolean => !!data?.health && data.health.sensors.some(s => s.kind === 'optic' && s.ifIndex !== undefined);
export const hasProtocols = (data: HealthRes | null): boolean => !!data?.extras?.dai?.vlans.length || !!data?.health && (!!data.health.stp || data.health.ospf.length > 0 || data.health.bgp.length > 0 || !!data.health.eigrp?.length || !!data.health.bfd?.length);

/** Sensors and PoE: the physical state of the device. The light levels of optics are with their interfaces. */
export function hardwarePanel(o: { data: HealthRes | null; ifName?: (ifIndex: number) => string }): VNode | null {
  const hl = o.data?.health ?? NO_HEALTH;
  if (!hasHardware(o.data)) return null;
  const others = hl.sensors.filter(s => s.kind !== 'optic');
  const sections: (VNode | null)[] = [];
  for (const [kind, title] of SENSOR_GROUPS) {
    const list = others.filter(s => (SENSOR_GROUPS.some(g => g[0] === s.kind) ? s.kind : 'other') === kind);
    if (!list.length) continue;
    sections.push(h('div', { key: kind, class: 'col', style: 'gap:6px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, title),
      h('div', { style: 'display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:8px' }, list.map(sensorTile))));
  }
  if (hl.poe.length) sections.push(h('div', { key: 'poe', class: 'col', style: 'gap:6px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, 'Power over Ethernet'),
    h('div', { class: 'row', style: 'gap:10px;align-items:stretch;flex-wrap:wrap' }, hl.poe.map(p => poeTile(p, hl.poe.length > 1))),
    hl.poe.some(p => p.allocW != null) ? h('span', { class: 'dim', style: 'font-size:12px' }, 'Drawn is what the devices use now. Reserved is the power the switch has set aside for them (their class or negotiated maximum): a new device is refused when the reserved power reaches the budget, even if little is being drawn.') : null));
  const ex = o.data?.extras;
  if (ex?.stack) sections.push(stackSection(ex.stack));
  if (ex?.rf) sections.push(redundancySection(ex.rf));
  if (ex?.lag?.length) sections.push(lagSection(ex.lag, o.ifName));
  if (ex?.ntp) sections.push(ntpSection(ex.ntp));
  if (ex?.aaa?.servers.length) sections.push(aaaSection(ex.aaa));
  if (ex?.config) sections.push(configSection(ex.config));
  if (ex?.procs) sections.push(processSection(ex.procs));
  return h('div', { class: 'col', style: 'gap:12px' }, sections);
}

/** PoE of one power source: what is drawn now, what is reserved, and the budget, in one tile with a two-layer bar. */
export const poeLevel = (p: Poe): Level => (p.status === 'faulty' ? 'bad' : (p.allocPct ?? p.usedPct ?? 0) >= 100 ? 'bad' : (p.allocPct ?? 0) >= 90 || (p.usedPct ?? 0) >= 90 ? 'warn' : 'ok');
function poeTile(p: Poe, many: boolean): VNode {
  const b = p.budgetW ?? 0, pc = (w: number | null | undefined) => (b > 0 && w != null ? Math.min(100, (w / b) * 100) : 0);
  const lvl = poeLevel(p), hasAlloc = p.allocW != null;
  const ports = p.portsTotal ? `${p.portsDelivering} of ${p.portsTotal} ports delivering${p.portsFault ? `, ${p.portsFault} in fault` : ''}` : '';
  return h('div', { key: p.group, class: 'stat', style: 'min-width:240px' },
    h('div', { class: 'slabel' }, many ? `PoE source ${p.group}` : 'PoE power'),
    h('div', { class: 'svalue' }, h('span', { style: p.status === 'faulty' ? colour('bad') : undefined }, p.usedW !== null ? `${num(p.usedW)} W` : p.status), p.usedW !== null ? h('span', { class: 'dim', style: 'font-size:12px;font-weight:400' }, ' drawn') : null),
    b > 0 ? h('div', { style: 'position:relative;height:8px;border-radius:4px;background:var(--line);overflow:hidden;margin:6px 0 4px', role: 'img', 'aria-label': `${num(p.usedW ?? 0)} W drawn${hasAlloc ? `, ${num(p.allocW!)} W reserved` : ''} of ${num(b)} W` },
      hasAlloc ? h('span', { style: `position:absolute;inset:0 auto 0 0;width:${pc(p.allocW)}%;background:var(--warn);opacity:.45` }) : null,
      h('span', { style: `position:absolute;inset:0 auto 0 0;width:${pc(p.usedW)}%;background:var(--${lvl === 'ok' || hasAlloc ? 'accent' : lvl})` })) : null,
    h('div', { class: 'ssub' }, hasAlloc && b > 0 ? h('span', { style: colour(lvl) }, `${num(p.allocW!)} W reserved of ${num(b)} W (${p.allocPct}%)`) : b > 0 ? `${p.usedPct}% of the ${num(b)} W budget` : '', ports ? h('div', null, ports) : null));
}

const w1 = (n: number): string => String(Math.round(n * 10) / 10);
/** One port's PoE as a box, like the whole-switch one: what the device draws, against what the switch has reserved for it. */
export function poePortBox(x: { allocW: number; drawnW: number; maxW: number | null; detected: boolean; askedW?: number | null; grantedW?: number | null }, denied: string | null = null): VNode {
  // both layers are drawn against the port limit, as the whole-switch tile draws them against the budget: reserved behind, drawn in front
  const scale = x.maxW && x.maxW > 0 ? x.maxW : Math.max(x.allocW, x.drawnW, 1);
  const pc = (w: number) => Math.min(100, (w / scale) * 100);
  const bar = x.allocW > 0 || x.drawnW > 0;
  return h('div', { class: 'col', style: 'gap:6px' }, h('div', { class: 'row', style: 'gap:8px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, 'Power over Ethernet'), h('span', { class: 'dim', style: 'font-size:11.5px' }, 'Drawn is what the device uses now; reserved is what the switch has set aside for it')),
    denied ? note(denied, 'bad') : null,
    h('div', { class: 'stat', style: 'min-width:240px;align-self:flex-start' },
      h('div', { class: 'slabel' }, 'PoE power'),
      h('div', { class: 'svalue' }, `${w1(x.drawnW)} W`, h('span', { class: 'dim', style: 'font-size:12px;font-weight:400' }, ' drawn')),
      bar ? h('div', { style: 'position:relative;height:8px;border-radius:4px;background:var(--line);overflow:hidden;margin:6px 0 4px', role: 'img', 'aria-label': `${w1(x.drawnW)} W drawn, ${w1(x.allocW)} W reserved${x.maxW ? ` of a ${w1(x.maxW)} W port limit` : ''}` },
        h('span', { style: `position:absolute;inset:0 auto 0 0;width:${pc(x.allocW)}%;background:var(--warn);opacity:.45` }),
        h('span', { style: `position:absolute;inset:0 auto 0 0;width:${pc(x.drawnW)}%;background:var(--accent)` })) : null,
      h('div', { class: 'ssub' }, `${w1(x.allocW)} W reserved${x.maxW ? ` of ${w1(x.maxW)} W` : ''}`),
      x.askedW != null ? h('div', { class: 'ssub', style: x.grantedW != null && x.grantedW < x.askedW ? 'color:var(--warn)' : undefined, title: 'LLDP-MED power negotiation: what the device asked the switch for, and what the switch gave it' }, `Asked for ${w1(x.askedW)} W, granted ${x.grantedW == null ? '—' : w1(x.grantedW) + ' W'}${x.grantedW != null && x.grantedW < x.askedW ? ': the device got less than it wanted' : ''}`) : null));
}

const sub = (t: string, hint?: string) => h('div', { class: 'row', style: 'gap:8px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, t), hint ? h('span', { class: 'dim', style: 'font-size:11.5px' }, hint) : null);

/** Stack members and stack ports (Catalyst StackWise): a broken ring link is the thing to see. */
function redundancySection(r: Redundancy): VNode {
  return h('div', { key: 'rf', class: 'col', style: 'gap:6px' }, sub('Supervisor redundancy', `This unit is ${r.unitState}; the peer is ${r.peerState}`),
    ...r.problems.map(t => note(t, r.level === 'bad' ? 'bad' : 'warn', true)),
    h('div', { class: 'row', style: 'gap:16px;flex-wrap:wrap' }, stat('Configured', r.configured), stat('Running', r.operating), r.lastSwitchover ? stat('Last switchover', r.lastSwitchover) : null));
}

/** Port-channels: one row each, with the members that are not carrying traffic. */
function lagSection(chs: Channel[], ifName?: (i: number) => string): VNode {
  const nm = (i: number) => ifName?.(i) || `interface ${i}`;
  const bad = chs.filter(c => c.level !== 'ok');
  return h('div', { class: 'col', style: 'gap:6px' }, sub('Port-channels (LACP)', `${chs.length} channel${chs.length === 1 ? '' : 's'}, ${bad.length ? bad.length + ' with a problem' : 'all members working'}`),
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(120px,1fr) 80px minmax(220px,2fr) 100px;--w:620px' },
      h('div', { class: 'tr head' }, ...['Channel', 'Members', 'Member ports', 'State'].map(t => h('span', null, t))),
      [...bad, ...chs.filter(c => c.level === 'ok')].map(c => h('div', { key: c.ifIndex, class: 'tr' }, h('span', { class: 'mono', style: 'font-size:12px' }, nm(c.ifIndex)), h('span', { class: 'mono' }, `${c.members.filter(m => m.level === 'ok').length} of ${c.members.length}`),
        h('span', { class: 'mono', style: 'font-size:12px;overflow-wrap:anywhere', title: c.members.filter(m => m.why).map(m => `${nm(m.ifIndex)}: ${m.why}`).join('\n') }, c.members.map(m => nm(m.ifIndex) + (m.level === 'ok' ? '' : ' ⚠')).join(', ') || '—'),
        statusEl(c.level, c.level === 'ok' ? 'working' : c.problems[0] ?? 'problem'))))));
}

/** Time sources: a clock that drifts breaks logs, certificates and Kerberos long before anyone looks at NTP. */
function ntpSection(n: Ntp): VNode {
  return h('div', { class: 'col', style: 'gap:6px' }, sub('Time (NTP)', n.synced ? `Synchronised${n.stratum !== null ? ` at stratum ${n.stratum}` : ''}${n.offsetMs !== null ? `, ${Math.round(n.offsetMs * 10) / 10} ms off` : ''}` : 'Not synchronised'),
    ...n.problems.map(t => note(t, n.level === 'bad' ? 'bad' : 'warn', true)),
    n.sources.length ? h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(140px,1fr) 80px 100px 100px 80px 100px;--w:620px' },
      h('div', { class: 'tr head' }, ...['Source', 'Stratum', 'Offset', 'Delay', 'Reach', 'State'].map(t => h('span', null, t))),
      n.sources.map(x => h('div', { key: x.id, class: 'tr' }, h('span', { class: 'mono', style: 'font-size:12px' }, x.address + (x.active ? ' ◀' : '')), h('span', { class: 'mono' }, x.stratum === null ? '—' : String(x.stratum)),
        h('span', { class: 'mono', style: 'font-size:12px' }, x.offsetMs === null ? '—' : `${Math.round(x.offsetMs * 10) / 10} ms`), h('span', { class: 'mono', style: 'font-size:12px' }, x.delayMs === null ? '—' : `${Math.round(x.delayMs * 10) / 10} ms`),
        h('span', { class: 'mono', style: 'font-size:12px' }, x.reach === null ? '—' : x.reach.toString(8)), statusEl(x.level, x.level === 'ok' ? (x.active ? 'in use' : 'ok') : 'no answer'))))) : null);
}

function stackSection(st: Stack): VNode {
  return h('div', { key: 'stack', class: 'col', style: 'gap:6px' }, sub('Stack', `${st.members.length} member${st.members.length === 1 ? '' : 's'}, ${st.ports.filter(p => p.level === 'ok').length} of ${st.ports.length} stack ports up`),
    ...st.problems.map(t => note(t, 'warn', true)),
    st.svl ? h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:80px minmax(160px,1fr) minmax(160px,1fr) 90px;--w:520px' },
      h('div', { class: 'tr head' }, ...['Chassis', 'Stack link port', 'Port at the other end', 'State'].map(t => h('span', null, t))),
      st.ports.map(p => h('div', { key: `${p.neighbor}/${p.ifIndex}`, class: 'tr' }, h('span', { class: 'mono' }, String(st.members.find(m => m.index === p.neighbor)?.number ?? '—')), h('span', { class: 'mono', style: 'font-size:12px' }, p.name || `interface ${p.ifIndex}`), h('span', { class: 'mono', style: 'font-size:12px' }, p.neighborName || '—'), statusEl(p.level, p.status))))) : null,
    st.svl ? null : h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:80px 110px minmax(140px,1fr) 150px;--w:520px' },
      h('div', { class: 'tr head' }, ...['Member', 'Role', 'State', 'MAC address'].map(t => h('span', null, t))),
      st.members.map(m => h('div', { key: m.index, class: 'tr' }, h('span', { class: 'mono' }, String(m.number ?? m.index)), h('span', null, m.role), statusEl(m.level, m.state), h('span', { class: 'mono', style: 'font-size:12px' }, m.mac || '—'))))));
}

/** RADIUS and TACACS+ servers: when one is slow or dead, 802.1X and MAB clients fail and it looks like a network fault. */
function aaaSection(a: Aaa): VNode {
  const since = a.dtSec ? (a.dtSec < 120 ? Math.round(a.dtSec) + ' s' : Math.round(a.dtSec / 60) + ' min') : '';
  const pct = (x: number, of: number) => (of >= 20 ? ` (${((x / of) * 100).toFixed(1)}%)` : '');
  return h('div', { key: 'aaa', class: 'col', style: 'gap:6px' }, sub('Authentication servers', 'RADIUS and TACACS+ as this device sees them; counts are since the device started, "+" is the change since the last read'),
    ...a.servers.flatMap(sv => sv.problems.map(t => note(t, sv.level === 'bad' ? 'bad' : 'warn', true))),
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(150px,1fr) 90px 110px 130px 130px 100px 110px;--w:820px' },
      h('div', { class: 'tr head' }, ...['Server', 'Type', 'State', 'Requests', 'Timeouts', 'Failures', 'Last answer'].map(t => h('span', null, t))),
      a.servers.map(sv => { const req = sv.authReq + sv.acctReq, tmo = sv.authTimeouts + sv.acctTimeouts; return h('div', { key: sv.key, class: 'tr' },
        h('span', { class: 'mono', style: 'font-size:12px' }, `${sv.address}:${sv.port}`), h('span', null, sv.kind === 'tacacs' ? 'TACACS+' : 'RADIUS'),
        statusEl(sv.up ? (sv.level === 'ok' ? 'ok' : 'warn') : 'bad', sv.up ? `up ${sv.stateSec < 3600 ? Math.round(sv.stateSec / 60) + ' min' : dur(sv.stateSec * 1000)}` : 'dead'),
        h('span', { class: 'mono', style: 'font-size:12px', title: since && sv.newReq !== null ? `${num(sv.newReq)} in the last ${since}` : undefined }, num(req), sv.newReq ? ` +${num(sv.newReq)}` : ''),
        h('span', { class: 'mono', style: `font-size:12px;${(sv.newTimeouts ?? 0) > 0 ? 'color:var(--warn)' : ''}` }, num(tmo), pct(tmo, req), sv.newTimeouts ? ` +${num(sv.newTimeouts)}` : ''),
        h('span', { class: 'mono', style: 'font-size:12px' }, num(sv.authFail)),
        h('span', { class: 'mono', style: `font-size:12px;${sv.authMs >= 750 ? 'color:var(--warn)' : ''}` }, sv.authReq ? `${sv.authMs} ms` : '—')); }))),
    a.servers.some(sv => sv.deadCount) ? h('span', { class: 'dim', style: 'font-size:12px' }, a.servers.filter(sv => sv.deadCount).map(sv => `${sv.address} was marked dead ${sv.deadCount} time${sv.deadCount === 1 ? '' : 's'}`).join(' · ') + ' since the device started.') : null);
}

/** Whether the running configuration is saved, and who changed it last. */
function configSection(c: ConfigState): VNode {
  const age = unsavedFor(c);
  const when = (t: number | null) => (t ? dayClock(t) : 'not since it started');
  return h('div', { key: 'config', class: 'col', style: 'gap:6px' }, sub('Configuration', 'running against startup, from the change history of the device'),
    c.unsaved ? note(age >= UNSAVED_WARN_MS ? `The running configuration changed ${dur(age)} ago and has not been saved to startup. A reload now would lose the change.` : `The running configuration changed ${age < 90_000 ? 'moments' : dur(age)} ago and is not saved to startup yet. This is normal while a change is being made.`, age >= UNSAVED_WARN_MS ? 'warn' : 'info', true) : null,
    h('div', { class: 'row', style: 'gap:10px;align-items:stretch;flex-wrap:wrap' },
      stat('Last changed', when(c.changedAt)), stat('Last saved', when(c.savedAt)), stat('Saved', h('span', { style: colour(c.unsaved ? (age >= UNSAVED_WARN_MS ? 'warn' : 'ok') : 'ok') }, c.unsaved ? 'not yet' : 'yes'))),
    c.events.length ? h('span', { class: 'dim', style: 'font-size:12px' }, 'Recent: ' + c.events.map(e => `${e.what} ${dayClock(e.at)}${e.user ? ' by ' + e.user : ''}${e.via ? ' (' + e.via + ')' : ''}`).join(' · ')) : null);
}

/** The busiest processes. The SNMP engine is called out because polling is part of what it measures. */
function processSection(p: Processes): VNode {
  const snmpHigh = (p.snmpOne ?? 0) >= 10;
  return h('div', { key: 'procs', class: 'col', style: 'gap:6px' }, sub('Busiest processes', 'share of one CPU over 5 seconds, 1 minute and 5 minutes'),
    snmpHigh ? note(`The SNMP engine used ${p.snmpOne}% of the CPU over the last minute. Polling this device is part of its load: lengthen the poll interval or poll fewer tables if that is a problem.`, 'warn', true) : null,
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(180px,1fr) 80px 80px 80px;--w:420px' },
      h('div', { class: 'tr head' }, ...['Process', '5 sec', '1 min', '5 min'].map(t => h('span', null, t))),
      p.top.map(x => h('div', { key: x.name, class: 'tr' }, h('span', { class: 'mono', style: 'font-size:12px' }, x.name), ...[x.five, x.one, x.fiveMin].map(v => h('span', { class: 'mono', style: 'font-size:12px' }, `${v}%`)))))));
}

/** Dynamic ARP inspection: the VLANs where the switch is dropping ARP packets, and why. */
function daiSection(d: Dai): VNode {
  const since = d.dtSec ? (d.dtSec < 120 ? d.dtSec + ' s' : Math.round(d.dtSec / 60) + ' min') : '';
  return h('div', { key: 'dai', class: 'col', style: 'gap:6px' }, sub('ARP inspection', 'VLANs where ARP packets were dropped'),
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:70px 100px 130px minmax(220px,1fr);--w:640px' },
      h('div', { class: 'tr head' }, ...['VLAN', 'Forwarded', 'Dropped', 'Why'].map(t => h('span', null, t))),
      d.vlans.map(v => h('div', { key: v.vlan, class: 'tr' }, h('span', { class: 'mono' }, String(v.vlan)), h('span', { class: 'mono', style: 'font-size:12px' }, num(v.forwarded)),
        h('span', { class: 'mono', style: `font-size:12px;${v.droppedNow ? 'color:var(--warn)' : ''}` }, num(v.dropped), v.droppedNow ? ` (+${num(v.droppedNow)} in ${since})` : ''),
        h('span', { class: 'muted', style: 'font-size:12px' }, v.why))))));
}

/** Applications NBAR2 recognised on one interface. */
export function nbarPanel(nbar: Nbar | null | undefined, ifIndex: number): VNode | null {
  const list = nbar?.interfaces[ifIndex]; if (!list?.length) return null;
  return h('div', { class: 'col', style: 'gap:6px' }, sub('Applications on this port', 'recognised by NBAR2 since it was switched on; rates are worked out from the byte counters between reads'),
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(140px,1fr) 110px 110px 110px 110px;--w:600px' },
      h('div', { class: 'tr head' }, ...['Application', 'Rate in', 'Rate out', 'Bytes in', 'Bytes out'].map(t => h('span', null, t))),
      list.map(x => h('div', { key: x.name, class: 'tr' }, h('span', { class: 'mono', style: 'font-size:12px' }, x.name), h('span', { class: 'mono', style: 'font-size:12px', title: x.inBps === null ? 'Needs two reads of the counters (they are read every five minutes)' : undefined }, x.inBps === null ? '—' : bps(x.inBps)), h('span', { class: 'mono', style: 'font-size:12px' }, x.outBps === null ? '—' : bps(x.outBps)),
        h('span', { class: 'mono', style: 'font-size:12px' }, num(x.inBytes)), h('span', { class: 'mono', style: 'font-size:12px' }, num(x.outBytes)))))));
}

/** Spanning tree and routing protocols: how the device sees the rest of the network. */
export function protocolsPanel(o: { data: HealthRes | null; ifName?: (ifIndex: number) => string }): VNode | null {
  const hl = o.data?.health ?? NO_HEALTH;
  if (!hasProtocols(o.data)) return null;
  const sections: (VNode | null)[] = [];
  if (hl.stp) {
    const s = hl.stp;
    sections.push(h('div', { key: 'stp', class: 'col', style: 'gap:6px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, 'Spanning tree'),
      h('div', { class: 'row', style: 'gap:10px;align-items:stretch;flex-wrap:wrap' },
        stat('Root', s.isRoot ? 'This device' : 'Another bridge', s.isRoot ? 'It is the root bridge' : `${s.rootId}${s.rootPort ? ` · root port ${s.rootPort}` : ''}${s.rootCost ? ` · cost ${s.rootCost}` : ''}`),
        s.topChanges !== null ? stat('Topology changes', h('span', { style: s.sinceChangeSec !== null && s.sinceChangeSec < 600 && s.topChanges > 0 ? 'color:var(--warn)' : undefined }, num(s.topChanges)), s.sinceChangeSec !== null ? `last one ${dur(s.sinceChangeSec * 1000)} ago` : undefined) : null,
        s.ports ? stat('Blocking ports', String(s.blockingPorts), `of ${s.ports} bridge ports`) : null)));
  }
  if (hl.ospf.length) sections.push(h('div', { key: 'ospf', class: 'col', style: 'gap:6px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, 'OSPF neighbours'),
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(140px,1fr) minmax(140px,1fr) 120px;--w:480px' },
      h('div', { class: 'tr head' }, ...['Neighbour address', 'Router ID', 'State'].map(t => h('span', null, t))),
      hl.ospf.map(n => h('div', { key: n.address, class: 'tr' }, h('span', { class: 'mono', style: 'font-size:12px' }, n.address), h('span', { class: 'mono', style: 'font-size:12px' }, n.id || '—'), statusEl(n.level === 'off' ? 'off' : n.level, n.state)))))));
  if (hl.bgp.length) sections.push(h('div', { key: 'bgp', class: 'col', style: 'gap:6px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, `BGP peers${hl.bgpLocalAs ? ` (local AS ${hl.bgpLocalAs})` : ''}`),
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(130px,1fr) 90px 130px 110px 100px 100px minmax(160px,1fr);--w:900px' },
      h('div', { class: 'tr head' }, ...['Peer', 'AS', 'State', 'Up for', 'Updates in', 'Updates out', 'Prefixes accepted'].map(t => h('span', null, t))),
      hl.bgp.map(p => h('div', { key: p.address, class: 'tr' }, h('span', { class: 'mono', style: 'font-size:12px' }, p.address), h('span', { class: 'mono', style: 'font-size:12px' }, p.as === null ? '—' : String(p.as)),
        statusEl(p.level === 'off' ? 'off' : p.level, p.admin === 'stop' && p.level !== 'ok' ? `${p.state} (shut down)` : p.state),
        h('span', { class: 'muted' }, p.upSec !== null ? dur(p.upSec * 1000) : '—'), h('span', { class: 'mono', style: 'font-size:12px' }, p.updatesIn === null ? '—' : num(p.updatesIn)), h('span', { class: 'mono', style: 'font-size:12px' }, p.updatesOut === null ? '—' : num(p.updatesOut)),
        h('span', { class: 'mono', style: 'font-size:12px;overflow-wrap:anywhere' }, (p.families ?? []).length ? p.families!.map(f => h('span', { key: f.name, style: p.level === 'ok' && f.accepted === 0 ? 'color:var(--warn)' : undefined, title: `${f.name}: ${f.accepted ?? '?'} accepted, ${f.denied ?? '?'} denied, ${f.advertised ?? '?'} advertised${p.level === 'ok' && f.accepted === 0 ? '. The session is up but no routes are being learned.' : ''}` }, `${f.name} ${f.accepted ?? '?'}  `)) : '—')))))));
  const nm = (i: number | null) => (i ? o.ifName?.(i) || `interface ${i}` : '—');
  if (hl.eigrp?.length) sections.push(h('div', { key: 'eigrp', class: 'col', style: 'gap:6px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, `EIGRP neighbours (AS ${[...new Set(hl.eigrp.map(p => p.as))].join(', ')})`),
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(130px,1fr) minmax(130px,1fr) 90px 90px 90px 110px;--w:700px' },
      h('div', { class: 'tr head' }, ...['Neighbour', 'Interface', 'Up for', 'Round trip', 'Resent', 'State'].map(t => h('span', null, t))),
      hl.eigrp.map(p => h('div', { key: `${p.as}/${p.address}`, class: 'tr' }, h('span', { class: 'mono', style: 'font-size:12px' }, p.address), h('span', { class: 'mono', style: 'font-size:12px' }, nm(p.ifIndex)), h('span', { class: 'muted' }, p.upText || '—'),
        h('span', { class: 'mono', style: 'font-size:12px' }, p.srttMs === null ? '—' : `${p.srttMs} ms`), h('span', { class: 'mono', style: 'font-size:12px' }, p.retrans === null ? '—' : num(p.retrans)),
        statusEl(p.level, p.level === 'ok' ? 'adjacent' : `retrying ${p.retries}`)))))));
  if (hl.bfd?.length) sections.push(h('div', { key: 'bfd', class: 'col', style: 'gap:6px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, 'BFD sessions'),
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(130px,1fr) minmax(130px,1fr) 100px 100px 90px minmax(160px,1fr);--w:760px' },
      h('div', { class: 'tr head' }, ...['Peer', 'Interface', 'State', 'Up for', 'Detects in', 'Last failure'].map(t => h('span', null, t))),
      hl.bfd.map(b => h('div', { key: b.id, class: 'tr' }, h('span', { class: 'mono', style: 'font-size:12px', title: b.peerKnown === false ? 'The neighbour could not be worked out from the subnet, so this is the address of this device on the session' : undefined }, b.peerKnown === false ? `${b.address} (this end)` : b.address), h('span', { class: 'mono', style: 'font-size:12px' }, nm(b.ifIndex)), statusEl(b.level, b.state),
        h('span', { class: 'muted' }, b.upSec !== null ? dur(b.upSec * 1000) : '—'), h('span', { class: 'mono', style: 'font-size:12px' }, b.detectMs === null ? '—' : `${b.detectMs} ms`),
        h('span', { class: 'muted' }, b.diag ? `${b.diag}${b.upCount && b.upCount > 1 ? ` (${b.upCount - 1} earlier)` : ''}` : b.upCount && b.upCount > 1 ? `${b.upCount - 1} earlier` : 'none')))))));
  if (o.data?.extras?.dai?.vlans.length) sections.push(daiSection(o.data.extras.dai));
  void STP_TEXT;
  return h('div', { class: 'col', style: 'gap:12px' }, sections);
}

/** What each counter means, in plain words, for the tile under its name. */
const COUNTER_TEXT: Record<string, [string, string]> = {
  inErr: ['Input errors', 'frames received with an error, all kinds'], outErr: ['Output errors', 'frames that could not be sent'],
  inDisc: ['Input discards', 'received frames dropped with no error, usually for lack of buffer space'], outDisc: ['Output discards', 'frames dropped before sending, usually because the queue was full'],
  fcs: ['CRC errors', 'frames with a bad checksum: a bad cable, optic or duplex mismatch'], align: ['Alignment errors', 'frames that did not end on a byte boundary'], symbol: ['Symbol errors', 'bad signal on the wire'],
  late: ['Late collisions', 'collisions after the first 64 bytes. Half duplex only'], excessive: ['Excessive collisions', 'frames given up on after 16 collisions'], collisions: ['Collisions', 'frames that collided once or more. Half duplex only'],
  carrier: ['Carrier sense errors', 'the carrier was lost while sending'], tooLong: ['Frames too long', 'frames longer than the interface accepts'], unknown: ['Unknown protocol', 'packets for a protocol the device does not run'],
  outQDrops: ['Output queue drops', 'packets dropped because this port\'s output queue was full: the port is congested (Cisco)'], inQDrops: ['Input queue drops', 'packets dropped because the device could not keep up with this port (Cisco)'],
  resets: ['Interface resets', 'times the interface was reset (Cisco)'], storm: ['Storm control drops', 'packets suppressed because broadcast, multicast or unicast traffic went over the storm control limit (Cisco)'],
  portSec: ['Port security violations', 'frames from a MAC address the port is not allowed to learn (Cisco)']
};
const ERROR_ORDER = ['inErr', 'outErr', 'inDisc', 'outDisc', 'fcs', 'align', 'symbol', 'late', 'excessive', 'collisions', 'carrier', 'tooLong', 'unknown', 'outQDrops', 'inQDrops', 'storm', 'portSec', 'resets'];

/** The link quality of one interface: duplex, every error and discard counter by type, broadcast and multicast rates, the optic's light levels, and plain-language warnings. */
export function linkQuality(x: IfExtra | undefined, optics: Sensor[], speedMbps: number | null): VNode | null {
  if (!x && !optics.length) return null;
  const perSec = (v: number) => `${v >= 10 ? num(Math.round(v)) : (Math.round(v * 10) / 10).toString()}/s`;
  const since = x?.dtSec ? (x.dtSec < 120 ? x.dtSec + ' s' : Math.round(x.dtSec / 60) + ' min') : '';
  const grid = (list: VNode[]) => h('div', { style: 'display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:8px' }, list);
  const sect = (title: string, hint: string | null, body: VNode) => h('div', { class: 'col', style: 'gap:6px' }, h('div', { class: 'row', style: 'gap:8px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, title), hint ? h('span', { class: 'dim', style: 'font-size:11.5px' }, hint) : null), body);
  const errs: VNode[] = [];
  if (x) for (const k of ERROR_ORDER) {
    const total = x.totals[k]; if (total === undefined) continue;
    // collisions are counted once as single and multiple together, and late and excessive have their own tiles
    const d = x.delta ? x.delta[k] : undefined;
    const [label, what] = COUNTER_TEXT[k];
    const bad = d !== undefined && d > 0 && k !== 'unknown';
    errs.push(h('div', { key: k, class: 'stat', style: 'min-width:0;padding:10px 14px', title: what },
      h('div', { class: 'slabel' }, label),
      h('div', { class: 'svalue', style: `font-size:17px;${bad ? 'color:var(--warn)' : ''}` }, num(total)),
      h('div', { class: 'ssub' }, d === undefined ? 'since the counters started' : d > 0 ? `+${num(d)} in the last ${since}` : `none in the last ${since}`)));
  }
  const cast: VNode[] = [];
  if (x) for (const [k, label] of [['inBc', 'Broadcast in'], ['outBc', 'Broadcast out'], ['inMc', 'Multicast in'], ['outMc', 'Multicast out']] as const) {
    const total = x.totals[k]; if (total === undefined) continue;
    const r = x.delta && x.dtSec && x.delta[k] !== undefined ? x.delta[k]! / x.dtSec : null;
    const hot = r !== null && k.endsWith('Bc') && r >= 1000;
    cast.push(h('div', { key: k, class: 'stat', style: 'min-width:0;padding:10px 14px' }, h('div', { class: 'slabel' }, label),
      h('div', { class: 'svalue', style: `font-size:17px;${hot ? 'color:var(--warn)' : ''}` }, r === null ? num(total) : perSec(r)), h('div', { class: 'ssub' }, `packets · ${num(total)} in total`)));
  }
  const pick = (o: string) => optics.find(s => s.optic === o);
  const light: VNode[] = [];
  for (const [o, label] of [['rx', 'Receive light'], ['tx', 'Transmit light'], ['temp', 'Module temperature']] as const) {
    const s = pick(o); if (s) light.push(stat(label, h('span', { style: colour(s.state) }, reading(s)), s.state === 'ok' ? undefined : s.stateText));
  }
  const link: VNode[] = [];
  if (x && x.duplex && x.duplex !== 'unknown') link.push(stat('Duplex', h('span', { style: x.duplex === 'half' && (speedMbps ?? 0) >= 100 ? 'color:var(--bad)' : undefined }, x.duplex === 'full' ? 'Full' : 'Half')));
  const warns = x?.warnings ?? [];
  if (!errs.length && !cast.length && !light.length && !link.length && !warns.length) return null;
  return h('div', { class: 'col', style: 'gap:12px' },
    warns.length ? h('div', { class: 'col', style: 'gap:6px' }, warns.map(w => note(w.text, w.level === 'bad' ? 'bad' : 'warn'))) : null,
    link.length || light.length ? sect('Link and optic', null, h('div', { class: 'row', style: 'gap:10px;align-items:stretch;flex-wrap:wrap' }, [...link, ...light])) : null,
    errs.length ? sect('Errors and discards', 'Totals since the counters started, and what arrived since the read before', grid(errs)) : null,
    cast.length ? sect('Broadcast and multicast', 'Packets per second over the last interval', grid(cast)) : null,
    x?.delta === null && x ? h('span', { class: 'dim', style: 'font-size:11.5px' }, 'Changes appear after the second read, a few minutes after the device is first polled.') : null);
}
