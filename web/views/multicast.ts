import { h, type VNode } from '../vdom.js';
import { get, qs } from '../api.js';
import { go, redraw } from '../state.js';
import { btn, chip, empty, heading, note, select, spinner, stat, status as statusEl, textInput, toggle } from '../components.js';
import { ago, bps, num, stamp } from '../util.js';

/**
 * Multicast: what each router says it does with every group it knows. NetFlow records the interface a packet arrives on, so the
 * interfaces a group is sent out of, and the hosts that asked for it, come from the router's own multicast table read over SNMP.
 */

interface DevSummary { id: number; name: string; ip: string; role: string; readAt: number; stale: boolean; source: 'cisco' | 'standard'; routes: number; groups: number; receivers: number; forwarding: number; truncated: boolean }
interface HostAt { dev: string; port: string; vlan: number; confidence: string; neighbor: string | null }
interface Join { reporter: string | null; expirySec: number | null; self: boolean }
interface IgmpHint { vendor: string; platform: string; command: string | null }
interface Member { ip: string; ageSec: number; sinceSec: number | null; via?: 'snmp' | 'netflow' | 'both'; approx?: boolean }
const VIA_TEXT = { snmp: 'SNMP', netflow: 'NetFlow', both: 'SNMP and NetFlow' } as const;
const VIA_WHY = { snmp: "From the router's IGMP cache over SNMP: the last host to report the group on this interface, collected over time.", netflow: 'Seen in NetFlow as an IGMP version 1 or 2 membership report from this host to the group. Not in the IGMP cache.', both: 'In the IGMP cache over SNMP and also seen as an IGMP report in NetFlow: two independent sources agree.' } as const;
const viaChip = (v: Member['via']): VNode => chip(VIA_TEXT[v ?? 'snmp'], v === 'both' ? 'ok' : 'default', VIA_WHY[v ?? 'snmp']);
interface Out { ifIndex: number; name: string; pimMode?: string | null; members?: Member[]; forwarding: boolean; linkDown?: boolean; loopback?: boolean; pkts: number | null; neighbor: string | null; joins: Join[] }
interface RpfPeer { id: number; name: string; ifIndex: number; ifName: string; forwarding: boolean | null }
interface Rpf { peer?: RpfPeer | null; loss?: boolean; inIfIndex?: number | null; inIf: string | null; neighbor: string | null; who: string | null; route: string | null; proto: string | null; failures: number | null }
interface IgmpIf { name: string; querier: string | null; who: string | null; self: boolean; version: number | null; intervalSec: number | null; upSec: number | null; expirySec: number | null; hosts: number }
interface RpMap { range: string; rp: string; who: string | null; self: boolean; holdSec: number | null; expirySec: number | null }
interface Route {
  rpf?: Rpf | null;
  group: string; source: string; sharedTree: boolean; inIf: string | null; upstream: string | null; rp: string | null; bps: number | null; pkts: number | null; flags: string[]; protocol: number | null; mode?: 'sparse' | 'dense' | null; expirySec: number | null; out: Out[];
}
interface Detail {
  igmpHint?: IgmpHint;
  device: { id: number; name: string; ip: string; role: string; model?: string }; readAt: number; stale: boolean; source: 'cisco' | 'standard'; truncated: boolean; routes: Route[];
  routeSource?: 'ipmroute' | 'pim';
  netflowIgmp?: { reports: number; hosts: number; v3Hosts: number; windowMin: number; unmatched: number } | null;
  igmp?: IgmpIf[];
  rps?: { inUse?: { rp: string; who: string | null; self: boolean; up: boolean; groups: string[]; sinceSec: number | null }[]; map: RpMap[]; candidate: { range: string; rp: string; self: boolean }[] };
  pimIssues?: { level: 'warn' | 'info'; kind: string; text: string }[];
  pim: { interfaces: { name: string; mode: string; dr: string | null }[]; neighbors: { address: string; ifName: string }[] };
  hosts?: Record<string, HostAt | null>;
  load?: { name: string; inBps: number | null; outBps: number | null; inOctets: number | null; outOctets: number | null; ttl: number | null; rateLimit: number | null }[];
}

let devs: DevSummary[] | null = null; let devError = '';
let devId = 0; let detail: Detail | null = null; let detailError = ''; let loading = false;
let query = ''; let onlyForwarding = false; let hideIdle = false;
const open = new Set<string>();            // routes whose details are shown (group|source)
const openHosts = new Set<string>();       // outgoing interfaces whose host list is open
const openGroups = new Set<string>();      // groups whose sources are listed
const closedWhileSearching = new Set<string>();
const SIZES = [25, 50, 100, 250, 500];
let page = 0; let pageSize = 50;
/** Where a host is plugged in, as found by host tracking: "dist-sw-01 Gi1/0/12" */
const at = (ip: string | null): string => { const a = ip ? detail?.hosts?.[ip] : null; return a ? `${a.dev} ${a.port}` : ''; };
let seq = 0;

export function enter(p: URLSearchParams): void {
  page = 0;
  const d = Number(p.get('dev'));
  if (Number.isInteger(d) && d > 0 && d !== devId) { devId = d; detail = null; }
  if (p.has('q')) query = p.get('q') ?? '';
  const g = p.get('g'); if (g) { openGroups.add(g); query = g; }
  void loadDevices().then(() => { if (devId) void loadDetail(); });
}

async function loadDevices(): Promise<void> {
  try {
    devs = (await get<{ devices: DevSummary[] }>('/api/multicast/devices')).devices; devError = '';
    if (!devs.some(d => d.id === devId)) { const best = [...devs].sort((a, b) => b.routes - a.routes)[0]; devId = best ? best.id : 0; detail = null; }
  } catch (e) { devError = (e as Error).message; }
  redraw();
}

async function loadDetail(): Promise<void> {
  if (!devId) return;
  const my = ++seq; loading = true; detailError = ''; redraw();
  try { const d = await get<Detail>('/api/multicast/device' + qs({ id: devId })); if (my === seq) detail = d; } catch (e) { if (my === seq) { detail = null; detailError = (e as Error).message; } }
  if (my === seq) { loading = false; redraw(); }
}

function pickDevice(v: string): void { page = 0; devId = Number(v); detail = null; open.clear(); openGroups.clear(); openHosts.clear(); closedWhileSearching.clear(); void loadDetail(); }

const rate = (r: Route): string => (r.bps === null ? '—' : r.bps === 0 ? '0' : bps(r.bps));
const sec = (s: number | null): string => (s === null ? '—' : s < 90 ? `${s}s` : `${Math.round(s / 60)}m`);

function matches(r: Route, q: string): boolean {
  if (!q) return true;
  const hay = [r.group, r.source === '0.0.0.0' ? '* shared' : r.source, at(r.source), r.inIf ?? '', r.rp ?? '', r.upstream ?? '', ...r.out.map(o => o.name), ...r.out.flatMap(o => [...o.joins.flatMap(j => [j.reporter ?? '', at(j.reporter)]), ...(o.members ?? []).flatMap(m => [m.ip, at(m.ip)])])].join(' ').toLowerCase();
  return q.toLowerCase().split(/\s+/).filter(Boolean).every(t => hay.includes(t));
}

const keyOf = (r: Route) => r.group + '|' + r.source;

function outChips(r: Route): VNode {
  const fwd = r.out.filter(o => o.forwarding), pruned = r.out.length - fwd.length;
  if (!r.out.length) return h('span', { class: 'dim', title: 'The router has the route but nothing downstream has asked for the group, so it is not sent anywhere.' }, 'nowhere');
  return h('span', { class: 'mono', style: 'font-size:12px' }, fwd.slice(0, 4).map(o => o.name).join(', '), fwd.length > 4 ? ` +${fwd.length - 4}` : '', pruned ? h('span', { class: 'dim', title: 'Pruned: in the list but no one downstream wants the group' }, ` (${pruned} pruned)`) : null);
}

/** Shown wherever hosts that joined are listed: the router does not keep a full membership list for SNMP to read. */
/** How PIM mode changes what a router does with receivers. Dense floods and prunes; sparse waits for a join. */
const DENSE_WHY = 'PIM dense mode sends the group out of every PIM interface and then prunes the ones with no receiver, and floods again about every three minutes. An interface can show as forwarding with nobody behind it until it is pruned.';
const SPARSE_DENSE_WHY = 'PIM sparse-dense mode: a group with a rendezvous point runs sparse, and a group without one falls back to dense and is flooded to every PIM interface.';
const pimChip = (mode: string | null | undefined): VNode | null => (mode === 'dense' ? chip('PIM dense', 'warn', DENSE_WHY) : mode === 'sparse-dense' ? chip('PIM sparse-dense', 'warn', SPARSE_DENSE_WHY) : null);

/** The PIM modes the router runs, as a line above the table; dense and sparse-dense are flagged, since they change what a receiver gets. */
function pimSummary(d: Detail): VNode | null {
  const n = new Map<string, number>(); for (const p of d.pim.interfaces) n.set(p.mode, (n.get(p.mode) ?? 0) + 1);
  if (!n.size) return null;
  const flagged = (n.get('dense') ?? 0) + (n.get('sparse-dense') ?? 0) > 0;
  const text = [...n].map(([m, k]) => `${num(k)} ${m}`).join(', ');
  const dense = d.routes.filter(r => r.mode === 'dense').length;
  return h('div', { class: 'row', style: 'gap:8px;align-items:center;flex-wrap:wrap;font-size:12.5px' },
    h('span', { class: 'dim' }, 'PIM interfaces:'), h('span', { class: 'mono' }, text),
    n.get('dense') ? pimChip('dense') : null, n.get('sparse-dense') ? pimChip('sparse-dense') : null,
    dense ? h('span', { class: 'dim' }, `${num(dense)} route${dense === 1 ? ' runs' : 's run'} in dense mode`) : null,
    flagged ? h('span', { class: 'dim' }, 'Receivers behave differently here: hover a flag for how.') : null);
}

const VENDOR_NAME: Record<string, string> = { cisco: 'Cisco', juniper: 'Juniper', arista: 'Arista', h3c: 'H3C / HPE Comware' };
/** Where to look for the full list, by the switch's vendor. A vendor without a known command is pointed at its IGMP snooping table. */
function whereToLook(): string {
  const hint = detail?.igmpHint;
  if (!hint?.command) return 'check the switch\'s IGMP snooping table';
  const model = detail?.device.model ? ` (${detail.device.model})` : '';
  return `check the switch${model}: on ${VENDOR_NAME[hint.vendor] ?? hint.vendor} ${hint.platform}, run ${hint.command}`;
}
const incomplete = (): string => `Not a complete list. The router keeps only the last host to report each group, so FlowScope collects reporters as they answer queries (and, where the flow export includes IGMP, from NetFlow) and can miss hosts that have not been the last to report. For the full membership, ${whereToLook()}.`;

const ageText = (s: number): string => (s < 90 ? `${s}s ago` : s < 5400 ? `${Math.round(s / 60)} min ago` : s < 129_600 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} d ago`);

/** One outgoing interface. The hosts that joined are every reporter seen over time, so a VLAN with many receivers is a collapsible list. */
function oilRow(r: Route, o: Out): VNode {
  const hk = `${keyOf(r)}|${o.ifIndex}`, members = o.members ?? [], many = members.length > 1 || members.some(m => m.via === 'netflow' || m.via === 'both'), on = openHosts.has(hk);
  const joined = (): VNode | string => {
    if (o.loopback && !o.joins.some(j => j.reporter)) return 'the router joined the group itself';
    if (many) return h('button', { type: 'button', class: 'rowbtn', 'aria-expanded': on, title: o.neighbor ? undefined : incomplete(), onclick: () => toggleSet(openHosts, hk) }, `${on ? '▾' : '▸'} ${num(members.length)} hosts`);
    if (o.joins.length) return h('span', { title: o.neighbor ? undefined : incomplete() }, o.joins.slice(0, 4).map(j => (j.self ? 'this router' : (j.reporter ?? '?') + (at(j.reporter) ? ` on ${at(j.reporter)}` : '')) + (j.expirySec !== null ? ` (${sec(j.expirySec)})` : '')).join(', ') + (o.joins.length > 4 ? ` +${o.joins.length - 4}` : ''));
    return h('span', { class: 'dim' }, o.neighbor ? 'via the neighbour' : 'none seen');
  };
  return h('div', { key: o.ifIndex },
    h('div', { class: 'tr' },
        h('span', { class: 'mono', style: 'font-size:12px' }, o.name),
        h('span', null, o.linkDown ? chip('link down', 'bad', 'The route lists this interface' + (o.forwarding ? ' as forwarding' : '') + ', but the port is not up, so nothing is arriving over it') : o.forwarding ? chip('forwarding', 'ok') : chip('pruned', 'default', 'Listed, but no one downstream wants the group')),
        h('span', { class: 'mono dim', style: 'font-size:12px' }, o.neighbor ? `PIM neighbour ${o.neighbor}` : o.loopback ? 'this router (loopback)' : o.joins.length ? 'hosts on this segment' : '—', ' ', pimChip(o.pimMode)),
        h('span', { class: 'mono', style: 'font-size:12px' }, joined()),
        h('span', { class: 'mono', style: 'font-size:12px' }, num(o.pkts))),
    many && on ? h('div', { class: 'mcsub', style: 'margin:2px 0 10px 18px;border-left:2px solid var(--line);padding-left:10px' },
      o.neighbor ? null : note(incomplete(), 'warn'),
      h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(130px,1fr) minmax(220px,2fr) 150px 120px 110px;--w:700px' },
        h('div', { class: 'tr head' }, ...['Host', 'Plugged in at', 'Seen by', 'Last reported', 'Known for'].map(t => h('span', null, t))),
        members.map(m => h('div', { key: m.ip, class: 'tr' },
          h('span', { class: 'mono', style: 'font-size:12px' }, m.ip),
          h('span', { class: 'mono', style: 'font-size:12px' }, at(m.ip) || h('span', { class: 'dim' }, 'not located')),
          h('span', null, viaChip(m.via)),
          h('span', { style: 'font-size:12px' }, m.approx ? h('span', { class: 'dim', title: 'NetFlow gives a window, not a time' }, m.ageSec <= 300 ? 'within 5 min' : 'within 30 min') : m.ageSec < 150 ? chip('now', 'ok', 'Reported in the last two minutes') : h('span', { class: 'dim' }, ageText(m.ageSec))),
          h('span', { class: 'dim', style: 'font-size:12px' }, m.sinceSec === null ? '—' : ageText(m.sinceSec).replace(' ago', ''))))))) : null);
}

function expanded(r: Route): VNode {
  const cols = 'minmax(140px,1fr) 110px minmax(150px,1.2fr) minmax(200px,2fr) 90px';
  return h('div', { class: 'mcdetail', style: 'padding:6px 12px 14px' },
    h('div', { class: 'row', style: 'gap:8px 18px;flex-wrap:wrap;color:var(--muted);font-size:12.5px;margin-bottom:8px' },
      h('span', null, r.sharedTree ? 'Shared tree (*,G)' : `Source ${r.source}`, !r.sharedTree && at(r.source) ? h('span', null, ' · plugged in at ', h('b', { class: 'mono' }, at(r.source))) : null),
      r.mode === 'dense' ? pimChip('dense') : r.mode === 'sparse' ? chip('PIM sparse', 'default', 'The route runs in PIM sparse mode: it is sent only where a receiver has joined.') : null,
      r.inIf ? h('span', null, 'Arrives on ', h('b', { class: 'mono' }, r.inIf)) : null,
      r.rpf ? rpfLine(r.rpf, r.group) : r.upstream ? h('span', null, 'Upstream ', h('b', { class: 'mono' }, r.upstream)) : null,
      r.rp ? h('span', null, 'Rendezvous point ', h('b', { class: 'mono' }, r.rp)) : null,
      r.pkts !== null ? h('span', null, `${num(r.pkts)} packets`) : null,
      r.expirySec !== null ? h('span', null, r.expirySec === 0 ? 'route does not age out' : `route expires in ${sec(r.expirySec)}`) : null,
      r.flags.length ? h('span', null, 'Flags: ', r.flags.join(', ')) : null),
    r.out.length ? h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${cols};--w:780px` },
      h('div', { class: 'tr head' }, ...['Sent out of', 'State', 'Reaches', 'Hosts that joined (IGMP)', 'Packets'].map(t => h('span', null, t))),
      r.out.map(o => oilRow(r, o)))) : detail?.routeSource === 'pim' ? null : note('Nothing is joined downstream of this router, so it forwards this group nowhere.', 'info'));
}

interface Grp { group: string; routes: Route[] }

const toggleSet = (set: Set<string>, k: string): void => { if (set.has(k)) set.delete(k); else set.add(k); redraw(); };
const keyDown = (fn: () => void) => (e: KeyboardEvent): void => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fn(); } };
/** Searching opens the groups that match, so the matching sources are in view; a group closed by hand stays closed. */
const groupOpen = (g: string): boolean => (query ? !closedWhileSearching.has(g) : openGroups.has(g));
const toggleGroup = (g: string): void => { if (query) toggleSet(closedWhileSearching, g); else toggleSet(openGroups, g); };

/** One route as a row, opening its details (arrival interface, outgoing interfaces and the hosts that joined). */
function routeRow(r: Route, cols: string, lead: VNode[]): VNode {
  const k = keyOf(r), on = open.has(k);
  return h('div', { key: k }, h('div', { class: 'tr', role: 'button', tabindex: 0, 'aria-expanded': on, style: 'cursor:pointer', onclick: () => toggleSet(open, k), onkeydown: keyDown(() => toggleSet(open, k)) },
    h('span', { class: 'dim', 'aria-hidden': 'true' }, on ? '▾' : '▸'), ...lead,
    h('span', { class: 'mono', style: 'font-size:12px' }, r.inIf ?? '—'), outChips(r),
    h('span', { class: 'mono', style: 'font-size:12px' }, rate(r)), h('span', { class: 'mono dim', style: 'font-size:12px' }, r.rp ?? '—')), on ? expanded(r) : null);
}
const sourceCell = (r: Route): VNode => h('span', { class: 'mono', style: 'font-size:12px' }, r.sharedTree ? h('span', { class: 'dim', title: 'Any source: the shared tree (*,G)' }, '* (any source)') : r.source, !r.sharedTree && at(r.source) ? h('span', { class: 'dim' }, ` · ${at(r.source)}`) : null);

/** What is wrong with the RPF link of a route: drops, a neighbour that does not forward the group to this router, or multicast lost on the link. */
function rpfProblems(x: Rpf | null | undefined): { key: string; text: string; title: string }[] {
  if (!x) return [];
  const out: { key: string; text: string; title: string }[] = [];
  if (x.failures) out.push({ key: 'drops', text: `${num(x.failures)} RPF drops`, title: 'Packets for this route that arrived on an interface other than the RPF interface and were dropped. A counter since the route was created, so it shows that it happened, not that it is happening now.' });
  if (x.peer && x.peer.forwarding === false) out.push({ key: 'nofwd', text: 'neighbour not forwarding', title: `${x.peer.name} does not list ${x.peer.ifName} as an outgoing interface for this group that is forwarding, so nothing is sent to this router` });
  if (x.loss) out.push({ key: 'loss', text: 'multicast lost on link', title: 'The neighbour sends more multicast out of its end of this link than this router receives' });
  return out;
}
const rpfFlags = (x: Rpf | null | undefined): VNode[] => rpfProblems(x).map(p => chip(p.text, 'warn', p.title));
const linkBtn = (text: string, title: string, onclick: () => void): VNode => h('button', { type: 'button', class: 'lnk', title, onclick: (e: Event) => { e.stopPropagation(); onclick(); } }, text);
/** The RPF interface and neighbour of a route, with links to the neighbour's multicast table and to the interface statistics on both switches. */
function rpfLine(x: Rpf, group: string): VNode | null {
  if (!x.inIf && !x.neighbor) return null;
  const me = detail?.device;
  return h('span', { class: 'row', style: 'gap:6px 10px;flex-wrap:wrap;align-items:center' },
    x.inIf ? h('span', null, 'RPF interface ', me ? linkBtn(x.inIf, `Open ${x.inIf} on ${me.name} in Interfaces`, () => go('links', { dev: me.id, if: x.inIf ?? undefined })) : h('b', { class: 'mono' }, x.inIf)) : null,
    x.neighbor ? h('span', null, 'neighbour ', h('b', { class: 'mono' }, x.neighbor), x.who ? ` (${x.who})` : '') : null,
    x.peer ? [
      linkBtn(`${x.peer.name} multicast table`, `Open ${group} on ${x.peer.name}`, () => go('multicast', { dev: x.peer!.id, g: group })),
      linkBtn(`${x.peer.ifName} on ${x.peer.name}`, `Open ${x.peer.ifName} on ${x.peer.name} in Interfaces`, () => go('links', { dev: x.peer!.id, if: x.peer!.ifName }))
    ] : null,
    x.route ? h('span', { title: 'Reverse path forwarding: the unicast route back to the source (or to the rendezvous point for a shared tree) decides which interface the router accepts this group on. Traffic on any other interface is dropped.' }, 'via route ', h('b', { class: 'mono' }, x.route), x.proto ? ` (${x.proto})` : '') : null,
    ...rpfFlags(x));
}
/** One line per distinct RPF interface and neighbour in a group. */
function groupRpf(list: Route[], group: string): VNode | null {
  const by = new Map<string, { x: Rpf; n: number }>();
  for (const r of list) { if (!r.rpf) continue; const k = `${r.rpf.inIf}|${r.rpf.neighbor}`; const e = by.get(k); if (e) { e.n++; if (r.rpf.failures) e.x = { ...e.x, failures: (e.x.failures ?? 0) + r.rpf.failures }; if (r.rpf.peer?.forwarding === false && e.x.peer) e.x = { ...e.x, peer: { ...e.x.peer, forwarding: false } }; } else by.set(k, { x: { ...r.rpf }, n: 1 }); }
  if (!by.size) return null;
  return h('div', { class: 'col', style: 'gap:4px;margin:4px 0 8px;font-size:12.5px' }, [...by.values()].slice(0, 6).map(e => h('div', { key: e.x.inIf + '|' + e.x.neighbor, class: 'row', style: 'gap:8px;align-items:center;flex-wrap:wrap' }, rpfLine({ ...e.x, route: by.size === 1 ? e.x.route : null }, group), by.size > 1 ? h('span', { class: 'dim' }, `${num(e.n)} source${e.n === 1 ? '' : 's'}`) : null)));
}

/** One chip per kind of RPF problem across a group's routes, so a collapsed group still shows that something is wrong. */
function flagsOf(list: Route[]): (VNode | string)[] {
  const by = new Map<string, { p: { key: string; text: string; title: string }; n: number }>();
  for (const r of list) for (const p of rpfProblems(r.rpf)) { const e = by.get(p.key); if (e) e.n++; else by.set(p.key, { p, n: 1 }); }
  if (!by.size) return [];
  const all = [...by.values()], what = all.map(e => e.p.key === 'drops' ? 'RPF drops' : e.p.text).join(', ');
  return [' ', chip(all.length === 1 ? what : `${all.length} RPF problems`, 'warn', `${what}${list.length > 1 ? ` (open the group for which sources)` : ''}`)];
}

function groupRows(g: Grp): VNode {
  const cols = '28px minmax(120px,1fr) minmax(110px,1fr) minmax(90px,0.8fr) minmax(200px,2fr) 90px minmax(100px,0.9fr)';
  const list = g.routes;
  // a group with one route needs no middle level: its row opens the route directly
  if (list.length === 1) return routeRow(list[0]!, cols, [h('span', { class: 'mono', style: 'font-weight:600' }, g.group), sourceCell(list[0]!)]);
  const on = groupOpen(g.group);
  const fwd = new Set<string>(); for (const r of list) for (const o of r.out) if (o.forwarding) fwd.add(o.name);
  const arrives = [...new Set(list.map(r => r.inIf).filter((x): x is string => !!x))];
  const total = list.some(r => r.bps !== null) ? list.reduce((a, r) => a + (r.bps ?? 0), 0) : null;
  const rps = [...new Set(list.map(r => r.rp).filter((x): x is string => !!x))];
  const sub = 'minmax(150px,1.2fr) minmax(90px,0.8fr) minmax(200px,2fr) 90px minmax(100px,0.9fr)';
  const sorted = [...list].sort((a, b) => Number(b.sharedTree) - Number(a.sharedTree) || (b.bps ?? -1) - (a.bps ?? -1) || a.source.localeCompare(b.source, undefined, { numeric: true }));
  return h('div', { key: 'g|' + g.group },
    h('div', { class: 'tr', role: 'button', tabindex: 0, 'aria-expanded': on, style: 'cursor:pointer', onclick: () => toggleGroup(g.group), onkeydown: keyDown(() => toggleGroup(g.group)) },
      h('span', { class: 'dim', 'aria-hidden': 'true' }, on ? '▾' : '▸'),
      h('span', { class: 'mono', style: 'font-weight:600' }, g.group),
      h('span', { class: 'mono', style: 'font-size:12px' }, chip(`${num(list.length)} sources`, 'default', 'Click to list the sources of this group')),
      h('span', { class: 'mono', style: 'font-size:12px' }, arrives.slice(0, 2).join(', ') + (arrives.length > 2 ? ` +${arrives.length - 2}` : '') || '—', ...(flagsOf(list))),
      h('span', { class: 'mono', style: 'font-size:12px' }, [...fwd].slice(0, 4).join(', ') || h('span', { class: 'dim' }, 'nowhere'), fwd.size > 4 ? ` +${fwd.size - 4}` : ''),
      h('span', { class: 'mono', style: 'font-size:12px' }, total === null ? '—' : total === 0 ? '0' : bps(total)),
      h('span', { class: 'mono dim', style: 'font-size:12px' }, rps.length ? rps[0] + (rps.length > 1 ? ` +${rps.length - 1}` : '') : '—')),
    on ? h('div', { class: 'mcsub', style: 'margin:2px 0 10px 28px;border-left:2px solid var(--line);padding-left:10px' },
      groupRpf(list, g.group),
      h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:28px ${sub};--w:760px` },
        h('div', { class: 'tr head' }, ...['', 'Source', 'Arrives on', 'Sent out of', 'Rate', 'Rendezvous point'].map(t => h('span', null, t))),
        sorted.map(r => routeRow(r, cols, [sourceCell(r)]))))) : null);
}

function table(d: Detail): VNode {
  const rows = d.routes.filter(r => matches(r, query) && (!onlyForwarding || r.out.some(o => o.forwarding)) && (!hideIdle || (r.bps ?? 1) > 0));
  const by = new Map<string, Route[]>();
  for (const r of rows) { const a = by.get(r.group); if (a) a.push(r); else by.set(r.group, [r]); }
  const groups: Grp[] = [...by].map(([group, routes]) => ({ group, routes }));
  const pages = Math.max(1, Math.ceil(groups.length / pageSize));
  if (page >= pages) page = pages - 1;
  const shown = groups.slice(page * pageSize, (page + 1) * pageSize);
  const cols = '28px minmax(120px,1fr) minmax(110px,1fr) minmax(90px,0.8fr) minmax(200px,2fr) 90px minmax(100px,0.9fr)';
  return h('div', null,
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${cols};--w:900px` },
      h('div', { class: 'tr head' }, ...['', 'Group', 'Source', 'Arrives on', 'Sent out of', 'Rate', 'Rendezvous point'].map(t => h('span', null, t))),
      shown.map(groupRows),
      !shown.length ? empty(d.routes.length ? 'No routes match the filter.' : 'This device holds no multicast routes.') : null)),
    groups.length ? pager(groups.length, pages, page * pageSize + 1, page * pageSize + shown.length) : null);
}

function summary(s: DevSummary): VNode {
  return h('div', { class: 'row', style: 'gap:12px;flex-wrap:wrap' },
    stat('Groups', num(s.groups), `${num(s.routes)} routes`),
    stat('Forwarding', num(s.forwarding), 'routes with receivers'),
    stat('IGMP joins', num(s.receivers), 'last reporter per group'));
}

export function render(): VNode {
  const cur = devs?.find(d => d.id === devId) ?? null;
  return h('main', null,
    heading('Multicast', 'Where multicast groups are going', 'NetFlow records the interface a multicast packet arrives on, not the ones it is copied to. This is each router\'s own multicast table: the interfaces a group is sent out of and the hosts that joined, read over SNMP.'),
    devError ? note(devError, 'bad', true) : null,
    !devs && !devError ? spinner() : null,
    devs && !devs.length ? note('No polled device has published multicast routing state yet. A router or Layer 3 switch that runs PIM and answers IPMROUTE-STD-MIB shows up here within a few minutes of being polled. Tables are read every two minutes.', 'info') : null,
    devs && devs.length ? h('section', { class: 'panel col', style: 'gap:14px' },
      h('div', { class: 'row', style: 'gap:12px;align-items:center;flex-wrap:wrap' },
        devs.length > 1 ? select(String(devId), devs.map(d => [String(d.id), `${d.name} (${num(d.groups)} groups)`] as [string, string]), pickDevice, { aria: 'Device', width: '280px' }) : h('b', null, cur?.name ?? ''),
        cur ? h('span', { class: 'dim', title: stamp(cur.readAt) }, `read ${ago(cur.readAt)}`) : null,
        cur?.stale ? statusEl('warn', 'out of date') : null,
        cur ? chip(cur.source === 'cisco' ? 'IPMROUTE + Cisco rates' : 'IPMROUTE standard', 'default', cur.source === 'cisco' ? 'Rates and route flags come from CISCO-IPMROUTE-MIB' : 'The device does not publish rates; only the standard table was read') : null,
        btn('Refresh', { small: true, onclick: () => { void loadDevices().then(() => loadDetail()); } })),
      cur ? summary(cur) : null,
      detail ? pimSummary(detail) : null,
      ...(detail?.pimIssues ?? []).map(i => note(i.text, i.level === 'warn' ? 'warn' : 'info')),
      detail?.netflowIgmp !== undefined ? netflowNote(detail.netflowIgmp) : null,
      cur ? h('div', { class: 'dim', style: 'font-size:12.5px' }, `Hosts that joined come from the router's IGMP cache over SNMP and are not a complete list. For the full membership, ${whereToLook()}.`) : null,
      detail?.routeSource === 'pim' ? note('This device does not publish the standard multicast routing table (IPMROUTE-STD-MIB), as NX-OS does not. The groups and sources below come from PIM, so they have no incoming or outgoing interfaces, rates or RPF information. Use the device\'s CLI (show ip mroute) for those.', 'info') : null,
      cur?.truncated ? note('This device holds more routes than FlowScope keeps. The list is cut off.', 'warn') : null,
      h('div', { class: 'row', style: 'gap:12px;align-items:center;flex-wrap:wrap' },
        textInput(query, v => { query = v; page = 0; }, { placeholder: 'Search groups and source hosts: 239.1.1.1, 10.2.3.4, a port, a switch…', aria: 'Search groups and source hosts', width: '420px', id: 'mc-filter' }),
        toggle('Only groups with receivers', onlyForwarding, () => { onlyForwarding = !onlyForwarding; page = 0; redraw(); }),
        cur?.source === 'cisco' ? toggle('Hide idle routes', hideIdle, () => { hideIdle = !hideIdle; page = 0; redraw(); }, { onText: 'Hiding idle', offText: 'Showing idle' }) : null),
      loading && !detail ? spinner('Loading routes…') : null,
      detailError ? note(detailError, 'warn', true) : null,
      detail ? table(detail) : null,
      detail?.load?.length ? loadTable(detail.load) : null,
      detail?.igmp?.length ? igmpTable(detail.igmp) : null,
      detail?.rps && (detail.rps.map.length || detail.rps.candidate.length || detail.rps.inUse?.length) ? rpTable(detail.rps) : null,
      detail && detail.pim.neighbors.length ? h('div', { class: 'dim', style: 'font-size:12.5px' }, 'PIM neighbours: ', detail.pim.neighbors.map(n => `${n.address} on ${n.ifName}`).join(', ')) : null) : null);
}

/** What NetFlow contributed to the host lists, so an empty result can be told from a feed that does not carry IGMP. */
function netflowNote(n: NonNullable<Detail['netflowIgmp']> | null): VNode {
  if (!n) return h('div', { class: 'dim', style: 'font-size:12.5px' }, 'NetFlow: no flow exporter is matched to this device, so hosts come from SNMP only.');
  if (!n.reports && !n.v3Hosts) return h('div', { class: 'dim', style: 'font-size:12.5px' }, `NetFlow: no IGMP reports from this device in the last ${n.windowMin} minutes, so hosts come from SNMP only. Either no host is reporting through it, or its flow export does not include IGMP (many do not, and sampled exports drop most of it).`);
  return h('div', { class: 'dim', style: 'font-size:12.5px' }, `NetFlow: ${num(n.reports)} IGMP report${n.reports === 1 ? '' : 's'} from ${num(n.hosts)} host${n.hosts === 1 ? '' : 's'} in the last ${n.windowMin} minutes name a group (IGMP version 1 or 2). `,
    n.v3Hosts ? `${num(n.v3Hosts)} host${n.v3Hosts === 1 ? '' : 's'} also sent version 3 reports, which NetFlow cannot attribute to a group. ` : '',
    n.unmatched ? `${num(n.unmatched)} report${n.unmatched === 1 ? ' was' : 's were'} for a group or interface this router does not forward to and is left out.` : '');
}

/** The IGMP querier on each interface: the router that sends the membership queries, which keeps memberships alive. */
function igmpTable(list: IgmpIf[]): VNode {
  return h('div', { class: 'col', style: 'gap:6px' }, h('div', { class: 'row', style: 'gap:8px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, 'IGMP queriers'),
    h('span', { class: 'dim', style: 'font-size:11.5px' }, 'on a segment with several routers, the one with the lowest address queries; hosts only answer queries')),
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(120px,1fr) minmax(170px,1.4fr) 80px 110px 130px;--w:640px' },
      h('div', { class: 'tr head' }, ...['Interface', 'Querier', 'Version', 'Query interval', 'Querier for'].map(t => h('span', null, t))),
      list.map(i => h('div', { key: i.name, class: 'tr' }, h('span', { class: 'mono', style: 'font-size:12px' }, i.name),
        h('span', { class: 'mono', style: 'font-size:12px' }, i.querier ? h('span', null, i.querier, ' ', i.self ? chip('this router', 'ok') : i.who ? chip(i.who, 'default') : null) : chip('none', i.hosts ? 'bad' : 'default', i.hosts ? 'Hosts joined here but no querier is reported, so their memberships are not refreshed' : 'No querier is reported on this interface')),
        h('span', { class: 'mono', style: 'font-size:12px' }, i.version ? 'v' + i.version : '—'),
        h('span', { class: 'mono', style: 'font-size:12px' }, i.intervalSec ? sec(i.intervalSec) : '—'),
        h('span', { class: 'mono dim', style: 'font-size:12px' }, i.querier && i.upSec !== null ? ageText(i.upSec).replace(' ago', '') : '—'))))));
}

/** The rendezvous points the router knows and the group ranges they serve. */
function rpTable(rps: NonNullable<Detail['rps']>): VNode {
  return h('div', { class: 'col', style: 'gap:6px' }, h('div', { class: 'row', style: 'gap:8px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, 'Rendezvous points'),
    h('span', { class: 'dim', style: 'font-size:11.5px' }, 'SNMP does not say whether a mapping is configured by hand or learned from Auto-RP or a bootstrap router')),
    rps.inUse?.length && !rps.map.length ? h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(200px,1.4fr) 90px 80px minmax(220px,2.4fr);--w:640px' },
      h('div', { class: 'tr head' }, ...['Rendezvous point in use', 'State', 'Groups', 'Example groups'].map(t => h('span', null, t))),
      rps.inUse.map(x => h('div', { key: x.rp, class: 'tr' },
        h('span', { class: 'mono', style: 'font-size:12px' }, x.rp, ' ', x.self ? chip('this router', 'ok') : x.who ? chip(x.who, 'default') : null),
        h('span', null, x.up ? chip('up', 'ok') : chip('down', 'bad')), h('span', { class: 'mono', style: 'font-size:12px' }, num(x.groups.length)),
        h('span', { class: 'mono dim', style: 'font-size:12px' }, x.groups.slice(0, 3).join(', ') + (x.groups.length > 3 ? ` +${x.groups.length - 3}` : '')))))) : null,
    rps.map.length ? h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(150px,1fr) minmax(200px,1.6fr) 110px 110px;--w:600px' },
      h('div', { class: 'tr head' }, ...['Group range', 'Rendezvous point', 'Hold time', 'Expires in'].map(t => h('span', null, t))),
      rps.map.map(x => h('div', { key: x.range + x.rp, class: 'tr' }, h('span', { class: 'mono', style: 'font-size:12px' }, x.range),
        h('span', { class: 'mono', style: 'font-size:12px' }, x.rp, ' ', x.self ? chip('this router', 'ok') : x.who ? chip(x.who, 'default') : null),
        h('span', { class: 'mono', style: 'font-size:12px' }, x.holdSec !== null ? sec(x.holdSec) : '—'),
        h('span', { class: 'mono dim', style: 'font-size:12px' }, x.expirySec ? sec(x.expirySec) : '—'))))) : null,
    rps.candidate.length ? h('div', { class: 'dim', style: 'font-size:12.5px' }, 'This router is a candidate rendezvous point for ', rps.candidate.map(x => `${x.range} (${x.rp})`).join(', ')) : null);
}

/** Multicast bytes through each interface: replication multiplies it, so an interface can carry far more multicast out than came in. */
function loadTable(list: NonNullable<Detail['load']>): VNode {
  const shown = list.slice(0, 20);
  return h('div', { class: 'col', style: 'gap:6px' }, h('div', { class: 'row', style: 'gap:8px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, 'Multicast load by interface'),
    h('span', { class: 'dim', style: 'font-size:11.5px' }, 'rate since the previous read, and the total since the counters started')),
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(140px,1fr) 110px 110px 130px 130px 90px;--w:700px' },
      h('div', { class: 'tr head' }, ...['Interface', 'Rate in', 'Rate out', 'Bytes in', 'Bytes out', 'Limit'].map(t => h('span', null, t))),
      shown.map(x => h('div', { key: x.name, class: 'tr' }, h('span', { class: 'mono', style: 'font-size:12px' }, x.name),
        h('span', { class: 'mono', style: 'font-size:12px' }, x.inBps === null ? '—' : bps(x.inBps)), h('span', { class: 'mono', style: 'font-size:12px' }, x.outBps === null ? '—' : bps(x.outBps)),
        h('span', { class: 'mono', style: 'font-size:12px' }, x.inOctets === null ? '—' : num(x.inOctets)), h('span', { class: 'mono', style: 'font-size:12px' }, x.outOctets === null ? '—' : num(x.outOctets)),
        h('span', { class: 'dim', style: 'font-size:12px' }, x.rateLimit ? `${num(x.rateLimit)} kbps` : x.ttl ? `TTL ${x.ttl}` : 'none'))))),
    list.length > shown.length ? h('span', { class: 'dim', style: 'font-size:12px' }, `${list.length - shown.length} quieter interfaces not shown`) : null);
}

/** Rows per page and the page buttons. The search runs over every route of the device, not only the page on screen. */
function pager(total: number, pages: number, from: number, to: number): VNode {
  return h('div', { class: 'row', style: 'gap:10px;flex-wrap:wrap;align-items:center;justify-content:space-between', role: 'navigation', 'aria-label': 'Pages' },
    h('span', { class: 'dim', style: 'font-size:12.5px' }, `${num(from)}–${num(to)} of ${num(total)} group${total === 1 ? '' : 's'}`),
    h('div', { class: 'row', style: 'gap:8px;align-items:center' },
      h('span', { class: 'dim', style: 'font-size:12.5px' }, 'Rows per page'),
      select(String(pageSize), SIZES.map(n => [String(n), String(n)] as [string, string]), v => { pageSize = Number(v); page = 0; redraw(); }, { aria: 'Rows per page', width: '84px' }),
      btn('‹ Previous', { small: true, kind: 'ghost', disabled: page === 0, onclick: () => { page--; redraw(); } }),
      h('span', { class: 'mono', style: 'font-size:12px' }, `Page ${num(page + 1)} of ${num(pages)}`),
      btn('Next ›', { small: true, kind: 'ghost', disabled: page + 1 >= pages, onclick: () => { page++; redraw(); } })));
}
