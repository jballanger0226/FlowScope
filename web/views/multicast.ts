import { h, type VNode } from '../vdom.js';
import { get, qs } from '../api.js';
import { redraw } from '../state.js';
import { btn, chip, empty, heading, note, select, spinner, stat, status as statusEl, textInput, toggle } from '../components.js';
import { ago, bps, num, stamp } from '../util.js';

/**
 * Multicast: what each router says it does with every group it knows. NetFlow records the interface a packet arrives on, so the
 * interfaces a group is sent out of, and the hosts that asked for it, come from the router's own multicast table read over SNMP.
 */

interface DevSummary { id: number; name: string; ip: string; role: string; readAt: number; stale: boolean; source: 'cisco' | 'standard'; routes: number; groups: number; receivers: number; forwarding: number; truncated: boolean }
interface HostAt { dev: string; port: string; vlan: number; confidence: string; neighbor: string | null }
interface Join { reporter: string | null; expirySec: number | null; self: boolean }
interface Out { ifIndex: number; name: string; forwarding: boolean; linkDown?: boolean; pkts: number | null; neighbor: string | null; joins: Join[] }
interface Route {
  group: string; source: string; sharedTree: boolean; inIf: string | null; upstream: string | null; rp: string | null; bps: number | null; pkts: number | null; flags: string[]; protocol: number | null; expirySec: number | null; out: Out[];
}
interface Detail {
  device: { id: number; name: string; ip: string; role: string }; readAt: number; stale: boolean; source: 'cisco' | 'standard'; truncated: boolean; routes: Route[];
  pim: { interfaces: { name: string; mode: string; dr: string | null }[]; neighbors: { address: string; ifName: string }[] };
  hosts?: Record<string, HostAt | null>;
  load?: { name: string; inBps: number | null; outBps: number | null; inOctets: number | null; outOctets: number | null; ttl: number | null; rateLimit: number | null }[];
}

let devs: DevSummary[] | null = null; let devError = '';
let devId = 0; let detail: Detail | null = null; let detailError = ''; let loading = false;
let query = ''; let onlyForwarding = false; let hideIdle = false;
const open = new Set<string>();
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
  const g = p.get('g'); if (g) { open.add(g); query = query || g; }
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

function pickDevice(v: string): void { page = 0; devId = Number(v); detail = null; open.clear(); void loadDetail(); }

const rate = (r: Route): string => (r.bps === null ? '—' : r.bps === 0 ? '0' : bps(r.bps));
const sec = (s: number | null): string => (s === null ? '—' : s < 90 ? `${s}s` : `${Math.round(s / 60)}m`);

function matches(r: Route, q: string): boolean {
  if (!q) return true;
  const hay = [r.group, r.source === '0.0.0.0' ? '* shared' : r.source, at(r.source), r.inIf ?? '', r.rp ?? '', r.upstream ?? '', ...r.out.map(o => o.name), ...r.out.flatMap(o => o.joins.flatMap(j => [j.reporter ?? '', at(j.reporter)]))].join(' ').toLowerCase();
  return q.toLowerCase().split(/\s+/).filter(Boolean).every(t => hay.includes(t));
}

const keyOf = (r: Route) => r.group + '|' + r.source;

function outChips(r: Route): VNode {
  const fwd = r.out.filter(o => o.forwarding), pruned = r.out.length - fwd.length;
  if (!r.out.length) return h('span', { class: 'dim', title: 'The router has the route but nothing downstream has asked for the group, so it is not sent anywhere.' }, 'nowhere');
  return h('span', { class: 'mono', style: 'font-size:12px' }, fwd.slice(0, 4).map(o => o.name).join(', '), fwd.length > 4 ? ` +${fwd.length - 4}` : '', pruned ? h('span', { class: 'dim', title: 'Pruned: in the list but no one downstream wants the group' }, ` (${pruned} pruned)`) : null);
}

function expanded(r: Route): VNode {
  const cols = 'minmax(140px,1fr) 110px minmax(150px,1.2fr) minmax(200px,2fr) 90px';
  return h('div', { class: 'mcdetail', style: 'padding:6px 12px 14px' },
    h('div', { class: 'row', style: 'gap:8px 18px;flex-wrap:wrap;color:var(--muted);font-size:12.5px;margin-bottom:8px' },
      h('span', null, r.sharedTree ? 'Shared tree (*,G)' : `Source ${r.source}`, !r.sharedTree && at(r.source) ? h('span', null, ' · plugged in at ', h('b', { class: 'mono' }, at(r.source))) : null),
      r.inIf ? h('span', null, 'Arrives on ', h('b', { class: 'mono' }, r.inIf)) : null,
      r.upstream ? h('span', null, 'Upstream ', h('b', { class: 'mono' }, r.upstream)) : null,
      r.rp ? h('span', null, 'Rendezvous point ', h('b', { class: 'mono' }, r.rp)) : null,
      r.pkts !== null ? h('span', null, `${num(r.pkts)} packets`) : null,
      r.expirySec !== null ? h('span', null, r.expirySec === 0 ? 'route does not age out' : `route expires in ${sec(r.expirySec)}`) : null,
      r.flags.length ? h('span', null, 'Flags: ', r.flags.join(', ')) : null),
    r.out.length ? h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${cols};--w:780px` },
      h('div', { class: 'tr head' }, ...['Sent out of', 'State', 'Reaches', 'Hosts that joined (IGMP)', 'Packets'].map(t => h('span', null, t))),
      r.out.map(o => h('div', { key: o.ifIndex, class: 'tr' },
        h('span', { class: 'mono', style: 'font-size:12px' }, o.name),
        h('span', null, o.linkDown ? chip('link down', 'bad', 'The route lists this interface' + (o.forwarding ? ' as forwarding' : '') + ', but the port is not up, so nothing is arriving over it') : o.forwarding ? chip('forwarding', 'ok') : chip('pruned', 'default', 'Listed, but no one downstream wants the group')),
        h('span', { class: 'mono dim', style: 'font-size:12px' }, o.neighbor ? `PIM neighbour ${o.neighbor}` : o.joins.length ? 'hosts on this segment' : '—'),
        h('span', { class: 'mono', style: 'font-size:12px' }, o.joins.length ? o.joins.slice(0, 4).map(j => (j.self ? 'this router' : (j.reporter ?? '?') + (at(j.reporter) ? ` on ${at(j.reporter)}` : '')) + (j.expirySec !== null ? ` (${sec(j.expirySec)})` : '')).join(', ') + (o.joins.length > 4 ? ` +${o.joins.length - 4}` : '') : h('span', { class: 'dim' }, o.neighbor ? 'via the neighbour' : 'none seen')),
        h('span', { class: 'mono', style: 'font-size:12px' }, num(o.pkts)))))) : note('Nothing is joined downstream of this router, so it forwards this group nowhere.', 'info'));
}

function table(d: Detail): VNode {
  const rows = d.routes.filter(r => matches(r, query) && (!onlyForwarding || r.out.some(o => o.forwarding)) && (!hideIdle || (r.bps ?? 1) > 0));
  const pages = Math.max(1, Math.ceil(rows.length / pageSize));
  if (page >= pages) page = pages - 1;
  const shown = rows.slice(page * pageSize, (page + 1) * pageSize);
  const cols = '28px minmax(120px,1fr) minmax(110px,1fr) minmax(90px,0.8fr) minmax(200px,2fr) 90px minmax(100px,0.9fr)';
  return h('div', null,
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${cols};--w:900px` },
      h('div', { class: 'tr head' }, ...['', 'Group', 'Source', 'Arrives on', 'Sent out of', 'Rate', 'Rendezvous point'].map(t => h('span', null, t))),
      shown.map(r => {
        const k = keyOf(r), on = open.has(k);
        return h('div', { key: k }, h('div', {
          class: 'tr', role: 'button', tabindex: 0, 'aria-expanded': on, style: 'cursor:pointer',
          onclick: () => { if (on) open.delete(k); else open.add(k); redraw(); },
          onkeydown: (e: KeyboardEvent) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); if (on) open.delete(k); else open.add(k); redraw(); } }
        },
        h('span', { class: 'dim', 'aria-hidden': 'true' }, on ? '▾' : '▸'),
        h('span', { class: 'mono', style: 'font-weight:600' }, r.group),
        h('span', { class: 'mono', style: 'font-size:12px' }, r.sharedTree ? h('span', { class: 'dim', title: 'Any source: the shared tree (*,G)' }, '* (any source)') : r.source),
        h('span', { class: 'mono', style: 'font-size:12px' }, r.inIf ?? '—'),
        outChips(r),
        h('span', { class: 'mono', style: 'font-size:12px' }, rate(r)),
        h('span', { class: 'mono dim', style: 'font-size:12px' }, r.rp ?? '—')), on ? expanded(r) : null);
      }),
      !shown.length ? empty(d.routes.length ? 'No routes match the filter.' : 'This device holds no multicast routes.') : null)),
    rows.length ? pager(rows.length, pages, page * pageSize + 1, page * pageSize + shown.length) : null);
}

function summary(s: DevSummary): VNode {
  return h('div', { class: 'row', style: 'gap:12px;flex-wrap:wrap' },
    stat('Groups', num(s.groups), `${num(s.routes)} routes`),
    stat('Forwarding', num(s.forwarding), 'routes with receivers'),
    stat('IGMP joins', num(s.receivers), 'hosts reported'));
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
      cur?.truncated ? note('This device holds more routes than FlowScope keeps. The list is cut off.', 'warn') : null,
      h('div', { class: 'row', style: 'gap:12px;align-items:center;flex-wrap:wrap' },
        textInput(query, v => { query = v; page = 0; }, { placeholder: 'Search groups and source hosts: 239.1.1.1, 10.2.3.4, a port, a switch…', aria: 'Search groups and source hosts', width: '420px', id: 'mc-filter' }),
        toggle('Only groups with receivers', onlyForwarding, () => { onlyForwarding = !onlyForwarding; page = 0; redraw(); }),
        cur?.source === 'cisco' ? toggle('Hide idle routes', hideIdle, () => { hideIdle = !hideIdle; page = 0; redraw(); }, { onText: 'Hiding idle', offText: 'Showing idle' }) : null),
      loading && !detail ? spinner('Loading routes…') : null,
      detailError ? note(detailError, 'warn', true) : null,
      detail ? table(detail) : null,
      detail?.load?.length ? loadTable(detail.load) : null,
      detail && detail.pim.neighbors.length ? h('div', { class: 'dim', style: 'font-size:12.5px' }, 'PIM neighbours: ', detail.pim.neighbors.map(n => `${n.address} on ${n.ifName}`).join(', ')) : null) : null);
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
    h('span', { class: 'dim', style: 'font-size:12.5px' }, `${num(from)}–${num(to)} of ${num(total)} route${total === 1 ? '' : 's'}`),
    h('div', { class: 'row', style: 'gap:8px;align-items:center' },
      h('span', { class: 'dim', style: 'font-size:12.5px' }, 'Rows per page'),
      select(String(pageSize), SIZES.map(n => [String(n), String(n)] as [string, string]), v => { pageSize = Number(v); page = 0; redraw(); }, { aria: 'Rows per page', width: '84px' }),
      btn('‹ Previous', { small: true, kind: 'ghost', disabled: page === 0, onclick: () => { page--; redraw(); } }),
      h('span', { class: 'mono', style: 'font-size:12px' }, `Page ${num(page + 1)} of ${num(pages)}`),
      btn('Next ›', { small: true, kind: 'ghost', disabled: page + 1 >= pages, onclick: () => { page++; redraw(); } })));
}
