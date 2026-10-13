import { h, type VNode } from '../vdom.js';
import { get, qs } from '../api.js';
import { session, redraw, go } from '../state.js';
import { btn, chip, empty, field, heading, note, seg, select, spinner, status as statusEl, dot } from '../components.js';
import { bytes, clock, dayClock, dur, ms, num, RANGES, stamp, debounce } from '../util.js';

interface Row {
  id: string; srcIp: string; dstIp: string; sport: number; dport: number; proto: number; protoName: string; app: string; vlan: number | null; vlanName: string;
  t0: number; t1: number; bytes: number; pkts: number; fwdBytes: number; revBytes: number; hopCount: number; hops: string[]; qosChanged: boolean;
  ttlExpired: boolean; ttlReason: 'ttl' | 'icmp' | null; ttlLow: number | null;
  dscpInS: string; dscpOutS: string | null; flags: number; health: { kind: 'ok' | 'warn' | 'bad'; text: string } | null;
}
interface Hop {
  n: number; exporter: string; dev: string; role: string; inIf: string; outIf: string; frameSrc: string | null; frameDst: string | null; vlan: number | null; vlanName: string;
  ttl: number | null; ttlExpired: 'ttl' | 'icmp' | null; dscpInS: string; dscpOutS: string; qosChanged: boolean; pkts: number; bytes: number; linkMs: number | null; cumMs: number | null; policy: string | null;
  obs: { kind: string; text: string; severity: 'info' | 'warn' | 'bad' }[]; firstSeen: number; lastSeen: number;
  outIfs?: string[]; sourcePort?: string | null; sourceConfirmed?: boolean;
}
interface Attach { dev: string; ifName: string; vlan: number; macCount: number; edge: boolean; neighbor: string | null; neighborKind: string | null; portMode: string; confidence?: 'high' | 'medium' | 'low' }
interface Located { ip: string | null; macs: string[]; macSource: string; attach: Attach | null; others: Attach[]; note: string }
interface Multicast { group: string; source: string; location: Located | null }
interface Detail {
  skey: string; initiator: { ip: string; port: number }; responder: { ip: string; port: number }; proto: number; protoName: string; app: string; t0: number; t1: number;
  forward: Hop[]; reverse: Hop[]; qosChanged: boolean; ttlExpired: boolean; totals: { fwdBytes: number; revBytes: number; fwdPkts: number; revPkts: number }; note: string | null; multicast: Multicast | null;
  activity: { t0: number; t1: number; fwd: number[]; rev: number[] };
}

let q = '';
const protos = { tcp: true, udp: true, icmp: true };
let qosOnly = false;
let ttlOnly = false;
let range = '6h';
let sort: { key: 'time' | 'bytes' | 'pkts'; dir: 'asc' | 'desc' } = { key: 'time', dir: 'desc' };
let rows: Row[] = []; let total = 0; let truncated = false; let errors: string[] = [];
let loading = false; let loadError = '';
let selId = '';
let detail: Detail | null = null; let detailError = ''; let detailLoading = false;
let reverse = false;
let related: Row[] = [];
let live = false; let liveTimer: number | undefined;

export function enter(p: URLSearchParams): void {
  const nq = p.get('q'), ns = p.get('s'), nr = p.get('range');
  let changed = false;
  if (nq !== null && nq !== q) { q = nq; changed = true; }
  if (nr && nr !== range && RANGES.some(r => r[0] === nr)) { range = nr; changed = true; }
  if ((ns ?? '') !== selId) { selId = ns ?? ''; detail = null; related = []; if (selId) void loadDetail(); }
  if (changed || !rows.length) void load();
  setLive();
}

function setLive(): void {
  window.clearInterval(liveTimer);
  if (live && session.view === 'explorer') liveTimer = window.setInterval(() => { if (session.view === 'explorer' && !document.hidden) void load(true); }, 15_000);
}

function fullQuery(): string {
  const parts = [q.trim()];
  const on = (['tcp', 'udp', 'icmp'] as const).filter(k => protos[k]);
  if (on.length < 3) parts.push('proto:' + on.join(','));
  if (qosOnly) parts.push('qos:changed');
  if (ttlOnly) parts.push('ttl:expired');
  return parts.filter(Boolean).join(' ');
}

function syncHash(): void {
  const p = new URLSearchParams();
  if (q.trim()) p.set('q', q.trim());
  if (selId) p.set('s', selId);
  if (range !== '6h') p.set('range', range);
  const s = p.toString();
  history.replaceState(null, '', '#/explorer' + (s ? '?' + s : ''));
}

let seq = 0;
async function load(quiet = false): Promise<void> {
  const my = ++seq;
  if (!quiet) { loading = true; loadError = ''; redraw(); }
  try {
    const r = await get<{ rows: Row[]; total: number; truncated: boolean; errors: string[] }>('/api/streams' + qs({ range, q: fullQuery(), sort: sort.key, dir: sort.dir, limit: 200 }));
    if (my !== seq) return;
    rows = r.rows; total = r.total; truncated = r.truncated; errors = r.errors; loadError = '';
  } catch (e) { if (my === seq) { loadError = (e as Error).message; rows = []; total = 0; } }
  if (my === seq) { loading = false; redraw(); }
}
const loadSoon = debounce(() => { void load(); }, 350);

async function loadDetail(): Promise<void> {
  const id = selId; detailLoading = true; detailError = ''; redraw();
  try {
    const d = await get<Detail>('/api/streams/detail' + qs({ id, range: bigRange() }));
    if (id !== selId) return;
    detail = d; reverse = false;
    void loadRelated(d);
  } catch (e) { if (id === selId) { detail = null; detailError = (e as Error).message; } }
  detailLoading = false; redraw();
}
/** Detail is looked up over a wider window than the list, so a stream found a while ago can still be opened. */
function bigRange(): string { return range === '15m' || range === '1h' ? '24h' : range === '6h' ? '24h' : range; }

async function loadRelated(d: Detail): Promise<void> {
  try {
    const r = await get<{ rows: Row[] }>('/api/streams' + qs({ range: bigRange(), q: `ip:${d.initiator.ip} ip:${d.responder.ip}`, sort: 'bytes', limit: 8 }));
    if (selId === d.skey) { related = r.rows.filter(x => x.id !== d.skey).slice(0, 5); redraw(); }
  } catch { /* related conversations are optional */ }
}

function pick(id: string): void { selId = selId === id ? '' : id; detail = null; related = []; syncHash(); if (selId) void loadDetail(); else redraw(); }

/* ------------------------------------------------------------------ rendering */

const FLAGS: [string, number][] = [['FIN', 1], ['SYN', 2], ['RST', 4], ['PSH', 8], ['ACK', 16], ['URG', 32]];
const flagText = (f: number) => (f ? FLAGS.filter(([, b]) => f & b).map(([n]) => n).join(' ') : '—');
const PROTO_COLOR: Record<string, string> = { TCP: 'var(--info)', UDP: 'var(--accent)', ICMP: 'var(--violet)' };

function search(): VNode {
  const meta = session.meta;
  const tokens = q.trim() ? q.trim().split(/\s+/) : [];
  return h('section', { 'aria-label': 'Search flows', class: 'col', style: 'gap:12px' },
    h('div', { class: 'row' },
      h('div', { class: 'search' },
        h('svg', { 'aria-hidden': 'true', width: 18, height: 18, viewBox: '0 0 24 24', fill: 'none', 'stroke-width': 2, 'stroke-linecap': 'round', style: 'stroke:var(--muted)' }, h('circle', { cx: 11, cy: 11, r: 7 }), h('path', { d: 'M20 20l-3.5-3.5' })),
        h('input', { class: 'input', type: 'text', value: q, 'aria-label': 'Search flows', spellcheck: 'false', autocomplete: 'off',
          placeholder: 'Search IP, CIDR, MAC, port, service, device…   e.g. src:10.1.4.0/24 app:https hop:fw-edge-01',
          oninput: (e: Event) => { q = (e.target as HTMLInputElement).value; selId = selId; loadSoon(); redraw(); },
          onkeydown: (e: KeyboardEvent) => { if (e.key === 'Enter') { syncHash(); void load(); } } })),
      seg('Protocol filter', (['tcp', 'udp', 'icmp'] as const).map(k => ({ id: k, label: k.toUpperCase(), on: protos[k] })), id => {
        const k = id as 'tcp' | 'udp' | 'icmp';
        if (protos[k] && Object.values(protos).filter(Boolean).length === 1) return;   // keep at least one
        protos[k] = !protos[k]; void load(); redraw();
      }),
      select(range, RANGES, v => { range = v; syncHash(); void load(); if (selId) void loadDetail(); }, { aria: 'Time range', width: '176px' }),
      btn('QoS re-marked only', { pressed: qosOnly, onclick: () => { qosOnly = !qosOnly; void load(); redraw(); } }),
      btn('TTL expired only', { pressed: ttlOnly, title: 'Streams whose TTL ran out before they reached the destination', onclick: () => { ttlOnly = !ttlOnly; void load(); redraw(); } }),
      btn(live ? 'Live: on' : 'Live: off', { pressed: live, title: 'Refresh the list every 15 seconds', onclick: () => { live = !live; setLive(); redraw(); } }),
      btn('Refresh', { kind: 'ghost', onclick: () => void load() })),
    h('div', { class: 'row', style: 'gap:8px' },
      h('span', { class: 'muted' }, 'Try'),
      (meta?.examples ?? ['qos:changed', 'src:10.1.4.0/24', 'app:smb', 'hop:fw-edge-01', 'vlan:150']).slice(0, 8).map(ex => h('button', { key: ex, type: 'button', class: 'btn small ghost mono', onclick: () => { q = ex; syncHash(); void load(); redraw(); } }, ex)),
      tokens.length ? [h('span', { class: 'muted' }, 'Parsed:'), tokens.map((t, i) => chip(t, 'accent'))] : null,
      tokens.length ? btn('Clear search', { small: true, kind: 'ghost', onclick: () => { q = ''; syncHash(); void load(); redraw(); } }) : null),
    errors.length ? note(errors.join('. '), 'warn', true) : null);
}

const COLS = '78px minmax(160px,1.4fr) minmax(160px,1.4fr) 60px 100px 150px 80px 72px 48px 116px 112px 108px';

function qosTag(r: Row): VNode {
  if (!r.qosChanged) return h('span', { class: 'dim' }, '—');
  return h('span', { class: 'tag bad' }, r.dscpOutS ? `${r.dscpInS.replace(/ \(\d+\)/, '')} → ${r.dscpOutS.replace(/ \(\d+\)/, '')}` : 'changed');
}

function ttlTag(r: Row): VNode {
  if (!r.ttlExpired) return h('span', { class: 'dim' }, '—');
  const why = r.ttlReason === 'icmp' ? 'An ICMP Time Exceeded message: a router reported that a packet ran out of TTL' : `An exporter saw this traffic with TTL ${r.ttlLow}: the next router had to drop it, so it did not reach ${r.dstIp}`;
  return h('span', { class: 'tag bad', title: why }, r.ttlReason === 'icmp' ? 'TTL notice' : 'TTL expired');
}

function list(): VNode {
  const hdrBtn = (label: string, key: 'time' | 'bytes' | 'pkts') => h('button', { type: 'button', class: 'sortbtn', onclick: () => { sort = sort.key === key ? { key, dir: sort.dir === 'desc' ? 'asc' : 'desc' } : { key, dir: 'desc' }; void load(); } },
    label + (sort.key === key ? (sort.dir === 'desc' ? ' ↓' : ' ↑') : ''));
  const qosCount = rows.filter(r => r.qosChanged).length;
  const ttlCount = rows.filter(r => r.ttlExpired).length;
  return h('section', { 'aria-label': 'Flow results', class: 'col', style: 'gap:10px' },
    qosCount && !qosOnly ? h('div', { class: 'note bad row', style: 'justify-content:space-between' },
      h('span', null, h('b', null, `${qosCount} stream${qosCount === 1 ? '' : 's'}`), ' had their QoS marking (DSCP) changed somewhere along the path.'),
      btn('Show only these', { kind: 'danger', onclick: () => { qosOnly = true; void load(); redraw(); } })) : null,
    ttlCount && !ttlOnly ? h('div', { class: 'note bad row', style: 'justify-content:space-between' },
      h('span', null, h('b', null, `${ttlCount} stream${ttlCount === 1 ? '' : 's'}`), ' had the TTL expire before reaching the destination, or a router reported Time Exceeded for them.'),
      btn('Show only these', { kind: 'danger', onclick: () => { ttlOnly = true; void load(); redraw(); } })) : null,
    h('div', { class: 'row', style: 'justify-content:space-between;color:var(--muted)' },
      h('span', { 'aria-live': 'polite' }, loading ? 'Searching…' : loadError ? '' : `${num(rows.length)} of ${num(total)} stream${total === 1 ? '' : 's'} shown${truncated ? ' (more exist: narrow the search)' : ''}`),
      h('span', null, 'Select a flow to follow the stream and inspect it hop by hop')),
    loadError ? note(loadError, 'bad', true) : null,
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${COLS};--w:1410px` },
      h('div', { class: 'tr head' }, hdrBtn('Time', 'time'), h('span', null, 'Source'), h('span', null, 'Destination'), h('span', null, 'Proto'), h('span', null, 'Service'), h('span', null, 'VLAN'), hdrBtn('Bytes', 'bytes'), hdrBtn('Pkts', 'pkts'), h('span', null, 'Hops'), h('span', null, 'Status'), h('span', null, 'QoS'), h('span', null, 'TTL')),
      h('div', { class: 'scroll' },
        rows.map(r => h('button', { key: r.id, type: 'button', class: 'tr', 'aria-pressed': selId === r.id, onclick: () => pick(r.id) },
          h('span', { class: 'mono muted', style: 'font-size:12px' }, dayClock(r.t0)),
          h('span', { class: 'mono' }, r.srcIp, r.sport ? h('span', { class: 'dim' }, ':' + r.sport) : null),
          h('span', { class: 'mono' }, r.dstIp, r.dport ? h('span', { class: 'dim' }, ':' + r.dport) : null),
          h('span', { style: `font-weight:500;color:${PROTO_COLOR[r.protoName] ?? 'var(--text2)'}` }, r.protoName),
          h('span', null, r.app),
          h('span', { class: 'mono muted', style: 'font-size:12px' }, r.vlan ? String(r.vlan) : '—', ' ', h('span', { class: 'dim' }, r.vlanName)),
          h('span', { class: 'mono', style: 'font-size:12px' }, bytes(r.bytes)),
          h('span', { class: 'mono', style: 'font-size:12px' }, num(r.pkts)),
          h('span', { class: 'mono muted', style: 'font-size:12px' }, String(r.hopCount)),
          r.health ? statusEl(r.health.kind, r.health.text) : h('span', { class: 'dim' }, '—'),
          qosTag(r), ttlTag(r))),
        !rows.length && !loading ? empty('No flows match this search. Loosen the filters, widen the time range, or clear the search.') : null,
        loading && !rows.length ? spinner('Searching…') : null))));
}

/* ------------------------------------------------------------------ the followed stream */

function qosMessage(d: Detail): { text: string; dev?: string; ifName?: string } | null {
  for (const [dirName, hops] of [['initiator → responder', d.forward], ['responder → initiator', d.reverse]] as const) {
    for (const hp of hops) {
      if (hp.qosChanged) return { text: `${hp.dscpInS} → ${hp.dscpOutS} by the egress policy on ${hp.dev} (${hp.outIf}), ${dirName}.`, dev: hp.dev, ifName: hp.outIf };
    }
    for (let i = 1; i < hops.length; i++) {
      const ob = hops[i].obs.find(o => o.kind === 'remark' && o.text.startsWith('DSCP arrived'));
      if (ob) return { text: `${ob.text}. The marking changed between ${hops[i - 1].dev} and ${hops[i].dev}, ${dirName}.`, dev: hops[i - 1].dev, ifName: hops[i - 1].outIf };
    }
  }
  return d.qosChanged ? { text: 'The marking differs between hops.' } : null;
}

function ttlMessage(d: Detail): { text: string } | null {
  for (const [dirName, hops] of [['initiator → responder', d.forward], ['responder → initiator', d.reverse]] as const) {
    for (const hp of hops) {
      const ob = hp.obs.find(o => o.kind === 'ttl');
      if (ob) return { text: `${ob.text} (${dirName}).` };
    }
  }
  return d.ttlExpired ? { text: 'The TTL ran out before this stream reached its destination.' } : null;
}

function strip(hops: Hop[], d: Detail): VNode {
  const items: VNode[] = [];
  const src = reverse ? d.responder : d.initiator, dst = reverse ? d.initiator : d.responder;
  items.push(h('div', { key: 'src', class: 'node edge' }, h('b', { class: 'mono' }, src.ip), h('span', null, 'source host'), h('span', { class: 'mono' }, src.port ? ':' + src.port : '')));
  hops.forEach((hp, i) => {
    const slow = hp.obs.some(o => o.kind === 'slow'), loss = hp.obs.some(o => o.kind === 'loss');
    items.push(h('div', { key: 'l' + i, class: 'link' + (loss ? ' loss' : slow ? ' slow' : '') },
      h('span', null, i === 0 ? '' : hp.linkMs === null ? '?' : ms(hp.linkMs)), h('i'),
      h('span', { class: 'flag' }, loss ? 'loss' : slow ? 'slow' : '')));
    items.push(h('div', { key: 'n' + i, class: 'node' + (hp.qosChanged || hp.ttlExpired ? ' remark' : '') },
      h('b', null, hp.dev), h('span', null, hp.role), h('span', { class: 'mono' }, `${hp.inIf} → ${hp.outIf}`),
      hp.policy ? h('span', null, 'policy ' + hp.policy) : null, hp.qosChanged ? h('span', { style: 'color:var(--bad)' }, `${hp.dscpInS} → ${hp.dscpOutS}`) : null, hp.ttlExpired ? h('span', { style: 'color:var(--bad)' }, hp.ttlExpired === 'icmp' ? 'TTL exceeded notice' : `TTL ${hp.ttl ?? 1}: expired here`) : null));
  });
  items.push(h('div', { key: 'lend', class: 'link' }, h('span'), h('i'), h('span')));
  items.push(h('div', { key: 'dst', class: 'node edge' }, h('b', { class: 'mono' }, dst.ip), h('span', null, 'destination host'), h('span', { class: 'mono' }, dst.port ? ':' + dst.port : '')));
  return h('div', { class: 'panel flush' }, h('div', { class: 'strip', role: 'img', 'aria-label': `Path: ${[src.ip, ...hops.map(x => x.dev), dst.ip].join(' to ')}` }, items));
}

/**
 * A multicast stream is one source and many receivers. Every switch on the tree sees the same packets, so the devices below are not ordered
 * and none of them is "the" first hop. Where the source host is plugged in comes from the switches' MAC address tables, not from the flow records.
 */
function multicastStrip(hops: Hop[], d: Detail, m: Multicast): VNode {
  const at = m.location?.attach ?? null;
  const conf = at?.confidence;
  const sourceCard = h('div', { class: 'node edge', style: 'min-width:220px' },
    h('b', { class: 'mono' }, m.source), h('span', null, 'source host'),
    at ? [h('span', { style: 'color:var(--text)' }, `Plugged in to ${at.dev} ${at.ifName}`), h('span', null, [at.vlan ? `VLAN ${at.vlan}` : null, conf ? `${conf} confidence` : null].filter(Boolean).join(' · '))]
      : h('span', { style: 'color:var(--warn)' }, 'Location not known'));
  const groupCard = h('div', { class: 'node edge', style: 'min-width:170px' }, h('b', { class: 'mono' }, m.group), h('span', null, 'multicast group'), h('span', { class: 'mono' }, d.responder.port ? ':' + d.responder.port : ''), h('span', null, d.app));
  return h('div', { class: 'panel flush' }, h('div', { class: 'mctree', role: 'group', 'aria-label': `Multicast group ${m.group} from ${m.source}, seen by ${hops.length} device${hops.length === 1 ? '' : 's'}` },
    sourceCard, h('div', { class: 'mclink', 'aria-hidden': 'true' }, h('i')), groupCard, h('div', { class: 'mclink', 'aria-hidden': 'true' }, h('i')),
    h('div', { class: 'mcset' },
      h('span', { class: 'eyebrow' }, `Seen by ${hops.length} device${hops.length === 1 ? '' : 's'} (in no particular order)`),
      h('div', { class: 'mcgrid' }, hops.map((hp, i) => {
        const here = !!hp.sourcePort;
        return h('div', { key: i, class: 'node' + (here ? ' here' : '') + (hp.qosChanged ? ' remark' : '') },
          h('b', null, hp.dev), h('span', null, hp.role),
          h('span', { class: 'mono' }, `in ${hp.inIf || '—'}`),
          h('span', { class: 'mono' }, hp.outIfs && hp.outIfs.length > 1 ? `out ${hp.outIfs.length} interfaces` : `out ${hp.outIf || '—'}`),
          hp.outIfs && hp.outIfs.length > 1 ? h('span', { class: 'mono', title: hp.outIfs.join(', ') }, hp.outIfs.slice(0, 3).join(', ') + (hp.outIfs.length > 3 ? ', …' : '')) : null,
          here ? h('span', { style: 'color:var(--accent);font-weight:600' }, hp.sourceConfirmed ? `Source host is on ${hp.sourcePort}` : `Source host is on ${hp.sourcePort} (this switch's flow data shows ${hp.inIf})`) : null,
          hp.qosChanged ? h('span', { style: 'color:var(--bad)' }, `${hp.dscpInS} → ${hp.dscpOutS}`) : null);
      })))));
}

function multicastExplain(d: Detail, m: Multicast): VNode {
  const loc = m.location;
  return h('div', { class: 'note info' },
    h('b', null, 'This is a multicast stream: one source, many receivers'),
    h('div', null, 'Every switch and router that forwards the group reports the same packets, so each one appears once, side by side. They are not hops in a line, and no delay or loss is worked out between them. The receivers themselves are not listed because multicast flow data only shows the sending side.'),
    loc?.attach ? h('div', { style: 'margin-top:6px' }, `The source ${m.source} was found plugged in to ${loc.attach.dev} ${loc.attach.ifName}${loc.attach.vlan ? ' (VLAN ' + loc.attach.vlan + ')' : ''} by reading the MAC address tables${loc.macSource === 'arp' ? ' and ARP' : ''}, ${loc.attach.confidence} confidence.${loc.attach.confidence !== 'high' && loc.note ? ' ' + loc.note : ''}`)
      : h('div', { style: 'margin-top:6px' }, `The switch that ${m.source} is plugged in to is not known${loc?.note ? ': ' + loc.note : '. Host tracking has not learned this address yet, or its switch is not polled over SNMP.'} It is not guessed from the flow data.`));
}

function multicastTable(hops: Hop[]): VNode {
  const cols = 'minmax(140px,1.1fr) minmax(170px,1.3fr) minmax(150px,1.2fr) 110px 44px 110px 70px 70px minmax(200px,1.6fr)';
  return h('div', { class: 'tbl hops' }, h('div', { class: 'inner', style: `--cols:${cols};--w:1100px` },
    h('div', { class: 'tr head' }, ...['Device', 'Interfaces', 'Frame in (L2)', 'VLAN', 'TTL', 'DSCP', 'Packets', 'Bytes', 'Observations'].map(t => h('span', null, t))),
    hops.map((hp, i) => h('div', { key: i, class: 'tr' },
      h('div', null, h('div', { style: 'font-weight:600' }, hp.dev), h('div', { class: 'dim', style: 'font-size:12px' }, hp.role), h('div', { class: 'dim mono', style: 'font-size:11.5px' }, hp.exporter)),
      h('div', { class: 'mono', style: 'font-size:12px' }, h('div', null, h('span', { class: 'dim' }, 'in '), hp.inIf || '—'), h('div', null, h('span', { class: 'dim' }, 'out '), (hp.outIfs && hp.outIfs.length ? hp.outIfs : [hp.outIf]).join(', ') || '—'),
        hp.sourcePort ? h('div', { style: 'color:var(--accent)' }, `source host on ${hp.sourcePort}`) : null),
      h('div', { class: 'mono', style: 'font-size:12px' }, h('div', null, h('span', { class: 'dim' }, 'src '), hp.frameSrc ?? '—'), h('div', null, h('span', { class: 'dim' }, 'dst '), hp.frameDst ?? '—')),
      h('span', { class: 'mono', style: 'font-size:12px' }, hp.vlan ? String(hp.vlan) : '—', ' ', h('span', { class: 'dim' }, hp.vlanName)),
      h('span', { class: 'mono', style: 'font-size:12px' }, hp.ttl === null ? '—' : String(hp.ttl)),
      h('span', { style: 'font-size:12px' }, hp.qosChanged ? h('span', { class: 'tag bad' }, `${hp.dscpInS} → ${hp.dscpOutS}`) : hp.dscpInS),
      h('span', { class: 'mono', style: 'font-size:12px' }, num(hp.pkts)), h('span', { class: 'mono', style: 'font-size:12px' }, bytes(hp.bytes)),
      h('div', { class: 'obs' }, hp.obs.length ? hp.obs.map((o, k) => h('span', { key: k, class: 'ob ' + o.severity }, o.text)) : h('span', { class: 'dim' }, 'Nominal'))))));
}

function hopsTable(hops: Hop[]): VNode {
  const cols = '36px minmax(130px,1.1fr) minmax(110px,1fr) minmax(150px,1.2fr) 110px 44px 110px 70px 70px 56px 56px minmax(200px,1.6fr)';
  return h('div', { class: 'tbl hops' }, h('div', { class: 'inner', style: `--cols:${cols};--w:1310px` },
    h('div', { class: 'tr head' }, ...['#', 'Exporter', 'Interfaces', 'Frame in (L2)', 'VLAN', 'TTL', 'DSCP', 'Packets', 'Bytes', 'Link', 'Cumul.', 'Observations'].map(t => h('span', null, t))),
    hops.map((hp, i) => {
      const prev = i > 0 ? hops[i - 1] : null;
      const lossPct = prev && prev.pkts > 0 && hp.pkts < prev.pkts ? ((prev.pkts - hp.pkts) / prev.pkts) * 100 : 0;
      return h('div', { key: i, class: 'tr' },
        h('span', { class: 'mono muted' }, String(hp.n)),
        h('div', null, h('div', { style: 'font-weight:600' }, hp.dev), h('div', { class: 'dim', style: 'font-size:12px' }, hp.role), h('div', { class: 'dim mono', style: 'font-size:11.5px' }, hp.exporter)),
        h('div', { class: 'mono', style: 'font-size:12px' }, h('div', null, h('span', { class: 'dim' }, 'in '), hp.inIf), h('div', null, h('span', { class: 'dim' }, 'out '), hp.outIf)),
        h('div', { class: 'mono', style: 'font-size:12px' }, h('div', null, h('span', { class: 'dim' }, 'src '), hp.frameSrc ?? '—'), h('div', null, h('span', { class: 'dim' }, 'dst '), hp.frameDst ?? '—')),
        h('span', { class: 'mono', style: 'font-size:12px' }, hp.vlan ? String(hp.vlan) : '—', ' ', h('span', { class: 'dim' }, hp.vlanName)),
        h('span', { class: 'mono', style: 'font-size:12px' }, hp.ttl === null ? '—' : String(hp.ttl)),
        h('span', { style: 'font-size:12px' }, hp.qosChanged || hp.dscpOutS !== 'not reported' && hp.dscpOutS !== hp.dscpInS ? h('span', { class: 'tag bad' }, `${hp.dscpInS} → ${hp.dscpOutS}`) : hp.dscpInS),
        h('div', { class: 'mono', style: 'font-size:12px' }, h('div', null, num(hp.pkts)), lossPct >= 0.5 ? h('div', { style: 'color:var(--bad);font-size:11.5px' }, `−${lossPct.toFixed(1)}%`) : null),
        h('span', { class: 'mono', style: 'font-size:12px' }, bytes(hp.bytes)),
        h('span', { class: 'mono', style: 'font-size:12px' }, i === 0 ? '—' : hp.linkMs === null ? '?' : ms(hp.linkMs)),
        h('span', { class: 'mono', style: 'font-size:12px' }, i === 0 ? '—' : hp.cumMs === null ? '?' : ms(hp.cumMs)),
        h('div', { class: 'obs' }, hp.obs.length ? hp.obs.map((o, k) => h('span', { key: k, class: 'ob ' + o.severity }, o.text)) : h('span', { class: 'dim' }, 'Nominal')));
    })));
}

function layers(d: Detail, r: Row | undefined, first: Hop | undefined): VNode {
  const fwdLast = d.forward[d.forward.length - 1];
  const L = [
    { tag: 'L2', name: 'Data link', items: [['Src MAC', first?.frameSrc ?? '—'], ['Dst MAC', first?.frameDst ?? '—'], ['VLAN', first?.vlan ? `${first.vlan} ${first.vlanName}`.trim() : 'untagged']] },
    { tag: 'L3', name: 'Network', items: [['Src IP', d.initiator.ip], ['Dst IP', d.responder.ip], ['Protocol', d.protoName], ['DSCP', first ? (fwdLast && fwdLast.dscpOutS !== 'not reported' && fwdLast.dscpOutS !== first.dscpInS ? `${first.dscpInS} → ${fwdLast.dscpOutS}` : first.dscpInS) : '—'], ['TTL seen', first?.ttl === null || !first ? '—' : String(first.ttl)]] },
    { tag: 'L4', name: 'Transport', items: [['Src port', String(d.initiator.port || '—')], ['Dst port', String(d.responder.port || '—')], ['Service', d.app], ['TCP flags', r ? flagText(r.flags) : '—']] }
  ];
  return h('div', { class: 'layers' }, L.map(l => h('div', { key: l.tag, class: 'layer' },
    h('div', { class: 'lh' }, chip(l.tag, l.tag === 'L2' ? 'violet' : l.tag === 'L3' ? 'info' : 'accent'), h('span', null, l.name)),
    h('div', { class: 'kvs' }, l.items.map(([k, v]) => h('div', { key: k, class: 'kv' }, h('span', { class: 'k' }, k), h('span', { class: 'v' }, v)))))));
}

function activity(d: Detail): VNode {
  const a = d.activity;
  const max = Math.max(1, ...a.fwd, ...a.rev);
  const bars = (arr: number[], cls: string) => h('div', { class: 'act ' + cls, 'aria-hidden': 'true' }, arr.map((v, i) => h('span', { key: i, style: `height:${Math.max(1, (v / max) * 100)}%`, title: bytes(v) })));
  return h('div', { class: 'layer' },
    h('div', { class: 'row', style: 'justify-content:space-between' }, h('b', null, 'Stream activity'), h('span', { class: 'muted mono', style: 'font-size:12px' }, `${clock(a.t0)} → ${clock(a.t1)}`)),
    h('div', { class: 'col', style: 'gap:6px;margin:10px 0' }, bars(a.fwd, ''), bars(a.rev, 'rev')),
    h('div', { class: 'legendrow' },
      h('span', null, h('i', { class: 'sw', style: 'background:var(--accent)' }), 'Initiator → responder · ', h('b', null, bytes(d.totals.fwdBytes))),
      h('span', null, h('i', { class: 'sw', style: 'background:var(--warn)' }), 'Responder → initiator · ', h('b', null, bytes(d.totals.revBytes)))),
    h('div', { class: 'col', style: 'gap:6px;margin-top:12px' },
      h('span', { class: 'muted' }, 'Other conversations between these hosts'),
      related.length ? related.map(r => h('button', { key: r.id, type: 'button', class: 'cardbtn', onclick: () => pick(r.id) }, h('span', { class: 't mono' }, `${r.srcIp}:${r.sport} → ${r.dstIp}:${r.dport}`), h('span', { class: 's' }, `${r.app} · ${bytes(r.bytes)}`))) : h('span', { class: 'dim' }, 'None in this time range.')));
}

function followed(): VNode | null {
  if (!selId) return null;
  if (detailLoading && !detail) return h('section', { 'aria-label': 'Selected flow' }, spinner('Loading the path…'));
  if (detailError) return h('section', { 'aria-label': 'Selected flow' }, note(detailError, 'warn', true));
  const d = detail;
  if (!d) return null;
  const row = rows.find(r => r.id === d.skey);
  const mc = d.multicast;
  const hops = mc ? d.forward : reverse ? d.reverse : d.forward;
  const all = [...d.forward, ...d.reverse];
  const lat = d.forward.length ? d.forward[d.forward.length - 1].cumMs : null;
  const worst = all.flatMap(x => x.obs).find(o => o.severity === 'bad') ?? all.flatMap(x => x.obs).find(o => o.severity === 'warn');
  const qm = qosMessage(d);
  const tm = ttlMessage(d);
  return h('section', { 'aria-label': 'Selected flow', class: 'panel col', style: 'gap:16px' },
    h('div', { class: 'row', style: 'justify-content:space-between;align-items:flex-start' },
      h('div', { class: 'col', style: 'gap:6px' },
        h('span', { class: 'eyebrow' }, 'Following stream'),
        mc ? h('h2', { class: 'mono', style: 'font-size:18px;font-weight:600' }, `${mc.source}${d.initiator.port ? ':' + d.initiator.port : ''} → group ${mc.group}${d.responder.port ? ':' + d.responder.port : ''}`) : h('h2', { class: 'mono', style: 'font-size:18px;font-weight:600' }, `${d.initiator.ip}${d.initiator.port ? ':' + d.initiator.port : ''} → ${d.responder.ip}${d.responder.port ? ':' + d.responder.port : ''}`),
        h('div', { class: 'row', style: 'gap:8px 16px;color:var(--muted)' },
          h('span', null, `${d.protoName} · ${d.app}`), mc ? chip('Multicast', 'violet') : null,
          h('span', null, mc ? `seen by ${d.forward.length} device${d.forward.length === 1 ? '' : 's'}` : `${d.forward.length} hop${d.forward.length === 1 ? '' : 's'} forward, ${d.reverse.length} back`),
          !mc && lat !== null ? h('span', null, `about ${ms(lat)} end to end`) : null,
          h('span', null, `Started ${stamp(d.t0)} · lasted ${dur(d.t1 - d.t0)}`),
          worst ? statusEl(worst.severity === 'bad' ? 'bad' : 'warn', worst.text.length > 70 ? worst.text.slice(0, 68) + '…' : worst.text) : statusEl('ok', 'Healthy'))),
      mc ? null : seg('Path direction', [{ id: 'f', label: 'Initiator → responder', on: !reverse }, { id: 'r', label: 'Responder → initiator', on: reverse, disabled: !d.reverse.length, title: d.reverse.length ? undefined : 'No exporter reported the return direction' }], id => { reverse = id === 'r'; redraw(); })),
    d.note ? note(d.note, 'info') : null,
    qm ? h('div', { class: 'note bad row', style: 'justify-content:space-between' },
      h('div', null, h('b', null, 'QoS changed in transit'), h('div', null, qm.text)),
      qm.dev ? btn('Open egress queue', { kind: 'danger', onclick: () => go('links', { dev: qm.dev, if: qm.ifName }) }) : null) : null,
    tm ? h('div', { class: 'note bad' }, h('b', null, 'TTL expired before the destination'), h('div', null, tm.text)) : null,
    mc ? multicastExplain(d, mc) : null,
    mc ? (hops.length ? [multicastStrip(hops, d, mc), multicastTable(hops)] : note('No exporter reported this stream.', 'info')) : hops.length ? [strip(hops, d), hopsTable(hops)] : note('No exporter reported this direction.', 'info'),
    h('div', { class: 'split' }, h('div', { class: 'mainp', style: 'flex-basis:520px' }, layers(d, row, (mc ? d.forward.find(x => x.sourcePort) : undefined) ?? d.forward[0])), h('div', { class: 'side', style: 'flex-basis:420px' }, activity(d))));
}

export function render(): VNode {
  return h('main', null, search(), list(), followed());
}
