import { h, type VNode } from '../vdom.js';
import { get, qs } from '../api.js';
import { session, redraw } from '../state.js';
import { btn, chip, empty, field, heading, note, rangePicker, seg, select, spinner, status as statusEl } from '../components.js';
import { Follower, type Row } from './stream.js';
import { bytes, dayClock, num, RANGES, debounce, detailRange, isRange, svcLabel } from '../util.js';


let q = '';
const protos = { tcp: true, udp: true, icmp: true };
let qosOnly = false;
let ttlOnly = false;
let range = '15m';
let sort: { key: 'time' | 'bytes' | 'pkts'; dir: 'asc' | 'desc' } = { key: 'time', dir: 'desc' };
let rows: Row[] = []; let total = 0; let truncated = false; let errors: string[] = [];
let loading = false; let loadError = '';
/** Paging. The first page is answered from the newest PREVIEW flow records so the list appears at once; the full answer follows and replaces it. */
const PREVIEW = 2000;
const PAGE_SIZES = [100, 200, 500, 1000, 2000];
let page = 0; let pageSize = 200;
let partial = false;
/** The total is only a lower bound ("200+") on a wide range until the person asks for the exact count; a capped list looked at the newest records only. */
let totalExact = true, capped = false, scanCap = 0, wantCount = false;
const follow = new Follower(() => bigRange(), () => redraw(), id => pick(id));
let live = false; let liveTimer: number | undefined;

export function enter(p: URLSearchParams): void {
  const nq = p.get('q'), ns = p.get('s'), nr = p.get('range');
  let changed = false;
  if (nq !== null && nq !== q) { q = nq; changed = true; }
  if (nr && nr !== range && isRange(nr)) { range = nr; changed = true; }
  follow.select(ns ?? '');
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
  if (follow.selId) p.set('s', follow.selId);
  if (range !== '15m') p.set('range', range);
  const s = p.toString();
  history.replaceState(null, '', '#/explorer' + (s ? '?' + s : ''));
}

let seq = 0;
type Reply = { rows: Row[]; total: number; totalExact?: boolean; capped?: boolean; scanCap?: number | null; truncated: boolean; partial: boolean; errors: string[] };
async function load(quiet = false, keepPage = false): Promise<void> {
  const my = ++seq;
  if (!keepPage) { page = 0; if (!quiet) wantCount = false; }
  if (!quiet) { loading = true; loadError = ''; redraw(); }
  const base = { range, q: fullQuery(), sort: sort.key, dir: sort.dir, limit: pageSize, offset: page * pageSize, ...(wantCount ? { count: 1 } : {}) };
  const apply = (r: Reply) => { rows = r.rows; total = r.total; totalExact = r.totalExact !== false; capped = !!r.capped; scanCap = r.scanCap ?? 0; truncated = r.truncated; errors = r.errors; };
  try {
    // First page of a fresh search: show the newest records straight away, then fetch everything in the background
    if (!quiet && page === 0) {
      const p = await get<Reply>('/api/streams' + qs({ ...base, preview: PREVIEW }));
      if (my !== seq) return;
      apply(p); partial = p.partial; loading = false; redraw();
      if (!p.partial) return;
    }
    const r = await get<Reply>('/api/streams' + qs(base));
    if (my !== seq) return;
    if (!r.rows.length && page > 0 && r.total > 0) { page = Math.max(0, Math.ceil(r.total / pageSize) - 1); return load(true, true); }   // the list shrank under us
    apply(r); partial = false; loadError = '';
  } catch (e) {
    if (my === seq) {
      loadError = (e as Error).message;
      if (!partial) { rows = []; total = 0; }   // keep a preview that is already on screen
      partial = false;
    }
  }
  if (my === seq) { loading = false; redraw(); }
}
function goPage(n: number): void { page = Math.max(0, n); void load(false, true).then(() => document.querySelector('.tbl .scroll')?.scrollTo(0, 0)); }
const loadSoon = debounce(() => { void load(); }, 350);

/** Detail is looked up over a wider window than the list, so a stream found a while ago can still be opened. */
function pick(id: string): void { follow.select(follow.selId === id ? '' : id); syncHash(); }

function bigRange(): string { return detailRange(range); }



/* ------------------------------------------------------------------ rendering */

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
          oninput: (e: Event) => { q = (e.target as HTMLInputElement).value; loadSoon(); redraw(); },
          onkeydown: (e: KeyboardEvent) => { if (e.key === 'Enter') { syncHash(); void load(); } } })),
      seg('Protocol filter', (['tcp', 'udp', 'icmp'] as const).map(k => ({ id: k, label: k.toUpperCase(), on: protos[k] })), id => {
        const k = id as 'tcp' | 'udp' | 'icmp';
        if (protos[k] && Object.values(protos).filter(Boolean).length === 1) return;   // keep at least one
        protos[k] = !protos[k]; void load(); redraw();
      }),
      rangePicker('explorer', range, RANGES, v => { range = v; syncHash(); void load(); if (follow.selId) void follow.load(); }, { aria: 'Time range' }),
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

const COLS = '78px minmax(160px,1.4fr) minmax(160px,1.4fr) 60px 160px 150px 80px 72px 48px 116px 112px 108px';

function qosTag(r: Row): VNode {
  if (!r.qosChanged) return h('span', { class: 'dim' }, '—');
  const k = r.qosVerdict?.kind;
  const change = r.dscpOutS ? `${r.dscpInS.replace(/ \(\d+\)/, '')} → ${r.dscpOutS.replace(/ \(\d+\)/, '')}` : 'changed';
  // a change a policy explains is shown quietly; one nothing configured, or that is unknown, keeps the red tag, and mixed markings are a warning
  if (k === 'policy') return h('span', { class: 'tag info', title: 'Re-marked by a configured policy. ' + r.qosVerdict!.text }, change + ' · policy');
  if (k === 'mixed') return h('span', { class: 'tag warn', title: r.qosVerdict!.text }, 'mixed DSCP');
  return h('span', { class: 'tag bad', title: r.qosVerdict?.text }, change);
}

function ttlTag(r: Row): VNode {
  if (!r.ttlExpired) return h('span', { class: 'dim' }, '—');
  const why = r.ttlReason === 'icmp' ? 'An ICMP Time Exceeded message: a router reported that a packet ran out of TTL' : `An exporter saw this traffic with TTL ${r.ttlLow}: the next router had to drop it, so it did not reach ${r.dstIp}`;
  return h('span', { class: 'tag bad', title: why }, r.ttlReason === 'icmp' ? 'TTL notice' : 'TTL expired');
}

function list(): VNode {
  const hdrBtn = (label: string, key: 'time' | 'bytes' | 'pkts') => h('button', { type: 'button', class: 'sortbtn', onclick: () => { sort = sort.key === key ? { key, dir: sort.dir === 'desc' ? 'asc' : 'desc' } : { key, dir: 'desc' }; void load(); } },
    label + (sort.key === key ? (sort.dir === 'desc' ? ' ↓' : ' ↑') : ''));
  const qosCount = rows.filter(r => r.qosChanged && r.qosVerdict?.kind !== 'policy').length;
  const policyCount = rows.filter(r => r.qosChanged && r.qosVerdict?.kind === 'policy').length;
  const ttlCount = rows.filter(r => r.ttlExpired).length;
  return h('section', { 'aria-label': 'Flow results', class: 'col', style: 'gap:10px' },
    qosCount && !qosOnly ? h('div', { class: 'note bad row', style: 'justify-content:space-between' },
      h('span', null, h('b', null, `${qosCount} stream${qosCount === 1 ? '' : 's'}`), ' had their QoS marking (DSCP) changed somewhere along the path', policyCount ? ` (${policyCount} more ${policyCount === 1 ? 'was' : 'were'} re-marked by a configured policy and ${policyCount === 1 ? 'is' : 'are'} not counted)` : '', '.'),
      btn('Show only these', { kind: 'danger', onclick: () => { qosOnly = true; void load(); redraw(); } })) : null,
    ttlCount && !ttlOnly ? h('div', { class: 'note bad row', style: 'justify-content:space-between' },
      h('span', null, h('b', null, `${ttlCount} stream${ttlCount === 1 ? '' : 's'}`), ' had the TTL expire before reaching the destination, or a router reported Time Exceeded for them.'),
      btn('Show only these', { kind: 'danger', onclick: () => { ttlOnly = true; void load(); redraw(); } })) : null,
    partial ? h('div', { class: 'note warn row', role: 'status', style: 'gap:10px' }, h('span', { 'aria-hidden': 'true', class: 'spin' }),
      h('span', null, h('b', null, 'Not everything has loaded yet. '), `This is the newest ${num(PREVIEW)} flow records. The rest of the time range is still loading, so byte and packet totals and the stream count will change when it finishes.`)) : null,
    capped && !loading ? h('div', { class: 'note warn' }, h('b', null, 'Showing the newest streams. '), `A range this wide holds more than the ${num(scanCap)} flow records FlowScope looks at for a list, so older streams are left out. Narrow the time range or add a filter to see them, or sort by bytes or packets to rank everything.`) : null,
    h('div', { class: 'row', style: 'justify-content:space-between;color:var(--muted)' },
      h('span', { 'aria-live': 'polite', class: 'row', style: 'gap:8px' }, loading ? 'Searching…' : countText(), !loading && !partial && !totalExact && total > 0 ? btn('Count all', { small: true, kind: 'ghost', title: 'Count every matching stream. On a wide range this can take a while.', onclick: () => { wantCount = true; void load(false, true); } }) : null),
      pager(false)),
    loadError ? note(loadError, 'bad', true) : null,
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${COLS};--w:1470px` },
      h('div', { class: 'tr head' }, hdrBtn('Time', 'time'), h('span', null, 'Source'), h('span', null, 'Destination'), h('span', null, 'Proto'), h('span', null, 'Service'), h('span', null, 'VLAN'), hdrBtn('Bytes', 'bytes'), hdrBtn('Pkts', 'pkts'), h('span', null, 'Hops'), h('span', null, 'Status'), h('span', null, 'QoS'), h('span', null, 'TTL')),
      h('div', { class: 'scroll' },
        rows.map(r => h('button', { key: r.id, type: 'button', class: 'tr', 'aria-pressed': follow.selId === r.id, onclick: () => pick(r.id) },
          h('span', { class: 'mono muted', style: 'font-size:12px' }, dayClock(r.t0)),
          h('span', { class: 'mono' }, r.srcIp, r.sport ? h('span', { class: 'dim' }, ':' + r.sport) : null),
          h('span', { class: 'mono' }, r.dstIp, r.dport ? h('span', { class: 'dim' }, ':' + r.dport) : null),
          h('span', { style: `font-weight:500;color:${PROTO_COLOR[r.protoName] ?? 'var(--text2)'}` }, r.protoName),
          h('span', null, svcLabel(r.app, r.appPort)),
          h('span', { class: 'mono muted', style: 'font-size:12px' }, r.vlan ? String(r.vlan) : '—', ' ', h('span', { class: 'dim' }, r.vlanName)),
          h('span', { class: 'mono', style: 'font-size:12px' }, bytes(r.bytes)),
          h('span', { class: 'mono', style: 'font-size:12px' }, num(r.pkts)),
          h('span', { class: 'mono muted', style: 'font-size:12px' }, String(r.hopCount)),
          r.health ? statusEl(r.health.kind, r.health.text) : h('span', { class: 'dim' }, '—'),
          qosTag(r), ttlTag(r))),
        !rows.length && !loading ? empty('No flows match this search. Loosen the filters, widen the time range, or clear the search.') : null,
        loading && !rows.length ? spinner('Searching…') : null))),
    h('div', { class: 'row', style: 'justify-content:space-between;color:var(--muted)' }, h('span', null, 'Select a flow to follow the stream and inspect it hop by hop'), pager(true)));
}

function countText(): string {
  if (loadError && !rows.length) return '';
  if (partial) return `${num(rows.length)} stream${rows.length === 1 ? '' : 's'} so far`;
  if (!total) return '0 streams';
  const from = page * pageSize + 1, to = page * pageSize + rows.length;
  return `${num(from)}–${num(to)} of ${num(total)}${totalExact ? '' : '+'} stream${total === 1 ? '' : 's'}`;
}

function pager(bottom: boolean): VNode {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const pageText = totalExact ? `Page ${num(page + 1)} of ${num(pages)}` : `Page ${num(page + 1)}`;
  const busy = loading || partial;   // the totals are not final until the full answer is in
  return h('div', { class: 'row', style: 'gap:8px', role: 'navigation', 'aria-label': bottom ? 'Pages (bottom)' : 'Pages' },
    bottom ? null : [h('span', null, 'Rows per page'), select(String(pageSize), PAGE_SIZES.map(n => [String(n), String(n)] as [string, string]), v => { pageSize = Number(v); void load(); }, { aria: 'Rows per page', width: '84px' })],
    btn('‹ Previous', { small: true, kind: 'ghost', disabled: busy || page === 0, onclick: () => goPage(page - 1) }),
    h('span', { class: 'mono', style: 'font-size:12px' }, partial ? '…' : pageText),
    btn('Next ›', { small: true, kind: 'ghost', disabled: busy || page + 1 >= pages, onclick: () => goPage(page + 1) }));
}

export function render(): VNode {
  return h('main', null, search(), list(), follow.render(rows.find(r => r.id === follow.selId)));
}
