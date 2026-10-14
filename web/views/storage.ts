import { h, type VNode } from '../vdom.js';
import { get, put, post } from '../api.js';
import { redraw } from '../state.js';
import { btn, chip, heading, msg, note, numberInput, select, spinner, stat, field } from '../components.js';
import { bytes, days, num, stamp } from '../util.js';

type Tier = 'raw' | 'm1' | 'h1' | 'd1' | 'sRaw' | 'sH';
type Ret = Record<Tier, number>;
interface Info {
  retention: Ret; defaults: Ret; backend: 'sqlite' | 'clickhouse'; activeBackend: string; backends: { id: 'sqlite' | 'clickhouse'; name: string; note: string; available: boolean }[];
  collecting: boolean; collect: { flow: boolean; snmp: boolean }; canEdit: boolean; storeNote: string | null; logDays: number;
  stats: { backend: string; rawDays: number; rawRows: number; m1Rows: number; h1Rows: number; d1Rows: number; snmpRawRows: number; snmpHourlyRows: number; bytesOnDisk: number; oldestFlow: number | null; newestFlow: number | null; ingested: number; dropped: number };
}

let info: Info | null = null; let loadError = '';
let draft: Record<Tier, string> = { raw: '', m1: '', h1: '', d1: '', sRaw: '', sH: '' };
let saveMsg = ''; let saveOk = false; let saving = false;
// size estimate inputs. These are assumptions, not measurements.
let fps = '500'; let bpr = '40'; let snmpSec = '60'; let ifaceCount = 0;
let bkMsg = ''; let bkBusy = false; let bkPick: 'sqlite' | 'clickhouse' | null = null;

export function enter(_p: URLSearchParams): void { void load(true); }

async function load(reset: boolean): Promise<void> {
  try {
    info = await get<Info>('/api/storage'); loadError = '';
    if (reset || !draft.raw) for (const k of Object.keys(info.retention) as Tier[]) draft[k] = String(info.retention[k]);
    if (!bkPick) bkPick = info.backend;
    try { const d = await get<{ devices: { interfaces: number }[] }>('/api/devices'); ifaceCount = d.devices.reduce((a, x) => a + x.interfaces, 0); } catch { /* optional */ }
  } catch (e) { loadError = (e as Error).message; }
  redraw();
}

const TIERS: { id: Tier; name: string; grp: 'Flows' | 'SNMP'; keeps: string; share: number }[] = [
  { id: 'raw', name: 'Raw flow records', grp: 'Flows', keeps: 'Every record, per exporter. Needed to follow one stream hop by hop.', share: 1 },
  { id: 'm1', name: '1-minute rollups', grp: 'Flows', keeps: 'Totals per host pair, port and service for each minute. Used for reports and charts.', share: 0.08 },
  { id: 'h1', name: '1-hour rollups', grp: 'Flows', keeps: 'The same totals per hour. Used for the last weeks and months.', share: 0.006 },
  { id: 'd1', name: 'Daily rollups', grp: 'Flows', keeps: 'The same totals per day. Used for long-term trends.', share: 0.0005 },
  { id: 'sRaw', name: 'SNMP raw samples', grp: 'SNMP', keeps: 'Every poll of every interface and queue class.', share: 1 },
  { id: 'sH', name: 'SNMP hourly rollups', grp: 'SNMP', keeps: 'Average and peak per hour for each interface and class.', share: 0 }
];

function num_(s: string): number { return Number(s); }
function validDays(s: string): boolean { const n = Number(s); return Number.isInteger(n) && n >= 1 && n <= 3650; }

function warnFor(id: Tier): string | null {
  const v = (k: Tier) => num_(draft[k]);
  const chain: Record<string, [Tier, string]> = { m1: ['raw', 'raw records'], h1: ['m1', '1-minute rollups'], d1: ['h1', '1-hour rollups'], sH: ['sRaw', 'SNMP raw samples'] };
  const c = chain[id];
  if (c && validDays(draft[id]) && validDays(draft[c[0]]) && v(id) < v(c[0])) return `Kept for less time than the ${c[1]} (${v(c[0])} days), so it adds no history. Raise it to at least ${v(c[0])}.`;
  return null;
}

function perDay(id: Tier): number {
  const f = Math.max(0, num_(fps) || 0), b = Math.max(0, num_(bpr) || 0), p = Math.max(1, num_(snmpSec) || 60);
  const raw = f * 86400 * b;
  const snmpRaw = ifaceCount * (86400 / p) * 1.5 * 6;   // ~6 counters per interface sample
  if (id === 'sRaw') return snmpRaw;
  if (id === 'sH') return snmpRaw / Math.max(1, 3600 / p) * 2;
  return raw * TIERS.find(t => t.id === id)!.share;
}

async function save(): Promise<void> {
  const bad = (Object.keys(draft) as Tier[]).find(k => !validDays(draft[k]));
  if (bad) { saveOk = false; saveMsg = 'Enter whole numbers of days between 1 and 3650.'; redraw(); return; }
  const w = (Object.keys(draft) as Tier[]).map(warnFor).find(Boolean);
  if (w) { saveOk = false; saveMsg = w; redraw(); return; }
  saving = true; saveMsg = ''; redraw();
  try {
    const body: Partial<Ret> = {}; for (const k of Object.keys(draft) as Tier[]) body[k] = Number(draft[k]);
    const r = await put<{ retention: Ret; note: string }>('/api/storage/retention', body);
    saveOk = true; saveMsg = 'Saved. ' + r.note; await load(true);
  } catch (e) { saveOk = false; saveMsg = (e as Error).message; }
  saving = false; redraw();
}
async function reset(): Promise<void> {
  saving = true; redraw();
  try { await post('/api/storage/retention/reset'); saveOk = true; saveMsg = 'Reset to the defaults.'; await load(true); } catch (e) { saveOk = false; saveMsg = (e as Error).message; }
  saving = false; redraw();
}

async function applyBackend(): Promise<void> {
  if (!bkPick) return;
  bkBusy = true; bkMsg = ''; redraw();
  try {
    const r = await put<{ note?: string; changed: boolean }>('/api/storage/backend', { backend: bkPick });
    bkMsg = r.changed ? (r.note ?? 'Storage backend changed.') : 'That backend is already in use.';
    await load(false);
  } catch (e) { bkMsg = (e as Error).message; }
  bkBusy = false; redraw();
}

/* ------------------------------------------------------------------ rendering */

function summary(i: Info): VNode {
  const s = i.stats;
  return h('div', { class: 'stats' },
    stat('Storage used', bytes(s.bytesOnDisk), `${s.backend} backend`),
    stat('Raw flow records', num(s.rawRows), s.oldestFlow ? `since ${stamp(s.oldestFlow)}` : 'none stored yet'),
    stat('Rollup rows', num(s.m1Rows + s.h1Rows + s.d1Rows), `${num(s.m1Rows)} per minute · ${num(s.h1Rows)} per hour · ${num(s.d1Rows)} daily`),
    stat('SNMP samples', num(s.snmpRawRows + s.snmpHourlyRows), `${num(s.snmpRawRows)} raw · ${num(s.snmpHourlyRows)} hourly`),
    stat('Records dropped on intake', num(s.dropped), s.dropped ? 'The store could not keep up' : 'None'));
}

function tiersPanel(i: Info): VNode {
  const locked = !i.canEdit;
  const cols = 'minmax(280px,3fr) 200px 120px';
  let total = 0;
  const rows = TIERS.map(t => {
    const d = validDays(draft[t.id]) ? Number(draft[t.id]) : 0;
    const size = perDay(t.id) * d; total += size;
    const warn = warnFor(t.id);
    return h('div', { key: t.id, class: 'tr tall', style: `grid-template-columns:${cols}` },
      h('div', { class: 'col', style: 'gap:2px' }, h('div', { class: 'row', style: 'gap:8px' }, h('b', null, t.name), chip(t.grp, t.grp === 'Flows' ? 'info' : 'violet')), h('span', { class: 'muted', style: 'font-size:12px' }, t.keeps), warn ? h('span', { class: 'note warn', style: 'padding:4px 8px;font-size:12px', role: 'status' }, warn) : null),
      h('div', { class: 'row', style: 'gap:8px' }, numberInput(draft[t.id], v => { draft[t.id] = v; redraw(); }, { min: 1, max: 3650, aria: `${t.name}: days to keep`, disabled: locked, width: '90px' }), h('span', { class: 'muted' }, validDays(draft[t.id]) ? days(d) : 'invalid')),
      h('span', { class: 'mono' }, d ? '≈ ' + bytes(size) : '—'));
  });
  const dirty = (Object.keys(draft) as Tier[]).some(k => draft[k] !== String(i.retention[k]));
  return h('section', { 'aria-label': 'Retention tiers', class: 'col', style: 'gap:12px' },
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--w:700px' },
      h('div', { class: 'tr head', style: `grid-template-columns:${cols}` }, h('span', null, 'Tier'), h('span', null, 'Keep for (days)'), h('span', null, 'Est. size')), rows,
      h('div', { class: 'tr', style: `grid-template-columns:${cols};font-weight:600` }, h('span', null, 'Estimated total'), h('span'), h('span', { class: 'mono' }, '≈ ' + bytes(total))))),
    h('div', { class: 'sticky-save' },
      btn(saving ? 'Saving…' : 'Save retention policy', { kind: 'primary', disabled: locked || saving || !dirty, onclick: () => void save() }),
      btn('Reset to defaults', { kind: 'ghost', disabled: locked || saving, onclick: () => void reset() }),
      locked ? h('span', { class: 'muted' }, 'You can view these settings. Only the full admin role can change them.') : null,
      msg(saveMsg, saveOk ? 'ok' : saveMsg ? 'bad' : '')));
}

function estimate(): VNode {
  return h('section', { 'aria-label': 'Size estimate', class: 'panel col', style: 'gap:12px' },
    h('h3', null, 'Size estimate inputs'),
    h('div', { class: 'three' },
      field('Flow records per second', numberInput(fps, v => { fps = v; redraw(); }, { min: 1, aria: 'Flow records per second', width: '100%' })),
      field('Bytes per record, compressed', numberInput(bpr, v => { bpr = v; redraw(); }, { min: 1, aria: 'Bytes per record', width: '100%' })),
      field('SNMP poll interval', select(snmpSec, [['30', '30 s'], ['60', '60 s'], ['300', '5 min']], v => { snmpSec = v; redraw(); }, { aria: 'SNMP poll interval' }))),
    h('p', { class: 'muted' }, `These are placeholder assumptions, not measurements: rollups are assumed to hold 8%, 0.6% and 0.05% of the raw volume per day, and each SNMP sample about 9 bytes (${num(ifaceCount)} interface${ifaceCount === 1 ? '' : 's'} are polled now). Replace them with figures from your own exporters once real data arrives.`));
}

function tierMap(i: Info): VNode {
  const r = i.retention;
  const edges: [number, string, string][] = [];
  const add = (to: number, reads: string) => { if (!edges.length || to > edges[edges.length - 1][0]) edges.push([to, reads, '']); };
  add(r.raw, 'Raw records'); add(r.m1, '1-minute rollups'); add(r.h1, '1-hour rollups'); add(r.d1, 'Daily rollups');
  let from = 0;
  const lines = edges.map(([to, reads]) => { const l = { range: `${from === 0 ? 'Newer than' : `${days(from)} to`} ${days(to)}`.replace('Newer than', 'Up to'), reads, has: reads.startsWith('Raw') ? 'Full detail: every hop, MAC address, port' : reads.startsWith('1-min') ? 'Totals by host, port, service; no per-hop detail' : reads.startsWith('1-hour') ? 'Hourly totals; coarse time resolution' : 'Daily totals; trends only' }; from = to; return l; });
  return h('section', { 'aria-label': 'Tier map', class: 'panel col', style: 'gap:8px' },
    h('h3', null, 'What a search or report reads, by age of data'),
    lines.map((l, k) => h('div', { key: k, class: 'row', style: 'justify-content:space-between;border-bottom:1px solid var(--raised);padding:6px 0' }, h('b', { style: 'min-width:150px' }, l.range), h('span', { class: 'grow' }, l.reads), h('span', { class: 'muted grow' }, l.has))),
    h('span', { class: 'dim' }, `Older than ${days(from)}: nothing is kept.`));
}

function backend(i: Info): VNode {
  const locked = !i.canEdit || i.collecting;
  const why = !i.canEdit ? 'Only the full admin role can change the storage backend.' : i.collecting ? 'The backend is locked while collection is running. Stop flow collection and SNMP polling under Admin, Data collection, then change it here.' : '';
  const pts: Record<string, { pts: string[]; enforce: string; store: string; snmpStore: string }> = {
    sqlite: { pts: ['Nothing to install or run: it is built into FlowScope.', 'Raw records are written to one table per day; old days are dropped whole.', 'Fine for small sites, up to a few thousand flows per second. Choose it when you do not want to run a ClickHouse server.'], enforce: 'Each cleanup run drops the day tables older than the raw retention and deletes rollup rows past their own limits.', store: 'Embedded SQLite (flows, rollups)', snmpStore: 'Embedded SQLite (samples, hourly)' },
    clickhouse: { pts: ['Column store for high volume and long retention.', 'The default for the Docker, Linux and Proxmox installs, which set up a server for you.', 'Runs as a separate server (FLOWSCOPE_CLICKHOUSE_URL points to it); on Linux and Proxmox the installer puts one on the same machine.'], enforce: 'Tables carry a TTL set from the retention days, and ClickHouse removes expired parts in the background.', store: 'ClickHouse (flows, rollups)', snmpStore: 'ClickHouse (samples, hourly)' }
  };
  const sel = pts[bkPick ?? i.backend];
  return h('section', { 'aria-label': 'Backend', class: 'panel col', style: 'gap:14px' },
    h('div', { class: 'col', style: 'gap:4px' }, h('h3', null, 'Storage backend'), h('span', { class: 'muted' }, `In use now: ${i.activeBackend === 'sqlite' ? 'Embedded SQLite' : 'ClickHouse'}. Changing it starts an empty store; the old data is not copied.`)),
    i.storeNote ? note(i.storeNote, 'warn', true) : null,
    h('div', { role: 'group', 'aria-label': 'Backend options', class: 'row' }, i.backends.map(b => h('button', { key: b.id, type: 'button', class: 'cardbtn', style: 'flex:1 1 260px', 'aria-pressed': (bkPick ?? i.backend) === b.id, disabled: locked, onclick: () => { bkPick = b.id; redraw(); } },
      h('span', { class: 't' }, b.name, i.activeBackend === b.id ? h('span', { class: 'chip ok', style: 'margin-left:8px' }, 'in use') : null), h('span', { class: 's' }, b.note)))),
    h('div', { class: 'pts' }, sel.pts.map((p, k) => h('div', { key: k, class: 'pt' }, h('i'), h('span', null, p)))),
    h('div', { class: 'layer' }, h('b', null, 'How retention is enforced'), h('p', { class: 'muted', style: 'margin-top:4px' }, sel.enforce)),
    h('div', { class: 'row' }, btn(bkBusy ? 'Switching…' : 'Use this backend', { kind: 'primary', disabled: locked || bkBusy || (bkPick ?? i.backend) === i.backend, onclick: () => void applyBackend() }), why ? h('span', { class: 'muted' }, why) : null, msg(bkMsg, bkMsg.startsWith('The') || bkMsg.includes('could not') ? 'bad' : 'ok')),
    (bkPick === 'clickhouse' && !i.backends.find(b => b.id === 'clickhouse')?.available) ? note('ClickHouse is not configured. Set FLOWSCOPE_CLICKHOUSE_URL on the server and restart it.', 'info') : null,
    h('div', { class: 'col', style: 'gap:8px' }, h('b', null, 'Data path'),
      h('div', { class: 'flow' },
        h('span', { class: 'box' }, 'Exporters', h('small', null, 'NetFlow v5/v9, IPFIX')), h('span', { class: 'arrow', 'aria-hidden': 'true' }, '→'),
        h('span', { class: 'box' }, 'Collector', h('small', null, 'decode, enrich, stitch hops')), h('span', { class: 'arrow', 'aria-hidden': 'true' }, '→'), h('span', { class: 'box' }, sel.store)),
      h('div', { class: 'flow' },
        h('span', { class: 'box' }, 'SNMP pollers', h('small', null, 'IF-MIB, QoS MIB')), h('span', { class: 'arrow', 'aria-hidden': 'true' }, '→'), h('span', { class: 'box' }, sel.snmpStore),
        h('span', { class: 'arrow', 'aria-hidden': 'true' }, '→'), h('span', { class: 'box' }, 'API and web UI'))));
}

export function render(): VNode {
  const head = heading('Storage and retention', 'How long each kind of data is kept', 'Detailed records are kept briefly; pre-aggregated rollups are kept much longer. Searches and reports read the finest tier that still covers the time range, which keeps them quick as history grows.');
  if (loadError && !info) return h('main', null, head, note(loadError, 'bad', true));
  if (!info) return h('main', null, head, spinner());
  return h('main', null, head, summary(info), tiersPanel(info), h('div', { class: 'split' }, h('div', { class: 'mainp', style: 'flex-basis:420px' }, estimate()), h('div', { class: 'mainp', style: 'flex-basis:420px' }, tierMap(info))), backend(info));
}
