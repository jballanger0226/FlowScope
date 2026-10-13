import { h, type VNode } from '../vdom.js';
import { post, downloadPost } from '../api.js';
import { redraw } from '../state.js';
import { bar, btn, chip, field, msg, note, select, seg, spinner } from '../components.js';
import { bytes, num, pct, RANGES, stamp, debounce } from '../util.js';

interface Res {
  range: { from: number; to: number }; tier: string; dims: { id: string; label: string }[];
  rows: { dims: Record<string, string | number | null>; bytes: number; pkts: number; flows: number }[];
  totalRows: number; totals: { bytes: number; pkts: number; flows: number }; other: { bytes: number; pkts: number; flows: number; rows: number }; errors: string[]; bidir: boolean; prefix: number;
}

const LAYERS: { tag: 'L2' | 'L3' | 'L4'; name: string; key: 'f2' | 'f3' | 'f4'; ph: string; dims: [string, string][] }[] = [
  { tag: 'L2', name: 'Data link', key: 'f2', ph: 'mac:aa:bb:cc:dd:ee:ff vlan:150 vlan:voice', dims: [['srcMac', 'Source MAC'], ['dstMac', 'Destination MAC'], ['vlan', 'VLAN'], ['inIf', 'Ingress interface']] },
  { tag: 'L3', name: 'Network', key: 'f3', ph: 'src:10.1.0.0/16 dst:10.9.0.0/16 dscp:ef', dims: [['srcIp', 'Source IP'], ['dstIp', 'Destination IP'], ['proto', 'Protocol'], ['dscp', 'DSCP'], ['qos', 'QoS change']] },
  { tag: 'L4', name: 'Transport', key: 'f4', ph: 'port:443 app:https proto:tcp', dims: [['sport', 'Source port'], ['dport', 'Destination port'], ['svc', 'Service port'], ['app', 'Application'], ['flags', 'TCP flags']] }
];

let title = 'Top conversations';
let dims = new Set<string>(['srcIp', 'dstIp', 'dport']);
const filt: Record<'f2' | 'f3' | 'f4', string> = { f2: '', f3: '', f4: '' };
let prefix = 32; let customOn = false; let customText = '24'; let bidir = false; let range = '24h'; let sortBy = 'bytes'; let topN = '25';
let res: Res | null = null; let error = ''; let busy = false;
let fmt: 'csv' | 'json' = 'csv'; let copied = ''; let dlMsg = '';

export function enter(_p: URLSearchParams): void { if (!res && !busy) void run(); }

function body(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { dims: [...dims], f2: filt.f2.trim(), f3: filt.f3.trim(), f4: filt.f4.trim(), prefix, bidir, range, sortBy, topN: topN === 'all' ? 1000 : Number(topN), ...extra };
}

let seq = 0;
async function run(): Promise<void> {
  const my = ++seq; busy = true; error = ''; redraw();
  try {
    const r = await post<Res>('/api/reports', body());
    if (my !== seq) return;
    res = r;
  } catch (e) { if (my === seq) { error = (e as Error).message; res = null; } }
  if (my === seq) { busy = false; redraw(); }
}
/** The prefix typed into the custom box: a whole number from 0 to 32, with or without a leading slash. */
function parseCustom(t: string): number | null {
  const m = /^\/?\s*(\d{1,2})$/.exec(t.trim());
  if (!m) return null;
  const n = Number(m[1]);
  return n >= 0 && n <= 32 ? n : null;
}
const customBad = () => customOn && parseCustom(customText) === null;
function pickPrefix(id: string): void {
  if (id === 'custom') { customOn = true; customText = String(prefix); const n = parseCustom(customText); if (n !== null) prefix = n; }
  else { customOn = false; prefix = Number(id); void run(); }
  redraw();
}
const customSoon = debounce(() => { const n = parseCustom(customText); if (n !== null) { prefix = n; void run(); } }, 400);
const runSoon = debounce(() => void run(), 500);

function toggleDim(id: string): void { if (dims.has(id)) dims.delete(id); else dims.add(id); void run(); redraw(); }

async function download(f: 'csv' | 'json'): Promise<void> {
  dlMsg = '';
  try { await downloadPost('/api/reports/export', body({ format: f }), `flowscope-report.${f}`); dlMsg = `Downloaded ${f.toUpperCase()}.`; } catch (e) { dlMsg = (e as Error).message; }
  redraw();
}

function csvEscape(v: unknown): string { const s = v === null || v === undefined ? '' : String(v); return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }
function preview(r: Res): string {
  if (fmt === 'json') {
    return JSON.stringify({
      title, generatedAt: new Date().toISOString(), range: { from: new Date(r.range.from).toISOString(), to: new Date(r.range.to).toISOString() }, tier: r.tier, prefix: r.prefix, bidirectional: r.bidir,
      filters: { l2: filt.f2.trim() || null, l3: filt.f3.trim() || null, l4: filt.f4.trim() || null }, totals: r.totals,
      rows: r.rows.slice(0, 8).map(x => ({ ...x.dims, bytes: x.bytes, packets: x.pkts, flows: x.flows })), ...(r.rows.length > 8 ? { note: `${r.rows.length - 8} more rows in the download` } : {})
    }, null, 2);
  }
  const head = [...r.dims.map(d => d.label), 'Bytes', 'Packets', 'Flows'].map(csvEscape).join(',');
  const lines = r.rows.slice(0, 8).map(x => [...r.dims.map(d => x.dims[d.id]), x.bytes, x.pkts, x.flows].map(csvEscape).join(','));
  return [head, ...lines, ...(r.rows.length > 8 ? [`… ${r.rows.length - 8} more rows in the download`] : [])].join('\n');
}

async function copy(r: Res): Promise<void> {
  const text = fmt === 'json' ? preview(r) : preview(r);
  try { await navigator.clipboard.writeText(text); copied = 'Copied to the clipboard.'; } catch { copied = 'Could not copy. Select the text and copy it by hand.'; }
  redraw(); setTimeout(() => { copied = ''; redraw(); }, 4000);
}

function layerPanel(L: typeof LAYERS[number]): VNode {
  return h('div', { key: L.tag, class: 'layer col', style: 'gap:10px' },
    h('div', { class: 'lh' }, chip(L.tag, L.tag === 'L2' ? 'violet' : L.tag === 'L3' ? 'info' : 'accent'), h('span', null, L.name)),
    h('div', { class: 'seg', role: 'group', 'aria-label': `${L.name} fields to group by` }, L.dims.map(([id, label]) => h('button', { key: id, type: 'button', class: 'segbtn', 'aria-pressed': dims.has(id), onclick: () => toggleDim(id) }, label))),
    h('input', { class: 'input mono', type: 'text', value: filt[L.key], 'aria-label': `${L.name} filter`, placeholder: L.ph, spellcheck: 'false', autocomplete: 'off', oninput: (e: Event) => { filt[L.key] = (e.target as HTMLInputElement).value; runSoon(); redraw(); } }));
}

function table(r: Res): VNode {
  const max = r.totals.bytes || 1;
  const nd = r.dims.length;
  const cols = `${r.dims.map(() => 'minmax(110px,1.2fr)').join(' ')} 90px 110px 110px 150px`;
  return h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${cols};--w:${Math.max(760, nd * 150 + 460)}px` },
    h('div', { class: 'tr head' }, ...r.dims.map(d => h('span', { key: d.id }, d.label)), h('span', null, 'Flows'), h('span', null, 'Packets'), h('span', null, 'Bytes'), h('span', null, 'Share')),
    h('div', { class: 'scroll', style: 'max-height:460px' },
      r.rows.map((x, i) => h('div', { key: i, class: 'tr' },
        ...r.dims.map(d => h('span', { key: d.id, class: 'mono', style: 'font-size:12.5px;word-break:break-all' }, x.dims[d.id] === null || x.dims[d.id] === '' ? '—' : String(x.dims[d.id]))),
        h('span', { class: 'mono', style: 'font-size:12.5px' }, num(x.flows)), h('span', { class: 'mono', style: 'font-size:12.5px' }, num(x.pkts)), h('span', { class: 'mono', style: 'font-size:12.5px' }, bytes(x.bytes)),
        h('span', { class: 'row', style: 'gap:8px;flex-wrap:nowrap' }, bar((x.bytes / max) * 100, 100, 'accent'), h('span', { class: 'mono', style: 'font-size:12px' }, pct((x.bytes / max) * 100))))),
      r.other.rows ? h('div', { class: 'tr', style: 'color:var(--muted)' }, h('span', { style: 'grid-column:1/' + (nd + 1) }, `Other (${num(r.other.rows)} more group${r.other.rows === 1 ? '' : 's'})`), h('span', { class: 'mono' }, num(r.other.flows)), h('span', { class: 'mono' }, num(r.other.pkts)), h('span', { class: 'mono' }, bytes(r.other.bytes)), h('span', { class: 'mono', style: 'font-size:12px' }, pct((r.other.bytes / max) * 100))) : null,
      !r.rows.length ? h('div', { class: 'empty' }, 'No flows match these layer filters.') : null)));
}

export function render(): VNode {
  const r = res;
  return h('main', null,
    h('section', { 'aria-label': 'Report setup', class: 'col', style: 'gap:14px' },
      h('div', { class: 'heading', style: 'max-width:none' }, h('span', { class: 'eyebrow' }, 'Report builder'),
        h('input', { class: 'input', style: 'font-size:20px;font-weight:600;height:48px;max-width:560px', type: 'text', value: title, 'aria-label': 'Report title', oninput: (e: Event) => { title = (e.target as HTMLInputElement).value; redraw(); } }),
        h('p', { class: 'blurb' }, 'Choose which fields at each layer to group by, narrow the flows with per-layer filters, then export the combined result. Counters sum both directions of every conversation.')),
      h('div', { class: 'layers', 'aria-label': 'Layer selection' }, LAYERS.map(layerPanel)),
      h('div', { class: 'panel row end', 'aria-label': 'Combine options', style: 'gap:16px 28px' },
        h('div', { class: 'col', style: 'gap:6px' }, h('span', { class: 'flabel muted' }, 'Aggregate IPs to'),
          h('div', { class: 'row', style: 'gap:10px;flex-wrap:nowrap' },
            seg('IP prefix length', [['32', '/32 host'], ['24', '/24'], ['16', '/16'], ['custom', 'Custom']].map(([id, label]) => ({ id, label, on: id === 'custom' ? customOn : !customOn && String(prefix) === id })), pickPrefix),
            customOn ? h('label', { class: 'row', style: 'gap:6px;flex-wrap:nowrap' }, h('span', { class: 'mono muted' }, '/'),
              h('input', { class: 'input mono' + (customBad() ? ' bad' : ''), type: 'number', inputmode: 'numeric', min: 0, max: 32, step: 1, value: customText, 'aria-label': 'Prefix length, 0 to 32', 'aria-invalid': customBad(), style: 'width:76px', oninput: (e: Event) => { customText = (e.target as HTMLInputElement).value; customSoon(); redraw(); } })) : null),
          customOn ? (customBad() ? h('span', { class: 'msg bad', role: 'alert' }, 'Enter a whole number from 0 to 32.') : h('span', { class: 'dim', style: 'font-size:12px' }, prefix === 0 ? '/0 puts every address in one group.' : prefix === 32 ? '/32 keeps each host separate.' : `Addresses are grouped into /${prefix} networks.`)) : null),
        btn('Combine A ↔ B (merge both directions of a host pair)', { pressed: bidir, onclick: () => { bidir = !bidir; void run(); redraw(); } }),
        field('Time range', select(range, RANGES, v => { range = v; void run(); redraw(); }, { aria: 'Time range', width: '176px' })),
        field('Rank by', select(sortBy, [['bytes', 'Bytes'], ['pkts', 'Packets'], ['flows', 'Flows']], v => { sortBy = v; void run(); redraw(); }, { aria: 'Rank by', width: '130px' })),
        field('Show', select(topN, [['10', 'Top 10'], ['25', 'Top 25'], ['100', 'Top 100'], ['all', 'Up to 1000']], v => { topN = v; void run(); redraw(); }, { aria: 'Rows to show', width: '130px' })),
        r ? h('span', { class: 'muted', style: 'max-width:300px' }, `Read from ${r.tier === 'raw' ? 'raw records' : r.tier === 'm1' ? '1-minute rollups' : r.tier === 'h1' ? '1-hour rollups' : 'daily rollups'}, the finest tier that covers this range.`) : null)),
    h('div', { class: 'split' },
      h('section', { 'aria-label': 'Report preview', class: 'mainp', style: 'flex-basis:700px' },
        error ? note(error, 'bad', true) : null,
        r?.errors.length ? note(r.errors.join('. '), 'warn', true) : null,
        busy && !r ? spinner('Building the report…') : null,
        r ? [
          h('div', { class: 'stats' },
            [['Flows', num(r.totals.flows)], ['Packets', num(r.totals.pkts)], ['Bytes', bytes(r.totals.bytes)], ['Groups', num(r.totalRows)]].map(([l, v]) => h('div', { key: l, class: 'stat', style: 'min-width:120px' }, h('div', { class: 'slabel' }, l), h('div', { class: 'svalue' }, v)))),
          busy ? h('span', { class: 'muted', role: 'status' }, 'Updating…') : null,
          table(r),
          r.totalRows > r.rows.length ? h('p', { class: 'muted' }, `Showing ${num(r.rows.length)} of ${num(r.totalRows)} groups; the rest are summed into the “Other” row and in the totals above.`) : null,
          !dims.size ? h('p', { class: 'muted' }, 'No grouping fields selected, so all matching flows are combined into one total. Pick fields at any layer to break it down.') : null
        ] : null),
      h('aside', { 'aria-label': 'Export', class: 'side panel col', style: 'flex-basis:420px;gap:12px' },
        h('h3', null, 'Export report'),
        seg('Preview format', [{ id: 'csv', label: 'CSV', on: fmt === 'csv' }, { id: 'json', label: 'JSON', on: fmt === 'json' }], id => { fmt = id as 'csv' | 'json'; redraw(); }),
        h('pre', { class: 'pre' }, r ? preview(r) : 'Run a report to see the export.'),
        h('div', { class: 'row' }, btn('Download CSV', { kind: 'primary', disabled: !r, onclick: () => void download('csv') }), btn('Download JSON', { disabled: !r, onclick: () => void download('json') }), btn('Copy to clipboard', { kind: 'ghost', disabled: !r, onclick: () => r && void copy(r) })),
        msg(copied || dlMsg, (copied || dlMsg).startsWith('Could') ? 'bad' : 'ok'),
        h('p', { class: 'muted' }, 'The export contains the rows of this report, with the grouping, filters, prefix length and time range recorded in the JSON header.'),
        r ? h('span', { class: 'dim' }, `Generated ${stamp(Date.now())}`) : null)));
}
