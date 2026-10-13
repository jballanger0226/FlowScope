import { h, type VNode } from '../vdom.js';
import { get, qs } from '../api.js';
import { redraw, go } from '../state.js';
import { bar, btn, chip, empty, heading, lineChart, note, PALETTE, select, spinner, status as statusEl, textInput, type Series } from '../components.js';
import { ago, bps, bytes, clock, dayClock, dur, num, pct, debounce } from '../util.js';

interface Cls { cls: string; dscps: number[]; bw: string | null; queue: string | null; dropPct: number | null; dropPkts: number; dropBytes: number; sentBps: number | null; qdepth: number | null }
interface Iface {
  ifIndex: number; name: string; alias: string; speedMbps: number | null; oper: string; policy: string | null;
  utilIn: number | null; utilOut: number | null; inBps: number | null; outBps: number | null; disc: number; err: number;
  classes: Cls[]; worstDropPct: number | null; flagged: boolean;
}
interface Dev { id: number; name: string; ip: string; role: string; status: string; lastOk: number | null; lastError: string | null; profile: string; interfaces: Iface[] }
interface Overview { devices: Dev[]; windowMinutes: number; thresholds: { util: number; drop: number }; mibs: { name: string; what: string }[] }
interface SeriesRes {
  util: { step: number; points: { ts: number; utilIn: number; utilOut: number; inBps: number; outBps: number; disc: number; err: number }[] };
  classes: { cls: string; dscps: number[]; bw: string | null; points: { ts: number; dropPct: number; dropBps: number; dropPps: number; sentBps: number; qdepth: number }[] }[];
  step: number; tier: string;
}
interface StreamRow { id: string; srcIp: string; dstIp: string; sport: number; dport: number; app: string; protoName: string; bytes: number; qosChanged: boolean }

let data: Overview | null = null; let loadError = ''; let loading = false;
let search = '';
let devId = 0; let ifIndex = 0;
let graphRange = '6h';
let dropThr = 1;
let hidden = new Set<string>();
let series: SeriesRes | null = null; let seriesError = ''; let seriesLoading = false;
let streams: StreamRow[] = []; let streamsTotal = 0; let streamsLoading = false;
let pendingName: { dev: string; ifn: string } | null = null;
let timer: number | undefined;

const GRAPH_RANGES: [string, string][] = [['1h', 'Last hour'], ['6h', 'Last 6 hours'], ['24h', 'Last 24 hours'], ['7d', 'Last 7 days']];
const RANGE_MS: Record<string, number> = { '1h': 3600e3, '6h': 6 * 3600e3, '24h': 24 * 3600e3, '7d': 7 * 86400e3 };
const THRESHOLDS: [string, string][] = [['0.5', '0.5%'], ['1', '1%'], ['2', '2%'], ['5', '5%']];

export function enter(p: URLSearchParams): void {
  const d = p.get('dev'), i = p.get('if');
  if (d) {
    pendingName = { dev: d, ifn: i ?? '' };
    if (data) resolvePending();
  }
  void load();
  window.clearInterval(timer);
  timer = window.setInterval(() => { if (!document.hidden && location.hash.startsWith('#/links')) void load(true); }, 30_000);
}

async function load(quiet = false): Promise<void> {
  if (!quiet) { loading = true; loadError = ''; redraw(); }
  try {
    data = await get<Overview>('/api/links?minutes=10');
    loadError = '';
    if (pendingName) resolvePending();
    else if (!devId && data.devices.length) { const first = needsAttention()[0]; if (first) select_(first.dev.id, first.itf.ifIndex); else select_(data.devices[0].id, data.devices[0].interfaces[0]?.ifIndex ?? 0); }
  } catch (e) { loadError = (e as Error).message; }
  loading = false; redraw();
}

function resolvePending(): void {
  if (!data || !pendingName) return;
  const { dev, ifn } = pendingName; pendingName = null;
  const lc = dev.toLowerCase();
  const d = data.devices.find(x => x.name.toLowerCase() === lc || x.ip === dev || String(x.id) === dev) ?? data.devices.find(x => x.name.toLowerCase().includes(lc));
  if (!d) return;
  const itf = ifn ? d.interfaces.find(i => i.name.toLowerCase() === ifn.toLowerCase() || String(i.ifIndex) === ifn) : d.interfaces.find(i => i.flagged) ?? d.interfaces[0];
  select_(d.id, itf?.ifIndex ?? d.interfaces[0]?.ifIndex ?? 0);
}

function select_(d: number, i: number): void {
  devId = d; ifIndex = i; series = null; streams = []; streamsTotal = 0; seriesError = '';
  void loadSeries(); void loadStreams();
  redraw();
}

let sseq = 0;
async function loadSeries(): Promise<void> {
  if (!devId || !ifIndex) return;
  const my = ++sseq; seriesLoading = true; seriesError = ''; redraw();
  try {
    const r = await get<SeriesRes>('/api/links/series' + qs({ dev: devId, if: ifIndex, range: graphRange, points: 120 }));
    if (my !== sseq) return;
    series = r;
  } catch (e) { if (my === sseq) { series = null; seriesError = (e as Error).message; } }
  if (my === sseq) { seriesLoading = false; redraw(); }
}
async function loadStreams(): Promise<void> {
  if (!devId || !ifIndex) return;
  const d = devId, i = ifIndex; streamsLoading = true; redraw();
  try {
    const r = await get<{ rows: StreamRow[]; total: number }>('/api/links/streams' + qs({ dev: d, if: i, range: '1h', limit: 8 }));
    if (d === devId && i === ifIndex) { streams = r.rows; streamsTotal = r.total; }
  } catch { if (d === devId && i === ifIndex) { streams = []; streamsTotal = 0; } }
  streamsLoading = false; redraw();
}

const searchSoon = debounce(() => redraw(), 120);

function needsAttention(): { dev: Dev; itf: Iface }[] {
  if (!data) return [];
  const out: { dev: Dev; itf: Iface }[] = [];
  for (const d of data.devices) for (const i of d.interfaces) if (i.flagged) out.push({ dev: d, itf: i });
  out.sort((a, b) => (b.itf.worstDropPct ?? 0) - (a.itf.worstDropPct ?? 0) || Math.max(b.itf.utilOut ?? 0, b.itf.utilIn ?? 0) - Math.max(a.itf.utilOut ?? 0, a.itf.utilIn ?? 0));
  return out;
}

const cur = () => {
  const d = data?.devices.find(x => x.id === devId);
  return { dev: d, itf: d?.interfaces.find(i => i.ifIndex === ifIndex) };
};

const classColor = (name: string, all: string[]) => PALETTE[Math.max(0, all.indexOf(name)) % PALETTE.length];
const dscpText = (d: number[]) => (d.length ? d.join(', ') : '—');

/* ------------------------------------------------------------------ sidebar */

function sidebar(): VNode {
  const d = data!;
  const t = search.trim().toLowerCase();
  const devs = d.devices.filter(x => !t || x.name.toLowerCase().includes(t) || x.ip.includes(t) || x.role.toLowerCase().includes(t) || x.interfaces.some(i => i.name.toLowerCase().includes(t) || i.alias.toLowerCase().includes(t)));
  const attn = needsAttention();
  return h('aside', { class: 'side', 'aria-label': 'Devices' },
    h('div', { class: 'panel col', style: 'gap:10px' },
      h('h3', null, 'Devices'),
      textInput(search, v => { search = v; searchSoon(); }, { placeholder: 'Search device, address or interface', aria: 'Search devices' }),
      h('div', { class: 'cards' },
        devs.map(x => {
          const flagged = x.interfaces.filter(i => i.flagged).length;
          return h('button', { key: x.id, type: 'button', class: 'cardbtn', 'aria-pressed': x.id === devId, onclick: () => { const first = x.interfaces.find(i => i.flagged) ?? x.interfaces[0]; select_(x.id, first?.ifIndex ?? 0); } },
            h('span', { class: 't' }, x.name), h('span', { class: 's' }, `${x.role} · ${x.ip}`),
            h('span', { class: 's' }, x.status === 'ok' ? statusEl(flagged ? 'warn' : 'ok', flagged ? `${flagged} interface${flagged === 1 ? ' needs' : 's need'} attention` : 'Healthy') : statusEl(x.status === 'paused' ? 'off' : 'bad', x.status === 'paused' ? 'Polling paused' : x.lastError ? 'Not answering' : 'Waiting for first poll')));
        }),
        !devs.length ? h('span', { class: 'dim' }, d.devices.length ? 'No device matches.' : 'No devices are polled yet. Add one on the SNMP devices tab.') : null)),
    h('div', { class: 'panel col', style: 'gap:10px' },
      h('h3', null, 'Needs attention'),
      h('p', { class: 'muted' }, `Interfaces above ${d.thresholds.util}% utilisation or dropping more than ${d.thresholds.drop}% of a class, in the last ${d.windowMinutes} minutes.`),
      attn.length ? h('div', { class: 'cards' }, attn.slice(0, 8).map(a => h('button', { key: a.dev.id + '/' + a.itf.ifIndex, type: 'button', class: 'cardbtn', 'aria-pressed': a.dev.id === devId && a.itf.ifIndex === ifIndex, onclick: () => select_(a.dev.id, a.itf.ifIndex) },
        h('span', { class: 't' }, `${a.dev.name} · ${a.itf.name}`),
        h('span', { class: 's' }, [a.itf.worstDropPct !== null && a.itf.worstDropPct >= d.thresholds.drop ? `drops ${pct(a.itf.worstDropPct, 2)}` : null, `util ${pct(Math.max(a.itf.utilIn ?? 0, a.itf.utilOut ?? 0), 0)}`].filter(Boolean).join(' · '))))) : h('span', { class: 'dim' }, 'Nothing is over its threshold right now.')),
    h('div', { class: 'panel col', style: 'gap:8px' },
      h('h3', null, 'What is polled'),
      h('p', { class: 'muted' }, 'FlowScope reads these SNMP tables every minute from each device it can.'),
      h('div', { class: 'pts' }, d.mibs.map(m => h('div', { key: m.name, class: 'pt' }, h('i'), h('span', null, h('b', null, m.name), h('br'), h('span', { class: 'muted' }, m.what)))))));
}

/* ------------------------------------------------------------------ interface & class tables */

function ifTable(dev: Dev): VNode {
  const cols = 'minmax(120px,1fr) minmax(140px,1.2fr) 80px 70px 150px 150px 90px 120px';
  return h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${cols};--w:960px` },
    h('div', { class: 'tr head' }, ...['Interface', 'Description', 'Speed', 'State', 'In', 'Out', 'Discards', 'Queue policy'].map(t => h('span', null, t))),
    h('div', { class: 'scroll' }, dev.interfaces.map(i => h('button', { key: i.ifIndex, type: 'button', class: 'tr', 'aria-pressed': i.ifIndex === ifIndex, onclick: () => select_(dev.id, i.ifIndex) },
      h('span', { style: 'font-weight:600' }, i.name, i.flagged ? h('span', { style: 'color:var(--warn);margin-left:6px', title: 'Needs attention' }, '●') : null),
      h('span', { class: 'muted' }, i.alias || '—'),
      h('span', { class: 'mono', style: 'font-size:12px' }, i.speedMbps ? (i.speedMbps >= 1000 ? i.speedMbps / 1000 + ' G' : i.speedMbps + ' M') : '—'),
      h('span', null, i.oper === 'up' ? statusEl('ok', 'up') : statusEl(i.oper === 'down' ? 'bad' : 'off', i.oper)),
      utilCell(i.utilIn, i.inBps), utilCell(i.utilOut, i.outBps),
      h('span', { class: 'mono', style: 'font-size:12px' }, num(i.disc + i.err)),
      h('span', { class: 'muted', style: 'font-size:12px' }, i.policy ?? '—'))),
      !dev.interfaces.length ? empty('This device has not reported any interfaces yet.') : null)));
}
function utilCell(u: number | null, b: number | null): VNode {
  return h('span', { class: 'row', style: 'gap:8px;flex-wrap:nowrap' }, u === null ? h('span', { class: 'dim' }, 'no data') : [bar(u), h('span', { class: 'mono', style: 'font-size:12px' }, pct(u, 0) + ' ', h('span', { class: 'dim' }, bps(b)))]);
}

function classTable(itf: Iface): VNode {
  const cols = 'minmax(120px,1fr) minmax(110px,1fr) 100px 110px 110px 110px 100px';
  return h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${cols};--w:780px` },
    h('div', { class: 'tr head' }, ...['Class', 'DSCP values', 'Guaranteed', 'Sent', 'Drop %', 'Dropped', 'Queue depth'].map(t => h('span', null, t))),
    itf.classes.map(c => h('div', { key: c.cls, class: 'tr' },
      h('span', { style: 'font-weight:600' }, c.cls), h('span', { class: 'mono muted', style: 'font-size:12px' }, dscpText(c.dscps)),
      h('span', { class: 'mono', style: 'font-size:12px' }, c.bw ?? '—'), h('span', { class: 'mono', style: 'font-size:12px' }, bps(c.sentBps)),
      h('span', { class: 'mono', style: `font-size:12px;color:${(c.dropPct ?? 0) >= (data?.thresholds.drop ?? 1) ? 'var(--bad)' : 'inherit'}` }, c.dropPct === null ? '—' : pct(c.dropPct, 2)),
      h('span', { class: 'mono', style: 'font-size:12px' }, c.dropPkts ? `${num(c.dropPkts)} pkts · ${bytes(c.dropBytes)}` : '0'),
      h('span', { class: 'mono', style: 'font-size:12px' }, c.qdepth === null ? '—' : num(c.qdepth)))),
    !itf.classes.length ? h('div', { class: 'empty' }, itf.policy ? 'No class statistics have been read from this interface yet.' : 'No output queue policy is attached to this interface, or the device does not publish CISCO-CLASS-BASED-QOS-MIB.') : null));
}

/* ------------------------------------------------------------------ graphs */

interface Ev { cls: string; a: number; b: number; peak: number; pkts: number }

function events(s: SeriesRes, names: string[]): Ev[] {
  const out: Ev[] = [];
  for (const c of s.classes) {
    if (hidden.has(c.cls)) continue;
    let curE: Ev | null = null;
    for (const p of c.points) {
      if (p.dropPct >= dropThr) {
        const pk = p.dropPps * s.step / 1000;
        if (curE && p.ts - curE.b <= s.step * 1.5) { curE.b = p.ts; curE.peak = Math.max(curE.peak, p.dropPct); curE.pkts += pk; }
        else { if (curE) out.push(curE); curE = { cls: c.cls, a: p.ts, b: p.ts, peak: p.dropPct, pkts: pk }; }
      }
    }
    if (curE) out.push(curE);
  }
  void names;
  return out.sort((a, b) => b.a - a.a);
}

function graphs(s: SeriesRes, itf: Iface): VNode {
  const names = s.classes.map(c => c.cls);
  const to = Date.now(); const from = to - RANGE_MS[graphRange];
  const shown = s.classes.filter(c => !hidden.has(c.cls));
  const evs = events(s, names);
  const bands = evs.map(e => ({ a: e.a - s.step / 2, b: e.b + s.step / 2 }));
  const fmtT = (t: number) => (RANGE_MS[graphRange] > 86400e3 ? dayClock(t) : clock(t, false));
  const mk = (pick: (p: SeriesRes['classes'][0]['points'][0]) => number): Series[] => shown.map(c => ({ name: c.cls, color: classColor(c.cls, names), points: c.points.map(p => ({ t: p.ts, v: pick(p) })) }));
  const peak = (c: SeriesRes['classes'][0]) => Math.max(0, ...c.points.map(p => p.dropPct));
  return h('div', { class: 'col', style: 'gap:14px' },
    h('div', { class: 'row end' },
      select(graphRange, GRAPH_RANGES, v => { graphRange = v; void loadSeries(); }, { aria: 'Graph time range', width: '176px' }),
      h('label', { class: 'row', style: 'gap:8px' }, h('span', { class: 'muted' }, 'Mark drops above'), select(String(dropThr), THRESHOLDS, v => { dropThr = Number(v); redraw(); }, { aria: 'Drop threshold', width: '96px' })),
      s.tier === 'h1' ? chip('hourly averages', 'info', 'The range is older than the per-poll samples kept, so hourly summaries are shown') : null),
    names.length ? h('div', { role: 'group', 'aria-label': 'Classes shown', class: 'row', style: 'gap:8px' },
      s.classes.map(c => h('button', { key: c.cls, type: 'button', class: 'cbtn', 'aria-pressed': !hidden.has(c.cls), onclick: () => { if (hidden.has(c.cls)) hidden.delete(c.cls); else hidden.add(c.cls); redraw(); } },
        h('i', { class: 'sw', style: `background:${classColor(c.cls, names)};margin:0` }), h('span', null, c.cls), h('span', { class: 'dim' }, 'peak ' + pct(peak(c), 2))))) : null,
    names.length ? h('div', { class: 'charts' },
      lineChart({ title: 'Packets dropped (% of the class)', unit: v => (v < 10 ? v.toFixed(1) : v.toFixed(0)) + '%', series: mk(p => p.dropPct), from, to, threshold: dropThr, bands, fmtT, aria: `Drop percentage per class on ${itf.name}` }),
      lineChart({ title: 'Bytes dropped (per second)', unit: v => bytes(v) + '/s', series: mk(p => p.dropBps / 8), from, to, bands, fmtT, aria: `Bytes dropped per class on ${itf.name}` })) : null,
    h('div', { class: 'charts' }, lineChart({
      wide: true, title: 'Utilisation (% of line speed)', unit: v => v.toFixed(0) + '%', yMax: Math.max(100, ...s.util.points.map(p => Math.max(p.utilIn, p.utilOut))), threshold: data?.thresholds.util, from, to, fmtT,
      series: [{ name: 'In', color: 'var(--s3)', points: s.util.points.map(p => ({ t: p.ts, v: p.utilIn })) }, { name: 'Out', color: 'var(--s1)', points: s.util.points.map(p => ({ t: p.ts, v: p.utilOut })) }], aria: `Utilisation of ${itf.name}`
    })),
    h('div', { class: 'legendrow' }, h('span', null, h('i', { class: 'sw', style: 'background:var(--s3)' }), 'In'), h('span', null, h('i', { class: 'sw', style: 'background:var(--s1)' }), 'Out'), h('span', null, 'Shaded bands mark periods when a shown class was above the threshold, on every graph. Percentages and bytes come from the same SNMP counter deltas at each poll.')),
    h('div', { class: 'col', style: 'gap:6px' },
      h('b', null, 'Drop events above the threshold'),
      evs.length ? h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:150px 210px 90px 110px 1fr;--w:760px' }, evs.slice(0, 30).map((e, i) => h('div', { key: i, class: 'tr' },
        h('span', null, h('i', { class: 'sw', style: `background:${classColor(e.cls, names)}` }), e.cls),
        h('span', { class: 'mono', style: 'font-size:12px' }, `${dayClock(e.a)} → ${clock(e.b + s.step)}`), h('span', { class: 'muted' }, dur(e.b - e.a + s.step)),
        h('span', { class: 'mono', style: 'font-size:12px;color:var(--bad)' }, 'peak ' + pct(e.peak, 2)), h('span', { class: 'muted' }, `about ${num(e.pkts)} packets dropped`)))))
        : h('span', { class: 'dim' }, names.length ? 'No shown class went above the threshold in this window.' : 'There are no queue classes on this interface.')));
}

function streamsPanel(dev: Dev, itf: Iface): VNode {
  return h('div', { class: 'col', style: 'gap:8px' },
    h('b', null, `Streams leaving ${dev.name} · ${itf.name}`),
    streamsLoading && !streams.length ? spinner('Looking for streams…') : null,
    !streamsLoading && !streams.length ? h('span', { class: 'dim' }, 'No sampled streams leave through this interface in the current data.') : null,
    h('div', { class: 'cards' }, streams.map(x => h('button', { key: x.id, type: 'button', class: 'cardbtn', onclick: () => go('explorer', { s: x.id, q: `ip:${x.srcIp} ip:${x.dstIp}`, range: '24h' }) },
      h('span', { class: 't mono' }, `${x.srcIp}:${x.sport} → ${x.dstIp}:${x.dport}`),
      h('span', { class: 's' }, `${x.app} · ${bytes(x.bytes)}`, x.qosChanged ? h('span', { class: 'tag bad', style: 'margin-left:8px' }, 'QoS re-marked') : null)))),
    streamsTotal > streams.length ? h('span', { class: 'dim' }, `${num(streamsTotal)} streams in total in the last hour; the busiest are shown.`) : null);
}

/* ------------------------------------------------------------------ view */

export function render(): VNode {
  if (loading && !data) return h('main', null, heading('Links and QoS', 'Interfaces and queues'), spinner());
  if (loadError && !data) return h('main', null, heading('Links and QoS', 'Interfaces and queues'), note(loadError, 'bad', true), btn('Try again', { onclick: () => void load() }));
  if (!data) return h('main');
  const { dev, itf } = cur();
  const head = heading('Links and QoS', 'Interfaces and queues', 'Utilisation, discards and per-class queue drops read from your devices over SNMP. Pick a device and interface to see how it behaved and which streams use it.');
  if (!data.devices.length) return h('main', null, head, h('div', { class: 'panel' }, empty('No SNMP devices have been added yet. Add switches and routers on the SNMP devices tab, and their interfaces and queues will appear here.')), btn('Go to SNMP devices', { kind: 'primary', onclick: () => go('devices') }));
  return h('main', null, head, h('div', { class: 'split' }, sidebar(),
    h('div', { class: 'mainp' },
      dev ? h('section', { 'aria-label': 'Selected device', class: 'panel col', style: 'gap:14px' },
        h('div', { class: 'row', style: 'justify-content:space-between' },
          h('div', { class: 'col', style: 'gap:4px' }, h('h3', { style: 'font-size:17px' }, dev.name), h('span', { class: 'muted' }, `${dev.role} · ${dev.ip} · ${dev.profile || 'generic'} · last answered ${ago(dev.lastOk)}`)),
          btn('Edit in SNMP devices', { kind: 'ghost', small: true, onclick: () => go('devices', { id: dev.id }) })),
        dev.status !== 'ok' && dev.lastError ? note(`The last poll failed: ${dev.lastError}`, 'warn') : null,
        ifTable(dev)) : null,
      dev && itf ? h('section', { 'aria-label': 'Selected interface', class: 'panel col', style: 'gap:16px' },
        h('div', { class: 'row', style: 'justify-content:space-between' }, h('div', { class: 'col', style: 'gap:4px' }, h('h3', { style: 'font-size:17px' }, `${itf.name}${itf.alias ? ' · ' + itf.alias : ''}`),
          h('span', { class: 'muted' }, `${itf.speedMbps ? (itf.speedMbps >= 1000 ? itf.speedMbps / 1000 + ' Gbps' : itf.speedMbps + ' Mbps') : 'speed unknown'}${itf.policy ? ' · output policy ' + itf.policy : ''}`)),
          h('div', { class: 'row' }, itf.flagged ? chip('Needs attention', 'warn') : chip('Within thresholds', 'ok'))),
        classTable(itf),
        seriesLoading && !series ? spinner('Loading the graphs…') : seriesError ? note(seriesError, 'bad', true) : series ? graphs(series, itf) : null,
        streamsPanel(dev, itf)) : dev ? h('div', { class: 'panel' }, empty('Select an interface to see its queues and graphs.')) : null)));
}
