import { h, type VNode } from '../vdom.js';
import { get, qs } from '../api.js';
import { redraw, go } from '../state.js';
import { btn, chip, empty, field, heading, note, seg, select, spinner, textInput } from '../components.js';
import { bytes, dayClock, debounce, num, RANGES } from '../util.js';

/** Flows by port: pick a network device and one of its ports, say how many of the biggest flows to list, and open any of them in the Flow explorer. */

interface Port { ifIndex: number; name: string; alias: string; speedMbps: number; oper: string }
interface Dev { id: number; name: string; ip: string; role: string; ports: Port[] }
interface Exp { ip: string; name: string; lastSeen: number }
interface Sources { devices: Dev[]; exporters: Exp[]; counts: number[] }
interface Row {
  id: string; srcIp: string; dstIp: string; sport: number; dport: number; protoName: string; app: string; vlan: number | null; t0: number; t1: number;
  bytes: number; pkts: number; qosChanged: boolean; dscpInS: string; dscpOutS: string | null; ttlExpired: boolean; hopCount: number;
}
interface Result { device: { id: number | null; name: string; address: string }; port: { ifIndex: number; name: string; alias: string } | null; dir: string; sort: string; limit: number; total: number; shown: number; rows: Row[] }

const DIRS: [string, string][] = [['either', 'Either direction'], ['in', 'Entering the port'], ['out', 'Leaving the port']];
const SORTS: [string, string][] = [['bytes', 'Most bytes'], ['pkts', 'Most packets'], ['time', 'Most recent']];
const DIR_WORDS: Record<string, string> = { either: 'in either direction', in: 'entering', out: 'leaving' };
const SORT_WORDS: Record<string, string> = { bytes: 'by bytes', pkts: 'by packets', time: 'most recent first' };

let src: Sources | null = null; let srcError = '';
let who = '';                    // 'd:<device id>' or 'e:<exporter ip>'
let port = '0';                  // interface number as text; '0' is every port
let portFilter = '';
let devQuery = '';              // text typed into the device finder
let finding = false;             // the finder is open even though a device is chosen ("Change device")
let dir = 'either', sort = 'bytes', range = '1h', count = 50;
let res: Result | null = null; let loading = false; let err = '';

export function enter(p: URLSearchParams): void {
  const dev = p.get('dev'), exp = p.get('exporter');
  // A link that names a device starts from defaults, so a port picked earlier is not carried over to it.
  if ((dev && /^\d+$/.test(dev)) || exp) { port = '0'; portFilter = ''; devQuery = ''; finding = false; dir = 'either'; sort = 'bytes'; range = '1h'; count = 50; res = null; }
  if (dev && /^\d+$/.test(dev)) who = 'd:' + dev; else if (exp) who = 'e:' + exp;
  if (p.has('if') && /^\d+$/.test(p.get('if')!)) port = p.get('if')!;
  const d = p.get('dir'), s = p.get('sort'), r = p.get('range'), n = Number(p.get('n'));
  if (d && DIRS.some(x => x[0] === d)) dir = d;
  if (s && SORTS.some(x => x[0] === s)) sort = s;
  if (r && RANGES.some(x => x[0] === r)) range = r;
  if (n && (src?.counts ?? [25, 50, 100, 200, 500]).includes(n)) count = n;
  void loadSources().then(() => { if (who) void load(); });
}

async function loadSources(): Promise<void> {
  try { src = await get<Sources>('/api/ports/sources'); srcError = ''; } catch (e) { srcError = (e as Error).message; }
  redraw();
}

const devOf = (): Dev | undefined => who.startsWith('d:') ? src?.devices.find(d => String(d.id) === who.slice(2)) : undefined;

function syncHash(): void {
  const p = new URLSearchParams();
  if (who.startsWith('d:')) p.set('dev', who.slice(2)); else if (who.startsWith('e:')) p.set('exporter', who.slice(2));
  if (port !== '0') p.set('if', port);
  if (dir !== 'either') p.set('dir', dir);
  if (sort !== 'bytes') p.set('sort', sort);
  if (range !== '1h') p.set('range', range);
  if (count !== 50) p.set('n', String(count));
  const s = p.toString();
  history.replaceState(null, '', '#/ports' + (s ? '?' + s : ''));
}

let seq = 0;
async function load(): Promise<void> {
  if (!who) { res = null; redraw(); return; }
  const my = ++seq; loading = true; err = ''; redraw();
  const q = { dev: who.startsWith('d:') ? who.slice(2) : undefined, exporter: who.startsWith('e:') ? who.slice(2) : undefined, if: Number(port) || 0, dir, sort, range, limit: count };
  try {
    const r = await get<Result>('/api/ports/flows' + qs(q));
    if (my === seq) res = r;
  } catch (e) { if (my === seq) { res = null; err = (e as Error).message; } }
  if (my === seq) { loading = false; redraw(); }
}
const loadSoon = debounce(() => { void load(); }, 300);
function changed(soon = false): void { syncHash(); if (soon) loadSoon(); else void load(); }

const portLabel = (p: Port): string => [p.name, p.alias, p.speedMbps ? (p.speedMbps >= 1000 ? p.speedMbps / 1000 + ' G' : p.speedMbps + ' M') : '', p.oper !== 'up' ? p.oper : ''].filter(Boolean).join(' · ');

interface Choice { key: string; name: string; sub: string; kind: string; hay: string }
function choices(): Choice[] {
  const devs = src?.devices ?? [], exps = src?.exporters ?? [];
  return [
    ...devs.map(d => ({ key: 'd:' + d.id, name: d.name, sub: d.ip, kind: d.role, hay: `${d.name} ${d.ip} ${d.role} ${d.ports.map(p => p.name + ' ' + p.alias).join(' ')}`.toLowerCase() })),
    ...exps.map(e => ({ key: 'e:' + e.ip, name: e.name, sub: e.ip, kind: 'not polled', hay: `${e.name} ${e.ip} not polled exporter`.toLowerCase() }))
  ];
}
const matching = (): Choice[] => {
  const terms = devQuery.trim().toLowerCase().split(/\s+/).filter(Boolean);
  return choices().filter(c => terms.every(t => c.hay.includes(t)));
};
function choose(c: Choice): void { who = c.key; port = '0'; portFilter = ''; devQuery = ''; finding = false; changed(); }
function openFinder(): void {
  finding = true; redraw();
  setTimeout(() => document.getElementById('port-dev-find')?.focus(), 0);
}

/** The device search. Typing narrows the list by name, address, role or any port name on it; Enter takes the first match. Once a device is chosen it collapses to one line with a Change button. */
function deviceFinder(): VNode {
  const cur = choices().find(c => c.key === who);
  if (who && !finding) {
    return h('div', { class: 'field' }, h('span', { class: 'flabel' }, 'Network device'),
      h('div', { class: 'row', style: 'gap:10px;align-items:center;min-height:38px' },
        h('strong', null, cur?.name ?? who.slice(2)), cur && cur.sub !== cur.name ? h('span', { class: 'mono', style: 'color:var(--muted)' }, cur.sub) : null, cur ? chip(cur.kind, cur.kind === 'not polled' ? 'warn' : 'default') : null,
        btn('Change device', { small: true, onclick: openFinder })));
  }
  const all = choices(), found = matching();
  const shown = found.slice(0, 50);
  return h('div', { class: 'field', style: 'min-width:340px;flex:1 1 340px;max-width:560px' }, h('span', { class: 'flabel' }, 'Find a network device'),
    textInput(devQuery, v => { devQuery = v; }, {
      id: 'port-dev-find', placeholder: all.length ? `Search ${all.length} device${all.length === 1 ? '' : 's'}: name, address, role, port…` : 'No devices yet', aria: 'Search network devices', width: '100%',
      onenter: () => { if (found[0]) choose(found[0]); }
    }),
    h('div', { class: 'devlist', role: 'listbox', 'aria-label': 'Matching network devices' },
      shown.length ? shown.map(c => h('button', { key: c.key, type: 'button', role: 'option', class: 'devopt', 'aria-selected': c.key === who, onclick: () => choose(c) },
        h('span', { class: 'devname' }, c.name), c.sub !== c.name ? h('span', { class: 'mono devsub' }, c.sub) : null, chip(c.kind, c.kind === 'not polled' ? 'warn' : 'default')))
        : h('div', { class: 'empty', role: 'status' }, all.length ? `No device matches "${devQuery.trim()}".` : 'No devices are polled and no exporter has sent flows yet.'),
      found.length > shown.length ? h('div', { class: 'devmore' }, `${found.length - shown.length} more. Keep typing to narrow the list.`) : null),
    who ? h('span', { class: 'hint' }, btn('Keep the current device', { small: true, onclick: () => { finding = false; devQuery = ''; redraw(); } })) : null);
}

function picker(): VNode {
  const devs = src?.devices ?? [], exps = src?.exporters ?? [];
  const d = devOf();
  const terms = portFilter.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const ports = (d?.ports ?? []).filter(p => !terms.length || terms.every(t => portLabel(p).toLowerCase().includes(t)) || String(p.ifIndex) === port);
  const portOpts: [string, string][] = [['0', d ? `All ports of ${d.name.split('.')[0]}` : 'All ports'], ...ports.map(p => [String(p.ifIndex), portLabel(p)] as [string, string])];
  return h('div', { class: 'panel col', style: 'gap:14px' },
    h('div', { class: 'row', style: 'align-items:end;gap:14px' },
      deviceFinder(),
      who.startsWith('d:') && d ? [
        field('Find a port', textInput(portFilter, v => { portFilter = v; }, { placeholder: 'Gi1/0/46, uplink, AP…', aria: 'Filter the port list', width: '190px' })),
        field('Port', select(port, portOpts, v => { port = v; changed(); }, { aria: 'Port', width: '340px' }))]
        : who.startsWith('e:') ? field('Interface number (ifIndex)', textInput(port === '0' ? '' : port, v => { port = /^\d+$/.test(v.trim()) ? v.trim() : '0'; changed(true); }, { placeholder: 'blank = all ports', aria: 'Interface number', width: '190px', mono: true }), 'This device is not polled over SNMP, so its ports have numbers only.') : null),
    h('div', { class: 'row', style: 'align-items:end;gap:14px' },
      field('Direction', select(dir, DIRS, v => { dir = v; changed(); }, { aria: 'Direction', width: '190px' })),
      field('Time range', select(range, RANGES, v => { range = v; changed(); }, { aria: 'Time range', width: '176px' })),
      field('Rank by', select(sort, SORTS, v => { sort = v; changed(); }, { aria: 'Rank flows by', width: '160px' })),
      h('div', { class: 'field' }, h('span', { class: 'flabel' }, 'Show the top'),
        seg('How many flows', (src?.counts ?? [25, 50, 100, 200, 500]).map(n => ({ id: String(n), label: String(n), on: count === n })), id => { count = Number(id); changed(); }))));
}

function summary(r: Result): string {
  const where = r.port ? `${r.port.name}${r.port.alias ? ' (' + r.port.alias + ')' : ''} on ${r.device.name}` : `all ports of ${r.device.name}`;
  const what = r.port ? DIR_WORDS[r.dir] : 'in either direction';
  if (!r.total) return `No flows through ${where}, ${what}`;
  return `${r.shown === r.total ? 'All' : 'Top'} ${num(r.shown)} of ${num(r.total)} flow${r.total === 1 ? '' : 's'} through ${where}, ${what}, ${SORT_WORDS[r.sort]}`;
}

const COLS = '36px minmax(150px,1.3fr) minmax(150px,1.3fr) 56px 92px minmax(130px,1fr) 78px 112px 112px';
function results(): VNode {
  if (!who) return h('div', { class: 'panel' }, empty('Choose a network device to list its busiest flows. Then pick one port, or leave it on "All ports".'));
  const r = res;
  const top = r?.rows[0]?.bytes ?? 0;
  return h('section', { 'aria-label': 'Flows through the port', class: 'col', style: 'gap:10px' },
    h('div', { class: 'row', style: 'justify-content:space-between;color:var(--muted)' },
      h('span', { role: 'status', 'aria-live': 'polite' }, loading ? 'Searching…' : r ? summary(r) : ''),
      h('span', null, 'Select a flow to follow it hop by hop in the Flow explorer')),
    err ? note(err, 'bad', true) : null,
    r && r.total > r.shown && !loading ? note(`${num(r.total - r.shown)} more flow${r.total - r.shown === 1 ? '' : 's'} match. Raise the number above, or narrow the time range.`, 'info') : null,
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${COLS};--w:1080px` },
      h('div', { class: 'tr head' }, ...['#', 'Source', 'Destination', 'Proto', 'Service', 'Share of bytes', 'Bytes', 'Packets', 'Last seen'].map(t => h('span', null, t))),
      h('div', { class: 'scroll', style: 'max-height:640px' },
        (r?.rows ?? []).map((x, i) => h('button', { key: x.id, type: 'button', class: 'tr', title: 'Open this flow in the Flow explorer', onclick: () => go('explorer', { s: x.id, q: `ip:${x.srcIp} ip:${x.dstIp}`, range }) },
          h('span', { class: 'dim', style: 'font-size:12px' }, String(i + 1)),
          h('span', { class: 'mono' }, x.srcIp, x.sport ? h('span', { class: 'dim' }, ':' + x.sport) : null),
          h('span', { class: 'mono' }, x.dstIp, x.dport ? h('span', { class: 'dim' }, ':' + x.dport) : null),
          h('span', { style: 'font-weight:500' }, x.protoName),
          h('span', null, x.app),
          h('span', { class: 'row', style: 'gap:6px;flex-wrap:nowrap' }, h('span', { 'aria-hidden': 'true', style: 'flex:1;height:6px;border-radius:3px;background:var(--raised);overflow:hidden' }, h('span', { style: `display:block;height:100%;width:${top ? Math.max(2, Math.round(x.bytes / top * 100)) : 0}%;background:var(--accent)` })),
            x.qosChanged ? chip('QoS', 'bad', `DSCP re-marked ${x.dscpInS} → ${x.dscpOutS ?? ''}`) : null, x.ttlExpired ? chip('TTL', 'bad', 'TTL expired') : null),
          h('span', { class: 'mono', style: 'font-size:12px' }, bytes(x.bytes)),
          h('span', { class: 'mono', style: 'font-size:12px' }, num(x.pkts)),
          h('span', { class: 'mono muted', style: 'font-size:12px' }, dayClock(x.t1)))),
        loading && !r ? spinner('Searching…') : null,
        r && !r.rows.length && !loading ? empty('No flows were recorded through this port in the time range. Try a longer range, or "Either direction". Exporters that send input-only or output-only records only show the side they report.') : null))));
}

export function render(): VNode {
  return h('main', null,
    heading('Flows by port', 'The busiest flows through a port', 'Pick a network device and one of its ports to see the flows that crossed it, biggest first. Flow explorer shows everything; this finds the traffic of one cable.'),
    srcError ? note(srcError, 'bad', true) : null,
    !src && !srcError ? spinner() : null,
    src && !src.devices.length && !src.exporters.length ? note('No devices have sent flows or been added yet.', 'info') : null,
    src ? picker() : null,
    src ? results() : null);
}
