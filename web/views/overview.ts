import { h, type Child, type VNode } from '../vdom.js';
import { get } from '../api.js';
import { go, redraw, session } from '../state.js';
import { bar, btn, chip, heading, note, spinner } from '../components.js';
import { ago, bps, bytes, dur, num, pct, stamp } from '../util.js';

/** The home page: the top few things from each of the other pages, what needs attention, and whether any SNMP device is down. */

type Tab = 'overview' | 'interfaces' | 'hardware' | 'network' | 'wifi';
interface Notice { level: 'bad' | 'warn'; kind: 'device-down' | 'issue'; title: string; detail: string; devId: number; dev: string; target: { tab: Tab; ifIndex?: number; section?: 'traffic' | 'quality' } }
interface Down { id: number; name: string; ip: string; role: string; since: number; neverReached: boolean; downMs: number; lastError: string | null }
interface Exp { ip: string; name: string; devId: number | null; version: string; records: number; lastSeen: number; lastError: string | null }
interface Flow { id: string; srcIp: string; dstIp: string; sport: number; dport: number; app: string; protoName: string; bytes: number; hopCount: number; qosChanged: boolean; ttlExpired: boolean }
interface Port { devId: number; dev: string; ifIndex: number; name: string; alias: string; speedMbps: number | null; utilIn: number | null; utilOut: number | null; inBps: number | null; outBps: number | null; util: number; over: boolean }
interface LogRow { id: number; ts: number; level: 'WARN' | 'ERROR' | 'INFO' | 'DEBUG'; source: string; user: string; message: string }
interface Reply {
  generatedAt: number;
  collect: { flow: boolean; snmp: boolean };
  notices: { total: number; bad: number; warn: number; items: Notice[] };
  devices: { total: number; ok: number; paused: number; pending: number; down: Down[]; busyCpu: { id: number; name: string; role: string; cpuPct: number | null; memPct: number | null }[] };
  flows: { windowMinutes: number; top: Flow[] | null; error: string | null; stats: { packets: number; records: number; errors: number; dropped: number }; exporters: { total: number; active: number; silent: (Exp & { silentMs: number })[]; top: Exp[] } };
  ports: { windowMinutes: number; busiest: Port[] };
  logs: null | { windowHours: number; errors: number; warnings: number; items: LogRow[] };
}

let data: Reply | null = null; let loadError = ''; let timer: number | undefined;

export function enter(_p: URLSearchParams): void {
  void load();
  window.clearInterval(timer);
  timer = window.setInterval(() => { if (session.view === 'overview' && !document.hidden) void load(true); }, 30_000);
}

async function load(quiet = false): Promise<void> {
  try { data = await get<Reply>('/api/overview'); loadError = ''; } catch (e) { loadError = (e as Error).message; }
  if (!quiet || data) redraw();
}

const TAB_LABEL: Record<Tab, string> = { overview: 'device', interfaces: 'interface', hardware: 'hardware', network: 'routing', wifi: 'Wi-Fi' };

/** Opens a notice where it is explained: the device's page on Network health, at the right tab, interface and section. */
function review(n: Notice): void { go('links', { dev: n.devId, if: n.target.ifIndex, tab: n.target.tab, section: n.target.section }); }

const plural = (n: number, one: string, many = one + 's'): string => `${num(n)} ${n === 1 ? one : many}`;

/* ------------------------------------------------------------------ pieces */

function box(title: string, sub: Child, body: Child[], footer?: VNode | null): VNode {
  return h('section', { class: 'panel ovbox', 'aria-label': title },
    h('header', { class: 'ovhead' }, h('h3', null, title), sub ? h('span', { class: 'muted ovsub' }, sub) : null),
    ...body, footer ? h('div', { class: 'ovfoot' }, footer) : null);
}
const none = (text: string): VNode => h('p', { class: 'dim', style: 'margin:0;font-size:13px' }, text);

/** Devices that stopped answering SNMP, with how long each has been silent. Always shown, so "nothing is down" is something you can see. */
function downPanel(d: Reply): VNode {
  const caps = session.me?.caps;
  if (!d.devices.total) return h('section', { class: 'panel', 'aria-label': 'SNMP device status' }, h('div', { class: 'row', style: 'gap:10px' }, chip('No SNMP devices', 'default'), h('span', { class: 'muted', style: 'font-size:13px' }, 'Add devices to see their health, link utilisation and queue drops here.'),
    caps?.devices ? btn('Add SNMP devices', { small: true, onclick: () => go('devices') }) : null));
  if (!d.devices.down.length) return h('section', { class: 'panel', 'aria-label': 'SNMP device status' }, h('div', { class: 'row', style: 'gap:10px' }, chip('All responding', 'ok'),
    h('span', { style: 'font-size:13.5px' }, `All ${plural(d.devices.ok, 'SNMP device')} answered the last poll.`),
    d.devices.paused ? h('span', { class: 'muted', style: 'font-size:12.5px' }, `${num(d.devices.paused)} paused.`) : null));
  return h('section', { class: 'panel ovdown', 'aria-label': 'SNMP devices that are down', role: 'alert' },
    h('div', { class: 'row', style: 'gap:10px;margin-bottom:10px' }, chip(`${d.devices.down.length} of ${d.devices.total} down`, 'bad'), h('b', null, d.devices.down.length === 1 ? 'An SNMP device is not responding' : 'SNMP devices are not responding')),
    h('ul', { class: 'ovlist' }, d.devices.down.map(x => h('li', { key: x.id, class: 'ovitem bad' },
      h('div', { class: 'ovmain' },
        h('span', { class: 'ovtitle' }, x.name, ' ', h('span', { class: 'mono muted', style: 'font-weight:400;font-size:12px' }, x.ip)),
        h('span', { class: 'muted', style: 'font-size:12.5px' }, x.neverReached ? 'It has never answered a poll since it was added ' + ago(x.since) + '.' : `Last answered ${stamp(x.since)} (${ago(x.since)})`),
        x.lastError ? h('span', { class: 'dim', style: 'font-size:12px' }, x.lastError) : null),
      h('div', { class: 'row', style: 'gap:8px;flex-wrap:nowrap;flex:none' },
        h('span', { class: 'downfor', title: x.neverReached ? 'Time since the device was added' : 'Time since its last successful poll' }, h('small', null, 'Down for'), h('b', null, dur(x.downMs))),
        btn('Review', { small: true, kind: 'ghost', aria: `Review ${x.name}`, onclick: () => go('links', { dev: x.id, tab: 'overview' }) }),
        caps?.devices ? btn('Manage', { small: true, kind: 'ghost', aria: `Manage ${x.name}`, onclick: () => go('devices', { id: x.id }) }) : null)))));
}

function noticesPanel(d: Reply): VNode {
  const n = d.notices;
  const head = h('div', { class: 'row', style: 'gap:8px;margin-bottom:10px' }, h('h3', null, 'Highest-impact notices'),
    n.total ? [n.bad ? chip(`${n.bad} problem${n.bad === 1 ? '' : 's'}`, 'bad') : null, n.warn ? chip(`${n.warn} warning${n.warn === 1 ? '' : 's'}`, 'warn') : null] : chip('Nothing needs attention', 'ok'));
  if (!n.total) return h('section', { class: 'panel', 'aria-label': 'Notices' }, head, none('Devices, interfaces, hardware and routing are all within their limits.'));
  return h('section', { class: 'panel', 'aria-label': 'Notices' }, head,
    h('ul', { class: 'ovlist' }, n.items.map((x, i) => h('li', { key: i, class: 'ovitem ' + (x.level === 'bad' ? 'bad' : '') },
      h('div', { class: 'row', style: 'flex-wrap:nowrap;align-items:flex-start;gap:10px;min-width:0' },
        chip(x.level === 'bad' ? 'Problem' : 'Warning', x.level),
        h('div', { class: 'ovmain' }, h('span', { class: 'ovtitle' }, x.title), h('span', { class: 'muted', style: 'font-size:12px' }, x.dev + (x.detail ? ' · ' + x.detail : '')))),
      h('span', { style: 'flex:none' }, btn(x.target.tab === 'overview' ? 'Review device' : `Review in ${TAB_LABEL[x.target.tab]}`, { small: true, kind: 'ghost', aria: `Review: ${x.title} on ${x.dev}`, onclick: () => review(x) }))))),
    h('div', { class: 'row', style: 'gap:10px;margin-top:10px' },
      n.total > n.items.length ? h('span', { class: 'muted', style: 'font-size:12.5px' }, `${plural(n.total - n.items.length, 'more notice')} on Network health.`) : null,
      btn('Open Network health', { small: true, onclick: () => go('links') })));
}

function flowsBox(d: Reply): VNode {
  const f = d.flows;
  const body: Child[] = [];
  if (f.error) body.push(note('Could not search flows: ' + f.error, 'bad'));
  else if (!f.top || !f.top.length) body.push(none(d.collect.flow ? 'No flows were recorded in the last hour.' : 'Flow collection is off, so nothing new is being recorded.'));
  else body.push(h('ul', { class: 'ovlist' }, f.top.map(x => h('li', { key: x.id },
    h('button', { type: 'button', class: 'ovitem ovbtn', title: 'Search for this flow in Flow explorer', onclick: () => go('explorer', { q: `src:${x.srcIp} dst:${x.dstIp} dport:${x.dport}`, range: '1h' }) },
      h('div', { class: 'ovmain' }, h('span', { class: 'ovtitle mono' }, `${x.srcIp} → ${x.dstIp}`), h('span', { class: 'muted', style: 'font-size:12px' }, [x.app || x.protoName, `port ${x.dport}`, plural(x.hopCount, 'hop'), x.ttlExpired ? 'TTL expired' : '', x.qosChanged ? 're-marked' : ''].filter(Boolean).join(' · '))),
      h('b', { class: 'mono', style: 'flex:none' }, bytes(x.bytes)))))));
  return box('Biggest flows', `last ${f.windowMinutes} min, by bytes`, body, btn('Open Flow explorer', { small: true, onclick: () => go('explorer') }));
}

function exportersBox(d: Reply): VNode {
  const e = d.flows.exporters, s = d.flows.stats;
  const open = (x: Exp): void => (x.devId !== null ? go('ports', { dev: x.devId }) : go('ports', { exporter: x.ip }));
  const row = (x: Exp, extra: string): VNode => h('li', { key: x.ip }, h('button', { type: 'button', class: 'ovitem ovbtn', title: 'See the flows this exporter reports', onclick: () => open(x) },
    h('div', { class: 'ovmain' }, h('span', { class: 'ovtitle' }, x.name || x.ip), h('span', { class: 'muted mono', style: 'font-size:12px' }, x.ip + (x.version ? ' · ' + x.version : ''))),
    h('span', { class: 'muted', style: 'flex:none;font-size:12.5px;text-align:right' }, extra)));
  const body: Child[] = [
    h('div', { class: 'row', style: 'gap:8px' }, chip(`${e.active} of ${e.total} sending`, e.total && e.active === e.total ? 'ok' : e.active ? 'warn' : e.total ? 'bad' : 'default'),
      s.errors ? chip(`${num(s.errors)} decode errors`, 'warn') : null, s.dropped ? chip(`${num(s.dropped)} records dropped`, 'warn') : null)
  ];
  if (!e.total) body.push(none('No exporter has sent flows yet. Point NetFlow or IPFIX at this server.'));
  if (e.silent.length) body.push(h('div', { class: 'col', style: 'gap:6px' }, h('b', { style: 'font-size:12.5px' }, 'Gone quiet'), h('ul', { class: 'ovlist' }, e.silent.map(x => row(x, 'silent ' + dur(x.silentMs))))));
  if (e.top.length) body.push(h('div', { class: 'col', style: 'gap:6px' }, h('b', { style: 'font-size:12.5px' }, 'Busiest exporters'), h('ul', { class: 'ovlist' }, e.top.map(x => row(x, `${num(x.records)} records`)))));
  return box('Flow exporters', null, body, btn('Open Flows by port', { small: true, onclick: () => go('ports') }));
}

function portsBox(d: Reply): VNode {
  const p = d.ports;
  const body: Child[] = p.busiest.length ? [h('ul', { class: 'ovlist' }, p.busiest.map(x => h('li', { key: `${x.devId}/${x.ifIndex}` },
    h('button', { type: 'button', class: 'ovitem ovbtn', title: 'See the flows through this port', onclick: () => go('ports', { dev: x.devId, if: x.ifIndex }) },
      h('div', { class: 'ovmain', style: 'flex:1' },
        h('span', { class: 'ovtitle' }, `${x.dev} · ${x.name}`, x.alias ? h('span', { class: 'muted', style: 'font-weight:400' }, ` (${x.alias})`) : null),
        h('span', { class: 'row', style: 'gap:8px;flex-wrap:nowrap' }, bar(x.util, 100), h('span', { class: 'mono', style: 'font-size:12px;flex:none' }, `${pct(x.util, 0)}`)),
        h('span', { class: 'muted mono', style: 'font-size:12px' }, `in ${bps(x.inBps)} · out ${bps(x.outBps)}`)),
      x.over ? chip('Over limit', 'warn') : null))))] : [none(d.collect.snmp ? 'No interface traffic has been read yet.' : 'SNMP polling is off, so link rates are not being recorded.')];
  return box('Busiest ports', `last ${p.windowMinutes} min, by utilisation`, body, btn('Open Flows by port', { small: true, onclick: () => go('ports') }));
}

function devicesBox(d: Reply): VNode {
  const v = d.devices;
  const body: Child[] = [
    h('div', { class: 'row', style: 'gap:8px' }, chip(`${v.ok} responding`, v.ok === v.total ? 'ok' : 'default'), v.down.length ? chip(`${v.down.length} down`, 'bad') : null, v.paused ? chip(`${v.paused} paused`, 'default') : null, v.pending ? chip(`${v.pending} waiting for first poll`, 'info') : null)
  ];
  if (v.busyCpu.length) body.push(h('div', { class: 'col', style: 'gap:6px' }, h('b', { style: 'font-size:12.5px' }, 'Highest CPU'), h('ul', { class: 'ovlist' }, v.busyCpu.map(x => h('li', { key: x.id },
    h('button', { type: 'button', class: 'ovitem ovbtn', title: 'Open the hardware tab of this device', onclick: () => go('links', { dev: x.id, tab: 'hardware' }) },
      h('div', { class: 'ovmain', style: 'flex:1' }, h('span', { class: 'ovtitle' }, x.name), h('span', { class: 'row', style: 'gap:8px;flex-wrap:nowrap' }, bar(x.cpuPct ?? 0, 100), h('span', { class: 'mono', style: 'font-size:12px;flex:none' }, `CPU ${pct(x.cpuPct, 0)}${x.memPct !== null ? ' · memory ' + pct(x.memPct, 0) : ''}`)))))))));
  return box('Network devices', plural(v.total, 'device'), body, h('span', { class: 'row', style: 'gap:8px' }, btn('Open Network health', { small: true, onclick: () => go('links') }), session.me?.caps.devices ? btn('Open SNMP devices', { small: true, kind: 'ghost', onclick: () => go('devices') }) : null));
}

function logsBox(d: Reply): VNode | null {
  const l = d.logs;
  if (!l) return null;
  const body: Child[] = [h('div', { class: 'row', style: 'gap:8px' }, l.errors ? chip(`${num(l.errors)} error${l.errors === 1 ? '' : 's'}`, 'bad') : chip('No errors', 'ok'), l.warnings ? chip(`${num(l.warnings)} warning${l.warnings === 1 ? '' : 's'}`, 'warn') : null)];
  if (!l.items.length) body.push(none(`Nothing was logged at warning level or above in the last ${l.windowHours} hours.`));
  else body.push(h('ul', { class: 'ovlist' }, l.items.map(x => h('li', { key: x.id, class: 'ovitem ' + (x.level === 'ERROR' ? 'bad' : '') },
    h('div', { class: 'row', style: 'flex-wrap:nowrap;align-items:flex-start;gap:8px;min-width:0' }, chip(x.level === 'ERROR' ? 'Error' : 'Warning', x.level === 'ERROR' ? 'bad' : 'warn'),
      h('div', { class: 'ovmain' }, h('span', { class: 'ovlogmsg', title: x.message }, x.message), h('span', { class: 'muted', style: 'font-size:12px' }, `${x.source} · ${ago(x.ts)}`)))))));
  return box('Application logs', `errors first, last ${l.windowHours} h`, body, btn('Open logs', { small: true, onclick: () => go('admin', { tab: 'logs' }) }));
}

/* ------------------------------------------------------------------ page */

export function render(): VNode {
  const head = heading('Overview', 'How the network is doing', 'The top items from each page, what needs attention, and whether any SNMP device has stopped answering. Select an item to review it in its own page.');
  if (loadError && !data) return h('main', null, head, note(loadError, 'bad', true));
  if (!data) return h('main', null, head, spinner());
  const d = data;
  return h('main', null, head,
    loadError ? note('Could not refresh: ' + loadError + '. Showing the last data received.', 'warn', true) : null,
    downPanel(d), noticesPanel(d),
    h('div', { class: 'ovgrid' }, flowsBox(d), exportersBox(d), portsBox(d), devicesBox(d), logsBox(d)),
    h('p', { class: 'dim', style: 'font-size:12px;margin:0 0 24px' }, `Updated ${stamp(d.generatedAt)}. This page refreshes every 30 seconds.`));
}
