import { h, type Child, type VNode } from '../vdom.js';
import { get } from '../api.js';
import { go, redraw, session } from '../state.js';
import { bar, btn, chip, dot, note, spinner } from '../components.js';
import { ago, bps, bytes, dur, num, pct, stamp } from '../util.js';

/**
 * The home page. Top to bottom: a one-line verdict, a row of tiles for the numbers worth seeing first, the traffic picture,
 * what needs attention (devices that stopped answering, then notices), and the state of the devices and of FlowScope itself.
 * Every item opens the page it came from.
 */

type Tab = 'overview' | 'interfaces' | 'hardware' | 'network' | 'wifi';
type Level = 'ok' | 'warn' | 'bad';
interface Notice { level: 'bad' | 'warn'; title: string; detail: string; devId: number; dev: string; target: { tab: Tab; ifIndex?: number; section?: 'traffic' | 'quality' } }
interface Down { id: number; name: string; ip: string; role: string; since: number; neverReached: boolean; downMs: number; lastError: string | null }
interface Exp { ip: string; name: string; devId: number | null; version: string; records: number; lastSeen: number; lastError: string | null }
interface Flow { id: string; srcIp: string; dstIp: string; sport: number; dport: number; app: string; protoName: string; bytes: number; hopCount: number; qosChanged: boolean; ttlExpired: boolean }
interface Port { devId: number; dev: string; ifIndex: number; name: string; alias: string; speedMbps: number | null; utilIn: number | null; utilOut: number | null; inBps: number | null; outBps: number | null; util: number; over: boolean }
interface LogRow { id: number; ts: number; level: 'WARN' | 'ERROR' | 'INFO' | 'DEBUG'; source: string; user: string; message: string }
interface Reply {
  generatedAt: number;
  collect: { flow: boolean; snmp: boolean };
  verdict: { level: Level; headline: string };
  freshness: { lastFlowAt: number | null; lastPollAt: number | null };
  notices: { total: number; bad: number; warn: number; items: Notice[] };
  devices: { total: number; ok: number; paused: number; pending: number; down: Down[]; busyCpu: { id: number; name: string; role: string; cpuPct: number | null; memPct: number | null }[]; restarted: { id: number; name: string; role: string; uptimeSec: number }[] };
  flows: {
    windowMinutes: number; top: Flow[] | null; error: string | null;
    traffic: { bytes: number; flows: number; apps: { name: string; bytes: number; share: number }[] } | null;
    anomalies: { ttlExpired: number | null; qosChanged: number | null };
    stats: { packets: number; records: number; errors: number; dropped: number };
    exporters: { total: number; active: number; silent: (Exp & { silentMs: number })[]; top: Exp[] };
  };
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

/** What the "Open …" button says for each place a notice can lead. */
const OPEN_LABEL: Record<Tab, string> = { overview: 'Open device', interfaces: 'Open interface', hardware: 'Open hardware', network: 'Open routing', wifi: 'Open Wi-Fi' };

/** Opens a notice where it is explained: the device's page on Network health, at the right tab, interface and section. */
function review(n: Notice): void { go('links', { dev: n.devId, if: n.target.ifIndex, tab: n.target.tab, section: n.target.section }); }

const plural = (n: number, one: string, many = one + 's'): string => `${num(n)} ${n === 1 ? one : many}`;
/** A time with the exact moment as a tooltip, so "4 min ago" can be checked. */
const when = (t: number): VNode => h('span', { title: stamp(t) }, ago(t));

/* ------------------------------------------------------------------ building blocks */

/** A titled box with one plain sentence saying what it shows, so nobody has to guess what a number covers. */
function box(title: string, about: string, body: Child[], footer?: Child): VNode {
  return h('section', { class: 'panel ovbox', 'aria-label': title },
    h('header', { class: 'ovhead' }, h('h3', null, title), h('p', { class: 'ovdesc' }, about)),
    ...body, footer ? h('div', { class: 'ovfoot' }, footer) : null);
}
const none = (text: string): VNode => h('p', { class: 'dim', style: 'margin:0;font-size:13px' }, text);
const section = (title: string, ...kids: Child[]): VNode => h('div', { class: 'col', style: 'gap:12px' }, h('h3', { class: 'ovsec' }, title), ...kids);
const subhead = (t: string): VNode => h('b', { class: 'ovsubhead' }, t);

function tile(label: string, value: Child, sub: Child, kind: Level | 'plain' = 'plain'): VNode {
  return h('div', { class: 'ovtile ' + kind }, h('span', { class: 'ovtlabel' }, label), h('span', { class: 'ovtvalue' }, value), h('span', { class: 'ovtsub' }, sub));
}

/* ------------------------------------------------------------------ top of the page */

function verdictHead(d: Reply): VNode {
  return h('div', { class: 'heading' },
    h('span', { class: 'eyebrow' }, 'Overview'),
    h('h2', { class: 'verdict ' + d.verdict.level, role: 'status' }, dot(d.verdict.level), h('span', null, d.verdict.headline)),
    h('p', { class: 'blurb' }, `Updated ${stamp(d.generatedAt).slice(11)}. Refreshes every 30 seconds. Select any item to open the page it comes from.`));
}

/** The numbers worth seeing in the first second. */
function tiles(d: Reply): VNode {
  const v = d.devices, n = d.notices, e = d.flows.exporters, t = d.flows.traffic, f = d.freshness;
  const stale = (at: number | null, on: boolean): boolean => on && at !== null && Date.now() - at > 5 * 60_000;
  const flowStale = stale(f.lastFlowAt, d.collect.flow), pollStale = stale(f.lastPollAt, d.collect.snmp);
  return h('div', { class: 'ovtiles' },
    tile('SNMP devices', v.total ? `${v.ok} of ${v.total} answering` : 'None added', v.down.length ? `${v.down.length} down` : v.paused ? `${v.paused} paused` : v.total ? 'All answering' : 'Add devices to monitor them', v.down.length ? 'bad' : v.total ? 'ok' : 'plain'),
    tile('Notices', n.total ? plural(n.total, 'notice') : 'None', n.total ? `${n.bad} problem${n.bad === 1 ? '' : 's'}, ${n.warn} warning${n.warn === 1 ? '' : 's'}` : 'Everything is within limits', n.bad ? 'bad' : n.warn ? 'warn' : 'ok'),
    tile('Flow exporters', e.total ? `${e.active} of ${e.total} sending` : 'None yet', e.silent.length ? `${e.silent.length} quiet for over 5 min` : e.total ? 'All sending' : 'Nothing has sent flows', !e.total ? 'plain' : e.active === 0 ? 'bad' : e.silent.length ? 'warn' : 'ok'),
    tile('Traffic, last hour', t ? bytes(t.bytes) : '—', t ? `${num(t.flows)} flows recorded` : 'Could not be counted'),
    tile('Data freshness', f.lastFlowAt ? `Flow ${ago(f.lastFlowAt)}` : 'No flows yet', f.lastPollAt ? `SNMP poll ${ago(f.lastPollAt)}` : 'No SNMP poll yet', flowStale || pollStale ? 'warn' : f.lastFlowAt || f.lastPollAt ? 'ok' : 'plain'));
}

/* ------------------------------------------------------------------ needs attention */

function downList(d: Reply): VNode {
  const caps = session.me?.caps;
  return h('section', { class: 'panel ovdown', 'aria-label': 'SNMP devices that are not responding', role: 'alert' },
    h('header', { class: 'ovhead' }, h('h3', null, d.devices.down.length === 1 ? 'An SNMP device is not responding' : 'SNMP devices are not responding'),
      h('p', { class: 'ovdesc' }, 'These stopped answering their last poll. "Down for" counts from the last poll that worked.')),
    h('ul', { class: 'ovlist' }, d.devices.down.map(x => h('li', { key: x.id, class: 'ovitem bad' },
      h('div', { class: 'ovmain' },
        h('span', { class: 'ovtitle' }, x.name, ' ', h('span', { class: 'mono muted', style: 'font-weight:400;font-size:12px' }, x.ip)),
        h('span', { class: 'muted', style: 'font-size:12.5px' }, x.neverReached ? ['It has not answered once since it was added ', when(x.since), '.'] : ['Last answered ', when(x.since), ' (', stamp(x.since), ').']),
        x.lastError ? h('span', { class: 'dim', style: 'font-size:12px' }, 'Error: ' + x.lastError) : null),
      h('div', { class: 'row', style: 'gap:8px;flex-wrap:nowrap;flex:none' },
        h('span', { class: 'downfor' }, h('small', null, 'Down for'), h('b', null, dur(x.downMs))),
        btn('Open device', { small: true, kind: 'ghost', aria: `Open ${x.name}`, onclick: () => go('links', { dev: x.id, tab: 'overview' }) }),
        caps?.devices ? btn('Manage', { small: true, kind: 'ghost', aria: `Manage ${x.name}`, onclick: () => go('devices', { id: x.id }) }) : null)))));
}

function noticeList(d: Reply): VNode {
  const n = d.notices;
  return h('section', { class: 'panel', 'aria-label': 'Notices' },
    h('header', { class: 'ovhead' },
      h('div', { class: 'row', style: 'gap:8px' }, h('h3', null, d.devices.down.length ? 'Other notices' : 'Notices'), n.bad ? chip(`${n.bad} problem${n.bad === 1 ? '' : 's'}`, 'bad') : null, n.warn ? chip(`${n.warn} warning${n.warn === 1 ? '' : 's'}`, 'warn') : null),
      h('p', { class: 'ovdesc' }, 'Things outside their limits on devices that are answering, worst first. A problem is more serious than a warning, and routers and firewalls come before switches.')),
    h('ul', { class: 'ovlist' }, n.items.map((x, i) => h('li', { key: i, class: 'ovitem ' + (x.level === 'bad' ? 'bad' : '') },
      h('div', { class: 'row', style: 'flex-wrap:nowrap;align-items:flex-start;gap:10px;min-width:0' },
        chip(x.level === 'bad' ? 'Problem' : 'Warning', x.level),
        h('div', { class: 'ovmain' }, h('span', { class: 'ovdev' }, x.dev), h('span', { class: 'ovtitle' }, x.title), x.detail ? h('span', { class: 'muted', style: 'font-size:12px' }, x.detail) : null)),
      h('span', { style: 'flex:none' }, btn(OPEN_LABEL[x.target.tab], { small: true, kind: 'ghost', aria: `${OPEN_LABEL[x.target.tab]}: ${x.title} on ${x.dev}`, onclick: () => review(x) }))))),
    n.total > n.items.length ? h('div', { class: 'ovfoot row', style: 'gap:10px' }, h('span', { class: 'muted', style: 'font-size:12.5px' }, `${plural(n.total - n.items.length, 'more notice')} not shown.`), btn('See all on Network health', { small: true, onclick: () => go('links') })) : null);
}

function attention(d: Reply): VNode {
  const caps = session.me?.caps;
  const parts: VNode[] = [];
  if (d.devices.down.length) parts.push(downList(d));
  if (d.notices.total) parts.push(noticeList(d));
  if (!parts.length) {
    parts.push(h('section', { class: 'panel', 'aria-label': 'Needs attention' }, d.devices.total
      ? h('div', { class: 'row', style: 'gap:10px' }, chip('All clear', 'ok'), h('span', { style: 'font-size:13.5px' }, `All ${plural(d.devices.ok, 'SNMP device')} answered their last poll and nothing is outside its limits.`), d.devices.paused ? h('span', { class: 'muted', style: 'font-size:12.5px' }, `${num(d.devices.paused)} paused.`) : null)
      : h('div', { class: 'row', style: 'gap:10px' }, chip('No SNMP devices', 'default'), h('span', { class: 'muted', style: 'font-size:13px' }, 'Add devices to see their health, link use and queue drops here.'), caps?.devices ? btn('Add SNMP devices', { small: true, onclick: () => go('devices') }) : null)));
  }
  return section('Needs attention', ...parts);
}

/* ------------------------------------------------------------------ traffic */

function appsBox(d: Reply): VNode {
  const t = d.flows.traffic;
  const body: Child[] = !t ? [none('Traffic could not be counted just now.')] : !t.apps.length ? [none(d.collect.flow ? 'No flows were recorded in the last hour.' : 'Flow collection is off, so nothing new is being recorded.')]
    : [h('ul', { class: 'ovlist' }, t.apps.map(a => h('li', { key: a.name, class: 'ovitem' },
      h('div', { class: 'ovmain', style: 'flex:1' }, h('span', { class: 'ovtitle' }, a.name), h('span', { class: 'row', style: 'gap:8px;flex-wrap:nowrap' }, bar(a.share * 100, 100, 'accent'), h('span', { class: 'mono muted', style: 'font-size:12px;flex:none' }, pct(a.share * 100, a.share < 0.1 ? 1 : 0)))),
      h('b', { class: 'mono', style: 'flex:none' }, bytes(a.bytes)))))];
  return box('Top applications', 'Where the last hour\'s traffic went, by service. Each stream is counted once, however many devices reported it.', body, btn('Open Report builder', { small: true, onclick: () => go('reports') }));
}

function flowsBox(d: Reply): VNode {
  const f = d.flows;
  const body: Child[] = [];
  if (f.error) body.push(note('Could not search flows: ' + f.error, 'bad'));
  else if (!f.top || !f.top.length) body.push(none(d.collect.flow ? 'No flows were recorded in the last hour.' : 'Flow collection is off, so nothing new is being recorded.'));
  else body.push(h('ul', { class: 'ovlist' }, f.top.map(x => h('li', { key: x.id },
    h('button', { type: 'button', class: 'ovitem ovbtn', title: 'Search for this stream in Flow explorer', onclick: () => go('explorer', { q: `src:${x.srcIp} dst:${x.dstIp} dport:${x.dport}`, range: '1h' }) },
      h('div', { class: 'ovmain' }, h('span', { class: 'ovtitle mono' }, `${x.srcIp} → ${x.dstIp}`), h('span', { class: 'muted', style: 'font-size:12px' }, [x.app || x.protoName, `port ${x.dport}`, plural(x.hopCount, 'hop'), x.ttlExpired ? 'TTL expired' : '', x.qosChanged ? 'DSCP changed' : ''].filter(Boolean).join(' · '))),
      h('b', { class: 'mono', style: 'flex:none' }, bytes(x.bytes)))))));
  return box('Largest flows', 'The five largest streams of the last hour, by bytes. Select one to look it up in Flow explorer.', body, btn('Open Flow explorer', { small: true, onclick: () => go('explorer') }));
}

function portsBox(d: Reply): VNode {
  const p = d.ports;
  const body: Child[] = p.busiest.length ? [h('ul', { class: 'ovlist' }, p.busiest.map(x => h('li', { key: `${x.devId}/${x.ifIndex}` },
    h('button', { type: 'button', class: 'ovitem ovbtn', title: 'See the flows through this port', onclick: () => go('ports', { dev: x.devId, if: x.ifIndex }) },
      h('div', { class: 'ovmain', style: 'flex:1' },
        h('span', { class: 'ovtitle' }, `${x.dev} · ${x.name}`, x.alias ? h('span', { class: 'muted', style: 'font-weight:400' }, ` (${x.alias})`) : null),
        h('span', { class: 'row', style: 'gap:8px;flex-wrap:nowrap' }, bar(x.util, 100), h('span', { class: 'mono', style: 'font-size:12px;flex:none' }, pct(x.util, 0))),
        h('span', { class: 'muted mono', style: 'font-size:12px' }, `in ${bps(x.inBps)} · out ${bps(x.outBps)}`)),
      x.over ? chip('Over limit', 'warn', 'Above the utilisation or queue-drop limit set for alerts') : null))))] : [none(d.collect.snmp ? 'No link traffic has been read yet.' : 'SNMP polling is off, so link traffic is not being recorded.')];
  return box('Busiest ports', `How full each link is, over the last ${p.windowMinutes} minutes (the higher of in and out). Select one to see the flows through it.`, body, btn('Open Flows by port', { small: true, onclick: () => go('ports') }));
}

function exportersBox(d: Reply): VNode {
  const e = d.flows.exporters, s = d.flows.stats;
  const open = (x: Exp): void => (x.devId !== null ? go('ports', { dev: x.devId }) : go('ports', { exporter: x.ip }));
  const row = (x: Exp, extra: Child): VNode => h('li', { key: x.ip }, h('button', { type: 'button', class: 'ovitem ovbtn', title: 'See the flows this exporter reports', onclick: () => open(x) },
    h('div', { class: 'ovmain' }, h('span', { class: 'ovtitle' }, x.name || x.ip), h('span', { class: 'muted mono', style: 'font-size:12px' }, x.ip + (x.version ? ' · ' + x.version : ''))),
    h('span', { class: 'muted', style: 'flex:none;font-size:12.5px;text-align:right' }, extra)));
  const body: Child[] = [
    h('div', { class: 'row', style: 'gap:8px' }, chip(`${e.active} of ${e.total} sending`, !e.total ? 'default' : e.active === e.total ? 'ok' : e.active ? 'warn' : 'bad'),
      s.errors ? chip(`${num(s.errors)} packets could not be read`, 'warn', 'Flow packets that FlowScope could not decode since it started') : null, s.dropped ? chip(`${num(s.dropped)} records dropped`, 'warn', 'Records discarded because the store could not keep up') : null)
  ];
  if (!e.total) body.push(none('No device has sent flows yet. Point NetFlow or IPFIX export at this server.'));
  if (e.silent.length) body.push(h('div', { class: 'col', style: 'gap:6px' }, subhead('Gone quiet'), h('ul', { class: 'ovlist' }, e.silent.map(x => row(x, ['last heard ', when(x.lastSeen)])))));
  if (e.top.length) body.push(h('div', { class: 'col', style: 'gap:6px' }, subhead('Sending the most'), h('ul', { class: 'ovlist' }, e.top.map(x => row(x, `${num(x.records)} records`)))));
  return box('Flow exporters', 'The routers and switches sending NetFlow or IPFIX to this server. One is "quiet" after 5 minutes without a packet.', body, btn('Open Flows by port', { small: true, onclick: () => go('ports') }));
}

function unusualBox(d: Reply): VNode {
  const a = d.flows.anomalies;
  const line = (n: number | null, label: string, why: string, q: string): VNode => h('li', null, h('button', { type: 'button', class: 'ovitem ovbtn', title: n ? `List these streams in Flow explorer` : undefined, disabled: !n, onclick: () => go('explorer', { q, range: '1h' }) },
    h('div', { class: 'ovmain' }, h('span', { class: 'ovtitle' }, label), h('span', { class: 'muted', style: 'font-size:12px' }, why)),
    n === null ? chip('Not counted', 'default') : n === 0 ? chip('None', 'ok') : h('b', { class: 'ovcount' }, num(n))));
  return box('Unusual flows', 'Streams from the last hour that FlowScope can tell something happened to along the way.', [h('ul', { class: 'ovlist' },
    line(a.ttlExpired, 'TTL ran out', 'The packets were dropped before reaching their destination, which points to a routing loop or a hop limit set too low.', 'ttl:expired'),
    line(a.qosChanged, 'DSCP marking changed', 'A device rewrote the priority marking. This includes changes your own QoS policies make on purpose.', 'qos:changed'))],
  btn('Open Flow explorer', { small: true, onclick: () => go('explorer') }));
}

/* ------------------------------------------------------------------ devices and system */

function devicesBox(d: Reply): VNode {
  const v = d.devices;
  const body: Child[] = [
    h('div', { class: 'row', style: 'gap:8px' }, chip(`${v.ok} answering`, v.total && v.ok === v.total ? 'ok' : 'default'), v.down.length ? chip(`${v.down.length} down`, 'bad') : null, v.paused ? chip(`${v.paused} paused`, 'default', 'Polling was turned off for these') : null, v.pending ? chip(`${v.pending} waiting for first poll`, 'info') : null)
  ];
  if (v.busyCpu.length) body.push(h('div', { class: 'col', style: 'gap:6px' }, subhead('Highest CPU'), h('ul', { class: 'ovlist' }, v.busyCpu.map(x => h('li', { key: x.id },
    h('button', { type: 'button', class: 'ovitem ovbtn', title: 'Open the hardware tab of this device', onclick: () => go('links', { dev: x.id, tab: 'hardware' }) },
      h('div', { class: 'ovmain', style: 'flex:1' }, h('span', { class: 'ovtitle' }, x.name), h('span', { class: 'row', style: 'gap:8px;flex-wrap:nowrap' }, bar(x.cpuPct ?? 0, 100), h('span', { class: 'mono', style: 'font-size:12px;flex:none' }, `CPU ${pct(x.cpuPct, 0)}${x.memPct !== null ? ' · memory ' + pct(x.memPct, 0) : ''}`)))))))));
  if (v.restarted.length) body.push(h('div', { class: 'col', style: 'gap:6px' }, subhead('Restarted in the last hour'), h('ul', { class: 'ovlist' }, v.restarted.map(x => h('li', { key: x.id },
    h('button', { type: 'button', class: 'ovitem ovbtn', title: 'Open the hardware tab, where restarts are marked on the graphs', onclick: () => go('links', { dev: x.id, tab: 'hardware' }) },
      h('span', { class: 'ovtitle' }, x.name), h('span', { class: 'muted', style: 'font-size:12.5px' }, `up for ${dur(x.uptimeSec * 1000)}`)))))));
  return box('Network devices', 'The SNMP devices FlowScope polls, with the busiest processors and any that rebooted recently.', body,
    h('span', { class: 'row', style: 'gap:8px' }, btn('Open Network health', { small: true, onclick: () => go('links') }), session.me?.caps.devices ? btn('Open SNMP devices', { small: true, kind: 'ghost', onclick: () => go('devices') }) : null));
}

function logsBox(d: Reply): VNode | null {
  const l = d.logs;
  if (!l) return null;
  const body: Child[] = [h('div', { class: 'row', style: 'gap:8px' }, l.errors ? chip(`${num(l.errors)} error${l.errors === 1 ? '' : 's'}`, 'bad') : chip('No errors', 'ok'), l.warnings ? chip(`${num(l.warnings)} warning${l.warnings === 1 ? '' : 's'}`, 'warn') : null)];
  if (!l.items.length) body.push(none(`Nothing was logged at warning level or above in the last ${l.windowHours} hours.`));
  else body.push(h('ul', { class: 'ovlist' }, l.items.map(x => h('li', { key: x.id, class: 'ovitem ' + (x.level === 'ERROR' ? 'bad' : '') },
    h('div', { class: 'row', style: 'flex-wrap:nowrap;align-items:flex-start;gap:8px;min-width:0' }, chip(x.level === 'ERROR' ? 'Error' : 'Warning', x.level === 'ERROR' ? 'bad' : 'warn'),
      h('div', { class: 'ovmain' }, h('span', { class: 'ovlogmsg', title: x.message }, x.message), h('span', { class: 'muted', style: 'font-size:12px' }, `${x.source} · `, when(x.ts))))))));
  return box('Application logs', `What FlowScope itself reported in the last ${l.windowHours} hours: errors first, then warnings. Only administrators see this.`, body, btn('Open logs', { small: true, onclick: () => go('admin', { tab: 'logs' }) }));
}

/* ------------------------------------------------------------------ page */

export function render(): VNode {
  if (loadError && !data) return h('main', null, h('div', { class: 'heading' }, h('span', { class: 'eyebrow' }, 'Overview'), h('h2', null, 'Could not load the overview')), note(loadError, 'bad', true));
  if (!data) return h('main', null, h('div', { class: 'heading' }, h('span', { class: 'eyebrow' }, 'Overview'), h('h2', null, 'Loading…')), spinner());
  const d = data;
  return h('main', null,
    verdictHead(d),
    loadError ? note('Could not refresh: ' + loadError + '. Showing the last data received.', 'warn', true) : null,
    tiles(d),
    section('Traffic', h('div', { class: 'ovgrid' }, appsBox(d), flowsBox(d), portsBox(d), exportersBox(d), unusualBox(d))),
    attention(d),
    section('Devices and system', h('div', { class: 'ovgrid' }, devicesBox(d), logsBox(d))),
    h('div', { style: 'height:24px' }));
}
