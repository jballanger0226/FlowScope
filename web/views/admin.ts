import { h, type VNode } from '../vdom.js';
import { get, put, del, qs } from '../api.js';
import { session, redraw } from '../state.js';
import { btn, chip, empty, field, heading, kv, msg, note, numberInput, select, spinner, tabs, textInput } from '../components.js';
import { bytes, clock, debounce, dur, num, stamp } from '../util.js';
import { refreshStatus } from '../status.js';
import * as cert from './admin_cert.js';
import * as aaa from './admin_auth.js';
import * as users from './admin_users.js';

type Tab = 'cert' | 'collect' | 'aaa' | 'roles' | 'snmp' | 'vlans' | 'logs';
const TABS: [Tab, string][] = [['cert', 'HTTPS certificate'], ['collect', 'Data collection'], ['aaa', 'Authentication'], ['roles', 'Roles and users'], ['snmp', 'SNMP credentials'], ['vlans', 'VLAN names'], ['logs', 'Application logs']];
let tab: Tab = 'cert';

export function enter(p: URLSearchParams): void {
  const t = p.get('tab') as Tab | null;
  if (t && TABS.some(x => x[0] === t)) tab = t;
  openTab();
}
function openTab(): void {
  if (tab === 'cert') void cert.load();
  else if (tab === 'collect') void loadCollect();
  else if (tab === 'aaa') void aaa.load();
  else if (tab === 'roles' || tab === 'snmp') void users.load();
  else if (tab === 'vlans') void loadVlans();
  else if (tab === 'logs') void loadLogs();
  redraw();
}

/* ------------------------------------------------------------------ data collection */

interface Sys { version: string; revision: string; builtAt: string | null; node: string; platform: string; os: string; container: boolean; dataDir: string; freeBytes: number | null; ports: { https?: number; http?: number }; flowPorts: number[]; tls: string; store: { backend: string; bytesOnDisk: number }; uptimeSec: number; memoryMb: number; demo: boolean }
let sys: Sys | null = null; let col = { flow: true, snmp: true, flowAt: 0, snmpAt: 0 }; let colErr = ''; let confirming: '' | 'flow' | 'snmp' = ''; let colBusy = false; let colMsg = '';

async function loadCollect(): Promise<void> {
  try {
    const [s, c] = await Promise.all([get<Sys>('/api/admin/system'), get<{ collect: typeof col }>('/api/admin/collection')]);
    sys = s; col = c.collect; colErr = '';
  } catch (e) { colErr = (e as Error).message; }
  redraw();
}
async function setCollect(k: 'flow' | 'snmp', on: boolean): Promise<void> {
  colBusy = true; colMsg = ''; redraw();
  try {
    const r = await put<{ collect: typeof col }>('/api/admin/collection', { [k]: on, confirm: on ? undefined : true });
    col = r.collect; confirming = ''; colMsg = `${k === 'flow' ? 'Flow collection' : 'SNMP polling'} turned ${on ? 'on' : 'off'}.`;
    await refreshStatus();
  } catch (e) { colMsg = (e as Error).message; }
  colBusy = false; redraw();
}

function collectTab(): VNode {
  if (!sys) return colErr ? note(colErr, 'bad', true) : spinner();
  const rows: { k: 'flow' | 'snmp'; name: string; what: string; on: boolean; at: number; warn: string }[] = [
    { k: 'flow', name: 'Flow collection', what: 'Receives NetFlow v5/v9 and IPFIX from your routers and switches.', on: col.flow, at: col.flowAt, warn: 'Exporters keep sending. Their packets will be discarded until you turn this back on, so there will be a gap in the flow data.' },
    { k: 'snmp', name: 'SNMP polling', what: 'Reads interface counters and queue statistics from added devices.', on: col.snmp, at: col.snmpAt, warn: 'Interface and queue statistics will not be recorded while polling is off, and drop graphs will show a gap.' }
  ];
  return h('section', { 'aria-label': 'Data collection', class: 'col', style: 'gap:16px' },
    h('p', { class: 'blurb' }, 'Turn each kind of collection on or off for the whole application. While one is off, stored data stays searchable but nothing new is recorded for it. Flow exporters keep sending, and those packets are discarded, so expect a gap in the data.'),
    h('div', { class: 'col', style: 'gap:12px' }, rows.map(r => h('div', { key: r.k, class: 'panel col', style: 'gap:10px' },
      h('div', { class: 'row', style: 'justify-content:space-between' }, h('h3', null, r.name), r.on ? chip('On', 'ok') : chip('Off', 'bad')),
      h('span', { class: 'muted' }, r.what), h('span', { class: 'dim' }, r.at ? `${r.on ? 'Turned on' : 'Turned off'} ${stamp(r.at)}` : r.on ? 'On since the system was installed' : ''),
      confirming === r.k ? h('div', { class: 'note warn col', style: 'gap:10px' }, h('span', null, r.warn), h('div', { class: 'row' }, btn(`Turn off ${r.name.toLowerCase()}`, { kind: 'danger', disabled: colBusy, onclick: () => void setCollect(r.k, false) }), btn('Keep collecting', { kind: 'ghost', onclick: () => { confirming = ''; redraw(); } })))
        : btn(r.on ? `Turn off ${r.name.toLowerCase()}` : `Turn on ${r.name.toLowerCase()}`, { kind: r.on ? 'warn' : 'primary', disabled: colBusy, onclick: () => { if (r.on) { confirming = r.k; redraw(); } else void setCollect(r.k, true); } })))),
    msg(colMsg, colMsg.includes('turned') ? 'ok' : 'bad'),
    h('div', { class: 'panel col', style: 'gap:8px' }, h('h3', null, 'This installation'),
      kv([['Version', sys.version], ['Revision', sys.revision], ['Built', sys.builtAt ? new Date(sys.builtAt).toLocaleString() : 'unknown'], ['Running for', dur(sys.uptimeSec * 1000)], ['Platform', `${sys.platform} (${sys.os})${sys.container ? ', in a container' : ''}`], ['Node.js', sys.node], ['Memory in use', `${sys.memoryMb} MB`],
        ['Data folder', sys.dataDir], ['Free disk space', sys.freeBytes === null ? 'unknown' : bytes(sys.freeBytes)], ['Store', `${sys.store.backend}, ${bytes(sys.store.bytesOnDisk)} used`],
        ['Web ports', [sys.ports.https ? 'HTTPS ' + sys.ports.https : '', sys.ports.http ? 'HTTP ' + sys.ports.http : ''].filter(Boolean).join(' · ') || '—'], ['Flow ports (UDP)', sys.flowPorts.join(', ') || 'none open']])));
}

/* ------------------------------------------------------------------ VLAN names */

interface Vlan { id: number; name: string; source: string }
let vlans: Vlan[] = []; let vErr = ''; let vId = '', vName = ''; let vMsg = '', vOk = false; let vQ = '';
async function loadVlans(): Promise<void> { try { vlans = (await get<{ vlans: Vlan[] }>('/api/vlans')).vlans; vErr = ''; } catch (e) { vErr = (e as Error).message; } redraw(); }
async function saveVlan(): Promise<void> {
  vMsg = '';
  try { const r = await put<{ vlans: Vlan[] }>('/api/admin/vlans/' + encodeURIComponent(vId.trim()), { name: vName.trim() }); vlans = r.vlans; vOk = true; vMsg = `VLAN ${vId.trim()} is now named ${vName.trim()}.`; vId = vName = ''; await get('/api/meta').then(m => { session.meta = m; }).catch(() => undefined); }
  catch (e) { vOk = false; vMsg = (e as Error).message; }
  redraw();
}
async function dropVlan(v: Vlan): Promise<void> {
  try { vlans = (await del<{ vlans: Vlan[] }>('/api/admin/vlans/' + v.id)).vlans; vOk = true; vMsg = `Removed the name for VLAN ${v.id}.`; } catch (e) { vOk = false; vMsg = (e as Error).message; }
  redraw();
}
function vlanTab(): VNode {
  const t = vQ.trim().toLowerCase();
  const rows = vlans.filter(v => !t || String(v.id).includes(t) || v.name.toLowerCase().includes(t));
  return h('section', { 'aria-label': 'VLAN names', class: 'col', style: 'gap:16px' },
    h('p', { class: 'blurb' }, 'Names are shown next to VLAN numbers, and you can search for flows by name (for example vlan:voice). Names learned from devices over SNMP appear here too; a name you enter yourself takes precedence.'),
    vErr ? note(vErr, 'bad', true) : null,
    h('div', { class: 'panel row end' },
      field('VLAN ID (1 to 4094)', textInput(vId, v => { vId = v; }, { aria: 'VLAN ID', width: '140px', mono: true })), field('Name', textInput(vName, v => { vName = v; }, { aria: 'VLAN name', onenter: () => void saveVlan() })),
      btn('Save name', { kind: 'primary', disabled: !vId.trim() || !vName.trim(), onclick: () => void saveVlan() }), msg(vMsg, vOk ? 'ok' : 'bad')),
    textInput(vQ, v => { vQ = v; redraw(); }, { placeholder: 'Search VLANs', aria: 'Search VLANs' }),
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:100px 1fr 120px 100px;--w:560px' },
      h('div', { class: 'tr head' }, ...['VLAN', 'Name', 'Source', ''].map(x => h('span', null, x))),
      h('div', { class: 'scroll' }, rows.map(v => h('div', { key: v.id, class: 'tr' }, h('span', { class: 'mono' }, String(v.id)), h('span', null, v.name), h('span', { class: 'muted' }, v.source === 'manual' ? 'Entered here' : 'From devices'),
        btn('Remove', { small: true, kind: 'danger', onclick: () => void dropVlan(v) }))), !rows.length ? empty('No VLAN names yet.') : null))));
}

/* ------------------------------------------------------------------ logs */

interface Log { id: number; ts: number; level: string; source: string; user: string; message: string }
let logs: Log[] = []; let sources: string[] = []; let lErr = ''; let lq = '', lLevel = 'all', lSrc = 'all', lRange = '24h'; let logDays = '90'; let lMsg = ''; let lOk = false; let lLoading = false;
async function loadLogs(): Promise<void> {
  lLoading = true; redraw();
  try {
    const r = await get<{ logs: Log[]; sources: string[]; retentionDays: number }>('/api/admin/logs' + qs({ q: lq.trim(), level: lLevel === 'all' ? '' : lLevel, source: lSrc === 'all' ? '' : lSrc, range: lRange, limit: 500 }));
    logs = r.logs; sources = r.sources; if (!lMsg) logDays = String(r.retentionDays); lErr = '';
  } catch (e) { lErr = (e as Error).message; }
  lLoading = false; redraw();
}
const logsSoon = debounce(() => void loadLogs(), 350);
async function saveLogDays(): Promise<void> {
  try { await put('/api/storage/logs', { days: Number(logDays) }); lOk = true; lMsg = `Logs are kept for ${logDays} days.`; } catch (e) { lOk = false; lMsg = (e as Error).message; }
  redraw();
}
function logExport(fmt: 'csv' | 'json'): string {
  return '/api/admin/logs/export' + qs({ format: fmt, q: lq.trim(), level: lLevel === 'all' ? '' : lLevel, source: lSrc === 'all' ? '' : lSrc, range: lRange });
}
const LVL_KIND: Record<string, string> = { ERROR: 'bad', WARN: 'warn', INFO: 'info', DEBUG: 'default' };
function logsTab(): VNode {
  const cols = '150px 70px 100px 120px 1fr';
  return h('section', { 'aria-label': 'Application logs', class: 'col', style: 'gap:12px' },
    h('div', { class: 'row end' },
      h('div', { class: 'grow', style: 'min-width:240px' }, textInput(lq, v => { lq = v; logsSoon(); redraw(); }, { placeholder: 'Search message, user or source', aria: 'Search logs' })),
      select(lLevel, [['all', 'All levels'], ['ERROR', 'Error'], ['WARN', 'Warning'], ['INFO', 'Info']], v => { lLevel = v; void loadLogs(); }, { aria: 'Log level', width: '140px' }),
      select(lSrc, [['all', 'All sources'], ...sources.map(s => [s, s] as [string, string])], v => { lSrc = v; void loadLogs(); }, { aria: 'Log source', width: '150px' }),
      select(lRange, [['1h', 'Last hour'], ['24h', 'Last 24 hours'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days']], v => { lRange = v; void loadLogs(); }, { aria: 'Log time range', width: '160px' }),
      h('label', { class: 'row', style: 'gap:8px' }, h('span', { class: 'muted' }, 'Keep logs for'), numberInput(logDays, v => { logDays = v; lMsg = ''; redraw(); }, { min: 1, max: 3650, aria: 'Log retention in days', width: '84px' }), h('span', { class: 'muted' }, 'days'), btn('Save', { small: true, onclick: () => void saveLogDays() }))),
    msg(lMsg, lOk ? 'ok' : 'bad'),
    h('div', { class: 'row', style: 'justify-content:space-between' }, h('span', { class: 'muted', 'aria-live': 'polite' }, lLoading ? 'Loading…' : `${num(logs.length)} entr${logs.length === 1 ? 'y' : 'ies'}${logs.length >= 500 ? ' (the newest 500; narrow the search or export for more)' : ''}`),
      h('div', { class: 'row', style: 'gap:8px' }, h('a', { class: 'btn small', href: logExport('csv'), download: '' }, 'Export CSV'), h('a', { class: 'btn small', href: logExport('json'), download: '' }, 'Export JSON'))),
    lErr ? note(lErr, 'bad', true) : null,
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${cols};--w:900px` },
      h('div', { class: 'tr head' }, ...['Time', 'Level', 'Source', 'User', 'Message'].map(x => h('span', null, x))),
      h('div', { class: 'scroll', style: 'max-height:520px' }, logs.map(l => h('div', { key: l.id, class: 'tr tall', style: 'align-items:start' },
        h('span', { class: 'mono muted', style: 'font-size:12px' }, `${stamp(l.ts).slice(5, 10)} ${clock(l.ts)}`), h('span', null, chip(l.level, (LVL_KIND[l.level] ?? 'default') as 'bad')), h('span', { class: 'muted' }, l.source), h('span', { class: 'muted' }, l.user || '—'),
        h('span', { style: 'word-break:break-word' }, l.message))), !logs.length && !lLoading ? empty('No log entries match these filters.') : null))),
    h('p', { class: 'muted' }, 'Exports contain the entries matching the current filters. Passwords, shared secrets and private keys are never written to the log.'));
}

/* ------------------------------------------------------------------ frame */

export function render(): VNode {
  return h('main', null,
    heading('Administration', 'Certificate, authentication, roles and logs', 'Only users with the full admin role can open this page.'),
    tabs('Administration sections', TABS.map(([id, label]) => ({ id, label, on: tab === id })), id => { tab = id as Tab; history.replaceState(null, '', '#/admin?tab=' + tab); openTab(); }),
    tab === 'cert' ? cert.render() : tab === 'collect' ? collectTab() : tab === 'aaa' ? aaa.render() : tab === 'roles' ? users.renderUsers() : tab === 'snmp' ? users.renderCreds() : tab === 'vlans' ? vlanTab() : logsTab());
}
