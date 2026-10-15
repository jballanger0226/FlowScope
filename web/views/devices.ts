import { h, type VNode } from '../vdom.js';
import { get, post, del, qs } from '../api.js';
import { session, redraw, go } from '../state.js';
import { btn, chip, empty, field, heading, msg, note, seg, select, spinner, status as statusEl, textInput, toggle, kv } from '../components.js';
import { ago, debounce, dur, num, stamp } from '../util.js';

interface Dev {
  id: number; name: string; ip: string; port: number; credId: number; credName: string; intervalSec: number; polling: boolean; source: string; addedAt: number;
  sysName: string; sysDescr: string; role: string; profile: string; lastPoll: number | null; lastOk: number | null; lastError: string | null;
  status: 'ok' | 'error' | 'paused' | 'pending'; interfaces: number; policies: number; classes: number; addresses: string[];
}
interface Cred { id: number; name: string; version: string; isDefault: boolean }
interface Found { ip: string; status: 'found' | 'already' | 'noresponse' | 'authfail' | 'error'; via?: string; sysName?: string; sysDescr?: string; role?: string; interfaces?: number; policies?: number; error?: string }
interface Job { id: string; spec: string; credName: string; total: number; done: number; cancelled: boolean; finishedAt: number | null; results: Found[]; tryOthers: boolean }

type Mode = 'one' | 'manage' | 'scan';
let mode: Mode = 'manage';
let devs: Dev[] = []; let creds: Cred[] = []; let canCreds = false; let loaded = false; let loadError = '';
// add one
let nName = '', nIp = '', nCred = '', nSec = '60'; let addBusy = false; let addMsg = ''; let addOk = false;
// manage
let mQ = ''; let sel = 0; let confirmRemove = false; let mMsg = ''; let mBusy = false;
// diagnostics
interface Check { id: string; title: string; state: 'ok' | 'warn' | 'fail' | 'na'; count: number; detail: string; hint?: string }
let diagFor = 0; let chk: { checkedAt: number; checks: Check[] } | null = null; let chkBusy = false; let chkErr = '';
interface WalkRow { oid: string; type: string; text: string }
interface WalkJob { id: string; device: string; startOid: string; state: 'running' | 'done' | 'cancelled' | 'error'; error: string | null; truncated: boolean; rows: number; startedAt: number; finishedAt: number | null; maxRows: number }
const PAGE = 100;
let wOid = ''; let wJob: WalkJob | null = null; let wRows: WalkRow[] = []; let wMatched = 0; let wOff = 0; let wQ = ''; let wBusy = false; let wErr = ''; let wOpen = false; let wTimer: number | undefined;
// scan
let dRange = '', dCred = '', dSec = '60', dTryOthers = false; let job: Job | null = null; let dMsg = ''; let picked = new Set<string>(); let scanTimer: number | undefined; let addFoundBusy = false;

export function enter(p: URLSearchParams): void {
  const id = Number(p.get('id'));
  if (id) { sel = id; mode = 'manage'; }
  void load();
}

async function load(): Promise<void> {
  try {
    const [d, c] = await Promise.all([get<{ devices: Dev[] }>('/api/devices'), get<{ credentials: Cred[]; canEdit: boolean }>('/api/snmp/credentials')]);
    devs = d.devices; creds = c.credentials; canCreds = c.canEdit; loadError = '';
    const def = creds.find(x => x.isDefault) ?? creds[0];
    if (!nCred || !creds.some(x => String(x.id) === nCred)) nCred = def ? String(def.id) : '';
    if (!dCred || (dCred !== 'default' && !creds.some(x => String(x.id) === dCred))) dCred = def ? String(def.id) : '';
    if (sel && !devs.some(x => x.id === sel)) sel = 0;
    loaded = true;
  } catch (e) { loadError = (e as Error).message; }
  redraw();
}

const credOpts = (): [string, string][] => creds.map(c => [String(c.id), `${c.name} (SNMP${c.version}${c.isDefault ? ', default' : ''})`]);
const intervals: [string, string][] = [['30', 'Every 30 s'], ['60', 'Every 60 s'], ['300', 'Every 5 min']];
const statusKind = (d: Dev): 'ok' | 'warn' | 'bad' | 'off' => d.status === 'ok' ? 'ok' : d.status === 'paused' ? 'off' : d.status === 'pending' ? 'warn' : 'bad';
const statusText = (d: Dev) => d.status === 'ok' ? 'Polling' : d.status === 'paused' ? 'Paused' : d.status === 'pending' ? 'Waiting for first poll' : 'Not answering';

/* ------------------------------------------------------------------ add one */

async function addOne(): Promise<void> {
  addBusy = true; addMsg = 'Contacting the device…'; addOk = false; redraw();
  try {
    const r = await post<{ device: Dev }>('/api/devices', { ip: nIp.trim(), name: nName.trim() || undefined, credId: Number(nCred) || undefined, intervalSec: Number(nSec) });
    addMsg = `Added ${r.device.name}: ${r.device.interfaces} interfaces and ${r.device.policies} queue polic${r.device.policies === 1 ? 'y' : 'ies'} found.`; addOk = true;
    nName = ''; nIp = '';
    await load(); sel = r.device.id;
  } catch (e) { addMsg = (e as Error).message; }
  addBusy = false; redraw();
}

function modeOne(): VNode {
  return h('div', { class: 'panel col', style: 'gap:14px' },
    h('h3', null, 'Add one device'),
    h('div', { class: 'three' },
      field('Host name', textInput(nName, v => { nName = v; }, { placeholder: 'acc-sw-3f-02', aria: 'Host name' }), 'Optional. The name the device reports is used when empty.'),
      field('Management IP', textInput(nIp, v => { nIp = v; }, { placeholder: '10.255.0.40', aria: 'Management IP', mono: true, onenter: () => void addOne() })),
      field('Credential set', select(nCred, credOpts(), v => { nCred = v; }, { aria: 'Credential set' })),
      field('Polling interval', select(nSec, intervals, v => { nSec = v; }, { aria: 'Polling interval' }))),
    h('div', { class: 'row' }, btn(addBusy ? 'Adding…' : 'Add and poll', { kind: 'primary', disabled: addBusy || !nIp.trim() || !nCred, onclick: () => void addOne() }), msg(addMsg, addOk ? 'ok' : addMsg && !addBusy ? 'bad' : '')),
    !creds.length ? note('No credential sets exist yet. A full administrator creates them under Admin, SNMP credentials.', 'warn') : null,
    h('p', { class: 'muted' }, 'The default credential set is preselected. If the set you need is missing, a full admin can create it under Admin, SNMP credentials. Secrets never appear on this page.'));
}

/* ------------------------------------------------------------------ manage */

async function setPolling(d: Dev, on: boolean): Promise<void> {
  mBusy = true; mMsg = ''; redraw();
  try { await post(`/api/devices/${d.id}/polling`, { on }); mMsg = on ? `Polling ${d.name} again.` : `Stopped polling ${d.name}. Its history is kept.`; await load(); } catch (e) { mMsg = (e as Error).message; }
  mBusy = false; redraw();
}
async function rediscover(d: Dev): Promise<void> {
  mBusy = true; mMsg = 'Reading interfaces and queue policies…'; redraw();
  try { await post(`/api/devices/${d.id}/rediscover`); mMsg = 'Interfaces and queue policies were read again.'; await load(); } catch (e) { mMsg = (e as Error).message; }
  mBusy = false; redraw();
}
async function remove(d: Dev): Promise<void> {
  mBusy = true; mMsg = ''; redraw();
  try { await del(`/api/devices/${d.id}`); mMsg = `Removed ${d.name}.`; sel = 0; confirmRemove = false; await load(); } catch (e) { mMsg = (e as Error).message; }
  mBusy = false; redraw();
}

function modeManage(): VNode {
  const t = mQ.trim().toLowerCase();
  const rows = devs.filter(d => !t || [d.name, d.ip, d.role, d.credName, d.sysName].some(s => s.toLowerCase().includes(t)));
  const d = devs.find(x => x.id === sel);
  return h('div', { class: 'split' },
    h('div', { class: 'side', style: 'flex-basis:380px' }, h('div', { class: 'panel col', style: 'gap:10px' },
      h('h3', null, 'Added devices'),
      h('input', { class: 'input', type: 'search', value: mQ, 'aria-label': 'Search added devices', placeholder: 'Search name, IP, role or credential set', oninput: (e: Event) => { mQ = (e.target as HTMLInputElement).value; redraw(); } }),
      h('span', { class: 'muted', 'aria-live': 'polite' }, `${num(rows.length)} of ${num(devs.length)} device${devs.length === 1 ? '' : 's'}`),
      !rows.length ? h('span', { class: 'dim' }, devs.length ? 'No device matches.' : 'No devices have been added yet.') : null,
      h('div', { class: 'cards scroll', style: 'max-height:520px' }, rows.map(x => h('button', { key: x.id, type: 'button', class: 'cardbtn', 'aria-pressed': x.id === sel, onclick: () => { sel = x.id; confirmRemove = false; mMsg = ''; redraw(); } },
        h('span', { class: 't' }, x.name), h('span', { class: 's' }, `${x.role} · ${x.ip}`), h('span', { class: 's' }, statusEl(statusKind(x), statusText(x)))))))),
    h('div', { class: 'mainp' }, h('div', { class: 'panel col', style: 'gap:14px' },
      !d ? h('span', { class: 'muted' }, 'Select a device to see its details, turn its polling on or off, or remove it.') : [
        h('div', { class: 'row', style: 'justify-content:space-between' }, h('h3', { style: 'font-size:17px' }, d.name), statusEl(statusKind(d), statusText(d))),
        kv([['Address', `${d.ip}:${d.port}`], ['Role', d.role], ['Model', d.sysDescr ? d.sysDescr.slice(0, 80) : '—'], ['Credential set', d.credName], ['Polling interval', `${d.intervalSec} s`],
          ['Interfaces', num(d.interfaces)], ['Queue policies', `${num(d.policies)} (${num(d.classes)} classes)`], ['Last answered', d.lastOk ? `${ago(d.lastOk)} (${stamp(d.lastOk)})` : 'never'],
          ['Added', `${stamp(d.addedAt)} · ${d.source}`], ['Addresses', d.addresses.join(', ') || d.ip]]),
        d.lastError && d.status !== 'ok' ? note(`The last poll failed: ${d.lastError}`, 'warn') : null,
        h('div', { class: 'row' },
          btn(d.polling ? 'Pause polling' : 'Resume polling', { disabled: mBusy, onclick: () => void setPolling(d, !d.polling) }),
          btn('Open in Links and QoS', { onclick: () => go('links', { dev: d.name }) }),
          btn('Read interfaces again', { kind: 'ghost', disabled: mBusy, onclick: () => void rediscover(d) }),
          !confirmRemove ? btn('Remove device', { kind: 'danger', onclick: () => { confirmRemove = true; redraw(); } }) : null),
        confirmRemove ? h('div', { class: 'note bad col', style: 'gap:10px' },
          h('span', null, `Remove ${d.name}? FlowScope stops polling it and deletes its stored interface and queue history. Flow records that passed through it are kept.`),
          h('div', { class: 'row' }, btn(`Remove ${d.name}`, { kind: 'danger', disabled: mBusy, onclick: () => void remove(d) }), btn('Cancel', { kind: 'ghost', onclick: () => { confirmRemove = false; redraw(); } }))) : null,
        msg(mMsg),
        diagnostics(d)])));
}

/* ------------------------------------------------------------------ diagnostics */

const WALK_PRESETS: [string, string][] = [['*', 'Everything (full walk)'], ['1.0.8802.1.1.2.1.4', 'LLDP neighbours (LLDP-MIB lldpRemTable)'], ['1.0.8802.1.1.2.1.3', 'LLDP local system and ports'], ['1.3.6.1.4.1.9.9.23.1.2.1', 'CDP neighbours (Cisco)'],
  ['1.3.6.1.2.1.1', 'System (name, description, uptime)'], ['1.3.6.1.2.1.31.1.1.1.1', 'Interface names (ifName)'], ['1.3.6.1.2.1.4.35.1.4', 'ARP / neighbour cache (MAC addresses)']];
const CHK_LABEL: Record<Check['state'], [string, 'ok' | 'warn' | 'bad' | 'default']> = { ok: ['Published', 'ok'], warn: ['Check', 'warn'], fail: ['Missing', 'bad'], na: ['Not applicable', 'default'] };

function syncDiag(d: Dev): void {
  if (diagFor === d.id) return;
  diagFor = d.id; chk = null; chkErr = ''; wJob = null; wRows = []; wMatched = 0; wOff = 0; wQ = ''; wErr = ''; window.clearTimeout(wTimer);
}
async function runCheck(d: Dev): Promise<void> {
  chkBusy = true; chkErr = ''; redraw();
  try { const r = await post<{ checkedAt: number; checks: Check[] }>(`/api/devices/${d.id}/check`, {}); if (diagFor === d.id) chk = r; }
  catch (e) { if (diagFor === d.id) { chk = null; chkErr = (e as Error).message; } }
  chkBusy = false; redraw();
}
/** Reads the walk's status and the current page. The page is cheap: the server filters and slices, the browser only ever holds PAGE rows. */
async function pollWalk(d: Dev): Promise<void> {
  if (!wJob || diagFor !== d.id) return;
  try {
    const r = await get<{ job: WalkJob; matched: number; rows: WalkRow[] }>(`/api/devices/${d.id}/walks/${wJob.id}` + qs({ offset: wOff, limit: PAGE, q: wQ.trim() }));
    if (diagFor !== d.id || !wJob || wJob.id !== r.job.id) return;
    wJob = r.job; wRows = r.rows; wMatched = r.matched; wErr = '';
  } catch (e) { wErr = (e as Error).message; if (wJob?.state === 'running') wJob = { ...wJob, state: 'error' }; }
  redraw();
  window.clearTimeout(wTimer);
  if (wJob?.state === 'running' && diagFor === d.id && location.hash.startsWith('#/devices')) wTimer = window.setTimeout(() => void pollWalk(d), 900);
}
async function startWalk(d: Dev): Promise<void> {
  wBusy = true; wErr = ''; wJob = null; wRows = []; wMatched = 0; wOff = 0; redraw();
  try { const r = await post<{ job: WalkJob }>(`/api/devices/${d.id}/walks`, { oid: wOid.trim() }); wJob = r.job; wBusy = false; await pollWalk(d); }
  catch (e) { wErr = (e as Error).message; wBusy = false; redraw(); }
}
async function cancelWalk(d: Dev): Promise<void> { if (!wJob) return; try { await post(`/api/devices/${d.id}/walks/${wJob.id}/cancel`, {}); } catch { /* the poll shows the state */ } await pollWalk(d); }
const filterWalk = debounce((d: Dev) => { wOff = 0; void pollWalk(d); }, 350);
function pageWalk(d: Dev, off: number): void { wOff = Math.max(0, off); void pollWalk(d); }
const walkExport = (d: Dev, fmt: string): string => wJob ? `/api/devices/${d.id}/walks/${wJob.id}/export` + qs({ format: fmt, q: wQ.trim() }) : '';

function walkPanel(d: Dev): VNode {
  const running = wJob?.state === 'running';
  const from = wJob ? (wJob.startOid ? '.' + wJob.startOid : 'the whole tree') : '';
  const cols = 'minmax(240px,2fr) 110px minmax(200px,3fr)';
  const first = wMatched ? wOff + 1 : 0, last = Math.min(wOff + PAGE, wMatched);
  const stateText = !wJob ? '' : running ? `Walking ${from}… ${num(wJob.rows)} rows so far (${dur(Date.now() - wJob.startedAt)})`
    : wJob.state === 'cancelled' ? `Cancelled. ${num(wJob.rows)} rows were read from ${from}.`
    : wJob.state === 'error' ? `Stopped by an error. ${num(wJob.rows)} rows were read from ${from}.`
    : `Finished: ${num(wJob.rows)} row${wJob.rows === 1 ? '' : 's'} under ${from}.`;
  return h('div', { class: 'col', style: 'gap:10px' },
    h('div', { class: 'row', style: 'align-items:end' },
      field('Starting OID (blank walks everything)', textInput(wOid, v => { wOid = v; }, { placeholder: 'blank = everything', aria: 'OID to walk', mono: true, width: '300px', onenter: () => { if (!running && !wBusy) void startWalk(d); } })),
      field('Common starting points', select('', [['', 'Pick one…'], ...WALK_PRESETS], v => { if (v) { wOid = v === '*' ? '' : v; redraw(); } }, { aria: 'Common OIDs' })),
      running ? btn('Cancel walk', { kind: 'danger', onclick: () => void cancelWalk(d) }) : btn(wBusy ? 'Starting…' : wOid.trim() ? 'Walk' : 'Walk everything', { kind: 'primary', disabled: wBusy, onclick: () => void startWalk(d) })),
    !wOid.trim() && !wJob ? h('span', { class: 'dim', style: 'font-size:12px' }, 'A full walk reads every value the device will give this credential. A large switch can take a few minutes and return tens of thousands of rows; it runs in the background and you can filter and export it when it finishes.') : null,
    wErr ? note(wErr, 'bad', true) : null,
    wJob ? h('div', { class: 'col', style: 'gap:8px' },
      h('span', { class: running ? 'muted' : wJob.state === 'done' ? 'muted' : 'warn-text', style: 'font-size:12.5px', role: 'status', 'aria-live': 'polite' }, stateText),
      wJob.error ? note(wJob.error, 'warn') : null,
      wJob.truncated && !wJob.error ? note(`Only the first ${num(wJob.maxRows)} rows are kept. Walk a narrower OID to see the rest.`, 'warn') : null,
      wJob.rows && !running && wMatched ? h('div', { class: 'row', style: 'gap:8px;align-items:center;padding:8px 12px;border:1px solid var(--line2);border-radius:8px' },
        h('b', { style: 'font-size:13px' }, 'Download'),
        h('span', { class: 'muted', style: 'font-size:12.5px' }, `${wQ.trim() ? num(wMatched) + ' matching rows' : 'all ' + num(wMatched) + ' rows'} as`),
        ...[['txt', 'Text (.txt)'], ['json', 'JSON'], ['csv', 'CSV'], ['xml', 'XML']].map(([f, label]) => h('a', { key: f, class: 'btn small', href: walkExport(d, f), download: '' }, label)),
        wQ.trim() ? h('span', { class: 'dim', style: 'font-size:12px' }, 'Clear the filter to download everything.') : null) : null,
      wJob.rows ? h('div', { class: 'row', style: 'gap:10px;align-items:center' },
        h('div', { style: 'flex:1 1 260px;max-width:420px' }, textInput(wQ, v => { wQ = v; filterWalk(d); }, { placeholder: 'Filter rows: every word must match the OID, type or value', aria: 'Filter walk rows', width: '100%' })),
        wQ.trim() ? btn('Clear', { kind: 'ghost', small: true, onclick: () => { wQ = ''; wOff = 0; void pollWalk(d); } }) : null,
        h('span', { class: 'muted', style: 'font-size:12.5px' }, wMatched ? `Rows ${num(first)}–${num(last)} of ${num(wMatched)}${wQ.trim() ? ' matching' : ''}` : wQ.trim() ? 'No row matches.' : ''),
        btn('‹ Previous', { small: true, kind: 'ghost', disabled: wOff <= 0, onclick: () => pageWalk(d, wOff - PAGE) }),
        btn('Next ›', { small: true, kind: 'ghost', disabled: wOff + PAGE >= wMatched, onclick: () => pageWalk(d, wOff + PAGE) })) : null,
      wRows.length ? h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${cols};--w:700px` },
        h('div', { class: 'tr head' }, ...['OID', 'Type', 'Value'].map(t => h('span', null, t))),
        h('div', { class: 'scroll', style: 'max-height:420px' }, wRows.map((r, i) => h('div', { key: wOff + i, class: 'tr' }, h('span', { class: 'mono', style: 'font-size:12px;word-break:break-all' }, r.oid), h('span', { class: 'dim', style: 'font-size:12px' }, r.type), h('span', { class: 'mono', style: 'font-size:12px;word-break:break-all' }, r.text)))))) : !running && !wJob.rows ? h('span', { class: 'dim', style: 'font-size:12.5px' }, `Nothing under ${from}. The device does not publish it, or this credential may not read it.`) : null,
    ) : null);
}

function diagnostics(d: Dev): VNode {
  syncDiag(d);
  const cols = 'minmax(220px,2fr) 110px minmax(200px,3fr)';
  return h('div', { class: 'col', style: 'gap:12px;border-top:1px solid var(--line);padding-top:14px' },
    h('div', { class: 'col', style: 'gap:2px' }, h('h3', { style: 'font-size:15px' }, 'SNMP diagnostics'),
      h('span', { class: 'muted', style: 'font-size:12.5px' }, 'Ask this device what it publishes, or read any part of its MIB. Both use the credential set above and only read.')),
    h('div', { class: 'row' },
      btn(chkBusy ? 'Checking…' : 'Check what this device publishes', { disabled: chkBusy, onclick: () => void runCheck(d) }),
      btn(wOpen ? 'Hide OID walk' : 'Walk an OID', { kind: 'ghost', pressed: wOpen, onclick: () => { wOpen = !wOpen; redraw(); } })),
    chkErr ? note(chkErr, 'bad', true) : null,
    chkBusy && !chk ? spinner('Reading the device…') : null,
    chk ? h('div', { class: 'col', style: 'gap:8px' },
      h('span', { class: 'dim', style: 'font-size:12px' }, `Checked ${ago(chk.checkedAt)}. "Not applicable" means this kind of device normally does not publish it.`),
      h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${cols};--w:700px` },
        h('div', { class: 'tr head' }, ...['What', 'Result', 'Detail'].map(t => h('span', null, t))),
        h('div', null, chk.checks.map(k => h('div', { key: k.id, class: 'tr tall', style: 'align-items:start' },
          h('span', { style: 'font-weight:600' }, k.title), h('span', null, chip(CHK_LABEL[k.state][0], CHK_LABEL[k.state][1])),
          h('span', { class: 'col', style: 'gap:4px' }, h('span', null, k.detail), k.hint ? h('span', { class: 'dim', style: 'font-size:12px' }, k.hint) : null))))))) : null,
    wOpen ? walkPanel(d) : null);
}

/* ------------------------------------------------------------------ discovery */

async function startScan(): Promise<void> {
  dMsg = 'Starting…'; redraw();
  try {
    const r = await post<{ job: Job }>('/api/discovery', { spec: dRange, credId: dCred === 'default' ? undefined : Number(dCred), tryOthers: dTryOthers });
    job = r.job; picked = new Set(); dMsg = '';
    window.clearInterval(scanTimer);
    scanTimer = window.setInterval(() => void pollScan(), 1200);
  } catch (e) { dMsg = (e as Error).message; }
  redraw();
}
async function pollScan(): Promise<void> {
  if (!job) return;
  try {
    const r = await get<{ job: Job }>('/api/discovery/' + job.id);
    job = r.job;
    if (job.finishedAt || job.cancelled) window.clearInterval(scanTimer);
  } catch (e) { window.clearInterval(scanTimer); dMsg = (e as Error).message; }
  redraw();
}
async function cancelScan(): Promise<void> { if (!job) return; try { await post(`/api/discovery/${job.id}/cancel`); } catch { /* ignore */ } void pollScan(); }

async function addFound(): Promise<void> {
  if (!job || !picked.size) return;
  addFoundBusy = true; dMsg = ''; redraw();
  try {
    const r = await post<{ added: Dev[]; failed: { ip: string; error: string }[] }>(`/api/discovery/${job.id}/add`, { ips: [...picked], intervalSec: Number(dSec) });
    dMsg = `Added ${r.added.length} device${r.added.length === 1 ? '' : 's'}.` + (r.failed.length ? ` Could not add: ${r.failed.map(f => `${f.ip} (${f.error})`).join('; ')}` : '');
    picked = new Set(); await pollScan(); await load();
  } catch (e) { dMsg = (e as Error).message; }
  addFoundBusy = false; redraw();
}

const FSTAT: Record<Found['status'], [string, 'ok' | 'warn' | 'bad' | 'off']> = { found: ['Answered', 'ok'], already: ['Already added', 'off'], noresponse: ['No answer', 'off'], authfail: ['Wrong credentials', 'warn'], error: ['Error', 'bad'] };

function modeScan(): VNode {
  const running = job && !job.finishedAt && !job.cancelled;
  const res = job?.results ?? [];
  const visible = res.filter(r => r.status === 'found' || r.status === 'already' || r.status === 'authfail');
  const foundN = res.filter(r => r.status === 'found').length;
  const cols = 'minmax(120px,1fr) minmax(140px,1.2fr) minmax(200px,2fr) minmax(130px,1fr) 150px 90px';
  return h('div', { class: 'panel col', style: 'gap:14px' },
    h('div', { class: 'col', style: 'gap:4px' }, h('h3', null, 'Discover switches by IP range'), h('span', { class: 'muted' }, 'FlowScope sends an SNMP request to each address with the credential set you pick, and lists the devices that answer. Nothing is polled until you add it.')),
    h('div', { class: 'three' },
      field('Address range', textInput(dRange, v => { dRange = v; }, { placeholder: '10.255.4.1-10.255.4.60 or 10.255.4.0/24', aria: 'Address range', mono: true, onenter: () => void startScan() })),
      field('Credential set', select(dCred, credOpts(), v => { dCred = v; }, { aria: 'Credential set' })),
      field('Poll new devices', select(dSec, intervals, v => { dSec = v; }, { aria: 'Polling interval for new devices' }))),
    h('div', { class: 'row' },
      toggle('If it does not answer, try the other credential sets', dTryOthers, () => { dTryOthers = !dTryOthers; redraw(); }, { onText: 'On', offText: 'Off' }),
      btn(running ? 'Scanning…' : 'Start discovery', { kind: 'primary', disabled: !!running || !dRange.trim() || !dCred, onclick: () => void startScan() }),
      running ? btn('Stop', { kind: 'ghost', onclick: () => void cancelScan() }) : null,
      msg(dMsg, dMsg.startsWith('Added') ? 'ok' : dMsg && !dMsg.startsWith('Starting') ? 'bad' : '')),
    dTryOthers ? note('Every extra credential set is one more guess per silent address. Devices that lock accounts after failed attempts may be affected.', 'warn') : null,
    job ? h('div', { class: 'col', style: 'gap:10px' },
      h('div', { class: 'row', style: 'justify-content:space-between' },
        h('b', { 'aria-live': 'polite' }, running ? `Scanning ${job.spec}: ${num(job.done)} of ${num(job.total)} addresses` : `${num(job.total)} addresses checked: ${foundN} answered${job.cancelled ? ' (stopped early)' : ''}`),
        job.tryOthers ? chip('trying other sets', 'info') : null),
      visible.length ? h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${cols};--w:860px` },
        h('div', { class: 'tr head' }, ...['Address', 'Host name', 'Model', 'Answered with', 'Status', 'Add'].map(t => h('span', null, t))),
        h('div', { class: 'scroll' }, visible.map(r => {
          const [lab, kind] = FSTAT[r.status];
          return h('div', { key: r.ip, class: 'tr' },
            h('span', { class: 'mono' }, r.ip), h('span', null, r.sysName ?? '—'), h('span', { class: 'muted', style: 'font-size:12px' }, r.sysDescr ? r.sysDescr.slice(0, 70) : r.error ?? '—'),
            h('span', { class: 'muted' }, r.via ?? '—'), statusEl(kind, lab),
            r.status === 'found' ? btn(picked.has(r.ip) ? 'Selected' : 'Select', { small: true, pressed: picked.has(r.ip), aria: `Add ${r.sysName ?? r.ip}`, onclick: () => { if (picked.has(r.ip)) picked.delete(r.ip); else picked.add(r.ip); redraw(); } }) : h('span', { class: 'dim' }, '—'));
        })))) : !running ? h('span', { class: 'dim' }, 'No device answered.') : null,
      foundN ? h('div', { class: 'row' },
        btn(`Add ${picked.size || ''} selected`.replace('  ', ' '), { kind: 'primary', disabled: !picked.size || addFoundBusy, onclick: () => void addFound() }),
        btn('Select all that answered', { kind: 'ghost', onclick: () => { picked = new Set(res.filter(r => r.status === 'found').map(r => r.ip)); redraw(); } })) : null,
      h('p', { class: 'muted' }, 'A device with the wrong credentials and a device that is not there look the same: no answer.')) : null);
}

/* ------------------------------------------------------------------ view */

export function render(): VNode {
  const head = heading('SNMP devices', 'Add and manage devices', 'Add one switch or router by hand, scan an address range and pick the devices that answer, or review the devices already added, pause their polling and remove them.');
  if (!loaded && !loadError) return h('main', null, head, spinner());
  return h('main', null, head,
    loadError ? note(loadError, 'bad', true) : null,
    seg('How to add devices', [{ id: 'manage', label: `Added devices (${devs.length})`, on: mode === 'manage' }, { id: 'one', label: 'Add one device', on: mode === 'one' }, { id: 'scan', label: 'Discover by IP range', on: mode === 'scan' }], id => { mode = id as Mode; redraw(); }),
    session.status && !session.status.collect.snmp ? note('SNMP polling is switched off for the whole system, so devices are kept but not polled. A full administrator can switch it on under Admin, Data collection.', 'warn') : null,
    mode === 'one' ? modeOne() : mode === 'scan' ? modeScan() : devs.length ? modeManage() : h('div', { class: 'panel' }, empty('No devices have been added yet. Add one by hand or discover them by IP range.')));
}
