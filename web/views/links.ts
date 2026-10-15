import { h, type VNode } from '../vdom.js';
import { get, qs } from '../api.js';
import { redraw, go } from '../state.js';
import { bar, btn, chip, empty, heading, lineChart, note, PALETTE, select, spinner, status as statusEl, textInput, type Series } from '../components.js';
import { ago, bps, bpsAxis, bytes, clock, dayClock, dur, niceCeil, num, pct, debounce, svcLabel } from '../util.js';
import { post } from '../api.js';
import { neighborLines, openPort, KIND_TEXT, type Neighbor } from '../neighbors.js';

interface Cls { cls: string; label: string; dir: 'in' | 'out'; dscps: number[]; bw: string | null; queue: string | null; dropPct: number | null; dropPkts: number; dropBytes: number; sentBps: number | null; qdepth: number | null }
interface Iface {
  ifIndex: number; name: string; alias: string; speedMbps: number | null; oper: string; policy: string | null; policyIn: string | null;
  portMode: string; vlan: number | null; vlanName: string; voiceVlan: number | null; voiceVlanName: string; vlanList: string; isVlanIf: boolean; hosts: number;
  utilIn: number | null; utilOut: number | null; inBps: number | null; outBps: number | null; disc: number; err: number;
  classes: Cls[]; worstDropPct: number | null; flagged: boolean;
}
interface Dev { id: number; name: string; ip: string; role: string; hasWlan: boolean; status: string; lastOk: number | null; lastError: string | null; profile: string; qosNote: string | null; hostsAt: number | null; hostsNote: string | null; interfaces: Iface[] }
interface Overview { devices: Dev[]; windowMinutes: number; thresholds: { util: number; drop: number }; mibs: { name: string; what: string }[] }
interface SeriesRes {
  util: { step: number; points: { ts: number; utilIn: number; utilOut: number; inBps: number; outBps: number; disc: number; err: number }[] };
  classes: { cls: string; dscps: number[]; bw: string | null; points: { ts: number; dropPct: number; dropBps: number; dropPps: number; sentBps: number; qdepth: number }[] }[];
  step: number; tier: string;
}
interface Wifi { name: string; os: string; ssid: string; ap: string; radio: number | null; band: string; channel: string; snr: number; txRate: number; rxRate: number; txBytes: number; rxBytes: number; uptimeSec: number; readAt: number }
interface PortHost { mac: string; vlan: number; vlanName: string; ips: string[]; firstSeen: number; lastSeen: number; since: number; active: boolean; wifi: Wifi | null }
interface WlanAp { mac: string; name: string; ip: string; serial: string; model: string; cpuPct: number; memFree: number; memTotal: number; uptimeSec: number; role: string }
interface WlanRadio { apMac: string; idx: number; mac: string; channel: string; band: string; txPower: number; noiseFloor: number; util4: number; util64: number; clients: number; mode: string; up: boolean }
interface WlanSsid { apMac: string; bssid: string; name: string; radio: number | null; ssidId: number | null; clients: number; ifName: string | null }
interface WlanClient { mac: string; apMac: string; apName: string; bssid: string; ssid: string; radio: number | null; ip: string; name: string; os: string; snr: number; txRate: number; rxRate: number; txBytes: number; rxBytes: number; uptimeSec: number }
interface WlanRes { readAt: number | null; aps: WlanAp[]; radios: WlanRadio[]; ssids: WlanSsid[]; clients: WlanClient[] }
interface NbPort { ifIndex: number; ifName: string; neighbors: Neighbor[] }
interface NbRes { ports: NbPort[]; readAt: number | null; note: string; tracking: boolean }
interface HostsRes { hosts: PortHost[]; neighbors: Neighbor[]; readAt: number | null; note: string; tracking: boolean }
interface Attach { devId: number; dev: string; ifIndex: number; ifName: string; vlan: number; macCount: number; edge: boolean; neighbor: string | null; neighborKind: string | null; portMode: string; lastSeen: number; active: boolean; mac: string; confidence?: 'high' | 'medium' | 'low' }
interface Located { query: string; ip: string | null; macs: string[]; macSource: string; attach: Attach | null; others: Attach[]; note: string }
type Conf = 'high' | 'medium' | 'low';
interface StreamRow { id: string; srcIp: string; dstIp: string; sport: number; dport: number; app: string; appPort: number | null; protoName: string; bytes: number; qosChanged: boolean }

let data: Overview | null = null; let loadError = ''; let loading = false;
let search = '';
let ifSearch = '';
let hostsRes: HostsRes | null = null; let hostsLoading = false; let hostsError = '';
let findQ = ''; let found: Located | null = null; let findError = ''; let finding = false;
let readingHosts = false; let readMsg = '';
let nbRes: NbRes | null = null; let nbError = ''; let nbLoading = false;
let wlan: WlanRes | null = null; let wlanError = ''; let wlanLoading = false; let clientFilter = '';
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
    else if (devId && cur().dev?.hasWlan) void loadWlan(true);
    if (!pendingName && !devId && data.devices.length) { const first = needsAttention()[0]; if (first) select_(first.dev.id, first.itf.ifIndex); else select_(data.devices[0].id, data.devices[0].interfaces[0]?.ifIndex ?? 0); }
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

let prevDev = 0;
function select_(d: number, i: number): void {
  if (d !== devId) ifSearch = '';
  devId = d; ifIndex = i; series = null; streams = []; streamsTotal = 0; seriesError = ''; hostsRes = null; hostsError = ''; readMsg = '';
  if (d !== prevDev) { nbRes = null; nbError = ''; void loadNeighbors(); wlan = null; wlanError = ''; clientFilter = ''; void loadWlan(); }
  prevDev = d;
  void loadSeries(); void loadStreams(); void loadHosts();
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

let nseq = 0;
async function loadNeighbors(): Promise<void> {
  if (!devId) return;
  const my = ++nseq, d = devId; nbLoading = true; nbError = ''; redraw();
  try {
    const r = await get<NbRes>('/api/links/neighbors' + qs({ dev: d }));
    if (my === nseq) nbRes = r;
  } catch (e) { if (my === nseq) { nbRes = null; nbError = (e as Error).message; } }
  if (my === nseq) { nbLoading = false; redraw(); }
}

let wseq = 0;
/** Wi-Fi state of the selected device, when it is an access point. Read from what FlowScope stored at the last host-table read. */
async function loadWlan(quiet = false): Promise<void> {
  const d = cur().dev; if (!d?.hasWlan) { wlan = null; return; }
  const my = ++wseq; if (!quiet) { wlanLoading = true; wlanError = ''; redraw(); }
  try { const r = await get<WlanRes>('/api/links/wlan' + qs({ dev: d.id })); if (my === wseq) wlan = r; }
  catch (e) { if (my === wseq) { wlan = null; wlanError = (e as Error).message; } }
  if (my === wseq) { wlanLoading = false; redraw(); }
}

let hseq = 0;
async function loadHosts(): Promise<void> {
  if (!devId || !ifIndex) return;
  const my = ++hseq; hostsLoading = true; hostsError = ''; redraw();
  try {
    const r = await get<HostsRes>('/api/links/hosts' + qs({ dev: devId, if: ifIndex }));
    if (my === hseq) hostsRes = r;
  } catch (e) { if (my === hseq) { hostsRes = null; hostsError = (e as Error).message; } }
  if (my === hseq) { hostsLoading = false; redraw(); }
}
async function readHostsNow(): Promise<void> {
  if (!devId) return;
  readingHosts = true; readMsg = ''; redraw();
  try {
    const r = await post<{ macs: number; arp: number; neighbors: number; note: string }>(`/api/devices/${devId}/read-hosts`, {});
    readMsg = `Read ${num(r.macs)} MAC addresses, ${num(r.arp)} ARP entries and ${num(r.neighbors)} neighbours.${r.note ? ' ' + r.note : ''}`;
    await load(true); await loadHosts(); await loadNeighbors(); await loadWlan(true);
  } catch (e) { readMsg = (e as Error).message; }
  readingHosts = false; redraw();
}
async function findHost(): Promise<void> {
  const q = findQ.trim(); if (!q) return;
  finding = true; findError = ''; redraw();
  try { found = await get<Located>('/api/hosts/locate' + qs({ q })); } catch (e) { found = null; findError = (e as Error).message; }
  finding = false; redraw();
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

const roleLabel = (r: string): string => (r === 'ap' ? 'access point' : r);
const classColor = (name: string, all: string[]) => PALETTE[Math.max(0, all.indexOf(name)) % PALETTE.length];
const dscpText = (d: number[]) => (d.length ? d.join(', ') : '—');

/* ------------------------------------------------------------------ sidebar */

function sidebar(): VNode {
  const d = data!;
  const t = search.trim().toLowerCase();
  const devs = d.devices.filter(x => !t || x.name.toLowerCase().includes(t) || x.ip.includes(t) || x.role.toLowerCase().includes(t) || roleLabel(x.role).includes(t) || x.interfaces.some(i => i.name.toLowerCase().includes(t) || i.alias.toLowerCase().includes(t)));
  const attn = needsAttention();
  return h('aside', { class: 'side', 'aria-label': 'Devices' },
    h('div', { class: 'panel col', style: 'gap:10px' },
      h('h3', null, 'Devices'),
      textInput(search, v => { search = v; searchSoon(); }, { placeholder: 'Search device, address or interface', aria: 'Search devices' }),
      h('div', { class: 'cards' },
        devs.map(x => {
          const flagged = x.interfaces.filter(i => i.flagged).length;
          return h('button', { key: x.id, type: 'button', class: 'cardbtn', 'aria-pressed': x.id === devId, onclick: () => { const first = x.interfaces.find(i => i.flagged) ?? x.interfaces[0]; select_(x.id, first?.ifIndex ?? 0); } },
            h('span', { class: 't' }, x.name), h('span', { class: 's' }, `${roleLabel(x.role)} · ${x.ip}`),
            h('span', { class: 's' }, x.status === 'ok' ? statusEl(flagged ? 'warn' : 'ok', flagged ? `${flagged} interface${flagged === 1 ? ' needs' : 's need'} attention` : 'Healthy') : statusEl(x.status === 'paused' ? 'off' : 'bad', x.status === 'paused' ? 'Polling paused' : x.lastError ? 'Not answering' : 'Waiting for first poll')));
        }),
        !devs.length ? h('span', { class: 'dim' }, d.devices.length ? 'No device matches.' : 'No devices are polled yet. Add one on the SNMP devices tab.') : null)),
    h('div', { class: 'panel col', style: 'gap:10px' },
      h('h3', null, 'Needs attention'),
      h('p', { class: 'muted' }, `Interfaces above ${d.thresholds.util}% utilisation or dropping more than ${d.thresholds.drop}% of a class, in the last ${d.windowMinutes} minutes.`),
      attn.length ? h('div', { class: 'cards' }, attn.slice(0, 8).map(a => h('button', { key: a.dev.id + '/' + a.itf.ifIndex, type: 'button', class: 'cardbtn', 'aria-pressed': a.dev.id === devId && a.itf.ifIndex === ifIndex, onclick: () => select_(a.dev.id, a.itf.ifIndex) },
        h('span', { class: 't' }, `${a.dev.name} · ${a.itf.name}`),
        h('span', { class: 's' }, [a.itf.worstDropPct !== null && a.itf.worstDropPct >= d.thresholds.drop ? `drops ${pct(a.itf.worstDropPct, 2)}` : null, `util ${pct(Math.max(a.itf.utilIn ?? 0, a.itf.utilOut ?? 0), 0)}`].filter(Boolean).join(' · '))))) : h('span', { class: 'dim' }, 'Nothing is over its threshold right now.')),
    locator(),
    h('div', { class: 'panel col', style: 'gap:8px' },
      h('h3', null, 'What is polled'),
      h('p', { class: 'muted' }, 'FlowScope reads these SNMP tables every minute from each device it can.'),
      h('div', { class: 'pts' }, d.mibs.map(m => h('div', { key: m.name, class: 'pt' }, h('i'), h('span', null, h('b', null, m.name), h('br'), h('span', { class: 'muted' }, m.what)))))));
}

/* ------------------------------------------------------------------ interface & class tables */

const vlanIn = (list: string, v: number) => !!list && (list === 'all' || list.split(',').some(p => { const [lo, hi] = p.split('-').map(Number); return hi === undefined ? lo === v : v >= lo && v <= hi; }));
const vlanLabel = (id: number | null, name: string) => (id ? (name ? `${id} ${name}` : String(id)) : '');

/** Words describing the VLAN(s) of a port, shown in the table and searched by the box above it. */
function vlanCell(i: Iface): VNode {
  if (i.isVlanIf || i.portMode === 'svi') return h('span', { class: 'muted' }, i.vlan ? `SVI for VLAN ${vlanLabel(i.vlan, i.vlanName)}` : 'SVI');
  if (i.portMode === 'trunk') return h('span', { class: 'col', style: 'gap:1px' }, h('span', null, h('span', { class: 'tag' }, 'trunk'), i.vlan ? ` native ${vlanLabel(i.vlan, i.vlanName)}` : ''), i.vlanList ? h('span', { class: 'dim mono', style: 'font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap', title: `Allowed VLANs: ${i.vlanList}` }, `allowed ${i.vlanList}`) : null);
  if (i.portMode === 'routed') return h('span', { class: 'muted' }, 'routed port');
  if (i.vlan) return h('span', { class: 'col', style: 'gap:1px' }, h('span', { style: 'font-weight:600' }, vlanLabel(i.vlan, i.vlanName)), i.voiceVlan ? h('span', { class: 'dim', style: 'font-size:11px' }, `voice ${vlanLabel(i.voiceVlan, i.voiceVlanName)}`) : null);
  return h('span', { class: 'dim' }, '—');
}

/** One search term against one interface. A bare number means a VLAN id (access, voice, native or allowed on a trunk) or a number in the port name. */
function termMatches(i: Iface, raw: string): boolean {
  let t = raw.toLowerCase();
  const vlanOnly = /^v(?:lan)?:/.test(t);
  if (vlanOnly) t = t.replace(/^v(?:lan)?:/, '');
  if (!t) return true;
  if (/^\d{1,4}$/.test(t)) {
    const n = Number(t);
    if (i.vlan === n || i.voiceVlan === n || (i.portMode === 'trunk' && vlanIn(i.vlanList, n))) return true;
    if (vlanOnly) return false;
    return i.name.split(/\D+/).includes(t) || i.alias.split(/\D+/).includes(t);
  }
  const vtext = `${vlanLabel(i.vlan, i.vlanName)} ${vlanLabel(i.voiceVlan, i.voiceVlanName)} ${i.vlanName} ${i.voiceVlanName}`.toLowerCase();
  if (vlanOnly) return vtext.includes(t) || (t === 'trunk' && i.portMode === 'trunk');
  const nb = (nbRes?.ports.find(p => p.ifIndex === i.ifIndex)?.neighbors ?? []).map(n => `${n.name} ${n.port} ${n.ip}`).join(' ');
  return `${i.name} ${i.alias} ${vtext} ${i.portMode} ${i.policy ?? ''} ${i.policyIn ?? ''} ${nb}`.toLowerCase().includes(t);
}
function filterIfaces(list: Iface[]): Iface[] {
  const terms = ifSearch.trim().split(/\s+/).filter(Boolean);
  return terms.length ? list.filter(i => terms.every(t => termMatches(i, t))) : list;
}

function policyCell(i: Iface): VNode {
  if (!i.policy && !i.policyIn) return h('span', { class: 'muted', style: 'font-size:12px' }, '—');
  return h('span', { class: 'col', style: 'gap:1px;font-size:12px' }, i.policy ? h('span', { class: 'muted', title: 'Policy applied to traffic leaving the port' }, 'out ', h('b', null, i.policy)) : null, i.policyIn ? h('span', { class: 'muted', title: 'Policy applied to traffic entering the port' }, 'in ', h('b', null, i.policyIn)) : null);
}

function ifTable(dev: Dev): VNode {
  const cols = 'minmax(88px,0.8fr) minmax(120px,1fr) minmax(130px,1fr) minmax(140px,1.1fr) 52px 58px 118px 118px 64px minmax(84px,0.8fr) 70px';
  const nbOf = (ix: number): Neighbor[] => nbRes?.ports.find(p => p.ifIndex === ix)?.neighbors ?? [];
  const rows = filterIfaces(dev.interfaces);
  return h('div', { class: 'col', style: 'gap:8px' },
    h('div', { class: 'row', style: 'gap:10px' },
      h('div', { style: 'flex:1 1 320px;max-width:460px' }, textInput(ifSearch, v => { ifSearch = v; }, { placeholder: 'Search interface, description, neighbour or VLAN', aria: 'Search interfaces', width: '100%' })),
      ifSearch.trim() ? btn('Clear', { kind: 'ghost', small: true, onclick: () => { ifSearch = ''; redraw(); } }) : null,
      h('span', { class: 'muted', role: 'status', 'aria-live': 'polite' }, ifSearch.trim() ? `${rows.length} of ${dev.interfaces.length} interfaces` : `${dev.interfaces.length} interfaces`),
      h('span', { class: 'dim', style: 'font-size:12px' }, 'Words must all match. A number is a VLAN id; vlan:20 matches only VLANs.')),
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${cols};--w:1230px` },
      h('div', { class: 'tr head' }, ...['Interface', 'Description', 'Neighbour (CDP/LLDP)', 'VLAN', 'Speed', 'State', 'In', 'Out', 'Discards', 'Service policy', 'Flows'].map(t => h('span', null, t))),
      h('div', { class: 'scroll' }, rows.map(i => h('div', { key: i.ifIndex, class: 'tr pick', 'aria-current': i.ifIndex === ifIndex ? 'true' : undefined, onclick: () => select_(dev.id, i.ifIndex) },
        h('span', { style: 'font-weight:600' }, h('button', { type: 'button', class: 'rowbtn', 'aria-pressed': i.ifIndex === ifIndex, title: `Show ${i.name}`, onclick: (e: Event) => { e.stopPropagation(); select_(dev.id, i.ifIndex); } }, i.name), i.flagged ? h('span', { style: 'color:var(--warn);margin-left:6px', title: 'Needs attention' }, '●') : null),
        h('span', { class: 'muted' }, i.alias || '—'),
        nbCell(nbOf(i.ifIndex)),
        vlanCell(i),
        h('span', { class: 'mono', style: 'font-size:12px' }, i.speedMbps ? (i.speedMbps >= 1000 ? i.speedMbps / 1000 + ' G' : i.speedMbps + ' M') : '—'),
        h('span', null, i.oper === 'up' ? statusEl('ok', 'up') : statusEl(i.oper === 'down' ? 'bad' : 'off', i.oper)),
        utilCell(i.utilIn, i.inBps), utilCell(i.utilOut, i.outBps),
        h('span', { class: 'mono', style: 'font-size:12px' }, num(i.disc + i.err)),
        policyCell(i),
        h('span', null, btn('Flows', { small: true, kind: 'ghost', title: `Flows by port: the busiest flows entering or leaving ${i.name}`, aria: `Flows through ${i.name}`, onclick: (e: Event) => { e.stopPropagation(); go('ports', { dev: dev.id, if: i.ifIndex }); } })))),
        !dev.interfaces.length ? empty('This device has not reported any interfaces yet.') : !rows.length ? empty('No interface matches that search.') : null))));
}
const shortName = (n: Neighbor): string => (n.name ? n.name.split('.')[0] || n.name : n.ip) || 'unnamed';

/** Who is cabled to a port. A neighbour that is a polled device is a link to that device and port, as in the Flow explorer. */
function nbCell(ns: Neighbor[]): VNode {
  if (!ns.length) return h('span', { class: 'dim' }, '—');
  return h('span', { class: 'col', style: 'gap:2px' }, ns.map((n, k) => {
    const label = n.name ? n.name.split('.')[0] || n.name : n.ip || 'unnamed';
    const tip = `${n.protos.map(p => p.toUpperCase()).join('·')}: ${n.name || n.ip}${n.port ? ' ' + n.port : ''}`;
    return h('span', { key: k, title: tip },
      n.device
        ? h('button', { type: 'button', class: 'lnk', style: 'font-weight:500', title: `Open ${n.device.name}${n.devicePort ? ' at ' + n.devicePort.name : ''} in Links and QoS`, onclick: (e: Event) => { e.stopPropagation(); openPort(n.device!.name, n.devicePort?.name); } }, label)
        : h('span', { style: 'font-weight:500' }, label),
      n.port ? h('span', { class: 'dim mono', style: 'font-size:11.5px' }, ' ' + n.port) : null);
  }));
}

/** Every CDP / LLDP neighbour of the device by port; a neighbour that is a polled device opens in this page. */
function neighborsPanel(dev: Dev): VNode {
  const ports = nbRes?.ports ?? [];
  const cols = 'minmax(90px,0.8fr) minmax(170px,1.4fr) minmax(130px,1fr) minmax(130px,1fr) 90px minmax(150px,0.9fr)';
  return h('div', { class: 'col', style: 'gap:8px' },
    h('div', { class: 'row', style: 'justify-content:space-between' },
      h('div', { class: 'col', style: 'gap:2px' }, h('b', null, 'Neighbours (CDP and LLDP)'),
        h('span', { class: 'muted', style: 'font-size:12px' }, dev.hostsAt ? `What ${dev.name} reports is at the other end of each port, last read ${ago(dev.hostsAt)}. A neighbour that is also an SNMP device here can be opened.` : 'Not read yet from this device.')),
      btn(readingHosts ? 'Reading…' : 'Read tables now', { small: true, kind: 'ghost', disabled: readingHosts, title: 'Ask the device for its MAC, ARP and neighbour tables right now', onclick: () => void readHostsNow() })),
    nbError ? note(nbError, 'bad', true) : null,
    nbLoading && !nbRes ? spinner('Loading neighbours…') : null,
    nbRes && !ports.length && !nbLoading ? h('span', { class: 'dim', style: 'font-size:12.5px' }, nbRes.note || 'This device reports no CDP or LLDP neighbours. Check that CDP or LLDP is turned on, on the device and on the port.') : null,
    ports.length ? h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${cols};--w:880px` },
      h('div', { class: 'tr head' }, ...['Port', 'Neighbour', 'Its port', 'Type', 'Protocol', 'SNMP'].map(t => h('span', null, t))),
      h('div', { class: 'scroll', style: 'max-height:320px' }, ports.flatMap(p => p.neighbors.map((n, k) => h('div', { key: p.ifIndex + '/' + k, class: 'tr' },
        k === 0 ? h('button', { type: 'button', class: 'lnk', title: `Show ${p.ifName}`, onclick: () => select_(dev.id, p.ifIndex) }, p.ifName) : h('span', null),
        h('span', null, n.device
          ? h('button', { type: 'button', class: 'lnk', title: `Open ${n.device.name}${n.devicePort ? ' at ' + n.devicePort.name : ''} in Links and QoS`, onclick: () => openPort(n.device!.name, n.devicePort?.name) }, n.name || n.device.name)
          : (n.name || n.ip || 'unnamed'), n.ip && n.name ? h('span', { class: 'dim mono', style: 'font-size:11.5px' }, ' ' + n.ip) : null),
        h('span', { class: 'mono', style: 'font-size:12px' }, n.port || '—'),
        h('span', { style: 'font-size:12px' }, KIND_TEXT[n.kind] ?? n.kind),
        h('span', { class: 'mono', style: 'font-size:12px' }, n.protos.map(x => x.toUpperCase()).join(' · ')),
        n.device ? h('span', { class: 'dim', style: 'font-size:12px' }, 'polled device') : h('span', { class: 'dim', style: 'font-size:12px' }, 'not an SNMP device'))))))) : null);
}
function utilCell(u: number | null, b: number | null): VNode {
  return h('span', { class: 'row', style: 'gap:8px;flex-wrap:nowrap' }, u === null ? h('span', { class: 'dim' }, 'no data') : [bar(u), h('span', { class: 'mono', style: 'font-size:12px' }, pct(u, 0) + ' ', h('span', { class: 'dim' }, bps(b)))]);
}

function classTable(itf: Iface): VNode {
  const cols = 'minmax(120px,1fr) minmax(110px,1fr) 100px 110px 110px 110px 100px';
  return h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${cols};--w:780px` },
    h('div', { class: 'tr head' }, ...['Class', 'DSCP values', 'Guaranteed', 'Sent', 'Drop %', 'Dropped', 'Queue depth'].map(t => h('span', null, t))),
    itf.classes.map(c => h('div', { key: c.cls, class: 'tr' },
      h('span', { style: 'font-weight:600' }, c.label, ' ', c.dir === 'in' ? h('span', { class: 'tag', title: 'This class belongs to the input service policy' }, 'in') : null), h('span', { class: 'mono muted', style: 'font-size:12px' }, dscpText(c.dscps)),
      h('span', { class: 'mono', style: 'font-size:12px' }, c.bw ?? '—'), h('span', { class: 'mono', style: 'font-size:12px' }, bps(c.sentBps)),
      h('span', { class: 'mono', style: `font-size:12px;color:${(c.dropPct ?? 0) >= (data?.thresholds.drop ?? 1) ? 'var(--bad)' : 'inherit'}` }, c.dropPct === null ? '—' : pct(c.dropPct, 2)),
      h('span', { class: 'mono', style: 'font-size:12px' }, c.dropPkts ? `${num(c.dropPkts)} pkts · ${bytes(c.dropBytes)}` : '0'),
      h('span', { class: 'mono', style: 'font-size:12px' }, c.qdepth === null ? '—' : num(c.qdepth)))),
    !itf.classes.length ? h('div', { class: 'empty' }, itf.policy || itf.policyIn ? 'No class statistics have been read from this interface yet.' : 'No service policy was found on this interface, or the device does not publish CISCO-CLASS-BASED-QOS-MIB.') : null));
}

/* ------------------------------------------------------------------ hosts on a port */


function hostsPanel(dev: Dev, itf: Iface): VNode {
  const r = hostsRes;
  const wifiCols = !!r?.hosts.some(x => x.wifi);
  const head = h('div', { class: 'row', style: 'justify-content:space-between' },
    h('div', { class: 'col', style: 'gap:2px' }, h('b', null, `Hosts on ${itf.name}`),
      h('span', { class: 'muted', style: 'font-size:12px' }, dev.hostsAt ? `From the MAC address, ARP and LLDP/CDP tables of ${dev.name}, last read ${ago(dev.hostsAt)}.` : 'From the MAC address, ARP and LLDP/CDP tables. Not read yet from this device.')),
    h('div', { class: 'row' }, readMsg ? h('span', { class: 'muted', style: 'font-size:12px', role: 'status' }, readMsg) : null,
      btn('Flows by port', { small: true, kind: 'ghost', title: `Open ${itf.name} in Flows by port`, aria: `Flows by port for ${itf.name}`, onclick: () => go('ports', { dev: dev.id, if: itf.ifIndex }) }),
      btn(readingHosts ? 'Reading…' : 'Read tables now', { small: true, kind: 'ghost', disabled: readingHosts, title: 'Ask the device for its MAC, ARP and neighbour tables right now', onclick: () => void readHostsNow() })));
  return h('div', { class: 'col', style: 'gap:8px' }, head,
    dev.hostsNote ? note(dev.hostsNote, 'warn') : null,
    hostsLoading && !r ? spinner('Loading hosts…') : hostsError ? note(hostsError, 'bad', true) : null,
    r && !r.tracking ? note('Host tracking is turned off, so no tables are being read automatically. Tables can still be read with the button above.', 'info') : null,
    r && r.neighbors.length ? neighborLines(r.neighbors) : null,
    r && r.neighbors.some(n => n.kind === 'infra') ? h('span', { class: 'dim', style: 'font-size:12px' }, 'This port leads to another switch or router. Addresses below are just what that device has forwarded, not hosts plugged in here.') : null,
    r && r.hosts.length ? h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${wifiCols ? 'minmax(150px,1fr) ' : ''}minmax(150px,1fr) minmax(130px,1fr)${wifiCols ? ' minmax(190px,1.2fr)' : ''} minmax(140px,1fr) 110px 110px 150px;--w:${wifiCols ? 1250 : 860}px` },
      h('div', { class: 'tr head' }, ...[...(wifiCols ? ['Name'] : []), 'MAC address', 'IP address', ...(wifiCols ? ['Wi-Fi'] : []), 'VLAN', 'First seen', 'Last seen', 'Flows'].map(t => h('span', null, t))),
      h('div', { class: 'scroll', style: 'max-height:240px' }, r.hosts.slice(0, 100).map(x => h('div', { key: x.mac + x.vlan, class: 'tr' },
        wifiCols ? h('span', null, x.wifi ? [x.wifi.name || '—', x.wifi.os ? h('span', { class: 'dim', style: 'font-size:12px' }, ' · ' + x.wifi.os) : null] : h('span', { class: 'dim' }, '—')) : null,
        h('span', { class: 'mono', style: 'font-size:12px' }, x.mac), h('span', { class: 'mono', style: 'font-size:12px' }, x.ips.join(', ') || '—'),
        wifiCols ? (x.wifi ? h('span', { style: 'font-size:12px' }, `${x.wifi.ssid || 'Wi-Fi'} · ${bandText(x.wifi.band, x.wifi.channel)} · `, snrTag(x.wifi.snr)) : h('span', { class: 'dim' }, '—')) : null,
        h('span', null, vlanLabel(x.vlan, x.vlanName) || '—'), h('span', { class: 'muted', style: 'font-size:12px' }, dayClock(x.firstSeen)),
        h('span', { class: x.active ? 'muted' : 'dim', style: 'font-size:12px' }, x.active ? ago(x.lastSeen) : 'gone ' + ago(x.lastSeen)),
        h('span', { class: 'row', style: 'gap:4px;flex-wrap:nowrap' },
          btn('Explorer', { small: true, kind: 'ghost', title: `Flows with ${x.ips[0] || x.mac} in Flow explorer`, aria: `Flow explorer for ${x.ips[0] || x.mac}`, onclick: () => go('explorer', { q: x.ips[0] ? 'ip:' + x.ips[0] : 'mac:' + x.mac, range: '1h' }) }),
          btn('Port', { small: true, kind: 'ghost', title: `Open ${itf.name} in Flows by port`, aria: `Flows by port for ${itf.name}`, onclick: () => go('ports', { dev: dev.id, if: itf.ifIndex }) }))))))) : null,
    r && !r.hosts.length && r.tracking && !hostsError ? h('span', { class: 'dim' }, dev.hostsAt ? 'No MAC addresses have been learned on this port.' : 'Nothing read yet. The first read happens within a few minutes of adding the device, or press Read tables now.') : null,
    r && r.hosts.length > 100 ? h('span', { class: 'dim' }, `${num(r.hosts.length)} addresses; the newest 100 are shown.`) : null);
}

/* ------------------------------------------------------------------ Wi-Fi (access points) */

const bandText = (band: string, channel: string): string => (band ? `${band} GHz` : 'radio') + (channel ? ` ch ${channel}` : '');
/** Signal to noise: a rough guide, 25 dB and up is good for most use, under 15 dB is poor. */
/** A value the access point does not report (see NA in src/snmp/wlan.ts). */
const NA = -1000;
const known = (n: number) => n > NA;
function snrTag(snr: number): VNode {
  if (!known(snr)) return h('span', { class: 'dim', title: 'This access point does not report signal strength' }, '—');
  const kind = snr >= 25 ? 'ok' : snr >= 15 ? 'warn' : 'bad';
  return h('span', { class: 'mono', style: `color:${kind === 'ok' ? 'inherit' : kind === 'warn' ? 'var(--warn)' : 'var(--bad)'}`, title: 'Signal to noise ratio. Roughly: 25 dB and up is good, 15 to 25 is fair, under 15 is poor.' }, `${snr} dB`);
}

function wlanPanel(dev: Dev): VNode {
  const w = wlan;
  const q = clientFilter.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const radioName = (apMac: string, idx: number | null): string => { const r = w?.radios.find(x => x.apMac === apMac && x.idx === idx); return r ? bandText(r.band, r.channel) : idx === null ? '—' : `radio ${idx}`; };
  const clients = (w?.clients ?? []).filter(c => !q.length || q.every(t => `${c.name} ${c.os} ${c.mac} ${c.ip} ${c.ssid} ${c.apName}`.toLowerCase().includes(t)));
  const apNames = new Set((w?.clients ?? []).map(c => c.apMac)); const multi = apNames.size > 1;
  const cCols = `minmax(150px,1.2fr) 128px 112px minmax(150px,1.1fr) 66px 104px minmax(130px,1fr) 76px`;
  return h('div', { class: 'col', style: 'gap:10px' },
    h('div', { class: 'row', style: 'justify-content:space-between' },
      h('div', { class: 'col', style: 'gap:2px' }, h('b', null, 'Wi-Fi'),
        h('span', { class: 'muted', style: 'font-size:12px' }, w?.readAt ? `Radios, SSIDs and clients from the access point's own tables, last read ${ago(w.readAt)}. They are read with the host tables, every few minutes.` : 'Not read yet from this access point.')),
      btn(readingHosts ? 'Reading…' : 'Read tables now', { small: true, kind: 'ghost', disabled: readingHosts, title: 'Ask the access point for its Wi-Fi tables right now', onclick: () => void readHostsNow() })),
    wlanError ? note(wlanError, 'bad', true) : null,
    wlanLoading && !w ? spinner('Loading Wi-Fi…') : null,
    w && w.aps.length ? h('div', { class: 'cards' }, w.aps.map(a => h('div', { key: a.mac, class: 'cardbtn', style: 'cursor:default' },
      h('span', { class: 't' }, a.name || a.mac), h('span', { class: 's' }, [a.model ? 'model ' + a.model : null, a.role || null, `up ${dur(a.uptimeSec * 1000)}`].filter(Boolean).join(' · ')),
      h('span', { class: 's' }, known(a.cpuPct) ? `CPU ${a.cpuPct}%` : null, a.memTotal ? ` · memory ${Math.round((a.memTotal - a.memFree) / a.memTotal * 100)}% used of ${bytes(a.memTotal)}` : '')))) : null,
    w && w.radios.length ? h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(150px,1.2fr) 90px 90px minmax(150px,1fr) minmax(150px,1fr) 80px 70px;--w:880px' },
      h('div', { class: 'tr head' }, ...['Radio', 'Power', 'Noise floor', 'Channel busy (4 s)', 'Channel busy (64 s)', 'Clients', 'State'].map(t => h('span', null, t))),
      w.radios.map(r => h('div', { key: r.apMac + r.idx, class: 'tr' },
        h('span', { style: 'font-weight:600' }, `Radio ${r.idx} · ${bandText(r.band, r.channel)}`, r.mode ? h('span', { class: 'dim', style: 'font-weight:400' }, ' · ' + r.mode) : null),
        h('span', { class: 'mono', style: 'font-size:12px' }, known(r.txPower) ? `${r.txPower} dBm` : '—'), h('span', { class: 'mono', style: 'font-size:12px' }, known(r.noiseFloor) ? `${r.noiseFloor} dBm` : '—'),
        known(r.util4) ? h('span', { class: 'row', style: 'gap:8px;flex-wrap:nowrap' }, bar(r.util4), h('span', { class: 'mono', style: 'font-size:12px' }, pct(r.util4, 0))) : h('span', { class: 'dim' }, '—'),
        known(r.util64) ? h('span', { class: 'row', style: 'gap:8px;flex-wrap:nowrap' }, bar(r.util64), h('span', { class: 'mono', style: 'font-size:12px' }, pct(r.util64, 0))) : h('span', { class: 'dim' }, '—'),
        h('span', { class: 'mono', style: 'font-size:12px' }, String(r.clients)), h('span', null, r.up ? statusEl('ok', 'up') : statusEl('bad', 'down')))))) : null,
    w && w.ssids.length ? h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(150px,1.2fr) minmax(150px,1fr) minmax(150px,1fr) 80px minmax(170px,1fr);--w:760px' },
      h('div', { class: 'tr head' }, ...['SSID', 'Radio', 'BSSID', 'Clients', 'Interface'].map(t => h('span', null, t))),
      w.ssids.map(s => { const itf = s.ifName ? dev.interfaces.find(i => i.name === s.ifName) : undefined; return h('div', { key: s.bssid, class: 'tr' },
        h('span', { style: 'font-weight:600' }, s.name || '—'), h('span', null, radioName(s.apMac, s.radio)), h('span', { class: 'mono', style: 'font-size:12px' }, /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(s.bssid) ? s.bssid : '—'), h('span', { class: 'mono', style: 'font-size:12px' }, String(s.clients)),
        itf ? h('button', { type: 'button', class: 'lnk', title: 'Show this interface: utilisation, discards and graphs', onclick: () => select_(dev.id, itf.ifIndex) }, itf.name) : h('span', { class: 'dim' }, '—')); }))) : null,
    w && w.clients.length ? h('div', { class: 'col', style: 'gap:8px' },
      h('div', { class: 'row', style: 'justify-content:space-between' },
        h('b', null, `Wireless clients (${num(w.clients.length)})`),
        textInput(clientFilter, v => { clientFilter = v; searchSoon(); }, { placeholder: 'Filter by name, MAC, IP or SSID', aria: 'Filter wireless clients', width: '280px' })),
      h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${cCols};--w:960px` },
        h('div', { class: 'tr head' }, ...['Client', 'MAC address', 'IP address', 'SSID and radio', 'Signal', 'Link rate', 'To / from client', 'Connected'].map(t => h('span', null, t))),
        h('div', { class: 'scroll', style: 'max-height:360px' }, clients.map(c => h('div', { key: c.mac, class: 'tr' },
          h('span', null, c.name || '—', c.os ? h('span', { class: 'dim', style: 'font-size:12px' }, ' · ' + c.os) : null, multi && c.apName ? h('span', { class: 'dim', style: 'font-size:12px' }, ' · on ' + c.apName) : null),
          h('span', { class: 'mono', style: 'font-size:12px' }, c.mac), h('span', { class: 'mono', style: 'font-size:12px' }, c.ip || '—'),
          h('span', { style: 'font-size:12px' }, `${c.ssid || '—'} · ${radioName(c.apMac, c.radio)}`), snrTag(c.snr),
          h('span', { class: 'mono', style: 'font-size:12px', title: 'Rate to the client / rate from the client, in Mbps' }, c.txRate || c.rxRate ? `${c.txRate} / ${c.rxRate} Mbps` : '—'),
          h('span', { class: 'mono', style: 'font-size:12px', title: 'Bytes the access point sent to the client / received from it, since it connected' }, c.txBytes || c.rxBytes ? `${bytes(c.txBytes)} / ${bytes(c.rxBytes)}` : '—'),
          h('span', { class: 'muted', style: 'font-size:12px' }, dur(c.uptimeSec * 1000)))),
          !clients.length ? h('div', { class: 'empty' }, 'No client matches the filter.') : null)))) : null,
    w && !w.clients.length && !wlanLoading && w.readAt ? h('span', { class: 'dim' }, 'No wireless clients are connected right now.') : null);
}

/** Sidebar box: type an IP or MAC address to see which switch port it is plugged in to. */
function locator(): VNode {
  const f = found;
  return h('div', { class: 'panel col', style: 'gap:10px' },
    h('h3', null, 'Find a host'),
    h('p', { class: 'muted' }, 'Where is an IP or MAC address plugged in? Answered from the switches\' MAC address and ARP tables.'),
    h('div', { class: 'row', style: 'flex-wrap:nowrap' }, textInput(findQ, v => { findQ = v; }, { placeholder: '10.1.20.5 or aa:bb:cc:dd:ee:ff', aria: 'IP or MAC address to find', mono: true, onenter: () => void findHost() }), btn(finding ? '…' : 'Find', { kind: 'primary', disabled: finding || !findQ.trim(), onclick: () => void findHost() })),
    findError ? note(findError, 'bad', true) : null,
    f ? foundBlock(f) : null);
}

/** Result of Find a host: confident ports as cards, low-confidence ones tucked away but still clickable, plus jumps to the flow pages. */
function foundBlock(f: Located): VNode {
  const cands: Attach[] = f.attach ? [f.attach, ...(f.others as Attach[])] : (f.others as Attach[]);
  const strong = cands.filter(a => a.confidence !== 'low');
  const primary = strong.length ? strong : (f.attach ? [f.attach] : []);
  const rest = cands.filter(a => !primary.includes(a));
  const flowsBtn = (a: Attach) => btn('Flows by port', { small: true, kind: 'ghost', title: `Open ${a.ifName} on ${a.dev} in Flows by port`, aria: `Flows by port for ${a.ifName} on ${a.dev}`, onclick: () => go('ports', { dev: a.devId, if: a.ifIndex }) });
  const q = f.ip ? 'ip:' + f.ip : f.macs.length ? 'mac:' + f.macs[0] : '';
  return h('div', { class: 'col', style: 'gap:6px' },
    ...primary.map(a => h('div', { key: a.devId + '/' + a.ifIndex, class: 'col', style: 'gap:4px' },
      h('button', { type: 'button', class: 'cardbtn', onclick: () => select_(a.devId, a.ifIndex) },
        h('span', { class: 't' }, `${a.dev} · ${a.ifName}`),
        h('span', { class: 's' }, [a.vlan ? `VLAN ${a.vlan}` : null, `${a.macCount} address${a.macCount === 1 ? '' : 'es'} on the port`, a.confidence ? `${a.confidence} confidence` : null].filter(Boolean).join(' · '))),
      h('div', { class: 'row' }, flowsBtn(a)))),
    q ? h('div', { class: 'row' }, btn(f.ip ? 'Flows with this IP in Flow explorer' : 'Flows with this MAC in Flow explorer', { small: true, kind: 'ghost', onclick: () => go('explorer', { q, range: '1h' }) })) : null,
    f.macs.length ? h('span', { class: 'muted', style: 'font-size:12px' }, 'MAC ', h('span', { class: 'mono' }, f.macs.join(', ')), f.ip ? ` · IP ${f.ip}` : '') : null,
    f.note ? h('span', { class: 'muted', style: 'font-size:12px' }, f.note) : null,
    rest.length ? h('details', null, h('summary', { class: 'muted' }, `Also seen on ${rest.length} other port${rest.length === 1 ? '' : 's'}`),
      h('div', { class: 'col', style: 'gap:4px;padding-top:4px' }, rest.map(o => h('div', { key: o.devId + '/' + o.ifIndex, class: 'row', style: 'gap:8px;font-size:12px' },
        h('button', { type: 'button', class: 'lnk', title: `Show ${o.ifName}`, onclick: () => select_(o.devId, o.ifIndex) }, `${o.dev} · ${o.ifName}`),
        h('span', { class: 'muted' }, o.edge ? 'low confidence' : 'uplink'),
        flowsBtn(o))))) : null);
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
      lineChart({ title: 'Packets dropped (% of the class)', unit: v => (v < 10 ? v.toFixed(1) : v.toFixed(0)) + '%', series: mk(p => p.dropPct), from, to, threshold: dropThr, bands, fmtT, fmtV: v => pct(v, 2), aria: `Drop percentage per class on ${itf.name}` }),
      lineChart({ title: 'Bytes dropped (per second)', unit: v => bytes(v) + '/s', series: mk(p => p.dropBps / 8), from, to, bands, fmtT, aria: `Bytes dropped per class on ${itf.name}` })) : null,
    h('div', { class: 'charts' }, lineChart({
      wide: true, title: 'Utilisation (% of line speed)', unit: v => v.toFixed(0) + '%', yMax: Math.max(100, ...s.util.points.map(p => Math.max(p.utilIn, p.utilOut))), threshold: data?.thresholds.util, from, to, fmtT, fmtV: v => pct(v, 1),
      series: [{ name: 'In', color: 'var(--s3)', points: s.util.points.map(p => ({ t: p.ts, v: p.utilIn })) }, { name: 'Out', color: 'var(--s1)', points: s.util.points.map(p => ({ t: p.ts, v: p.utilOut })) }], aria: `Utilisation of ${itf.name}`
    })),
    h('div', { class: 'charts' }, lineChart({
      wide: true, title: 'Throughput (bits per second)', unit: bpsAxis, fmtV: bps, yMax: niceCeil(Math.max(1000, ...s.util.points.map(p => Math.max(p.inBps, p.outBps)))), from, to, fmtT,
      series: [{ name: 'In', color: 'var(--s3)', points: s.util.points.map(p => ({ t: p.ts, v: p.inBps })) }, { name: 'Out', color: 'var(--s1)', points: s.util.points.map(p => ({ t: p.ts, v: p.outBps })) }], aria: `Throughput of ${itf.name} in bits per second`
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
    h('div', { class: 'row', style: 'justify-content:space-between' }, h('b', null, `Streams leaving ${dev.name} · ${itf.name}`),
      btn('All flows through this port', { small: true, kind: 'ghost', title: 'List the busiest flows entering or leaving this port, 25 to 500 of them', onclick: () => go('ports', { dev: dev.id, if: itf.ifIndex }) })),
    streamsLoading && !streams.length ? spinner('Looking for streams…') : null,
    !streamsLoading && !streams.length ? h('span', { class: 'dim' }, 'No sampled streams leave through this interface in the current data.') : null,
    h('div', { class: 'cards' }, streams.map(x => h('button', { key: x.id, type: 'button', class: 'cardbtn', onclick: () => go('explorer', { s: x.id, q: `ip:${x.srcIp} ip:${x.dstIp}`, range: '24h' }) },
      h('span', { class: 't mono' }, `${x.srcIp}:${x.sport} → ${x.dstIp}:${x.dport}`),
      h('span', { class: 's' }, `${svcLabel(x.app, x.appPort)} · ${bytes(x.bytes)}`, x.qosChanged ? h('span', { class: 'tag bad', style: 'margin-left:8px' }, 'QoS re-marked') : null)))),
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
          h('div', { class: 'col', style: 'gap:4px' }, h('h3', { style: 'font-size:17px' }, dev.name), h('span', { class: 'muted' }, `${roleLabel(dev.role)} · ${dev.ip} · ${dev.profile || 'generic'} · last answered ${ago(dev.lastOk)}`)),
          btn('Edit in SNMP devices', { kind: 'ghost', small: true, onclick: () => go('devices', { id: dev.id }) })),
        dev.status !== 'ok' && dev.lastError ? note(`The last poll failed: ${dev.lastError}`, 'warn') : null,
        ifTable(dev),
        dev.hasWlan ? wlanPanel(dev) : null,
        neighborsPanel(dev)) : null,
      dev && itf ? h('section', { 'aria-label': 'Selected interface', class: 'panel col', style: 'gap:16px' },
        h('div', { class: 'row', style: 'justify-content:space-between' }, h('div', { class: 'col', style: 'gap:4px' }, h('h3', { style: 'font-size:17px' }, `${itf.name}${itf.alias ? ' · ' + itf.alias : ''}`),
          h('span', { class: 'muted' }, [itf.speedMbps ? (itf.speedMbps >= 1000 ? itf.speedMbps / 1000 + ' Gbps' : itf.speedMbps + ' Mbps') : 'speed unknown',
            itf.portMode === 'trunk' ? `trunk, native VLAN ${vlanLabel(itf.vlan, itf.vlanName) || 'unknown'}${itf.vlanList ? ', allowed ' + itf.vlanList : ''}` : itf.vlan ? `${itf.isVlanIf ? 'SVI for ' : ''}VLAN ${vlanLabel(itf.vlan, itf.vlanName)}${itf.voiceVlan ? ', voice VLAN ' + vlanLabel(itf.voiceVlan, itf.voiceVlanName) : ''}` : null,
            itf.policy ? 'output policy ' + itf.policy : null, itf.policyIn ? 'input policy ' + itf.policyIn : null].filter(Boolean).join(' · '))),
          h('div', { class: 'row' }, itf.flagged ? chip('Needs attention', 'warn') : chip('Within thresholds', 'ok'))),
        dev.qosNote ? note(dev.qosNote, 'warn') : null,
        classTable(itf),
        itf.isVlanIf ? null : hostsPanel(dev, itf),
        seriesLoading && !series ? spinner('Loading the graphs…') : seriesError ? note(seriesError, 'bad', true) : series ? graphs(series, itf) : null,
        streamsPanel(dev, itf)) : dev ? h('div', { class: 'panel' }, empty('Select an interface to see its queues and graphs.')) : null)));
}
