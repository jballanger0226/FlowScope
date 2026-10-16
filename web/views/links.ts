import { h, type VNode } from '../vdom.js';
import { get, qs } from '../api.js';
import { redraw, go } from '../state.js';
import { bar, btn, chartGrid, chip, empty, heading, lineChart, rangePicker, spark, stat, note, PALETTE, select, spinner, status as statusEl, tabs, textInput, type Series } from '../components.js';
import { ago, bps, bpsAxis, bytes, clock, dayClock, dur, niceCeil, num, pct, debounce, rangeMs, svcLabel } from '../util.js';
import { post } from '../api.js';
import { correlate, verdict } from './correlate.js';
import { attentionPanel, cards, cardsRow, issues, type Target } from './links_overview.js';
import { hardwarePanel, hasHardware, hasOptics, linkQuality, nbarPanel, opticCell, opticMap, protocolsPanel, type HealthRes } from './links_health.js';
import { publicAddresses } from './ip_scope.js';
import { neighborLines, openPort, KIND_TEXT, type Neighbor } from '../neighbors.js';

interface Cls { cls: string; label: string; dir: 'in' | 'out'; dscps: number[]; bw: string | null; queue: string | null; dropPct: number | null; dropPkts: number; dropBytes: number; sentBps: number | null; qdepth: number | null }
interface Disk { name: string; usedPct: number; totalBytes: number; usedBytes: number }
interface Resources { uptimeSec: number | null; cpuPct: number | null; cores: number | null; load: [number, number, number] | null; memPct: number | null; memTotal: number | null; memUsed: number | null; swapPct: number | null; sessions?: number | null; sessionsMax?: number | null; tempC?: number | null; disks: Disk[]; source: string; readAt: number }
interface Iface {
  mac: string; addresses: string[];
  ifIndex: number; name: string; alias: string; speedMbps: number | null; oper: string; policy: string | null; policyIn: string | null;
  portMode: string; vlan: number | null; vlanName: string; voiceVlan: number | null; voiceVlanName: string; vlanList: string; isVlanIf: boolean; hosts: number;
  utilIn: number | null; utilOut: number | null; inBps: number | null; outBps: number | null; disc: number; err: number;
  classes: Cls[]; worstDropPct: number | null; flagged: boolean;
}
interface Dev { id: number; name: string; ip: string; role: string; hasWlan: boolean; status: string; lastOk: number | null; lastError: string | null; profile: string; qosNote: string | null; hostsAt: number | null; hostsNote: string | null; resources: Resources | null; interfaces: Iface[] }
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
interface ArpRow { ip: string; mac: string; ifIndex: number; ifName: string; lastSeen: number }
let arpRes: { rows: ArpRow[]; readAt: number | null } | null = null; let arpQ = '';
let nbRes: NbRes | null = null; let nbError = ''; let nbLoading = false;
let wlan: WlanRes | null = null; let wlanError = ''; let wlanLoading = false; let clientFilter = '';
let devId = 0; let ifIndex = 0;
let graphRange = '6h';
/** The stretch of time the user dragged across on a graph, when the graphs are zoomed in; null shows the chosen range ending now. */
type Zoom = { from: number; to: number };
let graphZoom: Zoom | null = null; let resZoom: Zoom | null = null;
type IfTab = 'traffic' | 'quality' | 'hosts';
let ifTab: IfTab = 'traffic';
interface QualityRes { step: number; tier: 'raw' | 'h1'; points: ({ ts: number } & Partial<Record<string, number>>)[] }
let quality: QualityRes | null = null; let qualityLoading = false;
let dropThr = 1;
let hidden = new Set<string>();
interface ResPoint { ts: number; cpu: number | null; cpuMax: number | null; mem: number | null; memMax: number | null; swap: number | null; disk: number | null; load: number | null; loadMax: number | null; temp: number | null; tempMax: number | null; sess: number | null; sessMax: number | null }
interface ResHist { step: number; tier: 'raw' | 'h1'; points: ResPoint[]; restarts: number[] }
/** Resource history by subject: '' is the device itself, otherwise an access point's MAC address. */
const resHists = new Map<string, ResHist>();
type DevTab = 'overview' | 'interfaces' | 'hardware' | 'network' | 'wifi';
let devTab: DevTab = 'overview';
const DEV_TABS: DevTab[] = ['overview', 'interfaces', 'hardware', 'network', 'wifi'];
let resHistError = ''; let resHistLoading = false; let resRange = '6h'; let resOpen = true;
const RES_RANGES: [string, string][] = [['1h', 'Last hour'], ['6h', 'Last 6 hours'], ['24h', 'Last 24 hours'], ['3d', 'Last 3 days'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days']];
let series: SeriesRes | null = null; let seriesError = ''; let seriesLoading = false;
let streams: StreamRow[] = []; let streamsTotal = 0; let streamsLoading = false;
let pendingName: { dev: string; ifn: string; tab?: DevTab; section?: 'traffic' | 'quality' } | null = null;
let timer: number | undefined;

const GRAPH_RANGES: [string, string][] = [['15m', 'Last 15 minutes'], ['1h', 'Last hour'], ['6h', 'Last 6 hours'], ['24h', 'Last 24 hours'], ['7d', 'Last 7 days']];
const THRESHOLDS: [string, string][] = [['0.5', '0.5%'], ['1', '1%'], ['2', '2%'], ['5', '5%']];

export function enter(p: URLSearchParams): void {
  const d = p.get('dev'), i = p.get('if');
  if (d) {
    const t = p.get('tab'), sec = p.get('section');
    pendingName = { dev: d, ifn: i ?? '', tab: DEV_TABS.includes(t as DevTab) ? (t as DevTab) : undefined, section: sec === 'traffic' || sec === 'quality' ? sec : undefined };
    if (data) resolvePending();
  }
  void load();
  window.clearInterval(timer);
  timer = window.setInterval(() => { if (!document.hidden && location.hash.startsWith('#/links')) { void load(true); void loadResHist(true); void loadHealth(true); } }, 30_000);
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
  const { dev, ifn, tab, section } = pendingName; pendingName = null;
  const lc = dev.toLowerCase();
  const d = data.devices.find(x => x.name.toLowerCase() === lc || x.ip === dev || String(x.id) === dev) ?? data.devices.find(x => x.name.toLowerCase().includes(lc));
  if (!d) return;
  const itf = ifn ? d.interfaces.find(i => i.name.toLowerCase() === ifn.toLowerCase() || String(i.ifIndex) === ifn) : d.interfaces.find(i => i.flagged) ?? d.interfaces[0];
  if (section) ifTab = section;
  select_(d.id, itf?.ifIndex ?? d.interfaces[0]?.ifIndex ?? 0, tab ?? (ifn ? 'interfaces' : undefined));
}

let prevDev = 0;
function select_(d: number, i: number, tab?: DevTab): void {
  if (d !== devId) ifSearch = '';
  if (d !== prevDev) { devTab = 'overview'; graphZoom = null; resZoom = null; quality = null; }
  if (tab) devTab = tab;
  devId = d; ifIndex = i; series = null; quality = null; streams = []; streamsTotal = 0; seriesError = ''; hostsRes = null; hostsError = ''; readMsg = '';
  if (d !== prevDev) { arpRes = null; arpQ = ''; void loadArp(); nbRes = null; nbError = ''; void loadNeighbors(); wlan = null; wlanError = ''; clientFilter = ''; void loadWlan(); resHists.clear(); ifCpu = null; void loadResHist(); healthRes = null; void loadHealth(); }
  prevDev = d;
  void loadSeries(); void loadStreams(); void loadHosts();
  redraw();
}

let healthRes: HealthRes | null = null; let healthLoading = false;
let hlseq = 0;
async function loadHealth(quiet = false): Promise<void> {
  if (!devId) return;
  const my = ++hlseq, d = devId; if (!quiet) healthLoading = true;
  try {
    const r = await get<HealthRes>('/api/links/health' + qs({ dev: d }));
    if (my === hlseq && d === devId) healthRes = r;
  } catch { if (my === hlseq && !quiet) healthRes = null; }
  if (my === hlseq) { healthLoading = false; redraw(); }
}

let rseq = 0;
/** Reads the history of the device and of each of its access points for the chosen range. */
async function loadResHist(quiet = false): Promise<void> {
  if (!devId) return;
  const my = ++rseq, d = devId; if (!quiet) { resHistLoading = true; resHistError = ''; redraw(); }
  const keys = ['', ...(wlan?.aps ?? []).map(a => a.mac.toLowerCase())];
  await Promise.all(keys.map(async k => {
    try {
      const r = await get<ResHist>('/api/links/resources' + qs({ dev: d, ...windowOf(resRange, resZoom), points: 120, ap: k }));
      if (my === rseq && d === devId) { resHists.set(k, r); if (k === '') resHistError = ''; }
    } catch (e) { if (my === rseq && !quiet && k === '') { resHists.delete(k); resHistError = (e as Error).message; } }
  }));
  if (my === rseq) { resHistLoading = false; redraw(); }
}

/** The device's CPU over the same stretch as the interface graphs, to set against its drops and discards. */
let ifCpu: ResHist | null = null;
let sseq = 0;
const windowOf = (range: string, z: Zoom | null) => (z ? { from: z.from, to: z.to } : { range });
async function loadSeries(): Promise<void> {
  if (!devId || !ifIndex) return;
  const my = ++sseq; seriesLoading = true; seriesError = ''; redraw();
  void loadQuality(my); void loadIfCpu(my);
  try {
    const r = await get<SeriesRes>('/api/links/series' + qs({ dev: devId, if: ifIndex, ...windowOf(graphRange, graphZoom), points: 120 }));
    if (my !== sseq) return;
    series = r;
  } catch (e) { if (my === sseq) { series = null; seriesError = (e as Error).message; } }
  if (my === sseq) { seriesLoading = false; redraw(); }
}
async function loadIfCpu(my: number): Promise<void> {
  const d = devId;
  try {
    const r = await get<ResHist>('/api/links/resources' + qs({ dev: d, ...windowOf(graphRange, graphZoom), points: 120, ap: '' }));
    if (my === sseq && d === devId) { ifCpu = r; redraw(); }
  } catch { if (my === sseq) { ifCpu = null; redraw(); } }
}
const CPU_HIGH = 80;
/** The CPU graph and a sentence on whether it lines up with the drops and discards shown, for the interface graphs. */
function cpuMatch(moments: { kind: string; ts: number[] }[], from: number, to: number, fmtT: (t: number) => string): { chart: { key: string; build: (size: { w: number; h: number }) => VNode } | null; note: VNode | null } {
  const pts = ifCpu?.points ?? [];
  const cpu = pts.filter(p => p.cpu !== null).map(p => ({ t: p.ts, v: p.cpu as number }));
  if (!cpu.length) return { chart: null, note: null };
  const peaks = (ifCpu?.step ?? 0) >= 180_000;
  const reach = Math.max(ifCpu?.step ?? 60_000, 90_000);
  const peak = pts.filter(p => p.cpuMax !== null).map(p => ({ t: p.ts, v: p.cpuMax as number }));
  const chart = { key: 'cpu', build: (size: { w: number; h: number }) => lineChart({ ...size, sync: 'iface', onZoom: zoomIf, title: 'Device CPU (for comparison)', unit: v => Math.round(v) + '%', yMax: 100, series: [...(peaks && peak.length ? [{ name: 'Peak', color: 'var(--s5)', points: peak }] : []), { name: 'CPU', color: 'var(--s1)', points: cpu }], from, to, fmtT, fmtV: v => pct(v, 1), aria: 'CPU of the device, to compare with drops and discards' }) };
  const lines = moments.filter(m => m.ts.length).map(m => {
    const v = verdict(correlate(m.ts, pts, CPU_HIGH, reach), CPU_HIGH);
    return h('div', { key: m.kind, class: 'row', style: 'gap:8px;align-items:flex-start;flex-wrap:nowrap' }, chip(m.kind, v.level === 'warn' ? 'warn' : v.level === 'ok' ? 'ok' : 'info'), h('span', { style: 'font-size:12.5px' }, v.text));
  });
  const note_ = h('div', { class: 'col', style: 'gap:6px' }, h('b', { style: 'font-size:13px' }, 'Does the CPU explain them?'),
    lines.length ? lines : h('span', { class: 'muted', style: 'font-size:12.5px' }, 'No drops or discards in this range, so there is nothing to compare.'),
    h('span', { class: 'dim', style: 'font-size:11.5px' }, `Compared with the device CPU at the same moments (${CPU_HIGH}% counts as high). The CPU graph below shares the crosshair with the others.`));
  return { chart, note: note_ };
}

/** Counter history (errors, discards, broadcast, multicast) of the selected interface, for the same window as the other graphs. */
async function loadQuality(my: number): Promise<void> {
  const d = devId, i = ifIndex; qualityLoading = true;
  try {
    const r = await get<QualityRes>('/api/links/quality' + qs({ dev: d, if: i, ...windowOf(graphRange, graphZoom), points: 120 }));
    if (my === sseq && d === devId && i === ifIndex) quality = r;
  } catch { if (my === sseq) quality = null; }
  if (my === sseq) { qualityLoading = false; redraw(); }
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

let aseq = 0;
async function loadArp(): Promise<void> {
  if (!devId) return;
  const my = ++aseq, d = devId;
  try { const r = await get<{ rows: ArpRow[]; readAt: number | null }>('/api/links/arp' + qs({ dev: d })); if (my === aseq && d === devId) arpRes = r; } catch { if (my === aseq) arpRes = null; }
  if (my === aseq) redraw();
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
  try {
    const r = await get<WlanRes>('/api/links/wlan' + qs({ dev: d.id }));
    if (my === wseq) { wlan = r; if (r.aps.some(a => !resHists.has(a.mac.toLowerCase()))) void loadResHist(true); }
  }
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
    await load(true); await loadHosts(); await loadNeighbors(); await loadArp(); await loadWlan(true);
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
      attn.length ? h('div', { class: 'cards' }, attn.slice(0, 8).map(a => h('button', { key: a.dev.id + '/' + a.itf.ifIndex, type: 'button', class: 'cardbtn', 'aria-pressed': a.dev.id === devId && a.itf.ifIndex === ifIndex, onclick: () => select_(a.dev.id, a.itf.ifIndex, 'interfaces') },
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
  return `${i.name} ${i.alias} ${vtext} ${i.portMode} ${i.policy ?? ''} ${i.policyIn ?? ''} ${nb} ${(i.addresses ?? []).join(' ')} ${publicAddresses(i.addresses).length ? 'public' : ''}`.toLowerCase().includes(t);
}
function filterIfaces(list: Iface[]): Iface[] {
  const terms = ifSearch.trim().split(/\s+/).filter(Boolean);
  return terms.length ? list.filter(i => terms.every(t => termMatches(i, t))) : list;
}

function policyCell(i: Iface): VNode {
  if (!i.policy && !i.policyIn) return h('span', { class: 'muted', style: 'font-size:12px' }, '—');
  return h('span', { class: 'col', style: 'gap:1px;font-size:12px' }, i.policy ? h('span', { class: 'muted', title: 'Policy applied to traffic leaving the port' }, 'out ', h('b', null, i.policy)) : null, i.policyIn ? h('span', { class: 'muted', title: 'Policy applied to traffic entering the port' }, 'in ', h('b', null, i.policyIn)) : null);
}

/** The IP addresses of a routed port or an SVI. A public one carries a quiet "public" tag: informational only, since edge routers and firewalls are meant to have one. */
function ipCell(i: Iface): VNode {
  if (!i.addresses?.length) return h('span', { class: 'dim' }, '—');
  const pub = new Set(publicAddresses(i.addresses));
  return h('span', { class: 'col', style: 'gap:2px' }, i.addresses.map(a => h('span', { key: a, class: 'row', style: 'gap:6px;flex-wrap:nowrap' },
    h('span', { class: 'mono', style: 'font-size:12px;white-space:nowrap' }, a),
    pub.has(a) ? h('span', { class: 'tag', style: 'padding:1px 6px;font-size:11px', title: 'A public (internet-routable) address. For information only.' }, 'public') : null)));
}

function ifTable(dev: Dev): VNode {
  const optics = opticMap(healthRes?.health?.sensors ?? []);
  const light = hasOptics(healthRes);
  const cols = 'minmax(88px,0.8fr) minmax(120px,1fr) minmax(200px,1fr) minmax(130px,1fr) minmax(140px,1.1fr) 52px 58px ' + (light ? '112px ' : '') + '118px 118px 64px minmax(84px,0.8fr) 70px';
  const nbOf = (ix: number): Neighbor[] => nbRes?.ports.find(p => p.ifIndex === ix)?.neighbors ?? [];
  const rows = filterIfaces(dev.interfaces);
  return h('div', { class: 'col', style: 'gap:8px' },
    h('div', { class: 'row', style: 'gap:10px' },
      h('div', { style: 'flex:1 1 320px;max-width:460px' }, textInput(ifSearch, v => { ifSearch = v; }, { placeholder: 'Search interface, description, neighbour, VLAN or address', aria: 'Search interfaces', width: '100%' })),
      ifSearch.trim() ? btn('Clear', { kind: 'ghost', small: true, onclick: () => { ifSearch = ''; redraw(); } }) : null,
      h('span', { class: 'muted', role: 'status', 'aria-live': 'polite' }, ifSearch.trim() ? `${rows.length} of ${dev.interfaces.length} interfaces` : `${dev.interfaces.length} interfaces`),
      h('span', { class: 'dim', style: 'font-size:12px' }, 'Words must all match. A number is a VLAN id; vlan:20 matches only VLANs. "public" finds interfaces with a public IP address.')),
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${cols};--w:${light ? 1545 : 1430}px` },
      h('div', { class: 'tr head' }, ...['Interface', 'Description', 'IP address', 'Neighbour (CDP/LLDP)', 'VLAN', 'Speed', 'State', ...(light ? [h('span', { title: 'Optic light levels in dBm: receive / transmit' }, 'Light Rx / Tx')] : []), 'In', 'Out', 'Discards', 'Service policy', 'Flows'].map(t => (typeof t === 'string' ? h('span', null, t) : t))),
      h('div', { class: 'scroll' }, rows.map(i => h('div', { key: i.ifIndex, class: 'tr pick', 'aria-current': i.ifIndex === ifIndex ? 'true' : undefined, onclick: () => select_(dev.id, i.ifIndex, 'interfaces') },
        h('span', { style: 'font-weight:600' }, h('button', { type: 'button', class: 'rowbtn', 'aria-pressed': i.ifIndex === ifIndex, title: `Show ${i.name}`, onclick: (e: Event) => { e.stopPropagation(); select_(dev.id, i.ifIndex, 'interfaces'); } }, i.name), i.flagged ? h('span', { style: 'color:var(--warn);margin-left:6px', title: 'Needs attention' }, '●') : null),
        h('span', { class: 'muted' }, i.alias || '—'),
        ipCell(i),
        nbCell(nbOf(i.ifIndex)),
        vlanCell(i),
        h('span', { class: 'mono', style: 'font-size:12px' }, i.speedMbps ? (i.speedMbps >= 1000 ? i.speedMbps / 1000 + ' G' : i.speedMbps + ' M') : '—'),
        h('span', null, i.oper === 'up' ? statusEl('ok', 'up') : statusEl(i.oper === 'down' ? 'bad' : 'off', i.oper)),
        light ? opticCell(optics.get(i.ifIndex)) : null,
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
        ? h('button', { type: 'button', class: 'lnk', style: 'font-weight:500', title: `Open ${n.device.name}${n.devicePort ? ' at ' + n.devicePort.name : ''} in Network health`, onclick: (e: Event) => { e.stopPropagation(); openPort(n.device!.name, n.devicePort?.name); } }, label)
        : h('span', { style: 'font-weight:500' }, label),
      n.port ? h('span', { class: 'dim mono', style: 'font-size:11.5px' }, ' ' + n.port) : null);
  }));
}

/** Every CDP / LLDP neighbour of the device by port; a neighbour that is a polled device opens in this page. */
/** The device's ARP / neighbour cache: which MAC address each IP address was seen at, and on which interface. Shown for routers and firewalls, and for any device that has entries. */
function arpPanel(dev: Dev): VNode | null {
  const rows = arpRes?.rows ?? [];
  if (!rows.length && dev.role !== 'router' && dev.role !== 'firewall') return null;
  const q = arpQ.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const shown = rows.filter(r => !q.length || q.every(t => `${r.ip} ${r.mac} ${r.ifName}`.toLowerCase().includes(t)));
  const cols = 'minmax(150px,1.2fr) 150px minmax(110px,1fr) 110px';
  return h('div', { class: 'col', style: 'gap:8px' },
    h('div', { class: 'row', style: 'justify-content:space-between' },
      h('div', { class: 'col', style: 'gap:2px' }, h('b', null, 'ARP and neighbour cache'),
        h('span', { class: 'muted', style: 'font-size:12px' }, rows.length ? `${num(rows.length)} entries from ${dev.name}, last read ${arpRes?.readAt ? ago(arpRes.readAt) : 'not yet'} with the host tables (IP-MIB ipNetToPhysicalTable, or ipNetToMediaTable on older agents).`
          : `${dev.name} has not returned any ARP entries. Use "Read tables now", or "Check what this device publishes" on the SNMP devices tab to see whether it publishes IP-MIB.`)),
      rows.length > 8 ? textInput(arpQ, v => { arpQ = v; redraw(); }, { placeholder: 'Search address, MAC or interface', aria: 'Search the ARP cache', width: '260px' }) : null),
    rows.length ? h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${cols};--w:560px` },
      h('div', { class: 'tr head' }, ...['IP address', 'MAC address', 'Interface', 'Last seen'].map(t => h('span', null, t))),
      h('div', { class: 'scroll', style: 'max-height:360px' }, shown.map(r => h('div', { key: r.ip + r.mac + r.ifIndex, class: 'tr' },
        h('span', { class: 'mono', style: 'font-size:12px' }, r.ip), h('span', { class: 'mono', style: 'font-size:12px' }, r.mac),
        r.ifName ? h('button', { type: 'button', class: 'lnk', style: 'text-align:left', onclick: () => select_(dev.id, r.ifIndex, 'interfaces') }, r.ifName) : h('span', { class: 'dim' }, '—'),
        h('span', { class: 'muted' }, ago(r.lastSeen))))),
      !shown.length ? empty('No entry matches that search.') : null)) : null);
}

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
        k === 0 ? h('button', { type: 'button', class: 'lnk', title: `Show ${p.ifName}`, onclick: () => select_(dev.id, p.ifIndex, 'interfaces') }, p.ifName) : h('span', null),
        h('span', null, n.device
          ? h('button', { type: 'button', class: 'lnk', title: `Open ${n.device.name}${n.devicePort ? ' at ' + n.devicePort.name : ''} in Network health`, onclick: () => openPort(n.device!.name, n.devicePort?.name) }, n.name || n.device.name)
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
      h('span', { class: 't' }, a.name || a.mac), h('span', { class: 's' }, [a.model ? 'model ' + a.model : null, a.role || null, a.ip || null].filter(Boolean).join(' · ') || null),
      a.uptimeSec > 0 ? h('span', { class: 's' }, `up ${dur(a.uptimeSec * 1000)} · CPU and memory are on the Overview tab`) : null))) : null,
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
        itf ? h('button', { type: 'button', class: 'lnk', title: 'Show this interface: utilisation, discards and graphs', onclick: () => select_(dev.id, itf.ifIndex, 'interfaces') }, itf.name) : h('span', { class: 'dim' }, '—')); }))) : null,
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
      h('button', { type: 'button', class: 'cardbtn', onclick: () => select_(a.devId, a.ifIndex, 'interfaces') },
        h('span', { class: 't' }, `${a.dev} · ${a.ifName}`),
        h('span', { class: 's' }, [a.vlan ? `VLAN ${a.vlan}` : null, `${a.macCount} address${a.macCount === 1 ? '' : 'es'} on the port`, a.confidence ? `${a.confidence} confidence` : null].filter(Boolean).join(' · '))),
      h('div', { class: 'row' }, flowsBtn(a)))),
    q ? h('div', { class: 'row' }, btn(f.ip ? 'Flows with this IP in Flow explorer' : 'Flows with this MAC in Flow explorer', { small: true, kind: 'ghost', onclick: () => go('explorer', { q, range: '1h' }) })) : null,
    f.macs.length ? h('span', { class: 'muted', style: 'font-size:12px' }, 'MAC ', h('span', { class: 'mono' }, f.macs.join(', ')), f.ip ? ` · IP ${f.ip}` : '') : null,
    f.note ? h('span', { class: 'muted', style: 'font-size:12px' }, f.note) : null,
    rest.length ? h('details', null, h('summary', { class: 'muted' }, `Also seen on ${rest.length} other port${rest.length === 1 ? '' : 's'}`),
      h('div', { class: 'col', style: 'gap:4px;padding-top:4px' }, rest.map(o => h('div', { key: o.devId + '/' + o.ifIndex, class: 'row', style: 'gap:8px;font-size:12px' },
        h('button', { type: 'button', class: 'lnk', title: `Show ${o.ifName}`, onclick: () => select_(o.devId, o.ifIndex, 'interfaces') }, `${o.dev} · ${o.ifName}`),
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

/** The time the interface graphs show: the stretch the user zoomed to, or the chosen range ending now. */
function graphWindow(): { from: number; to: number; spanMs: number } {
  const to = graphZoom ? graphZoom.to : Date.now();
  const from = graphZoom ? graphZoom.from : to - (rangeMs(graphRange) ?? 6 * 3600e3);
  return { from, to, spanMs: to - from };
}
/** Axis labels: with seconds on a short stretch, with the day on a long one. */
const axisTime = (spanMs: number) => (t: number): string => (spanMs > 86400e3 ? dayClock(t) : clock(t, spanMs < 20 * 60e3));
const zoomIf = (from: number, to: number): void => { graphZoom = { from, to }; void loadSeries(); };
const zoomRes = (from: number, to: number): void => { resZoom = { from, to }; void loadResHist(); };
/** Tells how to zoom, or shows what the graphs are zoomed to and a button to go back. */
function zoomBar(z: Zoom | null, reset: () => void): VNode {
  return z ? h('span', { class: 'row', style: 'gap:8px;flex-wrap:nowrap' }, chip(`Zoomed to ${dayClock(z.from)} – ${dayClock(z.to)} (${dur(z.to - z.from)})`, 'accent', 'Showing only the stretch you dragged across'), btn('Show the full range', { small: true, kind: 'ghost', onclick: reset }))
    : h('span', { class: 'dim', style: 'font-size:12px' }, 'Drag across a graph to zoom in on that time.');
}
/** The time range picker and zoom state shared by the interface graphs. */
function graphControls(): VNode {
  return h('span', { class: 'row', style: 'gap:10px' }, rangePicker('links-graphs', graphRange, GRAPH_RANGES, v => { graphRange = v; graphZoom = null; void loadSeries(); }, { aria: 'Graph time range' }),
    zoomBar(graphZoom, () => { graphZoom = null; void loadSeries(); }));
}

/** Errors, discards, broadcast and multicast of the selected interface over time. Each counter's growth per second, read every few minutes. */
function qualityGraphs(itf: Iface): VNode {
  const { from, to, spanMs } = graphWindow();
  const fmtT = axisTime(spanMs);
  const pts = quality?.points ?? [];
  const ser = (name: string, color: string, key: string): Series[] => {
    const v = pts.filter(p => p[key] !== undefined).map(p => ({ t: p.ts, v: p[key] as number }));
    return v.length ? [{ name, color, points: v }] : [];
  };
  const axis = (v: number) => (v === 0 ? '0' : v >= 100 ? num(v) + '/s' : v >= 10 ? v.toFixed(0) + '/s' : v >= 1 ? v.toFixed(1) + '/s' : v.toFixed(2) + '/s');
  const exact = (v: number) => (v < 0.1 ? v.toFixed(3) : v < 10 ? v.toFixed(2) : num(v)) + '/s';
  const make = (key: string, title: string, series: Series[], aria: string): { key: string; build: (size: { w: number; h: number }) => VNode } | null => {
    if (!series.length) return null;
    const top = Math.max(0.1, ...series.flatMap(x => x.points.map(p => p.v)));
    return { key, build: size => lineChart({ ...size, sync: 'iface', onZoom: zoomIf, title, unit: axis, fmtV: exact, yMax: niceCeil(top), series, from, to, fmtT, aria }) };
  };
  const inOut = (a: string, b: string): Series[] => [...ser('In', 'var(--s3)', a), ...ser('Out', 'var(--s1)', b)];
  const kinds: [string, string, string][] = [['fcs', 'CRC errors', 'var(--s1)'], ['align', 'Alignment errors', 'var(--s2)'], ['symbol', 'Symbol errors', 'var(--s3)'], ['late', 'Late collisions', 'var(--s4)'], ['excessive', 'Excessive collisions', 'var(--s5)'], ['collisions', 'Collisions', 'var(--s6)'], ['carrier', 'Carrier sense errors', 'var(--s7)'], ['tooLong', 'Frames too long', 'var(--s8)']];
  const charts = [
    make('err', 'Errors (per second)', inOut('inErr', 'outErr'), `Errors on ${itf.name}`),
    make('disc', 'Discards (per second)', inOut('inDisc', 'outDisc'), `Discards on ${itf.name}`),
    make('qd', 'Queue drops (per second)', inOut('inQDrops', 'outQDrops'), `Queue drops on ${itf.name}`),
    make('guard', 'Storm control and port security (per second)', [...ser('Storm control', 'var(--s4)', 'storm'), ...ser('Port security', 'var(--s2)', 'portSec')], `Storm control and port security on ${itf.name}`),
    make('bc', 'Broadcast (packets per second)', inOut('inBc', 'outBc'), `Broadcast packets on ${itf.name}`),
    make('mc', 'Multicast (packets per second)', inOut('inMc', 'outMc'), `Multicast packets on ${itf.name}`),
    make('types', 'Error types (per second)', kinds.flatMap(([k, n, c]) => ser(n, c, k)), `Error types on ${itf.name}`)
  ].filter((c): c is NonNullable<typeof c> => c !== null);
  const hit = (...k: string[]): number[] => pts.filter(p => k.some(x => (p[x] ?? 0) > 0)).map(p => p.ts);
  const match = cpuMatch([{ kind: 'Discards', ts: hit('inDisc', 'outDisc') }, { kind: 'Errors', ts: hit('inErr', 'outErr') }, { kind: 'Queue drops', ts: hit('inQDrops', 'outQDrops') }], from, to, fmtT);
  if (match.chart && charts.length) charts.push(match.chart);
  return h('div', { class: 'col', style: 'gap:12px' },
    h('div', { class: 'row end' }, graphControls(), quality?.tier === 'h1' ? chip('hourly averages', 'info', 'The range is older than the per-read samples kept, so hourly summaries are shown') : null),
    qualityLoading && !quality ? spinner('Loading the counter history…') : null,
    charts.length ? match.note : null,
    charts.length ? chartGrid(charts.length, size => charts.map(c => c.build(size))) : !qualityLoading ? h('span', { class: 'dim', style: 'font-size:12px' }, 'No counter history for this range yet. The counters are read every few minutes, and the graphs fill in as the device answers.') : null,
    charts.length ? h('div', { class: 'legendrow' }, h('span', null, h('i', { class: 'sw', style: 'background:var(--s3)' }), 'In'), h('span', null, h('i', { class: 'sw', style: 'background:var(--s1)' }), 'Out'), h('span', null, 'Counters are read every few minutes, so a short burst shows as its average over the read.')) : null);
}

function graphs(s: SeriesRes, itf: Iface): VNode {
  const names = s.classes.map(c => c.cls);
  const { from, to, spanMs } = graphWindow();
  const shown = s.classes.filter(c => !hidden.has(c.cls));
  const evs = events(s, names);
  const bands = evs.map(e => ({ a: e.a - s.step / 2, b: e.b + s.step / 2 }));
  const fmtT = axisTime(spanMs);
  const mk = (pick: (p: SeriesRes['classes'][0]['points'][0]) => number): Series[] => shown.map(c => ({ name: c.cls, color: classColor(c.cls, names), points: c.points.map(p => ({ t: p.ts, v: pick(p) })) }));
  const peak = (c: SeriesRes['classes'][0]) => Math.max(0, ...c.points.map(p => p.dropPct));
  const dropTs = [...new Set(s.classes.flatMap(c => c.points.filter(p => p.dropPps > 0 || p.dropPct > 0).map(p => p.ts)))];
  const match = cpuMatch([{ kind: 'Queue drops', ts: dropTs }, { kind: 'Discards', ts: s.util.points.filter(p => p.disc > 0).map(p => p.ts) }], from, to, fmtT);
  return h('div', { class: 'col', style: 'gap:14px' },
    h('div', { class: 'row end' },
      graphControls(),
      h('label', { class: 'row', style: 'gap:8px' }, h('span', { class: 'muted' }, 'Mark drops above'), select(String(dropThr), THRESHOLDS, v => { dropThr = Number(v); redraw(); }, { aria: 'Drop threshold', width: '96px' })),
      s.tier === 'h1' ? chip('hourly averages', 'info', 'The range is older than the per-poll samples kept, so hourly summaries are shown') : null),
    names.length ? h('div', { role: 'group', 'aria-label': 'Classes shown', class: 'row', style: 'gap:8px' },
      s.classes.map(c => h('button', { key: c.cls, type: 'button', class: 'cbtn', 'aria-pressed': !hidden.has(c.cls), onclick: () => { if (hidden.has(c.cls)) hidden.delete(c.cls); else hidden.add(c.cls); redraw(); } },
        h('i', { class: 'sw', style: `background:${classColor(c.cls, names)};margin:0` }), h('span', null, c.cls), h('span', { class: 'dim' }, 'peak ' + pct(peak(c), 2))))) : null,
    match.note,
    chartGrid((names.length ? 4 : 2) + (match.chart ? 1 : 0), size => [
      names.length ? lineChart({ ...size, sync: 'iface', onZoom: zoomIf, title: 'Packets dropped (% of the class)', unit: v => (v < 10 ? v.toFixed(1) : v.toFixed(0)) + '%', series: mk(p => p.dropPct), from, to, threshold: dropThr, bands, fmtT, fmtV: v => pct(v, 2), aria: `Drop percentage per class on ${itf.name}` }) : null,
      names.length ? lineChart({ ...size, sync: 'iface', onZoom: zoomIf, title: 'Bytes dropped (per second)', unit: v => bytes(v) + '/s', series: mk(p => p.dropBps / 8), from, to, bands, fmtT, aria: `Bytes dropped per class on ${itf.name}` }) : null,
      lineChart({
        ...size, sync: 'iface', onZoom: zoomIf, title: 'Utilisation (% of line speed)', unit: v => v.toFixed(0) + '%', yMax: Math.max(100, ...s.util.points.map(p => Math.max(p.utilIn, p.utilOut))), threshold: data?.thresholds.util, from, to, fmtT, fmtV: v => pct(v, 1),
        series: [{ name: 'In', color: 'var(--s3)', points: s.util.points.map(p => ({ t: p.ts, v: p.utilIn })) }, { name: 'Out', color: 'var(--s1)', points: s.util.points.map(p => ({ t: p.ts, v: p.utilOut })) }], aria: `Utilisation of ${itf.name}`
      }),
      lineChart({
        ...size, sync: 'iface', onZoom: zoomIf, title: 'Throughput (bits per second)', unit: bpsAxis, fmtV: bps, yMax: niceCeil(Math.max(1000, ...s.util.points.map(p => Math.max(p.inBps, p.outBps)))), from, to, fmtT,
        series: [{ name: 'In', color: 'var(--s3)', points: s.util.points.map(p => ({ t: p.ts, v: p.inBps })) }, { name: 'Out', color: 'var(--s1)', points: s.util.points.map(p => ({ t: p.ts, v: p.outBps })) }], aria: `Throughput of ${itf.name} in bits per second`
      }),
      match.chart ? match.chart.build(size) : null
    ]),
    h('div', { class: 'legendrow' }, h('span', null, h('i', { class: 'sw', style: 'background:var(--s3)' }), 'In'), h('span', null, h('i', { class: 'sw', style: 'background:var(--s1)' }), 'Out'), h('span', null, 'Shaded bands mark periods when a shown class was above the threshold, on every graph. Percentages and bytes come from the same SNMP counter deltas at each poll.')),
    h('div', { class: 'col', style: 'gap:6px' },
      h('b', null, 'Drop events above the threshold'),
      evs.length ? h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:150px 210px 90px 110px 1fr;--w:760px' }, evs.slice(0, 30).map((e, i) => h('div', { key: i, class: 'tr' },
        h('span', null, h('i', { class: 'sw', style: `background:${classColor(e.cls, names)}` }), e.cls),
        h('span', { class: 'mono', style: 'font-size:12px' }, `${dayClock(e.a)} → ${clock(e.b + s.step)}`), h('span', { class: 'muted' }, dur(e.b - e.a + s.step)),
        h('span', { class: 'mono', style: 'font-size:12px;color:var(--bad)' }, 'peak ' + pct(e.peak, 2)), h('span', { class: 'muted' }, `about ${num(e.pkts)} packets dropped`)))))
        : h('span', { class: 'dim' }, names.length ? 'No shown class went above the threshold in this window.' : 'There are no queue classes on this interface.')));
}

/** The tiles for uptime, CPU, memory and disks, the same for switches, routers, firewalls and access points. */
function resourceTileList(r: Resources, hist?: ResHist | null): VNode[] {
  const trend = (pick: (p: ResPoint) => number | null, label: string, max?: number): VNode | null => (hist ? spark(hist.points.map(pick).filter((v): v is number => v !== null), { max, label }) : null);
  const tiles: VNode[] = [];
  if (r.uptimeSec !== null) tiles.push(stat('Uptime', dur(r.uptimeSec * 1000)));
  if (r.cpuPct !== null) tiles.push(stat('CPU', h('span', { style: sevStyle(r.cpuPct) }, `${Math.round(r.cpuPct)}%`), [h('span', null, [r.cores ? `${r.cores} cores` : null, r.load ? `load ${r.load.map(x => x.toFixed(2)).join(' / ')}` : null].filter(Boolean).join(' · ')), trend(p => p.cpu, 'CPU over the chosen range', 100)]));
  else if (r.load) tiles.push(stat('Load average', r.load.map(x => x.toFixed(2)).join(' / '), '1, 5 and 15 minutes'));
  if (r.memPct !== null) tiles.push(stat('Memory', h('span', { style: sevStyle(r.memPct) }, `${Math.round(r.memPct)}%`), [h('span', null, r.memTotal !== null && r.memUsed !== null ? `${bytes(r.memUsed)} of ${bytes(r.memTotal)}${r.swapPct !== null ? ` · swap ${Math.round(r.swapPct)}%` : ''}` : ''), trend(p => p.mem, 'Memory over the chosen range', 100)]));
  if (r.tempC !== null && r.tempC !== undefined) tiles.push(stat('Temperature', h('span', { style: sevStyle(r.tempC, 65, 80) }, `${Math.round(r.tempC)} °C`), [h('span', null, 'hottest sensor'), trend(p => p.temp, 'Temperature over the chosen range', undefined)]));
  if (r.sessions !== null && r.sessions !== undefined) tiles.push(stat('Sessions', h('span', { style: r.sessionsMax ? sevStyle((r.sessions / r.sessionsMax) * 100) : undefined }, num(r.sessions)), [h('span', null, r.sessionsMax ? `${Math.round((r.sessions / r.sessionsMax) * 100)}% of ${num(r.sessionsMax)}` : 'in use now'), trend(p => p.sess, 'Sessions over the chosen range', undefined)]));
  for (const d of r.disks) tiles.push(stat(`Disk ${d.name}`, h('span', { style: sevStyle(d.usedPct, 80, 95) }, `${d.usedPct < 10 ? d.usedPct.toFixed(1) : Math.round(d.usedPct)}%`), `${bytes(d.usedBytes)} of ${bytes(d.totalBytes)}`));
  return tiles;
}
/** An access point's own readings in the same shape as any other device's. Memory used is total minus free. */
function apResources(a: WlanAp, readAt: number): Resources {
  const mem = a.memTotal > 0 ? Math.max(0, a.memTotal - a.memFree) : null;
  return { uptimeSec: a.uptimeSec > 0 ? a.uptimeSec : null, cpuPct: known(a.cpuPct) ? a.cpuPct : null, cores: null, load: null,
    memPct: mem !== null ? Math.round(mem / a.memTotal * 1000) / 10 : null, memTotal: mem !== null ? a.memTotal : null, memUsed: mem, swapPct: null, disks: [], source: "the access point's own tables", readAt };
}

const sevStyle = (p: number | null, warn = 75, bad = 90): string | undefined => (p === null ? undefined : p >= bad ? 'color:var(--bad)' : p >= warn ? 'color:var(--warn)' : undefined);
interface ResSubject { key: string; title: string | null; name: string; r: Resources }

/**
 * Whose resources the Overview shows: the device itself, and each access point it answers for. A device that is a single access point with no readings of
 * its own is shown as that access point, and one whose only access point is itself is not repeated.
 */
function resourceSubjects(dev: Dev): ResSubject[] {
  const out: ResSubject[] = [];
  if (dev.resources) out.push({ key: '', title: null, name: dev.name, r: dev.resources });
  const aps = wlan?.aps ?? [];
  if (dev.hasWlan && (aps.length > 1 || !dev.resources)) for (const a of aps) out.push({ key: a.mac.toLowerCase(), title: a.name || a.mac, name: a.name || a.mac, r: apResources(a, wlan?.readAt ?? 0) });
  if (out.length > 1) out[0].title = dev.name;
  return out;
}

/** Uptime, CPU, memory and disk with their history, for every kind of device: switches, routers, firewalls and access points alike. */
/** The resource tiles of the device (and of each access point). The graphs of their history are only with them on the Hardware tab. */
function resourcesPanel(dev: Dev, history = false): VNode | null {
  const subs = resourceSubjects(dev).filter(x => resourceTileList(x.r).length);
  if (!subs.length) return dev.lastOk === null && !dev.hasWlan ? null : h('span', { class: 'dim', style: 'font-size:12px' }, 'This device does not publish uptime, CPU or memory through HOST-RESOURCES-MIB, UCD-SNMP-MIB, the Cisco process and memory MIBs or a vendor MIB FlowScope reads.');
  return h('div', { class: 'col', style: 'gap:18px' }, subs.map((x, i) => {
    const r = x.r;
    return h('div', { key: x.key || 'device', class: 'col', style: 'gap:10px' },
      x.title ? h('b', null, x.title) : null,
      h('div', { class: 'row', style: 'gap:10px;align-items:stretch' }, resourceTileList(r, resHists.get(x.key))),
      h('span', { class: 'dim', style: 'font-size:11.5px' }, `Read ${r.readAt ? ago(r.readAt) : 'recently'}${r.source ? ' from ' + r.source : ''}. Memory leaves out the file cache where the device reports it.`),
      history ? resHistoryPanel(x, i === 0) : null);
  }));
}

/** CPU, memory, disk and load over time for the selected device, with its restarts marked. The graphs follow each other's hover like the interface graphs do. */
function resHistoryPanel(sub: ResSubject, first: boolean): VNode {
  const hist = resHists.get(sub.key);
  const grp = 'res:' + (sub.key || 'device');
  const to = resZoom ? resZoom.to : Date.now(), from = resZoom ? resZoom.from : to - (rangeMs(resRange) ?? 6 * 3600e3), spanMs = to - from;
  const fmtT = axisTime(spanMs);
  const head = h('div', { class: 'row', style: 'justify-content:space-between' },
    h('div', { class: 'col', style: 'gap:2px' }, h('b', null, sub.title && !first ? `${sub.title} history` : 'Resource history'),
      h('span', { class: 'muted', style: 'font-size:12px' }, 'CPU, memory, disk and load as the device reported them. Point at a graph to read every graph at that moment.')),
    first ? h('div', { class: 'row' },
      resOpen ? h('span', { class: 'row', style: 'gap:10px' }, rangePicker('res-hist', resRange, RES_RANGES, v => { resRange = v; resZoom = null; void loadResHist(); }, { aria: 'Resource history time range' }), zoomBar(resZoom, () => { resZoom = null; void loadResHist(); })) : null,
      btn(resOpen ? 'Hide' : 'Show history', { small: true, kind: 'ghost', pressed: resOpen, aria: resOpen ? 'Hide resource history' : 'Show resource history', onclick: () => { resOpen = !resOpen; redraw(); } })) : null);
  if (!resOpen) return h('div', { class: 'col', style: 'gap:8px' }, head);
  if (resHistLoading && !hist) return h('div', { class: 'col', style: 'gap:8px' }, head, spinner('Loading the history…'));
  if (resHistError && !hist) return h('div', { class: 'col', style: 'gap:8px' }, head, note(resHistError, 'bad', true));
  if (!hist || !hist.points.length) return h('div', { class: 'col', style: 'gap:8px' }, head, h('span', { class: 'dim', style: 'font-size:12px' }, 'No readings are stored for this range yet. They are taken about once a minute while the device answers.'));
  const col = (k: keyof ResPoint) => hist.points.filter(p => p[k] !== null).map(p => ({ t: p.ts, v: p[k] as number }));
  // with one-minute readings the peak of a bucket is the reading itself; the peak line only helps once readings are averaged together
  const peaks = hist.step >= 180_000;
  const mk = (name: string, color: string, k: keyof ResPoint): Series[] => (col(k).length ? [{ name, color, points: col(k) }] : []);
  const bands = hist.restarts.map(t => ({ a: t - 30_000, b: t + 30_000 }));
  const pctV = (v: number) => pct(v, 1);
  const charts: { key: string; build: (size: { w: number; h: number }) => VNode }[] = [];
  if (col('cpu').length) charts.push({ key: 'cpu', build: size => lineChart({ ...size, sync: grp, onZoom: zoomRes, title: 'CPU', unit: v => Math.round(v) + '%', yMax: 100, series: [...(peaks ? mk('Peak', 'var(--s5)', 'cpuMax') : []), ...mk(peaks ? 'Average' : 'CPU', 'var(--s1)', 'cpu')], from, to, bands, fmtT, fmtV: pctV, aria: `CPU of ${sub.name}` }) });
  if (col('mem').length) charts.push({ key: 'mem', build: size => lineChart({ ...size, sync: grp, onZoom: zoomRes, title: 'Memory in use', unit: v => Math.round(v) + '%', yMax: 100, series: [...(peaks ? mk('Peak', 'var(--s5)', 'memMax') : []), ...mk(peaks ? 'Average' : 'Memory', 'var(--s2)', 'mem'), ...mk('Swap', 'var(--s4)', 'swap')], from, to, bands, fmtT, fmtV: pctV, aria: `Memory of ${sub.name}` }) });
  if (col('disk').length) charts.push({ key: 'disk', build: size => lineChart({ ...size, sync: grp, onZoom: zoomRes, title: 'Fullest disk', unit: v => Math.round(v) + '%', yMax: 100, series: mk('Disk', 'var(--s3)', 'disk'), from, to, bands, fmtT, fmtV: pctV, aria: `Disk use of ${sub.name}` }) });
  if (col('load').length) charts.push({ key: 'load', build: size => lineChart({ ...size, sync: grp, onZoom: zoomRes, title: 'Load average (1 minute)', unit: v => v.toFixed(v < 10 ? 1 : 0), series: [...(peaks ? mk('Peak', 'var(--s5)', 'loadMax') : []), ...mk(peaks ? 'Average' : 'Load', 'var(--s6)', 'load')], from, to, bands, fmtT, fmtV: v => v.toFixed(2), aria: `Load of ${sub.name}` }) });
  if (col('temp').length) charts.push({ key: 'temp', build: size => lineChart({ ...size, sync: grp, onZoom: zoomRes, title: 'Temperature (hottest sensor)', unit: v => Math.round(v) + ' °C', series: [...(peaks ? mk('Peak', 'var(--s5)', 'tempMax') : []), ...mk(peaks ? 'Average' : 'Temperature', 'var(--s7)', 'temp')], from, to, bands, fmtT, fmtV: v => `${Math.round(v * 10) / 10} °C`, aria: `Temperature of ${sub.name}` }) });
  if (col('sess').length) charts.push({ key: 'sess', build: size => lineChart({ ...size, sync: grp, onZoom: zoomRes, title: 'Sessions', unit: v => (v >= 1000 ? Math.round(v / 100) / 10 + 'k' : String(Math.round(v))), series: [...(peaks ? mk('Peak', 'var(--s5)', 'sessMax') : []), ...mk(peaks ? 'Average' : 'Sessions', 'var(--s8)', 'sess')], from, to, bands, fmtT, fmtV: v => num(Math.round(v)), aria: `Sessions on ${sub.name}` }) });
  const restartsIn = hist.restarts.filter(t => t >= from);
  return h('div', { class: 'col', style: 'gap:10px' }, head,
    h('div', { class: 'row', style: 'gap:8px' },
      hist.tier === 'h1' ? chip('hourly summaries', 'info', 'The range is older than the per-minute readings kept (three days), so hourly averages and peaks are shown') : null,
      restartsIn.length ? chip(`${restartsIn.length === 1 ? 'Restarted' : restartsIn.length + ' restarts, last'} ${hist.tier === 'h1' ? 'around ' : ''}${dayClock(restartsIn[restartsIn.length - 1])}`, 'warn', 'The uptime went backwards: the device restarted. Restarts are shaded on the graphs.') : null),
    charts.length ? chartGrid(charts.length, size => charts.map(c => c.build(size))) : h('span', { class: 'dim', style: 'font-size:12px' }, 'The stored readings have no CPU, memory or disk values to draw.'));
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

/** The sections of the selected interface. Link quality is listed once something is known about it. */
function ifTabList(dev: Dev, itf: Iface): { id: IfTab; label: string }[] {
  const t: { id: IfTab; label: string }[] = [{ id: 'traffic', label: 'Traffic and queues' }];
  if (healthRes?.ifExtra.some(x => x.ifIndex === itf.ifIndex) || opticMap(healthRes?.health?.sensors ?? []).has(itf.ifIndex)) t.push({ id: 'quality', label: 'Link quality' });
  if (!itf.isVlanIf) t.push({ id: 'hosts', label: 'Hosts and neighbours' });
  void dev;
  return t;
}
const ifTabNow = (dev: Dev, itf: Iface): IfTab => ifTabList(dev, itf).find(t => t.id === ifTab)?.id ?? 'traffic';
function ifTabs(dev: Dev, itf: Iface): VNode {
  const now = ifTabNow(dev, itf);
  return tabs('Interface sections', ifTabList(dev, itf).map(t => ({ id: t.id, label: t.label, on: t.id === now })), id => { ifTab = id as IfTab; redraw(); });
}
function ifBody(dev: Dev, itf: Iface): VNode {
  const tab = ifTabNow(dev, itf);
  const body = tab === 'quality' ? [
      linkQuality(healthRes?.ifExtra.find(x => x.ifIndex === itf.ifIndex), (healthRes?.health?.sensors ?? []).filter(x => x.kind === 'optic' && x.ifIndex === itf.ifIndex), itf.speedMbps),
      qualityGraphs(itf)]
    : tab === 'hosts' ? [hostsPanel(dev, itf)]
    : [classTable(itf), nbarPanel(healthRes?.extras?.nbar, itf.ifIndex),
      seriesLoading && !series ? spinner('Loading the graphs…') : seriesError ? note(seriesError, 'bad', true) : series ? graphs(series, itf) : null,
      streamsPanel(dev, itf)];
  return h('div', { key: tab, role: 'tabpanel', class: 'col', style: 'gap:16px' }, body);
}

/** The sub-tabs of the selected device. Only those with something to show are listed. */
function availableTabs(dev: Dev): { id: DevTab; label: string }[] {
  const t: { id: DevTab; label: string }[] = [{ id: 'overview', label: 'Overview' }, { id: 'interfaces', label: `Interfaces (${dev.interfaces.length})` }];
  t.push({ id: 'hardware', label: 'Hardware' });
  t.push({ id: 'network', label: 'Neighbours and routing' });
  if (dev.hasWlan) t.push({ id: 'wifi', label: 'Wi-Fi' });
  return t;
}
function devTabs(dev: Dev, tab: DevTab): VNode {
  return tabs('Network health sections', availableTabs(dev).map(t => ({ id: t.id, label: t.label, on: t.id === tab })), id => { devTab = id as DevTab; redraw(); });
}
/** Jump to what an Overview item is about: its tab, and for an interface problem the interface and the section with the detail. */
function openTarget(dev: Dev, t: Target): void {
  if (t.ifIndex !== undefined) { if (t.section) ifTab = t.section; select_(dev.id, t.ifIndex, t.tab); } else { devTab = t.tab; redraw(); }
  window.scrollTo({ top: 0 });
}
function overviewPanel(dev: Dev): VNode {
  const input = { dev, health: healthRes, wlan, neighbours: nbRes ? nbRes.ports.reduce((n, p) => n + p.neighbors.length, 0) : null, arp: arpRes ? arpRes.rows.length : null, hasHardware: hasHardware(healthRes), thresholds: data?.thresholds ?? { util: 80, drop: 1 } };
  const all = issues(input);
  return h('div', { class: 'col', style: 'gap:18px' }, attentionPanel(all, t => openTarget(dev, t)), cardsRow(cards(input, all), t => openTarget(dev, t)), resourcesPanel(dev));
}
/** Resources with their history, then sensors and PoE where the device publishes them. Every device has this tab. */
function hardwareTab(dev: Dev): VNode {
  const sensors = hardwarePanel({ data: healthRes });
  return h('div', { class: 'col', style: 'gap:18px' }, resourcesPanel(dev, true),
    sensors ?? (healthRes ? h('span', { class: 'dim', style: 'font-size:12px' }, 'This device does not publish temperature, fan, power supply or PoE sensors that FlowScope reads.') : null));
}
function tabBody(dev: Dev, tab: DevTab): VNode {
  const body = tab === 'overview' ? overviewPanel(dev)
    : tab === 'interfaces' ? ifTable(dev)
    : tab === 'hardware' ? hardwareTab(dev)
    : tab === 'network' ? h('div', { class: 'col', style: 'gap:18px' }, protocolsPanel({ data: healthRes, ifName: i => dev.interfaces.find(x => x.ifIndex === i)?.name ?? '' }), arpPanel(dev), neighborsPanel(dev))
    : wlanPanel(dev);
  return h('div', { key: tab, role: 'tabpanel', class: 'col', style: 'gap:14px' }, body);
}

export function render(): VNode {
  if (loading && !data) return h('main', null, heading('Network health', 'Interfaces, queues and device resources'), spinner());
  if (loadError && !data) return h('main', null, heading('Network health', 'Interfaces, queues and device resources'), note(loadError, 'bad', true), btn('Try again', { onclick: () => void load() }));
  if (!data) return h('main');
  const { dev, itf } = cur();
  const tab = dev ? availableTabs(dev).find(t => t.id === devTab)?.id ?? 'overview' : 'overview';
  const head = heading('Network health', 'Interfaces, queues and device resources', 'How your devices are doing, read over SNMP: uptime, CPU, memory and disk with their history, and for each interface its utilisation, discards and per-class queue drops. Pick a device and interface to see how it behaved and which streams use it.');
  if (!data.devices.length) return h('main', null, head, h('div', { class: 'panel' }, empty('No SNMP devices have been added yet. Add switches and routers on the SNMP devices tab, and their interfaces and queues will appear here.')), btn('Go to SNMP devices', { kind: 'primary', onclick: () => go('devices') }));
  return h('main', null, head, h('div', { class: 'split' }, sidebar(),
    h('div', { class: 'mainp' },
      dev ? h('section', { 'aria-label': 'Selected device', class: 'panel col', style: 'gap:14px' },
        h('div', { class: 'row', style: 'justify-content:space-between' },
          h('div', { class: 'col', style: 'gap:4px' }, h('h3', { style: 'font-size:17px' }, dev.name), h('span', { class: 'muted' }, `${roleLabel(dev.role)} · ${dev.ip} · ${dev.profile || 'generic'} · last answered ${ago(dev.lastOk)}`)),
          btn('Edit in SNMP devices', { kind: 'ghost', small: true, onclick: () => go('devices', { id: dev.id }) })),
        dev.status !== 'ok' && dev.lastError ? note(`The last poll failed: ${dev.lastError}`, 'warn') : null,
        devTabs(dev, tab),
        tabBody(dev, tab)) : null,
      dev && tab === 'interfaces' && itf ? h('section', { 'aria-label': 'Selected interface', class: 'panel col', style: 'gap:16px' },
        h('div', { class: 'row', style: 'justify-content:space-between' }, h('div', { class: 'col', style: 'gap:4px' }, h('h3', { style: 'font-size:17px' }, `${itf.name}${itf.alias ? ' · ' + itf.alias : ''}`),
          h('span', { class: 'muted' }, [itf.speedMbps ? (itf.speedMbps >= 1000 ? itf.speedMbps / 1000 + ' Gbps' : itf.speedMbps + ' Mbps') : 'speed unknown',
            itf.portMode === 'trunk' ? `trunk, native VLAN ${vlanLabel(itf.vlan, itf.vlanName) || 'unknown'}${itf.vlanList ? ', allowed ' + itf.vlanList : ''}` : itf.vlan ? `${itf.isVlanIf ? 'SVI for ' : ''}VLAN ${vlanLabel(itf.vlan, itf.vlanName)}${itf.voiceVlan ? ', voice VLAN ' + vlanLabel(itf.voiceVlan, itf.voiceVlanName) : ''}` : null,
            itf.addresses?.length ? itf.addresses.map(a => publicAddresses([a]).length ? a + ' (public)' : a).join(', ') : null, itf.mac ? 'MAC ' + itf.mac : null,
            itf.policy ? 'output policy ' + itf.policy : null, itf.policyIn ? 'input policy ' + itf.policyIn : null].filter(Boolean).join(' · '))),
          h('div', { class: 'row' }, itf.flagged ? chip('Needs attention', 'warn') : chip('Within thresholds', 'ok'))),
        dev.qosNote ? note(dev.qosNote, 'warn') : null,
        ifTabs(dev, itf),
        ifBody(dev, itf)
        ) : dev && tab === 'interfaces' ? h('div', { class: 'panel' }, empty('Select an interface to see its queues and graphs.')) : null)));
}
