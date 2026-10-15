/** Hardware and protocol health on the Network health page: sensors and optics, PoE, spanning tree, OSPF and BGP, and the link quality of one interface. */
import { h, type VNode } from '../vdom.js';
import { btn, chip, note, stat, status as statusEl } from '../components.js';
import { dur, num } from '../util.js';

export type Level = 'ok' | 'warn' | 'bad' | 'off';
export interface Sensor { id: string; kind: string; name: string; value: number | null; unit: string; state: Level; stateText: string; optic?: 'tx' | 'rx' | 'temp' | 'other'; ifIndex?: number }
export interface Poe { group: number; budgetW: number | null; usedW: number | null; usedPct: number | null; status: string; portsDelivering: number; portsFault: number; portsTotal: number }
export interface Stp { rootId: string; isRoot: boolean; rootPort: number; rootCost: number; topChanges: number | null; sinceChangeSec: number | null; blockingPorts: number; ports: number }
export interface OspfNeighbor { id: string; address: string; state: string; level: Level }
export interface BgpPeer { address: string; as: number | null; state: string; level: Level; admin: string; upSec: number | null; updatesIn: number | null; updatesOut: number | null }
export interface Health { readAt: number; sensors: Sensor[]; poe: Poe[]; stp: Stp | null; ospf: OspfNeighbor[]; bgp: BgpPeer[]; bgpLocalAs: number | null }
export interface IfExtra {
  ifIndex: number; duplex: 'full' | 'half' | 'unknown' | null; admin: number | null; totals: Record<string, number | undefined>; delta: Record<string, number | undefined> | null; dtSec: number | null; readAt: number;
  warnings: { level: Level; text: string }[];
}
export interface HealthRes { health: Health | null; ifExtra: IfExtra[] }

const colour = (l: Level): string | undefined => (l === 'bad' ? 'color:var(--bad)' : l === 'warn' ? 'color:var(--warn)' : undefined);
const worst = (ls: Level[]): Level => (ls.includes('bad') ? 'bad' : ls.includes('warn') ? 'warn' : ls.length && ls.every(l => l === 'off') ? 'off' : 'ok');
const reading = (s: Sensor): string => (s.value === null ? s.stateText : `${Math.abs(s.value) < 100 && s.unit !== 'RPM' ? (Math.round(s.value * 10) / 10).toString() : Math.round(s.value).toString()}${s.unit ? (s.unit === '°C' ? ' °C' : ' ' + s.unit) : ''}`);
const SENSOR_GROUPS: [string, string][] = [['temperature', 'Temperatures'], ['fan', 'Fans'], ['power', 'Power supplies'], ['voltage', 'Voltages'], ['current', 'Currents'], ['humidity', 'Humidity'], ['status', 'Status'], ['other', 'Other']];

function sensorTile(s: Sensor): VNode {
  const sub = s.state === 'ok' ? (s.value === null ? undefined : undefined) : s.stateText;
  return h('div', { key: s.id, class: 'stat', style: 'min-width:0;padding:10px 14px' },
    h('div', { class: 'slabel', title: s.name, style: 'overflow:hidden;text-overflow:ellipsis;white-space:nowrap' }, s.name),
    h('div', { class: 'svalue', style: `font-size:17px;${colour(s.state) ?? ''}` }, s.value === null ? statusEl(s.state === 'off' ? 'off' : s.state, s.stateText) : reading(s)),
    sub && s.value !== null ? h('div', { class: 'ssub', style: colour(s.state) }, sub) : null);
}

/** Light levels and module temperature of each optic, one row per interface. */
function opticsTable(optics: Sensor[], names: Map<number, string>, open: (ifIndex: number) => void): VNode {
  const groups = new Map<string, Sensor[]>();
  for (const s of optics) { const k = s.ifIndex !== undefined ? String(s.ifIndex) : s.name; (groups.get(k) ?? groups.set(k, []).get(k)!).push(s); }
  const rows = [...groups].map(([k, list]) => {
    const pick = (o: string) => list.find(x => x.optic === o);
    const ifIndex = list[0].ifIndex;
    return { k, ifIndex, name: ifIndex !== undefined ? names.get(ifIndex) ?? list[0].name : list[0].name, tx: pick('tx'), rx: pick('rx'), temp: pick('temp'), level: worst(list.map(x => x.state)) };
  }).sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }));
  const cell = (s: Sensor | undefined) => (s ? h('span', { class: 'mono', style: `font-size:12px;${colour(s.state) ?? ''}` }, s.value === null ? '—' : reading(s)) : h('span', { class: 'dim' }, '—'));
  return h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(180px,1.4fr) 100px 100px 90px 110px;--w:640px' },
    h('div', { class: 'tr head' }, ...['Interface', 'Transmit', 'Receive', 'Temperature', 'State'].map(t => h('span', null, t))),
    rows.map(r => h('div', { key: r.k, class: 'tr' },
      r.ifIndex !== undefined ? h('button', { type: 'button', class: 'lnk', title: 'Show this interface', style: 'text-align:left', onclick: () => open(r.ifIndex!) }, r.name) : h('span', null, r.name),
      cell(r.tx), cell(r.rx), cell(r.temp), statusEl(r.level === 'off' ? 'off' : r.level, r.level === 'ok' ? 'ok' : r.level === 'warn' ? 'check' : r.level === 'bad' ? 'fault' : 'n/a')))));
}

const STP_TEXT = (s: Stp): string => (s.isRoot ? 'This device is the root bridge' : `Root bridge ${s.rootId}`);

/** What deserves a second look, as short chips, so a quick glance tells whether to open the details. */
export function attention(hl: Health | null): { level: Level; text: string }[] {
  if (!hl) return [];
  const out: { level: Level; text: string }[] = [];
  const bad = hl.sensors.filter(s => s.state === 'bad' && s.kind !== 'optic'), warn = hl.sensors.filter(s => s.state === 'warn' && s.kind !== 'optic');
  for (const s of bad) out.push({ level: 'bad', text: `${s.name}: ${s.stateText}` });
  for (const s of warn) out.push({ level: 'warn', text: `${s.name}: ${s.stateText}` });
  const opt = hl.sensors.filter(s => s.kind === 'optic' && (s.state === 'bad' || s.state === 'warn'));
  if (opt.length) out.push({ level: opt.some(s => s.state === 'bad') ? 'bad' : 'warn', text: `${opt.length} optic reading${opt.length === 1 ? '' : 's'} outside limits` });
  for (const p of hl.poe) if (p.status === 'faulty' || p.portsFault) out.push({ level: 'bad', text: `PoE: ${p.status === 'faulty' ? 'power source faulty' : p.portsFault + ' port' + (p.portsFault === 1 ? '' : 's') + ' in fault'}` });
  for (const p of hl.poe) if (p.usedPct !== null && p.usedPct >= 90) out.push({ level: 'warn', text: `PoE budget ${p.usedPct}% used` });
  const nb = hl.ospf.filter(n => n.level !== 'ok'); if (nb.length) out.push({ level: nb.some(n => n.level === 'bad') ? 'bad' : 'warn', text: `${nb.length} OSPF neighbour${nb.length === 1 ? '' : 's'} not full` });
  const bp = hl.bgp.filter(p => p.level === 'bad' || p.level === 'warn'); if (bp.length) out.push({ level: bp.some(p => p.level === 'bad') ? 'bad' : 'warn', text: `${bp.length} BGP peer${bp.length === 1 ? '' : 's'} not established` });
  if (hl.stp && hl.stp.sinceChangeSec !== null && hl.stp.sinceChangeSec < 600 && hl.stp.topChanges) out.push({ level: 'warn', text: `Spanning tree changed ${dur(hl.stp.sinceChangeSec * 1000)} ago` });
  return out;
}

export function healthPanel(o: { data: HealthRes | null; loading: boolean; open: boolean; toggle: () => void; ifNames: Map<number, string>; openInterface: (ifIndex: number) => void; localAs?: number | null }): VNode | null {
  const hl = o.data?.health ?? null;
  if (!hl) return o.loading && !o.data ? null : null;
  const att = attention(hl);
  const optics = hl.sensors.filter(s => s.kind === 'optic');
  const others = hl.sensors.filter(s => s.kind !== 'optic');
  const parts: string[] = [];
  if (others.length) parts.push(`${others.length} sensor${others.length === 1 ? '' : 's'}`);
  if (optics.length) parts.push(`${new Set(optics.map(s => s.ifIndex ?? s.name)).size} optic${new Set(optics.map(s => s.ifIndex ?? s.name)).size === 1 ? '' : 's'}`);
  if (hl.poe.length) parts.push('PoE');
  if (hl.stp) parts.push('spanning tree');
  if (hl.ospf.length) parts.push(`${hl.ospf.length} OSPF neighbour${hl.ospf.length === 1 ? '' : 's'}`);
  if (hl.bgp.length) parts.push(`${hl.bgp.length} BGP peer${hl.bgp.length === 1 ? '' : 's'}`);
  const head = h('div', { class: 'row', style: 'justify-content:space-between' },
    h('div', { class: 'col', style: 'gap:2px' }, h('b', null, 'Hardware and protocols'),
      h('span', { class: 'muted', style: 'font-size:12px' }, `${parts.join(', ')}. Read every few minutes.`)),
    btn(o.open ? 'Hide' : 'Show', { small: true, kind: 'ghost', pressed: o.open, aria: o.open ? 'Hide hardware and protocols' : 'Show hardware and protocols', onclick: o.toggle }));
  const flags = att.length ? h('div', { class: 'row', style: 'gap:6px;flex-wrap:wrap' }, att.slice(0, 8).map((a, i) => chip(a.text, a.level === 'bad' ? 'bad' : 'warn')), att.length > 8 ? chip(`+${att.length - 8} more`, 'default') : null)
    : h('div', { class: 'row', style: 'gap:6px' }, chip('Nothing outside its limits', 'ok'));
  if (!o.open) return h('div', { class: 'col', style: 'gap:8px' }, head, flags);

  const sections: (VNode | null)[] = [];
  for (const [kind, title] of SENSOR_GROUPS) {
    const list = others.filter(s => (SENSOR_GROUPS.some(g => g[0] === s.kind) ? s.kind : 'other') === kind);
    if (!list.length) continue;
    sections.push(h('div', { key: kind, class: 'col', style: 'gap:6px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, title),
      h('div', { style: 'display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:8px' }, list.map(sensorTile))));
  }
  if (optics.length) sections.push(h('div', { key: 'optics', class: 'col', style: 'gap:6px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, 'Optics (light levels in dBm)'), opticsTable(optics, o.ifNames, o.openInterface)));
  if (hl.poe.length) sections.push(h('div', { key: 'poe', class: 'col', style: 'gap:6px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, 'Power over Ethernet'),
    h('div', { class: 'row', style: 'gap:10px;align-items:stretch;flex-wrap:wrap' }, hl.poe.map(p => stat(hl.poe.length > 1 ? `PoE source ${p.group}` : 'PoE power',
      h('span', { style: colour(p.status === 'faulty' ? 'bad' : p.usedPct !== null && p.usedPct >= 90 ? 'warn' : 'ok') }, p.usedW !== null && p.budgetW ? `${num(p.usedW)} of ${num(p.budgetW)} W` : p.status),
      [p.usedPct !== null ? `${p.usedPct}% of the budget` : null, p.portsTotal ? `${p.portsDelivering} of ${p.portsTotal} ports delivering${p.portsFault ? `, ${p.portsFault} in fault` : ''}` : null].filter(Boolean).join(' · ') || undefined)))));
  if (hl.stp) {
    const s = hl.stp;
    sections.push(h('div', { key: 'stp', class: 'col', style: 'gap:6px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, 'Spanning tree'),
      h('div', { class: 'row', style: 'gap:10px;align-items:stretch;flex-wrap:wrap' },
        stat('Root', s.isRoot ? 'This device' : 'Another bridge', s.isRoot ? 'It is the root bridge' : `${s.rootId}${s.rootPort ? ` · root port ${s.rootPort}` : ''}${s.rootCost ? ` · cost ${s.rootCost}` : ''}`),
        s.topChanges !== null ? stat('Topology changes', h('span', { style: s.sinceChangeSec !== null && s.sinceChangeSec < 600 && s.topChanges > 0 ? 'color:var(--warn)' : undefined }, num(s.topChanges)), s.sinceChangeSec !== null ? `last one ${dur(s.sinceChangeSec * 1000)} ago` : undefined) : null,
        s.ports ? stat('Blocking ports', String(s.blockingPorts), `of ${s.ports} bridge ports`) : null)));
  }
  if (hl.ospf.length) sections.push(h('div', { key: 'ospf', class: 'col', style: 'gap:6px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, 'OSPF neighbours'),
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(140px,1fr) minmax(140px,1fr) 120px;--w:480px' },
      h('div', { class: 'tr head' }, ...['Neighbour address', 'Router ID', 'State'].map(t => h('span', null, t))),
      hl.ospf.map(n => h('div', { key: n.address, class: 'tr' }, h('span', { class: 'mono', style: 'font-size:12px' }, n.address), h('span', { class: 'mono', style: 'font-size:12px' }, n.id || '—'), statusEl(n.level === 'off' ? 'off' : n.level, n.state)))))));
  if (hl.bgp.length) sections.push(h('div', { key: 'bgp', class: 'col', style: 'gap:6px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, `BGP peers${hl.bgpLocalAs ? ` (local AS ${hl.bgpLocalAs})` : ''}`),
    h('div', { class: 'tbl' }, h('div', { class: 'inner', style: '--cols:minmax(130px,1fr) 90px 130px 110px 100px 100px;--w:720px' },
      h('div', { class: 'tr head' }, ...['Peer', 'AS', 'State', 'Up for', 'Updates in', 'Updates out'].map(t => h('span', null, t))),
      hl.bgp.map(p => h('div', { key: p.address, class: 'tr' }, h('span', { class: 'mono', style: 'font-size:12px' }, p.address), h('span', { class: 'mono', style: 'font-size:12px' }, p.as === null ? '—' : String(p.as)),
        statusEl(p.level === 'off' ? 'off' : p.level, p.admin === 'stop' && p.level !== 'ok' ? `${p.state} (shut down)` : p.state),
        h('span', { class: 'muted' }, p.upSec !== null ? dur(p.upSec * 1000) : '—'), h('span', { class: 'mono', style: 'font-size:12px' }, p.updatesIn === null ? '—' : num(p.updatesIn)), h('span', { class: 'mono', style: 'font-size:12px' }, p.updatesOut === null ? '—' : num(p.updatesOut))))))));
  void STP_TEXT;
  return h('div', { class: 'col', style: 'gap:12px' }, head, flags, sections);
}

/** The link quality of one interface: duplex, errors, collisions and broadcast, multicast and unknown-protocol traffic, with plain-language warnings and the interface's optic readings. */
export function linkQuality(x: IfExtra | undefined, optics: Sensor[], speedMbps: number | null): VNode | null {
  if (!x && !optics.length) return null;
  const tiles: VNode[] = [];
  const rate = (k: string): number | null => (x?.delta && x.dtSec && x.delta[k] !== undefined ? x.delta[k]! / x.dtSec : null);
  const perSec = (v: number) => `${v >= 10 ? num(Math.round(v)) : (Math.round(v * 10) / 10).toString()}/s`;
  if (x) {
    if (x.duplex && x.duplex !== 'unknown') tiles.push(stat('Duplex', h('span', { style: x.duplex === 'half' && (speedMbps ?? 0) >= 100 ? 'color:var(--bad)' : undefined }, x.duplex === 'full' ? 'Full' : 'Half')));
    const errs = ['fcs', 'align', 'symbol'].map(k => x.totals[k]).filter((v): v is number => v !== undefined);
    if (errs.length) {
      const total = errs.reduce((a, b) => a + b, 0);
      const d = x.delta ? ['fcs', 'align', 'symbol'].reduce((a, k) => a + (x.delta![k] ?? 0), 0) : null;
      tiles.push(stat('Frame errors', h('span', { style: d ? 'color:var(--warn)' : undefined }, num(total)), `CRC, alignment and symbol errors since the counters started${d !== null ? ` · +${num(d)} in the last ${x.dtSec! < 120 ? x.dtSec + ' s' : Math.round(x.dtSec! / 60) + ' min'}` : ''}`));
    }
    if ((x.totals.collisions ?? 0) > 0 || (x.totals.late ?? 0) > 0) tiles.push(stat('Collisions', num((x.totals.collisions ?? 0) + (x.totals.late ?? 0) + (x.totals.excessive ?? 0)), (x.totals.late ?? 0) + (x.totals.excessive ?? 0) > 0 ? `${num((x.totals.late ?? 0) + (x.totals.excessive ?? 0))} late or excessive` : undefined));
    const bc = [rate('inBc'), rate('outBc')].filter((v): v is number => v !== null).reduce((a, b) => a + b, 0), hasBc = rate('inBc') !== null || rate('outBc') !== null;
    if (hasBc) tiles.push(stat('Broadcast', h('span', { style: bc >= 1000 ? 'color:var(--warn)' : undefined }, perSec(bc)), 'packets, in and out'));
    const mc = [rate('inMc'), rate('outMc')].filter((v): v is number => v !== null).reduce((a, b) => a + b, 0), hasMc = rate('inMc') !== null || rate('outMc') !== null;
    if (hasMc) tiles.push(stat('Multicast', perSec(mc), 'packets, in and out'));
    if (x.totals.unknown) tiles.push(stat('Unknown protocol', num(x.totals.unknown), 'packets received for a protocol the device does not run'));
  }
  const pick = (o: string) => optics.find(s => s.optic === o);
  for (const [o, label] of [['tx', 'Optic transmit'], ['rx', 'Optic receive'], ['temp', 'Optic temperature']] as const) {
    const s = pick(o); if (s) tiles.push(stat(label, h('span', { style: colour(s.state) }, reading(s)), s.state === 'ok' ? undefined : s.stateText));
  }
  const warns = x?.warnings ?? [];
  if (!tiles.length && !warns.length) return null;
  return h('div', { class: 'col', style: 'gap:8px' },
    h('b', null, 'Link quality'),
    warns.length ? h('div', { class: 'col', style: 'gap:6px' }, warns.map((w, i) => note(w.text, w.level === 'bad' ? 'bad' : 'warn'))) : null,
    tiles.length ? h('div', { class: 'row', style: 'gap:10px;align-items:stretch;flex-wrap:wrap' }, tiles) : null,
    x?.delta === null && x ? h('span', { class: 'dim', style: 'font-size:11.5px' }, 'Rates appear after the second read, a few minutes after the device is first polled.') : null);
}
