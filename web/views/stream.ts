import { h, type VNode } from '../vdom.js';
import { get, qs } from '../api.js';
import { go } from '../state.js';
import { btn, chip, note, seg, spinner, status as statusEl } from '../components.js';
import { neighborLines, portLink, type Neighbor, type PortSource } from '../neighbors.js';
import { bps, bytes, clock, dur, ms, num, stamp, svcLabel } from '../util.js';
import { hideTip, showTip } from '../tooltip.js';

/** The "Following stream" panel: the path a stream took hop by hop, QoS and TTL findings, layers and activity. Shared by Flow explorer and Flows by port. */

export interface Row {
  id: string; srcIp: string; dstIp: string; sport: number; dport: number; proto: number; protoName: string; app: string; appPort: number | null; vlan: number | null; vlanName: string;
  t0: number; t1: number; bytes: number; pkts: number; fwdBytes: number; revBytes: number; hopCount: number; hops: string[]; qosChanged: boolean; qosVerdict?: (Verdict | { kind: 'mixed'; text: string }) | null;
  ttlExpired: boolean; ttlReason: 'ttl' | 'icmp' | null; ttlLow: number | null;
  dscpInS: string; dscpOutS: string | null; flags: number; health: { kind: 'ok' | 'warn' | 'bad'; text: string } | null;
}
export interface Hop {
  n: number; exporter: string; dev: string; role: string; inIf: string; outIf: string; frameSrc: string | null; frameDst: string | null; vlan: number | null; vlanName: string;
  ttl: number | null; ttlExpired: 'ttl' | 'icmp' | null; dscpInS: string; dscpOutS: string; qosChanged: boolean; qosVerdict?: Verdict | null; pkts: number; bytes: number; linkMs: number | null; cumMs: number | null; policy: string | null;
  obs: { kind: string; text: string; severity: 'info' | 'warn' | 'bad' }[]; firstSeen: number; lastSeen: number;
  outIfs?: string[]; sourcePort?: string | null; sourceConfirmed?: boolean;
  notExported?: string[]; devId?: number | null; inFrom?: PortSource; outFrom?: PortSource; inNeighbors?: Neighbor[]; outNeighbors?: Neighbor[];
}
interface Attach { dev: string; ifName: string; vlan: number; macCount: number; edge: boolean; neighbor: string | null; neighborKind: string | null; portMode: string; confidence?: 'high' | 'medium' | 'low' }
interface Located { ip: string | null; macs: string[]; macSource: string; attach: Attach | null; others: Attach[]; note: string }
/** Whether a configured QoS policy explains a DSCP change (see explainRemark in src/analysis/hops.ts). */
export interface Verdict { kind: 'policy' | 'unexplained' | 'unknown'; text: string }
interface Multicast { group: string; source: string; location: Located | null }
export interface Detail {
  skey: string; initiator: { ip: string; port: number }; responder: { ip: string; port: number }; proto: number; protoName: string; app: string; appPort: number | null; t0: number; t1: number;
  forward: Hop[]; reverse: Hop[]; qosChanged: boolean; qosVerdict?: (Verdict | { kind: 'mixed'; text: string }) | null; marking?: { direction: 'forward' | 'reverse'; values: { dscp: number; name: string; pkts: number; bytes: number; where: string[] }[] }[]; ttlExpired: boolean; totals: { fwdBytes: number; revBytes: number; fwdPkts: number; revPkts: number }; note: string | null; multicast: Multicast | null;
  activity: { t0: number; t1: number; fwd: number[]; rev: number[] };
}

const FLAGS: [string, number][] = [['FIN', 1], ['SYN', 2], ['RST', 4], ['PSH', 8], ['ACK', 16], ['URG', 32]];
const flagText = (f: number) => (f ? FLAGS.filter(([, b]) => f & b).map(([n]) => n).join(' ') : '—');

/** What one followed stream needs: which stream is selected, its loaded detail, and the direction being shown. Each page owns one. */
export class Follower {
  selId = ''; detail: Detail | null = null; error = ''; loading = false; reverse = false; related: Row[] = [];
  /** `range` gives the time window to look the stream up in; `changed` repaints the page; `onPick` is called when another conversation is chosen. */
  constructor(private range: () => string, public changed: () => void, public onPick: (id: string) => void) {}

  /** Make `id` the followed stream ('' clears it) and load its detail. */
  select(id: string): void {
    if (id === this.selId) return;
    this.selId = id; this.detail = null; this.related = []; this.error = '';
    if (id) void this.load(); else this.changed();
  }
  async load(): Promise<void> {
    const id = this.selId; if (!id) return;
    this.loading = true; this.error = ''; this.changed();
    try {
      const d = await get<Detail>('/api/streams/detail' + qs({ id, range: this.range() }));
      if (id !== this.selId) return;
      this.detail = d; this.reverse = false;
      void this.loadRelated(d);
    } catch (e) { if (id === this.selId) { this.detail = null; this.error = (e as Error).message; } }
    this.loading = false; this.changed();
  }
  private async loadRelated(d: Detail): Promise<void> {
    try {
      const r = await get<{ rows: Row[] }>('/api/streams' + qs({ range: this.range(), q: `ip:${d.initiator.ip} ip:${d.responder.ip}`, sort: 'bytes', limit: 8 }));
      if (this.selId === d.skey) { this.related = r.rows.filter(x => x.id !== d.skey).slice(0, 5); this.changed(); }
    } catch { /* related conversations are optional */ }
  }
  /** `row` is the matching list row, if the page has it; it adds the TCP flags. */
  render(row?: { flags: number }): VNode | null { return followed(this, row); }
}


function qosMessage(d: Detail): { text: string; dev?: string; ifName?: string; kind: 'bad' | 'info' | 'warn'; title: string } | null {
  const v = d.qosVerdict;
  if (!v) return null;
  if (v.kind === 'mixed') { /* handled below, with where each value was seen */ }
  const found = (): { text: string; dev?: string; ifName?: string } | null => {
    for (const [dirName, hops] of [['initiator → responder', d.forward], ['responder → initiator', d.reverse]] as const) {
      for (const hp of hops) {
        if (hp.qosChanged) return { text: `${hp.dscpInS} → ${hp.dscpOutS} on ${hp.dev} (${hp.outIf}), ${dirName}.`, dev: hp.dev, ifName: hp.outIf };
      }
      for (let i = 1; i < hops.length; i++) {
        const ob = hops[i].obs.find(o => o.kind === 'remark' && o.text.startsWith('DSCP arrived'));
        if (ob) return { text: `${ob.text.split('. ')[0]}. The marking changed between ${hops[i - 1].dev} and ${hops[i].dev}, ${dirName}.`, dev: hops[i - 1].dev, ifName: hops[i - 1].outIf };
      }
    }
    return null;
  };
  if (v.kind === 'mixed') {
    for (const m of d.marking ?? []) {
      const total = m.values.reduce((a, x) => a + x.pkts, 0) || 1;
      const parts = m.values.map(x => `${x.name} ${x.pkts.toLocaleString()} packets (${(100 * x.pkts / total) < 0.1 ? '<0.1' : (100 * x.pkts / total).toFixed(1)}%) at ${x.where[0]}`);
      return { text: `The packets of this stream carry more than one DSCP value, ${m.direction === 'forward' ? 'initiator → responder' : 'responder → initiator'}: ${parts.join('; ')}. No device re-marked them; the sender uses different markings for different packets of the same conversation.`, kind: 'warn', title: 'Mixed DSCP markings' };
    }
    return { text: v.text, kind: 'warn', title: 'Mixed DSCP markings' };
  }
  const f = found();
  if (v.kind === 'policy') return { text: `${f?.text ?? ''} ${v.text}`.trim(), kind: 'info', title: 'QoS re-marked by policy' };
  if (v.kind === 'unexplained') return { ...(f ?? { text: '' }), text: `${f?.text ?? ''} ${v.text}`.trim(), kind: 'bad', title: 'QoS changed in transit, not explained by a policy' };
  return { ...(f ?? { text: '' }), text: `${f?.text ?? 'The marking differs between hops.'} ${v.text}`.trim(), kind: 'warn', title: 'QoS changed in transit' };
}

function ttlMessage(d: Detail): { text: string } | null {
  for (const [dirName, hops] of [['initiator → responder', d.forward], ['responder → initiator', d.reverse]] as const) {
    for (const hp of hops) {
      const ob = hp.obs.find(o => o.kind === 'ttl');
      if (ob) return { text: `${ob.text} (${dirName}).` };
    }
  }
  return d.ttlExpired ? { text: 'The TTL ran out before this stream reached its destination.' } : null;
}

function strip(hops: Hop[], d: Detail, reverse: boolean): VNode {
  const items: VNode[] = [];
  const src = reverse ? d.responder : d.initiator, dst = reverse ? d.initiator : d.responder;
  items.push(h('div', { key: 'src', class: 'node edge' }, h('b', { class: 'mono' }, src.ip), h('span', null, 'source host'), h('span', { class: 'mono' }, src.port ? ':' + src.port : '')));
  hops.forEach((hp, i) => {
    const slow = hp.obs.some(o => o.kind === 'slow'), loss = hp.obs.some(o => o.kind === 'loss');
    items.push(h('div', { key: 'l' + i, class: 'link' + (loss ? ' loss' : slow ? ' slow' : '') },
      h('span', null, i === 0 ? '' : hp.linkMs === null ? '?' : ms(hp.linkMs)), h('i'),
      h('span', { class: 'flag' }, loss ? 'loss' : slow ? 'slow' : '')));
    items.push(h('div', { key: 'n' + i, class: 'node' + ((hp.qosChanged && hp.qosVerdict?.kind !== 'policy') || hp.ttlExpired ? ' remark' : '') },
      h('b', null, hp.dev), h('span', null, hp.role), h('span', { class: 'mono' }, `${hp.inIf} → ${hp.outIf}`),
      hp.outNeighbors && hp.outNeighbors.length ? h('span', { title: 'What CDP/LLDP says is connected to the outgoing port' }, '→ ' + hp.outNeighbors.map(n => n.name || n.ip).join(', ')) : null,
      hp.policy ? h('span', null, 'policy ' + hp.policy) : null, hp.qosChanged ? h('span', { style: `color:var(${hp.qosVerdict?.kind === 'policy' ? '--info' : '--bad'})`, title: hp.qosVerdict?.text }, `${hp.dscpInS} → ${hp.dscpOutS}${hp.qosVerdict?.kind === 'policy' ? ' (policy)' : ''}`) : null, hp.ttlExpired ? h('span', { style: 'color:var(--bad)' }, hp.ttlExpired === 'icmp' ? 'TTL exceeded notice' : `TTL ${hp.ttl ?? 1}: expired here`) : null));
  });
  items.push(h('div', { key: 'lend', class: 'link' }, h('span'), h('i'), h('span')));
  items.push(h('div', { key: 'dst', class: 'node edge' }, h('b', { class: 'mono' }, dst.ip), h('span', null, 'destination host'), h('span', { class: 'mono' }, dst.port ? ':' + dst.port : '')));
  return h('div', { class: 'panel flush' }, h('div', { class: 'strip', role: 'img', 'aria-label': `Path: ${[src.ip, ...hops.map(x => x.dev), dst.ip].join(' to ')}` }, items));
}

/**
 * A multicast stream is one source and many receivers. Every switch on the tree sees the same packets, so the devices below are not ordered
 * and none of them is "the" first hop. Where the source host is plugged in comes from the switches' MAC address tables, not from the flow records.
 */
function multicastStrip(hops: Hop[], d: Detail, m: Multicast): VNode {
  const at = m.location?.attach ?? null;
  const conf = at?.confidence;
  const sourceCard = h('div', { class: 'node edge', style: 'min-width:220px' },
    h('b', { class: 'mono' }, m.source), h('span', null, 'source host'),
    at ? [h('span', { style: 'color:var(--text)' }, `Plugged in to ${at.dev} ${at.ifName}`), h('span', null, [at.vlan ? `VLAN ${at.vlan}` : null, conf ? `${conf} confidence` : null].filter(Boolean).join(' · '))]
      : h('span', { style: 'color:var(--warn)' }, 'Location not known'));
  const groupCard = h('div', { class: 'node edge', style: 'min-width:170px' }, h('b', { class: 'mono' }, m.group), h('span', null, 'multicast group'), h('span', { class: 'mono' }, d.responder.port ? ':' + d.responder.port : ''), h('span', null, d.app));
  return h('div', { class: 'panel flush' }, h('div', { class: 'mctree', role: 'group', 'aria-label': `Multicast group ${m.group} from ${m.source}, seen by ${hops.length} device${hops.length === 1 ? '' : 's'}` },
    sourceCard, h('div', { class: 'mclink', 'aria-hidden': 'true' }, h('i')), groupCard, h('div', { class: 'mclink', 'aria-hidden': 'true' }, h('i')),
    h('div', { class: 'mcset' },
      h('span', { class: 'eyebrow' }, `Seen by ${hops.length} device${hops.length === 1 ? '' : 's'} (in no particular order)`),
      h('div', { class: 'mcgrid' }, hops.map((hp, i) => {
        const here = !!hp.sourcePort;
        return h('div', { key: i, class: 'node' + (here ? ' here' : '') + (hp.qosChanged && hp.qosVerdict?.kind !== 'policy' ? ' remark' : '') },
          h('b', null, hp.dev), h('span', null, hp.role),
          h('span', { class: 'mono' }, `in ${hp.inIf || '—'}`),
          h('span', { class: 'mono' }, hp.outIfs && hp.outIfs.length > 1 ? `out ${hp.outIfs.length} interfaces` : `out ${hp.outIf || '—'}`),
          hp.outIfs && hp.outIfs.length > 1 ? h('span', { class: 'mono', title: hp.outIfs.join(', ') }, hp.outIfs.slice(0, 3).join(', ') + (hp.outIfs.length > 3 ? ', …' : '')) : null,
          here ? h('span', { style: 'color:var(--accent);font-weight:600' }, hp.sourceConfirmed ? `Source host is on ${hp.sourcePort}` : `Source host is on ${hp.sourcePort} (this switch's flow data shows ${hp.inIf})`) : null,
          hp.qosChanged ? h('span', { style: `color:var(${hp.qosVerdict?.kind === 'policy' ? '--info' : '--bad'})`, title: hp.qosVerdict?.text }, `${hp.dscpInS} → ${hp.dscpOutS}${hp.qosVerdict?.kind === 'policy' ? ' (policy)' : ''}`) : null);
      })))));
}

function multicastExplain(d: Detail, m: Multicast): VNode {
  const loc = m.location;
  return h('div', { class: 'note info' },
    h('b', null, 'This is a multicast stream: one source, many receivers'),
    h('div', null, 'Every switch and router that forwards the group reports the same packets, so each one appears once, side by side. They are not hops in a line, and no delay or loss is worked out between them. The receivers themselves are not listed because multicast flow data only shows the sending side.'),
    loc?.attach ? h('div', { style: 'margin-top:6px' }, `The source ${m.source} was found plugged in to ${loc.attach.dev} ${loc.attach.ifName}${loc.attach.vlan ? ' (VLAN ' + loc.attach.vlan + ')' : ''} by reading the MAC address tables${loc.macSource === 'arp' ? ' and ARP' : ''}, ${loc.attach.confidence} confidence.${loc.attach.confidence !== 'high' && loc.note ? ' ' + loc.note : ''}`)
      : h('div', { style: 'margin-top:6px' }, `The switch that ${m.source} is plugged in to is not known${loc?.note ? ': ' + loc.note : '. Host tracking has not learned this address yet, or its switch is not polled over SNMP.'} It is not guessed from the flow data.`));
}

function multicastTable(hops: Hop[]): VNode {
  const cols = 'minmax(140px,1.1fr) minmax(170px,1.3fr) minmax(150px,1.2fr) 110px 44px 110px 70px 70px minmax(200px,1.6fr)';
  return h('div', { class: 'tbl hops' }, h('div', { class: 'inner', style: `--cols:${cols};--w:1100px` },
    h('div', { class: 'tr head' }, ...['Device', 'Interfaces', 'Frame in (L2)', 'VLAN', 'TTL', 'DSCP', 'Packets', 'Bytes', 'Observations'].map(t => h('span', null, t))),
    hops.map((hp, i) => h('div', { key: i, class: 'tr' },
      h('div', null, h('div', { style: 'font-weight:600' }, hp.dev), h('div', { class: 'dim', style: 'font-size:12px' }, hp.role), h('div', { class: 'dim mono', style: 'font-size:11.5px' }, hp.exporter),
        hp.notExported ? h('div', { class: 'dim', style: 'font-size:11.5px', title: 'The exporter does not include these in what it sends, so they are blank here. Add them to its flow record (Flexible NetFlow / IPFIX template) to see them.' }, 'Not sent: ' + hp.notExported.join(', ')) : null),
      h('div', { class: 'mono', style: 'font-size:12px' }, h('div', null, h('span', { class: 'dim' }, 'in '), hp.inIf || '—'), neighborLines(hp.inNeighbors), h('div', null, h('span', { class: 'dim' }, 'out '), (hp.outIfs && hp.outIfs.length ? hp.outIfs : [hp.outIf]).join(', ') || '—'), neighborLines(hp.outNeighbors),
        hp.sourcePort ? h('div', { style: 'color:var(--accent)' }, `source host on ${hp.sourcePort}`) : null),
      h('div', { class: 'mono', style: 'font-size:12px' }, h('div', null, h('span', { class: 'dim' }, 'src '), hp.frameSrc ?? '—'), h('div', null, h('span', { class: 'dim' }, 'dst '), hp.frameDst ?? '—')),
      h('span', { class: 'mono', style: 'font-size:12px' }, hp.vlan ? String(hp.vlan) : '—', ' ', h('span', { class: 'dim' }, hp.vlanName)),
      h('span', { class: 'mono', style: 'font-size:12px' }, hp.ttl === null ? '—' : String(hp.ttl)),
      h('span', { style: 'font-size:12px' }, hp.qosChanged ? h('span', { class: hp.qosVerdict?.kind === 'policy' ? 'tag info' : 'tag bad', title: hp.qosVerdict?.text }, `${hp.dscpInS} → ${hp.dscpOutS}`) : hp.dscpInS),
      h('span', { class: 'mono', style: 'font-size:12px' }, num(hp.pkts)), h('span', { class: 'mono', style: 'font-size:12px' }, bytes(hp.bytes)),
      h('div', { class: 'obs' }, hp.obs.length ? hp.obs.map((o, k) => h('span', { key: k, class: 'ob ' + o.severity }, o.text)) : h('span', { class: 'dim' }, 'Nominal'))))));
}

function hopsTable(hops: Hop[]): VNode {
  const cols = '36px minmax(130px,1.1fr) minmax(110px,1fr) minmax(150px,1.2fr) 110px 44px 110px 70px 70px 56px 56px minmax(200px,1.6fr)';
  return h('div', { class: 'tbl hops' }, h('div', { class: 'inner', style: `--cols:${cols};--w:1310px` },
    h('div', { class: 'tr head' }, ...['#', 'Exporter', 'Interfaces', 'Frame in (L2)', 'VLAN', 'TTL', 'DSCP', 'Packets', 'Bytes', 'Link', 'Cumul.', 'Observations'].map(t => h('span', null, t))),
    hops.map((hp, i) => {
      const prev = i > 0 ? hops[i - 1] : null;
      const lossPct = prev && prev.pkts > 0 && hp.pkts < prev.pkts ? ((prev.pkts - hp.pkts) / prev.pkts) * 100 : 0;
      return h('div', { key: i, class: 'tr' },
        h('span', { class: 'mono muted' }, String(hp.n)),
        h('div', null, h('div', { style: 'font-weight:600' }, hp.dev), h('div', { class: 'dim', style: 'font-size:12px' }, hp.role), h('div', { class: 'dim mono', style: 'font-size:11.5px' }, hp.exporter),
        hp.notExported ? h('div', { class: 'dim', style: 'font-size:11.5px', title: 'The exporter does not include these in what it sends, so they are blank here. Add them to its flow record (Flexible NetFlow / IPFIX template) to see them.' }, 'Not sent: ' + hp.notExported.join(', ')) : null),
        h('div', { class: 'mono', style: 'font-size:12px' },
          h('div', null, h('span', { class: 'dim' }, 'in '), portLink(hp.dev, hp.inIf, hp.inFrom, hp.devId != null)), neighborLines(hp.inNeighbors),
          h('div', null, h('span', { class: 'dim' }, 'out '), portLink(hp.dev, hp.outIf, hp.outFrom, hp.devId != null)), neighborLines(hp.outNeighbors)),
        h('div', { class: 'mono', style: 'font-size:12px' }, h('div', null, h('span', { class: 'dim' }, 'src '), hp.frameSrc ?? '—'), h('div', null, h('span', { class: 'dim' }, 'dst '), hp.frameDst ?? '—')),
        h('span', { class: 'mono', style: 'font-size:12px' }, hp.vlan ? String(hp.vlan) : '—', ' ', h('span', { class: 'dim' }, hp.vlanName)),
        h('span', { class: 'mono', style: 'font-size:12px' }, hp.ttl === null ? '—' : String(hp.ttl)),
        h('span', { style: 'font-size:12px' }, hp.qosChanged || hp.dscpOutS !== 'not reported' && hp.dscpOutS !== hp.dscpInS ? h('span', { class: hp.qosVerdict?.kind === 'policy' ? 'tag info' : 'tag bad', title: hp.qosVerdict?.text }, `${hp.dscpInS} → ${hp.dscpOutS}`) : hp.dscpInS),
        h('div', { class: 'mono', style: 'font-size:12px' }, h('div', null, num(hp.pkts)), lossPct >= 0.5 ? h('div', { style: 'color:var(--bad);font-size:11.5px' }, `−${lossPct.toFixed(1)}%`) : null),
        h('span', { class: 'mono', style: 'font-size:12px' }, bytes(hp.bytes)),
        h('span', { class: 'mono', style: 'font-size:12px' }, i === 0 ? '—' : hp.linkMs === null ? '?' : ms(hp.linkMs)),
        h('span', { class: 'mono', style: 'font-size:12px' }, i === 0 ? '—' : hp.cumMs === null ? '?' : ms(hp.cumMs)),
        h('div', { class: 'obs' }, hp.obs.length ? hp.obs.map((o, k) => h('span', { key: k, class: 'ob ' + o.severity }, o.text)) : h('span', { class: 'dim' }, 'Nominal')));
    })));
}

function layers(d: Detail, r: { flags: number } | undefined, first: Hop | undefined): VNode {
  const fwdLast = d.forward[d.forward.length - 1];
  const L = [
    { tag: 'L2', name: 'Data link', items: [['Src MAC', first?.frameSrc ?? '—'], ['Dst MAC', first?.frameDst ?? '—'], ['VLAN', first?.vlan ? `${first.vlan} ${first.vlanName}`.trim() : 'untagged']] },
    { tag: 'L3', name: 'Network', items: [['Src IP', d.initiator.ip], ['Dst IP', d.responder.ip], ['Protocol', d.protoName], ['DSCP', first ? (fwdLast && fwdLast.dscpOutS !== 'not reported' && fwdLast.dscpOutS !== first.dscpInS ? `${first.dscpInS} → ${fwdLast.dscpOutS}` : first.dscpInS) : '—'], ['TTL seen', first?.ttl === null || !first ? '—' : String(first.ttl)]] },
    { tag: 'L4', name: 'Transport', items: [['Src port', String(d.initiator.port || '—')], ['Dst port', String(d.responder.port || '—')], ['Service', svcLabel(d.app, d.appPort)], ['TCP flags', r ? flagText(r.flags) : '—']] }
  ];
  return h('div', { class: 'layers' }, L.map(l => h('div', { key: l.tag, class: 'layer' },
    h('div', { class: 'lh' }, chip(l.tag, l.tag === 'L2' ? 'violet' : l.tag === 'L3' ? 'info' : 'accent'), h('span', null, l.name)),
    h('div', { class: 'kvs' }, l.items.map(([k, v]) => h('div', { key: k, class: 'kv' }, h('span', { class: 'k' }, k), h('span', { class: 'v' }, v)))))));
}

function activity(d: Detail, f: Follower): VNode {
  const a = d.activity;
  const max = Math.max(1, ...a.fwd, ...a.rev);
  const n = Math.max(1, a.fwd.length);
  const slot = (a.t1 - a.t0) / n;
  const sums = { '': d.totals.fwdBytes, rev: d.totals.revBytes };
  const bars = (arr: number[], cls: '' | 'rev') => h('div', { class: 'act ' + cls, 'aria-hidden': 'true', onpointerleave: hideTip, onpointercancel: hideTip },
    arr.map((v, i) => h('span', {
      key: i, class: 'cell',
      // The cell spans the full height so even a near-empty interval is easy to point at; the bar inside is the visible part.
      onpointermove: (e: PointerEvent) => hoverBar(e, i),
      onpointerdown: (e: PointerEvent) => hoverBar(e, i)
    }, h('i', { style: `height:${Math.max(1, (v / max) * 100)}%` }))));
  /** Bits per second over an interval, counting at least one second so a very short stream is not shown as an absurd rate. */
  const rate = (v: number, ms: number) => v * 8 / (Math.max(1000, ms) / 1000);
  const peak = (arr: number[]) => Math.max(0, ...arr.map(v => rate(v, slot)));
  const hoverBar = (e: PointerEvent, i: number) => {
    const el = e.currentTarget as HTMLElement;
    const rev = !!el.parentElement?.classList.contains('rev');
    const v = (rev ? a.rev : a.fwd)[i] ?? 0;
    const total = sums[rev ? 'rev' : ''];
    const s0 = a.t0 + i * slot, s1 = i === n - 1 ? a.t1 : s0 + slot;
    const share = total > 0 ? v / total * 100 : null;
    showTip({
      title: `${clock(s0)} → ${clock(s1)}`,
      rows: [
        { color: rev ? 'var(--warn)' : 'var(--accent)', label: rev ? 'Responder → initiator' : 'Initiator → responder', value: bps(rate(v, s1 - s0)) },
        { label: 'Data in interval', value: v >= 1000 ? `${bytes(v)} (${num(v)} B)` : `${num(v)} B` },
        ...(share !== null ? [{ label: 'Share of this direction', value: (share < 10 ? share.toFixed(1) : share.toFixed(0)) + '%' }] : [])
      ],
      note: `Interval ${i + 1} of ${n} · ${dur(s1 - s0)} each`
    }, e.clientX, e.clientY);
  };
  return h('div', { class: 'layer' },
    h('div', { class: 'row', style: 'justify-content:space-between' }, h('b', null, 'Stream activity'), h('span', { class: 'muted mono', style: 'font-size:12px' }, `${clock(a.t0)} → ${clock(a.t1)}`)),
    h('div', { class: 'col', style: 'gap:6px;margin:10px 0' }, bars(a.fwd, ''), bars(a.rev, 'rev')),
    h('div', { class: 'legendrow' },
      h('span', null, h('i', { class: 'sw', style: 'background:var(--accent)' }), 'Initiator → responder · ', h('b', null, bytes(d.totals.fwdBytes)), h('span', { class: 'dim' }, ` · peak ${bps(peak(a.fwd))}`)),
      h('span', null, h('i', { class: 'sw', style: 'background:var(--warn)' }), 'Responder → initiator · ', h('b', null, bytes(d.totals.revBytes)), h('span', { class: 'dim' }, ` · peak ${bps(peak(a.rev))}`))),
    h('div', { class: 'col', style: 'gap:6px;margin-top:12px' },
      h('span', { class: 'muted' }, 'Other conversations between these hosts'),
      f.related.length ? f.related.map(r => h('button', { key: r.id, type: 'button', class: 'cardbtn', onclick: () => f.onPick(r.id) }, h('span', { class: 't mono' }, `${r.srcIp}:${r.sport} → ${r.dstIp}:${r.dport}`), h('span', { class: 's' }, `${svcLabel(r.app, r.appPort)} · ${bytes(r.bytes)}`))) : h('span', { class: 'dim' }, 'None in this time range.')));
}

function followed(f: Follower, row: { flags: number } | undefined): VNode | null {
  if (!f.selId) return null;
  if (f.loading && !f.detail) return h('section', { 'aria-label': 'Selected flow' }, spinner('Loading the path…'));
  if (f.error) return h('section', { 'aria-label': 'Selected flow' }, note(f.error, 'warn', true));
  const d = f.detail;
  if (!d) return null;
  const mc = d.multicast;
  const reverse = f.reverse;
  const hops = mc ? d.forward : reverse ? d.reverse : d.forward;
  const all = [...d.forward, ...d.reverse];
  const lat = d.forward.length ? d.forward[d.forward.length - 1].cumMs : null;
  const worst = all.flatMap(x => x.obs).find(o => o.severity === 'bad') ?? all.flatMap(x => x.obs).find(o => o.severity === 'warn');
  const qm = qosMessage(d);
  const tm = ttlMessage(d);
  return h('section', { 'aria-label': 'Selected flow', class: 'panel col', style: 'gap:16px' },
    h('div', { class: 'row', style: 'justify-content:space-between;align-items:flex-start' },
      h('div', { class: 'col', style: 'gap:6px' },
        h('span', { class: 'eyebrow' }, 'Following stream'),
        mc ? h('h2', { class: 'mono', style: 'font-size:18px;font-weight:600' }, `${mc.source}${d.initiator.port ? ':' + d.initiator.port : ''} → group ${mc.group}${d.responder.port ? ':' + d.responder.port : ''}`) : h('h2', { class: 'mono', style: 'font-size:18px;font-weight:600' }, `${d.initiator.ip}${d.initiator.port ? ':' + d.initiator.port : ''} → ${d.responder.ip}${d.responder.port ? ':' + d.responder.port : ''}`),
        h('div', { class: 'row', style: 'gap:8px 16px;color:var(--muted)' },
          h('span', null, `${d.protoName} · ${svcLabel(d.app, d.appPort)}`), mc ? chip('Multicast', 'violet') : null,
          h('span', null, mc ? `seen by ${d.forward.length} device${d.forward.length === 1 ? '' : 's'}` : `${d.forward.length} hop${d.forward.length === 1 ? '' : 's'} forward, ${d.reverse.length} back`),
          !mc && lat !== null ? h('span', null, `about ${ms(lat)} end to end`) : null,
          h('span', null, `Started ${stamp(d.t0)} · lasted ${dur(d.t1 - d.t0)}`),
          worst ? statusEl(worst.severity === 'bad' ? 'bad' : 'warn', worst.text.length > 70 ? worst.text.slice(0, 68) + '…' : worst.text) : statusEl('ok', 'Healthy'))),
      mc ? null : seg('Path direction', [{ id: 'f', label: 'Initiator → responder', on: !reverse }, { id: 'r', label: 'Responder → initiator', on: reverse, disabled: !d.reverse.length, title: d.reverse.length ? undefined : 'No exporter reported the return direction' }], id => { f.reverse = id === 'r'; f.changed(); })),
    d.note ? note(d.note, 'info') : null,
    qm ? h('div', { class: `note ${qm.kind} row`, style: 'justify-content:space-between' },
      h('div', null, h('b', null, qm.title), h('div', null, qm.text)),
      qm.dev ? btn('Open egress queue', { kind: qm.kind === 'bad' ? 'danger' : 'ghost', onclick: () => go('links', { dev: qm.dev, if: qm.ifName }) }) : null) : null,
    tm ? h('div', { class: 'note bad' }, h('b', null, 'TTL expired before the destination'), h('div', null, tm.text)) : null,
    mc ? multicastExplain(d, mc) : null,
    mc ? (hops.length ? [multicastStrip(hops, d, mc), multicastTable(hops)] : note('No exporter reported this stream.', 'info')) : hops.length ? [strip(hops, d, reverse), hopsTable(hops)] : note('No exporter reported this direction.', 'info'),
    h('div', { class: 'split' }, h('div', { class: 'mainp', style: 'flex-basis:520px' }, layers(d, row, (mc ? d.forward.find(x => x.sourcePort) : undefined) ?? d.forward[0])), h('div', { class: 'side', style: 'flex-basis:420px' }, activity(d, f))));
}
