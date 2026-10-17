/** The LISP fabric panel of an SD-Access node on the Network tab: endpoints in use, the registration check, and how the map cache has moved. */
import { h, type VNode } from '../vdom.js';
import { chip, note, spark, stat } from '../components.js';
import { bytes, dur, num } from '../util.js';

export interface LispConv { iid: number; vrf: string; ip: string; ageSec: number | null; rloc: string | null; rlocName: string; viaBorder: boolean; mac: string; user: string; sgt: { value: number; name: string } | null; bytes: number | null; flows: number | null }
export interface LispView {
  readAt: number; level: 'ok' | 'warn' | 'bad'; problems: string[]; cacheTotal: number; truncated: boolean;
  instances: { iid: number; vrf: string; cacheSize: number; cacheLimit: number; requestsOut: number; repliesIn: number; registersOut: number }[];
  history: { t: number; cache: number; added: number; removed: number }[];
  mapServers: { total: number; down: string[] }; mapResolvers: { total: number; down: string[] };
  registration: { registeredHosts: number; matched: number; macEids: number; instancesChecked: number; missingTotal: number; staleTotal: number;
    missing: { ip: string; vrf: string; mac: string; ifIndex: number; authenticated: boolean; user: string }[]; stale: { iid: number; vrf: string; ip: string; ageSec: number | null }[] };
  conversations: LispConv[]; fabricNodes: { rloc: string; name: string; active: number; total: number }[]; flowsKnown: boolean;
}

const mono = 'font-size:12px';
const vn = (vrf: string, iid: number) => vrf || (iid === 4097 ? 'default' : String(iid));
const sub = (t: string, hint?: string) => h('div', { class: 'row', style: 'gap:8px' }, h('span', { class: 'muted', style: 'font-size:12px;font-weight:600' }, t), hint ? h('span', { class: 'dim', style: 'font-size:11.5px' }, hint) : null);
const ageText = (s: number | null) => (s === null ? '—' : s < 90 ? `${s} s` : dur(s * 1000));
const table = (cols: string, w: number, head: string[], body: (VNode | null)[]) => h('div', { class: 'tbl' }, h('div', { class: 'inner', style: `--cols:${cols};--w:${w}px` }, h('div', { class: 'tr head' }, ...head.map(t => h('span', null, t))), h('div', { class: 'scroll', style: 'max-height:260px' }, body)));

export function lispPanel(v: LispView | null, ifName: (i: number) => string): VNode | null {
  if (!v) return null;
  const r = v.registration, conv = v.conversations;
  const sizes = v.history.map(p => p.cache);
  const last = v.history[v.history.length - 1];
  const win = v.history.length > 1 ? dur(v.history[v.history.length - 1]!.t - v.history[0]!.t) : '';
  const churn = v.history.slice(-12), added = churn.reduce((a, p) => a + p.added, 0), removed = churn.reduce((a, p) => a + p.removed, 0);
  return h('div', { class: 'col', style: 'gap:12px' },
    h('div', { class: 'col', style: 'gap:2px' }, h('b', null, 'LISP fabric'),
      h('span', { class: 'muted', style: 'font-size:12px' }, 'What this fabric node knows from LISP (LISP-MIB): the remote endpoints it has resolved because a local host sent to them, the addresses it registered, and the map servers. Read every 5 minutes.')),
    ...v.problems.map(t => note(t, v.level === 'bad' ? 'bad' : 'warn', true)),
    h('div', { class: 'row', style: 'gap:10px;align-items:stretch;flex-wrap:wrap' },
      stat('Map cache', num(v.cacheTotal), `${conv.length ? num(v.conversations.length) + ' in use' : 'none in use'}${v.truncated ? ', list cut off' : ''}`),
      stat('Registered', num(r.registeredHosts), `${num(r.matched)} seen on ports${r.macEids ? ` · ${num(r.macEids)} MAC addresses` : ''}`),
      stat('Map servers', h('span', { style: v.mapServers.down.length ? 'color:var(--warn)' : undefined }, `${v.mapServers.total - v.mapServers.down.length} of ${v.mapServers.total} up`), `${v.mapResolvers.total - v.mapResolvers.down.length} of ${v.mapResolvers.total} resolvers up`),
      stat('Cache movement', last ? `+${num(added)} / −${num(removed)}` : '—', churn.length > 1 ? `entries added / removed in the last ${dur(churn[churn.length - 1]!.t - churn[0]!.t)}` : 'needs two reads')),
    sizes.length > 2 ? h('div', { class: 'row', style: 'gap:10px;align-items:center' }, spark(sizes, { w: 220, h: 34, label: `Map cache size over ${win}` }), h('span', { class: 'dim', style: 'font-size:12px' }, `Map cache size over ${win}: ${num(Math.min(...sizes))} to ${num(Math.max(...sizes))} entries`)) : null,

    // endpoints in use
    h('div', { class: 'col', style: 'gap:6px' }, sub('Endpoints this node is sending to', v.flowsKnown ? 'map cache entries in use, with the NetFlow volume towards each over the last hour; an entry with no fabric node is forwarded to the border' : 'map cache entries in use. The switch does not count traffic per entry; no NetFlow from this node was available to show volumes'),
      conv.length ? table(`minmax(120px,1fr) 100px minmax(170px,1.3fr) 80px minmax(200px,1.6fr)${v.flowsKnown ? ' 100px' : ''}`, v.flowsKnown ? 900 : 780, ['Address', 'Network', 'Behind', 'Resolved', 'Host', ...(v.flowsKnown ? ['Last hour'] : [])],
        conv.slice(0, 150).map(c => h('div', { key: c.iid + c.ip, class: 'tr' },
          h('span', { class: 'mono', style: mono }, c.ip), h('span', null, vn(c.vrf, c.iid)),
          c.rloc ? h('span', { class: 'mono', style: mono, title: c.rloc }, c.rlocName || c.rloc, c.rlocName ? h('span', { class: 'dim' }, ' ' + c.rloc) : null) : h('span', { class: 'dim' }, 'border (no mapping)'),
          h('span', { class: 'muted', style: 'font-size:12px' }, ageText(c.ageSec) + ' ago'),
          h('span', { class: 'col', style: 'gap:1px' }, h('span', { class: 'mono', style: mono }, c.mac || '—'), c.user || c.sgt ? h('span', { class: 'dim', style: 'font-size:11px' }, [c.user, c.sgt ? `SGT ${c.sgt.value}${c.sgt.name ? ' ' + c.sgt.name : ''}` : ''].filter(Boolean).join(' · ')) : null),
          v.flowsKnown ? h('span', { class: 'mono', style: mono }, c.bytes ? bytes(c.bytes) : '—') : null)))
        : h('span', { class: 'dim', style: 'font-size:12px' }, 'No map cache entries are in use right now.')),
    v.fabricNodes.length ? h('div', { class: 'col', style: 'gap:6px' }, sub('Fabric nodes the endpoints are behind', 'how many map cache entries point at each node (RLOC)'),
      h('div', { class: 'row', style: 'gap:6px;flex-wrap:wrap' }, v.fabricNodes.slice(0, 16).map(n => chip(`${n.name || n.rloc}: ${n.active} in use of ${n.total}`, 'default', n.rloc)))) : null,

    // registration check
    h('div', { class: 'col', style: 'gap:6px' }, sub('Registration check', 'hosts on the ports of this node compared with the addresses it registered'),
      r.missingTotal === 0 && r.staleTotal === 0 ? note(`All ${num(r.matched)} hosts with an address seen on the ports are registered, and every registered address is on a port.`, 'ok', true) : null,
      r.missingTotal ? note(`${num(r.missingTotal)} host${r.missingTotal === 1 ? '' : 's'} on the ports ${r.missingTotal === 1 ? 'is' : 'are'} not registered with the fabric${r.missing.some(m => m.authenticated) ? `, ${num(r.missing.filter(m => m.authenticated).length)} of them authenticated` : ''}. Other nodes cannot reach an address that is not registered.`, r.missing.some(m => m.authenticated) ? 'warn' : 'info', true) : null,
      r.missing.length ? table('minmax(120px,1fr) 100px minmax(140px,1fr) minmax(110px,1fr) minmax(140px,1fr)', 700, ['Address', 'Network', 'MAC address', 'Port', 'Status'],
        r.missing.map(m => h('div', { key: m.vrf + m.ip, class: 'tr' }, h('span', { class: 'mono', style: mono }, m.ip), h('span', null, m.vrf || 'default'), h('span', { class: 'mono', style: mono }, m.mac), h('span', { class: 'mono', style: mono }, ifName(m.ifIndex) || String(m.ifIndex)),
          h('span', { class: m.authenticated ? 'warn' : 'muted', style: 'font-size:12px' }, m.authenticated ? `authenticated${m.user ? ' as ' + m.user : ''}, not registered` : 'seen, not registered')))) : null,
      r.staleTotal ? note(`${num(r.staleTotal)} registered address${r.staleTotal === 1 ? ' is' : 'es are'} not on any port of this node (older than 15 minutes). A host that left, or one that is silent and has aged out of the ARP table; the registration lingers until it expires.`, 'info', true) : null,
      r.stale.length ? table('minmax(120px,1fr) 100px 140px', 420, ['Address', 'Network', 'Registered for'], r.stale.slice(0, 100).map(x => h('div', { key: x.iid + x.ip, class: 'tr' }, h('span', { class: 'mono', style: mono }, x.ip), h('span', null, vn(x.vrf, x.iid)), h('span', { class: 'muted', style: 'font-size:12px' }, ageText(x.ageSec))))) : null),

    // per virtual network
    v.instances.length ? h('div', { class: 'col', style: 'gap:6px' }, sub('Virtual networks', 'map cache size and the map requests and replies of each instance since the node started'),
      table('90px 120px 130px 110px 110px 110px', 620, ['Instance', 'Network', 'Map cache', 'Requests', 'Replies', 'Registers'], v.instances.map(i => h('div', { key: i.iid, class: 'tr' }, h('span', { class: 'mono', style: mono }, String(i.iid)), h('span', null, vn(i.vrf, i.iid)),
        h('span', { class: 'mono', style: mono }, `${num(i.cacheSize)}${i.cacheLimit ? ' / ' + num(i.cacheLimit) : ''}`), h('span', { class: 'mono', style: mono }, num(i.requestsOut)), h('span', { class: 'mono', style: `${mono};${i.requestsOut > 20 && i.repliesIn < i.requestsOut * 0.9 ? 'color:var(--warn)' : ''}` }, num(i.repliesIn)), h('span', { class: 'mono', style: mono }, num(i.registersOut)))))) : null);
}
