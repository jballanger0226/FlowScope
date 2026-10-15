import { h, type VNode } from '../vdom.js';
import { btn, chip } from '../components.js';
import type { Card, Issue, Target } from './overview_logic.js';
export { cards, issues, type Target } from './overview_logic.js';

const TAB_NAME: Record<Target['tab'], string> = { interfaces: 'interface', hardware: 'Hardware', network: 'Neighbours and routing', wifi: 'Wi-Fi' };

export function attentionPanel(all: Issue[], go: (t: Target) => void): VNode {
  if (!all.length) return h('div', { class: 'row', style: 'gap:8px' }, chip('Nothing needs attention', 'ok'), h('span', { class: 'muted', style: 'font-size:12.5px' }, 'Interfaces, hardware and routing are all within their limits.'));
  const shown = all.slice(0, 12);
  return h('div', { class: 'col', style: 'gap:8px' },
    h('div', { class: 'row', style: 'gap:8px' }, h('b', null, 'Needs attention'), chip(String(all.length), all.some(i => i.level === 'bad') ? 'bad' : 'warn')),
    h('ul', { class: 'col', style: 'gap:6px;list-style:none;padding:0;margin:0' }, shown.map((i, n) => h('li', { key: n, class: 'row', style: 'flex-wrap:nowrap;gap:10px;justify-content:space-between;border:1px solid var(--line);border-radius:8px;padding:8px 12px' },
      h('div', { class: 'row', style: 'flex-wrap:nowrap;align-items:flex-start;gap:10px;min-width:0' }, chip(i.level === 'bad' ? 'Problem' : 'Warning', i.level), h('div', { class: 'col', style: 'gap:2px;min-width:0' }, h('span', { style: 'font-weight:600' }, i.title), i.detail ? h('span', { class: 'muted', style: 'font-size:12px' }, i.detail) : null)),
      i.target ? h('span', { style: 'flex:none' }, btn(`Open ${TAB_NAME[i.target.tab]}`, { small: true, kind: 'ghost', onclick: () => go(i.target!) })) : null))),
    all.length > shown.length ? h('span', { class: 'muted', style: 'font-size:12px' }, `${all.length - shown.length} more are listed in the tabs below.`) : null);
}

export function cardsRow(cs: Card[], go: (t: Target) => void): VNode {
  return h('div', { style: 'display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px' }, cs.map(c => h('button', { key: c.tab, type: 'button', class: 'cardbtn', title: `Open ${c.label}`, onclick: () => go({ tab: c.tab }) },
    h('span', { class: 't' }, c.label),
    h('span', { class: 's', style: c.level === 'bad' ? 'color:var(--bad)' : c.level === 'warn' ? 'color:var(--warn)' : undefined }, c.headline),
    ...c.lines.map(l => h('span', { class: 'muted', style: 'font-size:12px' }, l)))));
}
