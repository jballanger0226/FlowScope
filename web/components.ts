import { h, type Child, type VNode } from './vdom.js';
import { redraw } from './state.js';

export type Kind = 'default' | 'primary' | 'ghost' | 'danger' | 'warn';
const cls = (...a: (string | false | null | undefined)[]) => a.filter(Boolean).join(' ');

export function btn(label: Child, o: { onclick?: (e: Event) => void; kind?: Kind; pressed?: boolean; disabled?: boolean; title?: string; small?: boolean; type?: string; cls?: string; aria?: string } = {}): VNode {
  return h('button', {
    class: cls('btn', o.kind && o.kind !== 'default' && o.kind, o.small && 'small', o.cls), type: o.type ?? 'button', onclick: o.onclick, disabled: o.disabled, title: o.title,
    'aria-pressed': o.pressed === undefined ? undefined : o.pressed, 'aria-label': o.aria
  }, label);
}

/** A row of buttons where one or more can be on. */
export function seg(label: string, items: { id: string; label: Child; on: boolean; disabled?: boolean; title?: string }[], pick: (id: string) => void, extra = ''): VNode {
  return h('div', { class: cls('seg', extra), role: 'group', 'aria-label': label }, items.map(i => h('button', { key: i.id, type: 'button', class: 'segbtn', 'aria-pressed': i.on, disabled: i.disabled, title: i.title, onclick: () => pick(i.id) }, i.label)));
}

export function field(label: Child, input: VNode, hint?: Child): VNode {
  return h('label', { class: 'field' }, h('span', { class: 'flabel' }, label), input, hint ? h('span', { class: 'hint' }, hint) : null);
}

export function textInput(value: string, oninput: (v: string) => void, o: { placeholder?: string; type?: string; aria?: string; disabled?: boolean; autocomplete?: string; mono?: boolean; onenter?: () => void; width?: string; id?: string; maxlength?: number } = {}): VNode {
  return h('input', {
    class: cls('input', o.mono && 'mono'), type: o.type ?? 'text', value, placeholder: o.placeholder, 'aria-label': o.aria, disabled: o.disabled, id: o.id,
    autocomplete: o.autocomplete ?? 'off', spellcheck: 'false', maxlength: o.maxlength, style: o.width ? `width:${o.width}` : undefined,
    oninput: (e: Event) => { oninput((e.target as HTMLInputElement).value); redraw(); },
    onkeydown: o.onenter ? (e: KeyboardEvent) => { if (e.key === 'Enter') o.onenter!(); } : undefined
  });
}
export function numberInput(value: number | string, oninput: (v: string) => void, o: { min?: number; max?: number; aria?: string; disabled?: boolean; width?: string } = {}): VNode {
  return h('input', { class: 'input mono', type: 'number', value: String(value), min: o.min, max: o.max, 'aria-label': o.aria, disabled: o.disabled, style: `width:${o.width ?? '96px'}`, oninput: (e: Event) => { oninput((e.target as HTMLInputElement).value); redraw(); } });
}
export function textArea(value: string, oninput: (v: string) => void, o: { rows?: number; placeholder?: string; aria?: string; id?: string } = {}): VNode {
  return h('textarea', { class: 'input mono', rows: o.rows ?? 4, value, placeholder: o.placeholder, 'aria-label': o.aria, id: o.id, spellcheck: 'false', autocomplete: 'off', oninput: (e: Event) => { oninput((e.target as HTMLTextAreaElement).value); redraw(); } });
}
export function select(value: string, options: [string, string][], onchange: (v: string) => void, o: { aria?: string; disabled?: boolean; width?: string } = {}): VNode {
  return h('select', { class: 'input', value, 'aria-label': o.aria, disabled: o.disabled, style: o.width ? `width:${o.width}` : undefined, onchange: (e: Event) => { onchange((e.target as HTMLSelectElement).value); redraw(); } },
    options.map(([v, l]) => h('option', { key: v, value: v }, l)));
}
/** An on/off switch drawn as a button, with its state in words. */
export function toggle(label: Child, on: boolean, onclick: () => void, o: { onText?: string; offText?: string; disabled?: boolean } = {}): VNode {
  return h('button', { type: 'button', class: 'toggle', 'aria-pressed': on, disabled: o.disabled, onclick }, h('span', null, label), h('span', { class: 'tstate' }, on ? o.onText ?? 'On' : o.offText ?? 'Off'));
}

export function chip(text: Child, kind: 'default' | 'ok' | 'warn' | 'bad' | 'info' | 'accent' | 'violet' = 'default', title?: string): VNode { return h('span', { class: 'chip ' + kind, title }, text); }
export function dot(kind: 'ok' | 'warn' | 'bad' | 'off' | 'info'): VNode { return h('span', { class: 'dot ' + kind, 'aria-hidden': 'true' }); }
export function status(kind: 'ok' | 'warn' | 'bad' | 'off' | 'info', text: string): VNode { return h('span', { class: 'status ' + kind }, dot(kind), text); }

export function note(text: Child, kind: 'info' | 'warn' | 'bad' | 'ok' = 'info', live = false): VNode { return text ? h('div', { class: 'note ' + kind, role: live ? 'status' : undefined }, text) : h('span'); }
export function msg(text: string, kind: 'ok' | 'bad' | '' = ''): VNode { return h('span', { class: 'msg ' + kind, 'aria-live': 'polite' }, text); }

export function kv(rows: [Child, Child][]): VNode {
  return h('div', { class: 'kvs' }, rows.map(([k, v], i) => h('div', { key: i, class: 'kv' }, h('span', { class: 'k' }, k), h('span', { class: 'v' }, v))));
}

export function heading(eyebrow: string, title: string, blurb?: Child): VNode {
  return h('div', { class: 'heading' }, h('span', { class: 'eyebrow' }, eyebrow), h('h2', null, title), blurb ? h('p', { class: 'blurb' }, blurb) : null);
}

export function stat(label: string, value: Child, sub?: Child): VNode { return h('div', { class: 'stat' }, h('div', { class: 'slabel' }, label), h('div', { class: 'svalue' }, value), sub ? h('div', { class: 'ssub' }, sub) : null); }

export function bar(value: number, max = 100, kind: 'auto' | 'ok' | 'warn' | 'bad' | 'accent' = 'auto'): VNode {
  const p = Math.max(0, Math.min(100, (value / max) * 100));
  const k = kind === 'auto' ? (p >= 90 ? 'bad' : p >= 70 ? 'warn' : 'accent') : kind;
  return h('span', { class: 'bar', 'aria-hidden': 'true' }, h('span', { class: 'barfill ' + k, style: `width:${p}%` }));
}

export function tabs(label: string, items: { id: string; label: string; on: boolean }[], pick: (id: string) => void): VNode {
  return h('div', { class: 'tabs', role: 'tablist', 'aria-label': label }, items.map(i => h('button', { key: i.id, type: 'button', role: 'tab', class: 'tab', 'aria-selected': i.on, onclick: () => pick(i.id) }, i.label)));
}

export function empty(text: string): VNode { return h('div', { class: 'empty' }, text); }
export function spinner(text = 'Loading…'): VNode { return h('div', { class: 'empty', role: 'status' }, text); }

/* ------------------------------------------------------------------ line charts */

export interface Series { name: string; color: string; points: { t: number; v: number }[] }
export const PALETTE = ['var(--s1)', 'var(--s2)', 'var(--s3)', 'var(--s4)', 'var(--s5)', 'var(--s6)', 'var(--s7)', 'var(--s8)'];

/** A line chart drawn with SVG. Shaded bands mark time spans (events). */
export function lineChart(o: { title: string; unit: (v: number) => string; series: Series[]; from: number; to: number; yMax?: number; threshold?: number; bands?: { a: number; b: number }[]; aria: string; fmtT: (t: number) => string; wide?: boolean }): VNode {
  const W = o.wide ? 1100 : 520, H = 190, L = 64, R = 10, T = 8, B = 22;
  const all = o.series.flatMap(s => s.points.map(p => p.v));
  const maxV = o.yMax ?? Math.max(o.threshold ?? 0, ...all, 1e-9) * 1.1;
  const x = (t: number) => L + ((t - o.from) / Math.max(1, o.to - o.from)) * (W - L - R);
  const y = (v: number) => T + (1 - Math.min(1, v / maxV)) * (H - T - B);
  const grid = [0, 0.25, 0.5, 0.75, 1].map(f => f * maxV);
  const xt = [0, 0.25, 0.5, 0.75, 1].map(f => o.from + f * (o.to - o.from));
  return h('figure', { class: 'chart' },
    h('figcaption', null, o.title),
    h('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': o.aria, class: 'chartsvg', style: `aspect-ratio:${W}/${H}` },
      grid.map((g, i) => h('g', { key: 'g' + i }, h('line', { x1: L, x2: W - R, y1: y(g), y2: y(g), class: 'gridline' }), h('text', { x: L - 6, y: y(g) + 4, class: 'axis', 'text-anchor': 'end' }, o.unit(g)))),
      (o.bands ?? []).map((b, i) => h('rect', { key: 'b' + i, x: x(Math.max(o.from, b.a)), y: T, width: Math.max(2, x(Math.min(o.to, b.b)) - x(Math.max(o.from, b.a))), height: H - T - B, class: 'band' })),
      o.threshold !== undefined ? h('line', { x1: L, x2: W - R, y1: y(o.threshold), y2: y(o.threshold), class: 'thr' }) : null,
      o.series.map((s, i) => s.points.length ? h('polyline', { key: 's' + i, fill: 'none', style: `stroke:${s.color}`, 'stroke-width': 1.8, 'stroke-linejoin': 'round', points: s.points.map(p => `${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join(' ') }) : null),
      xt.map((t, i) => h('text', { key: 'x' + i, x: x(t), y: H - 6, class: 'axis', 'text-anchor': i === 0 ? 'start' : i === xt.length - 1 ? 'end' : 'middle' }, o.fmtT(t)))));
}
