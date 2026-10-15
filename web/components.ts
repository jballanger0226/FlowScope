import { h, type Child, type VNode } from './vdom.js';
import { redraw } from './state.js';
import { MAX_RANGE_DAYS, UNITS, stamp } from './util.js';
import { hideTip, showTip, type TipRow } from './tooltip.js';

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
/**
 * A time range: the usual presets, or "Custom…" with a number and a unit (minutes, hours, days).
 * `id` keeps the custom state of this picker apart from the pickers on other pages.
 */
const customOn = new Set<string>();
const draft = new Map<string, { n: string; unit: string }>();
export function rangePicker(id: string, value: string, presets: [string, string][], onchange: (v: string) => void, o: { aria?: string } = {}): VNode {
  const m = /^(\d+)([mhd])$/.exec(value);
  const isPreset = presets.some(p => p[0] === value);
  const custom = customOn.has(id) || !isPreset;
  const d = draft.get(id) ?? (m ? { n: m[1], unit: m[2] } : { n: '1', unit: 'h' });
  const maxFor = (unit: string) => Math.floor(MAX_RANGE_DAYS * 86_400_000 / UNITS.find(u => u[0] === unit)![2]);
  const invalid = () => { const n = Number(d.n); return !(d.n.trim() !== '' && Number.isInteger(n) && n >= 1 && n <= maxFor(d.unit)); };
  const bad = invalid();
  // the value is checked when it is applied, not when the page was last drawn; a repeat of the current value (change, then Enter) asks for nothing
  const apply = () => { draft.set(id, d); if (!invalid() && d.n + d.unit !== value) onchange(d.n + d.unit); redraw(); };
  return h('span', { class: 'row', style: 'gap:8px;flex-wrap:nowrap' },
    select(custom ? 'custom' : value, [...presets, ['custom', 'Custom…']], v => {
      if (v === 'custom') { customOn.add(id); draft.set(id, d); } else { customOn.delete(id); draft.delete(id); onchange(v); }
    }, { aria: o.aria, width: '150px' }),
    custom ? [
      h('input', { class: 'input mono', type: 'number', min: 1, max: maxFor(d.unit), value: d.n, 'aria-label': (o.aria ?? 'Time range') + ': length', 'aria-invalid': bad ? 'true' : undefined, style: 'width:84px',
        oninput: (e: Event) => { d.n = (e.target as HTMLInputElement).value; draft.set(id, d); redraw(); },
        onchange: apply, onkeydown: (e: KeyboardEvent) => { if (e.key === 'Enter') apply(); } }),
      select(d.unit, UNITS.map(u => [u[0], u[1]] as [string, string]), v => { d.unit = v; draft.set(id, d); apply(); }, { aria: (o.aria ?? 'Time range') + ': unit', width: '104px' }),
      bad ? h('span', { class: 'muted', role: 'status', style: 'font-size:12px' }, `Enter a whole number from 1 to ${num2(maxFor(d.unit))} (the limit is ${MAX_RANGE_DAYS} days)`) : null
    ] : null);
}
const num2 = (n: number) => n.toLocaleString('en-US');

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

/* ------------------------------------------------------------------ chart grid */

/** Last measured width of the chart grid and height of the window. Charts are drawn at the size they will be shown, so tall, wide and ultrawide windows all get graphs that fit. */
const gridBox = { cw: 0, vh: 0 };
const GAP = 16, CHART_PAD = 26, CAPTION = 24, MIN_W = 300, MIN_H = 140, MAX_H = 320;

function measure(el: Element): boolean {
  // A grid that is not on the page yet (or is hidden) has no width to go by.
  if (!el.isConnected || !el.clientWidth) return false;
  const cw = Math.floor(el.clientWidth), vh = window.innerHeight;
  const changed = Math.abs(cw - gridBox.cw) >= 2 || Math.abs(vh - gridBox.vh) >= 2;
  if (changed) { gridBox.cw = cw; gridBox.vh = vh; }
  return changed;
}

/**
 * Lays out `count` charts so they fit the space: side by side when the window is wide enough (all in one row on an ultrawide),
 * two by two on a normal screen, stacked on a narrow one. Heights follow the window height so a whole set of graphs can be seen at once.
 * `make` receives the pixel size to draw each chart at.
 */
export function chartGrid(count: number, make: (size: { w: number; h: number }) => (VNode | null)[]): VNode {
  const cw = gridBox.cw || 1100, vh = gridBox.vh || window.innerHeight;
  const cols = count <= 1 ? 1 : cw >= count * 440 + (count - 1) * GAP ? count : cw >= 820 ? 2 : 1;
  const rows = Math.ceil(count / cols);
  const w = Math.max(MIN_W, Math.floor((cw - GAP * (cols - 1)) / cols) - CHART_PAD);
  const ch = Math.round(Math.min(MAX_H, Math.max(MIN_H, (vh - 170) / rows - CAPTION - 24)));
  return h('div', {
    class: 'charts', style: `--cols:${cols}`,
    ref: (el: Element) => {
      const e = el as any;
      if (!e.__ro && typeof ResizeObserver !== 'undefined') {
        e.__ro = new ResizeObserver(() => { if (measure(el)) redraw(); });
        e.__ro.observe(el);
        // The window height changes the chart height without changing the grid width.
        e.__onResize = () => { if (!el.isConnected) { window.removeEventListener('resize', e.__onResize); return; } if (measure(el)) redraw(); };
        window.addEventListener('resize', e.__onResize);
      }
      if (measure(el)) requestAnimationFrame(redraw);
    }
  }, make({ w, h: ch }));
}

/** A line chart drawn with SVG. Shaded bands mark time spans (events). */
export function lineChart(o: { title: string; unit: (v: number) => string; series: Series[]; from: number; to: number; yMax?: number; threshold?: number; bands?: { a: number; b: number }[]; aria: string; fmtT: (t: number) => string; /** Precise value text for the hover readout (defaults to unit) */ fmtV?: (v: number) => string; /** Full timestamp for the hover readout */ fmtFull?: (t: number) => string; /** Charts sharing this name on a page follow each other's hover: pointing at one marks the same moment on the rest */ sync?: string; /** Drawing size in CSS pixels, so text stays true to size at any window shape (see chartGrid) */ w?: number; h?: number; wide?: boolean }): VNode {
  const W = Math.round(o.w ?? (o.wide ? 1100 : 520)), H = Math.round(o.h ?? 190), L = 76, R = 10, T = 8, B = 22;
  const all = o.series.flatMap(s => s.points.map(p => p.v));
  const maxV = o.yMax ?? Math.max(o.threshold ?? 0, ...all, 1e-9) * 1.1;
  const x = (t: number) => L + ((t - o.from) / Math.max(1, o.to - o.from)) * (W - L - R);
  const y = (v: number) => T + (1 - Math.min(1, v / maxV)) * (H - T - B);
  const grid = [0, 0.25, 0.5, 0.75, 1].map(f => f * maxV);
  const xt = [0, 0.25, 0.5, 0.75, 1].map(f => o.from + f * (o.to - o.from));
  return h('figure', { class: 'chart' },
    h('figcaption', null, o.title),
    h('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': o.aria, class: 'chartsvg', 'data-sync': o.sync, style: `aspect-ratio:${W}/${H}`, ref: (el: Element) => { (el as any).__lc = { o, g: { W, L, R, x, y } }; } },
      grid.map((g, i) => h('g', { key: 'g' + i }, h('line', { x1: L, x2: W - R, y1: y(g), y2: y(g), class: 'gridline' }), h('text', { x: L - 6, y: y(g) + 4, class: 'axis', 'text-anchor': 'end' }, o.unit(g)))),
      (o.bands ?? []).map((b, i) => h('rect', { key: 'b' + i, x: x(Math.max(o.from, b.a)), y: T, width: Math.max(2, x(Math.min(o.to, b.b)) - x(Math.max(o.from, b.a))), height: H - T - B, class: 'band' })),
      o.threshold !== undefined ? h('line', { key: 'thr', x1: L, x2: W - R, y1: y(o.threshold), y2: y(o.threshold), class: 'thr' }) : null,
      o.series.map((s, i) => s.points.length ? h('polyline', { key: 's' + i, fill: 'none', style: `stroke:${s.color}`, 'stroke-width': 1.8, 'stroke-linejoin': 'round', points: s.points.map(p => `${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join(' ') }) : null),
      xt.map((t, i) => h('text', { key: 'x' + i, x: x(t), y: H - 6, class: 'axis', 'text-anchor': i === 0 ? 'start' : i === xt.length - 1 ? 'end' : 'middle' }, o.fmtT(t))),
      // Hover tracking: a guide line and one dot per series that follow the pointer. They start hidden and are moved directly, not through a redraw.
      h('line', { key: 'hl', class: 'hoverline', y1: T, y2: H - B, x1: L, x2: L, visibility: 'hidden' }),
      o.series.map((s, i) => h('circle', { key: 'd' + i, class: 'hoverdot', r: 4, cx: L, cy: T, visibility: 'hidden', style: `stroke:${s.color};fill:var(--panel)` })),
      h('rect', {
        key: 'hz', class: 'hoverzone', x: L, y: T, width: W - L - R, height: H - T - B, fill: 'transparent',
        onpointermove: (e: PointerEvent) => hoverChart(e),
        onpointerdown: (e: PointerEvent) => hoverChart(e),
        onpointerleave: hoverOff,
        onpointercancel: hoverOff
      })));
}

type ChartOpts = Parameters<typeof lineChart>[0];

/** Index of the point nearest to time t in a time-ordered list. */
function nearest(pts: { t: number }[], t: number): number {
  let lo = 0, hi = pts.length - 1;
  while (lo < hi) { const m = (lo + hi) >> 1; if (pts[m].t < t) lo = m + 1; else hi = m; }
  return lo > 0 && Math.abs(pts[lo - 1].t - t) <= Math.abs(pts[lo].t - t) ? lo - 1 : lo;
}

/** The usual time between samples, so a point far from the pointer (a gap in the data) is not reported as if it were here. */
function typicalStep(pts: { t: number }[]): number {
  if (pts.length < 2) return Infinity;
  const d: number[] = [];
  for (let i = 1; i < pts.length; i++) d.push(pts[i].t - pts[i - 1].t);
  d.sort((a, b) => a - b);
  return Math.max(1, d[d.length >> 1]);
}

interface LC { o: ChartOpts; g: { W: number; L: number; R: number; x: (t: number) => number; y: (v: number) => number } }
const lcOf = (svg: Element): LC | undefined => (svg as any).__lc;

/** Puts the guide line at time t and a dot on each series' sample nearest to it. Returns the readout rows, or null when no series has data there. */
type MRow = TipRow & { n: number };
function mark(svg: Element, t: number, always: boolean): MRow[] | null {
  const lc = lcOf(svg);
  if (!lc) return null;
  const { o, g } = lc;
  const dots = svg.querySelectorAll<SVGCircleElement>('.hoverdot');
  const rows: MRow[] = [];
  o.series.forEach((s, i) => {
    const dot = dots[i];
    const show = (on: boolean) => { if (dot) dot.setAttribute('visibility', on ? 'visible' : 'hidden'); };
    if (!s.points.length) { show(false); return; }
    const p = s.points[nearest(s.points, t)];
    if (Math.abs(p.t - t) > typicalStep(s.points) * 1.5) { show(false); return; }
    rows.push({ color: s.color, label: s.name, value: (o.fmtV ?? o.unit)(p.v), n: p.v });
    if (dot) { dot.setAttribute('cx', g.x(p.t).toFixed(1)); dot.setAttribute('cy', g.y(p.v).toFixed(1)); }
    show(true);
  });
  const line = svg.querySelector('.hoverline');
  if (rows.length || (always && t >= o.from && t <= o.to)) {
    const lx = g.x(t).toFixed(1);
    line?.setAttribute('x1', lx); line?.setAttribute('x2', lx); line?.setAttribute('visibility', 'visible');
  } else line?.setAttribute('visibility', 'hidden');
  return rows.length ? rows : null;
}

function clear(svg: Element): void {
  svg.querySelector('.hoverline')?.setAttribute('visibility', 'hidden');
  svg.querySelectorAll('.hoverdot').forEach(d => d.setAttribute('visibility', 'hidden'));
}

/** The other charts in the same sync group as this one, if it has one. */
function siblings(svg: Element): Element[] {
  const grp = svg.getAttribute('data-sync');
  if (!grp) return [];
  return Array.from(svg.ownerDocument.querySelectorAll('svg.chartsvg[data-sync]')).filter(x => x !== svg && x.getAttribute('data-sync') === grp);
}

function hoverChart(e: PointerEvent): void {
  const svg = (e.currentTarget as SVGElement).ownerSVGElement;
  const lc = svg && lcOf(svg);
  if (!svg || !lc) return;
  const { o, g } = lc;
  const box = svg.getBoundingClientRect();
  if (!box.width) return;
  const vx = (e.clientX - box.left) * (g.W / box.width);
  const tCursor = o.from + ((vx - g.L) / Math.max(1, g.W - g.L - g.R)) * (o.to - o.from);
  // Snap to the sample closest to the pointer on any series, so the guide sits on real data.
  let snapT: number | null = null, best = Infinity;
  for (const s of o.series) {
    if (!s.points.length) continue;
    const p = s.points[nearest(s.points, tCursor)];
    const dist = Math.abs(p.t - tCursor);
    if (dist < best) { best = dist; snapT = p.t; }
  }
  const rows = snapT === null ? null : mark(svg, snapT, false);
  if (snapT === null || !rows) { hoverOff(e); return; }
  // Every graph in the group answers for the same moment. Each readout lives inside its own graph, beside its own guide line,
  // so the readouts never land on one another. The graph under the pointer follows the pointer's height.
  readout(svg, snapT, rows, e.clientY, 'main');
  for (const other of siblings(svg)) {
    const key = tipKey(other);
    const orows = mark(other, snapT, true);
    const b = other.getBoundingClientRect();
    if (!orows || !b.width || b.bottom < 0 || b.top > window.innerHeight) { hideTip(key); continue; }
    readout(other, snapT, orows, b.top + 10, key);
  }
}

let tipSeq = 0;
const tipKey = (svg: Element): string => ((svg as any).__tipKey ??= 'c' + tipSeq++);

/** Fits the rows to the room a graph has: identical values collapse to one line, and the rest are cut to the biggest few plus a count. */
function compact(rows: MRow[], room: number, fmt: (v: number) => string): TipRow[] {
  if (rows.length > 3 && rows.every(r => r.value === rows[0].value)) return [{ label: `All ${rows.length} series`, value: rows[0].value }];
  if (rows.length <= room) return rows;
  const sorted = [...rows].sort((a, b) => b.n - a.n);
  const rest = sorted.slice(room - 1);
  return [...sorted.slice(0, room - 1), { label: `+${rest.length} more`, value: '≤ ' + fmt(rest[0].n) }];
}

function readout(svg: Element, t: number, rows: MRow[], cy: number, key: string): void {
  const lc = lcOf(svg);
  if (!lc) return;
  const { o, g } = lc;
  const box = svg.getBoundingClientRect();
  const cx = box.left + g.x(t) * (box.width / g.W);
  const inBand = (o.bands ?? []).some(b => t >= b.a && t <= b.b);
  // About 70px of the box goes on the heading, time and note; each row is about 18px.
  const room = Math.max(2, Math.floor((box.height - 28 - 70) / 18));
  showTip({ sub: o.title, title: (o.fmtFull ?? stamp)(t), rows: compact(rows, room, o.fmtV ?? o.unit), note: inBand ? 'Inside a shaded drop period' : undefined }, cx, cy, key, box);
}

function hoverOff(e: Event): void {
  const svg = (e.currentTarget as SVGElement).ownerSVGElement;
  if (svg) { clear(svg); for (const other of siblings(svg)) clear(other); }
  hideTip();
}
