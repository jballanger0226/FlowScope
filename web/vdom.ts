/** A very small virtual DOM: h() builds a tree, mount() patches the real DOM to match it, so inputs keep focus between redraws. */

export type Child = VNode | string | number | boolean | null | undefined | Child[];
export type Props = Record<string, any>;
export interface VNode { tag: string; props: Props; kids: VNode[]; key?: string | number; text?: string; el?: Node }

const SVG_NS = 'http://www.w3.org/2000/svg';

function flat(children: Child[], out: VNode[]): VNode[] {
  for (const c of children) {
    if (c === null || c === undefined || c === false || c === true) continue;
    if (Array.isArray(c)) flat(c, out);
    else if (typeof c === 'object') out.push(c);
    else out.push({ tag: '#text', props: {}, kids: [], text: String(c) });
  }
  return out;
}

export function h(tag: string, props?: Props | null, ...children: Child[]): VNode {
  const p = props ?? {};
  const { key, ...rest } = p;
  return { tag, props: rest, kids: flat(children, []), key };
}

const BOOL = new Set(['disabled', 'checked', 'selected', 'readonly', 'required', 'multiple', 'open', 'hidden', 'autofocus']);
const PROP_ONLY = new Set(['value', 'checked', 'selected', 'disabled', 'indeterminate']);

function setProp(el: Element, name: string, value: any, old: any, svg: boolean): void {
  if (name === 'ref') return;
  if (name.startsWith('on') && name.length > 2) { (el as any)[name.toLowerCase()] = value ?? null; return; }
  if (name === 'class' || name === 'className') { if (value) el.setAttribute('class', value); else el.removeAttribute('class'); return; }
  if (name === 'style') {
    if (typeof value === 'object' && value) { (el as HTMLElement).style.cssText = ''; Object.assign((el as HTMLElement).style, value); }
    else if (value) el.setAttribute('style', value); else el.removeAttribute('style');
    return;
  }
  if (PROP_ONLY.has(name) && !svg) {
    const cur = (el as any)[name];
    const next = name === 'value' ? (value ?? '') : !!value;
    if (cur !== next) (el as any)[name] = next;
    if (name === 'disabled') { if (next) el.setAttribute('disabled', ''); else el.removeAttribute('disabled'); }
    return;
  }
  if (BOOL.has(name)) { if (value) el.setAttribute(name, ''); else el.removeAttribute(name); return; }
  if (value === null || value === undefined || value === false) { el.removeAttribute(name); return; }
  if (name === 'aria-pressed' || name === 'aria-selected' || name === 'aria-current' || name === 'aria-expanded') { el.setAttribute(name, String(value)); return; }
  const v = String(value);
  if (old !== value || el.getAttribute(name) !== v) el.setAttribute(name, v);
}

function applyProps(el: Element, next: Props, prev: Props, svg: boolean): void {
  for (const k of Object.keys(prev)) if (!(k in next) && k !== 'value') setProp(el, k, null, prev[k], svg);
  // value goes last: <select> needs its options first
  for (const k of Object.keys(next)) if (k !== 'value') { if (next[k] !== prev[k] || PROP_ONLY.has(k) || k.startsWith('on')) setProp(el, k, next[k], prev[k], svg); }
  if ('value' in next) setProp(el, 'value', next.value, prev.value, svg);
}

function create(v: VNode, svgParent: boolean): Node {
  if (v.tag === '#text') { const t = document.createTextNode(v.text!); v.el = t; return t; }
  const isSvg = svgParent || v.tag === 'svg';
  const el = isSvg ? document.createElementNS(SVG_NS, v.tag) : document.createElement(v.tag);
  v.el = el;
  applyProps(el, v.props, {}, isSvg);
  for (const k of v.kids) el.appendChild(create(k, isSvg && v.tag !== 'foreignObject'));
  if ('value' in v.props) setProp(el, 'value', v.props.value, undefined, isSvg);
  if (v.props.ref) v.props.ref(el);
  return el;
}

function sameKind(a: VNode, b: VNode): boolean { return a.tag === b.tag && a.key === b.key; }

function patch(parent: Node, a: VNode | undefined, b: VNode, svgParent: boolean): Node {
  if (!a || !a.el) { const n = create(b, svgParent); parent.appendChild(n); return n; }
  return update(a, b, svgParent);
}

function update(a: VNode, b: VNode, svgParent: boolean): Node {
  const el = a.el!;
  if (b.tag === '#text') { if (a.text !== b.text) (el as Text).data = b.text!; b.el = el; return el; }
  b.el = el;
  const isSvg = svgParent || b.tag === 'svg';
  applyProps(el as Element, b.props, a.props, isSvg);
  patchKids(el, a.kids, b.kids, isSvg && b.tag !== 'foreignObject');
  if ('value' in b.props) setProp(el as Element, 'value', b.props.value, a.props.value, isSvg);
  if (b.props.ref) b.props.ref(el);
  return el;
}

function patchKids(el: Node, oldK: VNode[], newK: VNode[], svg: boolean): void {
  const keyed = newK.some(k => k.key !== undefined) || oldK.some(k => k.key !== undefined);
  if (!keyed) {
    const n = Math.min(oldK.length, newK.length);
    for (let i = 0; i < n; i++) {
      if (sameKind(oldK[i], newK[i])) update(oldK[i], newK[i], svg);
      else { const nn = create(newK[i], svg); el.replaceChild(nn, oldK[i].el!); }
    }
    for (let i = n; i < newK.length; i++) el.appendChild(create(newK[i], svg));
    for (let i = n; i < oldK.length; i++) el.removeChild(oldK[i].el!);
    return;
  }
  const byKey = new Map<string | number, VNode>();
  const unkeyed: VNode[] = [];
  for (const o of oldK) { if (o.key !== undefined) byKey.set(o.key, o); else unkeyed.push(o); }
  const used = new Set<VNode>();
  let ref: Node | null = el.firstChild;
  for (const nv of newK) {
    let ov: VNode | undefined;
    if (nv.key !== undefined) { ov = byKey.get(nv.key); if (ov && ov.tag !== nv.tag) ov = undefined; } else ov = unkeyed.find(u => !used.has(u) && u.tag === nv.tag);
    let node: Node;
    if (ov) { used.add(ov); node = update(ov, nv, svg); } else node = create(nv, svg);
    if (node !== ref) el.insertBefore(node, ref); else ref = ref.nextSibling;
  }
  for (const o of oldK) if (!used.has(o)) { if (o.el && o.el.parentNode === el) el.removeChild(o.el); }
}

let current: VNode | null = null;

/** Draws the tree into a container, reusing what is already there. */
export function mount(container: HTMLElement, tree: VNode): void {
  if (!current || current.tag !== tree.tag) { container.textContent = ''; current = tree; container.appendChild(create(tree, false)); return; }
  update(current, tree, false);
  current = tree;
}
