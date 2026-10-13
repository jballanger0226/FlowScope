/**
 * A small, strict XML reader and exclusive canonicalisation (xml-exc-c14n, without comments), written for checking SAML signatures.
 * It refuses anything that makes XML risky (DOCTYPE, entity declarations, processing instructions inside the document) instead of trying to cope with it.
 */

export class XmlError extends Error {}

export interface Attr { prefix: string; local: string; ns: string; value: string }
export interface Elem {
  prefix: string; local: string; ns: string;
  attrs: Attr[];
  /** namespace declarations written on this element: prefix ('' for the default namespace) → uri */
  decls: Map<string, string>;
  kids: (Elem | string)[];
  parent: Elem | null;
}

const XML_NS = 'http://www.w3.org/XML/1998/namespace';
const NAME = /^[A-Za-z_][\w.\-]*(?::[A-Za-z_][\w.\-]*)?$/;

function decodeEntities(s: string, _inAttr: boolean): string {
  if (/&(?!(#x[0-9A-Fa-f]+|#[0-9]+|lt|gt|amp|quot|apos);)/.test(s)) throw new XmlError('Unknown or malformed entity reference');
  return s.replace(/&(#x[0-9A-Fa-f]+|#[0-9]+|lt|gt|amp|quot|apos);/g, (_m, e: string) => {
    if (e[0] === '#') {
      const cp = e[1] === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      if (!(cp === 9 || cp === 10 || cp === 13 || (cp >= 0x20 && cp <= 0xd7ff) || (cp >= 0xe000 && cp <= 0xfffd) || (cp >= 0x10000 && cp <= 0x10ffff))) throw new XmlError('Invalid character reference');
      return String.fromCodePoint(cp);
    }
    return ({ lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" } as Record<string, string>)[e];
  });
}

export function parseXml(input: string, maxBytes = 2_000_000): Elem {
  if (input.length > maxBytes) throw new XmlError('The XML document is too large');
  let s = input.replace(/^﻿/, '').replace(/\r\n?/g, '\n');
  if (/<!DOCTYPE|<!ENTITY/i.test(s)) throw new XmlError('DOCTYPE and entity declarations are not accepted');
  let i = 0;
  const n = s.length;
  const ws = () => { while (i < n && /[ \t\n]/.test(s[i])) i++; };
  if (s.startsWith('<?xml')) { const e = s.indexOf('?>'); if (e < 0) throw new XmlError('Bad XML declaration'); i = e + 2; }
  let root: Elem | null = null;
  let cur: Elem | null = null;
  let depth = 0;
  const lookup = (e: Elem | null, prefix: string): string => {
    if (prefix === 'xml') return XML_NS;
    for (let x = e; x; x = x.parent) { const v = x.decls.get(prefix); if (v !== undefined) return v; }
    return '';
  };
  while (i < n) {
    if (s[i] !== '<') {
      const e = s.indexOf('<', i); const end = e < 0 ? n : e;
      const raw = s.slice(i, end);
      if (!cur) { if (raw.trim()) throw new XmlError('Text outside the root element'); }
      else {
        if (/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(raw)) throw new XmlError('Invalid character');
        if (raw.includes(']]>')) throw new XmlError('Bad text');
        cur.kids.push(decodeEntities(raw, false));
      }
      i = end; continue;
    }
    if (s.startsWith('<!--', i)) { const e = s.indexOf('-->', i + 4); if (e < 0) throw new XmlError('Unclosed comment'); i = e + 3; continue; }
    if (s.startsWith('<![CDATA[', i)) {
      const e = s.indexOf(']]>', i + 9); if (e < 0 || !cur) throw new XmlError('Bad CDATA section');
      cur.kids.push(s.slice(i + 9, e)); i = e + 3; continue;
    }
    if (s.startsWith('<?', i)) { if (cur) throw new XmlError('Processing instructions are not accepted'); const e = s.indexOf('?>', i); if (e < 0) throw new XmlError('Bad processing instruction'); i = e + 2; continue; }
    if (s.startsWith('</', i)) {
      const e = s.indexOf('>', i); if (e < 0 || !cur) throw new XmlError('Unexpected closing tag');
      const name = s.slice(i + 2, e).trim();
      const q = cur.prefix ? `${cur.prefix}:${cur.local}` : cur.local;
      if (name !== q) throw new XmlError('Mismatched closing tag');
      cur = cur.parent; depth--; i = e + 1; continue;
    }
    // start tag
    i++;
    const m = /^[^\s/>]+/.exec(s.slice(i, i + 300));
    if (!m || !NAME.test(m[0])) throw new XmlError('Bad element name');
    const qname = m[0]; i += qname.length;
    const raws: { name: string; value: string }[] = [];
    for (;;) {
      ws();
      if (s[i] === '>' || s.startsWith('/>', i)) break;
      const am = /^[^\s=/>]+/.exec(s.slice(i, i + 300));
      if (!am || !NAME.test(am[0])) throw new XmlError('Bad attribute name');
      i += am[0].length; ws();
      if (s[i] !== '=') throw new XmlError('Attribute without a value');
      i++; ws();
      const q = s[i]; if (q !== '"' && q !== "'") throw new XmlError('Attribute value must be quoted');
      const e = s.indexOf(q, i + 1); if (e < 0) throw new XmlError('Unclosed attribute value');
      const rawv = s.slice(i + 1, e);
      if (rawv.includes('<')) throw new XmlError('"<" in an attribute value');
      if (raws.some(r => r.name === am[0])) throw new XmlError('Duplicate attribute');
      raws.push({ name: am[0], value: decodeEntities(rawv.replace(/[\t\n]/g, ' '), true) });
      i = e + 1;
    }
    const [pfx, loc] = qname.includes(':') ? qname.split(':') : ['', qname];
    const el: Elem = { prefix: pfx, local: loc, ns: '', attrs: [], decls: new Map(), kids: [], parent: cur };
    for (const a of raws) {
      if (a.name === 'xmlns') el.decls.set('', a.value);
      else if (a.name.startsWith('xmlns:')) { if (!a.value) throw new XmlError('Empty namespace prefix declaration'); el.decls.set(a.name.slice(6), a.value); }
    }
    el.ns = lookup(el, pfx);
    if (pfx && !el.ns) throw new XmlError(`Undeclared namespace prefix "${pfx}"`);
    for (const a of raws) {
      if (a.name === 'xmlns' || a.name.startsWith('xmlns:')) continue;
      const [ap, al] = a.name.includes(':') ? a.name.split(':') : ['', a.name];
      const ans = ap ? lookup(el, ap) : '';
      if (ap && !ans) throw new XmlError(`Undeclared namespace prefix "${ap}"`);
      el.attrs.push({ prefix: ap, local: al, ns: ans, value: a.value });
    }
    // two attributes that resolve to the same {namespace}local name are not allowed
    const seen = new Set<string>();
    for (const a of el.attrs) { const k = a.ns + '\u0000' + a.local; if (seen.has(k)) throw new XmlError('Duplicate attribute'); seen.add(k); }
    if (cur) cur.kids.push(el); else if (root) throw new XmlError('More than one root element'); else root = el;
    if (++depth > 64) throw new XmlError('The document is nested too deeply');
    if (s.startsWith('/>', i)) { i += 2; depth--; } else { i++; cur = el; }
  }
  if (!root || cur) throw new XmlError('The XML document is incomplete');
  return root;
}

/* ------------------------------------------------------------------ helpers for reading */

export const kidsOf = (e: Elem): Elem[] => e.kids.filter((k): k is Elem => typeof k !== 'string');
export const isEl = (e: Elem, ns: string, local: string): boolean => e.ns === ns && e.local === local;
export const childEls = (e: Elem, ns: string, local: string): Elem[] => kidsOf(e).filter(k => isEl(k, ns, local));
export function child(e: Elem, ns: string, local: string): Elem | null { return childEls(e, ns, local)[0] ?? null; }
export function textOf(e: Elem): string { return e.kids.map(k => (typeof k === 'string' ? k : textOf(k))).join(''); }
export function attrOf(e: Elem, local: string, ns = ''): string | null { return e.attrs.find(a => a.local === local && a.ns === ns)?.value ?? null; }
export function descendants(e: Elem, out: Elem[] = []): Elem[] { for (const k of kidsOf(e)) { out.push(k); descendants(k, out); } return out; }

/* ------------------------------------------------------------------ exclusive canonicalisation */

const escText = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\r/g, '&#xD;');
const escAttr = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;').replace(/\t/g, '&#x9;').replace(/\n/g, '&#xA;').replace(/\r/g, '&#xD;');

function inScope(e: Elem, prefix: string): string | undefined {
  for (let x: Elem | null = e; x; x = x.parent) { const v = x.decls.get(prefix); if (v !== undefined) return v; }
  return undefined;
}

/**
 * Canonical form of one element and everything below it (exclusive c14n, no comments).
 * `skip` is left out (the enveloped signature transform). `inclusive` is the InclusiveNamespaces PrefixList.
 */
export function exc14n(el: Elem, skip: Elem | null = null, inclusive: string[] = []): string {
  const out: string[] = [];
  // namespace declarations already written by the nearest output ancestor
  const walk = (e: Elem, rendered: Map<string, string>): void => {
    const used = new Set<string>([e.prefix]);
    for (const a of e.attrs) if (a.prefix) used.add(a.prefix);
    for (const p of inclusive) used.add(p === '#default' ? '' : p);
    const decls: [string, string][] = [];
    const next = new Map(rendered);
    for (const p of used) {
      if (p === 'xml') continue;
      const uri = inScope(e, p);
      if (p === '') {
        // default namespace: write it when it differs from what is already in effect in the output
        const want = uri ?? '';
        const have = rendered.get('') ?? '';
        if (want !== have) { decls.push(['', want]); next.set('', want); }
      } else if (uri !== undefined && rendered.get(p) !== uri) { decls.push([p, uri]); next.set(p, uri); }
    }
    decls.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    const attrs = e.attrs.slice().sort((a, b) => (a.ns < b.ns ? -1 : a.ns > b.ns ? 1 : a.local < b.local ? -1 : a.local > b.local ? 1 : 0));
    const q = e.prefix ? `${e.prefix}:${e.local}` : e.local;
    out.push('<' + q);
    for (const [p, u] of decls) out.push(p ? ` xmlns:${p}="${escAttr(u)}"` : ` xmlns="${escAttr(u)}"`);
    for (const a of attrs) out.push(` ${a.prefix ? a.prefix + ':' : ''}${a.local}="${escAttr(a.value)}"`);
    out.push('>');
    for (const k of e.kids) {
      if (typeof k === 'string') out.push(escText(k));
      else if (k !== skip) walk(k, next);
    }
    out.push(`</${q}>`);
  };
  walk(el, new Map());
  return out.join('');
}
