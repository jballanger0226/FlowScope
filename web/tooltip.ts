/** One floating tooltip shared by every graph. It lives on <body> and is driven straight from pointer events, so redraws of the virtual DOM never fight with it. */

export interface TipRow { color?: string; label: string; value: string }
export interface TipContent { title?: string; /** Smaller line above the rows, such as which graph this is */ sub?: string; rows?: TipRow[]; note?: string }

/** Tooltips by key: normally one ("main"), but linked graphs each get their own so every graph can show its values at once. */
const tips = new Map<string, HTMLDivElement>();
let wired = false;

function node(key: string): HTMLDivElement {
  let el = tips.get(key);
  if (el && el.isConnected) return el;
  el = document.createElement('div');
  el.className = 'tip';
  el.setAttribute('role', 'presentation');
  el.hidden = true;
  document.body.appendChild(el);
  tips.set(key, el);
  if (!wired) {
    wired = true;
    // A tooltip must never outlive the graph it describes: leaving the page or scrolling hides it.
    window.addEventListener('hashchange', () => hideTip());
    window.addEventListener('blur', () => hideTip());
    window.addEventListener('scroll', () => hideTip(), true);
  }
  return el;
}

function fill(t: TipContent, into: HTMLElement): void {
  into.textContent = '';
  if (t.sub) { const d = document.createElement('div'); d.className = 'ts'; d.textContent = t.sub; into.appendChild(d); }
  if (t.title) { const d = document.createElement('div'); d.className = 'tt'; d.textContent = t.title; into.appendChild(d); }
  for (const r of t.rows ?? []) {
    const d = document.createElement('div'); d.className = 'tr2';
    if (r.color) { const sw = document.createElement('i'); sw.className = 'sw'; sw.style.background = r.color; d.appendChild(sw); }
    const k = document.createElement('span'); k.className = 'tk'; k.textContent = r.label; d.appendChild(k);
    const v = document.createElement('b'); v.className = 'tv'; v.textContent = r.value; d.appendChild(v);
    into.appendChild(d);
  }
  if (t.note) { const d = document.createElement('div'); d.className = 'tn'; d.textContent = t.note; into.appendChild(d); }
}

/** Shows the tooltip next to the pointer, flipping to stay inside the window. */
export function showTip(t: TipContent, clientX: number, clientY: number, key = 'main'): void {
  const n = node(key);
  fill(t, n);
  n.hidden = false;
  const gap = 14, w = n.offsetWidth, hgt = n.offsetHeight;
  let x = clientX + gap, y = clientY + gap;
  if (x + w > window.innerWidth - 8) x = Math.max(8, clientX - gap - w);
  if (y + hgt > window.innerHeight - 8) y = Math.max(8, clientY - gap - hgt);
  n.style.left = x + 'px';
  n.style.top = y + 'px';
}

/** Hides one tooltip, or all of them when no key is given. */
export function hideTip(key?: string): void {
  if (key !== undefined) { const t = tips.get(key); if (t) t.hidden = true; return; }
  for (const t of tips.values()) t.hidden = true;
}
