/** Number, size and time formatting used across the interface. */

export function bytes(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0, v = Math.abs(n);
  while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
  return (n < 0 ? '-' : '') + (i === 0 ? String(Math.round(v)) : v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)) + ' ' + u[i];
}
export function bps(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '—';
  const u = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
  let i = 0, v = n;
  while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
  return (v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)) + ' ' + u[i];
}
export function num(n: number | null | undefined): string { return n === null || n === undefined || !Number.isFinite(n) ? '—' : Math.round(n).toLocaleString('en-US'); }
export function pct(n: number | null | undefined, d = 1): string { return n === null || n === undefined || !Number.isFinite(n) ? '—' : n.toFixed(d) + '%'; }
export function ms(n: number | null | undefined): string { return n === null || n === undefined ? '—' : n < 1 ? '<1 ms' : n.toFixed(n < 10 ? 1 : 0) + ' ms'; }

const p2 = (n: number) => String(n).padStart(2, '0');
export function clock(t: number, secs = true): string { const d = new Date(t); return `${p2(d.getHours())}:${p2(d.getMinutes())}${secs ? ':' + p2(d.getSeconds()) : ''}`; }
export function stamp(t: number): string { const d = new Date(t); return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`; }
export function dayClock(t: number): string {
  const d = new Date(t), now = new Date();
  return d.toDateString() === now.toDateString() ? clock(t) : `${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${clock(t, false)}`;
}
export function dur(msec: number): string {
  const s = Math.round(msec / 1000);
  if (s < 1) return '<1 s';
  if (s < 60) return s + ' s';
  if (s < 3600) return Math.floor(s / 60) + ' min ' + (s % 60 ? (s % 60) + ' s' : '');
  if (s < 86400) return Math.floor(s / 3600) + ' h ' + Math.floor((s % 3600) / 60) + ' min';
  return Math.floor(s / 86400) + ' d ' + Math.floor((s % 86400) / 3600) + ' h';
}
export function ago(t: number | null | undefined): string {
  if (!t) return 'never';
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 5) return 'just now';
  if (s < 60) return s + ' s ago';
  if (s < 3600) return Math.round(s / 60) + ' min ago';
  if (s < 86400) return Math.round(s / 3600) + ' h ago';
  return Math.round(s / 86400) + ' d ago';
}
export function days(n: number): string {
  if (n < 14) return n + ' day' + (n === 1 ? '' : 's');
  if (n < 60) return Math.round(n / 7) + ' weeks';
  if (n < 730) return (n / 30.4).toFixed(n < 365 ? 0 : 1).replace(/\.0$/, '') + ' months';
  return (n / 365).toFixed(1).replace(/\.0$/, '') + ' years';
}
export const RANGES: [string, string][] = [['15m', 'Last 15 minutes'], ['1h', 'Last hour'], ['6h', 'Last 6 hours'], ['24h', 'Last 24 hours'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days']];
export function download(name: string, type: string, body: Blob | string): void {
  const url = URL.createObjectURL(typeof body === 'string' ? new Blob([body], { type }) : body);
  const a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
export function debounce<A extends unknown[]>(fn: (...a: A) => void, ms2: number): (...a: A) => void {
  let t: number | undefined;
  return (...a: A) => { window.clearTimeout(t); t = window.setTimeout(() => fn(...a), ms2); };
}
