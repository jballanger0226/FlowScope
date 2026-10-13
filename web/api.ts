import { session } from './state.js';

export class ApiError extends Error {
  constructor(readonly status: number, message: string, readonly data: any) { super(message); }
}

/** Calls the server. Throws ApiError with the server's plain-language message. */
export async function api<T = any>(method: string, url: string, body?: unknown): Promise<T> {
  const h: Record<string, string> = {};
  if (body !== undefined) h['Content-Type'] = 'application/json';
  if (session.csrf && method !== 'GET') h['X-CSRF-Token'] = session.csrf;
  let r: Response;
  try { r = await fetch(url, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin' }); }
  catch { throw new ApiError(0, 'Could not reach the server. Check your connection.', null); }
  const text = await r.text();
  let data: any = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }
  if (!r.ok) {
    if (r.status === 401 && url !== '/api/auth/login') session.onExpired?.();
    throw new ApiError(r.status, data?.error || `Request failed (${r.status})`, data);
  }
  return data as T;
}
export const get = <T = any>(u: string) => api<T>('GET', u);
export const post = <T = any>(u: string, b: unknown = {}) => api<T>('POST', u, b);
export const put = <T = any>(u: string, b: unknown) => api<T>('PUT', u, b);
export const patch = <T = any>(u: string, b: unknown) => api<T>('PATCH', u, b);
export const del = <T = any>(u: string) => api<T>('DELETE', u);

export function qs(o: Record<string, string | number | boolean | null | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(o)) if (v !== null && v !== undefined && v !== '') p.set(k, String(v));
  const s = p.toString();
  return s ? '?' + s : '';
}

/** Downloads a file produced by a POST (the report export). */
export async function downloadPost(url: string, body: unknown, fallbackName: string): Promise<void> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' };
  if (session.csrf) h['X-CSRF-Token'] = session.csrf;
  const r = await fetch(url, { method: 'POST', headers: h, body: JSON.stringify(body), credentials: 'same-origin' });
  if (!r.ok) { let m = `Export failed (${r.status})`; try { m = (await r.json()).error || m; } catch { /* ignore */ } throw new ApiError(r.status, m, null); }
  const name = /filename="([^"]+)"/.exec(r.headers.get('content-disposition') || '')?.[1] || fallbackName;
  const blob = await r.blob();
  const { download } = await import('./util.js');
  download(name, blob.type, blob);
}
