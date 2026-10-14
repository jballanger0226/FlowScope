import http from 'node:http';
import net from 'node:net';
import https from 'node:https';
import tls from 'node:tls';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import type { Principal } from '../auth/service.js';
import { AuthError, ROLE_RANK } from '../auth/service.js';
import type { Role } from '../settings.js';

export class HttpError extends Error { constructor(readonly status: number, message: string, readonly extra?: Record<string, unknown>) { super(message); } }

export interface Ctx {
  req: http.IncomingMessage; res: http.ServerResponse;
  method: string; path: string; query: URLSearchParams; params: Record<string, string>;
  principal: Principal | null; ip: string; secure: boolean;
  body<T = Record<string, unknown>>(maxBytes?: number): Promise<T>;
  /** Reads an application/x-www-form-urlencoded body (used by the SAML POST binding). */
  form(maxBytes?: number): Promise<URLSearchParams>;
  redirect(url: string, status?: number): void;
  json(data: unknown, status?: number): void;
  text(data: string, type: string, status?: number, headers?: Record<string, string>): void;
  setCookie(name: string, value: string, opts?: { maxAge?: number; clear?: boolean }): void;
  user(): Principal;
}

export type Handler = (c: Ctx) => Promise<void> | void;
interface Route { method: string; re: RegExp; keys: string[]; role: Role | null; handler: Handler; csrf: boolean }

export interface AuthHooks {
  fromSession(token: string): Principal | null;
  fromToken(token: string): Principal | null;
  basic?(user: string, pass: string, ip: string): Promise<Principal>;
}

export const SESSION_COOKIE = 'fs_sid';

function parseCookies(h: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!h) return out;
  for (const part of h.split(';')) { const i = part.indexOf('='); if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); }
  return out;
}

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.txt': 'text/plain; charset=utf-8', '.map': 'application/json'
};

const PENDING = Symbol('response being written');
type Pending = http.ServerResponse & { [PENDING]?: boolean };

const plainIp = (a: string): string => a.startsWith('::ffff:') ? a.slice(7) : a;

/**
 * The address of the client. With no proxy that is the socket's peer. Behind `hops` proxies, each of which appends the address it
 * received the request from to X-Forwarded-For, the client is the entry `hops` places from the right: everything left of that
 * was written by the client or by a hop we do not control, so it can be anything. A header that is missing or does not hold an
 * address there falls back to the socket's peer, which is the proxy itself.
 */
export function clientAddress(peer: string, forwardedFor: string | string[] | undefined, hops: number): string {
  const socket = plainIp(peer);
  if (hops < 1 || !forwardedFor) return socket;
  const list = (Array.isArray(forwardedFor) ? forwardedFor.join(',') : forwardedFor).split(',').map(s => s.trim()).filter(Boolean);
  const pick = plainIp(list[Math.max(0, list.length - hops)] ?? '');
  return net.isIP(pick) ? pick : socket;
}

export class WebServer {
  private routes: Route[] = [];
  private servers: (http.Server | https.Server)[] = [];
  private tlsServers: https.Server[] = [];
  /** How many reverse proxies stand in front (0 = none, the socket address is used). */
  trustProxy = 0;
  private statics = new Map<string, { etag: string; body: Buffer; gz?: Buffer }>();
  private webRoot: string;

  constructor(private auth: AuthHooks, webRoot: string, private hsts = true) { this.webRoot = path.resolve(webRoot); }

  /** Registers a route. `role` is the least role allowed (null = public). Pattern segments starting with ":" are parameters. */
  route(method: string, pattern: string, role: Role | null, handler: Handler, o: { csrf?: boolean } = {}): void {
    const keys: string[] = [];
    const re = new RegExp('^' + pattern.replace(/\/:([A-Za-z]+)/g, (_m, k) => { keys.push(k); return '/([^/]+)'; }) + '/?$');
    this.routes.push({ method, re, keys, role, handler, csrf: o.csrf !== false });
  }
  get(p: string, role: Role | null, h: Handler) { this.route('GET', p, role, h); }
  post(p: string, role: Role | null, h: Handler, o?: { csrf?: boolean }) { this.route('POST', p, role, h, o); }
  put(p: string, role: Role | null, h: Handler) { this.route('PUT', p, role, h); }
  patch(p: string, role: Role | null, h: Handler) { this.route('PATCH', p, role, h); }
  del(p: string, role: Role | null, h: Handler) { this.route('DELETE', p, role, h); }

  private clientIp(req: http.IncomingMessage): string {
    return clientAddress(req.socket.remoteAddress || '', req.headers['x-forwarded-for'], this.trustProxy);
  }

  private async handle(req: http.IncomingMessage, res: http.ServerResponse, secure: boolean): Promise<void> {
    const url = new URL(req.url || '/', 'http://x');
    const method = (req.method || 'GET').toUpperCase();
    const ip = this.clientIp(req);
    const apiPath = url.pathname.startsWith('/api/');
    const baseHeaders: Record<string, string> = {
      'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'Cross-Origin-Opener-Policy': 'same-origin',
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
    };
    if (secure && this.hsts) baseHeaders['Strict-Transport-Security'] = 'max-age=31536000';
    for (const [k, v] of Object.entries(baseHeaders)) res.setHeader(k, v);
    const cookies: string[] = [];
    let principal: Principal | null = null;
    let viaCookie = false;

    const ctx: Ctx = {
      req, res, method, path: url.pathname, query: url.searchParams, params: {}, principal: null, ip, secure,
      body: async <T,>(max = 1_000_000) => {
        const chunks: Buffer[] = []; let n = 0;
        for await (const c of req) { n += (c as Buffer).length; if (n > max) throw new HttpError(413, 'The request is too large'); chunks.push(c as Buffer); }
        if (!n) return {} as T;
        const ct = String(req.headers['content-type'] || '');
        if (!ct.includes('json')) throw new HttpError(415, 'Send JSON with Content-Type: application/json');
        try { return JSON.parse(Buffer.concat(chunks).toString('utf8')) as T; } catch { throw new HttpError(400, 'The request body is not valid JSON'); }
      },
      form: async (max = 1_000_000) => {
        const chunks: Buffer[] = []; let n = 0;
        for await (const c of req) { n += (c as Buffer).length; if (n > max) throw new HttpError(413, 'The request is too large'); chunks.push(c as Buffer); }
        if (!String(req.headers['content-type'] || '').includes('application/x-www-form-urlencoded')) throw new HttpError(415, 'Send a form (application/x-www-form-urlencoded)');
        return new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
      },
      redirect: (to, status = 302) => { if (cookies.length) res.setHeader('Set-Cookie', cookies); res.setHeader('Cache-Control', 'no-store'); res.setHeader('Location', to); res.writeHead(status); res.end(); },
      json: (data, status = 200) => this.send(req, res, status, JSON.stringify(data), 'application/json; charset=utf-8', cookies, true),
      text: (data, type, status = 200, headers = {}) => { for (const [k, v] of Object.entries(headers)) res.setHeader(k, v); this.send(req, res, status, data, type, cookies, true); },
      setCookie: (name, value, o = {}) => {
        cookies.push(`${name}=${o.clear ? '' : encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Strict${secure ? '; Secure' : ''}${o.clear ? '; Max-Age=0' : o.maxAge ? `; Max-Age=${o.maxAge}` : ''}`);
      },
      user: () => { if (!ctx.principal) throw new HttpError(401, 'Sign in required'); return ctx.principal; }
    };

    try {
      if (!apiPath) { await this.serveStatic(req, res, url.pathname, method, cookies); return; }
      // authentication
      const authz = req.headers.authorization;
      if (authz?.startsWith('Bearer ')) principal = this.auth.fromToken(authz.slice(7).trim());
      else if (authz?.startsWith('Basic ') && this.auth.basic) {
        const [u, ...p] = Buffer.from(authz.slice(6), 'base64').toString('utf8').split(':');
        try { principal = await this.auth.basic(u, p.join(':'), ip); } catch (e) { if (e instanceof AuthError) throw new HttpError(e.status, e.message); throw e; }
      } else {
        const sid = parseCookies(req.headers.cookie)[SESSION_COOKIE];
        if (sid) { principal = this.auth.fromSession(sid); viaCookie = !!principal; }
      }
      ctx.principal = principal;

      let matched: Route | null = null; let pathMatched = false;
      for (const r of this.routes) {
        const m = r.re.exec(url.pathname);
        if (!m) continue;
        pathMatched = true;
        if (r.method !== method) continue;
        r.keys.forEach((k, i) => { ctx.params[k] = decodeURIComponent(m[i + 1]); });
        matched = r; break;
      }
      if (!matched) throw new HttpError(pathMatched ? 405 : 404, pathMatched ? 'Method not allowed' : 'Not found');
      if (matched.role) {
        if (!principal) throw new HttpError(401, 'Sign in required');
        if (ROLE_RANK[principal.role] < ROLE_RANK[matched.role]) throw new HttpError(403, 'Your role does not allow this');
        // A user who must change the password may only do that.
        if (principal.mustChange && !/^\/api\/auth\/(me|logout|password)$/.test(url.pathname)) throw new HttpError(403, 'Change your password first', { mustChange: true });
      }
      if (viaCookie && method !== 'GET' && method !== 'HEAD' && matched.csrf) {
        const origin = req.headers.origin;
        if (origin) { try { if (new URL(origin).host !== req.headers.host) throw new Error(); } catch { throw new HttpError(403, 'Cross-site request blocked'); } }
        const tok = String(req.headers['x-csrf-token'] || '');
        const want = principal!.csrf || '';
        if (!tok || tok.length !== want.length || !crypto.timingSafeEqual(Buffer.from(tok), Buffer.from(want))) throw new HttpError(403, 'Missing or wrong CSRF token. Reload the page.');
      }
      await matched.handler(ctx);
      if (!res.headersSent && !res.writableEnded && !(res as Pending)[PENDING]) throw new HttpError(500, 'The handler did not respond');
    } catch (e) {
      if ((res as Pending)[PENDING]) return;   // a response is already on its way
      if (res.headersSent) { res.end(); return; }
      const he = e instanceof HttpError ? e : e instanceof AuthError ? new HttpError(e.status, e.message) : null;
      if (!he) console.error('Unhandled error on', method, url.pathname, e);
      const status = he?.status ?? ((e as { status?: number }).status && (e as { status?: number }).status! < 500 ? (e as { status: number }).status : 500);
      this.send(req, res, status, JSON.stringify({ error: he ? he.message : status < 500 ? (e as Error).message : 'Internal error', ...(he?.extra ?? {}) }), 'application/json; charset=utf-8', cookies, true);
    }
  }

  /**
   * Writes a response. Bodies worth compressing go through the asynchronous gzip, so a large result does not stop the process
   * (the UDP receive loop shares it). `cache` holds the compressed form of a body that is served again, such as a static file.
   */
  private send(req: http.IncomingMessage, res: http.ServerResponse, status: number, body: string | Buffer, type: string, cookies: string[], noStore: boolean, cache?: { gz?: Buffer }): void {
    if (cookies.length) res.setHeader('Set-Cookie', cookies);
    if (noStore) res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', type);
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(body);
    const head = req.method === 'HEAD';
    const plain = () => { res.writeHead(status, { 'Content-Length': buf.length }); res.end(head ? undefined : buf); };
    const gz = (z: Buffer) => { res.setHeader('Content-Encoding', 'gzip'); res.setHeader('Vary', 'Accept-Encoding'); res.writeHead(status, { 'Content-Length': z.length }); res.end(head ? undefined : z); };
    const ae = String(req.headers['accept-encoding'] || '');
    if (!(buf.length > 1024 && /\bgzip\b/.test(ae) && /json|text|javascript|svg|csv/.test(type))) return plain();
    if (cache?.gz) return gz(cache.gz);
    (res as Pending)[PENDING] = true;
    zlib.gzip(buf, (err, z) => {
      if (res.writableEnded || res.destroyed) return;
      if (err) return plain();
      if (cache) cache.gz = z;
      gz(z);
    });
  }

  private async serveStatic(req: http.IncomingMessage, res: http.ServerResponse, pathname: string, method: string, cookies: string[]): Promise<void> {
    if (method !== 'GET' && method !== 'HEAD') throw new HttpError(405, 'Method not allowed');
    let rel = decodeURIComponent(pathname);
    if (rel.includes('\0')) throw new HttpError(400, 'Bad path');
    if (rel === '/' || rel === '') rel = '/index.html';
    let file = path.resolve(this.webRoot, '.' + rel);
    if (file !== this.webRoot && !file.startsWith(this.webRoot + path.sep)) throw new HttpError(404, 'Not found');
    let st: fs.Stats | null = null;
    try { st = fs.statSync(file); } catch { st = null; }
    if (!st || !st.isFile()) {
      // single-page app: unknown paths without a file extension get the shell
      if (path.extname(rel)) throw new HttpError(404, 'Not found');
      file = path.join(this.webRoot, 'index.html');
      try { st = fs.statSync(file); } catch { throw new HttpError(404, 'The web interface is not installed'); }
    }
    const etag = `W/"${st.size.toString(16)}-${Math.floor(st.mtimeMs).toString(16)}"`;
    res.setHeader('ETag', etag);
    res.setHeader('Cache-Control', file.endsWith('index.html') ? 'no-cache' : 'public, max-age=3600');
    if (req.headers['if-none-match'] === etag) { res.writeHead(304); res.end(); return; }
    // Files are read and compressed once per version of the file (size and modification time), not once per request.
    let hit = this.statics.get(file);
    if (!hit || hit.etag !== etag) {
      hit = { etag, body: fs.readFileSync(file) };
      this.statics.delete(file); this.statics.set(file, hit);
      while (this.statics.size > 256) this.statics.delete(this.statics.keys().next().value as string);
    }
    this.send(req, res, 200, hit.body, MIME[path.extname(file).toLowerCase()] || 'application/octet-stream', cookies, false, hit);
  }

  /** Starts listeners. Returns the bound ports. */
  async listen(o: { host: string; httpsPort?: number; httpPort?: number; tls?: tls.SecureContextOptions | null; redirectToHttps?: boolean }): Promise<{ https?: number; http?: number }> {
    const out: { https?: number; http?: number } = {};
    if (o.tls && o.httpsPort !== undefined) {
      const s = https.createServer({ ...o.tls, minVersion: 'TLSv1.2' }, (req, res) => void this.handle(req, res, true));
      this.tlsServers.push(s); this.servers.push(s);
      out.https = await new Promise<number>((res, rej) => { s.once('error', rej); s.listen(o.httpsPort, o.host, () => res((s.address() as { port: number }).port)); });
    }
    if (o.httpPort !== undefined) {
      const s = http.createServer((req, res) => {
        if (o.redirectToHttps && out.https) {
          const host = String(req.headers.host || '').replace(/:\d+$/, '');
          res.writeHead(308, { Location: `https://${host}${out.https === 443 ? '' : ':' + out.https}${req.url || '/'}` }); res.end(); return;
        }
        void this.handle(req, res, false);
      });
      this.servers.push(s);
      out.http = await new Promise<number>((res, rej) => { s.once('error', rej); s.listen(o.httpPort, o.host, () => res((s.address() as { port: number }).port)); });
    }
    for (const s of this.servers) { s.keepAliveTimeout = 30_000; s.headersTimeout = 20_000; s.requestTimeout = 120_000; }
    return out;
  }

  reloadTls(opts: tls.SecureContextOptions): void { for (const s of this.tlsServers) s.setSecureContext({ ...opts }); }

  async close(): Promise<void> {
    await Promise.all(this.servers.map(s => new Promise<void>(res => { s.close(() => res()); (s as http.Server).closeAllConnections?.(); })));
    this.servers = []; this.tlsServers = [];
  }
}
