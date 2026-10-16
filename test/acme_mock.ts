import crypto from 'node:crypto';
import http from 'node:http';
import net from 'node:net';

type JsonWebKey = Record<string, string>;
import * as d from '../src/tls/der.js';
import { generateKey } from '../src/tls/x509.js';

/** A small ACME server (and a Cloudflare DNS API) for the tests. It checks what a real CA checks: the signature of every request, its nonce and URL, external account binding and the challenges. */

const b64u = (b: Buffer | string) => Buffer.from(b).toString('base64url');
const unb64u = (s: string) => Buffer.from(s, 'base64url');

interface Tlv { tag: number; start: number; hlen: number; end: number; raw: Buffer }
function readTlv(b: Buffer, o: number): Tlv {
  const tag = b[o]!; let l = b[o + 1]!; let h = 2;
  if (l & 0x80) { const n = l & 0x7f; l = 0; for (let i = 0; i < n; i++) l = l * 256 + b[o + 2 + i]!; h = 2 + n; }
  return { tag, start: o, hlen: h, end: o + h + l, raw: b.subarray(o, o + h + l) };
}
function kids(b: Buffer, t: Tlv): Tlv[] { const out: Tlv[] = []; let o = t.start + t.hlen; while (o < t.end) { const k = readTlv(b, o); out.push(k); o = k.end; } return out; }

interface Authz { id: number; identifier: { type: string; value: string }; wildcard: boolean; status: 'pending' | 'processing' | 'valid' | 'invalid'; token: string; error?: unknown }
interface Order { id: number; identifiers: { type: string; value: string }[]; authz: Authz[]; status: 'pending' | 'ready' | 'valid'; cert?: string; csrSans?: string[] }

export class MockAcme {
  private server!: http.Server; private cf!: http.Server;
  port = 0; cfPort = 0;
  get base(): string { return `http://127.0.0.1:${this.port}`; }
  get directory(): string { return this.base + '/directory'; }
  get cloudflare(): string { return `http://127.0.0.1:${this.cfPort}`; }

  /** Where the CA looks for HTTP-01 answers (the identifier is a name, which in the test resolves to this port on the loopback). */
  httpPort = 0;
  /** TXT records by name; filled by tests (manual DNS) or by the Cloudflare API below. */
  txt = new Map<string, Set<string>>();
  requireEab: { kid: string; hmac: Buffer } | null = null;
  badNonceOnce = false;
  newAccounts = 0; orders = 0; tosRequired = false;
  requests: string[] = [];
  cfZone = 'example.test'; cfToken = 'cf-token'; cfCalls: string[] = [];
  private nonces = new Set<string>();
  private accounts = new Map<string, JsonWebKey>();
  private orderMap = new Map<number, Order>(); private authzMap = new Map<number, Authz>(); private n = 0;
  private caKey!: crypto.KeyObject; private caPem = '';
  /** The order of the last finalize, so a test can look at the names the CSR asked for. */
  lastCsrNames: string[] = [];

  async start(): Promise<void> {
    this.caKey = await generateKey('ecdsa-p256');
    this.caPem = this.makeCa();
    this.server = http.createServer((q, r) => void this.handle(q, r));
    await new Promise<void>(res => this.server.listen(0, '127.0.0.1', () => res()));
    this.port = (this.server.address() as net.AddressInfo).port;
    this.cf = http.createServer((q, r) => this.handleCf(q, r));
    await new Promise<void>(res => this.cf.listen(0, '127.0.0.1', () => res()));
    this.cfPort = (this.cf.address() as net.AddressInfo).port;
  }
  /** A self-signed CA certificate that is allowed to sign: CA:TRUE and the keyCertSign usage. */
  private makeCa(): string {
    const pub = crypto.createPublicKey(this.caKey).export({ type: 'spki', format: 'der' });
    const alg = d.seq(d.oid('1.2.840.10045.4.3.2'));
    const name = d.seq(d.set(d.seq(d.oid('2.5.4.10'), d.utf8('FlowScope tests'))), d.set(d.seq(d.oid('2.5.4.3'), d.utf8('Test ACME CA'))));
    const exts = [d.seq(d.oid('2.5.29.19'), d.bool(true), d.octets(d.seq(d.bool(true)))), d.seq(d.oid('2.5.29.15'), d.bool(true), d.octets(d.bitString(Buffer.from([0x06]), 1)))];
    const tbs = d.seq(d.ctx(0, d.int(2)), d.int(crypto.randomBytes(12)), alg, name, d.seq(d.time(new Date(Date.now() - 3600_000)), d.time(new Date(Date.now() + 3650 * 86400_000))), name, pub, d.ctx(3, d.seq(...exts)));
    return d.toPem('CERTIFICATE', d.seq(tbs, alg, d.bitString(crypto.sign('sha256', tbs, this.caKey))));
  }
  async stop(): Promise<void> { for (const s of [this.server, this.cf]) await new Promise<void>(res => { s.close(() => res()); s.closeAllConnections?.(); }); }

  private nonce(): string { const n = crypto.randomBytes(12).toString('base64url'); this.nonces.add(n); return n; }
  private send(r: http.ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
    const isPem = typeof body === 'string';
    r.writeHead(status, { 'replay-nonce': this.nonce(), 'content-type': isPem ? 'application/pem-certificate-chain' : status >= 400 ? 'application/problem+json' : 'application/json', ...headers });
    r.end(body === undefined ? undefined : isPem ? body : JSON.stringify(body));
  }
  private problem(r: http.ServerResponse, status: number, type: string, detail: string): void { this.send(r, status, { type: 'urn:ietf:params:acme:error:' + type, detail }); }

  private thumb(jwk: JsonWebKey): string { return b64u(crypto.createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest()); }

  private async handle(q: http.IncomingMessage, r: http.ServerResponse): Promise<void> {
    const url = q.url || '/'; this.requests.push(`${q.method} ${url}`);
    if (url === '/directory') return this.send(r, 200, { newNonce: this.base + '/nonce', newAccount: this.base + '/new-acct', newOrder: this.base + '/new-order', meta: { externalAccountRequired: !!this.requireEab, termsOfService: this.base + '/tos' } });
    if (url === '/nonce') return this.send(r, q.method === 'HEAD' ? 200 : 204, undefined);
    const chunks: Buffer[] = []; for await (const c of q) chunks.push(c as Buffer);
    let jws: { protected: string; payload: string; signature: string };
    try { jws = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return this.problem(r, 400, 'malformed', 'Not JSON'); }
    if (q.headers['content-type'] !== 'application/jose+json') return this.problem(r, 415, 'malformed', 'Content-Type must be application/jose+json');
    const head = JSON.parse(unb64u(jws.protected).toString('utf8')) as { alg: string; nonce: string; url: string; jwk?: JsonWebKey; kid?: string };
    if (this.badNonceOnce) { this.badNonceOnce = false; return this.problem(r, 400, 'badNonce', 'Stale nonce'); }
    if (!this.nonces.delete(head.nonce)) return this.problem(r, 400, 'badNonce', 'Unknown or reused nonce');
    if (head.url !== this.base + url) return this.problem(r, 400, 'malformed', `url in the protected header (${head.url}) does not match the request (${this.base + url})`);
    if (head.alg !== 'ES256') return this.problem(r, 400, 'badSignatureAlgorithm', 'Only ES256 here');
    if (!!head.jwk === !!head.kid) return this.problem(r, 400, 'malformed', 'Exactly one of jwk and kid');
    const jwk = head.jwk ?? this.accounts.get(head.kid!);
    if (!jwk) return this.problem(r, 400, 'accountDoesNotExist', 'No such account');
    const ok = crypto.verify('sha256', Buffer.from(`${jws.protected}.${jws.payload}`), { key: crypto.createPublicKey({ key: jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, unb64u(jws.signature));
    if (!ok) return this.problem(r, 403, 'unauthorized', 'The signature does not verify');
    const payload = jws.payload === '' ? null : JSON.parse(unb64u(jws.payload).toString('utf8'));

    if (url === '/new-acct') {
      if (!head.jwk) return this.problem(r, 400, 'malformed', 'new-acct needs jwk');
      if (this.tosRequired && payload.termsOfServiceAgreed !== true) return this.problem(r, 403, 'userActionRequired', 'Agree to the terms of service');
      if (this.requireEab) {
        const e = payload.externalAccountBinding as { protected: string; payload: string; signature: string } | undefined;
        if (!e) return this.problem(r, 400, 'externalAccountRequired', 'External account binding is required');
        const h = JSON.parse(unb64u(e.protected).toString('utf8'));
        const mac = crypto.createHmac('sha256', this.requireEab.hmac).update(`${e.protected}.${e.payload}`).digest();
        if (h.kid !== this.requireEab.kid || h.alg !== 'HS256' || h.url !== this.base + '/new-acct' || !crypto.timingSafeEqual(mac, unb64u(e.signature))) return this.problem(r, 403, 'unauthorized', 'External account binding failed');
        if (this.thumb(JSON.parse(unb64u(e.payload).toString('utf8'))) !== this.thumb(jwk)) return this.problem(r, 400, 'malformed', 'EAB payload is not the account key');
      }
      const kid = `${this.base}/acct/${++this.n}`; this.accounts.set(kid, jwk); this.newAccounts++;
      return this.send(r, 201, { status: 'valid', contact: payload.contact }, { location: kid });
    }
    if (!head.kid) return this.problem(r, 400, 'malformed', 'kid required');

    if (url === '/new-order') {
      const ids = payload.identifiers as { type: string; value: string }[];
      const id = ++this.orders; const authz: Authz[] = [];
      for (const i of ids) {
        const wildcard = i.value.startsWith('*.');
        const a: Authz = { id: ++this.n, identifier: { type: i.type, value: wildcard ? i.value.slice(2) : i.value }, wildcard, status: 'pending', token: crypto.randomBytes(16).toString('base64url') };
        this.authzMap.set(a.id, a); authz.push(a);
      }
      const o: Order = { id, identifiers: ids, authz, status: 'pending' }; this.orderMap.set(id, o);
      return this.send(r, 201, this.orderJson(o), { location: `${this.base}/order/${id}` });
    }
    let m: RegExpExecArray | null;
    if ((m = /^\/authz\/(\d+)$/.exec(url))) { const a = this.authzMap.get(Number(m[1])); return a ? this.send(r, 200, this.authzJson(a)) : this.problem(r, 404, 'malformed', 'no such authz'); }
    if ((m = /^\/chall\/(\d+)\/(http-01|dns-01)$/.exec(url))) {
      const a = this.authzMap.get(Number(m[1])); if (!a) return this.problem(r, 404, 'malformed', 'no such challenge');
      a.status = 'processing'; setTimeout(() => void this.validate(a, m![2] as 'http-01' | 'dns-01', jwk), 20);
      return this.send(r, 200, { type: m[2], url: this.base + url, status: 'processing', token: a.token });
    }
    if ((m = /^\/order\/(\d+)$/.exec(url))) { const o = this.orderMap.get(Number(m[1])); if (!o) return this.problem(r, 404, 'malformed', 'no such order'); return this.send(r, 200, this.orderJson(o)); }
    if ((m = /^\/finalize\/(\d+)$/.exec(url))) {
      const o = this.orderMap.get(Number(m[1]))!; this.refresh(o);
      if (o.status !== 'ready') return this.problem(r, 403, 'orderNotReady', 'The order is not ready');
      try { o.cert = this.issue(unb64u(payload.csr), o); } catch (e) { return this.problem(r, 400, 'badCSR', (e as Error).message); }
      o.status = 'valid';
      return this.send(r, 200, this.orderJson(o), { location: `${this.base}/order/${o.id}` });
    }
    if ((m = /^\/cert\/(\d+)$/.exec(url))) {
      if (!String(q.headers.accept || '').includes('application/pem-certificate-chain')) return this.problem(r, 406, 'malformed', 'Accept application/pem-certificate-chain');
      return this.send(r, 200, this.orderMap.get(Number(m[1]))!.cert!);
    }
    return this.problem(r, 404, 'malformed', 'unknown ' + url);
  }

  private authzJson(a: Authz) {
    const ch = (type: string) => ({ type, url: `${this.base}/chall/${a.id}/${type}`, token: a.token, status: a.status === 'invalid' ? 'invalid' : a.status, ...(a.error ? { error: a.error } : {}) });
    return { identifier: a.identifier, status: a.status, wildcard: a.wildcard || undefined, challenges: a.wildcard || a.identifier.type === 'dns' ? (a.identifier.type === 'ip' ? [ch('http-01')] : a.wildcard ? [ch('dns-01')] : [ch('http-01'), ch('dns-01')]) : [ch('http-01')] };
  }
  private refresh(o: Order): void { if (o.status === 'pending' && o.authz.every(a => a.status === 'valid')) o.status = 'ready'; }
  private orderJson(o: Order) {
    this.refresh(o);
    return { status: o.status, identifiers: o.identifiers, authorizations: o.authz.map(a => `${this.base}/authz/${a.id}`), finalize: `${this.base}/finalize/${o.id}`, ...(o.cert ? { certificate: `${this.base}/cert/${o.id}` } : {}) };
  }

  private async validate(a: Authz, type: 'http-01' | 'dns-01', jwk: JsonWebKey): Promise<void> {
    const keyAuth = `${a.token}.${this.thumb(jwk)}`;
    const fail = (type_: string, detail: string) => { a.status = 'invalid'; a.error = { type: 'urn:ietf:params:acme:error:' + type_, detail }; };
    if (type === 'http-01') {
      try {
        const res = await fetch(`http://127.0.0.1:${this.httpPort}/.well-known/acme-challenge/${a.token}`);
        const body = await res.text();
        if (res.status === 200 && body === keyAuth) a.status = 'valid'; else fail('unauthorized', `Invalid response from http://${a.identifier.value}/.well-known/acme-challenge/${a.token}: ${res.status}`);
      } catch (e) { fail('connection', `Could not connect to ${a.identifier.value}: ${(e as Error).message}`); }
    } else {
      const want = b64u(crypto.createHash('sha256').update(keyAuth).digest());
      if (this.txt.get('_acme-challenge.' + a.identifier.value)?.has(want)) a.status = 'valid'; else fail('unauthorized', `No TXT record found at _acme-challenge.${a.identifier.value}`);
    }
  }

  /** Signs a certificate for the key in the CSR with the test CA, for the names in the order. */
  private issue(csrDer: Buffer, o: Order): string {
    const csr = readTlv(csrDer, 0); const info = kids(csrDer, csr)[0]!; const [, subject, spki] = kids(csrDer, info);
    const spkiKey = crypto.createPublicKey({ key: spki!.raw, format: 'der', type: 'spki' });
    // the CSR must carry the names that were ordered
    const names = o.identifiers.map(i => i.value).sort();
    const csrNames = [...csrDer.toString('latin1').matchAll(/[a-z0-9*][a-z0-9.*-]*\.[a-z]+|localhost/g)].map(x => x[0]);
    for (const i of o.identifiers) if (i.type === 'dns' && !csrNames.includes(i.value)) throw new Error(`The CSR does not contain ${i.value}`);
    this.lastCsrNames = names;
    const caDer = d.fromPem(this.caPem)[0]!; const caTbs = kids(caDer, kids(caDer, readTlv(caDer, 0))[0]!); const caSubject = caTbs[5]!.raw;
    const ipb = (ip: string) => Buffer.from(ip.split('.').map(Number));
    const general = o.identifiers.map(i => (i.type === 'ip' ? d.ctxPrim(7, ipb(i.value)) : d.ctxPrim(2, Buffer.from(i.value, 'ascii'))));
    const alg = d.seq(d.oid('1.2.840.10045.4.3.2'));
    const tbs = d.seq(d.ctx(0, d.int(2)), d.int(crypto.randomBytes(12)), alg, caSubject, d.seq(d.time(new Date(Date.now() - 60_000)), d.time(new Date(Date.now() + 90 * 86400_000))), subject!.raw, spki!.raw,
      d.ctx(3, d.seq(d.seq(d.oid('2.5.29.19'), d.bool(true), d.octets(d.seq())), d.seq(d.oid('2.5.29.37'), d.octets(d.seq(d.oid('1.3.6.1.5.5.7.3.1')))), d.seq(d.oid('2.5.29.17'), d.octets(d.seq(...general))))));
    void spkiKey;
    const sig = crypto.sign('sha256', tbs, this.caKey);
    return d.toPem('CERTIFICATE', d.seq(tbs, alg, d.bitString(sig))) + this.caPem;
  }

  private handleCf(q: http.IncomingMessage, r: http.ServerResponse): void {
    const reply = (status: number, result: unknown, errors: { message: string }[] = []) => { r.writeHead(status, { 'content-type': 'application/json' }); r.end(JSON.stringify({ success: status < 400, result, errors })); };
    this.cfCalls.push(`${q.method} ${q.url}`);
    if (q.headers.authorization !== `Bearer ${this.cfToken}`) return reply(403, null, [{ message: 'Invalid token' }]);
    const u = new URL(q.url || '/', 'http://x');
    if (q.method === 'GET' && u.pathname === '/zones') return reply(200, u.searchParams.get('name') === this.cfZone ? [{ id: 'zone1', name: this.cfZone }] : []);
    const chunks: Buffer[] = []; q.on('data', c => chunks.push(c as Buffer)); q.on('end', () => {
      if (q.method === 'POST' && u.pathname === '/zones/zone1/dns_records') {
        const b = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { type: string; name: string; content: string };
        const set = this.txt.get(b.name) ?? new Set<string>(); set.add(b.content); this.txt.set(b.name, set);
        const id = `rec${++this.n}`; this.cfRecords.set(id, b); return reply(200, { id });
      }
      let m: RegExpExecArray | null;
      if (q.method === 'DELETE' && (m = /^\/zones\/zone1\/dns_records\/(rec\d+)$/.exec(u.pathname))) {
        const rec = this.cfRecords.get(m[1]!); if (rec) { this.txt.get(rec.name)?.delete(rec.content); this.cfRecords.delete(m[1]!); }
        return reply(200, { id: m[1] });
      }
      reply(404, null, [{ message: 'not found' }]);
    });
  }
  cfRecords = new Map<string, { type: string; name: string; content: string }>();
}
