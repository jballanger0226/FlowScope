import crypto from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';

/**
 * A small ACME client (RFC 8555) built on node:crypto, so FlowScope needs no extra package. It speaks to any ACME directory:
 * Let's Encrypt and other public CAs, or an internal CA such as step-ca. External account binding (RFC 8555 section 7.3.4) is supported.
 * This file is only the protocol. What to ask for, which challenge to answer and where the result goes is decided by AcmeService.
 */

export class AcmeError extends Error {
  constructor(message: string, readonly type = '', readonly status = 0, readonly sub: string[] = []) { super(message); }
}

export interface Resp { status: number; headers: http.IncomingHttpHeaders; body: Buffer }

const MAX_BODY = 2_000_000;
const b64u = (b: Buffer | string): string => Buffer.from(b).toString('base64url');

/** One HTTP(S) request. A CA certificate (PEM) can be given for a CA that has its own root; the usual public roots stay trusted too. */
export function request(url: string, o: { method?: string; headers?: Record<string, string>; body?: Buffer | string; caPem?: string; timeoutMs?: number } = {}): Promise<Resp> {
  return new Promise((resolve, reject) => {
    let u: URL;
    try { u = new URL(url); } catch { reject(new AcmeError(`"${url}" is not a valid address`)); return; }
    const secure = u.protocol === 'https:';
    if (!secure && u.protocol !== 'http:') { reject(new AcmeError(`"${url}" is not an http or https address`)); return; }
    const body = o.body === undefined ? undefined : Buffer.from(o.body);
    const req = (secure ? https : http).request(u, {
      method: o.method || 'GET', headers: { 'user-agent': 'FlowScope-ACME', ...(body ? { 'content-length': String(body.length) } : {}), ...o.headers },
      ...(secure ? { ca: o.caPem ? [...tls.rootCertificates, o.caPem] : undefined, minVersion: 'TLSv1.2' as const } : {})
    }, res => {
      const chunks: Buffer[] = []; let size = 0;
      res.on('data', (c: Buffer) => { size += c.length; if (size > MAX_BODY) { req.destroy(new AcmeError('The reply was larger than expected')); return; } chunks.push(c); });
      res.on('end', () => resolve({ status: res.statusCode || 0, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', reject);
    });
    req.setTimeout(o.timeoutMs ?? 30_000, () => req.destroy(new AcmeError(`${u.host} did not answer within ${Math.round((o.timeoutMs ?? 30_000) / 1000)} seconds`)));
    req.on('error', e => reject(e instanceof AcmeError ? e : new AcmeError(`Could not reach ${u.host}: ${(e as NodeJS.ErrnoException).code || e.message}`)));
    req.end(body);
  });
}

export interface Directory { newNonce: string; newAccount: string; newOrder: string; meta?: { termsOfService?: string; externalAccountRequired?: boolean } }
export interface Identifier { type: 'dns' | 'ip'; value: string }
export interface Challenge { type: string; url: string; token: string; status: string; error?: Problem }
export interface Authorization { identifier: Identifier; status: string; wildcard?: boolean; challenges: Challenge[]; expires?: string }
export interface Order { status: string; expires?: string; identifiers: Identifier[]; authorizations: string[]; finalize: string; certificate?: string; error?: Problem }
export interface Problem { type?: string; detail?: string; subproblems?: { identifier?: Identifier; detail?: string }[] }

export interface AcmeOpts {
  directoryUrl: string; caPem?: string; timeoutMs?: number;
  /** Pause between checks while the CA works, and how many checks to make before giving up. */
  pollMs?: number; maxPolls?: number;
}

/** Plain words for the problem types a person is most likely to meet. The CA's own detail text is always kept. */
function problemText(p: Problem, status: number): string {
  const t = (p.type || '').replace(/^urn:ietf:params:acme:error:/, '');
  const hint: Record<string, string> = {
    rateLimited: 'The CA is limiting how often certificates can be requested. Wait before trying again, or use the CA\'s staging address while testing.',
    unauthorized: 'The CA could not confirm this server controls the name.',
    connection: 'The CA could not connect to this server to check the challenge.',
    dns: 'The CA could not look the name up in DNS.',
    caa: 'A CAA record in DNS stops this CA from issuing for the name.',
    rejectedIdentifier: 'The CA will not issue for this name. Public CAs only issue for public domains you own, not names such as .local or .lan.',
    invalidContact: 'The CA did not accept the contact e-mail address.',
    externalAccountRequired: 'This CA needs an external account key id and HMAC key (from the CA) to register.',
    accountDoesNotExist: 'The CA does not know this account any more. It will be registered again.'
  };
  const subs = (p.subproblems || []).map(s => (s.identifier ? s.identifier.value + ': ' : '') + (s.detail || '')).filter(Boolean);
  return [p.detail || `The CA answered HTTP ${status}`, t && hint[t] ? hint[t] : '', subs.length ? subs.join('; ') : ''].filter(Boolean).join(' ');
}

export class AcmeClient {
  private dir: Directory | null = null;
  private nonces: string[] = [];
  private key: crypto.KeyObject | null = null;
  kid: string | null = null;
  readonly pollMs: number; readonly maxPolls: number;

  constructor(private o: AcmeOpts) { this.pollMs = o.pollMs ?? 2000; this.maxPolls = o.maxPolls ?? 90; }

  /** Account key (ES256, P-256) and, once registered, the account URL. */
  setAccount(key: crypto.KeyObject, kid: string | null = null): void { this.key = key; this.kid = kid; }
  static newAccountKey(): crypto.KeyObject { return crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey; }

  private req(url: string, o: Parameters<typeof request>[1] = {}): Promise<Resp> { return request(url, { ...o, caPem: this.o.caPem, timeoutMs: this.o.timeoutMs }); }

  async directory(): Promise<Directory> {
    if (this.dir) return this.dir;
    const r = await this.req(this.o.directoryUrl);
    if (r.status !== 200) throw new AcmeError(`${this.o.directoryUrl} is not an ACME directory (HTTP ${r.status})`);
    let d: Directory;
    try { d = JSON.parse(r.body.toString('utf8')) as Directory; } catch { throw new AcmeError(`${this.o.directoryUrl} did not return an ACME directory. Check the address; it usually ends in /directory.`); }
    if (!d.newNonce || !d.newAccount || !d.newOrder) throw new AcmeError(`${this.o.directoryUrl} did not return an ACME directory. Check the address; it usually ends in /directory.`);
    return (this.dir = d);
  }

  private async nonce(): Promise<string> {
    const n = this.nonces.pop();
    if (n) return n;
    const d = await this.directory();
    const r = await this.req(d.newNonce, { method: 'HEAD' });
    const nn = r.headers['replay-nonce'];
    if (!nn) throw new AcmeError('The CA did not give a nonce');
    return String(nn);
  }

  jwk(): { kty: string; crv: string; x: string; y: string } {
    if (!this.key) throw new AcmeError('No account key');
    const j = crypto.createPublicKey(this.key).export({ format: 'jwk' }) as { kty: string; crv: string; x: string; y: string };
    return { crv: j.crv, kty: j.kty, x: j.x, y: j.y };
  }
  thumbprint(): string { return b64u(crypto.createHash('sha256').update(JSON.stringify(this.jwk())).digest()); }
  /** The text the CA expects back for a challenge token (RFC 8555 section 8.1). */
  keyAuthorization(token: string): string { return `${token}.${this.thumbprint()}`; }
  /** The TXT record value for a dns-01 challenge. */
  dnsValue(token: string): string { return b64u(crypto.createHash('sha256').update(this.keyAuthorization(token)).digest()); }

  /** A signed POST. A null payload is a "POST-as-GET". The nonce is refreshed and the call repeated once if the CA says it was stale. */
  async post(url: string, payload: unknown | null, useJwk = false, tries = 0, accept = 'application/json'): Promise<Resp & { json: any }> {
    if (!this.key) throw new AcmeError('No account key');
    const prot = b64u(JSON.stringify({ alg: 'ES256', nonce: await this.nonce(), url, ...(useJwk || !this.kid ? { jwk: this.jwk() } : { kid: this.kid }) }));
    const pay = payload === null ? '' : b64u(JSON.stringify(payload));
    const sig = crypto.sign('sha256', Buffer.from(`${prot}.${pay}`), { key: this.key, dsaEncoding: 'ieee-p1363' });
    const r = await this.req(url, { method: 'POST', headers: { 'content-type': 'application/jose+json', accept }, body: JSON.stringify({ protected: prot, payload: pay, signature: b64u(sig) }) });
    const nn = r.headers['replay-nonce']; if (nn) this.nonces.push(String(nn));
    let json: any = null;
    const ct = String(r.headers['content-type'] || '');
    if (/json/.test(ct)) { try { json = JSON.parse(r.body.toString('utf8')); } catch { json = null; } }
    if (r.status >= 400) {
      const p = (json || {}) as Problem;
      if (/:badNonce$/.test(p.type || '') && tries < 2) return this.post(url, payload, useJwk, tries + 1, accept);
      throw new AcmeError(problemText(p, r.status), p.type || '', r.status, (p.subproblems || []).map(s => s.detail || ''));
    }
    return { ...r, json };
  }

  /** Registers an account, or finds the one that already exists for this key. Returns the account URL. */
  async register(o: { email?: string; tosAgreed: boolean; eab?: { kid: string; hmacKey: string } }): Promise<string> {
    const d = await this.directory();
    if (d.meta?.externalAccountRequired && !o.eab) throw new AcmeError('This CA needs an external account key id and HMAC key (from the CA) to register.', 'externalAccountRequired');
    const payload: Record<string, unknown> = { termsOfServiceAgreed: o.tosAgreed };
    if (o.email) payload.contact = [`mailto:${o.email}`];
    if (o.eab) {
      const p = b64u(JSON.stringify({ alg: 'HS256', kid: o.eab.kid, url: d.newAccount })), pl = b64u(JSON.stringify(this.jwk()));
      payload.externalAccountBinding = { protected: p, payload: pl, signature: b64u(crypto.createHmac('sha256', Buffer.from(o.eab.hmacKey, 'base64')).update(`${p}.${pl}`).digest()) };
    }
    const r = await this.post(d.newAccount, payload, true);
    const loc = r.headers.location;
    if (!loc) throw new AcmeError('The CA did not return an account address');
    this.kid = String(loc);
    return this.kid;
  }

  async newOrder(ids: Identifier[]): Promise<{ url: string; order: Order }> {
    const d = await this.directory();
    const r = await this.post(d.newOrder, { identifiers: ids });
    const url = r.headers.location;
    if (!url) throw new AcmeError('The CA did not return an order address');
    return { url: String(url), order: r.json as Order };
  }

  async authorization(url: string): Promise<Authorization> { return (await this.post(url, null)).json as Authorization; }

  /** Tells the CA the challenge is ready to be checked. */
  async triggerChallenge(url: string): Promise<void> { await this.post(url, {}); }

  private async wait<T extends { status: string }>(label: string, fetchIt: () => Promise<T>, done: (x: T) => boolean, failed: (x: T) => string | null): Promise<T> {
    for (let i = 0; i < this.maxPolls; i++) {
      const x = await fetchIt();
      const f = failed(x); if (f) throw new AcmeError(f);
      if (done(x)) return x;
      await new Promise(res => setTimeout(res, this.pollMs));
    }
    throw new AcmeError(`The CA did not finish ${label} in time`);
  }

  /** Waits until the CA has checked the challenge. Throws with the CA's own explanation when it failed. */
  async waitAuthorization(url: string): Promise<Authorization> {
    return this.wait('checking the challenge', () => this.authorization(url), a => a.status === 'valid', a => {
      if (a.status !== 'invalid' && a.status !== 'revoked' && a.status !== 'deactivated' && a.status !== 'expired') return null;
      const ch = a.challenges.find(c => c.error) ?? a.challenges[0];
      return `The CA could not verify ${a.identifier.value}. ${ch?.error ? problemText(ch.error, 0) : 'Status: ' + a.status}`;
    });
  }

  /** Sends the signing request, waits for the certificate to be made and returns it with its chain as PEM. */
  async finalize(orderUrl: string, order: Order, csrDer: Buffer): Promise<string> {
    let cur = order;
    if (cur.status === 'pending') cur = await this.wait('preparing the order', async () => (await this.post(orderUrl, null)).json as Order, o => o.status === 'ready' || o.status === 'valid', o => (o.status === 'invalid' ? 'The CA rejected the order. ' + (o.error ? problemText(o.error, 0) : '') : null));
    if (cur.status === 'ready') cur = (await this.post(order.finalize, { csr: b64u(csrDer) })).json as Order;
    if (cur.status !== 'valid') cur = await this.wait('issuing the certificate', async () => (await this.post(orderUrl, null)).json as Order, o => o.status === 'valid', o => (o.status === 'invalid' ? 'The CA could not issue the certificate. ' + (o.error ? problemText(o.error, 0) : '') : null));
    if (!cur.certificate) throw new AcmeError('The CA did not return a certificate address');
    const r = await this.post(cur.certificate, null, false, 0, 'application/pem-certificate-chain');
    const pem = r.body.toString('utf8');
    if (!/-----BEGIN CERTIFICATE-----/.test(pem)) throw new AcmeError('The CA did not return a certificate');
    return pem;
  }
}
