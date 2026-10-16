import crypto from 'node:crypto';
import http from 'node:http';
import type { Settings, DEFAULTS } from '../settings.js';
import type { Secrets } from '../secrets.js';
import type { AppLog } from '../logger.js';
import { AcmeClient, AcmeError, type Identifier } from './acme.js';
import { Cloudflare, challengeName, type DnsProvider } from './acme_dns.js';
import { buildCsr, generateKey, parseSans, type KeyType } from './x509.js';
import { fromPem } from './der.js';

export const PRESETS = {
  letsencrypt: { label: "Let's Encrypt", url: 'https://acme-v02.api.letsencrypt.org/directory', trusted: true },
  'letsencrypt-staging': { label: "Let's Encrypt staging (for testing; its certificates are not trusted)", url: 'https://acme-staging-v02.api.letsencrypt.org/directory', trusted: false }
} as const;
const KEY_TYPES: KeyType[] = ['ecdsa-p256', 'ecdsa-p384', 'rsa-2048', 'rsa-3072', 'rsa-4096'];
const RETRY_AFTER_FAILURE_MS = 6 * 3600_000;
const DAY = 86400_000;

export type AcmeConfig = (typeof DEFAULTS)['acme'];

export interface AcmeDeps {
  settings: Settings; secrets: Secrets; log: AppLog;
  /** Stages the certificate, and makes it the one in use when asked. */
  install(certPem: string, keyPem: string, apply: boolean): Promise<void>;
  /** The certificate in use now. */
  active(): { notBefore: number; notAfter: number; fingerprint: string; selfSigned: boolean } | null;
  /** Address the temporary challenge listener binds to, and the port of the console's own plain-HTTP listener if it has one. */
  bind: string; httpPort(): number | undefined;
  /** For tests: where the Cloudflare API is, and how fast to poll. */
  cloudflareBase?: string; pollMs?: number; maxPolls?: number; directoryOverride?: string;
}

export interface AcmeState { lastAttemptAt: number | null; lastOkAt: number | null; lastError: string | null; nextAttemptAt: number | null; fingerprint: string | null; names: string[]; applied: boolean | null; note: string | null }
const EMPTY_STATE: AcmeState = { lastAttemptAt: null, lastOkAt: null, lastError: null, nextAttemptAt: null, fingerprint: null, names: [], applied: null, note: null };

interface Pending { client: AcmeClient; orderUrl: string; order: Awaited<ReturnType<AcmeClient['newOrder']>>['order']; key: crypto.KeyObject; csrDer: Buffer; apply: boolean; at: number;
  items: { domain: string; name: string; value: string; authz: string; challenge: string }[] }

/** What was asked for and what the CA will accept, checked before anything is sent. Throws AcmeError with a message for the person editing the settings. */
export function resolveConfig(c: AcmeConfig): { directoryUrl: string; ids: Identifier[]; trusted: boolean } {
  const url = c.preset === 'custom' ? c.directoryUrl.trim() : PRESETS[c.preset].url;
  if (!url) throw new AcmeError('Enter the address of the ACME directory (it usually ends in /directory).');
  let u: URL;
  try { u = new URL(url); } catch { throw new AcmeError(`"${url}" is not a valid address`); }
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && /^(localhost|127\.|\[::1\])/.test(u.hostname))) throw new AcmeError('The ACME directory must be an https:// address.');
  if (!c.names.length) throw new AcmeError('Enter at least one name or IP address for the certificate.');
  let sans: ReturnType<typeof parseSans>;
  try { sans = parseSans(c.names); } catch (e) { throw new AcmeError((e as Error).message); }
  if (c.challenge === 'http-01' && sans.dns.some(n => n.startsWith('*.'))) throw new AcmeError('A wildcard name (*.example.com) can only be verified with DNS-01.');
  if (c.challenge === 'dns-01' && sans.ip.length) throw new AcmeError('An IP address can only be verified with HTTP-01.');
  if (c.preset !== 'custom' && sans.ip.length === 0 && sans.dns.some(n => !n.includes('.') || /\.(local|lan|internal|home|corp|localdomain)$/.test(n))) throw new AcmeError("A public CA only issues for public domain names you own. For a name such as .local or .lan, choose \"Internal or other ACME CA\".");
  if (c.preset !== 'custom' && !c.tosAgreed) throw new AcmeError("Tick the box to accept the CA's terms of service.");
  if (c.preset !== 'custom' && sans.ip.length) throw new AcmeError('Public CAs do not issue certificates for IP addresses here. Use a name, or an internal ACME CA.');
  if (c.caPem.trim()) { try { new crypto.X509Certificate(c.caPem); } catch { throw new AcmeError("The CA's root certificate is not valid PEM text."); } }
  if (c.challenge === 'dns-01' && c.dns.provider === 'cloudflare' && !c.dns.cloudflareTokenEnc) throw new AcmeError('Enter the Cloudflare API token.');
  if (!KEY_TYPES.includes(c.keyType as KeyType)) throw new AcmeError('Choose a key type from the list.');
  return { directoryUrl: url, ids: [...sans.dns.map(v => ({ type: 'dns' as const, value: v })), ...sans.ip.map(v => ({ type: 'ip' as const, value: v }))], trusted: c.preset === 'custom' || PRESETS[c.preset].trusted };
}

/**
 * Keeps the HTTPS certificate up to date from an ACME CA. It registers an account, answers the CA's challenge (HTTP-01 on port 80 for a
 * CA that can reach this server, DNS-01 for a server that cannot be reached, which works for a wildcard too), installs the result through
 * the certificate manager (so it can be rolled back) and renews it before it runs out.
 */
export class AcmeService {
  private running = false;
  private steps: { at: number; text: string }[] = [];
  private pending: Pending | null = null;
  private tokens = new Map<string, string>();
  private lastWarnAt = 0;

  constructor(private d: AcmeDeps) {}

  private get cfg() { return this.d.settings.get('acme'); }
  private state(): AcmeState { const r = this.d.settings.raw('acme_state'); try { return { ...EMPTY_STATE, ...(r ? JSON.parse(r) : {}) }; } catch { return { ...EMPTY_STATE }; } }
  private save(patch: Partial<AcmeState>): void { this.d.settings.setRaw('acme_state', JSON.stringify({ ...this.state(), ...patch })); }
  private step(text: string): void { this.steps.push({ at: Date.now(), text }); if (this.steps.length > 40) this.steps.shift(); }

  /** The body for /.well-known/acme-challenge/<token> while a challenge is open, otherwise undefined. */
  challengeBody(token: string): string | undefined { return this.tokens.get(token); }

  /** Everything the Admin page shows. Secrets are never included, only whether they are set. */
  status() {
    const c = this.cfg, st = this.state(), act = this.d.active();
    const acc = this.account();
    return {
      config: { enabled: c.enabled, preset: c.preset, directoryUrl: c.directoryUrl, email: c.email, tosAgreed: c.tosAgreed, names: c.names, challenge: c.challenge, httpPort: c.httpPort,
        dnsProvider: c.dns.provider, dnsWaitSec: c.dns.waitSec, cloudflareTokenSet: !!c.dns.cloudflareTokenEnc, eabKid: c.eabKid, eabHmacSet: !!c.eabHmacEnc, caPem: c.caPem, keyType: c.keyType, autoRenew: c.autoRenew, renewDays: c.renewDays },
      presets: Object.entries(PRESETS).map(([id, p]) => ({ id, label: p.label })), keyTypes: KEY_TYPES,
      state: st, running: this.running, steps: this.steps,
      pending: this.pending ? { at: this.pending.at, records: this.pending.items.map(i => ({ domain: i.domain, name: i.name, value: i.value })) } : null,
      account: { registered: !!acc, directoryUrl: acc?.directoryUrl ?? null },
      managed: !!act && !!st.fingerprint && act.fingerprint === st.fingerprint,
      renewAt: this.renewAt(), httpListener: { port: c.httpPort, own: this.d.httpPort() === c.httpPort }
    };
  }

  /** Saves the settings. A secret left out (undefined) is kept; null removes it. */
  configure(input: Partial<Omit<AcmeConfig, 'dns'>> & { dns?: Partial<AcmeConfig['dns']>; cloudflareToken?: string | null; eabHmac?: string | null }): void {
    const cur = this.cfg;
    const next = { ...cur, ...Object.fromEntries(Object.entries(input).filter(([k]) => !['dns', 'cloudflareToken', 'eabHmac'].includes(k))), dns: { ...cur.dns, ...(input.dns || {}) } } as AcmeConfig;
    next.names = (Array.isArray(next.names) ? next.names : String(next.names).split(/[\s,;]+/)).map(x => String(x).trim()).filter(Boolean);
    next.httpPort = Math.floor(Number(next.httpPort)); if (!(next.httpPort >= 1 && next.httpPort <= 65535)) throw new AcmeError('The HTTP port must be between 1 and 65535.');
    next.renewDays = Math.floor(Number(next.renewDays)); if (!(next.renewDays >= 1 && next.renewDays <= 60)) throw new AcmeError('Renew between 1 and 60 days before the certificate expires.');
    next.dns.waitSec = Math.floor(Number(next.dns.waitSec)); if (!(next.dns.waitSec >= 0 && next.dns.waitSec <= 600)) throw new AcmeError('Wait between 0 and 600 seconds after adding the DNS record.');
    if (input.cloudflareToken === null) next.dns.cloudflareTokenEnc = ''; else if (input.cloudflareToken) next.dns.cloudflareTokenEnc = this.d.secrets.encrypt(input.cloudflareToken.trim());
    if (input.eabHmac === null) next.eabHmacEnc = ''; else if (input.eabHmac) next.eabHmacEnc = this.d.secrets.encrypt(input.eabHmac.trim());
    next.email = String(next.email || '').trim();
    if (next.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(next.email)) throw new AcmeError('That does not look like an e-mail address.');
    if (next.enabled) resolveConfig(next);
    this.d.settings.set('acme', next);
  }

  /* ---------------------------------------------------------------- account */

  private account(): { directoryUrl: string; kid: string; keyEnc: string } | null {
    const r = this.d.settings.raw('acme_account'); if (!r) return null;
    try { return JSON.parse(r); } catch { return null; }
  }

  private async ensureAccount(client: AcmeClient, c: AcmeConfig, url: string, fresh = false): Promise<void> {
    const a = fresh ? null : this.account();
    if (a && a.directoryUrl === url) { client.setAccount(crypto.createPrivateKey(this.d.secrets.decrypt(a.keyEnc)), a.kid); return; }
    this.step('Registering an account with the CA');
    const key = AcmeClient.newAccountKey(); client.setAccount(key);
    const kid = await client.register({ email: c.email || undefined, tosAgreed: c.tosAgreed || c.preset === 'custom', eab: c.eabKid && c.eabHmacEnc ? { kid: c.eabKid, hmacKey: this.d.secrets.decrypt(c.eabHmacEnc) } : undefined });
    this.d.settings.setRaw('acme_account', JSON.stringify({ directoryUrl: url, kid, keyEnc: this.d.secrets.encrypt(key.export({ type: 'pkcs8', format: 'pem' }) as string) }));
    this.d.log.info('cert', `Registered an ACME account at ${url}`);
  }

  /* ---------------------------------------------------------------- issuing */

  /** When the certificate in use should be renewed: a third of its life before it ends, but no earlier than the configured number of days. */
  renewAt(): number | null {
    const a = this.d.active(); if (!a) return null;
    return a.notAfter - Math.min(this.cfg.renewDays * DAY, (a.notAfter - a.notBefore) / 3);
  }

  /**
   * Asks the CA for a certificate. With DNS-01 and no automatic DNS provider it stops after working out which TXT records to add; the
   * person adds them and calls proceed(). Everything else runs to the end. Throws with the reason when it fails.
   */
  async issue(): Promise<void> {
    if (this.running || this.pending) throw new AcmeError(this.pending ? 'A request is waiting for DNS records. Continue it or cancel it first.' : 'A request is already running.');
    this.running = true; this.steps = []; const now = Date.now();
    this.save({ lastAttemptAt: now, lastError: null, note: null });
    try {
      const c = this.cfg; const r = resolveConfig(c);
      const client = new AcmeClient({ directoryUrl: this.d.directoryOverride ?? r.directoryUrl, caPem: c.caPem.trim() || undefined, pollMs: this.d.pollMs, maxPolls: this.d.maxPolls });
      this.step('Contacting the CA'); await client.directory();
      await this.ensureAccount(client, c, this.d.directoryOverride ?? r.directoryUrl);
      const key = await generateKey(c.keyType as KeyType);
      const sans = parseSans(c.names);
      const cn = sans.dns[0] ?? sans.ip[0]!;
      const csrDer = fromPem(buildCsr(key, { cn: cn.replace(/^\*\./, '') }, sans))[0]!;
      this.step('Placing the order for ' + c.names.join(', '));
      let o: Awaited<ReturnType<AcmeClient['newOrder']>>;
      try { o = await client.newOrder(r.ids); }
      catch (e) {
        if (e instanceof AcmeError && e.type.endsWith(':accountDoesNotExist')) { await this.ensureAccount(client, c, this.d.directoryOverride ?? r.directoryUrl, true); o = await client.newOrder(r.ids); } else throw e;
      }
      const pend: Pending = { client, orderUrl: o.url, order: o.order, key, csrDer, apply: r.trusted, at: Date.now(), items: [] };
      for (const au of o.order.authorizations) {
        const a = await client.authorization(au);
        if (a.status === 'valid') continue;
        const ch = a.challenges.find(x => x.type === c.challenge);
        if (!ch) throw new AcmeError(`The CA does not offer ${c.challenge.toUpperCase()} for ${a.identifier.value}. It offers: ${a.challenges.map(x => x.type).join(', ') || 'nothing'}.`);
        const domain = (a.wildcard ? '*.' : '') + a.identifier.value;
        pend.items.push({ domain, name: challengeName(domain), value: c.challenge === 'dns-01' ? client.dnsValue(ch.token) : client.keyAuthorization(ch.token), authz: au, challenge: ch.url });
      }
      if (c.challenge === 'dns-01' && c.dns.provider === 'manual' && pend.items.length) {
        this.pending = pend;
        this.step('Waiting for you to add the TXT records, then choose Continue');
        this.d.log.info('cert', 'ACME request is waiting for DNS TXT records to be added');
        return;
      }
      await this.complete(pend);
    } catch (e) { this.fail(e); throw e; }
    finally { if (!this.pending) this.running = false; }
  }

  /** Second half of a manual DNS-01 request: the CA is told the records are there. */
  async proceed(): Promise<void> {
    const p = this.pending;
    if (!p) throw new AcmeError('There is no request waiting for DNS records.');
    this.pending = null; this.running = true;
    try { await this.complete(p); } catch (e) { this.fail(e); throw e; } finally { this.running = false; }
  }

  cancel(): void { if (this.pending) { this.pending = null; this.running = false; this.step('Cancelled'); this.save({ lastError: null, note: 'The request was cancelled.' }); } }

  private provider(c: AcmeConfig): DnsProvider | null {
    if (c.challenge !== 'dns-01' || c.dns.provider !== 'cloudflare') return null;
    return new Cloudflare(this.d.secrets.decrypt(c.dns.cloudflareTokenEnc), this.d.cloudflareBase);
  }

  /** Answers the challenges, waits for the CA, finalizes, and installs the certificate. */
  private async complete(p: Pending): Promise<void> {
    const c = this.cfg;
    const cleanups: (() => Promise<void>)[] = [];
    try {
      if (p.items.length) {
        if (c.challenge === 'http-01') {
          for (const it of p.items) this.tokens.set(it.value.split('.')[0]!, it.value);
          cleanups.push(await this.openHttpListener());
        } else {
          const prov = this.provider(c);
          if (prov) {
            for (const it of p.items) { this.step(`Adding the TXT record for ${it.domain}`); cleanups.push(await prov.present(it.domain, it.value)); }
            if (c.dns.waitSec > 0) { this.step(`Waiting ${c.dns.waitSec} seconds for DNS to update`); await new Promise(res => setTimeout(res, c.dns.waitSec * 1000)); }
          }
        }
        for (const it of p.items) { this.step(`Asking the CA to check ${it.domain}`); await p.client.triggerChallenge(it.challenge); }
        for (const it of p.items) await p.client.waitAuthorization(it.authz);
        this.step('The CA verified the names');
      }
      this.step('Asking the CA to issue the certificate');
      const chain = await p.client.finalize(p.orderUrl, p.order, p.csrDer);
      const leaf = new crypto.X509Certificate(chain.slice(chain.indexOf('-----BEGIN CERTIFICATE-----')));
      if (!leaf.checkPrivateKey(p.key)) throw new AcmeError('The CA returned a certificate that does not match the key that was generated.');
      this.step(p.apply ? 'Installing the certificate' : 'Staging the certificate (it is from a testing CA, so it is not applied)');
      await this.d.install(chain, p.key.export({ type: 'pkcs8', format: 'pem' }) as string, p.apply);
      this.save({ lastOkAt: Date.now(), lastError: null, nextAttemptAt: null, fingerprint: p.apply ? leaf.fingerprint256 : this.state().fingerprint, names: c.names, applied: p.apply, note: p.apply ? null : 'The certificate was staged but not applied, because the CA is a testing one.' });
      this.d.log.info('cert', `ACME certificate for ${c.names.join(', ')} ${p.apply ? 'installed' : 'staged (testing CA)'}; valid until ${new Date(leaf.validTo).toISOString().slice(0, 10)}`);
      this.step('Done');
    } finally {
      this.tokens.clear();
      for (const f of cleanups.reverse()) { try { await f(); } catch { /* best effort */ } }
    }
  }

  private fail(e: unknown): void {
    const msg = (e as Error).message || String(e);
    this.step('Failed: ' + msg);
    this.save({ lastError: msg, nextAttemptAt: Date.now() + RETRY_AFTER_FAILURE_MS });
    const act = this.d.active();
    const urgent = !!act && !act.selfSigned && act.notAfter - Date.now() < 7 * DAY;
    (urgent ? this.d.log.error : this.d.log.warn).call(this.d.log, 'cert', `Automatic certificate request failed: ${msg}`);
  }

  /** Serves the challenge on port 80 (or the configured port) for the duration of the validation, unless the console's own HTTP listener already does. */
  private async openHttpListener(): Promise<() => Promise<void>> {
    const port = this.cfg.httpPort;
    if (this.d.httpPort() === port) { this.step(`Answering the challenge on the console's HTTP port ${port}`); return async () => undefined; }
    const srv = http.createServer((req, res) => {
      const m = /^\/\.well-known\/acme-challenge\/([A-Za-z0-9_-]+)$/.exec((req.url || '').split('?')[0]!);
      const body = m ? this.tokens.get(m[1]!) : undefined;
      if (body === undefined) { res.writeHead(404); res.end(); return; }
      res.writeHead(200, { 'content-type': 'text/plain' }); res.end(body);
    });
    await new Promise<void>((resolve, reject) => {
      srv.once('error', (e: NodeJS.ErrnoException) => reject(new AcmeError(e.code === 'EADDRINUSE'
        ? `Port ${port} is already used by another program, so the CA's check cannot be answered. Stop it, or set the HTTP port here to the one that is forwarded to this server, or use DNS-01.`
        : e.code === 'EACCES' ? `This service is not allowed to open port ${port}. Give it the right to use low ports (on Linux: AmbientCapabilities=CAP_NET_BIND_SERVICE), or use DNS-01.`
        : `Could not open port ${port}: ${e.message}`)));
      srv.listen(port, this.d.bind, () => resolve());
    });
    this.step(`Listening on port ${port} for the CA's check`);
    return () => new Promise<void>(res => { srv.close(() => res()); srv.closeAllConnections?.(); });
  }

  /* ---------------------------------------------------------------- renewal */

  /** Called every few minutes. Requests a certificate when none from the CA is in use yet, when the names changed, or when renewal is due. */
  async tick(now = Date.now()): Promise<boolean> {
    const c = this.cfg;
    // a request waiting for DNS records that nobody has continued for a day is dropped, so it does not block renewals for good
    if (this.pending && now - this.pending.at > DAY) this.cancel();
    if (!c.enabled || !c.autoRenew || this.running || this.pending) return false;
    const st = this.state();
    if (st.nextAttemptAt && st.nextAttemptAt > now) return false;
    const act = this.d.active();
    const ours = !!act && !!st.fingerprint && act.fingerprint === st.fingerprint;
    const namesChanged = ours && [...st.names].sort().join(',') !== [...c.names].sort().join(',');
    const renewal = ours && act !== null && now >= (this.renewAt() ?? Infinity);
    const first = !act || act.selfSigned;
    if (!(first || namesChanged || renewal)) return false;
    if (c.challenge === 'dns-01' && c.dns.provider === 'manual') {
      // a person has to add the records, so this cannot run by itself; say so once a day
      if (now - this.lastWarnAt > DAY) { this.lastWarnAt = now; this.save({ note: 'The certificate is due for renewal, but DNS-01 with manual records cannot renew by itself. Open Admin, HTTPS certificate, and request it.' }); this.d.log.warn('cert', 'The HTTPS certificate is due for renewal, and manual DNS records are needed. Request it in Admin, HTTPS certificate.'); }
      return false;
    }
    try { await this.issue(); return true; } catch { return false; }
  }
}
