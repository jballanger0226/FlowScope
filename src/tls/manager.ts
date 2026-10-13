import crypto from 'node:crypto';
import tls from 'node:tls';
import type { ConfigDb } from '../db/configdb.js';
import type { Secrets } from '../secrets.js';
import type { AppLog } from '../logger.js';
import { buildCsr, buildSelfSigned, describeKey, generateKey, inspectCert, parseSans, type KeyType, type Subject } from './x509.js';
import { fromPem, toPem } from './der.js';

export class CertError extends Error {}

export interface CertView {
  slot: string; subject: string; issuer: string; sans: string[]; notBefore: number; notAfter: number; fingerprint: string; keyDesc: string; selfSigned: boolean;
  createdAt: number; chainLength: number; format: 'pem' | 'pkcs12'; expired: boolean; daysLeft: number;
}
export interface CsrView { cn: string; sans: string[]; keyDesc: string; createdAt: number; csrPem: string }

interface Row {
  id: number; slot: string; cert_pem: string; chain_pem: string; key_enc: string | null; subject: string; issuer: string; sans: string; not_before: number; not_after: number;
  fingerprint: string; key_desc: string; created_at: number; self_signed: number;
}

type Stored = { kind: 'pem'; key: string } | { kind: 'p12'; pfx: string; pass: string };

function splitCerts(pem: string): string[] {
  return fromPem(pem).filter(b => b.length > 0).map(b => toPem('CERTIFICATE', b));
}

function checkChain(certs: string[]): void {
  for (let i = 0; i < certs.length - 1; i++) {
    const a = new crypto.X509Certificate(certs[i]), b = new crypto.X509Certificate(certs[i + 1]);
    if (!a.checkIssued(b) || !a.verify(b.publicKey)) {
      throw new CertError(`The chain is out of order or incomplete at certificate ${i + 1}. Put the server certificate first, then each intermediate that signed the one before it.`);
    }
  }
}

/** Reads the server certificate and chain out of a PKCS#12 bundle by loading it into a throwaway TLS server on the loopback interface. */
async function unpackP12(pfx: Buffer, passphrase: string): Promise<string[]> {
  let ctxOpts: tls.TlsOptions;
  try { tls.createSecureContext({ pfx, passphrase }); ctxOpts = { pfx, passphrase }; }
  catch (e) {
    const m = (e as Error).message;
    if (/mac verify|password|decrypt|bad decrypt/i.test(m)) throw new CertError('The bundle could not be opened. The password is wrong, or the bundle uses an old encryption method (RC2 or 40-bit). Re-export it with AES.');
    if (/unsupported|legacy|RC2|rc2/i.test(m)) throw new CertError('The bundle uses an encryption method this server cannot read (' + m + '). Re-export it with AES-256.');
    throw new CertError('The file is not a usable PKCS#12 bundle: ' + m);
  }
  const server = tls.createServer(ctxOpts, s => s.end());
  await new Promise<void>((res, rej) => { server.once('error', rej); server.listen(0, '127.0.0.1', () => res()); });
  try {
    const port = (server.address() as { port: number }).port;
    return await new Promise<string[]>((resolve, reject) => {
      const c = tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false, servername: 'localhost' }, () => {
        try {
          const out: string[] = [];
          let cur: tls.DetailedPeerCertificate | undefined = c.getPeerCertificate(true);
          const seen = new Set<string>();
          while (cur && cur.raw && !seen.has(cur.fingerprint256)) {
            seen.add(cur.fingerprint256);
            out.push(toPem('CERTIFICATE', cur.raw));
            cur = cur.issuerCertificate && cur.issuerCertificate !== cur ? cur.issuerCertificate : undefined;
          }
          c.destroy(); resolve(out);
        } catch (e) { reject(e); }
      });
      c.on('error', reject);
    });
  } finally { server.close(); }
}

/** Manages the HTTPS certificate: a self-signed one on first start, then uploaded or CSR-issued certificates with stage, apply and roll back. */
export class CertManager {
  constructor(private cdb: ConfigDb, private secrets: Secrets, private log: AppLog) {}

  private row(slot: string): Row | undefined { return this.cdb.db.prepare('SELECT * FROM certs WHERE slot = ? ORDER BY id DESC LIMIT 1').get(slot) as unknown as Row | undefined; }
  private clear(slot: string): void { this.cdb.db.prepare('DELETE FROM certs WHERE slot = ?').run(slot); }

  private view(r: Row | undefined): CertView | null {
    if (!r) return null;
    const stored = r.key_enc ? JSON.parse(this.secrets.decrypt(r.key_enc)) as Stored : null;
    return {
      slot: r.slot, subject: r.subject, issuer: r.issuer, sans: JSON.parse(r.sans || '[]'), notBefore: r.not_before, notAfter: r.not_after, fingerprint: r.fingerprint, keyDesc: r.key_desc,
      selfSigned: r.self_signed === 1, createdAt: r.created_at, chainLength: splitCerts(r.chain_pem || '').length, format: stored?.kind === 'p12' ? 'pkcs12' : 'pem',
      expired: r.not_after < Date.now(), daysLeft: Math.floor((r.not_after - Date.now()) / 86400_000)
    };
  }

  status(): { active: CertView | null; staged: CertView | null; previous: CertView | null; csr: CsrView | null } {
    const csr = this.row('csr');
    let csrView: CsrView | null = null;
    if (csr) { const meta = JSON.parse(csr.sans) as { cn: string; sans: string[]; csr: string }; csrView = { cn: meta.cn, sans: meta.sans, keyDesc: csr.key_desc, createdAt: csr.created_at, csrPem: meta.csr }; }
    return { active: this.view(this.row('active')), staged: this.view(this.row('staged')), previous: this.view(this.row('previous')), csr: csrView };
  }

  private insert(slot: string, leaf: string, chain: string[], stored: Stored, selfSigned: boolean): void {
    const info = inspectCert(leaf);
    this.clear(slot);
    this.cdb.db.prepare(`INSERT INTO certs(slot, cert_pem, chain_pem, key_enc, subject, issuer, sans, not_before, not_after, fingerprint, key_desc, created_at, self_signed) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .run(slot, leaf, chain.join(''), this.secrets.encrypt(JSON.stringify(stored)), info.subject, info.issuer, JSON.stringify(info.sans), info.notBefore, info.notAfter, info.fingerprint, info.keyDesc, Date.now(), selfSigned ? 1 : 0);
  }

  /** TLS options for the active certificate, or null when none is installed. */
  options(slot = 'active'): tls.SecureContextOptions | null {
    const r = this.row(slot);
    if (!r || !r.key_enc) return null;
    const s = JSON.parse(this.secrets.decrypt(r.key_enc)) as Stored;
    if (s.kind === 'p12') return { pfx: Buffer.from(s.pfx, 'base64'), passphrase: s.pass };
    return { cert: r.cert_pem + (r.chain_pem || ''), key: s.key };
  }

  /** Creates the first certificate when none exists, or re-creates it when the stored one has expired. */
  async ensureActive(hosts: string[]): Promise<boolean> {
    const cur = this.row('active');
    if (cur && cur.not_after > Date.now() + 86400_000) return false;
    await this.makeSelfSigned(hosts);
    return true;
  }

  async makeSelfSigned(hosts: string[], keyType: KeyType = 'ecdsa-p256'): Promise<void> {
    const names = [...new Set(hosts.filter(Boolean))];
    const cn = names.find(h => !/^[\d.:]+$/.test(h)) || names[0] || 'localhost';
    const key = await generateKey(keyType);
    const pem = buildSelfSigned({ key, subject: { cn, o: 'FlowScope' }, sans: parseSans(names.length ? names : ['localhost']), days: 825 });
    const old = this.row('active');
    if (old) { this.clear('previous'); this.cdb.db.prepare("UPDATE certs SET slot = 'previous' WHERE id = ?").run(old.id); }
    this.insert('active', pem, [], { kind: 'pem', key: key.export({ type: 'pkcs8', format: 'pem' }) as string }, true);
    this.log.info('cert', `Created a self-signed HTTPS certificate for ${cn} (${describeKey(key)}, valid 825 days)`);
  }

  private commonChecks(certs: string[], expectHost?: string): string[] {
    const warnings: string[] = [];
    let leaf: crypto.X509Certificate;
    try { leaf = new crypto.X509Certificate(certs[0]); } catch (e) { throw new CertError('The certificate could not be read: ' + (e as Error).message); }
    const now = Date.now();
    if (Date.parse(leaf.validTo) < now) throw new CertError('This certificate expired on ' + new Date(leaf.validTo).toISOString().slice(0, 10) + '.');
    if (Date.parse(leaf.validFrom) > now + 5 * 60_000) throw new CertError('This certificate is not valid until ' + new Date(leaf.validFrom).toISOString().slice(0, 10) + '.');
    if (leaf.ca) warnings.push('This is a CA certificate, not a server certificate. Browsers will reject it for HTTPS.');
    checkChain(certs);
    if (expectHost) {
      const isIp = /^[\d.:]+$/.test(expectHost);
      const covered = isIp ? !!leaf.checkIP(expectHost) : !!leaf.checkHost(expectHost);
      if (!covered) warnings.push(`The certificate does not cover "${expectHost}", the name you are using now. Browsers will warn unless people reach this server by a name in the certificate.`);
    }
    if (certs.length === 1 && leaf.subject !== leaf.issuer) warnings.push('No intermediate certificates were included. Some clients will not trust the server unless the full chain is sent.');
    const days = Math.floor((Date.parse(leaf.validTo) - now) / 86400_000);
    if (days < 30) warnings.push(`This certificate expires in ${days} days.`);
    return warnings;
  }

  async stagePem(o: { certPem: string; keyPem?: string; expectHost?: string }): Promise<{ warnings: string[] }> {
    const certs = splitCerts(o.certPem || '');
    if (!certs.length) throw new CertError('No certificate found. Paste the PEM text that starts with -----BEGIN CERTIFICATE-----.');
    if (/-----BEGIN (RSA |EC )?PRIVATE KEY-----/.test(o.certPem) && !o.keyPem) throw new CertError('The certificate box contains a private key. Paste the key in the private key box.');
    const warnings = this.commonChecks(certs, o.expectHost);
    let keyPem = (o.keyPem || '').trim();
    let key: crypto.KeyObject;
    if (!keyPem) {
      const csr = this.row('csr');
      if (!csr || !csr.key_enc) throw new CertError('Paste the private key, or create a signing request here first so the server holds the key.');
      keyPem = (JSON.parse(this.secrets.decrypt(csr.key_enc)) as { kind: 'pem'; key: string }).key;
    }
    if (/ENCRYPTED/.test(keyPem)) throw new CertError('Encrypted private keys are not accepted. Remove the passphrase first (openssl pkey -in key.pem -out key-plain.pem).');
    try { key = crypto.createPrivateKey(keyPem); } catch (e) { throw new CertError('The private key could not be read: ' + (e as Error).message); }
    const leaf = new crypto.X509Certificate(certs[0]);
    if (!leaf.checkPrivateKey(key)) throw new CertError('The private key does not match this certificate.');
    try { tls.createSecureContext({ cert: certs.join(''), key: keyPem }); } catch (e) { throw new CertError('This certificate and key cannot be used by the server: ' + (e as Error).message); }
    const normKey = key.export({ type: 'pkcs8', format: 'pem' }) as string;
    this.insert('staged', certs[0], certs.slice(1), { kind: 'pem', key: normKey }, false);
    this.log.info('cert', `New HTTPS certificate staged (${leaf.subject.replace(/\n/g, ', ')}, PEM, ${certs.length - 1} intermediate)`);
    return { warnings };
  }

  async stageP12(o: { pfx: Buffer; passphrase: string; expectHost?: string }): Promise<{ warnings: string[] }> {
    if (!o.pfx?.length) throw new CertError('Choose a .pfx or .p12 file');
    if (!o.passphrase) throw new CertError('Enter the bundle password');
    const certs = await unpackP12(o.pfx, o.passphrase);
    if (!certs.length) throw new CertError('The bundle has no certificate');
    const warnings = this.commonChecks(certs, o.expectHost);
    this.insert('staged', certs[0], certs.slice(1), { kind: 'p12', pfx: o.pfx.toString('base64'), pass: o.passphrase }, false);
    this.log.info('cert', `New HTTPS certificate staged (${new crypto.X509Certificate(certs[0]).subject.replace(/\n/g, ', ')}, PKCS#12, ${certs.length - 1} intermediate)`);
    return { warnings };
  }

  async generateCsr(o: { cn: string; sans?: string[]; keyType: KeyType; o?: string; ou?: string; c?: string }): Promise<CsrView> {
    const cn = (o.cn || '').trim();
    if (!cn) throw new CertError('Enter a common name');
    if (o.c && !/^[A-Za-z]{2}$/.test(o.c)) throw new CertError('The country must be a two-letter code');
    let sans;
    try { sans = parseSans([cn, ...(o.sans || [])]); } catch (e) { throw new CertError((e as Error).message); }
    const key = await generateKey(o.keyType);
    const subj: Subject = { cn, o: o.o?.trim() || undefined, ou: o.ou?.trim() || undefined, c: o.c?.trim() || undefined };
    const csr = buildCsr(key, subj, sans);
    this.clear('csr');
    this.cdb.db.prepare(`INSERT INTO certs(slot, cert_pem, chain_pem, key_enc, subject, issuer, sans, not_before, not_after, fingerprint, key_desc, created_at, self_signed) VALUES ('csr','','',?,?,?,?,0,0,'',?,?,0)`)
      .run(this.secrets.encrypt(JSON.stringify({ kind: 'pem', key: key.export({ type: 'pkcs8', format: 'pem' }) })), cn, '', JSON.stringify({ cn, sans: [...sans.dns, ...sans.ip], csr }), describeKey(key), Date.now());
    this.log.info('cert', `Certificate signing request created for ${cn} (${describeKey(key)}). The private key stays on the server.`);
    return { cn, sans: [...sans.dns, ...sans.ip], keyDesc: describeKey(key), createdAt: Date.now(), csrPem: csr };
  }

  /** Makes the staged certificate the active one and keeps the old one for roll back. */
  apply(): tls.SecureContextOptions {
    const staged = this.row('staged');
    if (!staged) throw new CertError('Nothing is staged');
    this.cdb.tx(() => {
      const cur = this.row('active');
      this.clear('previous');
      if (cur) this.cdb.db.prepare("UPDATE certs SET slot = 'previous' WHERE id = ?").run(cur.id);
      this.cdb.db.prepare("UPDATE certs SET slot = 'active' WHERE id = ?").run(staged.id);
    });
    this.log.info('cert', 'HTTPS certificate applied; listeners reloaded');
    return this.options('active')!;
  }

  discardStaged(): void { this.clear('staged'); }

  rollback(): tls.SecureContextOptions {
    const prev = this.row('previous');
    if (!prev) throw new CertError('There is no previous certificate to return to');
    this.cdb.tx(() => {
      const cur = this.row('active');
      this.clear('staged');
      if (cur) this.cdb.db.prepare("UPDATE certs SET slot = 'staged' WHERE id = ?").run(cur.id);
      this.cdb.db.prepare("UPDATE certs SET slot = 'active' WHERE id = ?").run(prev.id);
    });
    this.log.warn('cert', 'HTTPS certificate rolled back to the previous one');
    return this.options('active')!;
  }
}
