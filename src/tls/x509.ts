import crypto from 'node:crypto';
import net from 'node:net';
import * as d from './der.js';

export type KeyType = 'ecdsa-p256' | 'ecdsa-p384' | 'ecdsa-p521' | 'rsa-2048' | 'rsa-3072' | 'rsa-4096' | 'ed25519';
export const KEY_TYPES: { id: KeyType; label: string }[] = [
  { id: 'ecdsa-p256', label: 'ECDSA P-256' }, { id: 'ecdsa-p384', label: 'ECDSA P-384' }, { id: 'ecdsa-p521', label: 'ECDSA P-521' },
  { id: 'rsa-2048', label: 'RSA 2048' }, { id: 'rsa-3072', label: 'RSA 3072' }, { id: 'rsa-4096', label: 'RSA 4096' }, { id: 'ed25519', label: 'Ed25519' }
];

export interface Subject { cn: string; o?: string; ou?: string; c?: string; st?: string; l?: string }

export function generateKey(type: KeyType): Promise<crypto.KeyObject> {
  return new Promise((resolve, reject) => {
    const done = (e: Error | null, priv: crypto.KeyObject) => (e ? reject(e) : resolve(priv));
    if (type === 'rsa-2048' || type === 'rsa-3072' || type === 'rsa-4096') {
      crypto.generateKeyPair('rsa', { modulusLength: Number(type.slice(4)), publicExponent: 0x10001 }, (e, _pub, priv) => done(e, priv));
    } else if (type === 'ed25519') {
      crypto.generateKeyPair('ed25519', {}, (e, _pub, priv) => done(e, priv));
    } else {
      const namedCurve = type === 'ecdsa-p256' ? 'prime256v1' : type === 'ecdsa-p384' ? 'secp384r1' : 'secp521r1';
      crypto.generateKeyPair('ec', { namedCurve }, (e, _pub, priv) => done(e, priv));
    }
  });
}

export function describeKey(k: crypto.KeyObject): string {
  const t = k.asymmetricKeyType;
  if (t === 'rsa') return `RSA ${k.asymmetricKeyDetails?.modulusLength ?? ''}`.trim();
  if (t === 'ec') return 'ECDSA ' + ({ prime256v1: 'P-256', secp384r1: 'P-384', secp521r1: 'P-521' } as Record<string, string>)[k.asymmetricKeyDetails?.namedCurve ?? ''] ;
  if (t === 'ed25519') return 'Ed25519';
  return String(t);
}

interface SigAlg { oidStr: string; hash: string | null; params: boolean }
function sigAlg(k: crypto.KeyObject): SigAlg {
  const t = k.asymmetricKeyType;
  if (t === 'rsa') return { oidStr: '1.2.840.113549.1.1.11', hash: 'sha256', params: true };
  if (t === 'ed25519') return { oidStr: '1.3.101.112', hash: null, params: false };
  if (t === 'ec') {
    const c = k.asymmetricKeyDetails?.namedCurve;
    if (c === 'secp384r1') return { oidStr: '1.2.840.10045.4.3.3', hash: 'sha384', params: false };
    if (c === 'secp521r1') return { oidStr: '1.2.840.10045.4.3.4', hash: 'sha512', params: false };
    return { oidStr: '1.2.840.10045.4.3.2', hash: 'sha256', params: false };
  }
  throw new Error('Unsupported key type ' + t);
}
const algId = (a: SigAlg) => d.seq(d.oid(a.oidStr), ...(a.params ? [d.nul()] : []));

function name(s: Subject): d.Der {
  const rdn = (o: string, v: string, printableOk = false) => d.set(d.seq(d.oid(o), printableOk && /^[A-Za-z0-9 '()+,\-./:=?]+$/.test(v) ? d.printable(v) : d.utf8(v)));
  const parts: d.Der[] = [];
  if (s.c) parts.push(rdn('2.5.4.6', s.c.toUpperCase(), true));
  if (s.st) parts.push(rdn('2.5.4.8', s.st));
  if (s.l) parts.push(rdn('2.5.4.7', s.l));
  if (s.o) parts.push(rdn('2.5.4.10', s.o));
  if (s.ou) parts.push(rdn('2.5.4.11', s.ou));
  parts.push(rdn('2.5.4.3', s.cn));
  return d.seq(...parts);
}

export interface San { dns: string[]; ip: string[] }
export function parseSans(list: string[]): San {
  const out: San = { dns: [], ip: [] };
  for (const raw of list) {
    const s = raw.trim();
    if (!s) continue;
    if (net.isIP(s)) out.ip.push(s);
    else if (/^(\*\.)?([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(s) && s.length <= 253) out.dns.push(s.toLowerCase());
    else throw new Error(`"${s}" is not a host name or IP address`);
  }
  return out;
}

function ipBytes(ip: string): Buffer {
  if (net.isIPv4(ip)) return Buffer.from(ip.split('.').map(Number));
  // IPv6: expand ::
  const [head, tail] = ip.split('::');
  const h = head ? head.split(':') : []; const t = tail !== undefined && tail ? tail.split(':') : [];
  const full = tail === undefined ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  const b = Buffer.alloc(16);
  full.forEach((g, i) => b.writeUInt16BE(parseInt(g || '0', 16), i * 2));
  return b;
}

function sanExt(s: San): d.Der {
  const names = [...s.dns.map(x => d.ctxPrim(2, Buffer.from(x, 'ascii'))), ...s.ip.map(x => d.ctxPrim(7, ipBytes(x)))];
  return d.seq(d.oid('2.5.29.17'), d.octets(d.seq(...names)));
}

/** PKCS#10 certificate request, signed with the private key. */
export function buildCsr(key: crypto.KeyObject, subject: Subject, sans: San): string {
  const pub = crypto.createPublicKey(key).export({ type: 'spki', format: 'der' });
  const attrs: d.Der[] = [];
  if (sans.dns.length || sans.ip.length) {
    attrs.push(d.seq(d.oid('1.2.840.113549.1.9.14'), d.set(d.seq(sanExt(sans)))));
  }
  const info = d.seq(d.int(0), name(subject), pub, d.ctx(0, ...attrs));
  const a = sigAlg(key);
  const sig = crypto.sign(a.hash, info, key);
  return d.toPem('CERTIFICATE REQUEST', d.seq(info, algId(a), d.bitString(sig)));
}

export interface SelfSignedOpts { key: crypto.KeyObject; subject: Subject; sans: San; days: number }

export function buildSelfSigned(o: SelfSignedOpts): string {
  const pub = crypto.createPublicKey(o.key).export({ type: 'spki', format: 'der' });
  const a = sigAlg(o.key);
  const nb = new Date(Date.now() - 5 * 60_000), na = new Date(Date.now() + o.days * 86400_000);
  const ski = crypto.createHash('sha1').update(pub).digest();
  const exts = [
    d.seq(d.oid('2.5.29.19'), d.bool(true), d.octets(d.seq(d.bool(true)))),
    d.seq(d.oid('2.5.29.15'), d.bool(true), d.octets(d.bitString(Buffer.from([o.key.asymmetricKeyType === 'rsa' ? 0xa0 : 0x80]), o.key.asymmetricKeyType === 'rsa' ? 5 : 7))),
    d.seq(d.oid('2.5.29.37'), d.octets(d.seq(d.oid('1.3.6.1.5.5.7.3.1')))),
    d.seq(d.oid('2.5.29.14'), d.octets(d.octets(ski)))
  ];
  if (o.sans.dns.length || o.sans.ip.length) exts.push(sanExt(o.sans));
  const serial = crypto.randomBytes(16); serial[0] &= 0x7f; if (serial[0] === 0) serial[0] = 1;
  const nm = name(o.subject);
  const tbs = d.seq(d.ctx(0, d.int(2)), d.int(serial), algId(a), nm, d.seq(d.time(nb), d.time(na)), nm, pub, d.ctx(3, d.seq(...exts)));
  const sig = crypto.sign(a.hash, tbs, o.key);
  return d.toPem('CERTIFICATE', d.seq(tbs, algId(a), d.bitString(sig)));
}

export interface CertInfo {
  subject: string; issuer: string; sans: string[]; notBefore: number; notAfter: number; fingerprint: string; serial: string; keyDesc: string; selfSigned: boolean; isCa: boolean;
}

export function inspectCert(pem: string): CertInfo {
  const x = new crypto.X509Certificate(pem);
  const sans = (x.subjectAltName || '').split(/,\s*/).filter(Boolean).map(s => s.replace(/^DNS:/, '').replace(/^IP Address:/, ''));
  return {
    subject: x.subject.replace(/\n/g, ', '), issuer: x.issuer.replace(/\n/g, ', '), sans, notBefore: Date.parse(x.validFrom), notAfter: Date.parse(x.validTo),
    fingerprint: x.fingerprint256, serial: x.serialNumber, keyDesc: describeKey(x.publicKey), selfSigned: x.subject === x.issuer && x.verify(x.publicKey), isCa: x.ca
  };
}
