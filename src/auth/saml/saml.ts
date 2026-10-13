import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { attrOf, child, childEls, descendants, exc14n, isEl, kidsOf, parseXml, textOf, XmlError, type Elem } from './xml.js';

/**
 * SAML 2.0 Web Browser SSO, service-provider side: AuthnRequest over HTTP-Redirect, Response over HTTP-POST.
 *
 * Deliberately narrow: exclusive canonicalisation only, enveloped signatures only, one signed element per reference,
 * the IdP key comes from the configuration (KeyInfo in the message is ignored), unsigned assertions are never accepted,
 * encrypted assertions are not supported, and IdP-initiated responses are refused (every response must answer a request we made).
 */

export class SamlError extends Error {}

const NS = {
  ds: 'http://www.w3.org/2000/09/xmldsig#', samlp: 'urn:oasis:names:tc:SAML:2.0:protocol', saml: 'urn:oasis:names:tc:SAML:2.0:assertion',
  md: 'urn:oasis:names:tc:SAML:2.0:metadata', ec: 'http://www.w3.org/2001/10/xml-exc-c14n#'
};
const ALG_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const ALG_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
const SIG: Record<string, { hash: string; ec: boolean }> = {
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': { hash: 'sha256', ec: false }, 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384': { hash: 'sha384', ec: false },
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': { hash: 'sha512', ec: false },
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256': { hash: 'sha256', ec: true }, 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384': { hash: 'sha384', ec: true },
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512': { hash: 'sha512', ec: true }
};
const DIGEST: Record<string, string> = { 'http://www.w3.org/2001/04/xmlenc#sha256': 'sha256', 'http://www.w3.org/2001/04/xmldsig-more#sha384': 'sha384', 'http://www.w3.org/2001/04/xmlenc#sha512': 'sha512' };

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

export function newRequestId(): string { return '_' + crypto.randomBytes(20).toString('hex'); }

export function buildAuthnRequest(o: { id: string; sp: string; acs: string; destination: string; now?: number }): string {
  const t = new Date(o.now ?? Date.now()).toISOString().replace(/\.\d+Z$/, 'Z');
  return `<samlp:AuthnRequest xmlns:samlp="${NS.samlp}" xmlns:saml="${NS.saml}" ID="${o.id}" Version="2.0" IssueInstant="${t}" Destination="${esc(o.destination)}" ` +
    `ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="${esc(o.acs)}"><saml:Issuer>${esc(o.sp)}</saml:Issuer>` +
    `<samlp:NameIDPolicy AllowCreate="true"/></samlp:AuthnRequest>`;
}

export function redirectUrl(sso: string, requestXml: string, relayState?: string): string {
  const u = new URL(sso);
  u.searchParams.set('SAMLRequest', zlib.deflateRawSync(Buffer.from(requestXml, 'utf8')).toString('base64'));
  if (relayState) u.searchParams.set('RelayState', relayState);
  return u.toString();
}

export function metadataXml(sp: string, acs: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<md:EntityDescriptor xmlns:md="${NS.md}" entityID="${esc(sp)}"><md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="${NS.samlp}">` +
    `<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${esc(acs)}" index="0" isDefault="true"/></md:SPSSODescriptor></md:EntityDescriptor>\n`;
}

/* ------------------------------------------------------------------ signatures */

function certKeys(pem: string): crypto.KeyObject[] {
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
  const keys: crypto.KeyObject[] = [];
  for (const b of blocks) { try { keys.push(new crypto.X509Certificate(b).publicKey); } catch { /* skip an unreadable block */ } }
  if (!keys.length) throw new SamlError('The IdP signing certificate is missing or not valid PEM');
  return keys;
}

function prefixList(e: Elem | null): string[] {
  const inc = e ? child(e, NS.ec, 'InclusiveNamespaces') : null;
  return (attrOf(inc ?? ({ attrs: [] } as unknown as Elem), 'PrefixList') ?? '').split(/\s+/).filter(Boolean);
}

function eqB64(a: Buffer, b: Buffer): boolean { return a.length === b.length && crypto.timingSafeEqual(a, b); }

/** Verifies the enveloped signature inside `signed`. Returns true when it is valid and covers `signed`; throws when a signature is present but wrong. */
function verifyEnveloped(signed: Elem, keys: crypto.KeyObject[]): boolean {
  const sigs = childEls(signed, NS.ds, 'Signature');
  if (!sigs.length) return false;
  if (sigs.length > 1) throw new SamlError('The message has more than one signature on the same element');
  const sig = sigs[0];
  const si = child(sig, NS.ds, 'SignedInfo');
  if (!si) throw new SamlError('The signature has no SignedInfo');
  const cm = child(si, NS.ds, 'CanonicalizationMethod');
  if (!cm || attrOf(cm, 'Algorithm') !== ALG_C14N) throw new SamlError('Only exclusive XML canonicalization (without comments) is supported');
  const sm = child(si, NS.ds, 'SignatureMethod');
  const alg = sm ? SIG[attrOf(sm, 'Algorithm') ?? ''] : undefined;
  if (!alg) throw new SamlError('Unsupported signature algorithm. Use RSA or ECDSA with SHA-256, SHA-384 or SHA-512.');
  const refs = childEls(si, NS.ds, 'Reference');
  if (refs.length !== 1) throw new SamlError('The signature must have exactly one reference');
  const ref = refs[0];
  const id = attrOf(signed, 'ID');
  if (!id || attrOf(ref, 'URI') !== '#' + id) throw new SamlError('The signature does not cover the element it is attached to');
  const tr = child(ref, NS.ds, 'Transforms');
  const tAlgs = tr ? childEls(tr, NS.ds, 'Transform') : [];
  let enveloped = false; let incl: string[] = [];
  for (const t of tAlgs) {
    const a = attrOf(t, 'Algorithm');
    if (a === ALG_ENVELOPED) enveloped = true;
    else if (a === ALG_C14N) incl = prefixList(t);
    else throw new SamlError('Unsupported signature transform');
  }
  if (!enveloped) throw new SamlError('The signature must use the enveloped-signature transform');
  const dm = child(ref, NS.ds, 'DigestMethod');
  const dh = dm ? DIGEST[attrOf(dm, 'Algorithm') ?? ''] : undefined;
  if (!dh) throw new SamlError('Unsupported digest algorithm. Use SHA-256, SHA-384 or SHA-512.');
  const dv = child(ref, NS.ds, 'DigestValue');
  if (!dv) throw new SamlError('The signature has no digest');
  const want = Buffer.from(textOf(dv).replace(/\s+/g, ''), 'base64');
  const have = crypto.createHash(dh).update(exc14n(signed, sig, incl), 'utf8').digest();
  if (!eqB64(want, have)) throw new SamlError('The message was changed after it was signed (digest mismatch)');
  const sv = child(sig, NS.ds, 'SignatureValue');
  if (!sv) throw new SamlError('The signature has no value');
  const sigBytes = Buffer.from(textOf(sv).replace(/\s+/g, ''), 'base64');
  const data = Buffer.from(exc14n(si, null, prefixList(cm)), 'utf8');
  for (const k of keys) {
    try {
      const ok = alg.ec ? crypto.verify(alg.hash, data, { key: k, dsaEncoding: 'ieee-p1363' }, sigBytes) : crypto.verify(alg.hash, data, k, sigBytes);
      if (ok) return true;
    } catch { /* wrong key type for this algorithm: try the next key */ }
  }
  throw new SamlError('The signature does not match the IdP signing certificate. Check that the certificate pasted here is the one the IdP signs with.');
}

/* ------------------------------------------------------------------ response */

export interface ResponseOpts {
  cert: string; idpEntity: string; sp: string; acs: string;
  /** true when this is the id of a request we sent and have not yet answered */
  knownRequest(id: string): boolean;
  requireSignedResponse: boolean;
  nameAttr: string; groupAttr: string;
  now?: number; skewMs?: number;
}
export interface SamlResult { name: string; groups: string[]; assertionId: string; expires: number; requestId: string; nameId: string; attributes: Record<string, string[]> }

const parseT = (s: string | null): number | null => { if (!s) return null; const t = Date.parse(s); return Number.isFinite(t) ? t : null; };

export function verifyResponse(base64: string, o: ResponseOpts): SamlResult {
  const now = o.now ?? Date.now(); const skew = o.skewMs ?? 120_000;
  let xml: string;
  try { xml = Buffer.from(base64.replace(/\s+/g, ''), 'base64').toString('utf8'); } catch { throw new SamlError('The response is not valid base64'); }
  let root: Elem;
  try { root = parseXml(xml); } catch (e) { throw new SamlError('The response is not acceptable XML: ' + (e instanceof XmlError ? e.message : 'unreadable')); }
  if (!isEl(root, NS.samlp, 'Response')) throw new SamlError('The message is not a SAML Response');
  // IDs must be unique, or a signature could be made to cover a different element than the one that is read
  const ids = new Map<string, number>();
  for (const e of [root, ...descendants(root)]) { const v = attrOf(e, 'ID'); if (v !== null) ids.set(v, (ids.get(v) ?? 0) + 1); }
  for (const [, c] of ids) if (c > 1) throw new SamlError('The message has duplicate element IDs');

  const keys = certKeys(o.cert);
  const status = child(root, NS.samlp, 'Status'); const code = status ? child(status, NS.samlp, 'StatusCode') : null;
  const responseSigned = verifyEnveloped(root, keys);
  const statusVal = code ? attrOf(code, 'Value') : null;
  if (statusVal !== 'urn:oasis:names:tc:SAML:2.0:status:Success') {
    const detail = status ? (child(status, NS.samlp, 'StatusMessage') ? textOf(child(status, NS.samlp, 'StatusMessage')!).trim() : (code && child(code, NS.samlp, 'StatusCode') ? attrOf(child(code, NS.samlp, 'StatusCode')!, 'Value') : '')) : '';
    throw new SamlError('The identity provider did not sign you in' + (detail ? ': ' + String(detail).replace(/^urn:oasis:names:tc:SAML:2.0:status:/, '') : ''));
  }
  if (o.requireSignedResponse && !responseSigned) throw new SamlError('The response itself is not signed, and signed responses are required in the settings');
  const dest = attrOf(root, 'Destination');
  if (dest !== null && dest !== o.acs) throw new SamlError('The response was addressed to a different URL than this server\'s ACS URL');
  const reqId = attrOf(root, 'InResponseTo');
  const issuerEl = child(root, NS.saml, 'Issuer');
  if (issuerEl && o.idpEntity && textOf(issuerEl).trim() !== o.idpEntity) throw new SamlError('The response comes from a different identity provider than the one configured');

  if (childEls(root, NS.saml, 'EncryptedAssertion').length) throw new SamlError('Encrypted assertions are not supported. Turn off assertion encryption at the identity provider.');
  const assertions = childEls(root, NS.saml, 'Assertion');
  if (assertions.length !== 1) throw new SamlError(assertions.length ? 'The response has more than one assertion' : 'The response has no assertion');
  const a = assertions[0];
  const assertionSigned = verifyEnveloped(a, keys);
  if (!responseSigned && !assertionSigned) throw new SamlError('The assertion is not signed. Unsigned assertions are never accepted.');

  const aIssuer = child(a, NS.saml, 'Issuer');
  if (o.idpEntity && (!aIssuer || textOf(aIssuer).trim() !== o.idpEntity)) throw new SamlError('The assertion was issued by a different identity provider than the one configured');
  const subject = child(a, NS.saml, 'Subject');
  const nameIdEl = subject ? child(subject, NS.saml, 'NameID') : null;
  const confs = subject ? childEls(subject, NS.saml, 'SubjectConfirmation').filter(c => attrOf(c, 'Method') === 'urn:oasis:names:tc:SAML:2.0:cm:bearer') : [];
  if (!confs.length) throw new SamlError('The assertion has no bearer confirmation');
  let requestId = '';
  let confirmed = false;
  for (const c of confs) {
    const d = child(c, NS.saml, 'SubjectConfirmationData');
    if (!d) continue;
    const rcp = attrOf(d, 'Recipient'); const nb = parseT(attrOf(d, 'NotBefore')); const na = parseT(attrOf(d, 'NotOnOrAfter')); const irt = attrOf(d, 'InResponseTo');
    if (rcp !== o.acs) continue;
    if (na === null || na + skew <= now) continue;
    if (nb !== null && nb - skew > now) continue;
    if (!irt || (reqId !== null && irt !== reqId)) continue;
    if (!o.knownRequest(irt)) continue;
    requestId = irt; confirmed = true; break;
  }
  if (!confirmed) {
    if (!reqId) throw new SamlError('Sign-in that starts at the identity provider is not accepted. Start from the FlowScope sign-in page.');
    throw new SamlError('The sign-in is not for this server, has expired, or answers a request that was not made here. Try again from the FlowScope sign-in page.');
  }
  const cond = child(a, NS.saml, 'Conditions');
  if (!cond) throw new SamlError('The assertion has no conditions (audience and validity period)');
  const nb = parseT(attrOf(cond, 'NotBefore')); const na = parseT(attrOf(cond, 'NotOnOrAfter'));
  if (nb !== null && nb - skew > now) throw new SamlError('The assertion is not valid yet. Check that this server\'s clock is correct.');
  if (na === null || na + skew <= now) throw new SamlError('The assertion has expired. Check that this server\'s clock is correct.');
  const ars = childEls(cond, NS.saml, 'AudienceRestriction');
  if (!ars.length) throw new SamlError('The assertion has no audience restriction');
  for (const ar of ars) if (!childEls(ar, NS.saml, 'Audience').some(x => textOf(x).trim() === o.sp)) throw new SamlError(`The assertion is meant for a different service (expected audience ${o.sp})`);

  const attributes: Record<string, string[]> = {};
  const st = child(a, NS.saml, 'AttributeStatement');
  if (st) for (const at of childEls(st, NS.saml, 'Attribute')) {
    const vals = childEls(at, NS.saml, 'AttributeValue').map(v => textOf(v).trim()).filter(Boolean);
    for (const k of [attrOf(at, 'Name'), attrOf(at, 'FriendlyName')]) if (k) attributes[k] = (attributes[k] ?? []).concat(vals);
  }
  const nameId = nameIdEl ? textOf(nameIdEl).trim() : '';
  const want = (o.nameAttr || 'NameID').trim();
  const name = (want.toLowerCase() === 'nameid' ? nameId : (attributes[want]?.[0] ?? nameId)).trim();
  if (!name || name.length > 256 || /[\0-\x1f]/.test(name)) throw new SamlError('The assertion has no usable user name. Check the "user name attribute" setting.');
  const groups = o.groupAttr ? (attributes[o.groupAttr] ?? []) : [];
  const assertionId = attrOf(a, 'ID') ?? '';
  void kidsOf;
  return { name, groups, assertionId, expires: (na ?? now) + skew, requestId, nameId, attributes };
}

/** Keeps track of requests we sent and assertions we have already accepted. In memory: a restart only asks people to sign in again. */
export class SamlState {
  private reqs = new Map<string, number>(); private used = new Map<string, number>();
  newRequest(now = Date.now()): string { this.sweep(now); if (this.reqs.size > 5000) throw new SamlError('Too many sign-ins are in progress. Try again in a few minutes.'); const id = newRequestId(); this.reqs.set(id, now + 10 * 60_000); return id; }
  /** Test hook: pretends a request with this id was sent. */
  adopt(id: string, now = Date.now()): void { this.reqs.set(id, now + 10 * 60_000); }
  known = (id: string, now = Date.now()): boolean => (this.reqs.get(id) ?? 0) > now;
  /** Marks the request answered. False when the assertion (or request) was already used. */
  consume(requestId: string, assertionId: string, expires: number, now = Date.now()): boolean {
    this.sweep(now);
    if (!this.reqs.delete(requestId)) return false;
    if (this.used.has(assertionId)) return false;
    this.used.set(assertionId, expires);
    return true;
  }
  private sweep(now: number): void { for (const [k, v] of this.reqs) if (v <= now) this.reqs.delete(k); for (const [k, v] of this.used) if (v <= now) this.used.delete(k); }
}
