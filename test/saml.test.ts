import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseXml, exc14n, kidsOf, XmlError, type Elem } from '../src/auth/saml/xml.js';
import { verifyResponse, buildAuthnRequest, metadataXml, redirectUrl, SamlError, SamlState } from '../src/auth/saml/saml.js';
import zlib from 'node:zlib';

const here = path.dirname(fileURLToPath(import.meta.url));
const fx = (n: string) => JSON.parse(fs.readFileSync(path.join(here, '..', '..', 'test', 'fixtures', n), 'utf8'));
const c14n = fx('c14n.json') as Record<string, { xml: string; c14n: string; subs: Record<string, string> }>;
const saml = fx('saml.json') as { acs: string; sp: string; idp: string; req: string; rsaCert: string; ecCert: string; cases: Record<string, { xml: string; cert: string }> };

function byPath(root: Elem, p: string): Elem {
  let cur = root;
  for (const step of p.split('/').slice(2)) {
    const els = kidsOf(cur);
    const m = /^\*\[(\d+)\]$/.exec(step);
    if (m) cur = els[Number(m[1]) - 1];
    else if (step === '*') cur = els[0];
    else cur = els.find(e => (e.prefix ? e.prefix + ':' : '') + e.local === step)!;
    assert.ok(cur, 'path ' + p);
  }
  return cur;
}

test('exclusive canonicalisation matches lxml for whole documents and for inner elements', () => {
  for (const [name, c] of Object.entries(c14n)) {
    const root = parseXml(c.xml);
    assert.equal(exc14n(root), c.c14n, name + ' (document)');
    for (const [p, want] of Object.entries(c.subs)) assert.equal(exc14n(byPath(root, p)), want, `${name} ${p}`);
  }
});

test('the XML reader refuses risky input', () => {
  for (const bad of ['<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>', '<a><?pi x?></a>', '<a><b></a>', '<a x="1" x="2"/>', '<p:a/>', '<a/><b/>', '<a>&bogus;</a>', '<a b=c/>', 'text']) {
    assert.throws(() => parseXml(bad), XmlError, bad);
  }
});

type Opts = Parameters<typeof verifyResponse>[1];
const base = (over: Partial<Opts> = {}): Omit<Opts, 'cert'> & { cert?: string } => ({
  idpEntity: saml.idp, sp: saml.sp, acs: saml.acs, requireSignedResponse: false, nameAttr: 'email', groupAttr: 'groups',
  knownRequest: (id: string) => id === saml.req, now: Date.parse('2026-10-13T12:01:00Z'), ...over
});
const run = (name: string, over: Partial<Opts> = {}, xmlEdit?: (x: string) => string) => {
  const c = saml.cases[name];
  const xml = xmlEdit ? xmlEdit(c.xml) : c.xml;
  return verifyResponse(Buffer.from(xml).toString('base64'), { ...base(over), cert: over.cert ?? (saml as unknown as Record<string, string>)[c.cert] });
};

test('accepts responses signed by an independent implementation (RSA and ECDSA, assertion or response signed)', () => {
  for (const n of ['rsa_assertion', 'rsa_response', 'ec_assertion']) {
    const r = run(n);
    assert.equal(r.name, 'jacob@example.com', n); assert.deepEqual(r.groups, ['netadmins', 'staff'], n); assert.equal(r.requestId, saml.req);
  }
  assert.deepEqual(run('escapes').groups, ['a&b<c']);
});

test('refuses unsigned, tampered and wrongly-keyed messages', () => {
  assert.throws(() => run('unsigned'), /not signed/);
  assert.throws(() => run('rsa_assertion', {}, x => x.replace('netadmins', 'superadmins')), /digest mismatch|changed/);
  assert.throws(() => run('rsa_assertion', { cert: saml.ecCert }), /does not match/);
  assert.throws(() => run('rsa_response', {}, x => x.replace('jacob@example.com', 'mallory@example.com')), /changed/);
  // wrapping: a second, unsigned assertion next to the signed one
  assert.throws(() => run('rsa_assertion', {}, x => x.replace('</samlp:Response>', '<saml:Assertion ID="_evil"><saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>')), /more than one assertion/);
  // duplicate IDs
  assert.throws(() => run('rsa_assertion', {}, x => x.replace('ID="_r1"', 'ID="_a1"')), /duplicate/);
});

test('checks audience, recipient, request id, time and issuer', () => {
  assert.throws(() => run('rsa_assertion', { sp: 'https://other/sp' }), /different service/);
  assert.throws(() => run('rsa_assertion', { acs: 'https://other/acs' }), /different URL/);
  assert.throws(() => run('rsa_assertion', { knownRequest: () => false }), /not for this server|answers a request/);
  assert.throws(() => run('rsa_assertion', { now: Date.parse('2031-01-01T00:00:00Z') }), /expired/);
  assert.throws(() => run('rsa_assertion', { now: Date.parse('2026-10-13T10:00:00Z') }), /not valid yet/);
  assert.throws(() => run('rsa_assertion', { idpEntity: 'https://another-idp' }), /different identity provider/);
  assert.throws(() => run('rsa_assertion', { requireSignedResponse: true }), /response itself is not signed/);
  assert.ok(run('rsa_response', { requireSignedResponse: true }));
});

test('request, redirect, metadata and replay bookkeeping', () => {
  const st = new SamlState();
  const id = st.newRequest();
  assert.ok(st.known(id));
  const x = buildAuthnRequest({ id, sp: saml.sp, acs: saml.acs, destination: 'https://idp.example.com/sso' });
  parseXml(x);
  const u = new URL(redirectUrl('https://idp.example.com/sso?tenant=1', x, 'r'));
  assert.equal(u.searchParams.get('tenant'), '1');
  assert.equal(zlib.inflateRawSync(Buffer.from(u.searchParams.get('SAMLRequest')!, 'base64')).toString(), x);
  assert.match(metadataXml(saml.sp, saml.acs), /AssertionConsumerService/);
  assert.ok(st.consume(id, '_a1', Date.now() + 1000));
  assert.ok(!st.consume(id, '_a1', Date.now() + 1000), 'a request can be answered once');
  const id2 = st.newRequest();
  assert.ok(!st.consume(id2, '_a1', Date.now() + 1000), 'an assertion can be used once');
  void SamlError;
});
