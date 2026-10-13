import type { App } from '../app.js';
import type { Ctx } from '../server/http.js';
import { HttpError, SESSION_COOKIE } from '../server/http.js';
import { AuthError } from '../auth/service.js';
import { buildAuthnRequest, metadataXml, redirectUrl, SamlError, verifyResponse } from '../auth/saml/saml.js';

const page = (title: string, body: string) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>` +
  `<style>body{background:#0D1217;color:#E7EDF2;font:15px/1.5 system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh}main{max-width:520px;padding:24px}a{color:#3FD0BC}</style></head><body><main>${body}</main></body></html>`;
const esc = (s: string) => s.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!));

export function registerSaml(app: App): void {
  const w = app.web;
  const cfg = () => app.settings.get('aaa');

  /** The address people (and the IdP) use to reach this server. */
  const base = (c: Ctx): string => {
    if (app.cfg.publicUrl) return app.cfg.publicUrl.replace(/\/+$/, '');
    const host = String(c.req.headers.host || 'localhost');
    return `${c.secure ? 'https' : 'http'}://${host}`;
  };
  const urls = (c: Ctx) => { const b = base(c); const s = cfg().saml; return { acs: `${b}/api/auth/saml/acs`, sp: s.sp || `${b}/api/auth/saml/metadata` }; };

  w.get('/api/auth/saml/metadata', null, c => {
    const u = urls(c);
    c.text(metadataXml(u.sp, u.acs), 'application/samlmetadata+xml; charset=utf-8', 200, { 'Content-Disposition': 'inline; filename="flowscope-sp-metadata.xml"' });
  });

  w.get('/api/auth/saml/login', null, c => {
    const a = cfg();
    if (a.services.web !== 'saml') throw new HttpError(404, 'SAML sign-in is not turned on');
    if (!a.saml.idpSso) throw new HttpError(400, 'SAML sign-in is not fully set up: the IdP sign-on URL is missing');
    const u = urls(c);
    const id = app.saml.newRequest();
    const xml = buildAuthnRequest({ id, sp: u.sp, acs: u.acs, destination: a.saml.idpSso });
    c.redirect(redirectUrl(a.saml.idpSso, xml));
  });

  w.post('/api/auth/saml/acs', null, async c => {
    const a = cfg();
    const fail = (status: number, msg: string): void => {
      c.text(page('Sign-in failed', `<h2>Sign-in failed</h2><p>${esc(msg)}</p><p><a href="/">Back to the FlowScope sign-in page</a></p>`), 'text/html; charset=utf-8', status);
    };
    if (a.services.web !== 'saml') return fail(404, 'SAML sign-in is not turned on.');
    let form: URLSearchParams;
    try { form = await c.form(600_000); } catch (e) { return fail(400, (e as Error).message); }
    const resp = form.get('SAMLResponse');
    if (!resp) return fail(400, 'No SAML response was sent.');
    const u = urls(c);
    try {
      const r = verifyResponse(resp, {
        cert: a.saml.idpCert, idpEntity: a.saml.idpEntity, sp: u.sp, acs: u.acs, knownRequest: id => app.saml.known(id),
        requireSignedResponse: a.saml.sign, nameAttr: a.saml.nameAttr, groupAttr: a.saml.groupAttr
      });
      if (!app.saml.consume(r.requestId, r.assertionId, r.expires)) throw new SamlError('This sign-in was already used. Start again from the FlowScope sign-in page.');
      const { principal } = app.auth.samlLogin(r.name, r.groups, c.ip);
      const s = app.auth.createSession(principal, c.ip);
      c.setCookie(SESSION_COOKIE, s.token, { maxAge: 12 * 3600 });
      c.redirect('/#/explorer');
    } catch (e) {
      if (e instanceof SamlError) { app.log.warn('auth', `SAML response refused from ${c.ip}: ${e.message}`); return fail(401, e.message); }
      if (e instanceof AuthError) return fail(e.status, e.message);
      throw e;
    }
  }, { csrf: false });
}
