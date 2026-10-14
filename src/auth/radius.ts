import crypto from 'node:crypto';
import dgram from 'node:dgram';
import net from 'node:net';

/** RADIUS client (RFC 2865, 2866, 3579) for PAP logins and accounting. */

export const Code = { AccessRequest: 1, AccessAccept: 2, AccessReject: 3, AccountingRequest: 4, AccountingResponse: 5, AccessChallenge: 11 } as const;
export const Attr = {
  UserName: 1, UserPassword: 2, NasIpAddress: 4, NasPort: 5, ServiceType: 6, FilterId: 11, ReplyMessage: 18, State: 24, Class: 25, NasIdentifier: 32,
  AcctStatusType: 40, AcctSessionId: 44, AcctSessionTime: 46, NasPortType: 61, MessageAuthenticator: 80
} as const;

export interface RadiusAttr { type: number; value: Buffer }
export interface RadiusPacket { code: number; id: number; authenticator: Buffer; attrs: RadiusAttr[] }

export class RadiusError extends Error { constructor(m: string, readonly kind: 'timeout' | 'protocol' | 'config' = 'protocol') { super(m); } }

export function encodeAttrs(attrs: RadiusAttr[]): Buffer {
  return Buffer.concat(attrs.map(a => {
    if (a.value.length > 253) throw new RadiusError('RADIUS attribute too long', 'config');
    return Buffer.concat([Buffer.from([a.type, a.value.length + 2]), a.value]);
  }));
}

export function parseAttrs(b: Buffer): RadiusAttr[] {
  const out: RadiusAttr[] = [];
  let o = 0;
  while (o < b.length) {
    if (o + 2 > b.length) throw new RadiusError('Truncated RADIUS attribute');
    const l = b[o + 1];
    if (l < 2 || o + l > b.length) throw new RadiusError('Bad RADIUS attribute length');
    out.push({ type: b[o], value: b.subarray(o + 2, o + l) });
    o += l;
  }
  return out;
}

export function parsePacket(b: Buffer): RadiusPacket {
  if (b.length < 20) throw new RadiusError('RADIUS packet too short');
  const len = b.readUInt16BE(2);
  if (len < 20 || len > b.length || len > 4096) throw new RadiusError('Bad RADIUS packet length');
  return { code: b[0], id: b[1], authenticator: Buffer.from(b.subarray(4, 20)), attrs: parseAttrs(b.subarray(20, len)) };
}

/** RFC 2865 section 5.2: User-Password hiding. */
export function hidePassword(password: Buffer, secret: Buffer, requestAuth: Buffer): Buffer {
  const padded = Buffer.alloc(Math.max(16, Math.ceil(password.length / 16) * 16));
  password.copy(padded);
  if (padded.length > 128) throw new RadiusError('Password is too long for RADIUS (128 bytes)', 'config');
  const out = Buffer.alloc(padded.length);
  let prev = requestAuth;
  for (let i = 0; i < padded.length; i += 16) {
    const key = crypto.createHash('md5').update(Buffer.concat([secret, prev])).digest();
    for (let j = 0; j < 16; j++) out[i + j] = padded[i + j] ^ key[j];
    prev = out.subarray(i, i + 16);
  }
  return out;
}

export function packet(code: number, id: number, auth: Buffer, attrs: RadiusAttr[]): Buffer {
  const body = encodeAttrs(attrs);
  const h = Buffer.alloc(20);
  h[0] = code; h[1] = id; h.writeUInt16BE(20 + body.length, 2); auth.copy(h, 4);
  return Buffer.concat([h, body]);
}

/**
 * Adds Message-Authenticator (HMAC-MD5 over the whole packet, RFC 3579) to a request.
 * It goes first: that is what stops an attacker who can inject attributes at the front of a request
 * from building a forged reply (CVE-2024-3596, "Blast-RADIUS").
 */
function withMessageAuth(code: number, id: number, auth: Buffer, attrs: RadiusAttr[], secret: Buffer): Buffer {
  const placeholder: RadiusAttr = { type: Attr.MessageAuthenticator, value: Buffer.alloc(16) };
  const pkt = packet(code, id, auth, [placeholder, ...attrs]);
  const mac = crypto.createHmac('md5', secret).update(pkt).digest();
  mac.copy(pkt, 22);   // 20 byte header + type + length
  return pkt;
}

/** Verifies a response: Response Authenticator, and Message-Authenticator when present. */
export function verifyResponse(raw: Buffer, requestAuth: Buffer, secret: Buffer): boolean {
  const len = raw.readUInt16BE(2);
  const resp = crypto.createHash('md5').update(Buffer.concat([raw.subarray(0, 4), requestAuth, raw.subarray(20, len), secret])).digest();
  if (!crypto.timingSafeEqual(resp, raw.subarray(4, 20))) return false;
  const p = parsePacket(raw);
  const ma = p.attrs.find(a => a.type === Attr.MessageAuthenticator);
  if (ma) {
    if (ma.value.length !== 16) return false;
    const copy = Buffer.from(raw.subarray(0, len));
    // locate the attribute value inside the packet and zero it; the MAC is computed with the request authenticator in the header
    let o = 20;
    while (o < len) { if (copy[o] === Attr.MessageAuthenticator) { copy.fill(0, o + 2, o + 18); break; } o += copy[o + 1]; }
    requestAuth.copy(copy, 4);
    const mac = crypto.createHmac('md5', secret).update(copy).digest();
    if (!crypto.timingSafeEqual(mac, ma.value)) return false;
  }
  return true;
}

export interface RadiusServer { host: string; port: number }
export interface RadiusOpts { servers: RadiusServer[]; secret: string; timeoutMs: number; retries: number; nasId?: string; nasIp?: string; requireMa?: boolean }

/** What to do with a datagram that arrived while waiting for a reply: accept it, ignore it, or remember why it was refused. */
type Verdict = 'ok' | 'ignore' | string;

/**
 * Sends one request and waits for an acceptable reply. The socket is connected, so the kernel drops datagrams from any other
 * address or port. Replies that do not match (wrong id, bad signature) are ignored rather than ending the wait, so someone who
 * can send us UDP cannot cancel a sign-in by racing the server. If nothing acceptable arrives, the reason for the last refused
 * reply is reported instead of a bare timeout, which is how a wrong shared secret is still found.
 */
function exchange(srv: RadiusServer, req: Buffer, timeoutMs: number, judge: (m: Buffer) => Verdict): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket(net.isIPv6(srv.host) ? 'udp6' : 'udp4');
    let done = false, refused = '';
    const end = (fn: () => void) => { if (done) return; done = true; clearTimeout(timer); try { sock.close(); } catch { /* closed */ } fn(); };
    const timer = setTimeout(() => end(() => reject(refused ? new RadiusError(refused, 'protocol') : new RadiusError(`No answer from ${srv.host}:${srv.port}`, 'timeout'))), timeoutMs);
    sock.on('message', m => {
      const v = judge(m);
      if (v === 'ok') end(() => resolve(m));
      else if (v !== 'ignore' && !refused) refused = `${srv.host}: ${v}`;
    });
    sock.on('error', e => end(() => reject(new RadiusError(`${srv.host}: ${e.message}`, 'timeout'))));
    sock.connect(srv.port, srv.host, () => {
      if (done) return;
      sock.send(req, e => { if (e) end(() => reject(new RadiusError(`${srv.host}: ${e.message}`, 'timeout'))); });
    });
  });
}

export interface RadiusResult { accepted: boolean; challenge: boolean; replyMessage: string; filterIds: string[]; classes: string[]; server: string; messageAuth: boolean }

const ACCESS_REPLIES = new Set<number>([Code.AccessAccept, Code.AccessReject, Code.AccessChallenge]);

async function send(o: RadiusOpts, build: (id: number, auth: Buffer) => { raw: Buffer; auth: Buffer }, needMa = false): Promise<{ resp: Buffer; auth: Buffer; server: string }> {
  const secret = Buffer.from(o.secret);
  let lastErr: Error = new RadiusError('No RADIUS server is configured', 'config');
  for (const srv of o.servers) {
    for (let attempt = 0; attempt <= o.retries; attempt++) {
      const id = crypto.randomBytes(1)[0];
      const { raw, auth } = build(id, crypto.randomBytes(16));
      const judge = (m: Buffer): Verdict => {
        if (m.length < 20 || m[1] !== id) return 'ignore';
        const len = m.readUInt16BE(2);
        if (len < 20 || len > m.length) return 'ignore';
        let ok = false;
        try { ok = verifyResponse(m, auth, secret); } catch { return 'ignore'; }
        if (!ok) return 'the reply failed authentication. The shared secret is probably wrong.';
        if (needMa && ACCESS_REPLIES.has(m[0]) && !hasMessageAuth(m)) return 'the reply has no Message-Authenticator. Turn on Message-Authenticator on the RADIUS server (recommended, see CVE-2024-3596), or turn off "Require Message-Authenticator" here.';
        return 'ok';
      };
      try {
        const resp = await exchange(srv, raw, o.timeoutMs, judge);
        return { resp, auth, server: `${srv.host}:${srv.port}` };
      } catch (e) {
        lastErr = e as Error;
        if ((e as RadiusError).kind === 'protocol') throw e;
      }
    }
  }
  throw lastErr;
}

function hasMessageAuth(raw: Buffer): boolean {
  return parsePacket(raw).attrs.some(a => a.type === Attr.MessageAuthenticator);
}

/** Sends an Access-Request using PAP. */
export async function authenticate(o: RadiusOpts, username: string, password: string): Promise<RadiusResult> {
  if (!password) return { accepted: false, challenge: false, replyMessage: 'Empty password', filterIds: [], classes: [], server: '', messageAuth: false };
  const secret = Buffer.from(o.secret);
  const { resp, server } = await send(o, (id, auth) => {
    const attrs: RadiusAttr[] = [
      { type: Attr.UserName, value: Buffer.from(username) },
      { type: Attr.UserPassword, value: hidePassword(Buffer.from(password), secret, auth) },
      { type: Attr.ServiceType, value: Buffer.from([0, 0, 0, 8]) }, // Authenticate-Only
      { type: Attr.NasPortType, value: Buffer.from([0, 0, 0, 5]) } // Virtual
    ];
    if (o.nasId) attrs.push({ type: Attr.NasIdentifier, value: Buffer.from(o.nasId) });
    if (o.nasIp && net.isIPv4(o.nasIp)) attrs.push({ type: Attr.NasIpAddress, value: Buffer.from(o.nasIp.split('.').map(Number)) });
    return { raw: withMessageAuth(Code.AccessRequest, id, auth, attrs, secret), auth };
  }, !!o.requireMa);
  const p = parsePacket(resp);
  const txt = (t: number) => p.attrs.filter(a => a.type === t).map(a => a.value.toString('utf8'));
  return { accepted: p.code === Code.AccessAccept, challenge: p.code === Code.AccessChallenge, replyMessage: txt(Attr.ReplyMessage).join(' '), filterIds: txt(Attr.FilterId), classes: txt(Attr.Class), server, messageAuth: hasMessageAuth(resp) };
}

/** Sends an Accounting-Request (Start or Stop). */
export async function account(o: RadiusOpts, username: string, sessionId: string, status: 'start' | 'stop', seconds = 0): Promise<void> {
  const secret = Buffer.from(o.secret);
  await send(o, (id) => {
    const attrs: RadiusAttr[] = [
      { type: Attr.AcctStatusType, value: Buffer.from([0, 0, 0, status === 'start' ? 1 : 2]) },
      { type: Attr.UserName, value: Buffer.from(username) },
      { type: Attr.AcctSessionId, value: Buffer.from(sessionId) }
    ];
    if (status === 'stop') attrs.push({ type: Attr.AcctSessionTime, value: Buffer.from([(seconds >>> 24) & 255, (seconds >>> 16) & 255, (seconds >>> 8) & 255, seconds & 255]) });
    if (o.nasId) attrs.push({ type: Attr.NasIdentifier, value: Buffer.from(o.nasId) });
    // RFC 2866: Request Authenticator = MD5(Code + ID + Length + 16 zero octets + attributes + secret)
    const zero = packet(Code.AccountingRequest, id, Buffer.alloc(16), attrs);
    const auth = crypto.createHash('md5').update(Buffer.concat([zero, secret])).digest();
    const raw = Buffer.from(zero); auth.copy(raw, 4);
    return { raw, auth };
  });
}
