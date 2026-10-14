import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/** Encrypts stored secrets (SNMP passwords, RADIUS secret, bind passwords, private keys) with AES-256-GCM.
 *  The master key comes from FLOWSCOPE_MASTER_KEY (any string, hashed) or a 0600 file in the data directory. */
export class Secrets {
  private key: Buffer;

  constructor(dataDir: string, envKey = process.env.FLOWSCOPE_MASTER_KEY) {
    if (envKey) {
      this.key = crypto.createHash('sha256').update(envKey).digest();
    } else {
      const file = path.join(dataDir, 'master.key');
      if (fs.existsSync(file)) {
        this.key = Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'base64');
        if (this.key.length !== 32) throw new Error('master.key is not 32 bytes of base64');
      } else {
        this.key = crypto.randomBytes(32);
        fs.mkdirSync(dataDir, { recursive: true });
        fs.writeFileSync(file, this.key.toString('base64') + '\n', { mode: 0o600 });
      }
    }
  }

  encrypt(plain: string): string {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
    return 'v1:' + iv.toString('base64') + ':' + c.getAuthTag().toString('base64') + ':' + ct.toString('base64');
  }

  decrypt(blob: string): string {
    const p = blob.split(':');
    if (p.length !== 4 || p[0] !== 'v1') throw new Error('unrecognised secret format');
    const d = crypto.createDecipheriv('aes-256-gcm', this.key, Buffer.from(p[1], 'base64'));
    d.setAuthTag(Buffer.from(p[2], 'base64'));
    return Buffer.concat([d.update(Buffer.from(p[3], 'base64')), d.final()]).toString('utf8');
  }

  encryptJson(v: unknown): string { return this.encrypt(JSON.stringify(v)); }
  decryptJson<T>(blob: string | null | undefined, fallback: T): T {
    if (!blob) return fallback;
    try { return JSON.parse(this.decrypt(blob)) as T; } catch { return fallback; }
  }
}

/**
 * scrypt password hashing in the form scrypt$N$r$p$salt$hash. The parameters are stored with each hash, so passwords hashed with
 * older, cheaper settings keep working and are upgraded at the next successful sign-in.
 * New hashes use N=2^17, r=8, p=1 (OWASP Password Storage Cheat Sheet), about half a second and 128 MiB while hashing.
 * FLOWSCOPE_SCRYPT_LOG2N (4 to 18) overrides the exponent, which is mainly for tests.
 */
export interface ScryptCost { N: number; r: number; p: number }
export function targetCost(): ScryptCost {
  const e = Number(process.env.FLOWSCOPE_SCRYPT_LOG2N);
  return { N: 2 ** (Number.isInteger(e) && e >= 4 && e <= 18 ? e : 17), r: 8, p: 1 };
}
const memFor = (c: ScryptCost): number => 160 * c.N * c.r * c.p + 4 * 1024 * 1024;

function format(c: ScryptCost, salt: Buffer, h: Buffer): string {
  return `scrypt$${c.N}$${c.r}$${c.p}$${salt.toString('base64')}$${h.toString('base64')}`;
}
function parse(stored: string): { cost: ScryptCost; salt: Buffer; want: Buffer } | null {
  const p = stored.split('$');
  if (p.length !== 6 || p[0] !== 'scrypt') return null;
  const cost = { N: Number(p[1]), r: Number(p[2]), p: Number(p[3]) };
  if (![cost.N, cost.r, cost.p].every(Number.isInteger) || cost.N < 2 || cost.N > 2 ** 20 || cost.r < 1 || cost.r > 32 || cost.p < 1 || cost.p > 16) return null;
  return { cost, salt: Buffer.from(p[4], 'base64'), want: Buffer.from(p[5], 'base64') };
}

export function hashPassword(pw: string): string {
  const salt = crypto.randomBytes(16), c = targetCost();
  return format(c, salt, crypto.scryptSync(pw, salt, 32, { ...c, maxmem: memFor(c) }));
}

export function verifyPassword(pw: string, stored: string): boolean {
  const d = parse(stored);
  if (!d) return false;
  const got = crypto.scryptSync(pw, d.salt, d.want.length, { ...d.cost, maxmem: memFor(d.cost) });
  return got.length === d.want.length && crypto.timingSafeEqual(got, d.want);
}

/** True when a stored hash uses cheaper settings than new hashes do. */
export function needsRehash(stored: string): boolean {
  const d = parse(stored), t = targetCost();
  return !!d && (d.cost.N < t.N || d.cost.r < t.r || d.cost.p < t.p);
}

export class PasswordBusy extends Error { constructor() { super('Too many sign-ins are being checked right now. Try again in a moment.'); } }

/**
 * Runs password work off the main thread, a few at a time. Each scrypt at the current cost holds 128 MiB, so the number running at
 * once is capped, and so is the queue behind them: a flood of sign-ins gets "busy" instead of memory or an endless wait.
 */
class Gate {
  private running = 0;
  private waiting: (() => void)[] = [];
  constructor(private max: number, private maxQueue: number) {}
  async run<T>(fn: () => Promise<T>): Promise<T> {
    if (this.running >= this.max) {
      if (this.waiting.length >= this.maxQueue) throw new PasswordBusy();
      await new Promise<void>(res => this.waiting.push(res));
    } else this.running++;
    try { return await fn(); }
    finally { const next = this.waiting.shift(); if (next) next(); else this.running--; }
  }
}
const gate = new Gate(2, 64);

const scryptAsync = (pw: string, salt: Buffer, len: number, c: ScryptCost): Promise<Buffer> =>
  new Promise((res, rej) => crypto.scrypt(pw, salt, len, { ...c, maxmem: memFor(c) }, (e, k) => e ? rej(e) : res(k)));

export function hashPasswordAsync(pw: string): Promise<string> {
  return gate.run(async () => { const salt = crypto.randomBytes(16), c = targetCost(); return format(c, salt, await scryptAsync(pw, salt, 32, c)); });
}

export function verifyPasswordAsync(pw: string, stored: string): Promise<boolean> {
  const d = parse(stored);
  if (!d) return Promise.resolve(false);
  return gate.run(async () => {
    const got = await scryptAsync(pw, d.salt, d.want.length, d.cost);
    return got.length === d.want.length && crypto.timingSafeEqual(got, d.want);
  });
}

export function randomToken(bytes = 32): string { return crypto.randomBytes(bytes).toString('base64url'); }
export function sha256(s: string): string { return crypto.createHash('sha256').update(s).digest('hex'); }
