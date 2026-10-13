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

/** scrypt password hashing in the form scrypt$N$r$p$salt$hash. */
export function hashPassword(pw: string): string {
  const salt = crypto.randomBytes(16);
  const N = 16384, r = 8, p = 1;
  const h = crypto.scryptSync(pw, salt, 32, { N, r, p, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${h.toString('base64')}`;
}

export function verifyPassword(pw: string, stored: string): boolean {
  const p = stored.split('$');
  if (p.length !== 6 || p[0] !== 'scrypt') return false;
  const N = Number(p[1]), r = Number(p[2]), pp = Number(p[3]);
  const salt = Buffer.from(p[4], 'base64'), want = Buffer.from(p[5], 'base64');
  const got = crypto.scryptSync(pw, salt, want.length, { N, r, p: pp, maxmem: 64 * 1024 * 1024 });
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

export function randomToken(bytes = 32): string { return crypto.randomBytes(bytes).toString('base64url'); }
export function sha256(s: string): string { return crypto.createHash('sha256').update(s).digest('hex'); }
