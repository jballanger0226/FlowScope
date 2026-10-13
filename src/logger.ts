import type { ConfigDb } from './db/configdb.js';
import type { Settings } from './settings.js';

export type Level = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';
const ORDER: Record<string, number> = { debug: 0, info: 1, warn: 2, error: 3 };

export interface LogRow { id: number; ts: number; level: Level; source: string; user: string; message: string }

/** Application log. Entries go to stdout and into the config database so admins can search and export them. */
export class AppLog {
  private queue: { ts: number; level: Level; source: string; user: string; message: string }[] = [];
  private timer: NodeJS.Timeout | null = null;
  private purgeTimer: NodeJS.Timeout | null = null;
  quiet = false;

  constructor(private cdb: ConfigDb, private settings: Settings, private minLevel: 'debug' | 'info' | 'warn' | 'error' = 'info') {
    this.timer = setInterval(() => this.flush(), 1000);
    this.timer.unref();
    this.purgeTimer = setInterval(() => this.purge(), 3600_000);
    this.purgeTimer.unref();
  }

  private add(level: Level, source: string, message: string, user = 'system'): void {
    const lv = level.toLowerCase();
    if (ORDER[lv] < ORDER[this.minLevel]) return;
    const ts = Date.now();
    this.queue.push({ ts, level, source, user, message });
    if (!this.quiet) {
      const line = `${new Date(ts).toISOString()} ${level.padEnd(5)} ${source.padEnd(9)} ${user === 'system' ? '' : '[' + user + '] '}${message}`;
      (level === 'ERROR' ? console.error : console.log)(line);
    }
    if (this.queue.length > 500) this.flush();
  }

  debug(source: string, message: string, user?: string): void { this.add('DEBUG', source, message, user); }
  info(source: string, message: string, user?: string): void { this.add('INFO', source, message, user); }
  warn(source: string, message: string, user?: string): void { this.add('WARN', source, message, user); }
  error(source: string, message: string, user?: string): void { this.add('ERROR', source, message, user); }
  /** Audit entries record who changed what. They are INFO or WARN with the source "audit". */
  audit(user: string, message: string, level: Level = 'INFO'): void { this.add(level, 'audit', message, user); }

  flush(): void {
    if (!this.queue.length) return;
    const rows = this.queue.splice(0, this.queue.length);
    try {
      this.cdb.tx(() => {
        const st = this.cdb.db.prepare('INSERT INTO logs(ts, level, source, user, message) VALUES (?, ?, ?, ?, ?)');
        for (const r of rows) st.run(r.ts, r.level, r.source, r.user, r.message);
      });
    } catch (e) { console.error('log flush failed', e); }
  }

  purge(): void {
    const days = Math.max(1, this.settings.get('logDays'));
    try { this.cdb.db.prepare('DELETE FROM logs WHERE ts < ?').run(Date.now() - days * 86400_000); } catch { /* ignore */ }
  }

  query(opts: { level?: string; source?: string; q?: string; limit?: number; since?: number }): LogRow[] {
    this.flush();
    const where: string[] = []; const args: (string | number)[] = [];
    if (opts.level && opts.level !== 'all') { where.push('level = ?'); args.push(opts.level); }
    if (opts.source && opts.source !== 'all') { where.push('source = ?'); args.push(opts.source); }
    if (opts.since) { where.push('ts >= ?'); args.push(opts.since); }
    if (opts.q) { where.push("(message LIKE ? ESCAPE '\\' OR user LIKE ? ESCAPE '\\' OR source LIKE ? ESCAPE '\\')"); const p = '%' + opts.q.replace(/[\\%_]/g, m => '\\' + m) + '%'; args.push(p, p, p); }
    const sql = `SELECT id, ts, level, source, user, message FROM logs ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY ts DESC, id DESC LIMIT ?`;
    args.push(Math.min(opts.limit ?? 1000, 50000));
    return this.cdb.db.prepare(sql).all(...args) as unknown as LogRow[];
  }

  close(): void {
    if (this.timer) clearInterval(this.timer);
    if (this.purgeTimer) clearInterval(this.purgeTimer);
    this.flush();
  }
}
