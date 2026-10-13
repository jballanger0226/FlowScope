#!/usr/bin/env node
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadConfig, defaultDataDir } from './config.js';
import { VERSION } from './app.js';

const HELP = `FlowScope ${VERSION}: NetFlow / IPFIX collector with SNMP link and QoS monitoring

Usage:
  flowscope [start] [--demo]          Run the server (Ctrl+C to stop)
  flowscope reset-password <user>     Set a new one-time password for a local user (server may be stopped or running)
  flowscope healthcheck               Exit 0 when the local server answers (used by container health checks)
  flowscope version

Settings are environment variables; see the README. The most useful:
  FLOWSCOPE_DATA_DIR, FLOWSCOPE_HTTPS_PORT (8443), FLOWSCOPE_FLOW_PORTS (2055,4739), FLOWSCOPE_TLS (auto|off), FLOWSCOPE_HTTP_PORT, FLOWSCOPE_ADMIN_PASSWORD
`;

async function healthcheck(): Promise<number> {
  const cfg = loadConfig();
  const tryOne = (mod: typeof http | typeof https, port: number) => new Promise<boolean>(res => {
    const req = mod.request({ host: '127.0.0.1', port, path: '/api/auth/config', timeout: 4000, rejectUnauthorized: false } as https.RequestOptions, r => { r.resume(); res((r.statusCode ?? 500) < 500); });
    req.on('error', () => res(false)); req.on('timeout', () => { req.destroy(); res(false); }); req.end();
  });
  if (cfg.tls === 'auto' && await tryOne(https, cfg.httpsPort)) return 0;
  if (cfg.httpPort > 0 && await tryOne(http, cfg.httpPort)) return 0;
  return 1;
}

async function resetPassword(user: string | undefined): Promise<number> {
  if (!user) { console.error('Usage: flowscope reset-password <user>'); return 2; }
  const { ConfigDb } = await import('./db/configdb.js');
  const { hashPassword, randomToken } = await import('./secrets.js');
  const cdb = new ConfigDb(defaultDataDir());
  try {
    const row = cdb.db.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE AND source = 'local'").get(user) as { id: number } | undefined;
    if (!row) { console.error(`No local user "${user}" in ${defaultDataDir()}`); return 1; }
    const pw = randomToken(12).replace(/[-_]/g, 'x');
    cdb.db.prepare('UPDATE users SET pw_hash = ?, must_change = 1, failed = 0, locked_until = 0, disabled = 0 WHERE id = ?').run(hashPassword(pw), row.id);
    cdb.db.prepare('DELETE FROM sessions WHERE username = ?').run(user);
    cdb.db.prepare("INSERT INTO logs(ts, level, source, user, message) VALUES (?, 'WARN', 'audit', ?, ?)").run(Date.now(), os.userInfo().username, `Password of ${user} reset from the command line`);
    console.log(`New one-time password for ${user}: ${pw}\nIt must be changed at the next sign-in.`);
    return 0;
  } finally { cdb.close(); }
}

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  const cmd = args[0] && !args[0].startsWith('-') ? args[0] : 'start';
  switch (cmd) {
    case 'start': {
      const cfg = loadConfig();
      if (args.includes('--demo')) cfg.demo = true;
      if (cfg.demo) {
        process.env.FLOWSCOPE_ADMIN_PASSWORD ||= 'flowscope-demo-admin';
        if (!process.env.FLOWSCOPE_DATA_DIR) {
          // a throw-away data folder, so demo data never mixes with real data
          cfg.dataDir = path.join(os.tmpdir(), 'flowscope-demo');
          fs.rmSync(cfg.dataDir, { recursive: true, force: true });
        }
      }
      const { run } = await import('./main.js');
      await run(cfg);
      return -1; // keep running
    }
    case 'healthcheck': return healthcheck();
    case 'reset-password': return resetPassword(args[1]);
    case 'version': case '--version': case '-v': console.log(VERSION); return 0;
    case 'help': case '--help': case '-h': console.log(HELP); return 0;
    default: console.error(`Unknown command "${cmd}"\n\n${HELP}`); return 2;
  }
}

main().then(code => { if (code >= 0) process.exit(code); }, e => { console.error('FlowScope could not start:', e instanceof Error ? e.message : e); process.exit(1); });
