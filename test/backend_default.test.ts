import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { App } from '../src/app.js';
import { loadConfig } from '../src/config.js';

/*
 * Which storage backend a start-up picks. ClickHouse is the default wherever the install provisions a server (the Docker compose files,
 * the Linux and Proxmox installers, the Proxmox template). Those set FLOWSCOPE_CLICKHOUSE_URL; a bare run without one stays on SQLite.
 * An install that already has data, or a stored choice, never changes because of the default.
 */

process.env.FLOWSCOPE_ADMIN_PASSWORD = 'admin-test-passphrase-1';

const freePort = () => new Promise<number>(res => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = (s.address() as net.AddressInfo).port; s.close(() => res(p)); }); });
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'fs-backend-'));

/** Starts the app far enough to open its store, reports what it chose, and shuts it down again. */
async function boot(dir: string, env: Record<string, string>) {
  const cfg = loadConfig({ FLOWSCOPE_TLS: 'off', FLOWSCOPE_HTTP_PORT: '0', FLOWSCOPE_LOG_LEVEL: 'error', FLOWSCOPE_MASTER_KEY: 'test-key', ...env });
  cfg.dataDir = dir;
  const app = await App.create(cfg);
  app.log.quiet = true;
  const r = { stored: app.settings.get('backend'), kind: app.store.kind, storeError: app.storeError };
  await app.store.close();
  app.log.close();
  app.cdb.close();
  return r;
}

/** Stands in for a ClickHouse server: refuses the first `failFirst` requests with a 503, then accepts everything. */
async function fakeClickHouse(failFirst: number) {
  let n = 0;
  const srv = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      n++;
      if (n <= failFirst) { res.statusCode = 503; res.end('starting up'); return; }
      res.setHeader('content-type', 'application/json');
      res.end('{"v":"25.8.1.1"}\n');
    });
  });
  await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
  return { url: `http://flowscope:secret@127.0.0.1:${(srv.address() as net.AddressInfo).port}/flowscope`, close: () => new Promise<void>(r => srv.close(() => r())), requests: () => n };
}

test('no ClickHouse URL: a new install uses SQLite', { timeout: 60_000 }, async () => {
  const r = await boot(tmp(), {});
  assert.equal(r.stored, 'sqlite');
  assert.equal(r.kind, 'sqlite');
  assert.equal(r.storeError, null);
});

test('a ClickHouse URL makes ClickHouse the default for a new install', { timeout: 60_000 }, async () => {
  const ch = await fakeClickHouse(0);
  try {
    const r = await boot(tmp(), { FLOWSCOPE_CLICKHOUSE_URL: ch.url });
    assert.equal(r.stored, 'clickhouse');
    assert.equal(r.kind, 'clickhouse');
    assert.equal(r.storeError, null);
  } finally { await ch.close(); }
});

test('FLOWSCOPE_BACKEND=sqlite overrides the ClickHouse default', { timeout: 60_000 }, async () => {
  const ch = await fakeClickHouse(0);
  try {
    const r = await boot(tmp(), { FLOWSCOPE_CLICKHOUSE_URL: ch.url, FLOWSCOPE_BACKEND: 'sqlite' });
    assert.equal(r.stored, 'sqlite');
    assert.equal(r.kind, 'sqlite');
    assert.equal(ch.requests(), 0);
  } finally { await ch.close(); }
});

test('an existing SQLite install keeps its data when a ClickHouse URL appears (upgrade)', { timeout: 60_000 }, async () => {
  const dir = tmp();
  // the first run, before ClickHouse was configured, creates the SQLite store
  assert.equal((await boot(dir, {})).kind, 'sqlite');
  // forget the stored choice, as on an install made before the setting existed
  const Database = (await import('node:sqlite')).DatabaseSync;
  const db = new Database(path.join(dir, 'config.db'));
  db.prepare("DELETE FROM settings WHERE key = 'backend'").run();
  db.close();
  const ch = await fakeClickHouse(0);
  try {
    const r = await boot(dir, { FLOWSCOPE_CLICKHOUSE_URL: ch.url });
    assert.equal(r.stored, 'sqlite');
    assert.equal(r.kind, 'sqlite');
    assert.equal(ch.requests(), 0);
  } finally { await ch.close(); }
});

test('the stored choice wins over a changed environment', { timeout: 60_000 }, async () => {
  const dir = tmp();
  const ch = await fakeClickHouse(0);
  try {
    assert.equal((await boot(dir, { FLOWSCOPE_CLICKHOUSE_URL: ch.url })).stored, 'clickhouse');
    // later start without the URL: still ClickHouse by choice, and since it cannot be used, SQLite serves this run and says why
    const r = await boot(dir, { FLOWSCOPE_CLICKHOUSE_WAIT: '0' });
    assert.equal(r.stored, 'clickhouse');
    assert.equal(r.kind, 'sqlite');
    assert.match(r.storeError ?? '', /Falling back to the embedded SQLite/);
  } finally { await ch.close(); }
});

test('waits for ClickHouse that is still starting, then uses it', { timeout: 60_000 }, async () => {
  const ch = await fakeClickHouse(2);
  try {
    const t0 = Date.now();
    const r = await boot(tmp(), { FLOWSCOPE_CLICKHOUSE_URL: ch.url, FLOWSCOPE_CLICKHOUSE_WAIT: '20' });
    assert.equal(r.kind, 'clickhouse');
    assert.equal(r.storeError, null);
    assert.ok(Date.now() - t0 >= 3500, 'it retried instead of giving up at once');
  } finally { await ch.close(); }
});

test('falls back to SQLite when ClickHouse never answers, without hanging past the wait', { timeout: 60_000 }, async () => {
  const dead = await freePort();
  const t0 = Date.now();
  const r = await boot(tmp(), { FLOWSCOPE_CLICKHOUSE_URL: `http://flowscope:secret@127.0.0.1:${dead}/flowscope`, FLOWSCOPE_CLICKHOUSE_WAIT: '5' });
  assert.equal(r.stored, 'clickhouse');
  assert.equal(r.kind, 'sqlite');
  assert.match(r.storeError ?? '', /could not be used/);
  assert.ok(Date.now() - t0 < 15_000);
});

test('a malformed ClickHouse URL falls back at once instead of waiting', { timeout: 60_000 }, async () => {
  const t0 = Date.now();
  const r = await boot(tmp(), { FLOWSCOPE_CLICKHOUSE_URL: 'ftp://flowscope:secret@127.0.0.1/flowscope', FLOWSCOPE_CLICKHOUSE_WAIT: '30' });
  assert.equal(r.kind, 'sqlite');
  assert.match(r.storeError ?? '', /must start with http/);
  assert.ok(Date.now() - t0 < 10_000);
});
