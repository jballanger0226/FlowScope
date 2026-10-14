import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ConfigDb } from '../src/db/configdb.js';
import { Settings } from '../src/settings.js';

const unix = process.platform !== 'win32';

test('the data folder and config database are private to the owner', { skip: !unix }, () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-perm-'));
  const dir = path.join(parent, 'data');
  fs.mkdirSync(dir, { mode: 0o755 });
  fs.chmodSync(dir, 0o755);
  // an older install left the database readable by everyone
  fs.writeFileSync(path.join(dir, 'config.db'), '', { mode: 0o644 }); fs.chmodSync(path.join(dir, 'config.db'), 0o644);
  const cdb = new ConfigDb(dir);
  try {
    new Settings(cdb).setRaw('x', '1');
    assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
    for (const f of ['config.db', 'config.db-wal', 'config.db-shm']) {
      if (fs.existsSync(path.join(dir, f))) assert.equal(fs.statSync(path.join(dir, f)).mode & 0o077, 0, f + ' is not readable by others');
    }
    assert.ok(fs.existsSync(path.join(dir, 'config.db-wal')), 'the test exercised the WAL file');
  } finally { cdb.close(); fs.rmSync(parent, { recursive: true, force: true }); }
});

test('FLOWSCOPE_KEEP_DATA_PERMS leaves permissions alone', { skip: !unix }, () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-perm-'));
  const dir = path.join(parent, 'data');
  fs.mkdirSync(dir); fs.chmodSync(dir, 0o750);
  process.env.FLOWSCOPE_KEEP_DATA_PERMS = '1';
  try {
    const cdb = new ConfigDb(dir); cdb.close();
    assert.equal(fs.statSync(dir).mode & 0o777, 0o750);
  } finally { delete process.env.FLOWSCOPE_KEEP_DATA_PERMS; fs.rmSync(parent, { recursive: true, force: true }); }
});
