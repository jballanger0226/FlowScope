import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ConfigDb } from '../src/db/configdb.js';

test('upgrading a database that is one migration behind runs only the newest migration', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-mig-'));
  try {
    const a = new ConfigDb(dir);
    const latest = (a.db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version;
    // what a database deployed before the newest migration looks like
    a.db.exec('DROP TABLE mcast_members');   // undo the newest migration: update this line when a newer one is added
    a.db.exec(`PRAGMA user_version = ${latest - 1}`);
    a.db.close();
    const b = new ConfigDb(dir);   // would throw "table ... already exists" if an older migration ran again
    assert.equal((b.db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version, latest);
    assert.ok((b.db.prepare('PRAGMA table_info(mcast_members)').all() as { name: string }[]).some(c => c.name === 'ip'));
    b.db.close();
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
