import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ConfigDb } from '../src/db/configdb.js';
import { Settings } from '../src/settings.js';

test('settings are cached, writes show up at once, and callers cannot corrupt the cache', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-set-'));
  const cdb = new ConfigDb(dir);
  try {
    const s = new Settings(cdb);
    const a = s.get('retention');
    const raw0 = a.raw;
    a.raw = 9999; // mutate the copy we were given
    assert.equal(s.get('retention').raw, raw0, 'a caller changing its copy must not change later reads');
    s.set('retention', { ...s.get('retention'), raw: 7 });
    assert.equal(s.get('retention').raw, 7, 'set() must be visible to the next get()');
    s.setRaw('retention', JSON.stringify({ ...s.get('retention'), raw: 11 }));
    assert.equal(s.get('retention').raw, 11, 'setRaw() must be visible to the next get()');
  } finally { cdb.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
