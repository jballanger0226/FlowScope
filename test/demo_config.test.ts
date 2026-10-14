import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { loadConfig, applyDemoDefaults } from '../src/config.js';

test('demo mode listens on loopback with a private, new data folder', () => {
  const cfg = loadConfig({});
  const note = applyDemoDefaults(cfg, {}, false);
  const cfg2 = loadConfig({}); applyDemoDefaults(cfg2, {}, false);
  try {
    assert.equal(cfg.bind, '127.0.0.1'); assert.equal(cfg.flowBind, '127.0.0.1'); assert.match(note, /127\.0\.0\.1/);
    assert.notEqual(cfg.dataDir, cfg2.dataDir, 'each run gets its own folder');
    assert.match(cfg.dataDir, /flowscope-demo-/);
    if (process.platform !== 'win32') assert.equal(fs.statSync(cfg.dataDir).mode & 0o077, 0);
  } finally { fs.rmSync(cfg.dataDir, { recursive: true, force: true }); fs.rmSync(cfg2.dataDir, { recursive: true, force: true }); }
});

test('explicit settings and containers keep the demo reachable', () => {
  const a = loadConfig({ FLOWSCOPE_BIND: '0.0.0.0' });
  const before = a.dataDir;
  assert.equal(applyDemoDefaults(a, { FLOWSCOPE_BIND: '0.0.0.0', FLOWSCOPE_FLOW_BIND: '0.0.0.0', FLOWSCOPE_DATA_DIR: before }, false), '');
  assert.equal(a.bind, '0.0.0.0'); assert.equal(a.flowBind, '0.0.0.0'); assert.equal(a.dataDir, before, 'a folder the person chose is kept');
  const b = loadConfig({}); const d = applyDemoDefaults(b, {}, true);
  try { assert.equal(b.bind, '0.0.0.0'); assert.equal(b.flowBind, '0.0.0.0'); assert.equal(d, ''); } finally { fs.rmSync(b.dataDir, { recursive: true, force: true }); }
});
