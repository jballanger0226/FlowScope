import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { readBuildInfo, shortRevision, describeVersion } from '../src/buildinfo.js';
import { VERSION } from '../src/app.js';

const sha = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'fs-build-'));

test('buildinfo.json is read, and anything odd in it is reported as unknown', () => {
  const d = tmp();
  try {
    const f = path.join(d, 'b.json');
    fs.writeFileSync(f, JSON.stringify({ revision: sha, builtAt: '2026-10-14T10:00:00.000Z' }));
    assert.deepEqual(readBuildInfo(pathToFileURL(f)), { revision: sha, builtAt: '2026-10-14T10:00:00.000Z' });
    fs.writeFileSync(f, JSON.stringify({ revision: '<script>', builtAt: 'yesterday' }));
    assert.deepEqual(readBuildInfo(pathToFileURL(f)), { revision: 'unknown', builtAt: null });
    fs.writeFileSync(f, 'not json');
    assert.equal(readBuildInfo(pathToFileURL(f)).revision, 'unknown');
    assert.equal(readBuildInfo(pathToFileURL(path.join(d, 'missing.json'))).revision, 'unknown');
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('revisions are shortened for display only when they are full commit ids', () => {
  assert.equal(shortRevision(sha), 'a1b2c3d');
  assert.equal(shortRevision(sha + '-dirty'), 'a1b2c3d-dirty');
  assert.equal(shortRevision('v1.2.0'), 'v1.2.0');
  assert.equal(describeVersion('0.1.0', { revision: sha, builtAt: null }), '0.1.0 (revision a1b2c3d)');
  assert.equal(describeVersion('0.1.0', { revision: 'unknown', builtAt: null }), '0.1.0 (revision unknown)');
});

test('VERSION matches package.json', () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  assert.equal(VERSION, (JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')) as { version: string }).version);
});

test('the build writes the revision it was given, or the checkout commit', () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const script = path.join(root, 'tools', 'build.mjs');
  // run only the revision logic: copy the script's function by running the real build would recompile everything, so load it as text
  const src = fs.readFileSync(script, 'utf8');
  const m = /function revision\(\) \{[\s\S]*?\n\}\n/.exec(src);
  assert.ok(m, 'revision() is in tools/build.mjs');
  const run = (env: Record<string, string>, cwd: string) => {
    const code = `import { execFileSync } from 'node:child_process'; const root = ${JSON.stringify(cwd)}; ${m[0]} console.log(revision());`;
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', code], { env: { PATH: process.env.PATH ?? '', ...env }, encoding: 'utf8' });
    return r.stdout.trim();
  };
  const d = tmp();
  try {
    assert.equal(run({ FLOWSCOPE_REVISION: sha }, d), sha);
    assert.equal(run({ FLOWSCOPE_REVISION: 'x y; rm -rf /' }, d), 'unknown', 'a value with spaces or shell characters is refused');
    assert.equal(run({}, d), 'unknown', 'no git folder and nothing given');
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});
