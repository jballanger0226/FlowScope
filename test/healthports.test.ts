import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { checkPorts, readPorts, writePorts } from '../src/healthports.js';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'fs-ports-'));
const cfg = (dataDir: string) => ({ httpsPort: 8443, httpPort: 0, dataDir });

test('the ports the server opened are written and read back', () => {
  const d = tmp();
  try {
    assert.deepEqual(readPorts(d), {}, 'nothing recorded yet');
    writePorts(d, { https: 443, http: 8080 });
    assert.deepEqual(readPorts(d), { https: 443, http: 8080 });
    writePorts(d, { https: 443 });
    assert.deepEqual(readPorts(d), { https: 443, http: undefined });
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('a shell with no settings checks the port the server recorded, not the built-in default', () => {
  const d = tmp();
  try {
    writePorts(d, { https: 443 });
    assert.deepEqual(checkPorts(cfg(d), {}), { https: 443, http: 0 });
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('a port set in the environment wins over the recorded one', () => {
  const d = tmp();
  try {
    writePorts(d, { https: 443, http: 8080 });
    assert.equal(checkPorts({ ...cfg(d), httpsPort: 9443 }, { FLOWSCOPE_HTTPS_PORT: '9443' }).https, 9443);
    assert.equal(checkPorts({ ...cfg(d), httpPort: 8081 }, { FLOWSCOPE_HTTP_PORT: '8081' }).http, 8081);
    assert.equal(checkPorts(cfg(d), { FLOWSCOPE_HTTPS_PORT: '' }).https, 443, 'an empty setting does not count as set');
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('a missing, damaged or silly file falls back to the configured ports', () => {
  const d = tmp();
  try {
    assert.deepEqual(checkPorts(cfg(d), {}), { https: 8443, http: 0 });
    fs.writeFileSync(path.join(d, 'ports.json'), 'not json');
    assert.deepEqual(checkPorts(cfg(d), {}), { https: 8443, http: 0 });
    fs.writeFileSync(path.join(d, 'ports.json'), JSON.stringify({ https: 'x', http: 99999 }));
    assert.deepEqual(readPorts(d), { https: undefined, http: undefined });
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});
