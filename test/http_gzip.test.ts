import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { WebServer } from '../src/server/http.js';

async function server() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-web-'));
  fs.writeFileSync(path.join(root, 'index.html'), '<html>' + 'x'.repeat(5000) + '</html>');
  fs.writeFileSync(path.join(root, 'app.js'), 'console.log(1);\n'.repeat(500));
  const web = new WebServer({ fromSession: () => null, fromToken: () => null }, root, false);
  web.get('/api/big', null, c => c.json({ rows: Array.from({ length: 3000 }, (_, i) => ({ i, name: 'row-' + i })) }));
  web.get('/api/small', null, c => c.json({ ok: true }));
  web.get('/api/boom', null, () => { throw new Error('nope'); });
  const ports = await web.listen({ host: '127.0.0.1', httpPort: 0 });
  const base = `http://127.0.0.1:${ports.http}`;
  return { web, root, base, done: async () => { await web.close(); fs.rmSync(root, { recursive: true, force: true }); } };
}

// fetch decodes gzip by itself, so the wire format is checked with a raw request
async function raw(url: string, headers: Record<string, string> = {}, method = 'GET') {
  const http = await import('node:http');
  return new Promise<{ status: number; headers: http.IncomingHttpHeaders; body: Buffer }>((res, rej) => {
    const req = http.request(url, { method, headers }, r => { const parts: Buffer[] = []; r.on('data', d => parts.push(d)); r.on('end', () => res({ status: r.statusCode!, headers: r.headers, body: Buffer.concat(parts) })); });
    req.on('error', rej); req.end();
  });
}

test('large JSON is gzipped when asked for and plain otherwise', async () => {
  const s = await server();
  try {
    const gz = await raw(s.base + '/api/big', { 'accept-encoding': 'gzip' });
    assert.equal(gz.status, 200); assert.equal(gz.headers['content-encoding'], 'gzip'); assert.equal(gz.headers['content-length'], String(gz.body.length));
    const rows = JSON.parse(zlib.gunzipSync(gz.body).toString()).rows;
    assert.equal(rows.length, 3000); assert.equal(rows[2999].name, 'row-2999');
    const plain = await raw(s.base + '/api/big');
    assert.equal(plain.headers['content-encoding'], undefined);
    assert.equal(JSON.parse(plain.body.toString()).rows.length, 3000);
    const small = await raw(s.base + '/api/small', { 'accept-encoding': 'gzip' });
    assert.equal(small.headers['content-encoding'], undefined);
    const head = await raw(s.base + '/app.js', { 'accept-encoding': 'gzip' }, 'HEAD');
    assert.equal(head.status, 200); assert.equal(head.body.length, 0);
    const err = await raw(s.base + '/api/boom', { 'accept-encoding': 'gzip' });
    assert.equal(err.status, 500);
  } finally { await s.done(); }
});

test('static files are compressed once and served again from memory, and a changed file is picked up', async () => {
  const s = await server();
  try {
    const first = await raw(s.base + '/app.js', { 'accept-encoding': 'gzip' });
    assert.equal(first.headers['content-encoding'], 'gzip');
    assert.equal(zlib.gunzipSync(first.body).toString().split('\n').length, 501);
    const orig = zlib.gzip;
    let calls = 0;
    (zlib as { gzip: unknown }).gzip = (...a: unknown[]) => { calls++; return (orig as (...x: unknown[]) => unknown)(...a); };
    try {
      for (let i = 0; i < 5; i++) assert.equal((await raw(s.base + '/app.js', { 'accept-encoding': 'gzip' })).headers['content-encoding'], 'gzip');
      assert.equal(calls, 0, 'the compressed copy is reused');
      fs.writeFileSync(path.join(s.root, 'app.js'), 'console.log(2);\n'.repeat(900));
      const changed = await raw(s.base + '/app.js', { 'accept-encoding': 'gzip' });
      assert.equal(zlib.gunzipSync(changed.body).toString().split('\n').length, 901);
      assert.equal(calls, 1);
    } finally { (zlib as { gzip: unknown }).gzip = orig; }
    const tag = first.headers.etag as string;
    assert.equal((await raw(s.base + '/index.html', { 'if-none-match': 'x' })).status, 200);
    const idx = await raw(s.base + '/index.html');
    assert.equal((await raw(s.base + '/index.html', { 'if-none-match': idx.headers.etag as string })).status, 304);
    assert.ok(tag);
  } finally { await s.done(); }
});
