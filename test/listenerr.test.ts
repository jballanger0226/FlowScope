import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { listenHint } from '../src/server/listenerr.js';

test('permission and in-use errors on a web port say what to do', () => {
  const a = listenHint(Object.assign(new Error('listen EACCES'), { code: 'EACCES', port: 443 }), [443]) as Error;
  assert.match(a.message, /port 443/); assert.match(a.message, /CAP_NET_BIND_SERVICE/); assert.match(a.message, /8443/);
  const b = listenHint(Object.assign(new Error('listen EADDRINUSE'), { code: 'EADDRINUSE', port: 8443 }), [8443]) as Error;
  assert.match(b.message, /already listening/);
});

test('other errors, and permission errors on high ports, are returned unchanged', () => {
  const e1 = Object.assign(new Error('x'), { code: 'EACCES', port: 8443 });
  assert.equal(listenHint(e1, [8443]), e1);
  const e2 = new Error('boom'); assert.equal(listenHint(e2, [443]), e2);
  assert.equal(listenHint(null, [443]), null);
});

test('a port that is really taken produces the hint', async () => {
  const s = net.createServer(); await new Promise<void>(r => s.listen(0, '127.0.0.1', () => r()));
  const port = (s.address() as net.AddressInfo).port;
  const err = await new Promise<unknown>(r => { const t = net.createServer(); t.once('error', r); t.listen(port, '127.0.0.1'); });
  assert.match((listenHint(err, [port]) as Error).message, new RegExp(`port ${port}`));
  s.close();
});
