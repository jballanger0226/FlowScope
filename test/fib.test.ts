import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import type { SnmpClient, SnmpValue } from '../src/snmp/client.js';
import { lookupFib, readFib, type Fib } from '../src/snmp/fib.js';
import { checkRoutes } from '../src/analysis/route_check.js';
import type { HopView } from '../src/analysis/hops.js';

/** Rows from a real walk of a Catalyst 9300 stack (CISCO-CEF-MIB): 34 prefixes including the default route, host routes, connected and local ones. */
const FIX = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, '..', '..', 'test', 'fixtures', 'fib-c9300.json'), 'utf8')) as Record<string, SnmpValue>;
function agent(rows: Record<string, SnmpValue>, asBuffers = false): SnmpClient {
  return { column: async (col: string) => {
    const m = new Map<string, SnmpValue>();
    for (const [o, v] of Object.entries(rows)) if (o.startsWith(col + '.')) m.set(o.slice(col.length + 1), asBuffers && col.endsWith('.1.3.1.1.8') && typeof v === 'string' ? Buffer.from(v.split('.').map(Number)) : v);
    return m;
  } } as unknown as SnmpClient;
}

test('the forwarding table is read as prefixes with their egress interface and next hop', async () => {
  const f = (await readFib(agent(FIX), 1000))!;
  assert.ok(f); assert.equal(f.entries.length, 34); assert.equal(f.truncated, false);
  const def = f.entries.find(e => e.prefix === '0.0.0.0' && e.len === 0)!;
  assert.equal(def.paths[0]!.ifIndex, 427, 'the default route is resolved to the interface of its next hop, though its path is recursive');
  assert.equal(def.paths[0]!.nextHop, '10.201.168.77');
  assert.equal(def.paths[0]!.kind, 'recursive');
  assert.ok(f.entries.some(e => e.paths.some(p => p.kind === 'receive')), 'addresses of the device itself are marked');
  assert.ok(f.entries.some(e => e.paths.some(p => p.kind === 'attached' && p.ifIndex > 0 && p.nextHop)));
});

test('next hops that arrive as raw bytes (how SNMP delivers an InetAddress) read the same', async () => {
  const a = (await readFib(agent(FIX)))!, b = (await readFib(agent(FIX, true)))!;
  assert.deepEqual(b.entries, a.entries);
});

test('longest prefix wins, and an address nothing matches has no route', async () => {
  const f = (await readFib(agent(FIX)))!;
  const host = f.entries.find(e => e.len === 32 && e.paths[0]!.kind !== 'receive' && e.paths[0]!.ifIndex > 0)!;
  assert.equal(lookupFib(f, host.prefix)!.len, 32);
  assert.equal(lookupFib(f, '8.8.8.8')!.len, 0, 'falls back to the default route');
  const noDefault: Fib = { ...f, entries: f.entries.filter(e => e.len > 0) };
  assert.equal(lookupFib(noDefault, '8.8.8.8'), null);
  assert.equal(lookupFib(f, 'not-an-ip'), null);
});

test('a device without CISCO-CEF-MIB gives null', async () => { assert.equal(await readFib(agent({})), null); });

const hop = (over: Partial<HopView>): HopView => ({ n: 1, exporter: '10.1.1.1', dev: 'core', role: 'switch', inIf: 'Vl1', outIf: 'Vl107', inIfIndex: 1, outIfIndex: 107, outIfs: [], frameSrc: null, frameDst: null, vlan: null, vlanName: '', ttl: null, ttlExpired: null,
  dscpIn: 0, dscpOut: 0, dscpInS: '', dscpOutS: '', qosChanged: false, qosVerdict: null, pkts: 1, bytes: 1, firstSeen: 1000, lastSeen: 2000, linkMs: null, cumMs: null, policy: null, obs: [], ...over } as unknown as HopView);

test('a flow that leaves where the table says is ok; one that leaves elsewhere is called out', async () => {
  const f = (await readFib(agent(FIX), 1500))!;
  const ctx = { fibOf: () => f, ifName: (_e: string, i: number) => `if${i}`, now: 2000 };
  const good = hop({ outIfIndex: 427 }), bad = hop({ outIfIndex: 107, outIf: 'if107' }), unknown = hop({ outIfIndex: 0 });
  checkRoutes([good, bad, unknown], '8.8.8.8', ctx);
  assert.equal(good.route!.state, 'ok'); assert.equal(good.obs.length, 0);
  assert.equal(bad.route!.state, 'mismatch');
  assert.equal(bad.obs[0]!.severity, 'warn');
  assert.match(bad.obs[0]!.text, /sends 8\.8\.8\.8 \(0\.0\.0\.0\/0\) out if427 via 10\.201\.168\.77, but this traffic left through if107/);
  assert.equal(unknown.route!.state, 'unknown'); assert.equal(unknown.obs.length, 0, 'no egress reported means nothing to compare');
});

test('a mismatch far from the time the table was read is only information', async () => {
  const f = (await readFib(agent(FIX), 1_000_000))!;
  const bad = hop({ outIfIndex: 107, lastSeen: 1_000_000 + 3 * 3600_000 });
  checkRoutes([bad], '8.8.8.8', { fibOf: () => f, ifName: (_e, i) => `if${i}`, now: 1_000_000 + 3 * 3600_000 });
  assert.equal(bad.obs[0]!.severity, 'info'); assert.match(bad.obs[0]!.text, /route may have changed/);
});

test('an address that belongs to the device itself is local, not a mismatch; no table means no route info; IPv6 is skipped', async () => {
  const f = (await readFib(agent(FIX)))!;
  const own = f.entries.find(e => e.len === 32 && e.paths[0]!.kind === 'receive')!;
  const h1 = hop({ outIfIndex: 5 });
  checkRoutes([h1], own.prefix, { fibOf: () => f, ifName: (_e, i) => `if${i}` });
  assert.equal(h1.route!.state, 'local'); assert.equal(h1.obs.length, 0);
  const h2 = hop({}); checkRoutes([h2], '8.8.8.8', { fibOf: () => null, ifName: () => '' }); assert.equal(h2.route, undefined);
  const h3 = hop({}); checkRoutes([h3], '2001:db8::1', { fibOf: () => f, ifName: () => '' }); assert.equal(h3.route, undefined);
});
