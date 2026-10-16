import type { HopView, RouteView } from './hops.js';
import { lookupFib, type Fib } from '../snmp/fib.js';

/**
 * Sets each hop's forwarding-table answer for the destination of the stream and says when the flow left through an interface the table
 * does not use. The table is the device's state now, so for a flow from earlier the answer is only information: routes may have changed.
 */
export interface RouteCtx {
  fibOf(exporterIp: string): Fib | null;
  ifName(exporterIp: string, ifIndex: number): string;
  now?: number;
}

const FRESH_MS = 15 * 60_000;

/** `dest` is the destination of the direction these hops belong to: the responder going forward, the initiator coming back. */
export function checkRoutes(hops: HopView[], dest: string, ctx: RouteCtx): void {
  if (dest.includes(':')) return;
  for (const hop of hops) {
    const fib = ctx.fibOf(hop.exporter);
    if (!fib) continue;
    const e = lookupFib(fib, dest);
    if (!e) {
      hop.route = { prefix: '', len: 0, readAt: fib.readAt, paths: [], state: 'unknown' };
      if (!fib.truncated) hop.obs.push({ kind: 'path', severity: 'warn', text: `${hop.dev} has no route to ${dest} in its forwarding table.` });
      continue;
    }
    const paths = e.paths.map(p => ({ ifIndex: p.ifIndex, ifName: p.ifIndex ? ctx.ifName(hop.exporter, p.ifIndex) : '', nextHop: p.nextHop, kind: p.kind }));
    const used = paths.filter(p => p.ifIndex > 0);
    const local = e.paths.some(p => p.kind === 'receive');
    let state: RouteView['state'] = 'unknown';
    if (local) state = 'local';
    else if (used.length && hop.outIfIndex > 0) state = used.some(p => p.ifIndex === hop.outIfIndex) ? 'ok' : 'mismatch';
    hop.route = { prefix: e.prefix, len: e.len, readAt: fib.readAt, paths, state };
    if (state === 'mismatch') {
      const near = Math.abs((ctx.now ?? Date.now()) - fib.readAt) < FRESH_MS && Math.abs(hop.lastSeen - fib.readAt) < FRESH_MS;
      const where = used.map(p => `${p.ifName}${p.nextHop ? ' via ' + p.nextHop : ''}`).join(' or ');
      hop.obs.push({
        kind: 'path', severity: near ? 'warn' : 'info',
        text: `${hop.dev}'s forwarding table sends ${dest} (${e.prefix}/${e.len}) out ${where}, but this traffic left through ${hop.outIf}.${near ? ' Policy routing, a recent route change or an asymmetric path can cause this.' : ' The table was read at a different time than this traffic, so the route may have changed since.'}`
      });
    }
  }
}
