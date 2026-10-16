/**
 * The hardware model of a device, from ENTITY-MIB (RFC 6933): the chassis (a stack has one per member) and the modules in it.
 * entPhysicalClass 3 is a chassis and 9 a module. Only those rows are asked for the model, serial number and description, since a
 * large switch lists every fan, sensor and port.
 */
import { toNum, toStr, type SnmpClient, type SnmpValue } from './client.js';

const ENT = '1.3.6.1.2.1.47.1.1.1.1';
const COL = { descr: 2, name: 7, sw: 10, serial: 11, model: 13 } as const;

export interface EntityPart { index: number; name: string; model: string; descr: string; serial: string; sw: string }
export interface Entity { readAt: number; chassis: EntityPart[]; modules: EntityPart[] }

export async function readEntity(c: SnmpClient, now: number): Promise<Entity | null> {
  let cls: Map<string, SnmpValue>;
  try { cls = await c.column(`${ENT}.5`); } catch { return null; }
  const chassisIx: number[] = [], moduleIx: number[] = [];
  for (const [k, v] of cls) { const n = Number(k), t = toNum(v); if (!Number.isInteger(n)) continue; if (t === 3) chassisIx.push(n); else if (t === 9) moduleIx.push(n); }
  const want = [...chassisIx.slice(0, 20), ...moduleIx.slice(0, 40)];
  if (!want.length) return null;
  const text = new Map<string, string>();
  for (let i = 0; i < want.length; i += 8) {
    const oids = want.slice(i, i + 8).flatMap(n => Object.values(COL).map(col => `${ENT}.${col}.${n}`));
    try { for (const [oid, vb] of await c.get(oids)) text.set(oid, toStr(vb.value as SnmpValue).trim()); } catch { /* a device that will not answer gives less */ }
  }
  const part = (n: number): EntityPart => { const g = (col: number) => text.get(`${ENT}.${col}.${n}`) ?? ''; return { index: n, name: g(COL.name), model: g(COL.model), descr: g(COL.descr), serial: g(COL.serial), sw: g(COL.sw) }; };
  const chassis = chassisIx.slice(0, 20).map(part).filter(p => p.model || p.descr), modules = moduleIx.slice(0, 40).map(part).filter(p => p.model);
  return chassis.length || modules.length ? { readAt: now, chassis, modules } : null;
}

/** "C9300-48UXM" for one chassis, "4 × C9300-48UXM" for a stack of identical members, "C9300-48UXM + C9300-24T" for a mixed one. */
export function modelText(e: Entity | null): string {
  if (!e) return '';
  const names = e.chassis.map(p => p.model || p.descr).filter(Boolean);
  const counts = new Map<string, number>();
  for (const n of names) counts.set(n, (counts.get(n) ?? 0) + 1);
  return [...counts].map(([n, k]) => (k > 1 ? `${k} × ${n}` : n)).join(' + ');
}
