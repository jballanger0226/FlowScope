import { parentPort, workerData } from 'node:worker_threads';
import { SqliteOps, openTsDb } from './ops.js';

interface Init { dir: string; writer: boolean }
const init = workerData as Init;
const db = openTsDb({ dir: init.dir, readOnly: !init.writer });
const ops = new SqliteOps(db, init.dir, init.writer);

interface Msg { id: number; op: string; args: unknown[] }
const allowedWrite = new Set(['insertFlows', 'insertSnmp', 'maintain', 'deleteDevice', 'stats']);
const allowedRead = new Set(['searchStreams', 'streamRecords', 'report', 'ifSeries', 'classSeries', 'classLatest', 'ifLatest', 'stats']);

parentPort!.on('message', (m: Msg | { close: true }) => {
  if ('close' in m) { try { db.close(); } catch { /* ignore */ } process.exit(0); }
  const allowed = init.writer ? allowedWrite : allowedRead;
  try {
    if (!allowed.has(m.op)) throw new Error('operation not allowed: ' + m.op);
    if (!init.writer) ops.refresh();
    const fn = (ops as unknown as Record<string, (...a: unknown[]) => unknown>)[m.op];
    const res = fn.apply(ops, m.args);
    parentPort!.postMessage({ id: m.id, ok: true, res });
  } catch (e) {
    parentPort!.postMessage({ id: m.id, ok: false, err: (e as Error).message });
  }
});
parentPort!.postMessage({ ready: true });
