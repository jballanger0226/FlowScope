import test from 'node:test';
import assert from 'node:assert/strict';
import { WalkJobs, WalkBusy, filterRows, exportRows, jobView, type Row } from '../src/snmp/walkjobs.js';
import { compareOid, type SnmpClient, type VarBind } from '../src/snmp/client.js';

/** A client whose walk delivers the given varbinds in batches of 3, optionally failing or waiting on a gate before the second batch. */
function fakeClient(vbs: VarBind[], o: { fail?: string; gate?: Promise<void> } = {}) {
  let closed = 0;
  const c = {
    close: () => { closed++; },
    walkEach: async (_oid: string, onRows: (r: VarBind[]) => boolean | void) => {
      for (let i = 0; i < vbs.length; i += 3) {
        if (i === 3 && o.gate) await o.gate;
        if (i === 3 && o.fail) throw new Error(o.fail);
        if (onRows(vbs.slice(i, i + 3)) === true) return 'stopped' as const;
      }
      return 'done' as const;
    }
  };
  return { c: c as unknown as SnmpClient, closed: () => closed };
}
const vb = (oid: string, type: number, value: VarBind['value']): VarBind => ({ oid, type, value });
const SAMPLE = [vb('1.3.6.1.2.1.1.1.0', 4, Buffer.from('OPNsense 14')), vb('1.3.6.1.2.1.1.3.0', 67, 4242), vb('1.3.6.1.2.1.2.2.1.6.1', 4, Buffer.from([0, 0x1b, 0x21, 1, 2, 3])),
  vb('1.3.6.1.2.1.2.2.1.9.1', 2, -5), vb('1.3.6.1.2.1.1.5.0', 4, Buffer.from('=cmd|x')), vb('1.3.6.1.2.1.1.6.0', 4, Buffer.from('a<b & "c"\nline2'))];
const dev = { id: 1, name: 'fw1.example', ip: '192.0.2.1' };
const settle = async (jobs: WalkJobs, id: string) => { for (let i = 0; i < 200 && !jobs.get(id)!.finishedAt; i++) await new Promise(r => setTimeout(r, 5)); return jobs.get(id)!; };

test('a walk runs in the background, keeps every row, and closes its client', async () => {
  const jobs = new WalkJobs(); const f = fakeClient(SAMPLE);
  const j = jobs.start(dev, f.c, '', 'netops');
  assert.equal(j.state, 'running');
  const done = await settle(jobs, j.id);
  assert.equal(done.state, 'done'); assert.equal(done.rows.length, 6); assert.equal(f.closed(), 1);
  assert.deepEqual(done.rows[1], ['1.3.6.1.2.1.1.3.0', 'TimeTicks', '4242']);
  assert.equal(done.rows[2][2], 'hex 00:1b:21:01:02:03');
  assert.equal(jobView(done).rows, 6);
});

test('only one walk per device and two overall; a cancelled walk keeps what it read', async () => {
  const jobs = new WalkJobs(); let open!: () => void; const gate = new Promise<void>(r => { open = r; });
  const a = fakeClient(SAMPLE, { gate }), b = fakeClient(SAMPLE), c2 = fakeClient(SAMPLE), c3 = fakeClient(SAMPLE);
  const j = jobs.start(dev, a.c, '', 'u');
  assert.throws(() => jobs.start(dev, b.c, '', 'u'), WalkBusy); assert.equal(b.closed(), 1);
  jobs.start({ id: 2, name: 'sw2', ip: '192.0.2.2' }, c2.c, '1.3.6.1.2.1.1', 'u');
  assert.throws(() => jobs.start({ id: 3, name: 'sw3', ip: '192.0.2.3' }, c3.c, '', 'u'), WalkBusy);
  jobs.cancel(j.id); open();
  const done = await settle(jobs, j.id);
  assert.equal(done.state, 'cancelled'); assert.ok(done.rows.length >= 3 && done.rows.length < 6);
});

test('an error part way keeps the rows read and says so; the row cap truncates', async () => {
  const jobs = new WalkJobs();
  const j = jobs.start(dev, fakeClient(SAMPLE, { fail: 'No response from the device (timeout).' }).c, '', 'u');
  const done = await settle(jobs, j.id);
  assert.equal(done.state, 'error'); assert.equal(done.rows.length, 3); assert.match(done.error!, /timeout.*kept/);
  const j2 = new WalkJobs().start({ id: 9, name: 'x', ip: '1.1.1.1' }, fakeClient(SAMPLE).c, '', 'u', { maxRows: 4 });
  await new Promise(r => setTimeout(r, 50));
  assert.equal(j2.truncated, true); assert.equal(j2.rows.length, 4); assert.equal(j2.state, 'done');
});

test('filtering needs every word and matches OID, type or value', async () => {
  const jobs = new WalkJobs(); const j = jobs.start(dev, fakeClient(SAMPLE).c, '', 'u'); const rows = (await settle(jobs, j.id)).rows;
  assert.equal(filterRows(rows, '').length, 6);
  assert.equal(filterRows(rows, 'opnsense').length, 1);
  assert.equal(filterRows(rows, '2.2.1 timeticks').length, 0);
  assert.equal(filterRows(rows, 'TimeTicks 4242').length, 1);
  assert.equal(filterRows(rows, '.1.3.6.1.2.1.1.').length, 4);
});

test('exports: text like snmpwalk, JSON, CSV safe for spreadsheets, XML that is well formed', async () => {
  const jobs = new WalkJobs(); const j = jobs.start(dev, fakeClient(SAMPLE).c, '1.3.6.1.2.1', 'u'); const done = await settle(jobs, j.id);
  const rows: Row[] = done.rows;
  const txt = exportRows(done, rows, 'txt', '');
  assert.equal(txt.ext, 'txt');
  assert.match(txt.body, /^# SNMP walk of fw1\.example \(192\.0\.2\.1\) from \.1\.3\.6\.1\.2\.1,/);
  assert.match(txt.body, /^\.1\.3\.6\.1\.2\.1\.1\.1\.0 = OctetString: OPNsense 14$/m);
  assert.match(txt.body, /a<b & "c"\\nline2$/m);                      // one row per line
  const json = JSON.parse(exportRows(done, rows, 'json', '').body);
  assert.equal(json.rows, 6); assert.equal(json.results[3].value, '-5'); assert.equal(json.startOid, '.1.3.6.1.2.1');
  const csv = exportRows(done, rows, 'csv', '').body;
  assert.match(csv, /"'=cmd\|x"/);                                   // a formula is defused
  assert.match(csv, /"-5"/);                                          // a number stays a number
  assert.match(csv, /"a<b & ""c""\nline2"/);
  const xml = exportRows(done, rows, 'xml', 'x"y').body;
  assert.match(xml, /^<\?xml version="1.0" encoding="UTF-8"\?>/);
  assert.match(xml, /filter="x&quot;y"/);
  assert.match(xml, />a&lt;b &amp; &quot;c&quot;\nline2<\/varbind>/);
  assert.equal((xml.match(/<varbind /g) ?? []).length, 6);
  assert.equal(exportRows(done, rows.slice(0, 1), 'txt', 'opns').body.split('\n').filter(l => l && !l.startsWith('#')).length, 1);
});

test('compareOid orders by arc, not by text', () => {
  assert.equal(compareOid('1.3.6.1.2', '1.3.6.1.10'), -1);
  assert.equal(compareOid('1.3.6.1.2.1', '1.3.6.1.2'), 1);
  assert.equal(compareOid('1.0.8802', '1.0.8802'), 0);
  assert.equal(compareOid('1.0', '1.0.8802'), -1);
});
