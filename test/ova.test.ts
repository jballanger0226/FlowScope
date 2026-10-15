import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/** The OVA packer used by packaging/vm/build.sh: the archive layout VMware requires, the manifest, and the descriptor. */
function findPacker(): string {
  let dir = path.dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++, dir = path.dirname(dir)) { const p = path.join(dir, 'packaging', 'vm', 'make-ova.mjs'); if (fs.existsSync(p)) return p; }
  return path.join(process.cwd(), 'packaging', 'vm', 'make-ova.mjs');
}

/** Reads a ustar archive: [{ name, size, data, headerOk }]. Written without the tar program so it checks the bytes, not a tool's leniency. */
function readTar(file: string): { name: string; size: number; data: Buffer; headerOk: boolean }[] {
  const buf = fs.readFileSync(file); const out = []; let off = 0;
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512);
    if (h.every(b => b === 0)) break;
    const name = h.toString('ascii', 0, 100).replace(/\0.*$/, '');
    const size = parseInt(h.toString('ascii', 124, 136).replace(/\0.*$/, '').trim(), 8);
    const stored = parseInt(h.toString('ascii', 148, 154), 8);
    const copy = Buffer.from(h); copy.fill(0x20, 148, 156);
    let sum = 0; for (const b of copy) sum += b;
    out.push({ name, size, data: buf.subarray(off + 512, off + 512 + size), headerOk: sum === stored && h.toString('ascii', 257, 262) === 'ustar' });
    off += 512 + Math.ceil(size / 512) * 512;
  }
  return out;
}

test('OVA packer: descriptor first, then manifest, then the disk, with matching SHA-256 sums', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ova-'));
  try {
    const vmdk = path.join(dir, 'disk.vmdk'); const disk = crypto.randomBytes(1_500_017);   // not a multiple of 512: exercises the padding
    fs.writeFileSync(vmdk, disk);
    const out = path.join(dir, 'x.ova');
    const r = spawnSync(process.execPath, [findPacker(), '--vmdk', vmdk, '--out', out, '--name', 'flow&scope vm', '--disk-gb', '20', '--cpus', '4', '--memory-mb', '8192', '--version', '1.2.3'], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    const members = readTar(out);
    assert.deepEqual(members.map(m => m.name), ['flow-scope-vm.ovf', 'flow-scope-vm.mf', 'flow-scope-vm.vmdk'], 'a name with odd characters is made file-safe, and the order is the one VMware requires');
    assert.ok(members.every(m => m.headerOk), 'every tar header has a valid checksum');
    assert.ok(members[2].data.equals(disk), 'the disk is stored unchanged');
    const mf = members[1].data.toString();
    for (const m of [members[0], members[2]]) assert.ok(mf.includes(`SHA256(${m.name})= ${crypto.createHash('sha256').update(m.data).digest('hex')}`), `manifest line for ${m.name}`);
    const ovf = members[0].data.toString();
    assert.match(ovf, /^<\?xml version="1.0" encoding="UTF-8"\?>/);
    assert.ok(ovf.includes(`ovf:href="flow-scope-vm.vmdk"`) && ovf.includes(`ovf:size="${disk.length}"`), 'the descriptor names the disk and its size');
    assert.ok(ovf.includes('ovf:capacity="20"') && ovf.includes('<rasd:VirtualQuantity>4</rasd:VirtualQuantity>') && ovf.includes('<rasd:VirtualQuantity>8192</rasd:VirtualQuantity>'));
    assert.ok(ovf.includes('streamOptimized') && ovf.includes('VmxNet3') && ovf.includes('<Version>1.2.3</Version>'));
    // tags balance, so the XML is at least well-formed in shape
    const stack: string[] = [];
    for (const m of ovf.replace(/<\?xml[^>]*\?>/, '').matchAll(/<(\/?)([A-Za-z:]+)([^>]*?)(\/?)>/g)) {
      if (m[4]) continue;
      if (m[1]) assert.equal(stack.pop(), m[2], `closing ${m[2]}`); else stack.push(m[2]);
    }
    assert.deepEqual(stack, []);
    // and the system tar program, where there is one, reads it too
    try { assert.match(execFileSync('tar', ['-tf', out], { encoding: 'utf8' }), /flow-scope-vm\.ovf[\s\S]*flow-scope-vm\.mf[\s\S]*flow-scope-vm\.vmdk/); } catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e; }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('OVA packer: refuses nonsense sizes and a missing disk', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ova-'));
  try {
    const vmdk = path.join(dir, 'd.vmdk'); fs.writeFileSync(vmdk, 'x');
    const run = (...a: string[]) => spawnSync(process.execPath, [findPacker(), ...a], { encoding: 'utf8' });
    assert.notEqual(run('--vmdk', vmdk, '--out', path.join(dir, 'a.ova'), '--name', 'n', '--disk-gb', '1').status, 0, 'a 1 GB disk is refused');
    assert.notEqual(run('--vmdk', path.join(dir, 'nope.vmdk'), '--out', path.join(dir, 'b.ova'), '--name', 'n', '--disk-gb', '20').status, 0, 'a missing disk is refused');
    assert.equal(run('--vmdk', vmdk).status, 2, 'missing arguments print usage');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
