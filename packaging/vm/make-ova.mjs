#!/usr/bin/env node
// Packs a streamOptimized VMDK into an OVA (the single file VMware ESXi, vCenter, Workstation and Fusion import).
//
//   node packaging/vm/make-ova.mjs --vmdk disk.vmdk --out flowscope.ova --name flowscope --disk-gb 20 [--cpus 2] [--memory-mb 4096] [--version 1.2.3] [--description "..."]
//
// An OVA is an uncompressed tar archive holding, in this order: the OVF descriptor (XML), the manifest (SHA-256 of every other file) and the
// disk. No dependencies: the tar archive is written here, so it behaves the same on every machine. packaging/vm/build.sh calls this.
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream, statSync, openSync, readSync, closeSync } from 'node:fs';
import { basename } from 'node:path';
import { pipeline } from 'node:stream/promises';

const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** The OVF descriptor. `diskFile` and `diskBytes` describe the VMDK; `populated` is the number of bytes of data in the virtual disk (informational). */
export function ovfXml(o) {
  const name = esc(o.name), cpus = Number(o.cpus ?? 2), mem = Number(o.memoryMb ?? 4096), gb = Number(o.diskGb ?? 20);
  if (!(cpus >= 1) || !(mem >= 512) || !(gb >= 4)) throw new Error('cpus, memory and disk size are out of range');
  const desc = esc(o.description ?? 'FlowScope NetFlow / IPFIX collector with SNMP link and QoS monitoring. Debian 12.');
  return `<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:cim="http://schemas.dmtf.org/wbem/wscim/1/common" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1" xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData" xmlns:vmw="http://www.vmware.com/schema/ovf" xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <References>
    <File ovf:href="${esc(o.diskFile)}" ovf:id="file1" ovf:size="${Number(o.diskBytes)}"/>
  </References>
  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:capacity="${gb}" ovf:capacityAllocationUnits="byte * 2^30" ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <NetworkSection>
    <Info>The list of logical networks</Info>
    <Network ovf:name="VM Network">
      <Description>The VM Network network</Description>
    </Network>
  </NetworkSection>
  <VirtualSystem ovf:id="${name}">
    <Info>A virtual machine</Info>
    <Name>${name}</Name>
    <OperatingSystemSection ovf:id="101" vmw:osType="otherLinux64Guest">
      <Info>The kind of installed guest operating system</Info>
      <Description>Debian GNU/Linux 12 (64-bit)</Description>
    </OperatingSystemSection>
    <ProductSection>
      <Info>FlowScope</Info>
      <Product>FlowScope</Product>
      <Version>${esc(o.version ?? '')}</Version>
      <Category>Settings</Category>
      <Property ovf:key="hostname" ovf:type="string" ovf:userConfigurable="true" ovf:value="">
        <Label>Host name</Label>
        <Description>Optional. Leave empty to keep the name the VM already has.</Description>
      </Property>
      <Property ovf:key="public-keys" ovf:type="string" ovf:userConfigurable="true" ovf:value="">
        <Label>SSH public key</Label>
        <Description>Optional. One public key (ssh-ed25519 AAAA...) allowed to sign in over SSH as the user "debian".</Description>
      </Property>
    </ProductSection>
    <AnnotationSection ovf:required="false">
      <Info>A human-readable annotation</Info>
      <Annotation>${desc}</Annotation>
    </AnnotationSection>
    <VirtualHardwareSection ovf:transport="com.vmware.guestInfo">
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemIdentifier>${name}</vssd:VirtualSystemIdentifier>
        <vssd:VirtualSystemType>vmx-13</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:Description>Number of Virtual CPUs</rasd:Description>
        <rasd:ElementName>${cpus} virtual CPU(s)</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>${cpus}</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:Description>Memory Size</rasd:Description>
        <rasd:ElementName>${mem}MB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>${mem}</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>SCSI Controller</rasd:Description>
        <rasd:ElementName>SCSI Controller 0</rasd:ElementName>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>lsilogic</rasd:ResourceSubType>
        <rasd:ResourceType>6</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:ElementName>Hard Disk 1</rasd:ElementName>
        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:Parent>3</rasd:Parent>
        <rasd:ResourceType>17</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>7</rasd:AddressOnParent>
        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Connection>VM Network</rasd:Connection>
        <rasd:Description>VmxNet3 ethernet adapter on "VM Network"</rasd:Description>
        <rasd:ElementName>Ethernet 1</rasd:ElementName>
        <rasd:InstanceID>5</rasd:InstanceID>
        <rasd:ResourceSubType>VmxNet3</rasd:ResourceSubType>
        <rasd:ResourceType>10</rasd:ResourceType>
      </Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
`;
}

const sha256File = async path => { const h = createHash('sha256'); await pipeline(createReadStream(path), h); return h.digest('hex'); };

/** One POSIX (ustar) header block for a regular file. Names must fit in 100 bytes, which holds for the three files of an OVA. */
function tarHeader(name, size) {
  if (Buffer.byteLength(name) > 100) throw new Error(`file name too long for a tar header: ${name}`);
  const b = Buffer.alloc(512);
  const put = (s, off, len) => b.write(s, off, len, 'ascii');
  const oct = (n, len) => n.toString(8).padStart(len - 1, '0') + '\0';
  put(name, 0, 100); put(oct(0o644, 8), 100, 8); put(oct(0, 8), 108, 8); put(oct(0, 8), 116, 8);
  put(oct(size, 12), 124, 12); put(oct(Math.floor(Date.now() / 1000), 12), 136, 12);
  put('        ', 148, 8);                       // checksum is counted as if it were eight spaces
  put('0', 156, 1); put('ustar\0', 257, 6); put('00', 263, 2);
  let sum = 0; for (const x of b) sum += x;
  put(oct(sum, 7).slice(0, 6) + '\0 ', 148, 8);
  return b;
}

/** Writes the three members in the order VMware requires (descriptor first, then manifest, then disk). */
async function writeTar(out, members) {
  const ws = createWriteStream(out);
  const write = buf => new Promise((res, rej) => ws.write(buf, e => (e ? rej(e) : res())));
  for (const m of members) {
    await write(tarHeader(m.name, m.size));
    if (m.data) await write(m.data); else await pipeline(createReadStream(m.path), ws, { end: false });
    const pad = (512 - (m.size % 512)) % 512; if (pad) await write(Buffer.alloc(pad));
  }
  await write(Buffer.alloc(1024));
  await new Promise((res, rej) => ws.end(e => (e ? rej(e) : res())));
}

export async function makeOva(o) {
  const base = String(o.name).replace(/[^A-Za-z0-9._-]/g, '-');
  const vmdkName = `${base}.vmdk`, ovfName = `${base}.ovf`, mfName = `${base}.mf`;
  const diskBytes = statSync(o.vmdk).size;
  const ovf = Buffer.from(ovfXml({ ...o, name: base, diskFile: vmdkName, diskBytes }), 'utf8');
  const mf = Buffer.from(`SHA256(${ovfName})= ${createHash('sha256').update(ovf).digest('hex')}\nSHA256(${vmdkName})= ${await sha256File(o.vmdk)}\n`, 'utf8');
  await writeTar(o.out, [{ name: ovfName, size: ovf.length, data: ovf }, { name: mfName, size: mf.length, data: mf }, { name: vmdkName, size: diskBytes, path: o.vmdk }]);
  return { ovfName, mfName, vmdkName, diskBytes };
}

if (process.argv[1] && basename(process.argv[1]) === 'make-ova.mjs') {
  const a = {}; const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i += 2) { if (!argv[i].startsWith('--') || argv[i + 1] === undefined) { console.error('usage: make-ova.mjs --vmdk F --out F --name N --disk-gb N [--cpus N] [--memory-mb N] [--version V] [--description T]'); process.exit(2); } a[argv[i].slice(2)] = argv[i + 1]; }
  for (const k of ['vmdk', 'out', 'name', 'disk-gb']) if (!a[k]) { console.error(`missing --${k}`); process.exit(2); }
  try { const fd = openSync(a.vmdk, 'r'); readSync(fd, Buffer.alloc(4), 0, 4, 0); closeSync(fd); } catch (e) { console.error(`error: cannot read ${a.vmdk}: ${e.message}`); process.exit(1); }
  makeOva({ vmdk: a.vmdk, out: a.out, name: a.name, diskGb: a['disk-gb'], cpus: a.cpus, memoryMb: a['memory-mb'], version: a.version, description: a.description })
    .then(r => console.log(`wrote ${a.out} (${r.ovfName}, ${r.mfName}, ${r.vmdkName}, ${r.diskBytes} bytes of disk)`))
    .catch(e => { console.error(`error: ${e.message}`); process.exit(1); });
}
