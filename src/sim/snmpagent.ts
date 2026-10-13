import snmp from 'net-snmp';
import { OID } from '../snmp/oids.js';

export interface SimIface { index: number; name: string; alias?: string; speedMbps: number; oper?: number; inBps: number; outBps: number; discPct?: number; type?: number }
export interface SimClass { name: string; dscps: number[]; queue: string; bw?: string; pps: number; pktBytes: number; dropPct: number; qBytes: number }
export interface SimQos { ifIndex: number; policy: string; classes: SimClass[]; direction?: 'input' | 'output'; ifType?: number; vlan?: number; parentPolicy?: number }
export interface SimPort { ifIndex: number; mode: 'access' | 'trunk'; vlan: number; voice?: number; allowed?: number[] }
export interface SimFdb { mac: string; vlan: number; ifIndex: number }
export interface SimLldp { ifIndex: number; name: string; port: string; /** first octet of lldpRemSysCapEnabled, bit 0 = 0x80 (other) ... bit 7 = 0x01 (station) */ caps: number }
export interface SimCdp { ifIndex: number; id: string; port: string; platform: string; caps: number; ip?: string }
export interface SimDevice {
  name: string; descr: string; objectId?: string; address: string; port: number;
  ifaces: SimIface[]; ips: { ip: string; ifIndex: number }[]; vlans: { id: number; name: string }[]; qos: SimQos[];
  /** Port VLANs (CISCO-VLAN-MEMBERSHIP-MIB, CISCO-VTP-MIB), the Q-BRIDGE MAC table, ARP (ipNetToMediaTable), LLDP and CDP neighbours. */
  ports?: SimPort[]; fdb?: SimFdb[]; arp?: { ip: string; mac: string; ifIndex: number }[]; lldp?: SimLldp[]; cdp?: SimCdp[];
  auth: { community?: string; user?: { name: string; level: 'noAuthNoPriv' | 'authNoPriv' | 'authPriv'; authProto?: string; authKey?: string; privProto?: string; privKey?: string } };
}

const M = snmp.MaxAccess['read-only'];
const NA = snmp.MaxAccess['not-accessible'];
const T = snmp.ObjectType;

function u64(n: bigint): Buffer { const b = Buffer.alloc(8); b.writeBigUInt64BE(n & 0xffffffffffffffffn); return b; }

interface Col { number: number; name: string; type: number; maxAccess?: number }

/** A virtual SNMP agent that serves IF-MIB, IP-MIB, Q-BRIDGE VLAN names and the Cisco class-based QoS MIB. Counters move with simulated traffic. */
export class VirtualDevice {
  private agent: any;
  private mib: any;
  private timer: NodeJS.Timeout | null = null;
  private lastTick = Date.now();
  private started = Date.now();
  private octIn = new Map<number, bigint>(); private octOut = new Map<number, bigint>();
  private discIn = new Map<number, bigint>(); private discOut = new Map<number, bigint>();
  private cls = new Map<string, { pre: bigint; preB: bigint; postB: bigint; drop: bigint; dropB: bigint }>();
  private qosKey = (q: SimQos, qi: number, cname: string) => `${qi}/${q.ifIndex}/${cname}`;
  /** Test hook: forced drop percentages by "ifIndex/class". */
  overrides = new Map<string, number>();

  constructor(readonly spec: SimDevice) {}

  get port(): number { return this.spec.port; }

  async start(): Promise<void> {
    const s = this.spec;
    await new Promise<void>((resolve, reject) => {
      this.agent = snmp.createAgent({ port: s.port, address: s.address, disableAuthorization: false, accessControlModelType: snmp.AccessControlModelType.None }, (err: Error | null) => { if (err && !/rinfo/.test(String(err))) { /* request level errors are expected for bad credentials */ } });
      this.agent.on?.('error', reject);
      const az = this.agent.getAuthorizer();
      if (s.auth.community) az.addCommunity(s.auth.community);
      if (s.auth.user) {
        const u = s.auth.user;
        const user: Record<string, unknown> = { name: u.name, level: snmp.SecurityLevel[u.level] };
        if (u.level !== 'noAuthNoPriv') { user.authProtocol = (snmp.AuthProtocols as any)[u.authProto || 'sha256']; user.authKey = u.authKey; }
        if (u.level === 'authPriv') { user.privProtocol = (snmp.PrivProtocols as any)[u.privProto || 'aes']; user.privKey = u.privKey; }
        az.addUser(user);
      }
      this.mib = this.agent.getMib();
      this.build();
      resolve();
    });
    this.timer = setInterval(() => this.tick(), 1000);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    try { this.agent?.close(); } catch { /* ignore */ }
  }

  private scalar(name: string, oid: string, type: number, value: unknown): void {
    this.mib.registerProvider({ name, type: snmp.MibProviderType.Scalar, oid, scalarType: type, maxAccess: M });
    this.mib.setScalarValue(name, value);
  }

  private table(name: string, entryOid: string, cols: Col[], index: string[]): void {
    this.mib.registerProvider({
      name, type: snmp.MibProviderType.Table, oid: entryOid, maxAccess: NA,
      tableColumns: cols.map(c => ({ number: c.number, name: c.name, type: c.type, maxAccess: c.maxAccess ?? M })),
      tableIndex: index.map(columnName => ({ columnName }))
    });
  }

  private build(): void {
    const s = this.spec;
    this.scalar('sysDescr', '1.3.6.1.2.1.1.1', T.OctetString, s.descr);
    this.scalar('sysObjectID', '1.3.6.1.2.1.1.2', T.OID, s.objectId || '1.3.6.1.4.1.9.1.1');
    this.scalar('sysUpTime', '1.3.6.1.2.1.1.3', T.TimeTicks, 1000);
    this.scalar('sysName', '1.3.6.1.2.1.1.5', T.OctetString, s.name);
    // net-snmp's agent spins when a walk runs past its last OID, so keep a sentinel at the end of the tree (real devices return endOfMibView).
    this.scalar('zzSentinel', '1.3.6.1.4.1.99999.1', T.Integer, 1);

    this.table('ifTable', '1.3.6.1.2.1.2.2.1', [
      { number: 1, name: 'ifIndex', type: T.Integer }, { number: 2, name: 'ifDescr', type: T.OctetString }, { number: 3, name: 'ifType', type: T.Integer },
      { number: 5, name: 'ifSpeed', type: T.Gauge32 }, { number: 8, name: 'ifOperStatus', type: T.Integer }, { number: 10, name: 'ifInOctets', type: T.Counter32 },
      { number: 13, name: 'ifInDiscards', type: T.Counter32 }, { number: 14, name: 'ifInErrors', type: T.Counter32 }, { number: 16, name: 'ifOutOctets', type: T.Counter32 },
      { number: 19, name: 'ifOutDiscards', type: T.Counter32 }, { number: 20, name: 'ifOutErrors', type: T.Counter32 }
    ], ['ifIndex']);
    this.table('ifXTable', '1.3.6.1.2.1.31.1.1.1', [
      { number: 1, name: 'ifName', type: T.OctetString }, { number: 6, name: 'ifHCInOctets', type: T.Counter64 }, { number: 10, name: 'ifHCOutOctets', type: T.Counter64 },
      { number: 15, name: 'ifHighSpeed', type: T.Gauge32 }, { number: 18, name: 'ifAlias', type: T.OctetString }, { number: 99, name: 'ifXIndex', type: T.Integer, maxAccess: NA }
    ], ['ifXIndex']);
    this.table('ipAddrTable', '1.3.6.1.2.1.4.20.1', [
      { number: 1, name: 'ipAdEntAddr', type: T.IpAddress }, { number: 2, name: 'ipAdEntIfIndex', type: T.Integer }
    ], ['ipAdEntAddr']);
    this.table('dot1qVlanStaticTable', '1.3.6.1.2.1.17.7.1.4.3.1', [
      { number: 1, name: 'dot1qVlanStaticName', type: T.OctetString }, { number: 99, name: 'dot1qVlanIdx', type: T.Integer, maxAccess: NA }
    ], ['dot1qVlanIdx']);

    for (const i of s.ifaces) {
      this.octIn.set(i.index, 1_000_000n); this.octOut.set(i.index, 1_000_000n); this.discIn.set(i.index, 0n); this.discOut.set(i.index, 0n);
      this.mib.addTableRow('ifTable', [i.index, i.name, i.type ?? 6, Math.min(i.speedMbps * 1_000_000, 4_294_967_295), i.oper ?? 1, 0, 0, 0, 0, 0, 0]);
      this.mib.addTableRow('ifXTable', [i.name, u64(0n), u64(0n), i.speedMbps, i.alias || '', i.index]);
    }
    for (const a of s.ips) this.mib.addTableRow('ipAddrTable', [a.ip, a.ifIndex]);
    for (const v of s.vlans) this.mib.addTableRow('dot1qVlanStaticTable', [v.name, v.id]);

    if (s.qos.length) this.buildQos();
    this.buildSwitching();
    this.tick();
  }

  private qosIds: { qi: number; policyIdx: number; ifIndex: number; policyObj: number; classObj: Map<string, number>; qObj: Map<string, number>; cfg: Map<string, number> }[] = [];

  private buildQos(): void {
    const B = '1.3.6.1.4.1.9.9.166.1';
    this.table('cbQosServicePolicyTable', B + '.1.1.1', [
      { number: 1, name: 'cbQosPolicyIndex', type: T.Integer, maxAccess: NA }, { number: 2, name: 'cbQosIfType', type: T.Integer }, { number: 3, name: 'cbQosPolicyDirection', type: T.Integer },
      { number: 4, name: 'cbQosIfIndex', type: T.Integer }, { number: 9, name: 'cbQosVlanIndex', type: T.Integer }, { number: 12, name: 'cbQosParentPolicyIndex', type: T.Integer }
    ], ['cbQosPolicyIndex']);
    this.table('cbQosObjectsTable', B + '.5.1.1', [
      { number: 1, name: 'cbQosObjectsIndex', type: T.Integer, maxAccess: NA }, { number: 2, name: 'cbQosConfigIndex', type: T.Integer }, { number: 3, name: 'cbQosObjectsType', type: T.Integer },
      { number: 4, name: 'cbQosParentObjectsIndex', type: T.Integer }, { number: 98, name: 'cbQosPolicyIndexO', type: T.Integer, maxAccess: NA }
    ], ['cbQosPolicyIndexO', 'cbQosObjectsIndex']);
    this.table('cbQosPolicyMapCfgTable', B + '.6.1.1', [{ number: 1, name: 'cbQosPolicyMapName', type: T.OctetString }, { number: 99, name: 'cfgIdxP', type: T.Integer, maxAccess: NA }], ['cfgIdxP']);
    this.table('cbQosCMCfgTable', B + '.7.1.1', [{ number: 1, name: 'cbQosCMName', type: T.OctetString }, { number: 99, name: 'cfgIdxC', type: T.Integer, maxAccess: NA }], ['cfgIdxC']);
    this.table('cbQosQueueingCfgTable', B + '.9.1.1', [
      { number: 1, name: 'cbQosQueueingCfgBandwidth', type: T.Gauge32 }, { number: 2, name: 'cbQosQueueingCfgBandwidthUnits', type: T.Integer }, { number: 99, name: 'cfgIdxQ', type: T.Integer, maxAccess: NA }
    ], ['cfgIdxQ']);
    this.table('cbQosCMStatsTable', B + '.15.1.1', [
      { number: 3, name: 'cbQosCMPrePolicyPkt64', type: T.Counter64 }, { number: 6, name: 'cbQosCMPrePolicyByte64', type: T.Counter64 }, { number: 10, name: 'cbQosCMPostPolicyByte64', type: T.Counter64 },
      { number: 14, name: 'cbQosCMDropPkt64', type: T.Counter64 }, { number: 17, name: 'cbQosCMDropByte64', type: T.Counter64 },
      { number: 98, name: 'statPolicy', type: T.Integer, maxAccess: NA }, { number: 99, name: 'statObj', type: T.Integer, maxAccess: NA }
    ], ['statPolicy', 'statObj']);
    this.table('cbQosQueueingStatsTable', B + '.18.1.1', [
      { number: 1, name: 'cbQosQueueingCurrentQDepth', type: T.Gauge32 }, { number: 98, name: 'qsPolicy', type: T.Integer, maxAccess: NA }, { number: 99, name: 'qsObj', type: T.Integer, maxAccess: NA }
    ], ['qsPolicy', 'qsObj']);

    let cfg = 100;
    this.spec.qos.forEach((q, qi) => {
      const policyIdx = 1000 + qi; let obj = 1;
      const ids = { qi, policyIdx, ifIndex: q.ifIndex, policyObj: obj, classObj: new Map<string, number>(), qObj: new Map<string, number>(), cfg: new Map<string, number>() };
      this.mib.addTableRow('cbQosServicePolicyTable', [policyIdx, q.ifType ?? 1, q.direction === 'input' ? 1 : 2, q.ifIndex, q.vlan ?? 0, q.parentPolicy ?? 0]);
      const pcfg = cfg++;
      this.mib.addTableRow('cbQosPolicyMapCfgTable', [q.policy, pcfg]);
      this.mib.addTableRow('cbQosObjectsTable', [ids.policyObj, pcfg, 1, 0, policyIdx]);
      obj++;
      for (const c of q.classes) {
        const ccfg = cfg++; const cobj = obj++;
        ids.classObj.set(c.name, cobj); ids.cfg.set(c.name, ccfg);
        this.mib.addTableRow('cbQosCMCfgTable', [c.name, ccfg]);
        this.mib.addTableRow('cbQosObjectsTable', [cobj, ccfg, 2, ids.policyObj, policyIdx]);
        const qcfg = cfg++; const qobj = obj++;
        ids.qObj.set(c.name, qobj);
        this.mib.addTableRow('cbQosObjectsTable', [qobj, qcfg, 4, cobj, policyIdx]);
        this.mib.addTableRow('cbQosQueueingCfgTable', [c.bw ? Number(c.bw.replace(/\D/g, '')) : 0, c.bw?.includes('%') ? 2 : 1, qcfg]);
        this.mib.addTableRow('cbQosCMStatsTable', [u64(0n), u64(0n), u64(0n), u64(0n), u64(0n), policyIdx, cobj]);
        this.mib.addTableRow('cbQosQueueingStatsTable', [0, policyIdx, qobj]);
        this.cls.set(this.qosKey(q, qi, c.name), { pre: 0n, preB: 0n, postB: 0n, drop: 0n, dropB: 0n });
      }
      this.qosIds.push(ids);
    });
  }

  /** Port VLANs, the Q-BRIDGE MAC table, ARP, LLDP and CDP. Multi-part indexes are registered as separate integer columns, which gives the same OIDs as the real MIBs. */
  private buildSwitching(): void {
    const s = this.spec;
    const mac = (m: string) => Buffer.from(m.replace(/[:-]/g, ''), 'hex');
    if (s.ports?.length) {
      this.table('vmMembershipTable', '1.3.6.1.4.1.9.9.68.1.2.2.1', [{ number: 2, name: 'vmVlan', type: T.Integer }, { number: 99, name: 'vmIf', type: T.Integer, maxAccess: NA }], ['vmIf']);
      this.table('vmVoiceVlanTable', '1.3.6.1.4.1.9.9.68.1.5.1.1', [{ number: 1, name: 'vmVoiceVlanId', type: T.Integer }, { number: 99, name: 'vmvIf', type: T.Integer, maxAccess: NA }], ['vmvIf']);
      this.table('vlanTrunkPortTable', '1.3.6.1.4.1.9.9.46.1.6.1.1', [
        { number: 4, name: 'vlanTrunkPortVlansEnabled', type: T.OctetString }, { number: 5, name: 'vlanTrunkPortNativeVlan', type: T.Integer }, { number: 14, name: 'vlanTrunkPortDynamicStatus', type: T.Integer },
        { number: 99, name: 'vtIf', type: T.Integer, maxAccess: NA }], ['vtIf']);
      for (const p of s.ports) {
        if (p.mode === 'access') this.mib.addTableRow('vmMembershipTable', [p.vlan, p.ifIndex]);
        if (p.voice) this.mib.addTableRow('vmVoiceVlanTable', [p.voice, p.ifIndex]);
        const bm = Buffer.alloc(128); for (const v of p.allowed ?? []) if (v >= 0 && v < 1024) bm[v >> 3] |= 0x80 >> (v & 7);
        this.mib.addTableRow('vlanTrunkPortTable', [bm, p.vlan, p.mode === 'trunk' ? 1 : 2, p.ifIndex]);
      }
    }
    if (s.fdb) {
      // one bridge port per ifIndex, numbered the same
      this.table('dot1dBasePortTable', '1.3.6.1.2.1.17.1.4.1', [{ number: 1, name: 'dot1dBasePort', type: T.Integer, maxAccess: NA }, { number: 2, name: 'dot1dBasePortIfIndex', type: T.Integer }], ['dot1dBasePort']);
      for (const i of s.ifaces) this.mib.addTableRow('dot1dBasePortTable', [i.index, i.index]);
      const idx = ['f', 'm1', 'm2', 'm3', 'm4', 'm5', 'm6'];
      this.table('dot1qTpFdbTable', '1.3.6.1.2.1.17.7.1.2.2.1', [
        { number: 2, name: 'dot1qTpFdbPort', type: T.Integer }, { number: 3, name: 'dot1qTpFdbStatus', type: T.Integer },
        ...idx.map((n, i) => ({ number: 90 + i, name: 'fdb_' + n, type: T.Integer, maxAccess: NA }))], idx.map(n => 'fdb_' + n));
      for (const e of s.fdb) this.mib.addTableRow('dot1qTpFdbTable', [e.ifIndex, 3, e.vlan, ...mac(e.mac)]);
    }
    if (s.arp?.length) {
      this.table('ipNetToMediaTable', '1.3.6.1.2.1.4.22.1', [
        { number: 1, name: 'ipNetToMediaIfIndex', type: T.Integer }, { number: 2, name: 'ipNetToMediaPhysAddress', type: T.OctetString },
        { number: 3, name: 'ipNetToMediaNetAddress', type: T.IpAddress }, { number: 4, name: 'ipNetToMediaType', type: T.Integer }], ['ipNetToMediaIfIndex', 'ipNetToMediaNetAddress']);
      for (const a of s.arp) this.mib.addTableRow('ipNetToMediaTable', [a.ifIndex, mac(a.mac), a.ip, 3]);
    }
    if (s.lldp?.length) {
      this.table('lldpLocPortTable', '1.0.8802.1.1.2.1.3.7.1', [{ number: 1, name: 'lldpLocPortNum', type: T.Integer, maxAccess: NA }, { number: 2, name: 'lldpLocPortIdSubtype', type: T.Integer }, { number: 3, name: 'lldpLocPortId', type: T.OctetString }, { number: 4, name: 'lldpLocPortDesc', type: T.OctetString }], ['lldpLocPortNum']);
      for (const l of s.lldp) { const nm = s.ifaces.find(i => i.index === l.ifIndex)?.name ?? ''; this.mib.addTableRow('lldpLocPortTable', [l.ifIndex, 5, nm, nm]); }
      this.table('lldpRemTable', '1.0.8802.1.1.2.1.4.1.1', [
        { number: 1, name: 'lldpRemTimeMark', type: T.Integer, maxAccess: NA }, { number: 2, name: 'lldpRemLocalPortNum', type: T.Integer, maxAccess: NA }, { number: 3, name: 'lldpRemIndex', type: T.Integer, maxAccess: NA },
        { number: 4, name: 'lldpRemChassisIdSubtype', type: T.Integer }, { number: 5, name: 'lldpRemChassisId', type: T.OctetString }, { number: 6, name: 'lldpRemPortIdSubtype', type: T.Integer }, { number: 7, name: 'lldpRemPortId', type: T.OctetString },
        { number: 8, name: 'lldpRemPortDesc', type: T.OctetString }, { number: 9, name: 'lldpRemSysName', type: T.OctetString }, { number: 12, name: 'lldpRemSysCapEnabled', type: T.OctetString }], ['lldpRemTimeMark', 'lldpRemLocalPortNum', 'lldpRemIndex']);
      s.lldp.forEach((l, i) => this.mib.addTableRow('lldpRemTable', [0, l.ifIndex, i + 1, 4, l.name, 5, l.port, l.port, l.name, Buffer.from([l.caps, 0])]));
    }
    if (s.cdp?.length) {
      this.table('cdpCacheTable', '1.3.6.1.4.1.9.9.23.1.2.1.1', [
        { number: 1, name: 'cdpCacheIfIndex', type: T.Integer, maxAccess: NA }, { number: 2, name: 'cdpCacheDeviceIndex', type: T.Integer, maxAccess: NA },
        { number: 4, name: 'cdpCacheAddress', type: T.OctetString }, { number: 6, name: 'cdpCacheDeviceId', type: T.OctetString }, { number: 7, name: 'cdpCacheDevicePort', type: T.OctetString },
        { number: 8, name: 'cdpCachePlatform', type: T.OctetString }, { number: 9, name: 'cdpCacheCapabilities', type: T.OctetString }], ['cdpCacheIfIndex', 'cdpCacheDeviceIndex']);
      s.cdp.forEach((d, i) => this.mib.addTableRow('cdpCacheTable', [d.ifIndex, i + 1, Buffer.from((d.ip ?? '0.0.0.0').split('.').map(Number)), d.id, d.port, d.platform, Buffer.from([0, 0, 0, d.caps])]));
    }
  }

  private tick(): void {
    const now = Date.now(); const dt = Math.max(0.001, (now - this.lastTick) / 1000); this.lastTick = now;
    this.mib.setScalarValue('sysUpTime', Math.floor((now - this.started) / 10) % 4294967296);
    for (const i of this.spec.ifaces) {
      const jitter = 0.9 + Math.random() * 0.2;
      const din = BigInt(Math.round((i.inBps / 8) * dt * jitter)), dout = BigInt(Math.round((i.outBps / 8) * dt * jitter));
      const oi = this.octIn.get(i.index)! + din, oo = this.octOut.get(i.index)! + dout;
      this.octIn.set(i.index, oi); this.octOut.set(i.index, oo);
      const disc = BigInt(Math.round(((i.outBps / 8 / 800) * dt) * ((i.discPct ?? 0) / 100)));
      const dd = this.discOut.get(i.index)! + disc; this.discOut.set(i.index, dd);
      const u32 = (n: bigint) => Number(n & 0xffffffffn);
      this.mib.setTableSingleCell('ifTable', 10, [i.index], u32(oi));
      this.mib.setTableSingleCell('ifTable', 16, [i.index], u32(oo));
      this.mib.setTableSingleCell('ifTable', 19, [i.index], u32(dd));
      this.mib.setTableSingleCell('ifXTable', 6, [i.index], u64(oi));
      this.mib.setTableSingleCell('ifXTable', 10, [i.index], u64(oo));
    }
    for (const ids of this.qosIds) {
      const q = this.spec.qos[ids.qi];
      for (const c of q.classes) {
        const k = this.qosKey(q, ids.qi, c.name); const st = this.cls.get(k)!;
        const dp = this.overrides.get(`${q.ifIndex}/${c.name}`) ?? c.dropPct;
        const pkts = BigInt(Math.round(c.pps * dt)); const bytes = pkts * BigInt(c.pktBytes);
        const drop = BigInt(Math.round(Number(pkts) * dp / 100)); const dropB = drop * BigInt(c.pktBytes);
        st.pre += pkts; st.preB += bytes; st.postB += bytes - dropB; st.drop += drop; st.dropB += dropB;
        const row = [ids.policyIdx, ids.classObj.get(c.name)!];
        this.mib.setTableSingleCell('cbQosCMStatsTable', 3, row, u64(st.pre));
        this.mib.setTableSingleCell('cbQosCMStatsTable', 6, row, u64(st.preB));
        this.mib.setTableSingleCell('cbQosCMStatsTable', 10, row, u64(st.postB));
        this.mib.setTableSingleCell('cbQosCMStatsTable', 14, row, u64(st.drop));
        this.mib.setTableSingleCell('cbQosCMStatsTable', 17, row, u64(st.dropB));
        this.mib.setTableSingleCell('cbQosQueueingStatsTable', 1, [ids.policyIdx, ids.qObj.get(c.name)!], Math.round(c.qBytes * (0.5 + Math.random())));
      }
    }
  }
}
export { OID };
