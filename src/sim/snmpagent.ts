import snmp from 'net-snmp';
import { OID } from '../snmp/oids.js';

export interface SimIface { index: number; name: string; alias?: string; speedMbps: number; oper?: number; inBps: number; outBps: number; discPct?: number; type?: number }
export interface SimClass { name: string; dscps: number[]; queue: string; bw?: string; pps: number; pktBytes: number; dropPct: number; qBytes: number }
export interface SimQos { ifIndex: number; policy: string; classes: SimClass[] }
export interface SimDevice {
  name: string; descr: string; objectId?: string; address: string; port: number;
  ifaces: SimIface[]; ips: { ip: string; ifIndex: number }[]; vlans: { id: number; name: string }[]; qos: SimQos[];
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
    this.tick();
  }

  private qosIds: { policyIdx: number; ifIndex: number; policyObj: number; classObj: Map<string, number>; qObj: Map<string, number>; cfg: Map<string, number> }[] = [];

  private buildQos(): void {
    const B = '1.3.6.1.4.1.9.9.166.1';
    this.table('cbQosServicePolicyTable', B + '.1.1.1', [
      { number: 1, name: 'cbQosPolicyIndex', type: T.Integer, maxAccess: NA }, { number: 3, name: 'cbQosPolicyDirection', type: T.Integer }, { number: 4, name: 'cbQosIfIndex', type: T.Integer }
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
      const ids = { policyIdx, ifIndex: q.ifIndex, policyObj: obj, classObj: new Map<string, number>(), qObj: new Map<string, number>(), cfg: new Map<string, number>() };
      this.mib.addTableRow('cbQosServicePolicyTable', [policyIdx, 2, q.ifIndex]);
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
        this.mib.addTableRow('cbQosQueueingCfgTable', [c.bw ? Number(c.bw.replace(/\D/g, '')) : 0, c.bw?.includes('%') ? 3 : 1, qcfg]);
        this.mib.addTableRow('cbQosCMStatsTable', [u64(0n), u64(0n), u64(0n), u64(0n), u64(0n), policyIdx, cobj]);
        this.mib.addTableRow('cbQosQueueingStatsTable', [0, policyIdx, qobj]);
        this.cls.set(`${q.ifIndex}/${c.name}`, { pre: 0n, preB: 0n, postB: 0n, drop: 0n, dropB: 0n });
      }
      this.qosIds.push(ids);
    });
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
      const q = this.spec.qos.find(x => x.ifIndex === ids.ifIndex)!;
      for (const c of q.classes) {
        const k = `${q.ifIndex}/${c.name}`; const st = this.cls.get(k)!;
        const dp = this.overrides.get(k) ?? c.dropPct;
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
