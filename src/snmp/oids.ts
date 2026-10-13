/** OIDs used by the poller. The Cisco class-based QoS values were checked against CISCO-CLASS-BASED-QOS-MIB. */
export const OID = {
  sysDescr: '1.3.6.1.2.1.1.1.0',
  sysObjectID: '1.3.6.1.2.1.1.2.0',
  sysUpTime: '1.3.6.1.2.1.1.3.0',
  sysName: '1.3.6.1.2.1.1.5.0',
  // IF-MIB ifTable
  ifIndex: '1.3.6.1.2.1.2.2.1.1',
  ifDescr: '1.3.6.1.2.1.2.2.1.2',
  ifType: '1.3.6.1.2.1.2.2.1.3',
  ifSpeed: '1.3.6.1.2.1.2.2.1.5',
  ifOperStatus: '1.3.6.1.2.1.2.2.1.8',
  ifInDiscards: '1.3.6.1.2.1.2.2.1.13',
  ifInErrors: '1.3.6.1.2.1.2.2.1.14',
  ifOutDiscards: '1.3.6.1.2.1.2.2.1.19',
  ifOutErrors: '1.3.6.1.2.1.2.2.1.20',
  ifInOctets32: '1.3.6.1.2.1.2.2.1.10',
  ifOutOctets32: '1.3.6.1.2.1.2.2.1.16',
  // IF-MIB ifXTable
  ifName: '1.3.6.1.2.1.31.1.1.1.1',
  ifHCInOctets: '1.3.6.1.2.1.31.1.1.1.6',
  ifHCOutOctets: '1.3.6.1.2.1.31.1.1.1.10',
  ifHighSpeed: '1.3.6.1.2.1.31.1.1.1.15',
  ifAlias: '1.3.6.1.2.1.31.1.1.1.18',
  // IP-MIB ipAddrTable
  ipAdEntAddr: '1.3.6.1.2.1.4.20.1.1',
  ipAdEntIfIndex: '1.3.6.1.2.1.4.20.1.2',
  // Q-BRIDGE-MIB dot1qVlanStaticName, indexed by VLAN id
  dot1qVlanStaticName: '1.3.6.1.2.1.17.7.1.4.3.1.1',
  // CISCO-VTP-MIB vtpVlanName, indexed by management domain then VLAN id
  vtpVlanName: '1.3.6.1.4.1.9.9.46.1.3.1.1.4',
  // CISCO-CLASS-BASED-QOS-MIB
  cbQosPolicyDirection: '1.3.6.1.4.1.9.9.166.1.1.1.1.3',
  cbQosIfIndex: '1.3.6.1.4.1.9.9.166.1.1.1.1.4',
  cbQosConfigIndex: '1.3.6.1.4.1.9.9.166.1.5.1.1.2',
  cbQosObjectsType: '1.3.6.1.4.1.9.9.166.1.5.1.1.3',
  cbQosParentObjectsIndex: '1.3.6.1.4.1.9.9.166.1.5.1.1.4',
  cbQosPolicyMapName: '1.3.6.1.4.1.9.9.166.1.6.1.1.1',
  cbQosCMName: '1.3.6.1.4.1.9.9.166.1.7.1.1.1',
  cbQosQueueingCfgBandwidth: '1.3.6.1.4.1.9.9.166.1.9.1.1.1',
  cbQosQueueingCfgBandwidthUnits: '1.3.6.1.4.1.9.9.166.1.9.1.1.2',
  cbQosCMPrePolicyPkt64: '1.3.6.1.4.1.9.9.166.1.15.1.1.3',
  cbQosCMPrePolicyByte64: '1.3.6.1.4.1.9.9.166.1.15.1.1.6',
  cbQosCMPostPolicyByte64: '1.3.6.1.4.1.9.9.166.1.15.1.1.10',
  cbQosCMDropPkt64: '1.3.6.1.4.1.9.9.166.1.15.1.1.14',
  cbQosCMDropByte64: '1.3.6.1.4.1.9.9.166.1.15.1.1.17',
  cbQosQueueingCurrentQDepth: '1.3.6.1.4.1.9.9.166.1.18.1.1.1'
} as const;

export const CBQOS_OBJ = { policymap: 1, classmap: 2, matchStatement: 3, queueing: 4 } as const;
export const IF_TYPE_IGNORED = new Set([24 /* softwareLoopback */, 53 /* propVirtual */, 131 /* tunnel */, 135 /* l2vlan */, 136 /* l3ipvlan */, 161 /* ieee8023adLag */]);
