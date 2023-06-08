#!/usr/bin/env python3
""" Copyright (c) 2023, Juniper Networks, Inc
    All rights reserved
    This SOFTWARE is licensed under the LICENSE provided in the
    ./LICENCE file. By downloading, installing, copying, or otherwise
    using the SOFTWARE, you agree to be bound by the terms of that
    LICENSE.
"""
_JUNIPER_IFD_ENCAP = {
    0: "Unspecfied",
    1: "Ethernet",
    2: "FDDI",
    3: "Token-Ring",
    4: "PPP",
    5: "Frame-Relay",
    6: "Cisco-HDLC",
    7: "SMDS-DXI",
    8: "ATM-PVC",
    9: "PPP-CCC",
    10: "Frame-Relay-CCC",
    11: "IP-over-IP",
    12: "GRE",
    13: "PIM-Encapsulator",
    14: "PIM-Decapsulator",
    15: "Cisco-HDLC-CCC",
    16: "VLAN-CCC",
    17: "Multilink-PPP",
    18: "Multilink-FR",
    19: "Multilink",
    20: "LSI",
    21: "DFE",
    22: "ATM-CCC-Cell-Relay",
    23: "IPSEC-over-IP",
    24: "GGSN",
    25: "LSI-enabled-PPP-SONET",
    26: "LSI-enabled-CHDLC-SONET",
    27: "PPP-TCC",
    28: "Frame-Relay-TCC",
    29: "Cisco-HDLC-TCC",
    30: "Ethernet-CCC",
    31: "VPN-Loopback-tunnel",
    32: "Extended-VLAN-CCC",
    33: "Ethernet-over-ATM",
    34: "Monitor",
    35: "Ethernet-TCC",
    36: "VLAN-TCC",
    37: "Extended-VLAN-TCC",
    38: "Controller",
    39: "Multilink-FR-UNI-NNI",
    40: "LinkService",
    41: "VPLS",
    42: "VLAN-VPLS",
    43: "Extended-VLAN-VPLS",
    44: "Logical-tunnel",
    45: "General-Services",
    46: "Ethernet-VPLS-over-ATM",
    47: "FR-dedicated-CCC",
    48: "Extended FR-CCC",
    49: "Extended FR-TCC",
    50: "Flexible-FrameRelay",
    51: "GGSN-Inspection",
    52: "Flexible-Ethernet-Services",
    53: "Flow-collection",
    54: "Aggregator",
    55: "LAPD",
    56: "PPPoE",
    57: "PPP-Subordinate",
    58: "Cisco-Hdlc-Subordinate",
    59: "Dynamic-Flow-Capture",
    60: "PIC Peer",
    61: "Single-Link-PPP",
    62: "VOIP",
    63: "Secure-Tunnel",
    64: "Fabric-Member-Ethernet",
    65: "Frame-Relay-Ether-Encap",
    66: "Frame-Relay-Ether-Encap-TCC",
    67: "Extended FR-Ether-Encap-TCC",
    68: "VLAN-VCI-CCC",
    69: "Container",
    70: "Virtual-Chassis-Interface",
    71: "VLAN",
    72: "Management-VLAN",
    73: "SAToP-Encapsulation",
    74: "CESoPSN-Encapsulation",
    75: "Uplink Tunnel",
    76: "Ethernet VPLS over PPP",
    77: "Xconnect Tunnel",
    78: "Inverse Multiplexing for ATM",
    79: "MPU",
    80: "FXS",
    81: "FXO",
    82: "FPC-LOCAL",
    83: "PFE-LOCAL",
    84: "DOCSIS",
    85: "JUNIPER-SERVICES-VLAN",
    86: "UDP Tunnel",
    87: "Fibrechannel",
    88: "Virtual-Server",
    89: "Switch Fabric-Member-Ethernet",
    90: "Pseudowire Service",
    91: "VxLAN Tunnel End Point",
    92: "Satellite Device",
    93: "Remote beb",
    94: "EVPN VxLAN AA",
    95: "SRX-SPU",
    96: "OT",
    97: "Flexible Tunnel",
}

_JUNIPER_IFL_ENCAP = {
    0: "Unspecified",
    1: "Null",
    2: "ATM SNAP",
    3: "ATM NLPID",
    4: "ATM VCMUX",
    5: "ATM LLC",
    6: "ATM PPP VCMUX",
    7: "ATM PPP LLC",
    8: "ATM PPP Funi",
    9: "CCC/ATM",
    10: "FR NLPID",
    11: "FR SNAP",
    12: "FR PPP",
    13: "FR CCC",
    14: "Ethernet",
    15: "802.3 SNAP",
    16: "802.3 LLC",
    17: "PPP",
    18: "Cisco HDLC",
    19: "CCC/PPP",
    20: "IP-in-IP",
    21: "PIM-E",
    22: "GRE",
    23: "GRE PPP",
    24: "PIM-D",
    25: "CCC/HDLC",
    26: "ATM C-NLPID",
    27: "CCC/VLAN",
    28: "ML-PPP",
    29: "ML-FR",
    32: "ATM Cell-relay",
    33: "IPSEC",
    34: "GGSN",
    35: "TCC/ATM",
    36: "TCC/FR",
    37: "TCC/PPP",
    38: "TCC/HDLC",
    39: "CCC/Ethernet",
    40: "VPN-loop tun",
    41: "Ethernet/ATM",
    42: "Extended CCC/VLAN",
    43: "TCC/ATM SNAP",
    44: "Monitor",
    45: "TCC/Ethernet",
    46: "TCC/VLAN",
    47: "Extended TCC/VLAN",
    48: "ML-FR-UNI-NNI",
    49: "VPLS/Ethernet",
    50: "VLAN/VPLS",
    51: "Extended VLAN/VPLS",
    52: "Services",
    53: "VPLS/ATM",
    54: "CCC/FR-PORT",
    55: "ATM MLPPP LLC",
    56: "CCC/Ethernet over ATM",
    57: "VLAN/LT",
    58: "Flow collection",
    59: "Flow aggregation",
    60: "ISDN-LAPD",
    61: "PPPoEoA LLC",
    62: "PPP over Ethernet",
    63: "PPPoE",
    66: "DFC",
    67: "PIC Peer",
    68: "VOIP",
    69: "Secure Tunnel",
    70: "FR-ETHER",
    71: "TCC/FR-ETHER",
    72: "CCC/VLAN Q-in-Q and VCI interworking",
    73: "CCC/TDM-SATOP",
    74: "CCC/TDM-CESoPSN",
    75: "VPLS over FR",
    76: "VPLS over PPP",
    78: "AMT UDP Tunnel",
    79: "Fibrechannel",
    80: "GTP",
    81: "Virtual Server",
    82: "Tether Enet Svcs",
    84: "CAPWAP Tunnel",
    85: "GRE L2",
    86: "VXLAN V4 over FT",
    87: "VXLAN V6 over FT",
    88: "UDP V4 over FT",
    89: "IPV4 over FT",
    255: "Link Specific",
}
