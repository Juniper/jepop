#!/usr/bin/env python3
""" Copyright (c) 2023, Juniper Networks, Inc
    All rights reserved
    This SOFTWARE is licensed under the LICENSE provided in the
    ./LICENCE file. By downloading, installing, copying, or otherwise
    using the SOFTWARE, you agree to be bound by the terms of that
    LICENSE.
"""
# stdlib imports
import re
from argparse import ArgumentParser

# local imports
from .juniper_ethernet import JuniperEthernet

# 3rd party imports
from scapy.utils import rdpcap, wrpcap
from scapy.plist import PacketList
from scapy.layers.l2 import Ether, Dot1Q
from scapy.compat import raw


def parse_args():
    """parses arguments
    :return args:
    :type Namespace:
    """
    parser = ArgumentParser()
    parser.add_argument("inpcap", help="path to input pcap file")
    parser.add_argument("outpcap", help="path to output pcap file")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="allow output file to be overwritten",
    )
    parser.add_argument(
        "--dmac",
        nargs=1,
        type=str,
        default=["00:00:00:00:00:00"],
        help="dst mac address to add to Ethernet header",
    )
    parser.add_argument(
        "--smac",
        nargs=1,
        type=str,
        default=["00:00:00:00:00:00"],
        help="src mac address to add to Ethernet header",
    )
    parser.add_argument(
        "--vlans",
        nargs=1,
        help="vlan id(s) to add to Ethernet header, example: 1,4",
    )
    args = parser.parse_args()
    return args


def process_optargs(args):
    """checks optional args validity
    :returns smac:
    :type string:
    :returns dmac:
    :type string:
    :returns vlans:
    :type list:
    :raises ValueError: if either vlans, smac, dmac are incorrect
    :raises FileExistsError: if output file already exists
    """
    ofile_exists = False
    try:
        with open(args.outpcap, "r") as outfile:
            ofile_exists = True
    except FileNotFoundError:
        pass

    if ofile_exists:
        with open(args.outpcap, "a") as outfile:
            if not args.overwrite:
                raise FileExistsError("to overwrite file, specify --overwrite argument")

    smac = args.smac[0].lower()
    dmac = args.dmac[0].lower()
    mac_address = re.compile(r"([a-f0-9]{2}:){5}[a-f0-9]{2}")
    if not re.match(mac_address, smac):
        raise ValueError("src mac not in the correct format")
    if not re.match(mac_address, dmac):
        raise ValueError("dst mac not in the correct format")

    vlans = []
    if args.vlans:
        vlans = args.vlans[0].split(",")
    if len(vlans) > 2:
        raise ValueError("max of 2 vlans can be added")

    return (smac, dmac, vlans)


def main():
    """Processes arguments. Reads packets from input pcap file.
    Process each packet popping off the juniper ethernet header.
    If L2 header is missing from inbound packet, a new L2 header is added
    along with any dot1q headers specified.
    Outbound packets always have an L2 header.
    Packets are written to the output pcap file.
    :returns None:
    """
    args = parse_args()
    smac, dmac, vlans = process_optargs(args)
    popped_pkts = 0
    in_pkts = rdpcap(args.inpcap)
    out_pkts = PacketList()
    for in_pkt in in_pkts:
        if not raw(in_pkt)[:3] == b"MGC":
            out_pkts.append(in_pkt)
            continue
        je_pkt = JuniperEthernet(in_pkt.load)
        if je_pkt.magic_number != 0x4d4743:
            print('magic number does not match expectation, this is a bug')
            continue
        if je_pkt.l3_payload and vlans:
            # inbound packet with L3 payload, add Ethernet and Dot1Q headers
            out_pkt = Ether(src=smac, dst=dmac)
            for vlan in vlans:
                out_pkt = out_pkt / Dot1Q(vlan=int(vlan))
            out_pkt = out_pkt / je_pkt.payload
        elif je_pkt.l3_payload:
            # inbound packet with L3 payload, add Ethernet header
            out_pkt = Ether(src=smac, dst=dmac) / je_pkt.payload
        else:
            # packet with L2 payload
            out_pkt = je_pkt.payload
        out_pkts.append(out_pkt)
        popped_pkts += 1
    if not popped_pkts:
        raise SystemExit(f"no packets with a Juniper Ethernet header found")
    wrpcap(args.outpcap, out_pkts)
