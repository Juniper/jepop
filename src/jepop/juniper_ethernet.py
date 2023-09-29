#!/usr/bin/env python3
""" Copyright (c) 2023, Juniper Networks, Inc
    All rights reserved
    This SOFTWARE is licensed under the LICENSE provided in the
    ./LICENCE file. By downloading, installing, copying, or otherwise
    using the SOFTWARE, you agree to be bound by the terms of that
    LICENSE.
"""
# stdlib imports
import logging

# local imports
from .juniper_encap import _JUNIPER_IFD_ENCAP, _JUNIPER_IFL_ENCAP

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# 3rd party imports
from scapy.fields import (
    ByteField,
    ByteEnumField,
    FieldLenField,
    StrLenField,
    X3BytesField,
    FlagsField,
    PacketListField,
    ConditionalField,
    ThreeBytesField,
)
from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

_JUNIPER_ETHERNET_HEADER_TLVS = {
    1: "JNX_EXT_TLV_IFD_IDX",
    2: "JNX_EXT_TLV_IFD_NAME",
    3: "JNX_EXT_TLV_IFD_MEDIATYPE",
    4: "JNX_EXT_TLV_IFL_IDX",
    5: "JNX_EXT_TLV_IFL_UNIT",
    6: "JNX_EXT_TLV_IFL_ENCAPS",
    7: "JNX_EXT_TLV_TTP_IFD_MEDIATYPE",
    8: "JNX_EXT_TLV_TTP_IFL_ENCAPS",
    9: "JNX_EXT_TLV_IRB_IFL_IDX",
    10: "JNX_EXT_TLV_IRB_L2_INPUT_IFL_IDX",
    11: "JNX_EXT_TLV_IRB_L2_OUTPUT_IFL_IDX",
    12: "JNX_EXT_TLV_JPTAP_META",
}

_L3_PAYLOAD = {
    2: "IP",
    6: "IPv6",
}

class JuniperEthernetExtensionTLV(Packet):
    name = "Juniper Ethernet - Generic Extension TLV"
    fields_desc = [
        ByteEnumField("type", None, _JUNIPER_ETHERNET_HEADER_TLVS),
        FieldLenField("len", None, length_of="value", fmt="b"),
        StrLenField("value", "", length_from=lambda pkt: pkt.len),
    ]

    def extract_padding(self, p):
        return b"", p

    registered_je_tlv = {}

    @classmethod
    def register_variant(cls):
        cls.registered_je_tlv[cls.type.default] = cls

    @classmethod
    def dispatch_hook(cls, pkt=None, *args, **kargs):
        if pkt:
            tmp_type = ord(pkt[:1])
            return cls.registered_je_tlv.get(tmp_type, cls)
        return cls


class JuniperEthernetInterfaceIndexTLV(JuniperEthernetExtensionTLV):
    name = "Juniper Ethernet Interface Index Extension TLV"
    fields_desc = [
        ByteEnumField("type", 1, _JUNIPER_ETHERNET_HEADER_TLVS),
        FieldLenField("len", None, length_of="value", fmt="b"),
        StrLenField("value", None, length_from=lambda x: x.len),
    ]

    def post_dissection(self, pkt):
        if pkt.fields["value"]:
            pkt.fields["value"] = int.from_bytes(
                pkt.fields["value"], byteorder="little"
            )


class JuniperEthernetInterfaceMediaTypeTLV(JuniperEthernetExtensionTLV):
    name = "Juniper Ethernet Interface Media Type Extension TLV"
    fields_desc = [
        ByteEnumField("type", 3, _JUNIPER_ETHERNET_HEADER_TLVS),
        FieldLenField("len", None, length_of="value", fmt="b"),
        StrLenField("value", None, length_from=lambda x: x.len),
    ]

    def post_dissection(self, pkt):
        if pkt.fields["value"]:
            encap_num = int.from_bytes(pkt.fields["value"], byteorder="little")
            pkt.fields["value"] = _JUNIPER_IFD_ENCAP[encap_num]


class JuniperEthernetLogicalInterfaceIndexTLV(JuniperEthernetExtensionTLV):
    name = "Juniper Ethernet Logical Interface Index Extension TLV"
    fields_desc = [
        ByteEnumField("type", 4, _JUNIPER_ETHERNET_HEADER_TLVS),
        FieldLenField("len", None, length_of="value", fmt="b"),
        StrLenField("value", None, length_from=lambda x: x.len),
    ]

    def post_dissection(self, pkt):
        if pkt.fields["value"]:
            pkt.fields["value"] = int.from_bytes(
                pkt.fields["value"], byteorder="little"
            )


class JuniperEthernetLogicalInterfaceUnitTLV(JuniperEthernetExtensionTLV):
    name = "Juniper Ethernet Logical Interface Unit Extension TLV"
    fields_desc = [
        ByteEnumField("type", 5, _JUNIPER_ETHERNET_HEADER_TLVS),
        FieldLenField("len", None, length_of="value", fmt="b"),
        StrLenField("value", None, length_from=lambda x: x.len),
    ]

    def post_dissection(self, pkt):
        if pkt.fields["value"]:
            pkt.fields["value"] = int.from_bytes(
                pkt.fields["value"], byteorder="little"
            )


class JuniperEthernetLogicalInterfaceEncapsulationTLV(JuniperEthernetExtensionTLV):
    name = "Juniper Ethernet Logical Interface Encapsulation Extension TLV"
    fields_desc = [
        ByteEnumField("type", 6, _JUNIPER_ETHERNET_HEADER_TLVS),
        FieldLenField("len", None, length_of="value", fmt="b"),
        StrLenField("value", None, length_from=lambda x: x.len),
    ]

    def post_dissection(self, pkt):
        if pkt.fields["value"]:
            encap_num = int.from_bytes(pkt.fields["value"], byteorder="little")
            pkt.fields["value"] = _JUNIPER_IFL_ENCAP[encap_num]


class JuniperEthernetTtpInterfaceMediaType(JuniperEthernetExtensionTLV):
    name = "Juniper Ethernet TTP Interface Media Type Extension TLV"
    fields_desc = [
        ByteEnumField("type", 7, _JUNIPER_ETHERNET_HEADER_TLVS),
        FieldLenField("len", None, length_of="value", fmt="b"),
        StrLenField("value", None, length_from=lambda x: x.len),
    ]

    def post_dissection(self, pkt):
        if pkt.fields["value"]:
            encap_num = int.from_bytes(pkt.fields["value"], byteorder="little")
            pkt.fields["value"] = _JUNIPER_IFD_ENCAP[encap_num]


class JuniperEthernetTtpLogicalInterfaceEncapsulation(JuniperEthernetExtensionTLV):
    name = "Juniper Ethernet TTP Logical Interface Encapsulation Extension TLV"
    fields_desc = [
        ByteEnumField("type", 8, _JUNIPER_ETHERNET_HEADER_TLVS),
        FieldLenField("len", None, length_of="value", fmt="b"),
        StrLenField("value", None, length_from=lambda x: x.len),
    ]

    def post_dissection(self, pkt):
        if pkt.fields["value"]:
            encap_num = int.from_bytes(pkt.fields["value"], byteorder="little")
            pkt.fields["value"] = _JUNIPER_IFL_ENCAP[encap_num]


class JuniperEthernetIrbLogicalInterfaceIndexTLV(JuniperEthernetExtensionTLV):
    name = "Juniper Ethernet IRB Logical Interface Index Extension TLV"
    fields_desc = [
        ByteEnumField("type", 9, _JUNIPER_ETHERNET_HEADER_TLVS),
        FieldLenField("len", None, length_of="value", fmt="b"),
        StrLenField("value", None, length_from=lambda x: x.len),
    ]

    def post_dissection(self, pkt):
        if pkt.fields["value"]:
            pkt.fields["value"] = int.from_bytes(
                pkt.fields["value"], byteorder="little"
            )


class JuniperEthernetIrbL2InputLogicalInterfaceIndexTLV(JuniperEthernetExtensionTLV):
    name = "Juniper Ethernet IRB Layer2 Input Logical Interface Index Extension TLV"
    fields_desc = [
        ByteEnumField("type", 10, _JUNIPER_ETHERNET_HEADER_TLVS),
        FieldLenField("len", None, length_of="value", fmt="b"),
        StrLenField("value", None, length_from=lambda x: x.len),
    ]

    def post_dissection(self, pkt):
        if pkt.fields["value"]:
            pkt.fields["value"] = int.from_bytes(
                pkt.fields["value"], byteorder="little"
            )


class JuniperEthernetIrbL2OutputLogicalInterfaceIndexTLV(JuniperEthernetExtensionTLV):
    name = "Juniper Ethernet IRB Layer2 Output Logical Interface Index Extension TLV"
    fields_desc = [
        ByteEnumField("type", 11, _JUNIPER_ETHERNET_HEADER_TLVS),
        FieldLenField("len", None, length_of="value", fmt="b"),
        StrLenField("value", None, length_from=lambda x: x.len),
    ]

    def post_dissection(self, pkt):
        if pkt.fields["value"]:
            pkt.fields["value"] = int.from_bytes(
                pkt.fields["value"], byteorder="little"
            )


# class JuniperEthernetJptapMetaTLV(JuniperEthernetExtensionTLV):
#    name = "Juniper Ethernet Jptap Meta Extension TLV"
#    fields_desc = [
#        ByteEnumField("type", 12, _JUNIPER_ETHERNET_HEADER_TLVS),
#        ByteField("len", ),
#        NBytesField("value", 0, ),
#    ]


class JuniperEthernet(Packet):
    name = "JuniperEthernet"
    fields_desc = [
        X3BytesField("magic_number", 0x4d4743),
        FlagsField("extensions_present", 0, 6, ["f0", "f1", "f2", "f3", "f4", "f5"]),
        FlagsField("l2_header_presence", 0, 1, ["f0"]), # 0 == True, 1 == False
        FlagsField("pkt_direction", 0, 1, ["f0"]), # 0 == outbound, 1 == inbound
        FieldLenField("extensions_length", None, length_of="tlv_objects"),
        PacketListField(
            "tlv_objects",
            [],
            JuniperEthernetExtensionTLV,
            length_from=lambda pkt: pkt.extensions_length,
        ),
        ConditionalField(
            ByteEnumField("l3_payload", None, _L3_PAYLOAD),
            lambda pkt: pkt.l2_header_presence == "f0",
        ),
        ConditionalField(
            ThreeBytesField("padding", None),
            lambda pkt: pkt.l2_header_presence == "f0",
        ),
    ]

    def guess_payload_class(self, payload):
        if not self.l2_header_presence:
            return Ether
        elif self.l3_payload == 2:
            return IP
        elif self.l3_payload == 6:
            return IPv6
