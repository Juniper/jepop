# jepop - pops Juniper Ethernet headers from a .pcap file  

## Usage
```
usage: jepop [-h] [--overwrite] [--dmac DMAC] [--smac SMAC] [--vlans VLANS] inpcap outpcap
```

Packets captured on wan interfaces contain hostpath packets  
Hostpath packets contain an additional Juniper Ethernet header which is not understood outside of Juniper products   
This limits the ability to use these .pcap files with tools such as tcpreplay, ngrep, tcpflow and more   
This utility reads packets from a .pcap file, pops the Juniper Ethernet header if found, then writes the packets to a new .pcap  
It uses scapy (https://scapy.net) to achieve this    
Hostbound packets (input direction) may have L2 headers stripped by the PFE, in this case a crafted Ethernet header is added  
By default the crafted Ethernet header src and dst macs will be all zeros, you can specify macs with the `smac` and `dmac` options  
Additionally, you can specify add up to 2 vlan tags to be added with the `vlans` option   

- Reads packets from `inpcap` into a PacketList  
- Each packet is checked for the presence of the Juniper Ethernet header  
-- If found, the l2_header_presence bit is used to determine if the payload is L2  
-- If L2, Juniper Ethernet header is popped and packet is appended to the output PacketList  
-- If not L2, the payload_type field is used to determine the L3 payload  
-- A new packet is created with a crafted Ethernet header, any vlans specified, and the L3 payload  
-- Packet is appended to output PacketList  
- Output PacketList is written to `outpcap`  

### OPTIONAL ARGUMENTS

`smac` - source mac to be added to crafted L2 header  
`dmac` - destination mac to be added to crafted L2 header  
`vlans` - dot1q vlans to be added after crafted L2 header  
`overwrite` - allows output file to be overwritten  

## INSTALLATION

Installation requires Python >= 3.6 and associated `pip` tool

    python3 -m pip install jepop

Installing from Git is also supported (OS must have git installed).

    To install the latest MASTER code
    python3 -m pip install git+https://github.com/Juniper/jepop.git
    -or-
    To install a specific version, branch, tag, etc.
    python3 -m pip install git+https://github.com/Juniper/jepop.git@<branch,tag,commit>

Upgrading has the same requirements as installation and has the same format with the addition of --upgrade

    python3 -m pip install jepop --upgrade

## LICENSE

GPL-2.0  

## CONTRIBUTORS

Juniper Networks is actively contributing to and maintaining this repo  
Please contact jnpr-community-netdev@juniper.net for any queries  

*Contributors:*

[Chris Jenn](https://github.com/ipmonk)
