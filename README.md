# VLAN with OpenFlow
In this project we implement a network with two interconnected switches, divided into two virtual LANs with use of the VLAN technology, which are connected through two routers. 
Both routers support ARP spoofing in their respective LAN port and static routing between the two LANs. They also reply with an ICMP type 3, "Destination Host Unreachable" packet, 
when they receive a packet that is destined to an unknown IP address. Finally, they have an extra link between them, using their port 4, while their controller uses this link for proactive forwarding 
of the high-priority traffic between the routers. 
