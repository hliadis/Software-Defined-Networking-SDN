# VLAN with OpenFlow
In this project we implement a network with two interconnected switches, divided into two virtual LANs with use of the VLAN technology, which are connected through two routers. 

![Screenshot from 2022-12-15 18-43-51](https://user-images.githubusercontent.com/101011526/207918531-fa1656f7-c4a0-41f7-b05a-6b24e8c51c5e.png)

Both routers support ARP spoofing in their respective LAN port and static routing between the two LANs. They also reply with an ICMP type 3, "Destination Host Unreachable" packet, 
when they receive a packet that is destined to an unknown IP address. Finally, they have an extra link between them, using their port 4, while their controller uses this link for proactive forwarding 
of the high-priority traffic between the routers. 
