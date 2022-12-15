# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#AUTHOR: ILIADIS ILIAS
#AEM: 02523

"""
Two OpenFlow 1.0 L3 Static Routers and two OpenFlow 1.0 L2 learning switches.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.ofproto import inet
from ryu.lib.packet import vlan
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.ofproto import ether

ROUTER1_IPADDR_L = '192.168.1.1'
ROUTER2_IPADDR_R = '192.168.2.1'
ROUTER1_MACADDR_L = '00:00:00:00:01:01'
ROUTER1_MACADDR_R = '00:00:00:00:03:01'
ROUTER2_MACADDR_L = '00:00:00:00:03:02'
ROUTER2_MACADDR_R = '00:00:00:00:02:01'
ROUTER1_MACADDR_TOS = '00:00:00:00:04:01'
ROUTER2_MACADDR_TOS = '00:00:00:00:04:02'

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = msg.datapath_id
        
        if dpid == 0x1A:
            srcMac = ROUTER1_MACADDR_TOS
            dstMac = ROUTER2_MACADDR_TOS

            match = datapath.ofproto_parser.OFPMatch(
                    dl_type = ether_types.ETH_TYPE_IP, nw_tos = 8, nw_dst = '192.168.2.0', nw_dst_mask=24)

            actions = [datapath.ofproto_parser.OFPActionSetDlSrc(srcMac), datapath.ofproto_parser.OFPActionSetDlDst(dstMac),datapath.ofproto_parser.OFPActionOutput(4)]

            self.add_flow(datapath,match,actions)

            return
        
        if dpid == 0x1B:
            srcMac = ROUTER2_MACADDR_TOS
            dstMac = ROUTER1_MACADDR_TOS

            match = datapath.ofproto_parser.OFPMatch(
                    dl_type = ether_types.ETH_TYPE_IP, nw_tos = 8, nw_dst = '192.168.1.0', nw_dst_mask=24)

            actions = [datapath.ofproto_parser.OFPActionSetDlSrc(srcMac), datapath.ofproto_parser.OFPActionSetDlDst(dstMac),datapath.ofproto_parser.OFPActionOutput(4)]

            self.add_flow(datapath,match,actions)

            return            

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        ip_to_mac = { '192.168.1.2' : '00:00:00:00:01:02' , '192.168.1.3' : '00:00:00:00:01:03',
                      '192.168.2.2' : '00:00:00:00:02:02' , '192.168.2.3' : '00:00:00:00:02:03',
                      '192.168.1.4' : '00:00:00:00:01:04' ,  '192.168.2.4' : '00:00:00:00:02:04' }
        
        #access port hash table
        access_ports = { 2 : { 100 : [2, 3] , 200 : [4] } , 
                         3 : { 100 : [4] , 200 : [2, 3] }  ,
                         4 : { 100 : [2], 200 : [3] } }
        
        #trunk port hash table 
        trunk_ports = { 2 : {100 : [1], 200 : [1]} ,
                        3 : {100 : [1, 5], 200 : [1, 5]}, 
                        4 : {100 : [1], 200 : [1]} }

        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        out_port = None
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)

        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype
        
        #extract vlan header
        if(ethertype == ether_types.ETH_TYPE_8021Q):
            vlan_header = pkt.get_protocol(vlan.vlan)

        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s in_port=%s", hex(dpid).ljust(4), hex(ethertype), src, dst, msg.in_port)

        self.mac_to_port[dpid][src] = msg.in_port

        if dpid == 0x1A:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                arpPacket = pkt.get_protocol(arp.arp)

                # make sure it's a ARP request
                if arpPacket.opcode == 1:
                    arp_dstIP = arpPacket.dst_ip

                    print("received an ARP request from %s to %s in_port: %d" %(src, dst, msg.in_port))

                    # construct an ARP reply messange and send it to the destination host
                    dstIp = arpPacket.src_ip
                    srcIp = arpPacket.dst_ip
                    dstMac = src

                    if arp_dstIP == ROUTER1_IPADDR_L:
                        srcMac = ROUTER1_MACADDR_L
                        self.reply_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, msg.in_port)

                    return
                return

            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                if '192.168.2' in ip.dst:
                    srcMac = ROUTER1_MACADDR_R
                    dstMac = ROUTER2_MACADDR_L
                    out_port = 1
                    match = datapath.ofproto_parser.OFPMatch(
                    dl_type = ether_types.ETH_TYPE_IP, nw_dst = ip.dst, nw_dst_mask = 24)

                elif '192.168.1' in ip.dst:
                    srcMac = ROUTER1_MACADDR_L
                    out_port = 2
                    dstMac = ip_to_mac.get(ip.dst)
                    match = datapath.ofproto_parser.OFPMatch(
                    dl_type = ether_types.ETH_TYPE_IP, nw_dst = ip.dst)
                
                # Unknown IP address, send type 3 ICMP packet
                else:
                    self.send_icmp_dest_unreach(datapath, ROUTER1_MACADDR_L, src, ROUTER1_IPADDR_L, ip.src, msg.in_port, msg)
                    return
                
                actions = [datapath.ofproto_parser.OFPActionSetDlSrc(srcMac), datapath.ofproto_parser.OFPActionSetDlDst(dstMac), datapath.ofproto_parser.OFPActionOutput(out_port,0)]

                self.add_flow(datapath, match, actions)

                out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER, in_port=datapath.ofproto.OFPP_CONTROLLER,
                actions=actions, data=msg.data)
                
                datapath.send_msg(out)
                return
            
            return

        if dpid == 0x1B:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                
                arpPacket = pkt.get_protocol(arp.arp)
                
                # make sure it's a ARP request
                if arpPacket.opcode == 1:
                    arp_dstIP = arpPacket.dst_ip

                    print("received an ARP request from %s to %s in_port: %d" %(src, dst, msg.in_port))

                    # construct an ARP reply messange and send it to the destination host
                    dstIp = arpPacket.src_ip
                    srcIp = arpPacket.dst_ip
                    dstMac = src
                    
                    if arp_dstIP == ROUTER2_IPADDR_R:
                        srcMac = ROUTER2_MACADDR_R
                        self.reply_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, msg.in_port)
                    return
                return

            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                
                if '192.168.1' in ip.dst:
                    srcMac = ROUTER2_MACADDR_L
                    dstMac = ROUTER1_MACADDR_R
                    out_port = 1
                    match = datapath.ofproto_parser.OFPMatch(
                    dl_type = ether_types.ETH_TYPE_IP, nw_dst = ip.dst, nw_dst_mask = 24)

                elif '192.168.2' in ip.dst:
                    srcMac = ROUTER2_MACADDR_R
                    dstMac = ip_to_mac.get(ip.dst)
                    out_port = 2
                    match = datapath.ofproto_parser.OFPMatch(
                    dl_type = ether_types.ETH_TYPE_IP, nw_dst = ip.dst)
                
                # Unknown IP address, send type 3 ICMP packet
                else:
                    self.send_icmp_dest_unreach(datapath, ROUTER2_MACADDR_R, src, ROUTER1_IPADDR_L, ip.src, msg.in_port, msg)
                    return
                
                actions = [datapath.ofproto_parser.OFPActionSetDlSrc(srcMac), datapath.ofproto_parser.OFPActionSetDlDst(dstMac), datapath.ofproto_parser.OFPActionOutput(out_port,0)]

                self.add_flow(datapath, match, actions)

                out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER, in_port=datapath.ofproto.OFPP_CONTROLLER,
                actions=actions, data=msg.data)
                datapath.send_msg(out)
                return
            return
        
        #--------------------VLAN_IMPLEMENTATION_EXTENDED_TOPOLOGY--------------------

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        
        # Learn in which vlan the sender participates 
        vlan_id = [key for key, list_of_values in access_ports[dpid].items()
                    if msg.in_port in list_of_values]
        
        if len(vlan_id):
            vlan_id = vlan_id.pop()
        
        # If in_port has no match in the nested dictionary for access ports, 
        # the packet is VLAN encapsulated
        else:
            vlan_id = vlan_header.vid

        actions = []
        
        # Switch has no mac to port match
        if out_port == None:
            
            # If packet was forwarded from trunk port, strip VLAN header
            if msg.in_port in trunk_ports[dpid][vlan_id]:
                actions.append(datapath.ofproto_parser.OFPActionStripVlan())
            
            # FLOOD packet to all access ports that participate in the same VLAN
            for i in access_ports[dpid][vlan_id]:
                if i != msg.in_port:
                    actions.append(datapath.ofproto_parser.OFPActionOutput(i))
            
            # Encapsulate packet in VLAN header before forwarding it to all trunk ports
            for i in trunk_ports[dpid][vlan_id]:
                if i != msg.in_port:
                    actions.append(datapath.ofproto_parser.OFPActionVlanVid(vlan_id))
                    actions.append(datapath.ofproto_parser.OFPActionOutput(i))
        
        # out_port is known
        else:

            # If packet is to be forwarded to a trunk link, 
            # it should be encapsulated with the known VLAN id.
            # Note that if the packet in_port is a trunk port too, the
            # encapsulation is omitted.
            if out_port in trunk_ports[dpid][vlan_id]:
                
                match = datapath.ofproto_parser.OFPMatch(
                    in_port=msg.in_port, dl_dst=haddr_to_bin(dst))         
                
                if msg.in_port not in trunk_ports[dpid][vlan_id]:
                    actions.append(datapath.ofproto_parser.OFPActionVlanVid(vlan_id))
                
                actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))
                self.add_flow(datapath, match, actions)
            
            # If packet is to be forwarded to an access link and 
            # the in_port is a trunk port, it should be decapsulated 
            # from the VLAN header.
            elif out_port in access_ports[dpid][vlan_id]:
                
                if msg.in_port in trunk_ports[dpid][vlan_id]:
                    
                    match = datapath.ofproto_parser.OFPMatch(
                        in_port=msg.in_port, dl_vlan = vlan_id,  dl_dst=haddr_to_bin(dst))
                    
                    actions.append(datapath.ofproto_parser.OFPActionStripVlan()) 
                
                else:
                    match = datapath.ofproto_parser.OFPMatch(
                        in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                    
                actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))
                self.add_flow(datapath, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER, in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions, data=data)
        datapath.send_msg(out)
    
    def send_icmp_dest_unreach(self, datapath, srcMac, dstMac, srcIp, dstIp, outPort, msg):
        
        print("creating icmp packet ...")
        e = ethernet.ethernet(dstMac, srcMac, ether.ETH_TYPE_IP)
        ip = ipv4.ipv4(version=4, header_length=5, tos=0, total_length=0, identification=0, flags=0, offset=0, ttl=255, proto=inet.IPPROTO_ICMP, csum=0, src=srcIp, dst=dstIp)
        icmp_data = icmp.dest_unreach(data_len=len(msg.data[14:]), data=msg.data[14:])
        ic = icmp.icmp(icmp.ICMP_DEST_UNREACH, icmp.ICMP_HOST_UNREACH_CODE, 0, data=icmp_data)

        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(ip)
        p.add_protocol(ic)
        p.serialize()
        
        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER, in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions, data=p.data)
        
        datapath.send_msg(out)


    def reply_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):

        targetMac = dstMac
        targetIp = dstIp

        e = ethernet.ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        
        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER, in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions, data=p.data)
        
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
