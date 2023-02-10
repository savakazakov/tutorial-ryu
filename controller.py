# -*- coding: utf-8 -*-

"""
Ryu Tutorial Controller

This controller allows OpenFlow datapaths to act as Ethernet Hubs. Using the
tutorial you should convert this to a layer 2 learning switch.

See the README for more...
"""

from ryu import utils
from ryu.base.app_manager import RyuApp
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.dpid import dpid_to_str
from ryu.lib.packet import ethernet

class Controller(RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        # Initialize mac address table.
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        '''
        Handshake: Features Request Response Handler

        Installs a low level (0) flow table modification that pushes packets to
        the controller. This acts as a rule for flow-table misses.
        '''
        
        # ev.msg is an object that represents a packet_in data structure.
        # In ev.msg, the instance of the OpenFlow message class corresponding to the event is stored.
        # msg.dp is an object that represents a datapath (switch).
        # In msg.datapath, the instance of the ryu.controller.controller.Datapath class corresponding
        # to the OpenFlow switch that issued this message is stored.
        datapath = ev.msg.datapath
        
        # dp.ofproto and dp.ofproto_parser are objects that represent the OpenFlow protocol that Ryu and the switch negotiated.
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # An empty match is generated to match all packets
        match = parser.OFPMatch()
        
        # OFPActionOutput class is used with a packet_out message to specify a switch port that you want to send the packet out of.
        # The Table-miss flow entry has the lowest (0) priority and this entry matches all packets. In the instruction of this
        # entry, by specifying the output action to output to the controller port, in case the received packet does not match
        # any of the normal flow entries, Packet-In is issued.
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.logger.info("Handshake taken place with {}".format(dpid_to_str(datapath.id)))
        self.__add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        '''
        Packet In Event Handler

        Takes packets provided by the OpenFlow packet in event structure and
        floods them to all ports. This is the core functionality of the Ethernet
        Hub.
        '''
        
        # ev.msg is an object that represents a packet_in data structure.
        # In ev.msg, the instance of the OpenFlow message class corresponding to the event is stored.
        # msg.dp is an object that represents a datapath (switch).
        # In msg.datapath, the instance of the ryu.controller.controller.Datapath class corresponding
        # to the OpenFlow switch that issued this message is stored.
        msg = ev.msg
        datapath = msg.datapath

        # dp.ofproto and dp.ofproto_parser are objects that represent the OpenFlow protocol that Ryu and the switch negotiated.
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        
        # Analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)        
        
        # Get the destination and source MAC addresses.
        dst = eth_pkt.dst
        src = eth_pkt.src
        
        # Get the received port number from packet_in message.
        in_port = msg.match['in_port']

        self.logger.info("Packet in %s %s %s %s.", dpid, src, dst, in_port)

        self.mac_to_port.setdefault(dpid, {})
        
        # Learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        
        # If the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
            
        # Construct action list.
        # OFPActionOutput class is used with a packet_out message to specify a switch port that you want to send the packet out of.
        # This application uses the OFPP_FLOOD flag to indicate that the packet should be sent out on all ports.
        actions = [parser.OFPActionOutput(out_port)]
        
        # Install a flow to avoid packet_in next time.
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(eth_dst=dst)
            self.__add_flow(datapath, 1, match, actions)
        
        # Construct packet_out message and send it.
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        
        self.logger.info("Sending packet out")
        datapath.send_msg(out)
        
        if msg.reason == ofproto.OFPR_NO_MATCH:
            reason = 'NO MATCH'
        elif msg.reason == ofproto.OFPR_ACTION:
            reason = 'ACTION'
        elif msg.reason == ofproto.OFPR_INVALID_TTL:
            reason = 'INVALID TTL'
        else:
            reason = 'unknown'

        # self.logger.debug('OFPPacketIn received: '
        #                 'buffer_id=%x total_len=%d reason=%s '
        #                 'table_id=%d cookie=%d match=%s data=%s ',
        #                 msg.buffer_id, msg.total_len, reason,
        #                 msg.table_id, msg.cookie, msg.match,
        #                 utils.hex_array(msg.data))
        
        self.logger.debug('OFPPacketIn received: '
                        'buffer_id=%x total_len=%d reason=%s '
                        'table_id=%d cookie=%d match=%s ',
                        msg.buffer_id, msg.total_len, reason,
                        msg.table_id, msg.cookie, msg.match)
        
        return

    def __add_flow(self, datapath, priority, match, actions):
        '''
        Install Flow Table Modification

        Takes a set of OpenFlow Actions and a OpenFlow Packet Match and creates
        the corresponding Flow-Mod. This is then installed to a given datapath
        at a given priority.
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Apply Actions is used for the instruction to set so that the specified action is immediately used.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        # The instance of the OFPFlowMod class is generated and the message is sent to the 
        # OpenFlow switch using the Datapath.send_msg() method.
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, idle_timeout=60)
        
        # Print some useful information.
        self.logger.info("Flow-Mod written to {}".format(dpid_to_str(datapath.id)))
        
        datapath.send_msg(mod)