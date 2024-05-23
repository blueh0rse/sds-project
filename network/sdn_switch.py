import time
import array
import json
import socket
import datetime
from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.app.wsgi import Response
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_int
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import packet
from ryu.lib.packet.ether_types import ETH_TYPE_IP
from ryu.lib import hub, alert, snortlib
from threading import Thread

from firewall_controller import FirewallController, SWITCHID_PATTERN, VLANID_PATTERN, REST_NW_PROTO_TCP, REST_NW_PROTO_ICMP, REST_NW_PROTO_UDP

class FirewallRules():

    RULES = {
        1: {
            "dpid": "0000000000000001",
            "rules": [
                # 1 users
                # 2 workers
                # 3 admin
                # 4 ad
                # 5 web
                # Allows communications within specific subnets
                {"nw_src": "10.0.1.0/24", "nw_dst": "10.0.1.0/24", "nw_proto": "ALL", "actions": "ALLOW", "priority": 5},
                {"nw_src": "10.0.2.0/24", "nw_dst": "10.0.2.0/24", "nw_proto": "ALL", "actions": "ALLOW", "priority": 5},
                {"nw_src": "10.0.3.0/24", "nw_dst": "10.0.3.0/24", "nw_proto": "ALL", "actions": "ALLOW", "priority": 5},

                # Block communications between certain subnets
                ## users ->x admins
                {"nw_src": "10.0.1.0/24", "nw_dst": "10.0.3.0/24", "nw_proto": "ALL", "actions": "DENY", "priority": 10},
                ## workers ->x admins
                {"nw_src": "10.0.2.0/24", "nw_dst": "10.0.3.0/24", "nw_proto": "ALL", "actions": "DENY", "priority": 10},

                # Allow communications between certain subnets
                ## admins -> users
                {"nw_src": "10.0.3.0/24", "nw_dst": "10.0.1.0/24", "nw_proto": "ALL", "actions": "ALLOW", "priority": 5},
                ## admins -> workers
                {"nw_src": "10.0.3.0/24", "nw_dst": "10.0.2.0/24", "nw_proto": "ALL", "actions": "ALLOW", "priority": 5},

                # Allow communications from all users, workers, and admins VLANs to the AD and Web Servers
                {"nw_src": "10.0.1.0/24", "nw_dst": "10.0.4.0/24", "nw_proto": "ALL", "actions": "ALLOW", "priority": 5},
                {"nw_src": "10.0.1.0/24", "nw_dst": "10.0.5.0/24", "nw_proto": "ALL", "actions": "ALLOW", "priority": 5},

                {"nw_src": "10.0.2.0/24", "nw_dst": "10.0.4.0/24", "nw_proto": "ALL", "actions": "ALLOW", "priority": 5},
                {"nw_src": "10.0.2.0/24", "nw_dst": "10.0.5.0/24", "nw_proto": "ALL", "actions": "ALLOW", "priority": 5},

                {"nw_src": "10.0.3.0/24", "nw_dst": "10.0.4.0/24", "nw_proto": "ALL", "actions": "ALLOW", "priority": 5},
                {"nw_src": "10.0.3.0/24", "nw_dst": "10.0.5.0/24", "nw_proto": "ALL", "actions": "ALLOW", "priority": 5}

                # pub1 access to web1 and web2
                {"nw_src": "10.0.255.0/24", "nw_dst": "10.0.3.0/24", "nw_proto": "ICMP", "actions": "ALLOW", "priority": 5},
                {"nw_src": "10.0.255.0/24", "nw_dst": "10.0.0.100/32", "nw_proto": "ICMP", "actions": "ALLOW", "priority": 5},
                {"nw_src": "10.0.3.0/24", "nw_dst": "10.0.255.0/24", "nw_proto": "ICMP", "actions": "ALLOW", "priority": 5},
                {"nw_src": "10.0.0.100/24", "nw_dst": "10.0.255.0/24", "nw_proto": "ICMP", "actions": "ALLOW", "priority": 5},
                {"nw_src": "10.0.255.0/24", "nw_dst": "10.0.3.0/24", "nw_proto": "TCP", "actions": "ALLOW", "priority": 5},
                {"nw_src": "10.0.255.0/24", "nw_dst": "10.0.0.100/32", "nw_proto": "TCP", "actions": "ALLOW", "priority": 5},
                {"nw_src": "10.0.3.0/24", "nw_dst": "10.0.255.0/24", "nw_proto": "TCP", "actions": "ALLOW", "priority": 5},
                {"nw_src": "10.0.0.100/24", "nw_dst": "10.0.255.0/24", "nw_proto": "TCP", "actions": "ALLOW", "priority": 5},

                # General DENY
                {"nw_src": "10.0.0.0/16", "nw_dst": "10.0.0.0/16", "nw_proto": "ICMP", "actions": "DENY"},
            ]
        }
    }

    IP_TO_MAIN_SWITCH = {
        "10.0.1.1": {
            "int": 1,
            "dpid": "0000000000000001"
        },
        "10.0.1.2": {
            "int": 1,
            "dpid": "0000000000000001"
        },
        "10.0.1.3": {
            "int": 1,
            "dpid": "0000000000000001"
        },
        "10.0.2.1": {
            "int": 1,
            "dpid": "0000000000000001"
        },
        "10.0.2.2": {
            "int": 1,
            "dpid": "0000000000000001"
        },
        "10.0.2.3": {
            "int": 1,
            "dpid": "0000000000000001"
        },
        "10.0.3.1": {
            "int": 1,
            "dpid": "0000000000000001"
        },
        "10.0.3.2": {
            "int": 1,
            "dpid": "0000000000000001"
        },
        "10.0.3.3": {
            "int": 1,
            "dpid": "0000000000000001"
        },
        "10.0.4.1": {
            "int": 1,
            "dpid": "0000000000000001"
        },
        "10.0.5.1": {
            "int": 1,
            "dpid": "0000000000000001"
        },
        "10.0.5.2": {
            "int": 1,
            "dpid": "0000000000000001"
        },
        "10.0.255.1": {
            "int": 1,
            "dpid": "0000000000000001"
        },
        "10.0.255.2": {
            "int": 1,
            "dpid": "0000000000000001"
        }
    }

    SWITCHES_ID = [1]

class DynamicFirewall(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'snortlib': snortlib.SnortLib
    }

    REQUIREMENTS = {'switchid': SWITCHID_PATTERN, 'vlanid': VLANID_PATTERN}

    VIRTUAL_IP = '10.0.0.100'  # The virtual server IP

    SERVER1_IP = '10.0.5.1'
    SERVER1_MAC = '00:00:00:00:05:01'
    SERVER1_PORT = 1
    SERVER2_IP = '10.0.5.2'
    SERVER2_MAC = '00:00:00:00:05:02'
    SERVER2_PORT = 2

    UDP_IP = "127.0.0.1"
    UDP_PORT = 8094

    def __init__(self, *args, **kwargs):
        super(DynamicFirewall, self).__init__(*args, **kwargs)

        # Firewall configuration
        self.dpset = kwargs['dpset']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters
        self.banned_rules = {}

        self.fwc = FirewallController(self.data)

        # logger configure
        self.fwc.set_logger(self.logger)

        # Snort configuration
        self.snort = kwargs['snortlib']
        self.snort_port = 60
        self.mac_to_port = {}

        socket_config = {'unixsock': True}
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

        self.mac_to_port = {}
        self.monitor_thread = hub.spawn(self._monitor)

        #testing purpose , to be deleted
        self.ssh_connections = {}
        self.port_scans = {}
        self.ping_log = {}
        self.http_response = {}


    ################################
    ####### Helper Functions #######
    ################################

    def _monitor(self):
        print("_monitor")
        while True:
            self._send_stats()
            hub.sleep(10)

    #ToDo Port scan is working with hardcoded data , needs actual testing , PING and HTTP_RES messages are not sent.
    def _send_stats(self):
        SSH_MSG = "ssh,src_ip=%s,dst_ip=%s repetitions=%d %d"
        PORT_SCAN_MSG = "port_scan,src_ip=%s,dst_ip=%s repetitions=%d %d"
        PING_MSG = "ping,src_ip=%s,dst_ip=%s packets_received=%d,packets_transmitted=%d,percent_packet_loss=%.2f %d"
        HTTP_MSG = "http,src_ip=%s,dst_ip=%s packets_received=%d,packets_transmitted=%d %d"

        def send_udp_message(message):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message.encode(), (self.UDP_IP, self.UDP_PORT))

        for src_ip in self.ssh_connections:
            for dst_ip in self.ssh_connections[src_ip]:
                timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
                msg = SSH_MSG % (src_ip, dst_ip, self.ssh_connections[src_ip][dst_ip], timestamp)
                send_udp_message(msg)

        for src_ip in self.port_scans:
            for dst_ip in self.port_scans[src_ip]:
                timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
                msg = PORT_SCAN_MSG % (src_ip, dst_ip, self.port_scans[src_ip][dst_ip], timestamp)
                send_udp_message(msg)

        for src_ip in self.ping_log:
            for dst_ip in self.ping_log[src_ip]:
                timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
                packets_received = self.ping_log[src_ip][dst_ip]["packets_received"]
                packets_transmitted = self.ping_log[src_ip][dst_ip]["packets_transmitted"]
                percent_packet_loss = self.ping_log[src_ip][dst_ip]["percent_packet_loss"]

                msg = PING_MSG % (src_ip, dst_ip, packets_received, packets_transmitted, percent_packet_loss, timestamp)
                send_udp_message(msg)

        for src_ip in self.http_response:
            for dst_ip in self.http_response[src_ip]:
                timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
                packets_received = self.http_response[src_ip][dst_ip]["packets_received"]
                packets_transmitted = self.http_response[src_ip][dst_ip]["packets_transmitted"]

                msg = HTTP_MSG % (src_ip, dst_ip, packets_received, packets_transmitted, timestamp)
                send_udp_message(msg)

        self.ssh_connections = {}
        self.port_scans = {}
        self.ping_log = {}
        self.http_response = {}

    # Used with Firewall
    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            self.waiters[dp.id] = None
        self.waiters[dp.id] = (hub.Event(), [msg])

        flags = 0
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION or \
                dp.ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            flags = dp.ofproto.OFPMPF_REPLY_MORE

        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters
        self.fwc.update(self.data)

        if msg.flags & flags:
            return

    # Used with Snort
    def packet_print(self, pkt):
        pkt = packet.Packet(array.array('B', pkt))

        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)

        if _icmp:
            self.logger.info("%r", _icmp)

        if _ipv4:
            self.logger.info("%r", _ipv4)

        if eth:
            self.logger.info("%r", eth)

        # for p in pkt.protocols:
        #     if hasattr(p, 'protocol_name') is False:
        #         break
        #     print('p: %s' % p.protocol_name)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def remove_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)

    def delayed_remove_flow(self, datapath, match, duration):
        time.sleep(duration)
        self.remove_flow(datapath, match)

    def snort_packet_in_handler(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port),
                   parser.OFPActionOutput(self.snort_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    ## Getters
    def get_snort_sid(self, string):
        return str(string.split(" --- ")[1].rstrip('\x00')).strip()

    def get_src_ip(self, pkt, protocol = ipv4.ipv4):
        pkt = packet.Packet(array.array('B', pkt))
        return pkt.get_protocol(protocol).src

    def get_dst_ip(self, pkt, protocol = ipv4.ipv4):
        pkt = packet.Packet(array.array('B', pkt))
        return pkt.get_protocol(protocol).dst

    def get_bytes(self, pkt):
        return len(pkt)

    def get_response(self, res):
        tmp = json.loads(res.body.decode())
        if tmp[0]:
            if tmp[0][1]:
                try:
                    return tmp[0][1][0]
                except:
                    return tmp[0][1]

    def get_rule_id_from_banning(self, res):
        rule = (self.get_response(res)["details"].split(" : ")[1]).strip()
        res = {}
        res["rule_id"] = rule.split("=")[1]
        return json.dumps(res)

    def ban_ip(self, ip, protocol = REST_NW_PROTO_ICMP):
        fwID = FirewallRules.IP_TO_MAIN_SWITCH[ip]["int"]
        dpID = FirewallRules.IP_TO_MAIN_SWITCH[ip]["dpid"]
        rule = {"nw_src": ip, "nw_dst": "10.0.0.0/16", "nw_proto": protocol, "actions": "DENY", "priority": 100}

        if fwID not in self.banned_rules:
            self.banned_rules[fwID] = {}
        if str(rule) in self.banned_rules[fwID]:
            return None

        print("////////////////")
        print("Banning IP: %s" % ip)

        res = self.fwc.set_rule(Response(content_type='application/json', body=json.dumps(rule)), dpID)
        ruleID = json.loads(self.get_rule_id_from_banning(res))
        self.banned_rules[fwID][str(rule)] = ruleID["rule_id"]

        print(json.dumps(self.get_response(res), indent=4))

        print("////////////////")

        return (json.dumps(ruleID), str(rule))

    def delayed_unban_rule(self, bannedRule, duration):
        if duration == -1:
            return

        time.sleep(duration)
        self.unban_rule(bannedRule)

    def unban_rule(self, res):
        jsonRule = json.loads(res[0])

        print("////////////////")
        print("Unbanning rule: %s" % jsonRule["rule_id"])

        fwIDs = []
        for fwID in self.banned_rules:
            for rule in self.banned_rules[fwID].copy():
                if rule == res[1]:
                    fwIDs.append(fwID)
                    del self.banned_rules[fwID][rule]

        print("////////////////")
        print(fwIDs)
        print("////////////////")
        for fwID in fwIDs:
            result = self.fwc.delete_rule(Response(content_type='application/json', body=json.dumps(res[0])), FirewallRules.RULES[fwID]["dpid"])
            if result.status_code == 200:
                print(json.dumps(self.get_response(result), indent=4))

        print("////////////////")

    # Load Balancer Functions
    def load_balancer_packet_in_hanlder(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst_mac = eth.dst
        src_mac = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src_mac, dst_mac, in_port)

        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
            delayed_remove_flow_thread = Thread(target=self.delayed_remove_flow, args=(datapath, match, 14))
            delayed_remove_flow_thread.start()

        # if ev.msg.datapath.id in [4, 10]:
        # Handle ARP Packet
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_header = pkt.get_protocol(arp.arp)
            if arp_header.dst_ip == self.VIRTUAL_IP and arp_header.opcode == arp.ARP_REQUEST:
                # Build an ARP reply packet using source IP and source MAC
                reply_packet = self.arp_reply(arp_header.src_ip, arp_header.src_mac)
                actions = [parser.OFPActionOutput(in_port)]
                packet_out = parser.OFPPacketOut(datapath=datapath,
                                                in_port=ofproto.OFPP_ANY,
                                                data=reply_packet.data,
                                                actions=actions,
                                                buffer_id=ofproto.OFP_NO_BUFFER)
                datapath.send_msg(packet_out)
                self.logger.info("Sent the ARP reply packet")
                return

        if ev.msg.datapath.id in [10]:
            # Handle TCP Packet
            if eth.ethertype == ETH_TYPE_IP:
                ip_header = pkt.get_protocol(ipv4.ipv4)
                if ip_header.dst == self.VIRTUAL_IP:
                    self.handle_tcp_packet(datapath, in_port, ip_header, parser, dst_mac, src_mac)
                    self.logger.info("TCP packet handled")
                    return

        # Send if other packet
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    # Source IP and MAC passed here now become the destination for the reply packet
    def arp_reply(self, dst_ip, dst_mac):
        arp_target_ip = dst_ip  # the sender ip
        arp_target_mac = dst_mac  # the sender mac
        # Making the load balancer IP as source IP
        src_ip = self.VIRTUAL_IP

        if haddr_to_int(arp_target_mac) % 2 == 1:
            src_mac = self.SERVER1_MAC
        else:
            src_mac = self.SERVER2_MAC
        self.logger.info("Selected server MAC: " + src_mac)

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_ARP))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip, dst_mac=arp_target_mac, dst_ip=arp_target_ip))
        pkt.serialize()
        return pkt

    def handle_tcp_packet(self, datapath, in_port, ip_header, parser, dst_mac, src_mac):

        if dst_mac == self.SERVER1_MAC:
            server_dst_ip = self.SERVER1_IP
            server_out_port = self.SERVER1_PORT
        else:
            server_dst_ip = self.SERVER2_IP
            server_out_port = self.SERVER2_PORT

        # Route to server
        match = parser.OFPMatch(in_port=in_port, eth_type=ETH_TYPE_IP, ip_proto=ip_header.proto,
                                ipv4_dst=self.VIRTUAL_IP, ipv4_src=ip_header.src)

        actions = [parser.OFPActionSetField(ipv4_dst=server_dst_ip),
                   parser.OFPActionOutput(server_out_port)]

        self.add_flow(datapath, 20, match, actions)
        self.logger.info("<==== Added TCP Flow- Route to Server: " + str(server_dst_ip) +
                         " from Client :" + str(ip_header.src) + " on Switch Port:" +
                         str(server_out_port) + "====>")
        delayed_remove_flow_thread = Thread(target=self.delayed_remove_flow, args=(datapath, match, 15))
        delayed_remove_flow_thread.start()

        # Reverse route from server
        match = parser.OFPMatch(in_port=server_out_port, eth_type=ETH_TYPE_IP,
                                ip_proto=ip_header.proto,
                                ipv4_src=server_dst_ip,
                                eth_dst=src_mac)
        actions = [parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP),
                   parser.OFPActionOutput(in_port)]

        self.add_flow(datapath, 20, match, actions)
        self.logger.info("<==== Added TCP Flow- Reverse route from Server: " + str(server_dst_ip) +
                         " to Client: " + str(src_mac) + " on Switch Port:" +
                         str(in_port) + "====>")
        delayed_remove_flow_thread = Thread(target=self.delayed_remove_flow, args=(datapath, match, 16))
        delayed_remove_flow_thread.start()

    #################################
    ######## Events Handlers ########
    #################################
    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        fwID = ev.dp.id
        if fwID in FirewallRules.SWITCHES_ID:
            if ev.enter:
                self.fwc.regist_ofs(ev.dp)
                self.fwc.set_enable("", FirewallRules.RULES[fwID]["dpid"])
                for rule in FirewallRules.RULES[fwID]["rules"]:
                    res = Response(content_type='application/json', body=json.dumps(rule))
                    self.fwc.set_rule(res, FirewallRules.RULES[fwID]["dpid"])
            else:
                self.fwc.unregist_ofs(ev.dp)

    # for OpenFlow version1.0
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_0(self, ev):
        if ev.msg.datapath.id in FirewallRules.SWITCHES_ID:
            self.stats_reply_handler(ev)

    # for OpenFlow version1.2 or later
    @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_2(self, ev):
        if ev.msg.datapath.id in FirewallRules.SWITCHES_ID:
            self.stats_reply_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        if ev.msg.datapath.id in FirewallRules.SWITCHES_ID:
            self.fwc.packet_in_handler(ev.msg)
        elif ev.msg.datapath.id in [2, 3, 4, 10]:
            self.load_balancer_packet_in_hanlder(ev)
        # else:
        #     self.snort_packet_in_handler(ev.msg)

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        _alert: alert.AlertPkt = ev.msg
        msg = _alert.alertmsg[0].decode()
        sid = self.get_snort_sid(msg)
        bannedRule = None
        duration = -1

        # self.fwc.get_log_status(None)
        if int(sid) == 1100001: # local ICMP flood (light)
            ip = self.get_src_ip(_alert.pkt)
            bannedRule = self.ban_ip(ip)
            if bannedRule is not None:
                print("local ICMP flood (light)")
            duration = 30
        elif int(sid) == 1100002: # local ICMP flood (medium)
            ip = self.get_src_ip(_alert.pkt)
            bannedRule = self.ban_ip(ip)
            if bannedRule is not None:
                print("local ICMP flood (medium)")
            duration = 30
        elif int(sid) == 1100003: # external ICMP flood (light)
            ip = self.get_src_ip(_alert.pkt)
            bannedRule = self.ban_ip(ip)
            if bannedRule is not None:
                print("external ICMP flood (light)")
            duration = 30
        elif int(sid) == 1100004: # external ICMP flood (medium)
            ip = self.get_src_ip(_alert.pkt)
            bannedRule = self.ban_ip(ip)
            if bannedRule is not None:
                print("external ICMP flood (medium)")
            duration = 30
        elif int(sid) == 1100005: # external ICMP flood (heavy)
            ip = self.get_src_ip(_alert.pkt)
            bannedRule = self.ban_ip(ip)
            if bannedRule is not None:
                print("external ICMP flood (heavy)")
            duration = 30
        elif int(sid) == 1100006: # external ICMP flood (dst tracking)
            ip = self.get_src_ip(_alert.pkt)
            bannedRule = self.ban_ip(ip)
            if bannedRule is not None:
                print("external ICMP flood (dst tracking)")
            duration = 30
        elif int(sid) == 1100007: # TCP flood (light)
            ip = self.get_src_ip(_alert.pkt)
            bannedRule = self.ban_ip(ip, REST_NW_PROTO_TCP)
            if bannedRule is not None:
                print("TCP flood (light)")
            duration = 30
        elif int(sid) == 1100008: # TCP flood (medium)
            ip = self.get_src_ip(_alert.pkt)
            bannedRule = self.ban_ip(ip, REST_NW_PROTO_TCP)
            if bannedRule is not None:
                print("TCP flood (medium)")
            duration = 30
        elif int(sid) == 1100009: # TCP flood (heavy)
            ip = self.get_src_ip(_alert.pkt)
            bannedRule = self.ban_ip(ip, REST_NW_PROTO_TCP)
            if bannedRule is not None:
                print("TCP flood (heavy)")
            duration = 30
        elif int(sid) == 1100010: # TCP flood (dst tracking)
            ip = self.get_src_ip(_alert.pkt)
            bannedRule = self.ban_ip(ip, REST_NW_PROTO_TCP)
            if bannedRule is not None:
                print("TCP flood (dst tracking)")
            duration = 30
        elif int(sid) == 1100011: # TCP port scan
            ip = self.get_src_ip(_alert.pkt)
            bannedRule = self.ban_ip(ip, REST_NW_PROTO_TCP)

            if bannedRule is not None:
                print("TCP port scan")
            duration = 30
        elif int(sid) == 1100012: # TCP port scan (DMZ)
            ip = self.get_src_ip(_alert.pkt, REST_NW_PROTO_TCP)
            bannedRule = self.ban_ip(ip)

            if bannedRule is not None:
                print("TCP port scan (DMZ)")
            duration = 30
        elif int(sid) == 1100014: # SSH connection (attack)
            ip = self.get_src_ip(_alert.pkt, REST_NW_PROTO_TCP)
            bannedRule = self.ban_ip(ip)
            if bannedRule is not None:
                print("SSH connection (attack)")
            duration = 30


        elif int(sid) == 1100016: # failed SSH connection retries
            ip = self.get_src_ip(_alert.pkt)
            bannedRule = self.ban_ip(ip, REST_NW_PROTO_TCP)
            if bannedRule is not None:
                print("Failed SSH connection retries")
            duration = 30
        elif int(sid) == 1100017: # API Honeypot detection
            ip = self.get_src_ip(_alert.pkt)
            bannedRule = self.ban_ip(ip, REST_NW_PROTO_TCP)
            if bannedRule is not None:
                print("API Honeypot detection")
            duration = 30

        elif int(sid) == 1100013: # SSH connection (log)
            if not (str(self.get_src_ip(_alert.pkt)) in self.ssh_connections):
                self.ssh_connections[str(self.get_src_ip(_alert.pkt))] = {}

            if str(self.get_dst_ip(_alert.pkt)) in self.ssh_connections[str(self.get_src_ip(_alert.pkt))]:
                self.ssh_connections[str(self.get_src_ip(_alert.pkt))][str(self.get_dst_ip(_alert.pkt))] += 1
            else:
                self.ssh_connections[str(self.get_src_ip(_alert.pkt))][str(self.get_dst_ip(_alert.pkt))] = 1
        elif int(sid) == 1100018: # ICMP Ping (log)
            try:
                src_ip = self.get_src_ip(_alert.pkt)
                dst_ip = self.get_dst_ip(_alert.pkt)
            except:
                return

            if str(src_ip) not in self.ping_log:
                self.ping_log[src_ip] = {}
            if str(dst_ip) not in self.ping_log:
                self.ping_log[dst_ip] = {}

            if str(dst_ip) in self.ping_log[src_ip]:
                self.ping_log[src_ip][dst_ip]["packets_transmitted"] += 1
            else:
                self.ping_log[src_ip][dst_ip] = {
                    "packets_received": 0,
                    "packets_transmitted": 1,
                    "percent_packet_loss": 0,
                }

            if str(src_ip) in self.ping_log[dst_ip]:
                self.ping_log[dst_ip][src_ip]["packets_received"] += 1
            else:
                self.ping_log[dst_ip][src_ip] = {
                    "packets_received": 1,
                    "packets_transmitted": 0,
                    "percent_packet_loss": 0,
                }

            src_transmitted = self.ping_log[src_ip][dst_ip]["packets_transmitted"]
            src_received = self.ping_log[src_ip][dst_ip]["packets_received"]
            self.ping_log[src_ip][dst_ip]["percent_packet_loss"] = ((src_transmitted - src_received) / src_transmitted) * 100 if src_transmitted > 0 else 0

            dest_transmitted = self.ping_log[dst_ip][src_ip]["packets_transmitted"]
            dest_received = self.ping_log[dst_ip][src_ip]["packets_received"]
            self.ping_log[dst_ip][src_ip]["percent_packet_loss"] = ((dest_transmitted - dest_received) / dest_transmitted) * 100 if dest_transmitted > 0 else 0
        elif int(sid) == 1100019:  # HTTP (log)
            src_ip = str(self.get_src_ip(_alert.pkt))
            dst_ip = str(self.get_dst_ip(_alert.pkt))

            if not (str(src_ip) in self.http_response):
                self.http_response[src_ip] = {}
            if not (str(dst_ip) in self.http_response):
                self.http_response[dst_ip] = {}

            if str(dst_ip) in self.http_response[src_ip]:
                self.http_response[src_ip][dst_ip]["packets_transmitted"] += 1
            else:
                self.http_response[src_ip][dst_ip] = {
                    "packets_received": 0,
                    "packets_transmitted": 1
                }

            if str(src_ip) in self.http_response[dst_ip]:
                self.http_response[dst_ip][src_ip]["packets_received"] += 1
            else:
                self.http_response[dst_ip][src_ip] = {
                    "packets_received": 1,
                    "packets_transmitted": 0
                }
        elif int(sid) == 1100020:  # TCP port scanning (log)
            ip = self.get_src_ip(_alert.pkt)

            if not (str(ip) in self.port_scans):
                self.port_scans[str(ip)] = {}

            dst_ip = self.get_dst_ip(_alert.pkt)
            if str(dst_ip) in self.port_scans[str(ip)]:
                self.port_scans[str(ip)][str(dst_ip)] += 1
            else:
                self.port_scans[str(ip)][str(dst_ip)] = 1

        elif int(sid) == 1110000: # Debugging
            ip = self.get_dst_ip(_alert.pkt)
            bannedRule = self.ban_ip(ip)
            duration = 30

        if bannedRule is not None:
            thread = Thread(target=self.delayed_unban_rule, args=(bannedRule, duration,))
            thread.start()

        # self.packet_print(_alert.pkt)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

