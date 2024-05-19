import time
import array
import json

from ryu.app.wsgi import Response
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib import hub, alert, snortlib
from threading import Thread

from firewall_controller import FirewallController, SWITCHID_PATTERN, VLANID_PATTERN

class FirewallRules():

    RULES = {
        1: {
            "dpid": "0000000000000001",
            "rules": [
                # General ICMP rules
                {"nw_src": "10.0.2.0/24", "nw_dst": "10.0.2.0/24", "nw_proto": "ICMP", "actions": "ALLOW", "priority": 5},
                {"nw_src": "10.0.1.0/24", "nw_dst": "10.0.1.0/24", "nw_proto": "ICMP", "actions": "ALLOW", "priority": 5},

                # Only h1 was access to pad
                {"nw_src": "10.0.1.1/32", "nw_dst": "10.0.2.0/24", "nw_proto": "ICMP", "actions": "ALLOW", "priority": 5},
                {"nw_src": "10.0.2.0/24", "nw_dst": "10.0.1.1/32", "nw_proto": "ICMP", "actions": "ALLOW", "priority": 5},
                {"nw_src": "10.0.1.1/32", "nw_dst": "10.0.2.1/32", "nw_proto": "TCP", "actions": "ALLOW", "priority": 5},
                {"nw_src": "10.0.2.1/32", "nw_dst": "10.0.1.1/32", "nw_proto": "TCP", "actions": "ALLOW", "priority": 5},

                # pu1 access to ws1 and ws2
                {"nw_src": "10.0.255.0/24", "nw_dst": "10.0.3.0/24", "nw_proto": "ICMP", "actions": "ALLOW", "priority": 5},
                {"nw_src": "10.0.3.0/24", "nw_dst": "10.0.255.0/24", "nw_proto": "ICMP", "actions": "ALLOW", "priority": 5},

                # General DENY
                {"nw_src": "10.0.0.0/16", "nw_dst": "10.0.0.0/16", "nw_proto": "ICMP", "actions": "DENY"}
            ]
        },
        2: {
            "dpid": "0000000000000002",
            "rules": [
                {"nw_src": "10.0.0.0/16", "nw_dst": "10.0.0.0/16", "nw_proto": "ICMP", "actions": "ALLOW", "priority": 5},
            ]
        },
        3: {
            "dpid": "0000000000000003",
            "rules": [
                {"nw_src": "10.0.0.0/16", "nw_dst": "10.0.0.0/16", "nw_proto": "ICMP", "actions": "ALLOW", "priority": 5},
            ]
        },
        4: {
            "dpid": "0000000000000004",
            "rules": [
                {"nw_src": "10.0.0.0/16", "nw_dst": "10.0.0.0/16", "nw_proto": "ICMP", "actions": "ALLOW", "priority": 5},
            ]
        },
        10: {
            "dpid": "000000000000000a",
            "rules": [
                {"nw_src": "10.0.255.0/24", "nw_dst": "10.0.3.0/24", "nw_proto": "ICMP", "actions": "ALLOW", "priority": 5},
                {"nw_src": "10.0.3.0/24", "nw_dst": "10.0.255.0/24", "nw_proto": "ICMP", "actions": "ALLOW", "priority": 5},

                # General DENY
                {"nw_src": "10.0.0.0/16", "nw_dst": "10.0.0.0/16", "nw_proto": "ICMP", "actions": "DENY"}
            ]
        }
    }

    IP_TO_MAIN_SWITCH = {
        "10.0.1.1": {
            "int": 2,
            "dpid": "0000000000000002"
        },
        "10.0.1.2": {
            "int": 2,
            "dpid": "0000000000000002"
        },
        "10.0.1.3": {
            "int": 2,
            "dpid": "0000000000000002"
        },
        "10.0.2.1": {
            "int": 3,
            "dpid": "0000000000000003"
        },
        "10.0.3.1": {
            "int": 10,
            "dpid": "000000000000000a"
        },
        "10.0.3.2": {
            "int": 10,
            "dpid": "000000000000000a"
        },
        "10.0.255.1": {
            "int": 4,
            "dpid": "0000000000000004"
        }
    }

    SWITCHES_ID = [1, 2, 3, 4, 10]

class DynamicFirewall(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'snortlib': snortlib.SnortLib
    }

    REQUIREMENTS = {'switchid': SWITCHID_PATTERN, 'vlanid': VLANID_PATTERN}

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



    ################################
    ####### Helper Functions #######
    ################################

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

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

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

    def get_src_ip(self, pkt):
        pkt = packet.Packet(array.array('B', pkt))
        return pkt.get_protocol(ipv4.ipv4).src

    def get_dst_ip(self, pkt):
        pkt = packet.Packet(array.array('B', pkt))
        return pkt.get_protocol(ipv4.ipv4).dst

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

    def ban_ip(self, ip):
        fwID = FirewallRules.IP_TO_MAIN_SWITCH[ip]["int"]
        dpID = FirewallRules.IP_TO_MAIN_SWITCH[ip]["dpid"]
        rule = {"nw_src": ip, "nw_dst": "10.0.0.0/16", "nw_proto": "ICMP", "actions": "DENY", "priority": 100}

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

    #################################
    ######## Events Handlers ########
    #################################
    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter:
            self.fwc.regist_ofs(ev.dp)

            fwID = ev.dp.id
            if fwID in FirewallRules.SWITCHES_ID:
                self.fwc.set_enable("", FirewallRules.RULES[fwID]["dpid"])
                for rule in FirewallRules.RULES[fwID]["rules"]:
                    res = Response(content_type='application/json', body=json.dumps(rule))
                    self.fwc.set_rule(res, FirewallRules.RULES[fwID]["dpid"])
        else:
            self.fwc.unregist_ofs(ev.dp)

    # for OpenFlow version1.0
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_0(self, ev):
        self.stats_reply_handler(ev)

    # for OpenFlow version1.2 or later
    @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_2(self, ev):
        self.stats_reply_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        self.fwc.packet_in_handler(ev.msg)
        self.snort_packet_in_handler(ev.msg)

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
        if int(sid) == 1100002: # local ICMP flood (medium)
            ip = self.get_src_ip(_alert.pkt)
            bannedRule = self.ban_ip(ip)
            if bannedRule is not None:
                print("local ICMP flood (medium)")
            duration = 30
        if int(sid) == 1100003: # external ICMP flood (light)
            ip = self.get_src_ip(_alert.pkt)
            bannedRule = self.ban_ip(ip)
            if bannedRule is not None:
                print("external ICMP flood (light)")
            duration = 30
        if int(sid) == 1100004: # external ICMP flood (medium)
            ip = self.get_src_ip(_alert.pkt)
            bannedRule = self.ban_ip(ip)
            if bannedRule is not None:
                print("external ICMP flood (medium)")
            duration = 30
        if int(sid) == 1100005: # external ICMP flood (heavy)
            ip = self.get_src_ip(_alert.pkt)
            bannedRule = self.ban_ip(ip)
            if bannedRule is not None:
                print("external ICMP flood (heavy)")
            duration = 30
        if int(sid) == 1100006: # external ICMP flood (dst tracking)
            ip = self.get_src_ip(_alert.pkt)
            bannedRule = self.ban_ip(ip)
            if bannedRule is not None:
                print("external ICMP flood (dst tracking)")
            duration = 30
        elif int(sid) == 1100017: # Debugging
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

