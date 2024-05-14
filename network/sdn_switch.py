import json

from ryu.app.wsgi import Response
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3

from firewall_controller import FirewallController, SWITCHID_PATTERN, VLANID_PATTERN

class FirewallRules():

    RULES = [
        {
            "dpid": "0000000000000001",
            "rules": [
                '{"nw_src": "10.0.0.1/32","nw_dst": "10.0.0.2/32","nw_proto": "ICMP"}',
                '{"nw_src": "10.0.0.1/32","nw_dst": "10.0.0.3/32","nw_proto": "ICMP"}',
                '{"nw_src": "10.0.0.1/32","nw_dst": "10.0.0.4/32","nw_proto": "ICMP"}',
                '{"nw_src": "10.0.0.2/32","nw_dst": "10.0.0.1/32","nw_proto": "ICMP"}',
                '{"nw_src": "10.0.0.3/32","nw_dst": "10.0.0.1/32","nw_proto": "ICMP"}',
                '{"nw_src": "10.0.0.4/32","nw_dst": "10.0.0.1/32","nw_proto": "ICMP"}'
            ]
        }
    ]

class DynamicFirewall(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = { 'dpset': dpset.DPSet }

    REQUIREMENTS = {'switchid': SWITCHID_PATTERN, 'vlanid': VLANID_PATTERN}

    def __init__(self, *args, **kwargs):
        super(DynamicFirewall, self).__init__(*args, **kwargs)

        # logger configure
        FirewallController.set_logger(self.logger)

        self.dpset = kwargs['dpset']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters

        self.fwc = FirewallController(self.data)


    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        flags = 0
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION or \
                dp.ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            flags = dp.ofproto.OFPMPF_REPLY_MORE

        if msg.flags & flags:
            return
        del self.waiters[dp.id][msg.xid]
        lock.set()

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter:
            FirewallController.regist_ofs(ev.dp)

            fwID = ev.dp.id
            if len(FirewallRules.RULES) >= fwID:
                self.fwc.set_enable("", FirewallRules.RULES[fwID-1]["dpid"])
                for rule in FirewallRules.RULES[fwID-1]["rules"]:
                    body = json.dumps(str(rule))
                    res = Response(content_type='application/json', body=body)
                    self.fwc.set_rule(res, FirewallRules.RULES[fwID-1]["dpid"])
        else:
            FirewallController.unregist_ofs(ev.dp)

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
        FirewallController.packet_in_handler(ev.msg)
