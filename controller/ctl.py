# -*- coding: utf-8 -*-
import os
import switch
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from datetime import datetime

class MeinDatasetCollector(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(MeinDatasetCollector, self).__init__(*args, **kwargs)
        self.datapaths = {}
        hub.spawn(self.monitor)

        self.csv_file = "mein_dtset.csv"
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, "w") as f:
                header = [
                    "PKT_RATE","PKT_DELAY","BYTE_RATE","LAST_PKT_RECEIVED",
                    "FID","NUMBER_OF_PKT","FIRST_PKT_SENT",
                    "DES_ADD","PKT_IN","PKT_SEND_TIME",
                    "NUMBER_OF_BYTE","PKT_RECEIVED_TIME",
                    "PKT_OUT","PKT_SIZE","label"
                ]
                f.write(",".join(header) + "\n")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp     = ev.msg.datapath
        ofp    = dp.ofproto
        parser = dp.ofproto_parser

        # 1) Smurf: ICMP to broadcast 10.0.0.255
        smurf_match = parser.OFPMatch(
            eth_type=0x0800,    # IPv4
            ip_proto=1,         # ICMP
            ipv4_dst="10.0.0.255"
        )
        actions = [
            parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER),
            parser.OFPActionOutput(ofp.OFPP_FLOOD, 0)
        ]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(
            datapath     = dp,
            priority     = 200,
            match        = smurf_match,
            instructions = inst
        ))

        # 2) Capture all ICMP (general flood and benign)
        icmp_match = parser.OFPMatch(eth_type=0x0800, ip_proto=1)
        dp.send_msg(parser.OFPFlowMod(
            datapath     = dp,
            priority     = 100,
            match        = icmp_match,
            instructions = inst
        ))

        # 3) Capture UDP (flood + benign)
        udp_match = parser.OFPMatch(eth_type=0x0800, ip_proto=17)
        dp.send_msg(parser.OFPFlowMod(
            datapath     = dp,
            priority     = 100,
            match        = udp_match,
            instructions = inst
        ))

        # 4) Capture TCP flood
        tcp_match = parser.OFPMatch(eth_type=0x0800, ip_proto=6)
        dp.send_msg(parser.OFPFlowMod(
            datapath     = dp,
            priority     = 100,
            match        = tcp_match,
            instructions = inst
        ))

        # 5) Default reactive rules
        super(MeinDatasetCollector, self).switch_features_handler(ev)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    def monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(0.85)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_handler(self, ev):
        now = datetime.now().timestamp()
        with open(self.csv_file, "a") as f:
            for stat in ev.msg.body:
                m = stat.match
                proto = m.get('ip_proto')
                # Only ICMP, UDP, TCP with packets
                if stat.packet_count == 0 or proto not in (1, 17, 6):
                    continue

                # Extract fields
                ip_src = m.get('ipv4_src', '0.0.0.0')
                ip_dst = m.get('ipv4_dst', '0.0.0.0')
                des_add = ip_dst

                duration = stat.duration_sec + stat.duration_nsec * 1e-9
                pkt_cnt  = stat.packet_count
                byte_cnt = stat.byte_count
                pkt_rate  = pkt_cnt / duration if duration>0 else 0
                pkt_delay = duration / pkt_cnt if pkt_cnt>0 else 0
                byte_rate = byte_cnt / duration if duration>0 else 0

                first_pkt = now - duration
                last_pkt  = now
                pkt_in    = pkt_cnt
                pkt_out   = pkt_cnt
                num_pkt   = pkt_cnt
                num_byte  = byte_cnt
                pkt_sz    = byte_cnt / pkt_cnt if pkt_cnt>0 else 0

                tp_s = m.get('tcp_src', m.get('udp_src', 0))
                tp_d = m.get('tcp_dst', m.get('udp_dst', 0))
                flow_id = "%s-%s-%s-%s-%s" % (ip_src, tp_s, ip_dst, tp_d, proto)
                fid     = hash(flow_id)

                # Determine label (empty for benign, 'attack' for floods)
                label = ''
                if proto == 1:
                    # ICMP: smurf or flood
                    label = 'smurf' if ip_dst == '10.0.0.255' else 'icmp_flood'
                elif proto == 17:
                    # UDP: flood vs benign by rate threshold
                    label = 'udp_flood' if pkt_rate > 50 else 'udp_benign'
                elif proto == 6:
                    label = 'tcp_flood'

                row = [
                    pkt_rate, pkt_delay, byte_rate, last_pkt,
                    fid, num_pkt, first_pkt,
                    des_add, pkt_in, duration,
                    num_byte, duration,
                    pkt_out, pkt_sz, label
                ]
                f.write(",".join(map(str, row)) + "\n")

        # end flow_stats_handler

