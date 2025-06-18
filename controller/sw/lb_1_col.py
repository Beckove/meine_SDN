# -*- coding: utf-8 -*-
# It give your current dtset Này cho dtset chuẩn
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

        # 1) Cài rule đúng cho Smurf broadcast IP 10.0.0.255
        smurf_match = parser.OFPMatch(
            eth_type=0x0800,    # IPv4
            ip_proto=1,         # ICMP
            ipv4_dst="10.0.0.255"
        )
        actions = [
            # gửi copy lên controller
            parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER),
            # vẫn flood để reactive parent có packet-in
            parser.OFPActionOutput(ofp.OFPP_FLOOD, 0)
        ]
        inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
        dp.send_msg(parser.OFPFlowMod(
            datapath     = dp,
            priority     = 100,
            match        = smurf_match,
            instructions = inst
        ))

        # 2) Gọi parent để cài các rule reactive bình thường:
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
                # Yêu cầu toàn bộ flow stats
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(10)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_handler(self, ev):
        now = datetime.now().timestamp()
        with open(self.csv_file, "a") as f:
            for stat in ev.msg.body:
                m = stat.match
                # Chỉ quan tâm ICMP đã cài (reactive + smurf)
                if stat.packet_count == 0 or m.get('ip_proto') != 1:
                    continue

                # Đảm bảo stat.match có ipv4_dst
                ip_src = m.get('ipv4_src', '0.0.0.0')
                ip_dst = m.get('ipv4_dst', '0.0.0.0')
                # DES_ADD sẽ đúng 10.0.0.255 cho smurf, và đúng dst unicast
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
                flow_id = "%s-%s-%s-%s-%s" % (ip_src, tp_s, ip_dst, tp_d, 1)
                fid     = hash(flow_id)

                row = [
                    pkt_rate, pkt_delay, byte_rate, last_pkt,
                    fid, num_pkt, first_pkt,
                    des_add, pkt_in, duration,
                    num_byte, duration,
                    pkt_out, pkt_sz, ""
                ]
                f.write(",".join(map(str, row)) + "\n")

