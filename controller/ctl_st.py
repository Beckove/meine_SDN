from __future__ import print_function
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import ethernet, ipv4, tcp, udp, icmp

import os
from datetime import datetime

import switch  # kế thừa từ SimpleSwitch13

class SimpleMonitorLabel(switch.SimpleSwitch13):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleMonitorLabel, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        self.out_file = 'dt_col.csv'
        if not os.path.exists(self.out_file):
            with open(self.out_file, 'w') as f:
                f.write('pkt_rate,pkt_delay,byte_rate,last_pkt,'
                        'fid,num_pkt,first_pkt,des_add,'
                        'pkt_in,duration_1,byte_count,duration_2,'
                        'pkt_out,pkt_sz,is_broadcast,label\n')

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        # Mọi gói đến controller
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst_all = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=0,
                                      match=parser.OFPMatch(), instructions=inst_all))

        super(SimpleMonitorLabel, self).switch_features_handler(ev)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, dp):
        dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        now_ts = datetime.now().timestamp()
        with open(self.out_file, 'a') as f:
            for stat in ev.msg.body:
                proto = stat.match.get('ip_proto')
                if proto not in (1, 6, 17):
                    continue

                pkt_cnt = stat.packet_count
                byte_cnt = stat.byte_count
                if pkt_cnt == 0:
                    continue

                dur = stat.duration_sec + stat.duration_nsec * 1e-9
                pkt_rate = pkt_cnt / dur if dur else 0
                pkt_delay = dur / pkt_cnt if pkt_cnt else 0
                byte_rate = byte_cnt / dur if dur else 0
                last_pkt = now_ts
                first_pkt = now_ts - dur
                pkt_sz = byte_cnt / pkt_cnt
                is_b = 1 if stat.match.get('ipv4_dst','').endswith('.255') else 0

                src = stat.match.get('ipv4_src','0.0.0.0')
                dst = stat.match.get('ipv4_dst','0.0.0.0')
                sport = stat.match.get('tcp_src', stat.match.get('udp_src', 0))
                dport = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))
                # Đơn giản hóa: dùng tuple làm flow ID
                fid = hash((src, sport, dst, dport, proto))

                # Ghi ra CSV, label cố định bằng 1
                row = [pkt_rate, pkt_delay, byte_rate, last_pkt,
                       fid, pkt_cnt, first_pkt, dst,
                       pkt_cnt, dur, byte_cnt, dur,
                       pkt_cnt, pkt_sz, is_b, 1]
                f.write(','.join(map(str, row)) + '\n')
