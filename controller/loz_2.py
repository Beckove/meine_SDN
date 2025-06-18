# -*- coding: utf-8 -*-
from __future__ import print_function
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import ethernet, ipv4, tcp, udp, icmp

import numpy as np
import ipaddress
import joblib
import os
from datetime import datetime

import switch

class SimpleMonitorLabel(switch.SimpleSwitch13):
    """
    Ryu controller dùng RandomForest để phân loại luồng,
    capture traffic giống nguyên bản: chỉ table-miss + smurf, sau đó dùng reactive của SimpleSwitch13
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleMonitorLabel, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        self.out_file = 'lz.csv'
        if not os.path.exists(self.out_file):
            with open(self.out_file, 'w') as f:
                f.write('pkt_rate,pkt_delay,byte_rate,last_pkt,'
                        'fid,num_pkt,first_pkt,des_add,'
                        'pkt_in,duration_1,duration_2,byte_count,'
                        'pkt_out,pkt_sz,is_broadcast,'
                        'tcp_flags,icmp_type,icmp_code,label\n')

        # Load model và scaler (vẫn sử dụng model 5 lớp)
        self.rf = joblib.load('rf_model.joblib')
        self.scaler = joblib.load('rf_scaler.joblib')

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # Table-miss: gửi tất cả packet lạ lên controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst))

        # Smurf detection: ICMP đến broadcast
        smurf_match = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=1,
            ipv4_dst='10.0.0.255'
        )
        flood_actions = [
            parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER),
            parser.OFPActionOutput(ofp.OFPP_FLOOD, 0)
        ]
        inst2 = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, flood_actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=100, match=smurf_match, instructions=inst2))

        # Gọi super để dùng reactive rules của SimpleSwitch13
        super(SimpleMonitorLabel, self).switch_features_handler(ev)

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, dp):
        parser = dp.ofproto_parser
        dp.send_msg(parser.OFPFlowStatsRequest(dp))

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

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

                # Tính thời gian tồn tại của flow
                dur = stat.duration_sec + stat.duration_nsec * 1e-9
                duration_1 = dur
                first_pkt = now_ts - dur
                duration_2 = now_ts - first_pkt

                pkt_rate = pkt_cnt / dur if dur else 0
                pkt_delay = dur / pkt_cnt if pkt_cnt else 0
                byte_rate = byte_cnt / dur if dur else 0
                last_pkt = now_ts

                src_ip = stat.match.get('ipv4_src', '0.0.0.0')
                dst_ip = stat.match.get('ipv4_dst', '0.0.0.0')
                sport = stat.match.get('tcp_src', stat.match.get('udp_src', 0))
                dport = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))
                fid = hash((src_ip, sport, dst_ip, dport, proto))
                pkt_sz = byte_cnt / pkt_cnt if pkt_cnt else 0

                # Cờ broadcast
                is_b = 1 if dst_ip.endswith('.255') else 0

                # Các đặc trưng mở rộng
                tcp_flags = stat.match.get('tcp_flags', 0)
                icmp_type = stat.match.get('icmp_type', 0)
                icmp_code = stat.match.get('icmp_code', 0)

                # Chuẩn bị feature và dự đoán
                feat = [pkt_rate, pkt_delay, byte_rate, last_pkt,
                        fid, pkt_cnt, first_pkt, dst_ip,
                        pkt_cnt, duration_1, duration_2, byte_cnt,
                        pkt_cnt, pkt_sz, is_b,
                        tcp_flags, icmp_type, icmp_code]
                X = np.array([[pkt_rate, pkt_delay, byte_rate,
                               last_pkt, fid, pkt_cnt, first_pkt,
                               int(ipaddress.IPv4Address(dst_ip)), pkt_cnt,
                               duration_1, duration_2, byte_cnt,
                               pkt_cnt, pkt_sz, is_b,
                               tcp_flags, icmp_type, icmp_code]])
                try:
                    Xs = self.scaler.transform(X)
                    pred = self.rf.predict(Xs)[0]
                    # Map 5 lớp: benign, smurf, icmp_fl, tcp_fl, udp_fl
                    label_map = {
                        0: 'benign', 1: 'smurf',
                        2: 'icmp_fl', 3: 'tcp_fl', 4: 'udp_fl'
                    }
                    label = label_map.get(pred, 'unknown')
                except Exception:
                    label = 'error'

                f.write(','.join(map(str, feat + [label])) + '\n')

