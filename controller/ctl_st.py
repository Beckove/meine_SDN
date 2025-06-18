#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Controller Ryu dùng Random Forest đã train trên dm.csv (14 feature) để gán nhãn luồng.
"""
from __future__ import print_function
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp

import numpy as np
import ipaddress
import joblib
import os
from datetime import datetime

import switch

class SimpleMonitorLabel(switch.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleMonitorLabel, self).__init__(*args, **kwargs)
        # Load model và scaler
        def load_model(path):
            return joblib.load(path)
        self.rf     = load_model('rf_model.joblib')
        self.scaler = load_model('rf_scaler.joblib')

        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        # Khởi tạo file CSV đầu ra
        self.out_file = 'lz.csv'
        if not os.path.exists(self.out_file):
            with open(self.out_file, 'w') as f:
                header = (
                    'pkt_rate,pkt_delay,byte_rate,last_pkt,'
                    'fid,num_pkt,first_pkt,des_add,'
                    'pkt_in,duration_1,num_byte,duration_2,'
                    'pkt_out,pkt_sz,is_broadcast,label\n'
                )
                f.write(header)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # Table-miss: gửi tất cả packet lên controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst))

        # Smurf detection: flood + controller
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
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=100, match=smurf_match, instructions=inst2
        ))

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
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, dp):
        parser = dp.ofproto_parser
        req = parser.OFPFlowStatsRequest(dp)
        dp.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        now_ts = datetime.now().timestamp()
        with open(self.out_file, 'a') as f:
            for stat in ev.msg.body:
                proto = stat.match.get('ip_proto')
                if proto not in (1, 6, 17):
                    continue

                pkt_cnt  = stat.packet_count
                byte_cnt = stat.byte_count
                if pkt_cnt == 0:
                    continue

                dur = stat.duration_sec + stat.duration_nsec * 1e-9

                # Tính feature
                pkt_rate  = pkt_cnt / dur if dur else 0
                pkt_delay = dur / pkt_cnt if pkt_cnt else 0
                byte_rate = byte_cnt / dur if dur else 0
                last_pkt  = now_ts
                first_pkt = now_ts - dur

                src_ip = stat.match.get('ipv4_src', '0.0.0.0')
                dst_ip = stat.match.get('ipv4_dst', '0.0.0.0')
                sport  = stat.match.get('tcp_src', stat.match.get('udp_src', 0))
                dport  = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))
                fid    = hash((src_ip, sport, dst_ip, dport, proto))

                pkt_sz = byte_cnt / pkt_cnt if pkt_cnt else 0
                is_b   = 1 if dst_ip.endswith('.255') else 0

                try:
                    des_int = int(ipaddress.IPv4Address(dst_ip))
                except:
                    des_int = 0

                # Tạo X đầu vào RF: đúng 14 feature theo thứ tự đã train (không có des_int)
                X = np.array([[
                    pkt_rate, pkt_delay, byte_rate,
                    last_pkt, fid, pkt_cnt, first_pkt,
                    pkt_cnt, dur, byte_cnt,
                    dur, pkt_cnt, pkt_sz, is_b
                ]])
                Xs   = self.scaler.transform(X)
                pred = self.rf.predict(Xs)[0]
                label_map = {0:'benign',1:'smurf',2:'icmp_fl',3:'tcp_fl',4:'udp_fl'}
                lbl = label_map.get(pred, 'unknown')

                # Ghi đủ 16 cột vào CSV (có thêm des_add là dst_ip và label)
                feat = [
                    pkt_rate, pkt_delay, byte_rate, last_pkt,
                    fid, pkt_cnt, first_pkt, dst_ip,
                    pkt_cnt, dur, byte_cnt, dur,
                    pkt_cnt, pkt_sz, is_b
                ]
                f.write(','.join(map(str, feat + [lbl])) + '\n')

