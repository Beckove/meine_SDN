# -*- coding: utf-8 -*-
from __future__ import print_function
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import numpy as np
import pandas as pd
import ipaddress
import joblib
import os
from datetime import datetime

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

import switch

class SimpleMonitorRF5(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(SimpleMonitorRF5, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        self.dm_csv_file = "dm.csv"
        if not os.path.exists(self.dm_csv_file):
            with open(self.dm_csv_file, "w") as f:
                header = (
                    "pkt_rate,pkt_delay,byte_rate,last_pkt,"
                    "fid,num_pkt,first_pkt,des_add,"
                    "pkt_in,duration_1,num_byte,duration_2,"
                    "pkt_out,pkt_sz,is_broadcast,label\n"
                )
                f.write(header)

        self.flow_training()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        smurf_match = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=1,
            ipv4_dst="10.0.0.255"
        )
        actions = [
            parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER),
            parser.OFPActionOutput(ofp.OFPP_FLOOD, 0)
        ]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp,
            priority=100,
            match=smurf_match,
            instructions=inst
        ))
        super(SimpleMonitorRF5, self).switch_features_handler(ev)

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

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()
        try:
            rf = joblib.load('rf_model.joblib')
            scaler = joblib.load('rf_scaler.joblib')
        except Exception as e:
            self.logger.error("Model loading failed: %s", e)
            return

        with open(self.dm_csv_file, 'a') as f:
            for stat in ev.msg.body:
                proto = stat.match.get('ip_proto')
                # only process ICMP(1), TCP(6), UDP(17)
                if proto not in (1, 6, 17):
                    continue
                pkt_cnt = stat.packet_count
                byte_cnt = stat.byte_count
                if pkt_cnt == 0:
                    continue
                duration_s = stat.duration_sec + stat.duration_nsec * 1e-9
                pkt_rate = pkt_cnt / duration_s if duration_s else 0
                pkt_delay = duration_s / pkt_cnt if pkt_cnt else 0
                byte_rate = byte_cnt / duration_s if duration_s else 0
                first_pkt = timestamp - duration_s
                last_pkt = timestamp
                src = stat.match.get('ipv4_src', '0.0.0.0')
                dst = stat.match.get('ipv4_dst', '0.0.0.0')
                flow_id = '%s-%s-%s-%s-%s' % (
                    src,
                    stat.match.get('tcp_src', stat.match.get('udp_src', 0)),
                    dst,
                    stat.match.get('tcp_dst', stat.match.get('udp_dst', 0)),
                    proto
                )
                fid = hash(flow_id)
                pkt_sz = byte_cnt / pkt_cnt if pkt_cnt else 0
                is_broadcast = 1 if dst.endswith('.255') else 0
                try:
                    des_add_int = int(ipaddress.IPv4Address(dst))
                except:
                    des_add_int = 0
                feat = [
                    pkt_rate, pkt_delay, byte_rate, last_pkt,
                    fid, pkt_cnt, first_pkt, dst,
                    pkt_cnt, duration_s, byte_cnt, duration_s,
                    pkt_cnt, pkt_sz, is_broadcast
                ]
                X = np.array([[
                    pkt_rate, pkt_delay, byte_rate, fid, pkt_cnt,
                    des_add_int, pkt_cnt, duration_s, byte_cnt,
                    pkt_cnt, pkt_sz, is_broadcast
                ]])
                try:
                    X_scaled = scaler.transform(X)
                    pred = rf.predict(X_scaled)[0]
                    label_map = {0:"benign",1:"smurf",2:"icmp_fl",3:"tcp_fl",4:"udp_fl"}
                    label_str = label_map.get(pred, "unknown")
                except Exception as e:
                    label_str = "error"
                    self.logger.error("Prediction failed: %s", e)
                row = feat + [label_str]
                f.write(','.join(map(str, row)) + '\n')

    def flow_training(self):
        self.logger.info("Flow Training ...")
        df = pd.read_csv('labeled_traffic.csv')
        feats, labels = [], []
        for row in df.values:
            line = ','.join(map(str, row))
            f, lbl = self.parse_line(line)
            feats.append(f)
            if lbl.isdigit():
                labels.append(int(lbl))
            else:
                mapping = {'benign':0,'smurf':1,'icmp_fl':2,'tcp_fl':3,'udp_fl':4}
                labels.append(mapping.get(lbl, -1))
        X = np.array(feats)
        y = np.array(labels)
        valid = y >= 0
        X, y = X[valid], y[valid]
        if X.shape[0] == 0:
            self.logger.error("No valid training samples found.")
            return
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        clf = RandomForestClassifier(n_estimators=10, criterion='entropy', random_state=0)
        clf.fit(X_scaled, y)
        joblib.dump(clf, 'rf_model.joblib')
        joblib.dump(scaler, 'rf_scaler.joblib')
        acc = (clf.predict(X_scaled) == y).mean() * 100
        self.logger.info("Labels 0-4 training accuracy: %.2f%%", acc)

    def parse_line(self, line):
        parts = line.strip().split(',')
        pkt_rate = float(parts[0])
        pkt_delay = float(parts[1])
        byte_rate = float(parts[2])
        fid = float(parts[4])
        num_pkt = float(parts[5])
        try:
            des_add_int = int(ipaddress.IPv4Address(parts[7]))
        except:
            des_add_int = 0
        pkt_in = float(parts[8])
        duration_1 = float(parts[9])
        num_byte = float(parts[10])
        pkt_out = float(parts[12])
        pkt_sz = float(parts[13])
        is_broadcast = 1 if parts[7].endswith('.255') else 0
        feats = [pkt_rate, pkt_delay, byte_rate, fid, num_pkt, # 16 col 
                 des_add_int, pkt_in, duration_1, num_byte,
                 pkt_out, pkt_sz, is_broadcast]
        label_str = parts[14] if len(parts) > 14 else ''
        return feats, label_str

