import os
import sys
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import switchm
from datetime import datetime

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, accuracy_score

# Add parent directory for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from Codes.controller.adaptive_mitigation import AdaptiveMitigationEngine
from Codes.controller.traffic_monitor import TrafficMonitor

class AdaptiveDDoSController(switchm.SimpleSwitch13):
    """
    Ryu SDN Controller Application supporting both:
    1. Baseline Mode: Traditional aggressive dynamic port blocking.
    2. Adaptive Mode: AI-Based Adaptive Mitigation Engine.
    """
    def __init__(self, *args, **kwargs):
        super(AdaptiveDDoSController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mode = kwargs.get('mode', 'adaptive')
        self.adaptive_engine = AdaptiveMitigationEngine(selector_type="rule")
        self.traffic_monitor = TrafficMonitor()
        
        self.monitor_thread = hub.spawn(self._monitor)

        start = datetime.now()
        self.flow_training()
        end = datetime.now()
        self.logger.info(f"Random Forest Training Completed in {end - start}")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)
            self.flow_predict()

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()
        file0 = open("PredictFlowStatsfile.csv", "w")
        file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
        
        body = ev.msg.body
        icmp_code = -1
        icmp_type = -1
        tp_src = 0
        tp_dst = 0

        for stat in sorted([flow for flow in body if (flow.priority == 1)], key=lambda flow:
            (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):
        
            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match['ip_proto']
            
            if stat.match['ip_proto'] == 1:
                icmp_code = stat.match['icmpv4_code']
                icmp_type = stat.match['icmpv4_type']
            elif stat.match['ip_proto'] == 6:
                tp_src = stat.match['tcp_src']
                tp_dst = stat.match['tcp_dst']
            elif stat.match['ip_proto'] == 17:
                tp_src = stat.match['udp_src']
                tp_dst = stat.match['udp_dst']

            flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)
          
            try:
                packet_count_per_second = stat.packet_count / stat.duration_sec
                packet_count_per_nsecond = stat.packet_count / stat.duration_nsec
            except Exception:
                packet_count_per_second = 0
                packet_count_per_nsecond = 0
                
            try:
                byte_count_per_second = stat.byte_count / stat.duration_sec
                byte_count_per_nsecond = stat.byte_count / stat.duration_nsec
            except Exception:
                byte_count_per_second = 0
                byte_count_per_nsecond = 0
                
            file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                        stat.match['ip_proto'], icmp_code, icmp_type,
                        stat.duration_sec, stat.duration_nsec,
                        stat.idle_timeout, stat.hard_timeout,
                        stat.flags, stat.packet_count, stat.byte_count,
                        packet_count_per_second, packet_count_per_nsecond,
                        byte_count_per_second, byte_count_per_nsecond))
            
        file0.close()

    def flow_training(self):
        self.logger.info("Training Baseline Random Forest DDoS Classifier...")
        dataset_path = 'FlowStatsfile.csv'
        if not os.path.exists(dataset_path):
            dataset_path = os.path.join(os.path.dirname(__file__), '../ml/FlowStatsfile.csv')

        flow_dataset = pd.read_csv(dataset_path)
        flow_dataset.iloc[:, 2] = flow_dataset.iloc[:, 2].astype(str).str.replace('.', '')
        flow_dataset.iloc[:, 3] = flow_dataset.iloc[:, 3].astype(str).str.replace('.', '')
        flow_dataset.iloc[:, 5] = flow_dataset.iloc[:, 5].astype(str).str.replace('.', '')

        X_flow = flow_dataset.iloc[:, :-1].values.astype('float64')
        y_flow = flow_dataset.iloc[:, -1].values

        X_train, X_test, y_train, y_test = train_test_split(X_flow, y_flow, test_size=0.25, random_state=0)
        classifier = RandomForestClassifier(n_estimators=10, criterion="entropy", random_state=0)
        self.flow_model = classifier.fit(X_train, y_train)

        y_pred = self.flow_model.predict(X_test)
        cm = confusion_matrix(y_test, y_pred)
        acc = accuracy_score(y_test, y_pred)
        self.logger.info(f"Model Confusion Matrix:\n{cm}\nAccuracy: {acc*100:.2f}%")

    def flow_predict(self):
        try:
            if not os.path.exists('PredictFlowStatsfile.csv'):
                return

            predict_df = pd.read_csv('PredictFlowStatsfile.csv')
            if len(predict_df) == 0:
                return

            predict_df_clean = predict_df.copy()
            predict_df_clean.iloc[:, 2] = predict_df_clean.iloc[:, 2].astype(str).str.replace('.', '')
            predict_df_clean.iloc[:, 3] = predict_df_clean.iloc[:, 3].astype(str).str.replace('.', '')
            predict_df_clean.iloc[:, 5] = predict_df_clean.iloc[:, 5].astype(str).str.replace('.', '')

            X_predict = predict_df_clean.iloc[:, :].values.astype('float64')
            y_pred = self.flow_model.predict(X_predict)
            probs = self.flow_model.predict_proba(X_predict)

            legitimate_count = sum(1 for label in y_pred if label == 0)
            ddos_count = sum(1 for label in y_pred if label == 1)
            total_flows = len(y_pred)

            legit_ratio = (legitimate_count / total_flows) * 100.0 if total_flows > 0 else 100.0
            
            # Aggregate Telemetry
            total_pps = predict_df['packet_count_per_second'].sum()
            total_bps = predict_df['byte_count_per_second'].sum()
            net_stats = self.traffic_monitor.get_network_stats()

            for idx, label in enumerate(y_pred):
                confidence = float(probs[idx][label])
                flow_row = predict_df.iloc[idx]
                dp_id = int(flow_row['datapath_id'])
                datapath = self.datapaths.get(dp_id)

                match_fields = {
                    'eth_type': 0x0800,
                    'ipv4_src': str(flow_row['ip_src']),
                    'ipv4_dst': str(flow_row['ip_dst']),
                    'ip_proto': int(flow_row['ip_proto'])
                }

                telemetry_data = {
                    "prediction_label": label,
                    "confidence": confidence,
                    "packet_rate": float(flow_row['packet_count_per_second']),
                    "network_load": net_stats['network_load_percent'],
                    "legitimate_traffic_rate": total_pps * (legit_ratio / 100.0)
                }

                if self.mode == "baseline":
                    if legit_ratio <= 80.0 and label == 1:
                        self.logger.info("[BASELINE MODE] DDoS attack detected. Applying fixed aggressive port blocking.")
                        in_port = 1
                        self.block_port(datapath, in_port)
                else: # Adaptive Mode
                    self.adaptive_engine.evaluate_and_mitigate(datapath, match_fields, telemetry_data, verbose=True)

        except Exception as e:
            self.logger.error(f"Error in flow_predict: {e}")