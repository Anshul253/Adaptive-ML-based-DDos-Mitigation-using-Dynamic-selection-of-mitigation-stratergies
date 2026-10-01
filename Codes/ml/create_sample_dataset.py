import numpy as np
import pandas as pd
import time

def generate_sample_flowstats(num_benign=1000, num_ddos=1000, output_path='FlowStatsfile.csv'):
    np.random.seed(42)
    records = []
    
    start_time = time.time()
    
    # Generate Benign Flows (label = 0)
    for i in range(num_benign):
        ts = start_time + i * 0.5
        dp_id = 1
        src_host = np.random.randint(1, 10)
        dst_host = np.random.randint(10, 20)
        ip_src = f"10.0.0.{src_host}"
        ip_dst = f"10.0.0.{dst_host}"
        proto = np.random.choice([6, 17, 1]) # TCP, UDP, ICMP
        
        if proto == 1:
            tp_src, tp_dst = 0, 0
            icmp_code, icmp_type = 0, 8
        elif proto == 6:
            tp_src = np.random.randint(1024, 65535)
            tp_dst = 80
            icmp_code, icmp_type = -1, -1
        else:
            tp_src = np.random.randint(1024, 65535)
            tp_dst = 53
            icmp_code, icmp_type = -1, -1
            
        flow_id = f"{ip_src}{tp_src}{ip_dst}{tp_dst}{proto}"
        
        dur_sec = np.random.randint(5, 120)
        dur_nsec = np.random.randint(1000000, 999999999)
        idle_timeout = 0
        hard_timeout = 0
        flags = 0
        
        pkt_cnt = np.random.randint(10, 150)
        byte_cnt = pkt_cnt * np.random.randint(64, 1500)
        
        pkt_per_sec = pkt_cnt / max(dur_sec, 1)
        pkt_per_nsec = pkt_cnt / dur_nsec
        byte_per_sec = byte_cnt / max(dur_sec, 1)
        byte_per_nsec = byte_cnt / dur_nsec
        
        label = 0
        records.append([
            ts, dp_id, flow_id, ip_src, tp_src, ip_dst, tp_dst, proto,
            icmp_code, icmp_type, dur_sec, dur_nsec, idle_timeout, hard_timeout,
            flags, pkt_cnt, byte_cnt, pkt_per_sec, pkt_per_nsec, byte_per_sec, byte_per_nsec, label
        ])

    # Generate DDoS Attack Flows (label = 1)
    for i in range(num_ddos):
        ts = start_time + num_benign * 0.5 + i * 0.1
        dp_id = 1
        src_host = np.random.randint(50, 250)
        dst_host = 1 # Target victim host
        ip_src = f"10.0.0.{src_host}"
        ip_dst = f"10.0.0.{dst_host}"
        proto = np.random.choice([6, 17, 1])
        
        if proto == 1:
            tp_src, tp_dst = 0, 0
            icmp_code, icmp_type = 0, 8
        elif proto == 6:
            tp_src = np.random.randint(1024, 65535)
            tp_dst = 80
            icmp_code, icmp_type = -1, -1
        else:
            tp_src = np.random.randint(1024, 65535)
            tp_dst = 80
            icmp_code, icmp_type = -1, -1
            
        flow_id = f"{ip_src}{tp_src}{ip_dst}{tp_dst}{proto}"
        
        dur_sec = np.random.randint(1, 10)
        dur_nsec = np.random.randint(100000, 9999999)
        idle_timeout = 0
        hard_timeout = 0
        flags = 0
        
        pkt_cnt = np.random.randint(5000, 50000)
        byte_cnt = pkt_cnt * np.random.randint(64, 500)
        
        pkt_per_sec = pkt_cnt / max(dur_sec, 1)
        pkt_per_nsec = pkt_cnt / dur_nsec
        byte_per_sec = byte_cnt / max(dur_sec, 1)
        byte_per_nsec = byte_cnt / dur_nsec
        
        label = 1
        records.append([
            ts, dp_id, flow_id, ip_src, tp_src, ip_dst, tp_dst, proto,
            icmp_code, icmp_type, dur_sec, dur_nsec, idle_timeout, hard_timeout,
            flags, pkt_cnt, byte_cnt, pkt_per_sec, pkt_per_nsec, byte_per_sec, byte_per_nsec, label
        ])

    columns = [
        'timestamp','datapath_id','flow_id','ip_src','tp_src','ip_dst','tp_dst','ip_proto',
        'icmp_code','icmp_type','flow_duration_sec','flow_duration_nsec','idle_timeout','hard_timeout',
        'flags','packet_count','byte_count','packet_count_per_second','packet_count_per_nsecond',
        'byte_count_per_second','byte_count_per_nsecond','label'
    ]

    df = pd.DataFrame(records, columns=columns)
    df.to_csv(output_path, index=False)
    print(f"Dataset successfully created at {output_path} with {len(df)} records ({num_benign} benign, {num_ddos} DDoS).")

if __name__ == '__main__':
    generate_sample_flowstats(1000, 1000, 'e:/CNS/DDoS-Attack-Detection-and-Mitigation/FlowStatsfile.csv')
    generate_sample_flowstats(1000, 1000, 'e:/CNS/DDoS-Attack-Detection-and-Mitigation/Codes/ml/FlowStatsfile.csv')
    generate_sample_flowstats(1000, 1000, 'e:/CNS/DDoS-Attack-Detection-and-Mitigation/Codes/controller/FlowStatsfile.csv')
