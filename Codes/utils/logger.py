import time

def log_explainability_decision(prediction_label, confidence, packet_rate, network_load, leg_traffic_rate, decision, reason):
    """
    Real-time CLI / Terminal Dashboard logger for Adaptive Decision Explainability.
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    border = "=" * 65
    print(f"\n{border}")
    print(f"       [ADAPTIVE DDoS DECISION ENGINE - {timestamp}]")
    print(f"{border}")
    print(f" Attack Status:       {'DETECTED DDoS' if prediction_label == 1 else 'NORMAL TRAFFIC'}")
    print(f" Confidence Score:    {confidence * 100:.1f}%")
    print(f" Packet Rate:         {packet_rate:,.0f} pps")
    print(f" Current Network Load: {network_load:.1f}%")
    print(f" Legitimate Traffic:  {leg_traffic_rate:,.0f} pps")
    print(f"-----------------------------------------------------------------")
    print(f" SELECTED STRATEGY:   [{decision}]")
    print(f" EXPLANATION REASON:  {reason}")
    print(f"{border}\n")

def print_cli_dashboard(metrics_dict, mode="ADAPTIVE"):
    """
    Displays real-time operational dashboard summary.
    """
    border = "=" * 65
    print(f"\n{border}")
    print(f"            [SDN DDoS MITIGATION DASHBOARD - {mode.upper()} MODE]")
    print(f"{border}")
    print(f" Attack Packets Served:     {metrics_dict.get('attack_packets_served_percent', 0.0):.2f}%")
    print(f" Legitimate Packet Loss:    {metrics_dict.get('legitimate_packet_loss_percent', 0.0):.2f}%")
    print(f" Network Congestion Load:   {metrics_dict.get('network_load_percent', 0.0):.2f}%")
    print(f" Avg RTT / Delay:           {metrics_dict.get('avg_rtt_ms', 0.0):.2f} ms")
    print(f" Throughput:                {metrics_dict.get('throughput_mbps', 0.0):.2f} Mbps")
    print(f" Mitigation Response Time:  {metrics_dict.get('mitigation_response_time_sec', 0.0):.3f} s")
    print(f" Composite Adaptive Score:  {metrics_dict.get('composite_score', 0.0):.2f} / 100")
    print(f"{border}\n")
