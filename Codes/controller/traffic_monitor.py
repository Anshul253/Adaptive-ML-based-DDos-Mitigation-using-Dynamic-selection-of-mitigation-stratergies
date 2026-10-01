import time

class TrafficMonitor:
    """
    Real-time SDN Traffic and Network Load Monitor.
    Tracks packet rates, byte rates, link utilization %, and latency estimates.
    """
    def __init__(self, capacity_mbps=100.0):
        self.capacity_bps = capacity_mbps * 1e6
        self.reset()

    def reset(self):
        self.last_timestamp = time.time()
        self.total_packets = 0
        self.total_bytes = 0
        self.legit_packets_gen = 0
        self.legit_packets_dropped = 0
        self.attack_packets_gen = 0
        self.attack_packets_served = 0
        self.active_flows = 0

    def update_telemetry(self, packet_count, byte_count, active_flows=1, is_attack=False, is_dropped=False):
        self.total_packets += packet_count
        self.total_bytes += byte_count
        self.active_flows = active_flows

        if is_attack:
            self.attack_packets_gen += packet_count
            if not is_dropped:
                self.attack_packets_served += packet_count
        else:
            self.legit_packets_gen += packet_count
            if is_dropped:
                self.legit_packets_dropped += packet_count

    def get_network_stats(self):
        now = time.time()
        duration = max(0.1, now - self.last_timestamp)
        
        pps = self.total_packets / duration
        bps = (self.total_bytes * 8) / duration
        network_load_percent = min(100.0, (bps / self.capacity_bps) * 100.0)
        
        # Estimate proxy RTT delay based on congestion level
        # Base RTT: 5ms, under congestion up to +150ms
        estimated_rtt_ms = 5.0 + (network_load_percent / 100.0) ** 2 * 145.0

        return {
            "duration_sec": duration,
            "packet_rate_pps": pps,
            "byte_rate_bps": bps,
            "network_load_percent": network_load_percent,
            "estimated_rtt_ms": estimated_rtt_ms,
            "active_flows": self.active_flows,
            "legit_gen": self.legit_packets_gen,
            "legit_dropped": self.legit_packets_dropped,
            "attack_gen": self.attack_packets_gen,
            "attack_served": self.attack_packets_served
        }
