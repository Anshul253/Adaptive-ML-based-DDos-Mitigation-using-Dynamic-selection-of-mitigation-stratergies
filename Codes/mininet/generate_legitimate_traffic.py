import sys
import time
from random import choice, randrange

def run_legitimate_traffic_simulation(net=None, duration_sec=30, num_flows=50):
    """
    Generates legitimate background network traffic (ICMP ping, TCP iperf, UDP iperf, HTTP GET).
    Can be run directly inside Mininet environment or in simulation mode.
    """
    print(f"[LEGITIMATE TRAFFIC GENERATOR] Starting legitimate traffic simulation for {duration_sec}s...")
    
    if net is not None:
        hosts = net.hosts
        server = hosts[0] # h1
        server.cmd('python -m SimpleHTTPServer 80 &')
        server.cmd('iperf -s -p 5050 &')
        
        start_t = time.time()
        flows_sent = 0
        while time.time() - start_t < duration_sec:
            src = choice(hosts[1:])
            dst = choice(hosts)
            if src != dst:
                src.cmd(f"ping {dst.IP()} -c 2 &")
                src.cmd(f"iperf -p 5050 -c {server.IP()} -t 2 &")
                flows_sent += 1
            time.sleep(0.5)
        print(f"[LEGITIMATE TRAFFIC GENERATOR] Completed {flows_sent} legitimate flow bursts.")
        return {"flows_generated": flows_sent, "type": "Legitimate"}
    else:
        # Simulation mode for evaluation runner
        print(f"[SIMULATION MODE] Generated {num_flows} simulated legitimate background flows.")
        return {"flows_generated": num_flows, "type": "Legitimate (Simulated)"}

if __name__ == '__main__':
    run_legitimate_traffic_simulation(duration_sec=10)
