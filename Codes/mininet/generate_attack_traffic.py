import sys
import time

SEVERITY_RATES = {
    "low": {"pps": 2500, "hping_opts": "-i u400 --flood"},
    "medium": {"pps": 10000, "hping_opts": "-i u100 --flood"},
    "high": {"pps": 35000, "hping_opts": "--flood"}
}

def run_attack_simulation(attack_type="udp", severity="medium", target_ip="10.0.0.1", duration_sec=10, net=None):
    """
    Generates DDoS attack traffic (UDP, TCP SYN, ICMP flood) at controlled severity levels.
    """
    attack_type = attack_type.lower()
    severity = severity.lower()
    sev_info = SEVERITY_RATES.get(severity, SEVERITY_RATES["medium"])
    target_pps = sev_info["pps"]
    
    flag = "-2" if attack_type == "udp" else ("-S" if attack_type in ["syn", "tcp"] else "-1")
    
    print(f"\n[ATTACK GENERATOR] Launching {attack_type.upper()} Flood ({severity.upper()} severity ~{target_pps:,.0f} pps) -> Target {target_ip} for {duration_sec}s")
    
    if net is not None:
        attackers = net.hosts[1:4] # Hosts h2, h3, h4 as attacker botnet
        for host in attackers:
            cmd = f"hping3 {flag} -V -d 120 -w 64 -p 80 --rand-source {sev_info['hping_opts']} {target_ip} &"
            host.cmd(cmd)
        time.sleep(duration_sec)
        for host in attackers:
            host.cmd("killall -9 hping3")
        print(f"[ATTACK GENERATOR] Terminated attack flood.")
    else:
        # Simulation mode for benchmark execution
        total_packets = target_pps * duration_sec
        print(f"[SIMULATION MODE] Generated ~{total_packets:,.0f} attack packets ({attack_type.upper()}, severity={severity.upper()}).")

    return {
        "attack_type": attack_type,
        "severity": severity,
        "target_pps": target_pps,
        "target_ip": target_ip,
        "duration_sec": duration_sec
    }

if __name__ == '__main__':
    run_attack_simulation(attack_type="udp", severity="low", duration_sec=5)
