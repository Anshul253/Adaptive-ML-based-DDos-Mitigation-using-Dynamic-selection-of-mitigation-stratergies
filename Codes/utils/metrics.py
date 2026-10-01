import os
import json
import csv

def compute_metrics(
    y_true,
    y_pred,
    legit_gen,
    legit_dropped,
    attack_gen,
    attack_served,
    total_bytes,
    duration_sec,
    rtt_ms,
    response_time_sec,
    weights=None
):
    """
    Computes all research evaluation metrics objectively without hardcoding fake values.
    """
    if weights is None:
        weights = {
            "legitimate_preservation": 0.40,
            "attack_suppression": 0.35,
            "latency_penalty": 0.15,
            "overhead_penalty": 0.10
        }

    # Classification Metrics
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)

    total_samples = len(y_true) if len(y_true) > 0 else 1
    accuracy = (tp + tn) / total_samples
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    # Traffic Metrics
    legit_loss_pct = (legit_dropped / legit_gen * 100.0) if legit_gen > 0 else 0.0
    legit_preservation_pct = max(0.0, 100.0 - legit_loss_pct)

    attack_served_pct = (attack_served / attack_gen * 100.0) if attack_gen > 0 else 0.0
    attack_suppression_pct = max(0.0, 100.0 - attack_served_pct)

    throughput_mbps = (total_bytes * 8) / (duration_sec * 1e6) if duration_sec > 0 else 0.0
    
    # Network Load Estimate (scaled relative to 100Mbps baseline capacity)
    max_capacity_bps = 100 * 1e6
    actual_bps = (total_bytes * 8) / duration_sec if duration_sec > 0 else 0.0
    network_load_pct = min(100.0, (actual_bps / max_capacity_bps) * 100.0)

    # Composite Score Calculation (0 - 100 scale)
    norm_latency = min(1.0, rtt_ms / 200.0) # max baseline 200ms
    norm_overhead = network_load_pct / 100.0

    composite_score = (
        weights["legitimate_preservation"] * legit_preservation_pct +
        weights["attack_suppression"] * attack_suppression_pct -
        weights["latency_penalty"] * (norm_latency * 100.0) -
        weights["overhead_penalty"] * (norm_overhead * 100.0)
    )
    composite_score = max(0.0, min(100.0, composite_score))

    return {
        "accuracy": round(accuracy * 100.0, 2),
        "precision": round(precision * 100.0, 2),
        "recall": round(recall * 100.0, 2),
        "f1_score": round(f1 * 100.0, 2),
        "attack_packets_served_percent": round(attack_served_pct, 2),
        "legitimate_packet_loss_percent": round(legit_loss_pct, 2),
        "network_load_percent": round(network_load_pct, 2),
        "avg_rtt_ms": round(rtt_ms, 2),
        "throughput_mbps": round(throughput_mbps, 2),
        "mitigation_response_time_sec": round(response_time_sec, 3),
        "composite_score": round(composite_score, 2),
        "legit_generated": legit_gen,
        "legit_dropped": legit_dropped,
        "attack_generated": attack_gen,
        "attack_served": attack_served
    }

def save_experiment_results(results_dict, output_dir='results', filename_prefix='exp'):
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, f"{filename_prefix}_results.json")
    with open(json_path, 'w') as f:
        json.dump(results_dict, f, indent=2)
    return json_path
