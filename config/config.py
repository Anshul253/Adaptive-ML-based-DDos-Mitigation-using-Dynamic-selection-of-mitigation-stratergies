import os
import json

CONFIG_FILE_PATH = os.path.join(os.path.dirname(__file__), 'adaptive_mitigation.json')

DEFAULT_CONFIG = {
    "thresholds": {
        "intensity": {
            "low_pps": 5000,
            "high_pps": 20000
        },
        "network_load": {
            "low_percent": 40.0,
            "high_percent": 75.0
        },
        "confidence": {
            "high_threshold": 0.85,
            "moderate_threshold": 0.60
        }
    },
    "rate_limiting": {
        "target_rate_kbps": 1000,
        "burst_size_kb": 100
    },
    "weights": {
        "legitimate_preservation": 0.40,
        "attack_suppression": 0.35,
        "latency_penalty": 0.15,
        "overhead_penalty": 0.10
    }
}

def load_config(config_path=None):
    path = config_path or CONFIG_FILE_PATH
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[Config] Error loading {path}: {e}. Falling back to default config.")
    return DEFAULT_CONFIG
