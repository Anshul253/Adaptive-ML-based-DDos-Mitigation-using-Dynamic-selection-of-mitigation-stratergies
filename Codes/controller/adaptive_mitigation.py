import os
import sys
import time

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from config.config import load_config
from Codes.utils.logger import log_explainability_decision
from Codes.Mitigation.blocking import DynamicBlockingStrategy
from Codes.Mitigation.rate_limiting import RateLimitingStrategy
from Codes.Mitigation.migration import ControllerMigrationStrategy

class BaseMitigationSelector:
    """Base interface for adaptive mitigation selectors."""
    def select_strategy(self, telemetry_data):
        raise NotImplementedError("Subclasses must implement select_strategy()")

class RuleBasedSelector(BaseMitigationSelector):
    """
    Deterministic & Explainable Adaptive Mitigation Decision Rule Engine.
    Dynamically selects mitigation strategy based on attack intensity, network congestion,
    classification confidence, and legitimate traffic preservation priorities.
    """
    def __init__(self, config=None):
        self.config = config or load_config()
        t = self.config.get("thresholds", {})
        self.low_pps = t.get("intensity", {}).get("low_pps", 5000)
        self.high_pps = t.get("intensity", {}).get("high_pps", 20000)
        self.low_load = t.get("network_load", {}).get("low_percent", 40.0)
        self.high_load = t.get("network_load", {}).get("high_percent", 75.0)
        self.high_conf = t.get("confidence", {}).get("high_threshold", 0.85)
        self.mod_conf = t.get("confidence", {}).get("moderate_threshold", 0.60)

    def select_strategy(self, telemetry_data):
        is_ddos = telemetry_data.get("prediction_label", 0) == 1
        confidence = telemetry_data.get("confidence", 1.0)
        packet_rate = telemetry_data.get("packet_rate", 0)
        network_load = telemetry_data.get("network_load", 0.0)
        legit_rate = telemetry_data.get("legitimate_traffic_rate", 0)

        if not is_ddos:
            return {
                "strategy": "NO_ACTION",
                "reason": "Traffic classified as normal flow. No mitigation action required.",
                "confidence": confidence
            }

        # Case 1: High Confidence & (High Intensity OR High Network Congestion) -> Dynamic Blocking
        if (confidence >= self.high_conf and (packet_rate >= self.high_pps or network_load >= self.high_load)) or (network_load >= 85.0 and confidence >= self.mod_conf):
            return {
                "strategy": "DYNAMIC_BLOCKING",
                "reason": f"High attack confidence ({confidence*100:.1f}%) with severe attack intensity ({packet_rate:,.0f} pps) / network load ({network_load:.1f}%). Immediate flow drop required.",
                "confidence": confidence
            }

        # Case 2: High Congestion or Medium Attack -> Safe Inspection / Controller Migration
        if network_load >= self.high_load or (packet_rate >= self.low_pps and network_load >= self.low_load):
            return {
                "strategy": "CONTROLLER_MIGRATION",
                "reason": f"High network load ({network_load:.1f}%) detected with medium flood ({packet_rate:,.0f} pps). Avoid rate limiting to prevent queue congestion; redirecting to safe proxy inspection.",
                "confidence": confidence
            }

        # Case 3: Low/Moderate Attack & Low Congestion -> Rate Limiting
        if packet_rate < self.high_pps and network_load < self.high_load:
            return {
                "strategy": "RATE_LIMITING",
                "reason": f"Moderate attack intensity ({packet_rate:,.0f} pps) with low network load ({network_load:.1f}%). Capping rate to preserve legitimate traffic.",
                "confidence": confidence
            }

        # Default Fallback -> Dynamic Blocking
        return {
            "strategy": "DYNAMIC_BLOCKING",
            "reason": "Fallback default mitigation due to detected attack state.",
            "confidence": confidence
        }

class MLSelector(BaseMitigationSelector):
    """
    ML-based Adaptive Decision Selector interface for future reinforcement learning / policy models.
    """
    def __init__(self, model_path=None):
        self.rule_fallback = RuleBasedSelector()

    def select_strategy(self, telemetry_data):
        # Placeholder for trained Policy ML Model, falling back cleanly to RuleBasedSelector
        return self.rule_fallback.select_strategy(telemetry_data)

class AdaptiveMitigationEngine:
    """
    Adaptive Mitigation Decision Engine.
    Executes dynamic strategy selection and dispatches execution to mitigation handlers.
    """
    def __init__(self, selector_type="rule", config=None):
        self.config = config or load_config()
        if selector_type == "ml":
            self.selector = MLSelector()
        else:
            self.selector = RuleBasedSelector(self.config)

        self.blocking_handler = DynamicBlockingStrategy()
        self.rate_limit_handler = RateLimitingStrategy(
            target_rate_kbps=self.config.get("rate_limiting", {}).get("target_rate_kbps", 1000)
        )
        self.migration_handler = ControllerMigrationStrategy()

    def evaluate_and_mitigate(self, datapath, match_fields, telemetry_data, verbose=True):
        start_t = time.time()
        
        # 1. Select Adaptive Strategy
        decision_info = self.selector.select_strategy(telemetry_data)
        strategy = decision_info["strategy"]
        reason = decision_info["reason"]
        confidence = decision_info["confidence"]

        if verbose:
            log_explainability_decision(
                prediction_label=telemetry_data.get("prediction_label", 0),
                confidence=confidence,
                packet_rate=telemetry_data.get("packet_rate", 0),
                network_load=telemetry_data.get("network_load", 0.0),
                leg_traffic_rate=telemetry_data.get("legitimate_traffic_rate", 0),
                decision=strategy,
                reason=reason
            )

        # 2. Execute Selected Strategy
        result = {"strategy": strategy, "reason": reason, "applied": False}
        if strategy == "DYNAMIC_BLOCKING":
            result.update(self.blocking_handler.apply(datapath, match_fields))
        elif strategy == "RATE_LIMITING":
            result.update(self.rate_limit_handler.apply(datapath, match_fields))
        elif strategy == "CONTROLLER_MIGRATION":
            result.update(self.migration_handler.apply(datapath, match_fields))
        else:
            result.update({"applied": False, "response_time_sec": time.time() - start_t})

        return result
