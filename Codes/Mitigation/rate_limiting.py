import time

class RateLimitingStrategy:
    """
    Rate Limiting Mitigation Strategy.
    Applies OpenFlow meters or rate queues to cap traffic throughput for moderate/suspicious flows.
    """
    def __init__(self, target_rate_kbps=1000, burst_size_kb=100, priority=80):
        self.target_rate_kbps = target_rate_kbps
        self.burst_size_kb = burst_size_kb
        self.priority = priority

    def apply(self, datapath, match_fields, logger=None):
        start_t = time.time()
        if datapath is not None:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            # Construct OpenFlow meter mod if supported, or queue action
            meter_id = 1
            bands = [parser.OFPMeterBandDrop(rate=self.target_rate_kbps, burst_size=self.burst_size_kb)]
            req = parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_ADD,
                                     flags=ofproto.OFPMF_KBPS | ofproto.OFPMF_BURST,
                                     meter_id=meter_id, bands=bands)
            try:
                datapath.send_msg(req)
            except Exception as e:
                if logger:
                    logger.warning(f"[RATE LIMITING] Meter creation fallback: {e}")

            match = parser.OFPMatch(**match_fields)
            inst = [parser.OFPInstructionMeter(meter_id)]
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=self.priority,
                idle_timeout=60,
                match=match,
                instructions=inst
            )
            try:
                datapath.send_msg(mod)
            except Exception as e:
                if logger:
                    logger.warning(f"[RATE LIMITING] FlowMod fallback: {e}")

            if logger:
                logger.info(f"[RATE LIMITING] Applied rate cap ({self.target_rate_kbps} kbps) for match={match_fields}")

        exec_time = time.time() - start_t
        return {
            "strategy": "RATE_LIMITING",
            "applied": True,
            "target_rate_kbps": self.target_rate_kbps,
            "match_fields": match_fields,
            "response_time_sec": exec_time
        }
