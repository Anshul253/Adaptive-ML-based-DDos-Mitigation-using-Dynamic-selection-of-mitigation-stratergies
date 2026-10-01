import time

class DynamicBlockingStrategy:
    """
    Dynamic Blocking Mitigation Strategy.
    Installs OpenFlow flow rules with empty action set (DROP) for high-confidence attack flows.
    """
    def __init__(self, priority=100, drop_duration_sec=120):
        self.priority = priority
        self.drop_duration_sec = drop_duration_sec

    def apply(self, datapath, match_fields, logger=None):
        start_t = time.time()
        if datapath is not None:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            # Construct OpenFlow match
            match = parser.OFPMatch(**match_fields)
            actions = [] # Empty actions array = DROP
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=self.priority,
                hard_timeout=self.drop_duration_sec,
                match=match,
                instructions=inst
            )
            datapath.send_msg(mod)
            if logger:
                logger.info(f"[DYNAMIC BLOCKING] Flow mod sent to DPID {datapath.id}: match={match_fields} (DROP)")
        
        exec_time = time.time() - start_t
        return {
            "strategy": "DYNAMIC_BLOCKING",
            "applied": True,
            "match_fields": match_fields,
            "response_time_sec": exec_time
        }
