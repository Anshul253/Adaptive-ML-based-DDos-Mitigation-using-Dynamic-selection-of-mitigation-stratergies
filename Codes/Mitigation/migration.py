import time

class ControllerMigrationStrategy:
    """
    Controller Migration / Safe Inspection Proxy Mitigation Strategy.
    Redirects suspicious or high-interest flows to a safe inspection proxy port / controller mirror
    to prevent target link overload while performing deep packet inspection.
    """
    def __init__(self, inspection_port=99, priority=90):
        self.inspection_port = inspection_port
        self.priority = priority

    def apply(self, datapath, match_fields, logger=None):
        start_t = time.time()
        if datapath is not None:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            match = parser.OFPMatch(**match_fields)
            # Action: Output to inspection proxy port & controller for safe monitoring
            actions = [
                parser.OFPActionOutput(self.inspection_port),
                parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
            ]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=self.priority,
                idle_timeout=45,
                match=match,
                instructions=inst
            )
            try:
                datapath.send_msg(mod)
            except Exception as e:
                if logger:
                    logger.warning(f"[SAFE INSPECTION] FlowMod exception: {e}")

            if logger:
                logger.info(f"[SAFE INSPECTION / PROXY] Redirected match={match_fields} to inspection port {self.inspection_port}")

        exec_time = time.time() - start_t
        return {
            "strategy": "CONTROLLER_MIGRATION",
            "applied": True,
            "inspection_port": self.inspection_port,
            "match_fields": match_fields,
            "response_time_sec": exec_time
        }
