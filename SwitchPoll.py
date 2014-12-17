from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
import time
from ryu.lib.packet import ethernet

class SwitchPoll():
    def __init__(self):
        self._running = True

    def terminate(self):
        self._running = False

    def send_port_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY)
        datapath.send_msg(req)

    def run(self, pollTime,datapathdict):
        while True:
            for the_key, datapath in datapathdict.iteritems():
                self.send_port_stats_request(datapath)
            time.sleep(pollTime)
