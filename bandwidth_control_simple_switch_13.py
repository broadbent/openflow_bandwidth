from webob.static import DirectoryApp
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager

from rpc_server import *
from SwitchPoll import *
from multiprocessing import Process

import os
from threading import *
from pprint import pprint
import pyjsonrpc
from collections import namedtuple

PATH = os.path.dirname(__file__)

StatRecord = namedtuple('StatRecord',['tx_packets','rx_packets','tx_bytes','rx_bytes'])
TimedStatRecord = namedtuple('TimedStatRecord',['tx_packets','rx_packets','tx_bytes','rx_bytes', 'duration_sec','duration_nsec'])

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.datapathdict = {}
        #init polling thread

        switchPoll = SwitchPoll()
        pollThread = Thread(target=switchPoll.run, args=(10,self.datapathdict))
        pollThread.start()
        print "Created polling threads"

        self.LAST_TP_DICT = {}
        self.MAX_TP_DICT = {}

        Thread(target=rpc_server().run, args=(1,self.MAX_TP_DICT,self.add_meter_port,self.add_meter_service)).start()
        #-- Attempt at activly testing the network --#
        #poutTask = PacketOutLoop()
        #pollingThread2=Thread(target=poutTask.run,args=(10,self.datapathdict))
        #pollingThread2.start()

        #Map for sw to meters to ports
        self.datapathID_to_meters = {}

        #Meter id for per flow based meters (Dont want port and flow meter ids conflicting)
        #starts at 53, hp
        # meter_id= 53
        self.datapathID_to_meter_ID= {}
	self.datapath_to_flows = {}


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 1, match, actions)


        #Add new switches for polling
        self.datapathdict[datapath.id]=datapath
	#	self.add_meter_service(datapath.id, "10.1.1.1", "10.1.1.2", 200)



    #Add flow modified to allow meters
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, meter=None, timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        print "The meter is :",meter
        if meter != None:
            print "Sending flow mod with meter instruction, meter :", meter
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),parser.OFPInstructionMeter(meter)]
        else:
            print "Not sending instruction"
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, hard_timeout=timeout,
                                    idle_timeout=timeout, table_id=100)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    hard_timeout=timeout, idle_timeout=timeout, table_id=100)
        datapath.send_msg(mod)

        #Edit this
    def add_meter_port(self, datapath_id, port_no, speed):
        print "ADDING METER TO PORT"

	datapath_id = int(datapath_id)
	
        if datapath_id not in self.datapathdict:
		"dont have dick"
		return -1
        datapath= self.datapathdict[datapath_id]
        

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser


	#METER ID's WILL DIRECTLY RELATE TO PORT NUMBERS
        #change meter with meter_id <port_no>, on switch <datapath>, to have a rate of <speed>
	print datapath_id
	
	if datapath_id in self.datapathID_to_meters:
        	port_to_meter= self.datapathID_to_meters[datapath_id]
	else:
		print "not in"
        bands=[]
        #set starting bit rate of meter
        dropband = parser.OFPMeterBandDrop(rate=int(speed), burst_size=0)
	bands.append(dropband)
        #Delete meter incase it already exists (other instructions pre installed will still work)
        request = parser.OFPMeterMod(datapath=datapath,command=ofproto.OFPMC_DELETE,flags=ofproto.OFPMF_KBPS,meter_id=int(port_no),bands=bands)
        datapath.send_msg(request)
        #Create meter
        request = parser.OFPMeterMod(datapath=datapath,command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS,meter_id=int(port_no),bands=bands)
        datapath.send_msg(request)
	print request
        #Prvent overwriting incase rule added before traffic seen
        port_to_meter[int(port_no)]=int(port_no)




        return 1

    def add_meter_service(self, datapath_id, src_addr, dst_addr, speed):
        print "ADDING METER FOR SERVICE"
        datapath_id=int(datapath_id)
	if datapath_id not in self.datapathdict:
            print "### Error: datapath_id not in self.datapathdict"
            return -1
        else:
            datapath= self.datapathdict[datapath_id]

	speed= int(speed)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
	

        if datapath_id in self.datapath_to_flows:
            flows = self.datapath_to_flows[datapath_id]
        else:
            flows = {}
            self.datapath_to_flows[datapath_id]=flows
       

	 #Check if meter id created for this switch
        if datapath_id in self.datapathID_to_meter_ID:
            meter_id = self.datapathID_to_meter_ID[datapath_id]
        else:
            meter_id=53
            self.datapathID_to_meter_ID[datapath_id]=meter_id



        #Check if the src and dst has already had a meter created for it
        if src_addr+dst_addr in flows:
            #flow already exists!
            #find out what that flow used for its meter_id
            meter_id = flows[src_addr+dst_addr]
        else:
            flows[src_addr+dst_addr]=meter_id


        #create meter with rate of <speed> and intall - NEED TO GIVE A METER ID HIGHER THAN MAX PORTS
        bands=[]
        #set starting bit rate of meter
        dropband = parser.OFPMeterBandDrop(rate=speed, burst_size=0)
        bands.append(dropband)

        #Delete meter incase it already exists (other instructions pre installed will still work)
        request = parser.OFPMeterMod(datapath=datapath,command=ofproto.OFPMC_DELETE,flags=ofproto.OFPMF_KBPS,meter_id=meter_id,bands=bands)
        datapath.send_msg(request)

        #Create meter
        request = parser.OFPMeterMod(datapath=datapath,command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS,meter_id=meter_id,bands=bands)
        datapath.send_msg(request)


        #create flow with <src> and <dst> - with a higher priority than normal switch behaviour -
        #action NORMAL && link to meter
        match = parser.OFPMatch(eth_type=0x800, ipv4_src=src_addr, ipv4_dst=dst_addr)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]


        self.add_flow(datapath, 100, match, actions, buffer_id=None, meter=meter_id, timeout=0)


        self.datapathID_to_meter_ID[datapath_id]=meter_id+1

        return 1

    def add_meter_flow(self, datapath_id, flow_id, speed):
        #add meter to an existing flow through normal switch behaviour
        #doens't need implemented yet!
        return 1


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
	print('DPID', dpid)
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        #get port to meter for this switch (mainly to see if meter already exists)
        #print self.datapathID_to_meters
	#check if switch already seen
	if dpid not in self.datapathID_to_meters:
		self.datapathID_to_meters[dpid]={}
	port_to_meter= self.datapathID_to_meters[dpid]


        #Create new meters
        #Check for flood, dont want to add meter for flood
        if out_port != ofproto.OFPP_FLOOD:
             print "NOT A FLOOD PACKET"
             if out_port in port_to_meter:
                     #if the meter already exists for THIS SWITCH set instruction to use
                     print "Meter already exists for this port"
             else:
                 #This controller not added meter before, need to create one for this port
                 print "NEW METER CREATED FOR :", out_port
                 bands=[]
                 #set starting bit rate of meter
                 dropband = parser.OFPMeterBandDrop(rate=1000000, burst_size=0)
                 bands.append(dropband)
                 #Delete meter first, it might already exist
                 request = parser.OFPMeterMod(datapath=datapath,command=ofproto.OFPMC_DELETE,flags=ofproto.OFPMF_KBPS,meter_id=out_port,bands=bands)
                 datapath.send_msg(request)
                 request = parser.OFPMeterMod(datapath=datapath,command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS,meter_id=out_port,bands=bands)
                 datapath.send_msg(request)
                 port_to_meter[out_port]=out_port




        #Standard smart switch continues
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 2, match, actions, msg.buffer_id, meter=out_port, timeout=60)
                return
            else:
                self.add_flow(datapath, 2, match, actions, meter=out_port, timeout=60)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    #handle stats replies
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):

        def _unpack(portStats):
            unpacked = {}
            for statsEntry in portStats:
                port = statsEntry.port_no
                if port != 4294967294: # this magic number is the 'local'port, which is not real....
                    unpacked[port] = TimedStatRecord (statsEntry.tx_packets, statsEntry.rx_packets, statsEntry.tx_bytes, statsEntry.rx_bytes, statsEntry.duration_sec, statsEntry.duration_nsec )
            return unpacked

        currentSentTP=0
        currentRecievedTP=0

        # pprint(ev.msg.datapath.id)
        # pprint(ev.msg.body)

        # currentMaxDictionary and currentLastDictionary are just references to the applicable persistent dictionary slice

        # on first entry for a switch just save the stats, initiliase the max counters to zero and exit
        if ev.msg.datapath.id not in self.LAST_TP_DICT:
            self.logger.info("port_stats_reply_handler - first entry for switch %d", ev.msg.datapath.id )
            self.LAST_TP_DICT[ev.msg.datapath.id] = _unpack(ev.msg.body)
            self.MAX_TP_DICT[ev.msg.datapath.id] = {}
            maxStats = self.MAX_TP_DICT[ev.msg.datapath.id]
            for statsEntry in ev.msg.body:
                if statsEntry.port_no != 4294967294: # this magic number is the 'local'port, which is not real....
                    maxStats[statsEntry.port_no] = StatRecord(0,0,0,0)

        # we have a previous stats record so it is now possible to calculate the delta
        else:
            self.logger.info("port_stats_reply_handler - repeat entry for switch %d", ev.msg.datapath.id )
            oldStats = self.LAST_TP_DICT[ev.msg.datapath.id]
            newStats = _unpack(ev.msg.body)
            # pprint(newStats)
            # save away this dataset for the next time around...
            self.LAST_TP_DICT[ev.msg.datapath.id] = newStats
            maxStats = self.MAX_TP_DICT[ev.msg.datapath.id]
            # calculate deltas for all of the cumulative fields (tx/rx_packets/bytes,duration_sec/nsec)
            # and also calculate new max values for all deltas
            delta = {}
            for port in newStats:

                if newStats[port].duration_nsec < oldStats[port].duration_nsec:
                    delta_sec = newStats[port].duration_sec - oldStats[port].duration_sec -1
                    delta_nsec = oldStats[port].duration_nsec - newStats[port].duration_nsec
                else:
                    delta_sec = newStats[port].duration_sec - oldStats[port].duration_sec
                    delta_nsec = newStats[port].duration_nsec - oldStats[port].duration_nsec

                delta[port] = TimedStatRecord (newStats[port].tx_packets - oldStats[port].tx_packets,
                                               newStats[port].rx_packets - oldStats[port].rx_packets,
                                               newStats[port].tx_bytes - oldStats[port].tx_bytes,
                                               newStats[port].rx_bytes - oldStats[port].rx_bytes,
                                               delta_sec,
                                               delta_nsec )

                maxStats[port] = StatRecord ( max(maxStats[port].tx_packets,delta[port].tx_packets),
                                              max(maxStats[port].rx_packets,delta[port].rx_packets),
                                              max(maxStats[port].tx_bytes,delta[port].tx_bytes),
                                              max(maxStats[port].rx_bytes,delta[port].rx_bytes) )

            print "oldStats"
            pprint(oldStats)
            print "newStats"
            pprint(newStats)
            print "delta"
            pprint(delta)
            print "maxStats"
            pprint(maxStats)
