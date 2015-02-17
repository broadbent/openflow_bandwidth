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
import pyjsonrpc

PATH = os.path.dirname(__file__)

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
        ports = []
        currentMaxDictionary={}
        currentLastDictionary={}
        currentSentTP=0
        currentRecievedTP=0

        # currentMaxDictionary and currentLastDictionary are just references to the applicable persistent dictionary slice
        if ev.msg.datapath.id not in self.MAX_TP_DICT:
            self.MAX_TP_DICT[ev.msg.datapath.id]={}
        currentMaxDictionary= self.MAX_TP_DICT[ev.msg.datapath.id]

        if ev.msg.datapath.id not in self.LAST_TP_DICT:
            self.LAST_TP_DICT[ev.msg.datapath.id]={}
        currentLastDictionary=self.LAST_TP_DICT[ev.msg.datapath.id]



        for stat in ev.msg.body:
        #    self.logger.info('PortStats: Port:%d Duration nsec: %s Duration sec:%s Sent bytes: %s Recieved bytes %s',stat.port_no, stat.duration_nsec, stat.duration_sec, stat.tx_bytes, stat.rx_bytes)

            #self.logger.info('------------Port:%d-------------',stat.port_no)

            if stat.port_no in currentLastDictionary:
                currentSentTP = stat.tx_bytes-(currentLastDictionary[stat.port_no])[0]
                currentRecievedTP = stat.rx_bytes-(currentLastDictionary[stat.port_no])[1]
                #print('Current sent bytes per second =', currentSentTP)
                #print('Current recieved bytes per second =', currentRecievedTP)

            currentLastDictionary[stat.port_no] = [stat.tx_bytes,stat.rx_bytes,stat.duration_nsec]


            if stat.port_no in currentMaxDictionary:
                #If SENT bytes is greater then save it as max
                if currentSentTP>currentMaxDictionary[stat.port_no][0]:
                    currentMaxDictionary[stat.port_no][0]=currentSentTP

                #If RECIEVED bytes is greater then save it as max
                if currentRecievedTP>currentMaxDictionary[stat.port_no][1]:
                    currentMaxDictionary[stat.port_no][1]=currentRecievedTP
            else:
                #else init current max
                currentMaxDictionary[stat.port_no]=[currentSentTP,currentRecievedTP]



            #Unused method left for reference
            ports.append('port_no=%d '
                         'rx_packets=%d tx_packets=%d '
                         'rx_bytes=%d tx_bytes=%d '
                         'rx_dropped=%d tx_dropped=%d '
                         'rx_errors=%d tx_errors=%d '
                         'rx_frame_err=%d rx_over_err=%d rx_crc_err=%d '
                         'collisions=%d duration_sec=%d duration_nsec=%d' %
                         (stat.port_no,
                          stat.rx_packets, stat.tx_packets,
                          stat.rx_bytes, stat.tx_bytes,
                          stat.rx_dropped, stat.tx_dropped,
                          stat.rx_errors, stat.tx_errors,
                          stat.rx_frame_err, stat.rx_over_err,
                          stat.rx_crc_err, stat.collisions,
                          stat.duration_sec, stat.duration_nsec))
        #print('MAX THROUGHPUT :',currentMaxDictionary)
        #print('MAX_TP_DICT: ', self.MAX_TP_DICT)
        #self.http_client.notify("add", ev.msg.datapath.id, currentMaxDictionary)
        #print currentMaxDictionary


#Added ryu apps for rest intergation
#app_manager.require_app('ryu.app.rest_topology')
#app_manager.require_app('ryu.app.ws_topology')
#app_manager.require_app('ryu.app.ofctl_rest')
#Ryu gui app works with little success
#app_manager.require_app('ryu.app.gui_topology')
