# coding: utf-8
#
import pyjsonrpc
import json
from pprint import pprint

class rpc_server:
	def __init__(self):
		self._running = True

	def terminate(self):
		self._running = False

	def run(self, num, (port_rate,port_max,flow_rate,flow_max), add_meter_port, add_meter_service):
		http_server = pyjsonrpc.ThreadingHttpServer(server_address = ('localhost', 4000),RequestHandlerClass = RequestHandler)
		http_server.add_meter_port = add_meter_port
		http_server.add_meter_service = add_meter_service
		http_server.port_rate = port_rate
		http_server.port_max = port_max
		http_server.flow_rate = flow_rate
		http_server.flow_max = flow_max
		http_server.serve_forever()

class Error(Exception):
    pass

class RequestHandler(pyjsonrpc.HttpRequestHandler):
        def select_stats(self, flows_wanted, max_wanted):
	    return ( self.server.flow_max if flows_wanted else self.server.port_max) if max_wanted else (self.server.flow_rate if flows_wanted else self.server.port_rate)
        
	@pyjsonrpc.rpcmethod
	def report_port(self, flows_wanted,  max_wanted, switch, port):
                stats = self.select_stats(flows_wanted, max_wanted)
                if  int(switch) in stats:
                    if int(port) in stats[int(switch)]:
                        return stats[int(switch)][int(port)]
                    else:
                        print "invalid port/flow reference"
                        return {}
                else:
                    print "invalid switch reference"
                    return {}

	@pyjsonrpc.rpcmethod
	def report_switch_ports(self, flows_wanted, max_wanted,  switch):
                stats = self.select_stats(flows_wanted, max_wanted)
                if  int(switch) in stats:
                    return stats[int(switch)]
                else:
                    print "invalid switch reference"
                    return {}

	@pyjsonrpc.rpcmethod
	def report_all_ports(self, flows_wanted, max_wanted):
	    print ("self.select_stats(%r,%r)" % (flows_wanted, max_wanted))
            return self.select_stats(flows_wanted, max_wanted)

	@pyjsonrpc.rpcmethod
	def reset_port(self, switch, port):
		pass
                # self.server.max_throughput[switch.encode('ascii')][int(port)] = [0,0]

	@pyjsonrpc.rpcmethod
	def reset_switch_port(self, switch):
		pass
                # self.server.max_throughput[switch.encode('ascii')] = {}

	@pyjsonrpc.rpcmethod
	def enforce_port_outbound(self, switch, port, speed):
		self.server.add_meter_port(switch.encode('ascii'), int(port), int(speed))

	@pyjsonrpc.rpcmethod
	def enforce_service(self, switch, src, dst, speed):
		return self.server.add_meter_service(switch.encode('ascii'), src.encode('ascii'), dst.encode('ascii'), int(speed))
