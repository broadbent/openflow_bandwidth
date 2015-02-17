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

	def run(self, num, max_throughput, add_meter_port, add_meter_service):
		http_server = pyjsonrpc.ThreadingHttpServer(server_address = ('localhost', 4000),RequestHandlerClass = RequestHandler)
		http_server.add_meter_port = add_meter_port
		http_server.add_meter_service = add_meter_service
		http_server.max_throughput = max_throughput
		http_server.serve_forever()

class RequestHandler(pyjsonrpc.HttpRequestHandler):
	@pyjsonrpc.rpcmethod
	def report_port(self, switch, port):
                print "report_port(switch=%s, port=%s)" % ( switch , port )
		# return json.dumps(self.server.max_throughput[switch.encode('ascii')][int(port)])
                if  int(switch) in self.server.max_throughput:
                    if int(port) in self.server.max_throughput[int(switch)]:
                        print "port reference OK"
                        reply = self.server.max_throughput[int(switch)][int(port)]
                        print reply
                        return reply
                    else:
                        print "invalid port reference"
                        return {}
                else:
                    print "invalid switch reference"
                    return {}

	@pyjsonrpc.rpcmethod
	def report_switch_ports(self, switch):
                print "report_switch_ports(switch=%s)" % switch
                # pprint(self.server.max_throughput)
                # print "keys: ", self.server.max_throughput.keys()
                # print switch, switch.encode('ascii')
                if  int(switch) in self.server.max_throughput:
                    # print "switch reference OK"
                    reply = self.server.max_throughput[int(switch)]
                    # print reply
                    return reply
                else:
                    print "invalid switch reference"
                    return {}
		# return self.server.max_throughput[switch.encode('ascii')]
		# return json.dumps(self.server.max_throughput[switch.encode('ascii')])

	@pyjsonrpc.rpcmethod
	def report_all_ports(self):
                print "report_all_ports()"
		return self.server.max_throughput

	@pyjsonrpc.rpcmethod
	def reset_port(self, switch, port):
		self.server.max_throughput[switch.encode('ascii')][int(port)] = [0,0]

	@pyjsonrpc.rpcmethod
	def reset_switch_port(self, switch):
		self.server.max_throughput[switch.encode('ascii')] = {}

	@pyjsonrpc.rpcmethod
	def enforce_port_outbound(self, switch, port, speed):
		self.server.add_meter_port(switch.encode('ascii'), int(port), int(speed))

	@pyjsonrpc.rpcmethod
	def enforce_service(self, switch, src, dst, speed):
		self.server.add_meter_service(switch.encode('ascii'), src.encode('ascii'), dst.encode('ascii'), int(speed))












