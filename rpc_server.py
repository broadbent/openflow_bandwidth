# coding: utf-8
#
import pyjsonrpc
import json

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
		return json.dumps(self.server.max_throughput[switch.encode('ascii')][int(port)])

	@pyjsonrpc.rpcmethod
	def report_switch_ports(self, switch):
		return json.dumps(self.server.max_throughput[switch.encode('ascii')])

	@pyjsonrpc.rpcmethod
	def report_all_ports(self):
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












