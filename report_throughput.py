#!/usr/bin/python
# coding: utf-8


# This is the command line interface to the JSON-RPC service for the services report_all_ports, report_port and report_switch_ports
# implemented in the server enforce_bandwodth_simple_switch
# if called with -a (for all) then report_all_ports is invoked
# if called with -s (for switch) then report_all_ports is invoked
# unless -p (ports) is also given, in which case report_port is called
#
# In every case, the output from the RPC call is simply printed as a python object, decoded from the JSON response


import json
import pyjsonrpc
import sys, getopt
from pprint import pprint

def __init__(self):
	http_client = None

# It is also possible to use the *method* name as *attribute* name.
#print http_client.call("report_port", 1, 3)

# Notifications send messages to the server, without response.
#http_client.notify("add", 3, 4)

def _decode_dict(data):
    rv = {}
    for key, value in data.iteritems():
        if isinstance(key, unicode):
            key = int(key)
        if isinstance(value, unicode):
            value = value.encode('ascii')
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value
    return rv

def main(argv):
	http_client = pyjsonrpc.HttpClient(url = "http://localhost:4000/jsonrpc")

	if http_client is None:
		print 'Could not connect to rcp server'
		sys.exit()

	usage = "\nusage: report_throughput.py <url> [options]\n\nOptions:\n-a\t\tall ports all switchs\n-s <switch_id>\tall ports on <switch_id>\n-p <port_no>\tport <port_no>. To be used with -s."

	al = False
	switch = None
	port = None				

	try:
		opts, args = getopt.getopt(argv,"has:p:",[])
	except getopt.GetoptError:
		print usage
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-a':
			al = True
		elif opt == '-s':
			switch = arg
		elif opt == '-p':
			port = arg
		else:
			print usage
			sys.exit(2)

	if al == True:
		pprint(http_client.call("report_all_ports"))
	elif switch is not None and port is not None:
		pprint(http_client.call("report_port", switch, port))
		#print json.loads(http_client.call("report_port", switch, port), object_hook=decode_dict)
	elif switch is not None:
		pprint(http_client.call("report_switch_ports", switch))
		# print json.loads(http_client.call("report_switch_ports", switch), object_hook=decode_dict)
	else:
		print usage

if __name__== "__main__":
	main(sys.argv[1:])
