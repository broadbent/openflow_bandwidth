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

def main(argv):
	http_client = pyjsonrpc.HttpClient(url = "http://localhost:4000/jsonrpc")

	if http_client is None:
		print 'Could not connect to rcp server'
		sys.exit()

	usage = "\nusage: report_throughput.py <url> [options]\n"\
                "\nOptions:\n-a\t\tall ports all switchs\n"\
                "-s <switch_id>\tall ports on <switch_id>\n"\
                "-p <port_no>\tport <port_no>. To be used with -s.\n"\
                "-m request max stats not current stats\n"

	al = False
	max_wanted = False
	flows_wanted = False
	switch = None
	port = None				

	try:
		opts, args = getopt.getopt(argv,"fmas:p:",[])
	except getopt.GetoptError:
		print usage
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-f':
			flows_wanted = True
		elif opt == '-m':
			max_wanted = True
		elif opt == '-a':
			al = True
		elif opt == '-s':
			switch = arg
		elif opt == '-p':
			port = arg
		else:
			print usage
			sys.exit(2)

	if al == True:
		pprint(http_client.call("report_all_ports", flows_wanted, max_wanted))
	elif switch is not None and port is not None:
		pprint(http_client.call("report_port", flows_wanted,  max_wanted, switch, port))
	elif switch is not None:
		pprint(http_client.call("report_switch_ports", flows_wanted,  max_wanted, switch))
	else:
		print usage

if __name__== "__main__":
	main(sys.argv[1:])
