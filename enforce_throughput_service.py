#!/usr/bin/python
# coding: utf-8

import json
import pyjsonrpc
import sys, getopt

def __init__(self):
	http_client = None


def main(argv):

	http_client = pyjsonrpc.HttpClient(url = "http://localhost:4000/jsonrpc")

	if http_client is None:
		print 'Could not connect to JSON-RPC server'
		sys.exit(2)

	usage = "usage: python enforce_throughput_service.py <switch_id> <src> <dst> <speed B/s>"

	try:
		opts, args = getopt.getopt(argv,"h",[])
	except getopt.GetoptError:
		print usage
		sys.exit()

	switch = args[0]
	src = args[1]
	dst = args[2]
	speed = args[3]

	meter_id = http_client.call("enforce_service", switch, src, dst, speed)
        print "Meter ID is: %d" % meter_id

if __name__ == '__main__':
	main(sys.argv[1:])



