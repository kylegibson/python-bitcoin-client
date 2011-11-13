#!/usr/bin/env python

import signal
import logging
import sys
import random
import time
from optparse import OptionParser

import context

LOGFILE = "node.log"
LOGLEVEL = logging.DEBUG

def initialize_logging():
	stream = sys.stdout
	logging.basicConfig(stream=stream,
		level=logging.DEBUG,
		format="[%s]" % sys.argv[0] + ' %(asctime)s - %(levelname)s - %(message)s'
	)

def signal_handler(a, b):
	thread.interrupt_main()

def initialize_configuration():
	parser = OptionParser(version="1")
	parser.add_option('--test',  
			dest='test', action="store_true", default=False,
			help='use test network')
	parser.add_option('--nodes', 
			dest='nodes', default=[], metavar='ip:port,...',
			help='connect -only- to these nodes, do not use irc, dns, or anything else')
	parser.add_option('--add-nodes', 
			dest='add_nodes', default=[], metavar='ip:port,...',
			help='include these nodes in the connection pool')
	parser.add_option('--irc', 
			dest='irc', default='92.243.23.21:6667', metavar="92.243.23.21:6667",
			help='irc address, set to blank to disable')
	parser.add_option('--dns', 
			dest='dns', default='bitseed.xf2.org,bitseed.bitcoin.org.uk', metavar='bitseed.xf2.org,bitseed.bitcoin.org.uk', 
			help='dns seed hosts, set blank to disable')
	parser.add_option('--port', 
			dest='port', type='int', default=8333, metavar=8333,
			help='local port')
	parser.add_option('--bind-ip', 
			dest='bind_ip', default="0.0.0.0", metavar="0.0.0.0",
			help='ip address to bind to for multihomed servers')
	parser.add_option('--external-ip', 
			dest='external_ip', default=None, metavar="0.0.0.0",
			help='external ip to communicate to other nodes')
	parser.add_option('--maxconnections', 
			dest='maxconnections', type='int', default=10, metavar=10,
			help='ip address to bind to for multihomed servers')
	parser.add_option('--irc-timeout', 
			dest='irc_timeout', type='int', default=30, metavar=30,
			help='number of seconds to wait for irc to get external IP and some nodes to connect to (default 30 seconds)')

	(options, args) = parser.parse_args()

	genesis_hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	network = 0xD9B4BEF9
	if options.test:
		genesis_hash = "00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008"
		network = 0xDAB5BFFA

	if options.nodes:
		options.irc = ""
		options.dns = ""
		options.add_nodes = ""

	nodes = []
	for node in options.nodes.split(","):
		if not node:
			continue
		ip, port = node.split(":")
		nodes.append((ip, int(port)))

	for node in options.add_nodes.split(","):
		if not node:
			continue
		ip, port = node.split(":")
		nodes.append((ip, int(port)))

	irc = None
	if options.irc:
		irc_ip, irc_port = options.irc.split(":")
		irc = (irc_ip, int(irc_port))

	config = {
		"boot" : time.time(),
		"version" : 32100,
		"network" : network,
		"services" : 0,
		"nonce" : random.getrandbits(64),
		"maxconnections" : options.maxconnections,
		"default_port" : 8333,
		"listen_address" : options.bind_ip,
		"local_port" : options.port,
		"external_ip" : options.external_ip,
		"irc_timeout" : options.irc_timeout,
		"dns_seed" : options.dns.split(",") if options.dns else [],
		"genesis_hash" : genesis_hash.decode("hex_codec"),
		"event_loop_sleep" : 0.01,
		"event_loop_timeout" : 10,
		"nodes" : nodes,
		"irc" : irc,
	}
	return config

def main():
	signal.signal(signal.SIGTERM, signal_handler)
	signal.signal(signal.SIGQUIT, signal_handler)
	initialize_logging()
	ctx = context.Context(initialize_configuration())
	logging.debug("initializing")
	ctx.load_blocks()
	try: ctx.event_loop()
	except KeyboardInterrupt:
		logging.debug("received interrupt signal, stopping")
	logging.debug("exiting")

if __name__ == '__main__':
	main()
