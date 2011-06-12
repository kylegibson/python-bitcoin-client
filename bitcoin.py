#!/usr/bin/env python

#import readline
import urllib2
import asyncore
import asynchat
import socket 
import signal
import logging
import sys
import struct
import base58
import random
import time

import irc
import net
import context

LOGFILE = "node.log"
LOGLEVEL = logging.DEBUG

def config_logging(args):
	stream = sys.stdout
	logging.basicConfig(stream=stream,
		level=logging.DEBUG,
		format="[%s]" % args[0] + ' %(asctime)s - %(levelname)s - %(message)s'
	)

def get_seed_nodes(hosts):
	nodes = []
	for host in hosts:
		ips = socket.gethostbyname_ex(host)[2]	
		nodes.extend(ips)
	return nodes

def get_local_address(url):
	data = urllib2.urlopen(url).read()
	i = data.find(" ", data.find("Address:"))
	j = data.find("<", i)
	return data[i+1:j]

def signal_handler(a, b):
	thread.interrupt_main()

def main(args):
	signal.signal(signal.SIGTERM, signal_handler)
	signal.signal(signal.SIGQUIT, signal_handler)
	config_logging(args)
	nonce = random.getrandbits(64)
	logging.debug("initializing %s", nonce)
	config = {
		"boot" : time.time(),
		"version" : 32100,
		"network" : 0xD9B4BEF9,
		"services" : 0,
		"local_address" : None,
		"nonce" : nonce,
		"local_port" : 8333,
		"default_port" : 8333,
		"irc" : ("92.243.23.21",6667),
		"genesis_hash" : 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f,
	}
	data = {
		"nodes" : {},
		"blocks" : []
	}

	ctx = context.Context(config, data)

	if config.get("irc", None) is not None:
		seeder = irc.BIRCSeeder(ctx)
	else:
		config["external_ip"] = get_external_ip("http://91.198.22.70")
		nodes = get_seed_nodes(["bitseed.xf2.org", "bitseed.bitcoin.org.uk"])
		for node in nodes:
			data["nodes"][(node, config["default_port"])] = {}

	#net.BConnection(("::ffff:127.0.0.1", 8333), ctx) 
	try: 
		while True:
			asyncore.loop(timeout=10,count=1)
			logging.debug("loop %s", len(ctx.data["nodes"]))
			time.sleep(0.01)
	except KeyboardInterrupt:
		logging.debug("received interrupt signal, stopping")
	logging.debug("exiting")

if __name__ == '__main__':
	main(sys.argv)
