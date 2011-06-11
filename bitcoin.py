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

LOGFILE = "node.log"
LOGLEVEL = logging.DEBUG

class BConnection(asynchat.async_chat):
	def __init__(self, config, data, addr):
		asynchat.async_chat.__init__(self)
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		self.connect(addr)
		self.config = config
		self.data = data
		self.addr = addr
		self.incoming_data = ""
		self.remote = None
		self.set_incoming_format()
		self.push_version()
		self.incoming_handler = None
		self.incoming_handlers = {
			"version" : self.pop_version,
			"verack" : self.pop_verack,
		}

	def unpack_incoming_data(self):
		return struct.unpack(self.incoming_format, self.incoming_data)

	def set_incoming_format(self, format="<L12sL"):
		self.incoming_format = format
		size = struct.calcsize(format)
		self.set_terminator(size)

	def collect_incoming_data(self, data):
		self.incoming_data += data

	def handle_connect(self):
		logging.debug("connected to node %s", self.addr)

	def found_terminator(self):
		data = self.incoming_data
		logging.debug("received packet %s %s", len(data), data.encode("hex_codec"))
		if callable(self.incoming_handler):
			if not self.incoming_handler(data):
				self.incoming_data = ""
				self.set_incoming_format()
				self.incoming_handler = None
		else:
			network, command, paylen = self.unpack_incoming_data()
			if network != self.config["network"]:
				logging.error("received garbage from %s", connection.addr)
				self.close()
				return
			command = command.strip('\0')
			handler = self.incoming_handlers.get(command, None)
			if handler is None:
				logging.error("Unable to handle command %s (paylen=%s)", command, paylen)
				self.close()
				return
			logging.debug("received %s paylen %s", command, paylen)
			if paylen == 0:
				handler(None)
				self.set_incoming_format()
			else:
				self.incoming_handler = handler
				self.set_terminator(paylen)
			self.incoming_data = ""

	def pack_string(self, s):
		l = len(s)
		f = 0
		if l < 253:
			f = chr(l)
		elif l < 0x10000:
			f = chr(253) + struct.pack("<H", l)
		elif l < 0x100000000L:
			f = chr(254) + struct.pack("<I", l)
		else:
			f = chr(255) + struct.pack("<Q", l)
		return f + s

	def unpack_string(self, data):
		(f,) = struct.unpack("<B", data[0])
		data = data[1:]
		if f == 253:
			(l,) = struct.unpack("<H", data[:2])
			data = data[2:]
		elif f == 254:
			(l,) = struct.unpack("<I", data[:4])
			data = data[4:]
		elif f == 255:
			(l,) = struct.unpack("<Q", data[:8])
			data = data[8:]
		return data

	def pack_address(self, addr, port):
		data = struct.pack("<Q", self.config["services"])
		data += struct.pack("!10s2s4sH", "", "\xff" * 2, socket.inet_aton(addr), port)
		return data

	def push_packet(self, command, data=""):
		size = len(data)
		header = struct.pack("<L12sL", self.config["network"], command, size)
		if size > 0 and command not in ("version", "verack"):
			h = base58.sha_256(base58.sha_256(data))
			checksum = h[:4]
			header += struct.pack("<L", checksum)
		self.push(header)
		logging.debug("push_packet header: %s (%s) %s", command, len(header), header.encode("hex_codec"))
		if size > 0:
			self.push(data)
			logging.debug("packet: (%s) %s", size, data.encode("hex_codec"))

	def push_version(self):
		remote = self.pack_address(*self.addr)
		local = self.pack_address(self.config["local_address"], self.config["port"])
		data = struct.pack("<iQQ26s26sQxL", 
				self.config["version"], self.config["services"], 
				int(time.time()), remote, local, 
				self.config["nonce"], self.config["last_block"])
		self.push_packet("version", data)

	def pop_version(self, data):
		if self.remote:
			return
		version, services, timestamp, remote, local, nonce, last = struct.unpack("<iQQ26s26sQxL", data)
		logging.debug("pop_version %s %s %s %s %s", version, services, timestamp, nonce, last)
		if nonce == self.config["nonce"] and nonce > 1:
			logging.error("Connected to self, disconnection")
			self.close()
			return
		self.remote = {
			"version" : version,
			"services" : services,
			"timestamp" : timestamp,
			"nonce" : nonce,
			"last" : last
		}
		if version >= 209:
			self.push_verack()

	def push_verack(self):
		self.push_packet("verack")

	def pop_verack(self, data):
		logging.debug("pop_verack")
		self.push_getaddr()

	def push_getaddr(self):
		logging.debug("push_getaddr")
		self.push_packet("getaddr")

	#def push_getblocks(self):
	#	logging.debug("push_getblocks")
	#	data = struct.pack("",
	#		)
	#	self.push_packet("getdata", data)

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

	nodes = get_seed_nodes(["bitseed.xf2.org", "bitseed.bitcoin.org.uk"])

	config = {
		"version" : 32100,
		"network" : 0xD9B4BEF9,
		"services" : 0,
		"local_address" : get_local_address("http://checkip.dyndns.org"),
		"nonce" : nonce,
		"port" : 8333,
		"seed" : nodes,
		"last_block" : 0
	}

	data = {}

	logging.debug("seed nodes: %s", " ".join(nodes))
	BConnection(config, data, ("127.0.0.1", 8333)) 

	try: 
		while True:
			asyncore.loop(timeout=30,count=10)
			time.sleep(0.01)

	except KeyboardInterrupt:
		logging.debug("received interrupt signal, stopping")

	logging.debug("exiting")

if __name__ == '__main__':
	main(sys.argv)
