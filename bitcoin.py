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

CLIENT_ONLY = True

MAGIC = {
	"main" : 0xD9B4BEF9,
	"test" : 0xDAB5BFFA
}

DEFAULT_PORT = 8333
NODE_NETWORK = 1 << 0

LOCAL_ADDRESS = None

LOCAL_NONCE = random.getrandbits(64)

VERSION = 32100

LAST_BLOCK = 0
GENESIS_BLOCK_HASH = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f

DNS_SEED_ADDRESS = ["bitseed.xf2.org", "bitseed.bitcoin.org.uk"]
LOGFILE = "node.log"
LOGLEVEL =  logging.DEBUG

LOCAL_SERVICES = 0
if not CLIENT_ONLY:
	LOCAL_SERVICES += NODE_NETWORK

class BConnection(asynchat.async_chat):
	def __init__(self, network, services, addr):
		asynchat.async_chat.__init__(self)
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		self.connect(addr)
		self.addr = addr
		self.network = network
		self.services = services
		self.incoming_data = ""
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
		data = struct.pack("<Q", self.services)
		data += struct.pack("!10s2s4sH", "", "\xff" * 2, socket.inet_aton(addr), port)
		return data

	def push_packet(self, command, data):
		header = struct.pack("<L12sL", self.network, command, len(data))
		if command != "version":
			h = base58.sha_256(base58.sha_256(data))
			checksum = h[:4]
			header += struct.pack("<L", checksum)
		self.push(header)
		logging.debug("header: %s (%s) %s", command, len(header), header.encode("hex_codec"))
		self.push(data)
		logging.debug("packet: (%s) %s", len(data), data.encode("hex_codec"))

	def push_version(self):
		remote = self.pack_address(*self.addr)
		local = self.pack_address(LOCAL_ADDRESS, DEFAULT_PORT)
		data = struct.pack("<iQQ26s26sQxL", VERSION, self.services, int(time.time()),
				remote, local, LOCAL_NONCE, LAST_BLOCK)
		self.push_packet("version", data)
	

	def handle_connect(self):
		logging.debug("connected to node %s", self.addr)

	def found_terminator(self):
		data = self.incoming_data
		#logging.debug("received packet %s %s", len(data), data.encode("hex_codec"))
		if callable(self.incoming_handler):
			if not self.incoming_handler(data):
				self.incoming_data = ""
				self.set_incoming_format()
				self.incoming_handler = None
		else:
			network, command, paylen = self.unpack_incoming_data()
			if network != self.network:
				logging.error("received garbage from %s", connection.addr)
				self.close()
				return
			command = command.strip('\0')
			handler = self.incoming_handlers.get(command, None)
			if handler is None:
				logging.error("Unable to handle command %s (paylen=%s)", command, paylen)
				self.close()
				return
			self.incoming_handler = handler
			logging.debug("received %s paylen %s", command, paylen)
			self.set_terminator(paylen)
			self.incoming_data = ""

	def pop_verack(self, data):
		if len(data) > 0:
			logging.error("received verack with len(payload) > 0")
		return

	def pop_version(self, data):
		version, services, timestamp, remote, local, nonce, last = struct.unpack("<iQQ26s26sQxL", data)
		logging.debug("%s %s %s %s %s", version, services, timestamp, nonce, last)
		self.remote = {
			"version" : version,
			"services" : services,
			"timestamp" : timestamp,
			"nonce" : nonce,
			"last" : last
		}

def config_logging(args):
	stream = sys.stdout
	logging.basicConfig(stream=stream,
		level=logging.DEBUG,
		format="[%s]" % args[0] + ' %(asctime)s - %(levelname)s - %(message)s'
	)

def get_seed_nodes():
	nodes = []
	for host in DNS_SEED_ADDRESS:
		ips = socket.gethostbyname_ex(host)[2]	
		nodes.extend(ips)
	return nodes

def get_local_address():
	global LOCAL_ADDRESS
	data = urllib2.urlopen("http://checkip.dyndns.org").read()
	i = data.find(" ", data.find("Address:"))
	j = data.find("<", i)
	LOCAL_ADDRESS = data[i+1:j]
	logging.debug("local address: %s", LOCAL_ADDRESS)

def signal_handler(a, b):
	thread.interrupt_main()

def main(args):
	signal.signal(signal.SIGTERM, signal_handler)
	signal.signal(signal.SIGQUIT, signal_handler)
	config_logging(args)

	logging.debug("initializing %s", LOCAL_NONCE)
	nodes = get_seed_nodes()
	logging.debug("seed nodes: %s", " ".join(nodes))

	get_local_address()

	BConnection(MAGIC["main"], LOCAL_SERVICES, ("127.0.0.1", DEFAULT_PORT)) 

	try: 
		while True:
			asyncore.loop(timeout=30,count=10)
			time.sleep(0.01)

	except KeyboardInterrupt:
		logging.debug("received interrupt signal, stopping")

	logging.debug("exiting")

if __name__ == '__main__':
	main(sys.argv)
