#!/usr/bin/env python

#import readline
import urllib2
import asyncore
import socket 
import signal
import logging
import sys
import struct
import base58
import random
import time

from connection import Connection

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

#DNS_SEED_ADDRESS = ["bitseed.xf2.org", "bitseed.bitcoin.org.uk"]
DNS_SEED_ADDRESS = ["localhost"]
LOGFILE = "node.log"
LOGLEVEL =  logging.DEBUG

LOCAL_SERVICES = 0
if not CLIENT_ONLY:
	LOCAL_SERVICES += NODE_NETWORK


class BString:
	def __init__(self, s = None):
		self.string = s

	def pack(self, s = None):
		if not s:
			s = self.string
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

	def unpack(self, data):
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
		return f.read(l)

class BAddress:
	def __init__(self, services, ip, port):
		self.services = services
		self.ip = ip
		self.port = port
	
	def pack(self):
		r = struct.pack("<Q", self.services)
		r += struct.pack("!10s2s4sH", 
				"", "\xff" * 2, socket.inet_aton(self.ip), self.port)
		return r

class BPacketHeader:
	def __init__(self, network, packet):
		self.network = network
		self.packet = packet
		self.checksum = 0
	def response(self):
		return self
	def pack(self):
		payload = self.packet.pack()
		f = "<L12sL"
		parts = [self.network, self.packet.command, len(payload)]
		if self.packet.command != "version":
			f.append("L")
			h = base58.sha_256(base58.sha_256(payload))
			parts.append(h[:4])
		return struct.pack(f, *parts) + payload
	def unpack(self):
		pass

class BPacketVersion:
	def __init__(self, services, remote_address):
		self.command = "version"
		self.services = services
		self.remote_address = remote_address
	def pack(self):
		remote = BAddress(self.services, self.remote_address, DEFAULT_PORT).pack()
		local = BAddress(self.services, LOCAL_ADDRESS, DEFAULT_PORT).pack()
		return struct.pack("<iQQ26s26sQxL",
			VERSION, self.services, int(time.time()),
			remote, local, LOCAL_NONCE, LAST_BLOCK)
	def unpack(self):
		pass

class BConnection(Connection):
	def __init__(self, network, services, addr):
		Connection.__init__(self, addr)
		self.network = network
		self.services = services
		self.responses = []

	def push_expect(response):
		self.responses.append(response)

	def push_packet(self, packet):
		header = BPacketHeader(self.network, packet)
		data = header.pack()
		logging.debug("packet: %s (%s) %s", packet.command, len(data), data.encode("hex_codec"))
		self.push(data)
		self.push_expect(header.response())

	def handle_connect(self):
		logging.debug("connecting to node %s",self.addr)
		version = BPacketVersion(self.services, self.addr[0])
		self.push_packet(version)

	def handle_read(self):
		if not Connection.handle_read(self):
			return False

		if len(self.responses) == 0:
			logging.debug("No reponses expected, closing connection")
			self.close()
			return

		while response in self.responses[:]:
			result = response.consume(self)
			if not result:
				break
			self.responses.pop(0)

		#if len(self.rbuf) < self.wait_for_bytes:
		#	logging.debug("handle read: not enough bytes to decode response header")
		#	return

		#data = self.rbuf[:self.wait_for_bytes]
		#magic, command, paylen = struct.unpack(self.header_format, data)
		#if magic != self.network:
		#	logging.error("received magic version does not match configuration %s %s", magic.encode("hex_codec"), self.network.encode("hex_codec"))
		#	self.close()
		#	return

		#if len(self.rbuf) < self.wait_for_bytes + paylen:
		#	logging.debug("handle read: not enough bytes to decode response payload")
		#	return

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

	BConnection(MAGIC["main"], LOCAL_SERVICES, (nodes[0], DEFAULT_PORT)) 

	try: 
		while True:
			asyncore.loop(timeout=30,count=10)
			time.sleep(0.01)

	except KeyboardInterrupt:
		logging.debug("received interrupt signal, stopping")

	logging.debug("exiting")

if __name__ == '__main__':
	main(sys.argv)
