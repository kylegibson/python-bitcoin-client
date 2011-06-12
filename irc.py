import logging
import asynchat
import socket
import struct
import random

import base58

class BIRCSeeder(asynchat.async_chat):
	def __init__(self, addr):
		asynchat.async_chat.__init__(self)
		ip, port = addr.split(":")
		port = int(port)
		self.addr = (ip, port)
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		self.connect(self.addr)
		self.set_terminator("\r\n")
		self.reset_incoming_data()
		self.welcome()
		self.handlers = {
			"302" : self.recv_userhost,
		}

	def welcome(self):
		nick = "x%s" % random.getrandbits(32)
		self.push_nick(nick)
		self.push_crlf("USER %s 8 * : %s", nick, nick)
		self.push_crlf("USERHOST %s", nick)

	def push_crlf(self, msg, *args):
		msg += "\r\n"
		self.push(msg % args)

	def push_nick(self, nick):
		self.push_crlf("NICK %s", nick)

	def collect_incoming_data(self, data):
		self.incoming_data += data

	def reset_incoming_data(self):
		self.incoming_data = ""

	def handle_connect(self):
		logging.debug("connected to %s", self.addr)

	def found_terminator(self):
		logging.debug("received packet (%s) %s", len(self.incoming_data), self.incoming_data.strip())
		parts = self.incoming_data.split(" ", 2)
		handler = self.handlers.get(parts[1], None)
		if callable(handler):
			handler(parts[2])
		self.reset_incoming_data()

	def recv_userhost(self, data):
		at = data.find("@")
		ip = data[at+1:]
		logging.debug("found ip %s", ip)
		nick = "f" + self.encode_address(ip, 8333)
		logging.debug("nick %s", nick)
		self.push_nick(nick)
		self.push_crlf("JOIN #bitcoin")
		self.push_crlf("WHO #bitcoin")

	def encode_address(self, ip, port):
		ip = socket.inet_aton(ip)
		port = struct.pack("!H", port)
		data = ip + port
		h = base58.checksum(data)
		data += h[:4]
		return base58.b58encode(data)



	def decode_address(self, data):

