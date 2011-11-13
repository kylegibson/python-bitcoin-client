import asynchat
import socket
import struct
import logging
import base58

class BConnection(asynchat.async_chat):
	def __init__(self, addr, context):
		asynchat.async_chat.__init__(self)
		self.context = context
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		logging.debug("connecting to address %s", addr)
		self.connect(addr)
		self.remote = None
		self.header_format = "<L12sL"
		self.header_size = struct.calcsize(self.header_format)
		self.set_terminator(self.header_size)
		self.last_seen = None
		self.incoming_handlers = {
			"version"		: self.pop_version,
			"verack"		: self.pop_verack,
			"addr"			: self.pop_addr,
			"block"			: self.pop_block,
			"inv"				: self.pop_inv,
		}
		self.incoming_handler = None
		self.reset_incoming_data()
		self.push_version()

	def unpack_incoming_header(self):
		(network, command, paylen), data = self.context.parser.unpack(self.header_format, self.incoming_data)
		self.incoming_data = data
		command = command.strip('\0')
		return network, command, paylen

	def checksum(self, data):
		h = base58.checksum(data)
		return h[:4]

	def verify_checksum(self, data):
		checksum, data = self.pop_checksum(data)
		real_checksum = self.checksum(data)
		if checksum == real_checksum:
			return data
		return None

	def collect_incoming_data(self, data):
		#logging.debug("collect_incoming_data %s", len(data))
		self.incoming_data += data
		self.last_seen = self.context.get_system_time()

	def reset_incoming_data(self):
		self.incoming_data = ""

	def handle_connect(self):
		logging.debug("connected to node %s", self.addr)

	def handle_expt(self):
		if not self.connected:
			logging.debug("connection refused to %s", self.addr)
		else:
			logging.exception()
		self.close()

	def found_terminator(self):
		logging.debug("received packet %s", len(self.incoming_data))
		if callable(self.incoming_handler):
			try:
				if self.incoming_handler():
					self.close()
				#logging.debug("set_terminator %s", self.header_size)
				self.set_terminator(self.header_size)
			except:
				logging.exception("incoming handler")
				self.close()
			return
		network, command, paylen = self.unpack_incoming_header()
		if network != self.context.config["network"]:
			logging.error("received garbage from %s", self.addr)
			self.close()
			return
		handler = self.incoming_handlers.get(command, None)
		if handler is None:
			logging.error("Unable to handle command %s (paylen=%s)", command, paylen)
			self.close()
			return
		logging.debug("received %s paylen %s", command, paylen)
		if paylen == 0:
			handler()
			self.set_terminator(self.header_size)
		else:
			self.incoming_handler = handler
			csize = 0
			if command not in ("version", "verack"):
				csize = self.context.parser.get_checksum_size()
			self.set_terminator(csize + paylen)

	def push_packet(self, command, data=""):
		size = len(data)
		header = struct.pack("<L12sL", self.context.config["network"], command, size)
		if size > 0 and command not in ("version", "verack"):
			c = self.checksum(data)
			#logging.debug("checksum: %s", c.encode("hex_codec"))
			header += c
		self.push(header)
		#logging.debug("push_packet header: %s (%s)", command, len(header))
		if size > 0:
			self.push(data)
			#logging.debug("push_packet data: \n%s", data.encode("hex_codec"))

	def push_version(self):
		remote = self.context.parser.pack_address(
				self.context.config["services"],
				self.addr[0], self.addr[1])
		local = self.context.parser.pack_address(
				self.context.config["services"],
				self.context.get_external_address(),
				self.context.config["local_port"])
		data = struct.pack("<LQQ26s26sQxL", 
				self.context.config["version"], 
				self.context.config["services"], 
				self.context.get_system_time(),
				remote, local, 
				self.context.config["nonce"], 
				self.context.get_last_block())
		self.push_packet("version", data)

	def pop_version(self):
		if self.remote:
			return 
		self.incoming_handler = None
		result, data = self.context.parser.unpack("<LQQ26s26sQxL", self.incoming_data)
		self.incoming_data = data
		version, services, timestamp, remote, local, nonce, last = result
		logging.debug("pop_version %s %s %s %s %s", version, services, timestamp, nonce, last)
		if nonce == self.context.config["nonce"] and nonce > 1:
			logging.error("Connected to self, disconnecting")
			return True
		self.remote = {
			"version" : version,
			"services" : services,
			"timestamp" : timestamp,
			"nonce" : nonce,
			"last" : last
		}
		if version >= 209:
			self.push_verack()
		self.context.add_time_delta(0, timestamp)

	def push_verack(self):
		self.push_packet("verack")

	def pop_verack(self):
		logging.debug("pop_verack")
		self.incoming_handler = None
		if not self.context.blocks:
			self.bootstrap()

	def bootstrap():
		if not self.locks.get("bootstrap", None):
			self.locks["bootstrap"] = (self, self.context.get_system_time(), 30)



		self.push_getblocks([self.context.config["genesis_hash"]])

	def push_getaddr(self):
		logging.debug("push_getaddr")
		self.push_packet("getaddr")

	def pop_addr(self):
		logging.debug("pop_addr")
		self.incoming_handler = None
		data = self.verify_checksum(self.incoming_data)
		if not data:
			logging.error("checksum failure")
			return True

	def push_getblocks(self,hash_starts,hash_stop=None):
		if not hash_stop:
			hash_stop = "\0" * 32
		starts = ""
		for start in hash_starts:
			starts += start[::-1]
		vector = self.context.parser.pack_variable_int(len(hash_starts)) + starts
		data = struct.pack("<i", self.context.config["version"])
		packet = data + vector + hash_stop
		self.push_packet("getblocks", packet)

	def pop_checksum(self, data):
		return data[:4], data[4:]

	def pop_block(self):
		logging.debug("pop_block")
		self.incoming_handler = None
		data = self.verify_checksum(self.incoming_data)
		if not data:
			logging.error("checksum failure")
			return True
		h = base58.checksum(data[:4+32+32+4+4+4])
		block, data = self.context.parser.unpack_block(data)
		logging.debug("block: %s %s", h.encode("hex_codec"), block)
		self.incoming_data = data

	def push_inv(self):
		pass

	def pop_inv(self):
		logging.debug("pop_inv")
		self.incoming_handler = None
		data = self.verify_checksum(self.incoming_data)
		if not data:
			logging.error("checksum failure")
			return True
		size, data = self.context.parser.unpack_variable_int(data)
		logging.debug("inv size: %s", size)
		invs = []
		for i in range(size):
			inv, data = self.context.parser.unpack_inv(data)
			if inv[0] == 0:
				logging.error("invalid invector vector")
				self.close()
				return
			if inv[0] == 1:
				storage = self.context.transactions
			if inv[0] == 2:
				storage = self.context.blocks
			storage[inv[1]] = storage.get(inv[1], {})
			logging.debug("received inv %s %s", inv[0], inv[1].encode("hex_codec"))
		self.incoming_data = data

