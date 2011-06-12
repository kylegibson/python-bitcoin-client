import asynchat
import struct
import logging
import time



class BConnection(asynchat.async_chat):
	def __init__(self, config, data, addr):
		asynchat.async_chat.__init__(self)
		self.config, self.data, self.addr = config, data, addr
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		self.connect(addr)
		self.remote = None
		self.header_format = "<L12sL"
		self.header_size = struct.calcsize(self.header_format)
		self.set_terminator(self.header_size)
		self.incoming_handlers = {
			"version" : self.pop_version,
			"verack" : self.pop_verack,
			"addr" : self.pop_addr,
		}
		self.incoming_handler = None
		self.reset_incoming_data()
		self.push_version()

	def unpack(self, fmt, data):
		size = struct.calcsize(fmt)
		data, rem = data[:size], data[size:]
		return struct.unpack(fmt, data), rem

	def unpack_incoming_header(self):
		(network, command, paylen), data = self.unpack(self.header_format, self.incoming_data)
		self.incoming_data = data
		command = command.strip('\0')
		return network, command, paylen

	def checksum(self, data):
		h = base58.sha_256(base58.sha_256(data))
		return h[:4]

	def pack_checksum(self, data):
		return struct.pack("<L", self.checksum(data))

	def unpack_checksum(self, data):
		return self.unpack("<L", data)

	def collect_incoming_data(self, data):
		self.incoming_data += data

	def reset_incoming_data(self):
		self.incoming_data = ""

	def handle_connect(self):
		logging.debug("connected to node %s", self.addr)

	def found_terminator(self):
		logging.debug("received packet %s", len(self.incoming_data))
		if callable(self.incoming_handler):
			try:
				if self.incoming_handler():
					self.close()
				self.set_terminator(self.header_size)
			except:
				logging.exception("incoming handler")
				self.close()
			return
		network, command, paylen = self.unpack_incoming_header()
		if network != self.config["network"]:
			logging.error("received garbage from %s", connection.addr)
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
		else:
			self.incoming_handler = handler
			csize = 0
			if command not in ("version", "verack"):
				csize = struct.calcsize("<L") # checksum
			self.set_terminator(csize + paylen)

	def pack_int(self, n):
		if n < 0xfd:
			return struct.pack("<B", n)
		if n <= 0xffff:
			return struct.pack("<BH", 0xfd, n)
		if n <= 0xffffffff:
			return struct.pack("<BL", 0xfe, n)
		return struct.pack("<Q", 0xff, n)

	def unpack_int(self, data):
		m = struct.unpack("<B", data[:1])
		if m == 0xff:
			return struct.unpack("<Q", data[1:])
		if m == 0xfe:
			return struct.unpack("<L", data[1:])
		if m == 0xfd:
			return struct.unpack("<H", data[1:])
		return m

	def pack_address(self, addr, port):
		data = struct.pack("<Q", self.config["services"])
		if len(addr) > 4:
			addr = socket.inet_aton(addr)
		data += struct.pack("!10s2s4sH", "", "\xff\xff", addr, port)
		return data

	def push_packet(self, command, data=""):
		size = len(data)
		header = struct.pack("<L12sL", self.config["network"], command, size)
		if size > 0 and command not in ("version", "verack"):
			header += self.pack_checksum(data) 
		self.push(header)
		logging.debug("push_packet header: %s (%s)", command, len(header))
		if size > 0:
			self.push(data)

	def push_version(self):
		remote = self.pack_address(*self.addr)
		local = self.pack_address(self.config["local_address"], self.config["port"])
		data = struct.pack("<iQQ26s26sQxL", 
				self.config["version"], 
				self.config["services"], 
				int(time.time()), 
				remote, 
				local, 
				self.config["nonce"], 
				len(self.data["blocks"])-1)
		self.push_packet("version", data)

	def pop_version(self):
		if self.remote:
			return 
		self.incoming_handler = None
		pack, data = self.unpack("<iQQ26s26sQxL", self.incoming_data)
		self.incoming_data = data
		version, services, timestamp, remote, local, nonce, last = pack
		logging.debug("pop_version %s %s %s %s %s", version, services, timestamp, nonce, last)
		if nonce == self.config["nonce"] and nonce > 1:
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

	def push_verack(self):
		self.push_packet("verack")

	def pop_verack(self):
		logging.debug("pop_verack")
		self.incoming_handler = None
		self.push_getaddr()

	def push_getaddr(self):
		logging.debug("push_getaddr")
		self.push_packet("getaddr")

	def pop_addr(self):
		logging.debug("pop_addr")
		self.incoming_handler = None
		checksum, data = self.unpack_checksum(self.incoming_data)
		if checksum != self.checksum(data):
			logging.error("checksum mismatch")
			return True
		logging.debug("checksum matches")

	def push_getblocks(self):
		pass	

	#def push_getblocks(self):
	#	logging.debug("push_getblocks")
	#	data = struct.pack("",
	#		)
	#	self.push_packet("getdata", data)
class BConnection(asynchat.async_chat):
	def __init__(self, config, data, addr):
		asynchat.async_chat.__init__(self)
		self.config, self.data, self.addr = config, data, addr
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		self.connect(addr)
		self.remote = None
		self.header_format = "<L12sL"
		self.header_size = struct.calcsize(self.header_format)
		self.set_terminator(self.header_size)
		self.incoming_handlers = {
			"version" : self.pop_version,
			"verack" : self.pop_verack,
			"addr" : self.pop_addr,
		}
		self.incoming_handler = None
		self.reset_incoming_data()
		self.push_version()

	def unpack(self, fmt, data):
		size = struct.calcsize(fmt)
		data, rem = data[:size], data[size:]
		return struct.unpack(fmt, data), rem

	def unpack_incoming_header(self):
		(network, command, paylen), data = self.unpack(self.header_format, self.incoming_data)
		self.incoming_data = data
		command = command.strip('\0')
		return network, command, paylen

	def checksum(self, data):
		h = base58.sha_256(base58.sha_256(data))
		return h[:4]

	def pack_checksum(self, data):
		return struct.pack("<L", self.checksum(data))

	def unpack_checksum(self, data):
		return self.unpack("<L", data)

	def collect_incoming_data(self, data):
		self.incoming_data += data

	def reset_incoming_data(self):
		self.incoming_data = ""

	def handle_connect(self):
		logging.debug("connected to node %s", self.addr)

	def found_terminator(self):
		logging.debug("received packet %s", len(self.incoming_data))
		if callable(self.incoming_handler):
			try:
				if self.incoming_handler():
					self.close()
				self.set_terminator(self.header_size)
			except:
				logging.exception("incoming handler")
				self.close()
			return
		network, command, paylen = self.unpack_incoming_header()
		if network != self.config["network"]:
			logging.error("received garbage from %s", connection.addr)
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
		else:
			self.incoming_handler = handler
			csize = 0
			if command not in ("version", "verack"):
				csize = struct.calcsize("<L") # checksum
			self.set_terminator(csize + paylen)

	def pack_int(self, n):
		if n < 0xfd:
			return struct.pack("<B", n)
		if n <= 0xffff:
			return struct.pack("<BH", 0xfd, n)
		if n <= 0xffffffff:
			return struct.pack("<BL", 0xfe, n)
		return struct.pack("<Q", 0xff, n)

	def unpack_int(self, data):
		m = struct.unpack("<B", data[:1])
		if m == 0xff:
			return struct.unpack("<Q", data[1:])
		if m == 0xfe:
			return struct.unpack("<L", data[1:])
		if m == 0xfd:
			return struct.unpack("<H", data[1:])
		return m

	def pack_address(self, addr, port):
		data = struct.pack("<Q", self.config["services"])
		if len(addr) > 4:
			addr = socket.inet_aton(addr)
		data += struct.pack("!10s2s4sH", "", "\xff\xff", addr, port)
		return data

	def push_packet(self, command, data=""):
		size = len(data)
		header = struct.pack("<L12sL", self.config["network"], command, size)
		if size > 0 and command not in ("version", "verack"):
			header += self.pack_checksum(data) 
		self.push(header)
		logging.debug("push_packet header: %s (%s)", command, len(header))
		if size > 0:
			self.push(data)

	def push_version(self):
		remote = self.pack_address(*self.addr)
		local = self.pack_address(self.config["local_address"], self.config["port"])
		data = struct.pack("<iQQ26s26sQxL", 
				self.config["version"], 
				self.config["services"], 
				int(time.time()), 
				remote, 
				local, 
				self.config["nonce"], 
				len(self.data["blocks"])-1)
		self.push_packet("version", data)

	def pop_version(self):
		if self.remote:
			return 
		self.incoming_handler = None
		pack, data = self.unpack("<iQQ26s26sQxL", self.incoming_data)
		self.incoming_data = data
		version, services, timestamp, remote, local, nonce, last = pack
		logging.debug("pop_version %s %s %s %s %s", version, services, timestamp, nonce, last)
		if nonce == self.config["nonce"] and nonce > 1:
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
		self.add_time_data(timestamp)

	def push_verack(self):
		self.push_packet("verack")

	def pop_verack(self):
		logging.debug("pop_verack")
		self.incoming_handler = None
		self.push_getaddr()

	def push_getaddr(self):
		logging.debug("push_getaddr")
		self.push_packet("getaddr")

	def pop_addr(self):
		logging.debug("pop_addr")
		self.incoming_handler = None
		checksum, data = self.unpack_checksum(self.incoming_data)
		if checksum != self.checksum(data):
			logging.error("checksum mismatch")
			return True
		logging.debug("checksum matches")

	def push_getblocks(self):
		pass	

	#def push_getblocks(self):
	#	logging.debug("push_getblocks")
	#	data = struct.pack("",
	#		)
	#	self.push_packet("getdata", data)

