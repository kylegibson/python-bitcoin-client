import struct
import socket

class BParser:
	def __init__(self):
		pass

	def unpack(self, fmt, data):
		size = struct.calcsize(fmt)
		data, rem = data[:size], data[size:]
		return struct.unpack(fmt, data), rem

	def pack_variable_int(self, n):
		if n < 0xfd:
			return struct.pack("<B", n)
		if n <= 0xffff:
			return struct.pack("<BH", 0xfd, n)
		if n <= 0xffffffff:
			return struct.pack("<BL", 0xfe, n)
		return struct.pack("<Q", 0xff, n)

	def unpack_variable_int(self, data):
		(m,), data = self.unpack("<B", data)
		f = None
		if m == 0xff:
			f = "Q"
		elif m == 0xfe:
			f = "L"
		elif m == 0xfd:
			f = "H"
		else:
			return m, data
		(n,), data = self.unpack("<"+f, data)
		return n, data

	def pack_variable_string(self, data):
		return self.pack_variable_int(len(data)) + data

	def unpack_variable_string(self, data):
		size, data = self.unpack_variable_int(data)
		return data[:size], data[size:]

	def pack_address(self, services, addr, port):
		addr = "::ffff:"+addr
		addr = socket.inet_pton(socket.AF_INET6, addr)
		return struct.pack("<Q", services) + addr + struct.pack("!H", port)

	def unpack_address(self, data):
		(services, addr), data = self.unpack("<Q16s", data)
		(port,), data = self.unpack("!H", data)
		return (services, addr, port), data

	def get_checksum_size(self):
		return struct.calcsize("<L")

	def pack_checksum(self, checksum):
		return struct.pack("<L", checksum)

	def unpack_checksum(self, data):
		(checksum,), data = self.unpack("<L", data)
		return checksum, data

	def unpack_block(self, data):
		original = data
		result, data = self.unpack("<L32B32BLLL", data)
		version, pblock, merkle, timestamp, bits, nonce = result
		size, data = self.unpack_variable_int(data)
		transactions = []
		for i in range(size):
			tx, data = self.unpack_transaction(data)
			transactions.append(tx)
		block = (version, pblock, merkle, timestamp, bits, nonce, transactions)
		return block, data

	def unpack_transaction(self, data):
		o = data
		(version,), data = self.unpack("<L", data)
		tx_in_count, data = self.unpack_variable_int(data)
		tx_in = []
		for i in range(tx_in_count):
			tx_in.append(data[:41])
			data = data[41:]
		tx_out_count, data = self.unpack_variable_int(data)
		tx_out = []
		for i in range(tx_out_count):
			tx_in.append(data[:8])
			data = data[8:]
		(lock_time,), data = self.unpack("<L", data)
		tx = (version, tx_in, tx_out, lock_time)
		return tx, data

