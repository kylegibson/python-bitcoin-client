import asyncore
import socket
class Connection(asyncore.dispatcher):
	def __init__(self, addr):
		asyncore.dispatcher.__init__(self)
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		self.connect(addr)
		self.addr = addr
		self.rbuf = ""
		self.wbuf = ""

	def push(self, data):
		self.wbuf += data

	def writable(self):
		return len(self.wbuf) > 0

	def handle_read(self):
		try: r = self.recv(8192)
		except socket.error, (errno, msg):
			if errno == 111: # Connection refused
				logging.error("connection refused %s", self.addr)
			else:
				logging.exception("recv")
			self.close()
			return False
		self.rbuf += r
		return True

	def handle_write(self):
		try: s = self.send(self.wbuf)
		except socket.error, (errno, msg):
			logging.exception("send")
			self.close()
			return False
		self.wbuf = self.wbuf[s:]
		return True
