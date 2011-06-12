import time
import logging
import parser

class Context:
	def __init__(self, config, data):
		self.config, self.data = config, data
		self.time_offset = 0
		self.time_ip_set = set()
		self.time_offset_list = [0]
		self.time_offset_median_tolerance = 70 * 60
		self.clock_error_displayed = False
		self.parser = parser.BParser()

	def add_node_address(self, addr):
		self.data["nodes"][addr] = {}

	def get_last_block(self):
		return len(self.data["blocks"]) - 1
	
	def get_system_time(self):
		return int(time.time())

	def get_adjusted_time(self):
		return self.time_offset + self.get_system_time()

	def add_time_delta(self, ip, ntime):
		sample = ntime - self.get_system_time()
		if ip in self.time_ip_set:
			return
		self.time_ip_set.add(ip)
		self.time_offset_list.append(sample)
		l = len(self.time_offset_list)
		if l >= 5 and l % 2 == 1:
			self.time_offset_list.sort()
			median = self.time_offset_list[l/2]
			if abs(median) < self.time_offset_median_tolerance:
				self.time_offset = median
			else:
				self.time_offset = 0
				match = False
				for offset in self.time_offset_list:
					if offset != 0 and abs(offset) < 5 * 60:
						match = True
						break
				if not match and not self.clock_error_displayed:
					self.clock_error_displayed = True
					logging.error("ERROR: Please check that your computer's date and time are correct.  If your clock is wrong Bitcoin will not work properly.")

