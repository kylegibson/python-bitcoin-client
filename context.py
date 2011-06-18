
import asyncore
import urllib2
import time
import logging
import socket 

import irc
import net
import parser

class Context:
	def __init__(self, config):
		self.config = config
		self.blocks = {}
		self.transactions = {}
		self.nodes = set()
		self.addresses = [set(), set()] # Pending, All
		self.time_offset = 0
		self.time_ip_set = set()
		self.time_offset_list = [0]
		self.time_offset_median_tolerance = 70 * 60
		self.clock_error_displayed = False
		self.parser = parser.BParser()

	#def load_blocks(self):

	def get_dns_nodes(self):
		for host in self.config["dns_seed"]:
			if not host:
				continue
			ips = socket.gethostbyname_ex(host)[2]
			for ip in ips:
				yield ip

	def get_external_ip_using_http(self):
		host = "http://91.198.22.70"
		data = urllib2.urlopen(host).read()
		i = data.find(" ", data.find("Address:"))
		j = data.find("<", i)
		return data[i+1:j]

	def seed_dns_nodes(self):
		for ip in self.get_dns_nodes():
			if not ip:
				continue
			self.add_node_address((ip, config["default_port"]))

	def event_loop(self):
		bootstrap = True
		birc = None
		uptime_wait = 1
		if self.config.get("irc", None):
			birc = irc.BIRCSeeder(self)
			uptime_wait = 10
		if self.config["nodes"]:
			for node in self.config["nodes"]:
				self.add_node_address(node)
		uptime = self.get_uptime()
		delta = 0
		while True:
			asyncore.loop(timeout=self.config["event_loop_timeout"],count=1)
			time.sleep(self.config["event_loop_sleep"])
			delta += self.get_uptime() - uptime
			uptime = self.get_uptime()
			if bootstrap and uptime > uptime_wait and delta > 1:
				delta = 0
				eip = self.config.get("external_ip", None)
				naddr = len(self.addresses[1])
				if eip and naddr > 0:
					bootstrap = False
					continue
				if birc and uptime > self.config["irc_timeout"]:
					logging.error("IRC failed to get external IP or nodes within %s seconds, falling back", uptime)
					birc.close()
					birc = None
				if not birc:
					if self.config.get("dns_seed"):
						logging.debug("seeding using dns")
						self.seed_dns_nodes()
					if not eip:
						ip = self.get_external_ip_using_http()
						self.set_external_ip(ip)
					bootstrap = False
			elif not bootstrap and delta > 1:
				if len(self.nodes) < self.config["maxconnections"]:
					if len(self.addresses[0]) > 0:
						self.create_node_connection()
					elif len(self.addresses[1]) == 0:
						logging.error("No addresses available")
						time.sleep(5)

	def create_node_connection(self):
		if len(self.addresses[0]) == 0:
			return
		addr = self.addresses[0].pop()
		node = net.BConnection(addr, self) 
		self.nodes.add(node)

	def add_node_address(self, addr):
		if addr not in self.addresses[1]:
			self.addresses[0].add(addr)
			self.addresses[1].add(addr)

	def set_external_ip(self, ip):
		logging.debug("got external ip %s", ip)
		self.config["external_ip"] = ip

	def get_external_address(self):
		return self.config["external_ip"]

	def get_last_block(self):
		return len(self.blocks)

	def get_system_time(self):
		return int(time.time())

	def get_adjusted_time(self):
		return self.time_offset + self.get_system_time()

	def get_uptime(self):
		return self.get_system_time() - self.config["boot"]

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

