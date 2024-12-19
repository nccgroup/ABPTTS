#!/usr/bin/env python

#	This file is part of A Black Path Toward The Sun ("ABPTTS")

# Copyright 2016 NCC Group

# A Black Path Toward The Sun ("ABPTTS") is free software: you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as published by
# the Free Software Foundation.

# A Black Path Toward The Sun ("ABPTTS") is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with A Black Path Toward The Sun ("ABPTTS") (in the file license.txt).
# If not, see <http://www.gnu.org/licenses/>.

# Client component of A Black Path Toward The Sun

import threading
import logging
import select
import socket

from client.client import Client

logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s')

class Listener(threading.Thread):	
	logger = logging.getLogger(__name__)

	def __init__(self, params, config):
		super().__init__()
		self.params = params
		self.config = config
		self.forwarding_url = params["forwarding_url"]
		self.local = params["local"]
		self.remote = params["remote"]
		self.queue = []
		self.running = True

	def run(self):
		try:
			server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			server.bind((self.local["host"], self.local["port"]))
			server.listen()
		except Exception as e:
			self.logger.exception(f"Could not start listener on {self.local["host"]}:{self.local["port"]}")

		self.logger.info(f"Listener ready to forward connections from {self.local["host"]}:{self.local["port"]} to {self.remote["host"]}:{self.remote["port"]} via {self.forwarding_url}")
		self.logger.info(f"Waiting for client connections on {self.local["host"]}:{self.local["port"]}")

		while self.running:
			try:
				timeout = 2
				readable, writable, errored = select.select([server], [], [], timeout)
				for s in readable:
					client, addr = s.accept()
					self.logger.info(f"Client connected to {self.local["host"]}:{self.local["port"]}")
					formattedAddress = f"{self.local["host"]}:{self.local["port"]}"
					client = Client(client, addr, self.params, self.config)
					client.start()
					self.queue.append(client)
			except Exception as e:
				if "Closing connections" not in str(e):
					raise e

	def stop(self):
		for q in self.queue:
			q.stop()
		self.running = False
