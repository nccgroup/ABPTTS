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

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import threading
import logging
import socket
import random
import math
import os
import sys
import requests
from requests.adapters import HTTPAdapter, Retry
import time

logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s')

class Client(threading.Thread):	
	logger = logging.getLogger(__name__)
	encryption_key = None
	connection_id = None
	running = True
	traffic_sent = False
	is_listener_stopped = False
	c2s_buffer = b""
	iterations_counter = 0
	bytes_read = 0
	bytes_sent = 0

	def __init__(self, socket, addr, listener, config):
		super().__init__()
		self.socket = socket
		self.addr = addr
		self.listener = listener
		self.config = config
		self.get_config_values()
		self.session = self.init_session(listener["unsafe_tls"])

	def get_config_values(self):
		self.header_value_key = self.config.get_key("Authentication", "headerValueKey")
		self.header_name_key = self.config.get_key("Authentication", "headerNameKey")
		self.header_value_user_agent = self.config.get_key("Encryption", "headerValueUserAgent")

		self.access_key_mode =  self.config.get_key("Encryption", "accessKeyMode")
		self.encryption_key_hex = self.config.get_key("Encryption", "encryptionKeyHex")

		self.param_name_data = self.config.get_key("Obfuscation", "paramNameData")
		self.param_name_operation = self.config.get_key("Obfuscation", "paramNameOperation")
		self.param_name_access_key = self.config.get_key("Obfuscation", "paramNameAccessKey")
		self.param_name_connection_ID = self.config.get_key("Obfuscation", "paramNameConnectionID")
		self.param_name_destination_host = self.config.get_key("Obfuscation", "paramNameDestinationHost")
		self.param_name_destination_port = self.config.get_key("Obfuscation", "paramNameDestinationPort")
		self.param_name_encrypted_block = self.config.get_key("Obfuscation", "paramNameEncryptedBlock")
		self.param_name_plaintext_block = self.config.get_key("Obfuscation", "paramNamePlaintextBlock")
		self.data_block_name_value_separator_b64 = self.config.get_key("Obfuscation", "dataBlockNameValueSeparatorB64")
		self.data_block_param_separator_b64 = self.config.get_key("Obfuscation", "dataBlockParamSeparatorB64")
		self.op_mode_string_open_connection = self.config.get_key("Obfuscation", "opModeStringOpenConnection")
		self.op_mode_string_close_connection = self.config.get_key("Obfuscation", "opModeStringCloseConnection")
		self.op_mode_string_send_receive = self.config.get_key("Obfuscation", "opModeStringSendReceive")
		self.response_string_data = self.config.get_key("Obfuscation", "responseStringData")
		self.response_string_prefix_b64 = self.config.get_key("Obfuscation", "responseStringPrefixB64")
		self.response_string_suffix_b64 = self.config.get_key("Obfuscation", "responseStringSuffixB64")
		self.response_string_connection_created = self.config.get_key("Obfuscation", "responseStringConnectionCreated")
		self.response_string_connection_closed = self.config.get_key("Obfuscation", "responseStringConnectionClosed")
		self.response_string_error_connection_not_found = self.config.get_key("Obfuscation", "responseStringErrorConnectionNotFound")
		self.response_string_no_data = self.config.get_key("Obfuscation", "responseStringNoData")
		self.response_string_error_invalid_request = self.config.get_key("Obfuscation", "responseStringErrorInvalidRequest")
		self.response_string_error_connection_open_failed = self.config.get_key("Obfuscation", "responseStringErrorConnectionOpenFailed")
		self.response_string_error_connections_send_failed = self.config.get_key("Obfuscation", "responseStringErrorConnectionSendFailed")
		self.response_string_error_connection_receive_failed = self.config.get_key("Obfuscation", "responseStringErrorConnectionReceiveFailed")
		self.response_string_error_decrypt_failed = self.config.get_key("Obfuscation", "responseStringErrorDecryptFailed")
		self.response_string_error_encrypt_failed = self.config.get_key("Obfuscation", "responseStringErrorEncryptFailed")
		self.response_string_error_encryption_not_supported = self.config.get_key("Obfuscation", "responseStringErrorEncryptionNotSupported")

		self.autoscale_client_socket_timeout = self.config.get_key("Network.client", "autoscaleClientSocketTimeout", "boolean")
		self.client_socket_timeout_min = self.config.get_key("Network.client", "clientSocketTimeoutMin", "float")
		self.client_socket_timeout_max = self.config.get_key("Network.client", "clientSocketTimeoutMax", "float")
		self.client_socket_timeout_scaling_multiplier = self.config.get_key("Network.client", "clientSocketTimeoutScalingMultiplier", "float")
		self.client_socket_timeout_variation = self.config.get_key("Network.client", "clientSocketTimeoutVariation", "float")
		self.client_socket_buffer_size = self.config.get_key("Network.client", "clientSocketBufferSize", "int")
		self.socket_timeout_current = self.config.get_key("Network.client", "clientSocketTimeoutBase", "float")
		self.client_to_server_block_size = self.config.get_key("Network.client", "clientToServerBlockSize", "int")
		self.client_block_transmit_sleep_time = self.config.get_key("Network.client", "clientBlockTransmitSleepTime", "float")
		self.client_block_size_limit_from_server = self.config.get_key("Network.client", "clientBlockSizeLimitFromServer", "int")
		self.echo_data = self.config.get_key("Logging", "echoData", "boolean")
		self.echo_HTTP_body = self.config.get_key("Logging", "echoHTTPBody", "boolean")
		self.echo_debug_messages = self.config.get_key("Logging", "echoDebugMessages", "boolean")
		self.stats_update_iterations = self.config.get_key("Logging", "statsUpdateIterations", "int")

	def init_session(self, unsafe_tls):
		s = requests.Session()
		retries = Retry(total=6, backoff_factor=1.0)

		s.headers.update({
			"User-Agent": self.header_value_user_agent,
			"Content-type": "application/x-www-form-urlencoded"
		})
		s.timeout = 10.0

		if unsafe_tls:
			requests.packages.urllib3.disable_warnings()
			s.verify = False

		s.mount('http://', HTTPAdapter(max_retries=retries))
		s.mount('https://', HTTPAdapter(max_retries=retries))

		return s

	def encrypt(self, data):
		nonce = get_random_bytes(12)
		cipher = AES.new(self.encryption_key, AES.MODE_GCM, nonce=nonce)
		ciphertext, tag = cipher.encrypt_and_digest(data.encode())
		return nonce + ciphertext + tag

	def decrypt(self, ciphertext):
		nonce = ciphertext[0:12]
		data = ciphertext[12:-AES.block_size]
		tag = ciphertext[-AES.block_size:]

		cipher = AES.new(self.encryption_key, AES.MODE_GCM, nonce=nonce)
		try:
			plaintext = cipher.decrypt_and_verify(data, tag)
			return plaintext
		except ValueError:
			self.logger.exception("Message decryption failed. Key incorrect or message corrupted")

	def get_clean_server_response(self, response):
		result = response
		wrapper_text = []
		wrapper_prefix = b64decode(self.response_string_prefix_b64).decode()
		wrapper_suffix = b64decode(self.response_string_suffix_b64).decode()

		for s in [wrapper_prefix, wrapper_suffix]:
			# Handle not only the "normal" prefix/suffix blocks, but also any variations created by "helpful" servers, e.g. Apache Tomcat, which transparently strips \r characters from output
			result = result.replace(s.replace("\r", ""), "")
			result = result.replace(s, "")

		result = result.strip()

		if self.echo_HTTP_body:
			self.output_tunnel_IO_message("S2C", response, "HTTP Response Body")
			self.output_tunnel_IO_message("S2C", result, "HTTP Response Body Without Wrapper Text")

		return result

	def output_tunnel_IO_message(self, direction, message, category=""):
		server_address = f"{self.listener["remote"]["host"]}:{self.listener["remote"]["port"]}"
		client_address = f"{self.addr[0]}:{self.addr[1]}"
		listening_address = f"{self.listener["remote"]["host"]}:{self.listener["remote"]["port"]}"
		result = f"[({direction}) "

		if direction == "S2C":
			result += f"{server_address} -> {listening_address} -> {client_address}"
		else:
			result += f"{client_address} -> {listening_address} -> {server_address}"

		if self.connection_id:
			result += f" (Connection ID: {self.connection_id})"

		if category:
			result += f" ({category})"

		result += f"]: {message}"

		self.logger.info(result)

	def set_encryption(self):
		if self.encryption_key_hex:
			try:
				self.encryption_key = bytes.fromhex(self.encryption_key_hex)
				if self.encryption_key and self.access_key_mode == "header":
					self.session.headers.update({ self.header_name_key: self.header_value_key })
			except Exception as e:
				self.logger.exception("Could not cast encryption key to array of bytes")
				sys.exit(1)
		else:
			self.logger.warning("The current configuration DOES NOT ENCRYPT tunneled traffic. If you wish to use symmetric encryption, restart this utility with a configuration file which defines a valid encryption key.")

	def create_message(self, operation, params):
		plaintext_message = ""

		separators = [
			b64decode(self.data_block_name_value_separator_b64).decode(),
			b64decode(self.data_block_param_separator_b64).decode()
		]

		plaintext_message += self.param_name_operation + separators[0]
		plaintext_message += operation + separators[1]
		for param, sep_idx in params[:-1]:
			plaintext_message += param + separators[sep_idx]
		plaintext_message += params[-1]

		return plaintext_message

	def create_open_connection_message(self):
		operation = self.op_mode_string_open_connection
		params = [
			(self.param_name_destination_host, 0),
			(self.listener["remote"]["host"], 1),
			(self.param_name_destination_port, 0),
			str(self.listener["remote"]["port"])
		]
		return self.create_message(operation, params)

	def create_close_connection_message(self):
		operation = self.op_mode_string_close_connection
		params = [
			(self.param_name_connection_ID, 0),
			self.connection_id
		]
		return self.create_message(operation, params)

	def create_send_receive_message(self, data):
		operation = self.op_mode_string_send_receive
		params = [
			(self.param_name_connection_ID, 0),
			(self.connection_id, 1),
			(self.param_name_data, 0),
			data
		]
		return self.create_message(operation, params)

	def read_socket(self):
		c2s_bytes_count = self.client_to_server_block_size
		c2s_buffer_length = len(self.c2s_buffer)
		c2s_bytes = b""

		if c2s_bytes_count > c2s_buffer_length:
			c2s_bytes_count = c2s_buffer_length

		if c2s_bytes_count < c2s_buffer_length:
			c2s_bytes = self.c2s_buffer[0:c2s_bytes_count]
			self.c2s_buffer = self.c2s_buffer[c2s_bytes_count:]
		else:
			c2s_bytes = self.c2s_buffer[:]
			self.c2s_buffer = b""

		c2s_b64encoded_data = b64encode(c2s_bytes).decode()

		if self.echo_debug_messages:
			self.output_tunnel_IO_message("C2S", f"Sending {len(c2s_bytes)} bytes")
		if self.echo_data:
			self.output_tunnel_IO_message("C2S", c2s_b64encoded_data, "Raw Data (Plaintext) (base64)")

		self.bytes_read += len(c2s_bytes)
		return c2s_b64encoded_data

	def send_message(self, message):
		response = ""
		clean_response = ""
		success = False

		if self.encryption_key:
			encrypted_data = self.encrypt(message)
			b64_encrypted_data = b64encode(encrypted_data).decode()
			if self.echo_data:
				self.output_tunnel_IO_message("C2S", b64_encrypted_data, "Raw Data (Encrypted) (base64)")
			body = { self.param_name_encrypted_block: b64_encrypted_data }
			if self.access_key_mode != "header":
				body[self.param_name_access_key] = self.header_value_key
		else:
			message = b64encode(message).decode()
			body = { self.param_name_plaintext_block: message }
			if self.access_key_mode != "header":
				body[self.param_name_access_key] = self.header_value_key

		if self.echo_HTTP_body:
			self.output_tunnel_IO_message("C2S", body, "HTTP Request Body")

		try:
			response = self.session.post(self.listener["forwarding_url"], data=body)
			response = response.text
			clean_response = self.get_clean_server_response(response)
			success = True
		except Exception as e:
			self.logger.exception("C2S: HTTP request failed")

		return clean_response, response, success

	def send_data_to_socket(self, body_array):
		bytes_sent = 0

		if body_array[0] == self.response_string_data:
			s2c_encoded_bytes = body_array[1]
			s2c_bytes = b64decode(s2c_encoded_bytes)

			if self.echo_data:
				data_format = "Encrypted" if self.encryption_key else "Plaintext"
				self.output_tunnel_IO_message("S2C", s2c_encoded_bytes, f"Raw Data ({data_format}) (base64)")

			if self.encryption_key:
				s2c_bytes = self.decrypt(s2c_bytes)

			s2c_bytes_len = len(s2c_bytes)
			number_of_blocks = int(math.ceil(float(s2c_bytes_len) / float(self.client_block_size_limit_from_server)))

			if self.echo_debug_messages and number_of_blocks > 1:
				self.output_tunnel_IO_message("S2C", f"Splitting large block ({s2c_bytes_len} bytes) into {number_of_blocks} blocks for relay to client")

			for block_index in range(number_of_blocks):
				first_byte = block_index * self.client_block_size_limit_from_server
				last_byte = (block_index + 1) * self.client_block_size_limit_from_server

				if last_byte > s2c_bytes_len:
					last_byte = s2c_bytes_len

				current_block = s2c_bytes[first_byte:last_byte]
				bytes_sent += len(current_block)

				if self.echo_data:
					self.output_tunnel_IO_message("S2C", b64encode(current_block).decode(), "Raw Data (Plaintext) (base64)")

				if self.echo_debug_messages:
					self.output_tunnel_IO_message("S2C", f"(Block {block_index + 1}/{number_of_blocks}) {len(current_block)} bytes")

				try:
					self.socket.send(current_block)
				except Exception as e:
					self.logger.exception("Error sending data to client")

				if self.client_block_transmit_sleep_time > 0.0:
					if block_index < (number_of_blocks - 1):
						time.sleep(self.client_block_transmit_sleep_time)

		return bytes_sent

	def update_iterations(self):
		self.iterations_counter += 1

		if self.iterations_counter > self.stats_update_iterations:
			self.output_tunnel_IO_message("C2S", f"{self.bytes_read} bytes sent since last report")
			self.output_tunnel_IO_message("S2C", f"{self.bytes_sent} bytes sent since last report")
			self.iterations_counter = 0
			self.bytes_read = 0
			self.bytes_sent = 0

	def parse_server_error(self, body):
		found_response_type = False

		if body == self.response_string_no_data:
			found_response_type = True
			if self.echo_debug_messages:
				self.output_tunnel_IO_message("S2C", "No data to receive from server at this time")
		else:
			self.traffic_sent = True

		if body == self.response_string_error_invalid_request:
			self.output_tunnel_IO_message("S2C", "The server reported that the request was invalid. Verify that that you are using a client configuration compatible with the server-side component.")
		elif body == self.response_string_error_connection_open_failed:
			self.output_tunnel_IO_message("S2C", "The server reported that the requested connection could not be opened. You may have requested a destination host/port that is inaccessible to the server, the server may have exhausted ephemeral ports (although this is unlikely), or another component (e.g. firewall) may be interfering with connectivity.")
		elif body == self.response_string_error_connections_send_failed:
			self.output_tunnel_IO_message("S2C", "The server reported that an error occurred while sending data over the TCP connection.")
		elif body == self.response_string_error_connection_receive_failed:
			self.output_tunnel_IO_message("S2C", "The server reported that an error occurred while receiving data over the TCP connection.")
		elif body == self.response_string_error_decrypt_failed:
			self.output_tunnel_IO_message("S2C", "The server reported a decryption failure. Verify that the encryption keys in the client and server configurations match.")
		elif body == self.response_string_error_encrypt_failed:
			self.output_tunnel_IO_message("S2C", "The server reported an encryption failure. Verify that the encryption keys in the client and server configurations match.")
		elif body == self.response_string_error_encryption_not_supported:
			self.output_tunnel_IO_message("S2C", "The server reported that it does not support encryption. Verify that that you are using a client configuration compatible with the server-side component.")
		else:
			if not found_response_type:
				self.output_tunnel_IO_message("S2C", f"Unexpected response from server: {body}")
				self.client_closed_connection = True

	def update_socket_timeout(self, scale_socket_timeout_down, scale_socket_timeout_up):
		timeout_change = 0.0
		new_socket_timeout = self.socket_timeout_current

		if scale_socket_timeout_down:
			new_socket_timeout = self.client_socket_timeout_min
		if scale_socket_timeout_up:
			timeout_change = self.client_socket_timeout_scaling_multiplier * self.socket_timeout_current
			new_socket_timeout = self.socket_timeout_current + timeout_change

		# make sure socket timeout is within specified range
		if new_socket_timeout < self.client_socket_timeout_min:
			new_socket_timeout = self.client_socket_timeout_min
		if new_socket_timeout > self.client_socket_timeout_max:
			new_socket_timeout = self.client_socket_timeout_max

		if new_socket_timeout != self.socket_timeout_current:
			if self.echo_debug_messages:
				self.logger.info(f"[Connection ID {self.connection_id}]: Client-side socket timeout has been changed from {self.socket_timeout_current} to {new_socket_timeout}")
			self.socket_timeout_current = new_socket_timeout

		# apply random socket timeout variation
		client_socket_timeout_variation_neg = self.client_socket_timeout_variation * -1.0
		timeout_var = random.uniform(client_socket_timeout_variation_neg, self.client_socket_timeout_variation)
		timeout_modifier = self.socket_timeout_current * timeout_var
		effective_timeout = self.socket_timeout_current + timeout_modifier
		if self.echo_debug_messages:
			self.logger.info(f"[Connection ID {self.connection_id}]: Applying random variation of {timeout_modifier} to client-side socket timeout for this iteration - timeout will be {effective_timeout}")

		self.socket.settimeout(effective_timeout)

	def start_connection(self):
		clean_response, raw_response, success = self.send_message(self.create_open_connection_message())

		if success:
			if self.response_string_connection_created in clean_response:
				response_array = clean_response.split(" ")
				if len(response_array) > 1:
					self.connection_id = response_array[1]
					self.output_tunnel_IO_message("S2C", f"Server created connection ID {self.connection_id}")
			else:
				self.stop()
				self.logger.critical(f"Could not create connection. Raw server response: {raw_response}")

	def run(self):
		self.socket.settimeout(self.socket_timeout_current)
		self.set_encryption()
		self.logger.info(f"Connecting to {self.listener["remote"]["host"]}:{self.listener["remote"]["port"]} via {self.listener["forwarding_url"]}")
		self.start_connection()
		self.client_closed_connection = False

		while self.running:
			c2s_b64encoded_data = ""
			self.traffic_sent = False
			self.bytes_read = 0
			self.bytes_sent = 0
			self.iterations_counter = 0

			try:
				data = self.socket.recv(self.client_socket_buffer_size)
				if data:
					self.c2s_buffer += data
				else:
					self.client_closed_connection = True
			except socket.error as e:
				if "timed out" not in str(e):
					self.logger.exception("Error reading socket")
					raise e

			if self.c2s_buffer:
				c2s_b64encoded_data = self.read_socket()
			else:
				if self.client_closed_connection:
					self.output_tunnel_IO_message("C2S", "Client closed channel")
					break

			clean_response, raw_response, success = self.send_message(self.create_send_receive_message(c2s_b64encoded_data))
			if success:
				self.traffic_sent = True
			else:
				break

			body_array = clean_response.split(" ", 1)
			if len(body_array) > 1:
				self.bytes_sent += self.send_data_to_socket(body_array)
			else:
				self.parse_server_error(clean_response)

			if self.response_string_connection_closed in clean_response:
				self.output_tunnel_IO_message("S2C", f"The server explicitly closed connection ID {self.connection_id}")
				self.client_closed_connection = True

			if self.response_string_error_connection_not_found in clean_response:
				self.output_tunnel_IO_message("S2C", f"The server reported that connection ID {self.connection_id} was not found - assuming connection has been closed.")
				self.client_closed_connection = True

			scale_socket_timeout_down = True if self.traffic_sent else False
			scale_socket_timeout_up = False if self.traffic_sent else True

			if self.client_closed_connection:
				self.stop()
				body_array = clean_response.split(" ")
				if len(body_array) > 1:
					self.connection_id = body_array[1]
					self.output_tunnel_IO_message("S2C", f"The server closed connection ID {self.connection_id}")
				else:
					self.output_tunnel_IO_message("S2C", f"The server closed connection ID {self.connection_id} without specifying its ID")

			self.update_iterations()
			if self.is_listener_stopped:
				self.logger.info(f"Server shutdown request received in thread for connection ID {self.connection_id}")
				self.stop()
			else:
				if self.autoscale_client_socket_timeout:
					self.update_socket_timeout(scale_socket_timeout_down, scale_socket_timeout_up)

		if self.client_closed_connection:
			server_address = f"{self.listener["remote"]["host"]}:{self.listener["remote"]["port"]}"
			client_address = f"{self.addr[0]}:{self.addr[1]}"
			listening_address = f"{self.listener["remote"]["host"]}:{self.listener["remote"]["port"]}"

			self.logger.info(f"Disengaging tunnel ({client_address} -> {listening_address} -> {server_address})")
			self.logger.info(f"Closing client socket ({client_address} -> {listening_address})")

			try:
				self.socket.shutdown(1)
				self.socket.close()
			except Exception as e:
				self.logger.exception(f"Exception while closing client socket ({client_address} -> {listening_address})")

			clean_response, raw_response, success = self.send_message(self.create_close_connection_message())
			if success:
				if self.response_string_connection_closed in clean_response:
					body_array = clean_response.split(" ")
					if len(body_array) > 1:
						self.connection_id = body_array[1]
						self.logger.info(f"Server closed connection ID {self.connection_id}")
				else:
					self.logger.warning(f"Could not close connection ID {self.connection_id} (may have already been closed on the server). Raw server response: {raw_response}")
		else:
			self.logger.info("Unexpected state: child loop exited without closeConnections being set to 1")

	def stop(self):
		self.running = False

	def stop_listener(self):
		self.is_listener_stopped = True