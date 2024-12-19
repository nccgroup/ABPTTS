#!/usr/bin/env python3

# This file is part of A Black Path Toward The Sun ("ABPTTS")

# Copyright 2024 NCC Group

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

import os
import sys
import logging
import configparser

from utils.utils import Utils

logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s')

class Config:
	logger = logging.getLogger(__name__)

	def __init__(self):
		self.config = configparser.ConfigParser()
    	# use case-sensitive keys, default is case-insensitive
		self.config.optionxform = str
		self.randomize_placeholder = "|RANDOMIZE|"

	def key_exists(self, section, parameterName):
		success = True

		if section not in self.config.sections():
			self.logger.critical(f"Section {section} not in config file")
			success = False

		if not self.config.has_option(section, parameterName):
			self.logger.critical(f"Parameter {parameterName} not in config file")	
			success = False

		return success

	def replace_placeholder(self, content, section, key):
		new_value = ""
		placeholder = f"|PLACEHOLDER_{key}|"
		success = self.key_exists(section, key)

		if success:
			new_value = content.replace(placeholder, self.config[section][key])

		return success, new_value

	def update_value(self, section, key, value):
		success = self.key_exists(section, key)

		if success:
			self.config.set(section, key, value)

		return success

	def get_key(self, section, key, value_type="string"):
		success = self.key_exists(section, key)
		value = ""

		if success:
			if value_type == "string":
				value = self.config.get(section, key)
			elif value_type == "int":
				value = self.config.getint(section, key)
			elif value_type == "float":
				value = self.config.getfloat(section, key)
			elif value_type == "boolean":
				value = self.config.getboolean(section, key)
			else:		
				self.logger.critical(f"Unknown value type '{value_type}'")
				success = False

		if not success:
			sys.exit(1)

		return value


	def replace_if_placeholder(self, key, value):
		for section in self.config.sections():
			if self.config.has_option(section, key) and self.config.get(section, key) == self.randomize_placeholder:
				self.config.set(section, key, value)

	def write_config(self, dst):
		success = False

		try:
			with open(dst, 'w') as configfile:
				self.config.write(configfile)
				self.logger.info(f"Created client configuration file '{dst}'")
				success = True
		except Exception as e:
			self.logger.exception(f"Error writing to '{dst}'")

		return success

	def load_config(self, filenames):
		success = False

		try:
			self.config.read(filenames)
			success = True
		except Exception as e:
			self.logger.exception(f"Could not read configuration files")

		return success

	def create_from_template(self, template_dir, template_name, output_dir):	
		success = False	
		template_src = os.path.join(template_dir, template_name)
		template_dst = os.path.join(output_dir, template_name)		
		success, template_content = Utils.read_file(template_src)

		if not success:
			return success

		if not template_content:
			self.logger.critical(f"The template file '{template_src}' did not contain any content. No corresponding output file will be generated.")
			return success

		options_dict = {
			"Network.server": ["useIPV6ClientSocketOnServer", "serverToClientBlockSize", "serverSocketMaxUnusedIterations", "serverSocketIOTimeout", "serverSocketSendBufferSize", "serverSocketReceiveBufferSize"],
			"Authentication": ["headerNameKey", "headerValueKey"],
			"Encryption": ["encryptionKeyHex", "accessKeyMode"],
			"Obfuscation": [
				"paramNameAccessKey", "paramNameOperation", "paramNameDestinationHost", "paramNameDestinationPort", "paramNameConnectionID", "paramNameData", "paramNamePlaintextBlock",
				"paramNameEncryptedBlock", "dataBlockNameValueSeparatorB64", "dataBlockParamSeparatorB64", "opModeStringOpenConnection", "opModeStringSendReceive", "opModeStringCloseConnection",
				"responseStringHide", "responseStringConnectionCreated", "responseStringConnectionClosed", "responseStringData", "responseStringNoData", "responseStringErrorGeneric", "responseStringErrorInvalidRequest",
				"responseStringErrorConnectionNotFound", "responseStringErrorConnectionOpenFailed", "responseStringErrorConnectionCloseFailed", "responseStringErrorConnectionSendFailed", "responseStringErrorConnectionReceiveFailed",
				"responseStringErrorDecryptFailed", "responseStringErrorEncryptFailed", "responseStringErrorEncryptionNotSupported", "responseStringPrefixB64", "responseStringSuffixB64"
			],
			"Output": ["fileGenerationAppNameShort"]
		}

		for key, values in options_dict.items():
			for value in values:
				success, template_content = self.replace_placeholder(template_content, key, value)
				if not success:
					return success

		try:
			with open(template_dst, 'w') as f:
				f.write(template_content)
			self.logger.info(f"Created server file '{template_dst}'")
			success = True
		except Exception as e:
			self.logger.exception(f"Output file '{template_dst}' could not be created")

		return success

	def dump(self):
		self.logger.debug(f"HTTP Request Header Name for Access Key: {self.config["Authentication"]["headerNameKey"]}")
		self.logger.debug(f"Access Key: {self.config["Authentication"]["headerValueKey"]}")
		self.logger.debug(f"Encryption Key: {self.config["Encryption"]["encryptionKeyHex"]}")
		self.logger.debug(f"HTTP User-Agent Request Header Value: {self.config["Encryption"]["headerValueUserAgent"]}")
		self.logger.debug(f"Send Access Key As: {self.config["Encryption"]["accessKeyMode"]}")
		self.logger.debug(f"Request Body Parameter Name for Access Key: {self.config["Obfuscation"]["paramNameAccessKey"]}")
		self.logger.debug(f"Request Body Parameter Name for Operation Type: {self.config["Obfuscation"]["paramNameOperation"]}")
		self.logger.debug(f"Request Body Parameter Name for Destination Host: {self.config["Obfuscation"]["paramNameDestinationHost"]}")
		self.logger.debug(f"Request Body Parameter Name for Destination Port: {self.config["Obfuscation"]["paramNameDestinationPort"]}")
		self.logger.debug(f"Request Body Parameter Name for Connection ID: {self.config["Obfuscation"]["paramNameConnectionID"]}")
		self.logger.debug(f"Request Body Parameter Name for Tunneled Data: {self.config["Obfuscation"]["paramNameData"]}")
		self.logger.debug(f"Request Body Parameter Name for Plaintext Request Block: {self.config["Obfuscation"]["paramNamePlaintextBlock"]}")
		self.logger.debug(f"Request Body Parameter Name for Encrypted Request Block: {self.config["Obfuscation"]["paramNameEncryptedBlock"]}")
		self.logger.debug(f"Encapsulated Request Body Base64-Encoded Name/Value Separator: {self.config["Obfuscation"]["dataBlockNameValueSeparatorB64"]}")
		self.logger.debug(f"Encapsulated Request Body Base64-Encoded Parameter Separator: {self.config["Obfuscation"]["dataBlockParamSeparatorB64"]}")
		self.logger.debug(f"Request Body Parameter Value for Operation \"Open Connection\": {self.config["Obfuscation"]["opModeStringOpenConnection"]}")
		self.logger.debug(f"Request Body Parameter Value for Operation \"Send/Receive\": {self.config["Obfuscation"]["opModeStringSendReceive"]}")
		self.logger.debug(f"Request Body Parameter Value for Operation \"Close Connection\": {self.config["Obfuscation"]["opModeStringCloseConnection"]}")
		self.logger.debug(f"Response Code for \"Incorrect Access Key (Hide)\": {self.config["Obfuscation"]["responseStringHide"]}")
		self.logger.debug(f"Response Code for \"Connection Created\": {self.config["Obfuscation"]["responseStringConnectionCreated"]}")
		self.logger.debug(f"Response Code for \"Connection Closed\": {self.config["Obfuscation"]["responseStringConnectionClosed"]}")
		self.logger.debug(f"Response Prefix for Tunneled Data: {self.config["Obfuscation"]["responseStringData"]}")
		self.logger.debug(f"Response Code for \"No Data to Send\": {self.config["Obfuscation"]["responseStringNoData"]}")
		self.logger.debug(f"Response Code for \"Generic Error\": {self.config["Obfuscation"]["responseStringErrorGeneric"]}")
		self.logger.debug(f"Response Code for \"Invalid Request\": {self.config["Obfuscation"]["responseStringErrorInvalidRequest"]}")
		self.logger.debug(f"Response Code for \"Connection Not Found\": {self.config["Obfuscation"]["responseStringErrorConnectionNotFound"]}")
		self.logger.debug(f"Response Code for \"Failed to Open Connection\": {self.config["Obfuscation"]["responseStringErrorConnectionOpenFailed"]}")
		self.logger.debug(f"Response Code for \"Failed to Close Connection\": {self.config["Obfuscation"]["responseStringErrorConnectionCloseFailed"]}")
		self.logger.debug(f"Response Code for \"Failed to Send Data (Server-Side)\": {self.config["Obfuscation"]["responseStringErrorConnectionSendFailed"]}")
		self.logger.debug(f"Response Code for \"Failed to Receive Data (Server-Side)\": {self.config["Obfuscation"]["responseStringErrorConnectionReceiveFailed"]}")
		self.logger.debug(f"Response Code for \"Decryption Failure\": {self.config["Obfuscation"]["responseStringErrorDecryptFailed"]}")
		self.logger.debug(f"Response Code for \"Encryption Failure\": {self.config["Obfuscation"]["responseStringErrorEncryptFailed"]}")
		self.logger.debug(f"Response Code for \"Encryption Not Supported\": {self.config["Obfuscation"]["responseStringErrorEncryptionNotSupported"]}")
		self.logger.debug(f"Base64-Encoded Response Prefix: {self.config["Obfuscation"]["responseStringPrefixB64"]}")
		self.logger.debug(f"Base64-Encoded Response Suffix: {self.config["Obfuscation"]["responseStringSuffixB64"]}")
		self.logger.debug(f"Log File Path: {self.config["Logging"]["logFilePath"]}")
		self.logger.debug(f"Write to Log File: {self.config["Logging"]["writeToLog"]}")
		self.logger.debug(f"Write to Standard Output: {self.config["Logging"]["writeToStandardOut"]}")
		self.logger.debug(f"Output Raw Tunneled Data: {self.config["Logging"]["echoData"]}")
		self.logger.debug(f"Output HTTP Request/Response Bodies: {self.config["Logging"]["echoHTTPBody"]}")
		self.logger.debug(f"Output Debugging Messages: {self.config["Logging"]["echoDebugMessages"]}")
		self.logger.debug(f"Request/Response Iterations Between Tunneled Data Statistics Output: {self.config["Logging"]["statsUpdateIterations"]}")
		self.logger.debug(f"Application Name: {self.config["Output"]["fileGenerationAppNameShort"]}")
		self.logger.debug(f"Maximum Number of Bytes for Server to Return to Client Component With Each Send/Receive Operation: {self.config["Network.client"]["clientToServerBlockSize"]} bytes")
		self.logger.debug(f"Client Socket Buffer Size: {self.config["Network.client"]["clientSocketBufferSize"]} bytes")
		self.logger.debug(f"Automatically Adjust Client Socket Timeout: {self.config["Network.client"]["autoscaleClientSocketTimeout"]}")
		self.logger.debug(f"Block Size for Retransmission to Clients: {self.config["Network.client"]["clientBlockSizeLimitFromServer"]} bytes")
		self.logger.debug(f"Sleep Time Between Client Socket Blocks: {self.config["Network.client"]["clientBlockTransmitSleepTime"]} seconds")
		self.logger.debug(f"Base Client Socket Timeout: {self.config["Network.client"]["clientSocketTimeoutBase"]} seconds")
		self.logger.debug(f"Client Socket Timeout Variation Range: {self.config["Network.client"]["clientSocketTimeoutVariation"]}")
		self.logger.debug(f"Client Socket Timeout Scaling Multiplier: {self.config["Network.client"]["clientSocketTimeoutScalingMultiplier"]}")
		self.logger.debug(f"Client Socket Maximum Timeout: {self.config["Network.client"]["clientSocketTimeoutMax"]}")
		self.logger.debug(f"Client Socket Minimum Timeout: {self.config["Network.client"]["clientSocketTimeoutMin"]}")
		self.logger.debug(f"Maximum Number of Bytes for Server to Return to Client Component With Each Send/Receive Operation: {self.config["Network.server"]["serverToClientBlockSize"]}")
		self.logger.debug(f"Maximum Unused Request/Response Iterations Before Abandoning Server-Side Socket: {self.config["Network.server"]["serverSocketMaxUnusedIterations"]}")
		self.logger.debug(f"Use IPv6 for Server-Side Client Sockets (See Documentation): {self.config["Network.server"]["useIPV6ClientSocketOnServer"]}")
		self.logger.debug(f"Server-Side Socket IO Timeout: {self.config["Network.server"]["serverSocketIOTimeout"]} milliseconds")
		self.logger.debug(f"Server-Side Socket Send Buffer Size: {self.config["Network.server"]["serverSocketSendBufferSize"]} bytes")
		self.logger.debug(f"Server-Side Socket Receive Buffer Size: {self.config["Network.server"]["serverSocketReceiveBufferSize"]} bytes")