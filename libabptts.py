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

#	Version 1.0
#	Ben Lincoln, NCC Group
#	2016-07-30

# shared classes

import base64
import binascii
import httplib2
import inspect
import math
#import multiprocessing
import os
import random
import re
import sys
import socket
import thread
#import threading
import time
import urllib
import zipfile

from Crypto.Cipher import AES
from datetime import datetime, date, tzinfo, timedelta
from shutil import copyfile

class ABPTTSVersion:
	@staticmethod
	def GetVersionString():
		return "1.0"
		
	@staticmethod
	def GetReleaseDateString():
		return "2016-07-30"
		
class OutputHandler:
	@staticmethod
	def outputMessage(message):
		dt = datetime.now().isoformat(' ')
		logMessage = "[%s] %s" % (dt, message)
		print logMessage

class ABPTTSConfiguration:
	def __init__(self, outputHandler):
		self.randomizedValuePlaceholder = "%RANDOMIZE%"
	
		self.OutputHandler = outputHandler
		# ABPTTS authentication / encryption
		#
		# Everything in this section MUST MATCH THE VALUES ON THE SERVER!
		#
		# HTTP request header name to use for sending the key used to access the ABPTTS
		# functionality instead of the dummy response page
		# this is lowercase because of httplib2's bad behaviour of converting all customer
		# request headers to lowercase. If it were uppercase here and lower on the server,
		# it wouldn't be detected.
		self.headerNameKey = "x-xsession-id"
				
		# Access key value (referred to as "header value" for historical reasons - 
		# early versions of ABPTTS only supported sending this value in an HTTP header)
		self.headerValueKey = "tQgGur6TFdW9YMbiyuaj9g6yBJb2tCbcgrEq"
		
		# Send access key as an HTTP header or a POST parameter?
		# A header should be slightly less likely to be logged than a POST parameter
		# valid values: header, postparam
		self.accessKeyMode = "header"
		
		# AES-128 encryption key used for ABPTTS-tunneled data (in ASCII hex format)
		# Leave blank to disable encryption
		self.encryptionKeyHex = "63688c4f211155c76f2948ba21ebaf83"

		# HTTP anti-detection options
		# 
		# User-Agent spoofing
		# note: not very solid spoofing because of httplib2's annoying behaviour of 
		# making customer header names lowercase.
		self.headerValueUserAgent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)"

		# ABPTTS protocol obfuscation
		#
		# Everything in this section MUST MATCH THE VALUES ON THE SERVER!
		#
		# These settings define the various request/response strings used by ABPTTS
		# E.g. if paramNameOperation is "op" and opModeStringSendReceive is "sr", 
		# then when making a "send/receive" request, the (unencrypted) body will 
		# contain the string "op=sr"
		#
		# These are redefinable to prevent detection by simplistic pattern-matching
		# IDS/IPS/WAF-type devices. I did not want any vendor to be able to claim 
		# they could "detect" ABPTTS just because they wrote a regex like
		# "op=sr&.*connection=.*data="
		#
		# request parameter names
		self.paramNameAccessKey = "accesskey"
		self.paramNameOperation = "op"
		self.paramNameDestinationHost = "host"
		self.paramNameDestinationPort = "port"
		self.paramNameConnectionID = "connection"
		self.paramNameData = "data"
		self.paramNamePlaintextBlock = "plaintextblock"
		self.paramNameEncryptedBlock = "encryptedblock"
		#
		# separator characters to use inside of encrypted blocks, encoded as base64
		# These need to either be non-printable ASCII characters, or strings of sufficient
		# complexity that they will never appear inside the blocks they are separating.
		# It is extremely unlikely that they will ever be visible to an IDS/IPS/WAF-type
		# device.
		self.dataBlockNameValueSeparatorB64 = "Hw=="
		self.dataBlockParamSeparatorB64 = "Hg=="
		#dataBlockNameValueSeparator = "\x1F"
		#dataBlockParamSeparator = "\x1E"
		#
		# request parameter values for the Operation parameter
		self.opModeStringOpenConnection = "open"
		self.opModeStringSendReceive = "sr"
		self.opModeStringCloseConnection = "close"
		#
		# response codes
		self.responseStringHide = "OK"
		self.responseStringConnectionCreated = "OPENED"
		self.responseStringConnectionClosed = "CLOSED"
		self.responseStringData = "DATA"
		self.responseStringNoData = "NO_DATA"
		self.responseStringErrorGeneric = "ERROR"
		self.responseStringErrorInvalidRequest = "ERROR_INVALID_REQUEST"
		self.responseStringErrorConnectionNotFound = "ERROR_CONNECTION_NOT_FOUND"
		self.responseStringErrorConnectionOpenFailed = "ERROR_CONNECTION_OPEN_FAILED"
		self.responseStringErrorConnectionCloseFailed = "ERROR_CONNECTION_CLOSE_FAILED"
		self.responseStringErrorConnectionSendFailed = "ERROR_CONNECTION_SEND_FAILED"
		self.responseStringErrorConnectionReceiveFailed = "ERROR_CONNECTION_RECEIVE_FAILED"
		self.responseStringErrorDecryptFailed = "ERROR_DECRYPT_FAILED"
		self.responseStringErrorEncryptFailed = "ERROR_ENCRYPT_FAILED"
		self.responseStringErrorEncryptionNotSupported = "ERROR_ENCRYPTION_NOT_SUPPORTED"
		#
		# begin/end blocks to wrap the response in
		# e.g. to make the server responses look superficially more like a status page, 
		# forum post, API response, etc.
		# these are base64-encoded so that virtually any type of wrapper can be created
		# All text in these blocks is stripped by the ABPTTS client before processing
		# so make sure they aren't substrings of any of the values above
		# 
		self.responseStringPrefixB64 = "PGh0bWw+Cgk8aGVhZD4KCQk8dGl0bGU+U3lzdGVtIFN0YXR1czwvdGl0bGU+Cgk8L2hlYWQ+Cgk8Ym9keT4KPHByZT4K"
		self.responseStringSuffixB64 = "CjwvcHJlPgoJPC9ib2R5Pgo8L2h0bWw+"


		# Output control
		#
		# Log file to append output to
		self.logFilePath = 'ABPTTSClient-log.txt'
		#
		# Write to the log file?
		self.writeToLog = False
		#
		# Write to stdout?
		self.writeToStandardOut = True
		#
		# output raw TCP request/response data?
		self.echoData = False
		#
		# output raw HTTP request/response bodies?
		self.echoHTTPBody = False
		#
		# output assorted debugging messages?
		self.echoDebugMessages = False
		#
		# how frequently to provide stats regarding data I/O through the tunnel
		# e.g. a value of 100 will cause reporting every time the client has made 100 
		# send/receive requests to the server.
		self.statsUpdateIterations = 100


		# Low-level network tuning - client-side settings
		#
		# maximum number of bytes to send to the server component in each send/receive operation
		# see the description for the corresponding serverToClientBlockSize value, later 
		# in this file, for a detailed discussion.
		# This channel has less impact than that value unless a large amount of data is 
		# being sent *to* the server, but the concept is the same.
		self.clientToServerBlockSize = 32768
		#
		# size of the buffer to use on the client for TCP data
		self.clientSocketBufferSize = 6553600
		#
		# initial socket timeout interval
		self.clientSocketTimeoutBase = 0.01
		#
		# If the following value is set to False, then the base timeout will be used continuously
		# Otherwise the timeout will be scaled up/down depending on client/server traffic
		# (to minimize unnecessary communication)
		self.autoscaleClientSocketTimeout = True
		#autoscaleClientSocketTimeout = False
		#
		# Variation range (as a fraction of the current timeout value) to apply to 
		# whatever the current interval is
		self.clientSocketTimeoutVariation = 0.2
		#clientSocketTimeoutVariation = 0.0
		#
		# Multiplier (+/-) to use for autoscaling timeout interval:
		#clientSocketTimeoutScalingMultiplier = 0.25
		self.clientSocketTimeoutScalingMultiplier = 0.1
		#
		# Maximum timeout to allow the current timeout value to range to when 
		# auto-scaling the value:
		self.clientSocketTimeoutMax = 1.0
		#
		# Minimum timeout to allow the current timeout value to range to when 
		# auto-scaling:
		self.clientSocketTimeoutMin = 0.01
		#
		# Quasi-chunking settings
		# 
		# some TCP clients (*cough*SCPonMacOS*cough*) have fragile sockets that are easily
		# overloaded. Sending e.g. 2MB (or even 128K, in some cases) of data all at once will 
		# cause those clients to fail.
		#
		# Symptoms include e.g.:
		# - SCP clients reporting "Corrupted MAC on input. Disconnecting: Packet corrupt"
		# - rdesktop audio extremely stuttery, "Fooo!" on stdout
		#		note: this will still happen to some extent (even if connecting directly 
		#		instead of over an ABPTTS tunnel) if the throughput is too low, but most 
		#		of the audio should make it through.
		#
		# These settings control the quasi-chunking mechanism I implemented to work around 
		# this problem, where large blocks are split into smaller ones for relay to the 
		# client.
		#
		# Most TCP client software I tested works fine without this mechanism, but I like 
		# to default to the most reliable configuration, especially because losing a tunnel 
		# connection during a pen test is extremely frustrating.
		#
		# Increasing the block size can measurably improve throughput if the client software
		# / OS is capable of handling it.
		# 
		# Maximum size of data to send in each blocks to TCP clients connecting to ABPTTS
		# MacOS SCP* results:
		# 16384		success except in rare cases**
		# 32768		success except in rare cases**
		# 65536		success most of the time
		# 81920		success most of the time
		# 98304		consistent failure
		# 131072	consistent failure
		#
		# As reducing the value below 32768 did not appear to provide noticeably greater 
		# reliability, this value is the default. Feel free to experiment with other values.
		#
		# * because this was by far the most finnicky TCP client I tested in terms of this 
		#   specific problem
		#
		# ** stress-testing the tunnel (three simultaneous interactive SSH sessions, each 
		#    of which was continuously looping through a "find /" command, combined with a 
		#    fourth connection to SCP a binary file) would occassionally result in a bad 
		#    transmission
		#
		# split data into blocks no larger than the following number of bytes
		self.clientBlockSizeLimitFromServer = 32768
		#
		# Wait time (in seconds) between blocks
		# Set to 0.0 to disable waiting between blocks
		self.clientBlockTransmitSleepTime = 0.0


		# Low-level network tuning - server-side settings
		# (for generating config file/server file packages)
		#
		# for server-side languages that do not support automatically selecting IPv4 versus IPv6 as 
		# necessary, it can be manually specified here in the event that IPv6 should be used from 
		# the server to other systems.
		# Currently this option is only used by the ASP.NET / C# server-side component.
		self.useIPV6ClientSocketOnServer = False
		# maximum number of bytes to return to the client component in each send/receive operation
		# this value is the option which most directly affects the latency/throughput tradeoff of 
		# the tunnel. 
		# For example, a relatively low value like 32768 will ensure low enough latency
		# even over a relatively slow connection (IE the internet) to keep e.g. MacOS 
		# SCP happy with the connection, but the throughput will be reduced
		# significantly. (approximately 1/7th the throughput versus no cap on this 
		# value).
		# On the other hand, while high values will result in significantly increased 
		# throughput, the latency of the connection becomes much higher as well, 
		# especially over a slower connection. During testing, this did not cause 
		# issues for tunnels over a LAN, but over the internet, the delay due to 
		# downloading the extremely large HTTP responses from the server.
		self.serverToClientBlockSize = 32768
		#
		# if a socket has not been used in this many iterations (of send/receive requests 
		# in the same session), consider it abandoned and close it
		self.serverSocketMaxUnusedIterations = 1000
		#
		# timeout value (in milliseconds) for the server socket
		self.serverSocketIOTimeout = 100
		#
		# size of the send buffer (in bytes)
		self.serverSocketSendBufferSize = 6553600
		#
		# size of the receive buffer (in bytes)
		self.serverSocketReceiveBufferSize = 6553600


		# File-generation settings (for the factory script)
		#
		# short name to use for the application
		# e.g. if this value is FancyServerStatus, then server-side files will be 
		# named things like FancyServerStatus.jsp, URL-mappings will be things like 
		# /FancyServerStatus/, etc.
		self.fileGenerationAppNameShort = "abptts"

	def GetConfigFileData(self, resultHashtable, configFilePath, warnOnOverride):
		lines = ""
		try:
			f = open(configFilePath, 'rb')
			lines = f.read()
			f.close()
		except Exception as e:
			self.OutputHandler.outputMessage("Error: could not read the configuration file '%s': %s" % (configFilePath, e))
		fileLines = lines.splitlines()
		for l in fileLines:
			# strip comments
			l2 = re.sub("#.+", "", l).strip()
			#if self.echoDebugMessages:
			#	self.OutputHandler.outputMessage("Debug: '%s' => '%s'" % (l, l2))
			if l2 != "":
				lineSplit = l2.split(":::::::")
				if len(lineSplit) > 1:
					paramName = lineSplit[0]
					paramValue = lineSplit[1]
					if paramName in resultHashtable:
						existingParamValue = resultHashtable[paramName]
						if warnOnOverride:
							if existingParamValue != paramValue:
								self.OutputHandler.outputMessage("Warning: parameter '%s' already exists in the hashtable with value '%s', and will be overridden by the value '%s' which is defined later in the same file or a later file." % (paramName, existingParamValue, paramValue))
					resultHashtable[paramName] = paramValue
					
					if self.echoDebugMessages:
						self.OutputHandler.outputMessage("Set parameter hashtable value '%s' to '%s'" % (paramName, paramValue))
		return resultHashtable

	@staticmethod
	def ParseBool(boolString):
		bsl = boolString.lower()
		if bsl == "true":
			return True
		if bsl == "yes":
			return True
		if bsl == "y":
			return True
		if bsl == "1":
			return True
		return False
		
	def GetParametersFromHashtable(self, parameterHashtable):		
		if "headerNameKey" in parameterHashtable:
			self.headerNameKey = parameterHashtable["headerNameKey"]
		if "headerValueKey" in parameterHashtable:
			self.headerValueKey = parameterHashtable["headerValueKey"]
		if "encryptionKeyHex" in parameterHashtable:
			self.encryptionKeyHex = parameterHashtable["encryptionKeyHex"]
		if "headerValueUserAgent" in parameterHashtable:
			self.headerValueUserAgent = parameterHashtable["headerValueUserAgent"]
		if "accessKeyMode" in parameterHashtable:
			self.accessKeyMode = parameterHashtable["accessKeyMode"]
		if "paramNameAccessKey" in parameterHashtable:
			self.paramNameAccessKey = parameterHashtable["paramNameAccessKey"]
		if "paramNameOperation" in parameterHashtable:
			self.paramNameOperation = parameterHashtable["paramNameOperation"]
		if "paramNameDestinationHost" in parameterHashtable:
			self.paramNameDestinationHost = parameterHashtable["paramNameDestinationHost"]
		if "paramNameDestinationPort" in parameterHashtable:
			self.paramNameDestinationPort = parameterHashtable["paramNameDestinationPort"]
		if "paramNameConnectionID" in parameterHashtable:
			self.paramNameConnectionID = parameterHashtable["paramNameConnectionID"]
		if "paramNameData" in parameterHashtable:
			self.paramNameData = parameterHashtable["paramNameData"]
		if "paramNamePlaintextBlock" in parameterHashtable:
			self.paramNamePlaintextBlock = parameterHashtable["paramNamePlaintextBlock"]
		if "paramNameEncryptedBlock" in parameterHashtable:
			self.paramNameEncryptedBlock = parameterHashtable["paramNameEncryptedBlock"]
		if "dataBlockNameValueSeparatorB64" in parameterHashtable:
			self.dataBlockNameValueSeparatorB64 = parameterHashtable["dataBlockNameValueSeparatorB64"]
		if "dataBlockParamSeparatorB64" in parameterHashtable:
			self.dataBlockParamSeparatorB64 = parameterHashtable["dataBlockParamSeparatorB64"]
		if "opModeStringOpenConnection" in parameterHashtable:
			self.opModeStringOpenConnection = parameterHashtable["opModeStringOpenConnection"]
		if "opModeStringSendReceive" in parameterHashtable:
			self.opModeStringSendReceive = parameterHashtable["opModeStringSendReceive"]
		if "opModeStringCloseConnection" in parameterHashtable:
			self.opModeStringCloseConnection = parameterHashtable["opModeStringCloseConnection"]
		if "responseStringHide" in parameterHashtable:
			self.responseStringHide = parameterHashtable["responseStringHide"]
		if "responseStringConnectionCreated" in parameterHashtable:
			self.responseStringConnectionCreated = parameterHashtable["responseStringConnectionCreated"]
		if "responseStringConnectionClosed" in parameterHashtable:
			self.responseStringConnectionClosed = parameterHashtable["responseStringConnectionClosed"]
		if "responseStringData" in parameterHashtable:
			self.responseStringData = parameterHashtable["responseStringData"]
		if "responseStringNoData" in parameterHashtable:
			self.responseStringNoData = parameterHashtable["responseStringNoData"]
		if "responseStringErrorGeneric" in parameterHashtable:
			self.responseStringErrorGeneric = parameterHashtable["responseStringErrorGeneric"]
		if "responseStringErrorInvalidRequest" in parameterHashtable:
			self.responseStringErrorInvalidRequest = parameterHashtable["responseStringErrorInvalidRequest"]
		if "responseStringErrorConnectionNotFound" in parameterHashtable:
			self.responseStringErrorConnectionNotFound = parameterHashtable["responseStringErrorConnectionNotFound"]
		if "responseStringErrorConnectionOpenFailed" in parameterHashtable:
			self.responseStringErrorConnectionOpenFailed = parameterHashtable["responseStringErrorConnectionOpenFailed"]
		if "responseStringErrorConnectionCloseFailed" in parameterHashtable:
			self.responseStringErrorConnectionCloseFailed = parameterHashtable["responseStringErrorConnectionCloseFailed"]
		if "responseStringErrorConnectionSendFailed" in parameterHashtable:
			self.responseStringErrorConnectionSendFailed = parameterHashtable["responseStringErrorConnectionSendFailed"]
		if "responseStringErrorConnectionReceiveFailed" in parameterHashtable:
			self.responseStringErrorConnectionReceiveFailed = parameterHashtable["responseStringErrorConnectionReceiveFailed"]
		if "responseStringErrorDecryptFailed" in parameterHashtable:
			self.responseStringErrorDecryptFailed = parameterHashtable["responseStringErrorDecryptFailed"]
		if "responseStringErrorEncryptFailed" in parameterHashtable:
			self.responseStringErrorEncryptFailed = parameterHashtable["responseStringErrorEncryptFailed"]
		if "responseStringErrorEncryptionNotSupported" in parameterHashtable:
			self.responseStringErrorEncryptionNotSupported = parameterHashtable["responseStringErrorEncryptionNotSupported"]
		if "responseStringPrefixB64" in parameterHashtable:
			self.responseStringPrefixB64 = parameterHashtable["responseStringPrefixB64"]
		if "responseStringSuffixB64" in parameterHashtable:
			self.responseStringSuffixB64 = parameterHashtable["responseStringSuffixB64"]
		if "logFilePath" in parameterHashtable:
			self.logFilePath = parameterHashtable["logFilePath"]
		if "fileGenerationAppNameShort" in parameterHashtable:
			self.fileGenerationAppNameShort = parameterHashtable["fileGenerationAppNameShort"]
		if "writeToLog" in parameterHashtable:
			tv = parameterHashtable["writeToLog"]
			try:
				self.writeToLog = self.ParseBool(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as a boolean (true/false) value" % (tv))
		if "writeToStandardOut" in parameterHashtable:
			tv = parameterHashtable["writeToStandardOut"]
			try:
				self.writeToStandardOut = self.ParseBool(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as a boolean (true/false) value" % (tv))
		if "echoData" in parameterHashtable:
			tv = parameterHashtable["echoData"]
			try:
				self.echoData = self.ParseBool(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as a boolean (true/false) value" % (tv))
		if "echoHTTPBody" in parameterHashtable:
			tv = parameterHashtable["echoHTTPBody"]
			try:
				self.echoHTTPBody = self.ParseBool(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as a boolean (true/false) value" % (tv))
		if "echoDebugMessages" in parameterHashtable:
			tv = parameterHashtable["echoDebugMessages"]
			try:
				self.echoDebugMessages = self.ParseBool(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as a boolean (true/false) value" % (tv))
		if "autoscaleClientSocketTimeout" in parameterHashtable:
			tv = parameterHashtable["autoscaleClientSocketTimeout"]
			try:
				self.autoscaleClientSocketTimeout = self.ParseBool(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as a boolean (true/false) value" % (tv))
		if "useIPV6ClientSocketOnServer" in parameterHashtable:
			tv = parameterHashtable["useIPV6ClientSocketOnServer"]
			try:
				self.useIPV6ClientSocketOnServer = self.ParseBool(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as a boolean (true/false) value" % (tv))				
		if "statsUpdateIterations" in parameterHashtable:
			tv = parameterHashtable["statsUpdateIterations"]
			try:
				self.statsUpdateIterations = int(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as an integer value" % (tv))
		if "clientToServerBlockSize" in parameterHashtable:
			tv = parameterHashtable["clientToServerBlockSize"]
			try:
				self.clientToServerBlockSize = int(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as an integer value" % (tv))		
		if "clientSocketBufferSize" in parameterHashtable:
			tv = parameterHashtable["clientSocketBufferSize"]
			try:
				self.clientSocketBufferSize = int(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as an integer value" % (tv))		
		if "clientBlockSizeLimitFromServer" in parameterHashtable:
			tv = parameterHashtable["clientBlockSizeLimitFromServer"]
			try:
				self.clientBlockSizeLimitFromServer = int(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as an integer value" % (tv))
		if "serverToClientBlockSize" in parameterHashtable:
			tv = parameterHashtable["serverToClientBlockSize"]
			try:
				self.serverToClientBlockSize = int(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as an integer value" % (tv))
		if "serverSocketMaxUnusedIterations" in parameterHashtable:
			tv = parameterHashtable["serverSocketMaxUnusedIterations"]
			try:
				self.serverSocketMaxUnusedIterations = int(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as an integer value" % (tv))
		if "serverSocketIOTimeout" in parameterHashtable:
			tv = parameterHashtable["serverSocketIOTimeout"]
			try:
				self.serverSocketIOTimeout = int(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as an integer value" % (tv))
		if "serverSocketSendBufferSize" in parameterHashtable:
			tv = parameterHashtable["serverSocketSendBufferSize"]
			try:
				serverSocketSendBufferSize = int(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as an integer value" % (tv))
		if "serverSocketReceiveBufferSize" in parameterHashtable:
			tv = parameterHashtable["serverSocketReceiveBufferSize"]
			try:
				self.serverSocketReceiveBufferSize = int(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as an integer value" % (tv))
		if "clientSocketTimeoutBase" in parameterHashtable:
			tv = parameterHashtable["clientSocketTimeoutBase"]
			try:
				self.clientSocketTimeoutBase = float(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as a floating-point value" % (tv))
		if "clientSocketTimeoutVariation" in parameterHashtable:
			tv = parameterHashtable["clientSocketTimeoutVariation"]
			try:
				self.clientSocketTimeoutVariation = float(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as a floating-point value" % (tv))
		if "clientSocketTimeoutScalingMultiplier" in parameterHashtable:
			tv = parameterHashtable["clientSocketTimeoutScalingMultiplier"]
			try:
				self.clientSocketTimeoutScalingMultiplier = float(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as a floating-point value" % (tv))
		if "clientSocketTimeoutMax" in parameterHashtable:
			tv = parameterHashtable["clientSocketTimeoutMax"]
			try:
				self.clientSocketTimeoutMax = float(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as a floating-point value" % (tv))
		if "clientSocketTimeoutMin" in parameterHashtable:
			tv = parameterHashtable["clientSocketTimeoutMin"]
			try:
				self.clientSocketTimeoutMin = float(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as a floating-point value" % (tv))
		if "clientBlockTransmitSleepTime" in parameterHashtable:
			tv = parameterHashtable["clientBlockTransmitSleepTime"]
			try:
				self.clientBlockTransmitSleepTime = float(tv)
			except:
				self.OutputHandler.outputMessage("Error: could not parse '%s' as a floating-point value" % (tv))

	@staticmethod
	def WriteIfPresent(parameterHashtable, file, parameterName, parameterValue, formatString):
		if parameterName in parameterHashtable:
			s1 = '%s:::::::%s' % (parameterName, formatString)
			file.write(s1 % (parameterValue))
			file.write(os.linesep)
	
	def ReplaceIfRandomizationPlaceholder(self, parameterHashtable, parameterName, currentParameterValue, newParameterValue):
		if parameterName in parameterHashtable:
			if parameterHashtable[parameterName] == self.randomizedValuePlaceholder:
				return newParameterValue
		return currentParameterValue
	
	@staticmethod
	def MakeDir(newDir, outputHandler):
		try:
			os.mkdir(newDir)
			return True
		except Exception as e:
			outputHandler.outputMessage('Error: could not create a directory named "%s" - %s' % (newDir, e))
			return False

	@staticmethod
	def CopyFile(source, destination, outputHandler):
		try:
			copyfile(source, destination)
			return True
		except Exception as e:
			outputHandler.outputMessage('Error copying "%s" to "%s" - %s' % (source, destination, e))
			return False

	@staticmethod
	def ZipDir(sourceDirectory, outputFilePath, outputHandler):
		currentDir = os.getcwd()
		try:
			os.chdir(sourceDirectory)
			#relroot = os.path.abspath(os.path.join(sourceDirectory, os.pardir))
			relroot = os.path.abspath(os.path.join(sourceDirectory))
			#with zipfile.ZipFile(outputFilePath, "w", zipfile.ZIP_DEFLATED) as zip:
			with zipfile.ZipFile(outputFilePath, "w") as zip:
				for root, dirs, files in os.walk(sourceDirectory):
					# add directory (needed for empty dirs)
					# this is commented out because Tomcat 8 will reject WAR files with "./" in them.
					#zip.write(root, os.path.relpath(root, relroot))
					for file in files:
						filename = os.path.join(root, file)
						if os.path.isfile(filename): # regular files only
							arcname = os.path.join(os.path.relpath(root, relroot), file)
							zip.write(filename, arcname)
			return True
		except Exception as e:
			outputHandler.outputMessage('Error creating zip file "%s" from directory "%s" - %s' % (outputFilePath, sourceDirectory, e))
			return False
		os.chdir(currentDir)


	def WriteParametersBasedOnHashtable(self, parameterHashtable, outputFilePath):
		try:
			f = open(outputFilePath, 'wb')
			self.WriteIfPresent(parameterHashtable, f, 'headerNameKey', self.headerNameKey, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'headerValueKey', self.headerValueKey, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'encryptionKeyHex', self.encryptionKeyHex, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'headerValueUserAgent', self.headerValueUserAgent, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'accessKeyMode', self.accessKeyMode, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'paramNameAccessKey', self.paramNameAccessKey, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'paramNameOperation', self.paramNameOperation, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'paramNameDestinationHost', self.paramNameDestinationHost, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'paramNameDestinationPort', self.paramNameDestinationPort, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'paramNameConnectionID', self.paramNameConnectionID, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'paramNameData', self.paramNameData, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'paramNamePlaintextBlock', self.paramNamePlaintextBlock, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'paramNameEncryptedBlock', self.paramNameEncryptedBlock, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'dataBlockNameValueSeparatorB64', self.dataBlockNameValueSeparatorB64, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'dataBlockParamSeparatorB64', self.dataBlockParamSeparatorB64, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'opModeStringOpenConnection', self.opModeStringOpenConnection, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'opModeStringSendReceive', self.opModeStringSendReceive, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'opModeStringCloseConnection', self.opModeStringCloseConnection, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'responseStringHide', self.responseStringHide, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'responseStringConnectionCreated', self.responseStringConnectionCreated, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'responseStringConnectionClosed', self.responseStringConnectionClosed, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'responseStringData', self.responseStringData, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'responseStringNoData', self.responseStringNoData, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'responseStringErrorGeneric', self.responseStringErrorGeneric, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'responseStringErrorInvalidRequest', self.responseStringErrorInvalidRequest, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'responseStringErrorConnectionNotFound', self.responseStringErrorConnectionNotFound, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'responseStringErrorConnectionOpenFailed', self.responseStringErrorConnectionOpenFailed, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'responseStringErrorConnectionCloseFailed', self.responseStringErrorConnectionCloseFailed, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'responseStringErrorConnectionSendFailed', self.responseStringErrorConnectionSendFailed, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'responseStringErrorConnectionReceiveFailed', self.responseStringErrorConnectionReceiveFailed, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'responseStringErrorDecryptFailed', self.responseStringErrorDecryptFailed, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'responseStringErrorEncryptFailed', self.responseStringErrorEncryptFailed, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'responseStringErrorEncryptionNotSupported', self.responseStringErrorEncryptionNotSupported, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'responseStringPrefixB64', self.responseStringPrefixB64, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'responseStringSuffixB64', self.responseStringSuffixB64, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'logFilePath', self.logFilePath, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'fileGenerationAppNameShort', self.fileGenerationAppNameShort, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'writeToLog', self.writeToLog, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'writeToStandardOut', self.writeToStandardOut, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'echoData', self.echoData, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'echoHTTPBody', self.echoHTTPBody, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'echoDebugMessages', self.echoDebugMessages, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'autoscaleClientSocketTimeout', self.autoscaleClientSocketTimeout, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'statsUpdateIterations', self.statsUpdateIterations, '%i')
			self.WriteIfPresent(parameterHashtable, f, 'clientToServerBlockSize', self.clientToServerBlockSize, '%i')
			self.WriteIfPresent(parameterHashtable, f, 'clientSocketBufferSize', self.clientSocketBufferSize, '%i')
			self.WriteIfPresent(parameterHashtable, f, 'clientBlockSizeLimitFromServer', self.clientBlockSizeLimitFromServer, '%i')
			self.WriteIfPresent(parameterHashtable, f, 'useIPV6ClientSocketOnServer', self.useIPV6ClientSocketOnServer, '%s')
			self.WriteIfPresent(parameterHashtable, f, 'serverToClientBlockSize', self.serverToClientBlockSize, '%i')
			self.WriteIfPresent(parameterHashtable, f, 'serverSocketMaxUnusedIterations', self.serverSocketMaxUnusedIterations, '%i')
			self.WriteIfPresent(parameterHashtable, f, 'serverSocketIOTimeout', self.serverSocketIOTimeout, '%i')
			self.WriteIfPresent(parameterHashtable, f, 'serverSocketSendBufferSize', self.serverSocketSendBufferSize, '%i')
			self.WriteIfPresent(parameterHashtable, f, 'serverSocketReceiveBufferSize', self.serverSocketReceiveBufferSize, '%i')
			self.WriteIfPresent(parameterHashtable, f, 'clientSocketTimeoutBase', self.clientSocketTimeoutBase, '%f')
			self.WriteIfPresent(parameterHashtable, f, 'clientSocketTimeoutVariation', self.clientSocketTimeoutVariation, '%f')
			self.WriteIfPresent(parameterHashtable, f, 'clientSocketTimeoutScalingMultiplier', self.clientSocketTimeoutScalingMultiplier, '%f')
			self.WriteIfPresent(parameterHashtable, f, 'clientSocketTimeoutMax', self.clientSocketTimeoutMax, '%f')
			self.WriteIfPresent(parameterHashtable, f, 'clientSocketTimeoutMin', self.clientSocketTimeoutMin, '%f')
			self.WriteIfPresent(parameterHashtable, f, 'clientBlockTransmitSleepTime', self.clientBlockTransmitSleepTime, '%f')		
			f.close()
			self.OutputHandler.outputMessage('Created client configuration file "%s"' % (outputFilePath))
		except Exception as e:
			self.OutputHandler.outputMessage('Error writing to "%s" - %s' % (outputFilePath, e))

	def LoadParameters(self, parameterFileArray, warnOnOverride):
		parameterHashtable = {}
		for pf in parameterFileArray:
			parameterHashtable = self.GetConfigFileData(parameterHashtable, pf, warnOnOverride)
		self.GetParametersFromHashtable(parameterHashtable)
		return parameterHashtable

	def ShowParameters(self):
		self.OutputHandler.outputMessage('HTTP Request Header Name for Access Key: %s' % self.headerNameKey)
		self.OutputHandler.outputMessage('Access Key: %s' % self.headerValueKey)
		self.OutputHandler.outputMessage('Encryption Key: %s' % self.encryptionKeyHex)
		self.OutputHandler.outputMessage('HTTP User-Agent Request Header Value: %s' % self.headerValueUserAgent)
		self.OutputHandler.outputMessage('Send Access Key As: %s' % self.accessKeyMode)
		self.OutputHandler.outputMessage('Request Body Parameter Name for Access Key: %s' % self.paramNameAccessKey)
		self.OutputHandler.outputMessage('Request Body Parameter Name for Operation Type: %s' % self.paramNameOperation)
		self.OutputHandler.outputMessage('Request Body Parameter Name for Destination Host: %s' % self.paramNameDestinationHost)
		self.OutputHandler.outputMessage('Request Body Parameter Name for Destination Port: %s' % self.paramNameDestinationPort)
		self.OutputHandler.outputMessage('Request Body Parameter Name for Connection ID: %s' % self.paramNameConnectionID)
		self.OutputHandler.outputMessage('Request Body Parameter Name for Tunneled Data: %s' % self.paramNameData)
		self.OutputHandler.outputMessage('Request Body Parameter Name for Plaintext Request Block: %s' % self.paramNamePlaintextBlock)
		self.OutputHandler.outputMessage('Request Body Parameter Name for Encrypted Request Block: %s' % self.paramNameEncryptedBlock)
		self.OutputHandler.outputMessage('Encapsulated Request Body Base64-Encoded Name/Value Separator: %s' % self.dataBlockNameValueSeparatorB64)
		self.OutputHandler.outputMessage('Encapsulated Request Body Base64-Encoded Parameter Separator: %s' % self.dataBlockParamSeparatorB64)
		self.OutputHandler.outputMessage('Request Body Parameter Value for Operation "Open Connection": %s' % self.opModeStringOpenConnection)
		self.OutputHandler.outputMessage('Request Body Parameter Value for Operation "Send/Receive": %s' % self.opModeStringSendReceive)
		self.OutputHandler.outputMessage('Request Body Parameter Value for Operation "Close Connection": %s' % self.opModeStringCloseConnection)
		self.OutputHandler.outputMessage('Response Code for "Incorrect Access Key (Hide)": %s' % self.responseStringHide)
		self.OutputHandler.outputMessage('Response Code for "Connection Created": %s' % self.responseStringConnectionCreated)
		self.OutputHandler.outputMessage('Response Code for "Connection Closed": %s' % self.responseStringConnectionClosed)
		self.OutputHandler.outputMessage('Response Prefix for Tunneled Data: %s' % self.responseStringData)
		self.OutputHandler.outputMessage('Response Code for "No Data to Send": %s' % self.responseStringNoData)
		self.OutputHandler.outputMessage('Response Code for "Generic Error": %s' % self.responseStringErrorGeneric)
		self.OutputHandler.outputMessage('Response Code for "Invalid Request": %s' % self.responseStringErrorInvalidRequest)
		self.OutputHandler.outputMessage('Response Code for "Connection Not Found": %s' % self.responseStringErrorConnectionNotFound)
		self.OutputHandler.outputMessage('Response Code for "Failed to Open Connection": %s' % self.responseStringErrorConnectionOpenFailed)
		self.OutputHandler.outputMessage('Response Code for "Failed to Close Connection": %s' % self.responseStringErrorConnectionCloseFailed)
		self.OutputHandler.outputMessage('Response Code for "Failed to Send Data (Server-Side)": %s' % self.responseStringErrorConnectionSendFailed)
		self.OutputHandler.outputMessage('Response Code for "Failed to Receive Data (Server-Side)": %s' % self.responseStringErrorConnectionReceiveFailed)
		self.OutputHandler.outputMessage('Response Code for "Decryption Failure": %s' % self.responseStringErrorDecryptFailed)
		self.OutputHandler.outputMessage('Response Code for "Encryption Failure": %s' % self.responseStringErrorEncryptFailed)
		self.OutputHandler.outputMessage('Response Code for "Encryption Not Supported": %s' % self.responseStringErrorEncryptionNotSupported)
		self.OutputHandler.outputMessage('Base64-Encoded Response Prefix: %s' % self.responseStringPrefixB64)
		self.OutputHandler.outputMessage('Base64-Encoded Response Suffix: %s' % self.responseStringSuffixB64)
		self.OutputHandler.outputMessage('Log File Path: %s' % self.logFilePath)
		self.OutputHandler.outputMessage('Application Name: %s' % self.fileGenerationAppNameShort)
		self.OutputHandler.outputMessage('Write to Log File: %s' % self.writeToLog)
		self.OutputHandler.outputMessage('Write to Standard Output: %s' % self.writeToStandardOut)
		self.OutputHandler.outputMessage('Output Raw Tunneled Data: %s' % self.echoData)
		self.OutputHandler.outputMessage('Output HTTP Request/Response Bodies: %s' % self.echoHTTPBody)
		self.OutputHandler.outputMessage('Output Debugging Messages: %s' % self.echoDebugMessages)
		self.OutputHandler.outputMessage('Automatically Adjust Client Socket Timeout: %s' % self.autoscaleClientSocketTimeout)
		self.OutputHandler.outputMessage('Request/Response Iterations Between Tunneled Data Statistics Output: %i' % self.statsUpdateIterations)
		self.OutputHandler.outputMessage('Maximum Number of Bytes for Server to Return to Client Component With Each Send/Receive Operation: %i bytes' % self.clientToServerBlockSize)
		self.OutputHandler.outputMessage('Client Socket Buffer Size: %i bytes' % self.clientSocketBufferSize)
		self.OutputHandler.outputMessage('Block Size for Retransmission to Clients: %i bytes' % self.clientBlockSizeLimitFromServer)	
		self.OutputHandler.outputMessage('Sleep Time Between Client Socket Blocks: %f seconds' % self.clientBlockTransmitSleepTime)
		self.OutputHandler.outputMessage('Base Client Socket Timeout: %f seconds' % self.clientSocketTimeoutBase)
		self.OutputHandler.outputMessage('Client Socket Timeout Variation Range: %f' % self.clientSocketTimeoutVariation)
		self.OutputHandler.outputMessage('Client Socket Timeout Scaling Multiplier: %f' % self.clientSocketTimeoutScalingMultiplier)
		self.OutputHandler.outputMessage('Client Socket Maximum Timeout: %f' % self.clientSocketTimeoutMax)
		self.OutputHandler.outputMessage('Client Socket Minimum Timeout: %f' % self.clientSocketTimeoutMin)	
		self.OutputHandler.outputMessage('Maximum Number of Bytes for Server to Return to Client Component With Each Send/Receive Operation: %i' % self.serverToClientBlockSize)
		self.OutputHandler.outputMessage('Maximum Unused Request/Response Iterations Before Abandoning Server-Side Socket: %i' % self.serverSocketMaxUnusedIterations)
		self.OutputHandler.outputMessage('Use IPv6 for Server-Side Client Sockets (See Documentation): %s' % self.useIPV6ClientSocketOnServer)
		self.OutputHandler.outputMessage('Server-Side Socket IO Timeout: %i milliseconds' % self.serverSocketIOTimeout)
		self.OutputHandler.outputMessage('Server-Side Socket Send Buffer Size: %i bytes' % self.serverSocketSendBufferSize)
		self.OutputHandler.outputMessage('Server-Side Socket Receive Buffer Size: %i bytes' % self.serverSocketReceiveBufferSize)

	@staticmethod
	def ReplacePlaceholderValue(content, parameterHashtable, parameterName):
		placeholder = '%PLACEHOLDER_' + parameterName + '%'
		return content.replace(placeholder, parameterHashtable[parameterName])

	def GetFileAsString(self, inputFilePath):
		result = ''
		try:
			f = open(inputFilePath, 'rb')
			result = f.read()
			f.close()
		except Exception as e:
			outputHandler.outputMessage('Could not open the file "%s" - %s' % (inputFilePath, e))
			result = ''
		return result
		
	def GenerateServerFileFromTemplate(self, templateDirectory, templateFileName, outputDirectory, parameterHashtable):
		templateFilePath = os.path.join(templateDirectory, templateFileName)
		outputFilePath = os.path.join(outputDirectory, templateFileName)
		templateContent = self.GetFileAsString(templateFilePath)
		if templateContent == "":
			self.OutputHandler.outputMessage('The template file "%s" could not be found, did not contain any content, or was not accessible to the current user, and no corresponding output file will be generated.' % (templateFilePath))
			return
		outputFileContent = templateContent[:]
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'useIPV6ClientSocketOnServer')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'serverToClientBlockSize')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'serverSocketMaxUnusedIterations')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'serverSocketIOTimeout')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'serverSocketSendBufferSize')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'serverSocketReceiveBufferSize')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'headerValueKey')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'encryptionKeyHex')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'headerNameKey')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'accessKeyMode')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'paramNameAccessKey')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'paramNameOperation')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'paramNameDestinationHost')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'paramNameDestinationPort')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'paramNameConnectionID')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'paramNameData')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'paramNamePlaintextBlock')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'paramNameEncryptedBlock')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'dataBlockNameValueSeparatorB64')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'dataBlockParamSeparatorB64')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'opModeStringOpenConnection')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'opModeStringSendReceive')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'opModeStringCloseConnection')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'responseStringHide')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'responseStringConnectionCreated')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'responseStringConnectionClosed')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'responseStringData')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'responseStringNoData')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'responseStringErrorGeneric')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'responseStringErrorInvalidRequest')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'responseStringErrorConnectionNotFound')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'responseStringErrorConnectionOpenFailed')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'responseStringErrorConnectionCloseFailed')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'responseStringErrorConnectionSendFailed')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'responseStringErrorConnectionReceiveFailed')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'responseStringErrorDecryptFailed')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'responseStringErrorEncryptFailed')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'responseStringErrorEncryptionNotSupported')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'responseStringPrefixB64')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'responseStringSuffixB64')
		outputFileContent = self.ReplacePlaceholderValue(outputFileContent, parameterHashtable, 'fileGenerationAppNameShort')
		try:
			f = open(outputFilePath, 'wb')
			f.write(outputFileContent)
			f.close()
			self.OutputHandler.outputMessage('Created server file "%s"' % (outputFilePath))
		except Exception as e:
			self.OutputHandler.outputMessage('Error: The output file file "%s" could not be created - %s' % (outputFilePath, e))