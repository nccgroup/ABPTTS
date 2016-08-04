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

# Client component of A Black Path Toward The Sun

# it is very likely that you will need to install the httplib2 and pycrypto Python libraries to use ABPTTS.
# e.g.:
# pip install httplib2
# pip install pycrypto
#
# pycrypto may require the installation of additional OS-level packages to obtain the Python headers, e.g. on Debian:
# apt-get install python-dev
# ...or on Windows, download and install https://www.microsoft.com/en-us/download/details.aspx?id=44266

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

import libabptts

from Crypto.Cipher import AES
from datetime import datetime, date, tzinfo, timedelta

outputHandler = libabptts.OutputHandler()
conf = libabptts.ABPTTSConfiguration(outputHandler)

# \\\\\\ Do not modify below this line unless you know what you're doing! //////
#

socketTimeoutCurrent = 1.0
clientSocketTimeoutVariationNeg = 0.0

httpConnectionTimeout = 10.0
httpRequestRetryLimit = 12
httpRequestRetryDelay = 5.0

unsafeTLSMode = False

runServer = 1

clientToServerBuffer = ""

responseStringWrapperText = []

encryptionKey = []

dataBlockNameValueSeparator = ""
dataBlockParamSeparator = ""

encryptionBlockSize = 16

def showBanner():
	outputHandler.outputMessage("---===[[[ A Black Path Toward The Sun ]]]===---")
	outputHandler.outputMessage("   --==[[       -  Client  -          ]]==--")
	outputHandler.outputMessage("            Ben Lincoln, NCC Group")
	outputHandler.outputMessage('           Version %s - %s' % (libabptts.ABPTTSVersion.GetVersionString(), libabptts.ABPTTSVersion.GetReleaseDateString()))

#@staticmethod
def pad(s, blockSize):
    return s + (blockSize - len(s) % blockSize) * chr(blockSize - len(s) % blockSize)
	
#@staticmethod
def unpad(s):
	return s[:-ord(s[len(s)-1:])]

def encrypt(plaintext, key, blockSize):
	iv = bytearray(os.urandom(blockSize))
	iv = str(iv)
	reIV = bytearray(os.urandom(blockSize))
	reIV = str(reIV)
	rivPlaintext = pad(reIV + str(plaintext), blockSize)
	#print "rivPlaintext: " + base64.b64encode(rivPlaintext)
	cipher = AES.new(key, AES.MODE_CBC, IV=iv)
	return iv + str(cipher.encrypt(rivPlaintext))

def decrypt(ciphertext, key, blockSize):
	#print "ciphertext: " + base64.b64encode(ciphertext)
	iv = ciphertext[0:blockSize]
	#print "iv: " + base64.b64encode(iv)
	#print "ciphertext: " + base64.b64encode(ciphertext)
	rivCiphertext = ciphertext[blockSize:]
	#print "rivCiphertext: " + base64.b64encode(rivCiphertext)
	rivCiphertext = str(rivCiphertext)
	#print "rivCiphertext: " + base64.b64encode(rivCiphertext)
	cipher = AES.new(key, AES.MODE_CBC, IV=iv)
	rivPlaintext = cipher.decrypt(rivCiphertext)
	#print "rivPlaintext: " + base64.b64encode(rivPlaintext)
	rivPlaintext = str(rivPlaintext)
	#print "rivPlaintext: " + base64.b64encode(rivPlaintext)
	rivPlaintext = unpad(rivPlaintext)
	#print "rivPlaintext: " + base64.b64encode(rivPlaintext)
	#rivPlaintext = str(cipher.decrypt(str(rivCiphertext)))
	#print "rivPlaintext: " + base64.b64encode(rivPlaintext)
	#print "rivPlaintext: " + base64.b64encode(rivPlaintext[blockSize:])
	return rivPlaintext[blockSize:]
	#return rivPlaintext

def outputTunnelIOMessage(direction, clientAddress, listeningAddress, serverAddress, connectionID, category, message):
	result = '[(%s)' % (direction)
	if direction == "S2C":
		result = '%s %s -> %s -> %s' % (result, serverAddress, listeningAddress, clientAddress)
	else:
		result = '%s %s -> %s -> %s' % (result, clientAddress, listeningAddress, serverAddress)
		
	if connectionID != None:
		if connectionID.strip() != "":
			result = '%s (Connection ID: %s)' % (result, connectionID)			
	if category != None:
		if category.strip() != "":
			result = '%s (%s)' % (result, category)
			
	result = '%s]: %s' % (result, message)
		
	outputHandler.outputMessage(result)
			
def getServerResponseFromResponseBody(responseBody, wrapperTextArray, formattedServerAddress, formattedClientAddress, listeningAddress, connectionID):
	result = responseBody.strip()
	for wt in wrapperTextArray:
		result = result.replace(wt, "")
	result = result.strip()
	if conf.echoHTTPBody:
		outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, 'HTTP Response Body', '%s%s' % (os.linesep, responseBody))
		outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, 'HTTP Response Body Without Wrapper Text', '%s%s' % (os.linesep, result))
	return result
	
def getCookieFromServerResponse(connectionID, currentCookie, serverResponse):
	newCookie = currentCookie
	try:
		if 'set-cookie' in serverResponse:
			newCookie = serverResponse['set-cookie']
			if connectionID.strip() != "":
				outputHandler.outputMessage('[Connection ID %s]: Server set cookie %s' % (connectionID, newCookie))
			else:
				outputHandler.outputMessage('Server set cookie %s' % (newCookie))
	except:
		newCookie = currentCookie
	return newCookie

def child(clientsock, clientAddr, listeningAddress, forwardingURL, destAddress, destPort):
	global clientToServerBuffer
	global socketTimeoutCurrent
	try:
		formattedServerAddress = '%s:%s' % (destAddress, destPort)
		formattedClientAddress = '%s:%s' % (clientAddr[0], clientAddr[1])
		socketTimeoutCurrent = conf.clientSocketTimeoutBase
		clientsock.settimeout(socketTimeoutCurrent)
		closeConnections = 0
		runChildLoop = 1
		if conf.accessKeyMode == "header":
			headers = {'User-Agent': conf.headerValueUserAgent, 'Content-type': 'application/x-www-form-urlencoded', conf.headerNameKey: conf.headerValueKey, 'Connection': 'close'}
		else:
			headers = {'User-Agent': conf.headerValueUserAgent, 'Content-type': 'application/x-www-form-urlencoded', 'Connection': 'close'}
		connectionID = ""
		cookieVal = ""
		body = {}
		http = httplib2.Http(timeout=httpConnectionTimeout, disable_ssl_certificate_validation=unsafeTLSMode)
		response = ""
		content = ""
		cookieVal = ""
		
		try:
			outputHandler.outputMessage('Connecting to %s:%i via %s' % (destAddress, destPort, forwardingURL))
			
			plaintextMessage = conf.paramNameOperation + dataBlockNameValueSeparator + conf.opModeStringOpenConnection + dataBlockParamSeparator + conf.paramNameDestinationHost + dataBlockNameValueSeparator + destAddress + dataBlockParamSeparator + conf.paramNameDestinationPort + dataBlockNameValueSeparator + str(destPort)
			
			if len(encryptionKey) > 0:
				#plaintextMessage = conf.paramNameOperation + dataBlockNameValueSeparator + conf.opModeStringOpenConnection + dataBlockParamSeparator + conf.paramNameDestinationHost + dataBlockNameValueSeparator + destAddress + dataBlockParamSeparator + conf.paramNameDestinationPort + dataBlockNameValueSeparator + str(destPort)
				#print "Plaintext message: " + plaintextMessage
				ciphertextMessage = base64.b64encode(encrypt(plaintextMessage, str(encryptionKey), encryptionBlockSize))
				if conf.accessKeyMode == "header":
					body = {conf.paramNameEncryptedBlock: ciphertextMessage }
				else:
					body = {conf.paramNameAccessKey: conf.headerValueKey, conf.paramNameEncryptedBlock: ciphertextMessage }
			else:
#				body = {conf.paramNameOperation: conf.opModeStringOpenConnection, conf.paramNameDestinationHost: destAddress, conf.paramNameDestinationPort: destPort }
				plaintextMessage = base64.b64encode(plaintextMessage)
				if conf.accessKeyMode == "header":
					body = {conf.paramNamePlaintextBlock: plaintextMessage }
				else:
					body = {conf.paramNameAccessKey: conf.headerValueKey, conf.paramNamePlaintextBlock: plaintextMessage }
			encodedBody = urllib.urlencode(body)
			if conf.echoHTTPBody:
				outputTunnelIOMessage('C2S', formattedClientAddress, listeningAddress, formattedServerAddress, '', 'HTTP Request Body', '%s%s' % (os.linesep, encodedBody))
			
			http = httplib2.Http(timeout=httpConnectionTimeout, disable_ssl_certificate_validation=unsafeTLSMode)
			response, content = http.request(forwardingURL, 'POST', headers=headers, body=encodedBody)
			content = getServerResponseFromResponseBody(content, responseStringWrapperText, formattedServerAddress, formattedClientAddress, listeningAddress, connectionID)
			cookieVal = getCookieFromServerResponse(connectionID, cookieVal, response)
			headers['Cookie'] = cookieVal
			if conf.responseStringConnectionCreated in content:
				responseArray = content.split(" ")
				if len(responseArray) > 1:
					connectionID = responseArray[1]
					outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'Server created connection ID %s' % (connectionID))
			else:
				runChildLoop = 0
				outputHandler.outputMessage('Error: could not create connection. Raw server response: ' + content)
				
			iterationCounter = 0
			clientSentByteCounter = 0
			serverSentByteCounter = 0
			clientHasClosedConnection = False
				
			while runChildLoop == 1:
				clientMessageB64 = ""
				serverMessageB64 = ""
				content = ""
				scaleSocketTimeoutUp = False
				scaleSocketTimeoutDown = False
				clientSocketTimedOut = False
				trafficSent = False
				
				if clientHasClosedConnection == False:
					try:
						currentFromClient = clientsock.recv(conf.clientSocketBufferSize)
						if currentFromClient:
							clientToServerBuffer += currentFromClient
						else:
							clientHasClosedConnection = True					

					except socket.error as e:
						if "timed out" not in str(e):
							raise e
						else:
							clientSocketTimedOut = True

				c2sBufferLength = len(clientToServerBuffer)
				if c2sBufferLength > 0:
					trafficSent = True
					toServerByteCount = conf.clientToServerBlockSize
					if toServerByteCount > c2sBufferLength:
						toServerByteCount = c2sBufferLength
					fromClient = ""
					if toServerByteCount < c2sBufferLength:
						fromClient = clientToServerBuffer[0:toServerByteCount]
						clientToServerBuffer = clientToServerBuffer[toServerByteCount:]
					else:
						fromClient = clientToServerBuffer[:]
						clientToServerBuffer = ""
					clientSentByteCounter = clientSentByteCounter + len(fromClient)
					
					clientMessageB64 = base64.b64encode(fromClient)
					if conf.echoDebugMessages:
						outputTunnelIOMessage('C2S', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', '%s%i bytes' % (os.linesep, len(fromClient)))
					if conf.echoData:
						outputTunnelIOMessage('C2S', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, 'Raw Data (Plaintext) (base64)', '%s%s' % (os.linesep, clientMessageB64))
				else:
					if clientHasClosedConnection:
						outputTunnelIOMessage('C2S', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'Client closed channel')
						clientMessageB64 = ""
						runChildLoop = 0
						closeConnections = 1
							
				try:
					plaintextMessage = conf.paramNameOperation + dataBlockNameValueSeparator + conf.opModeStringSendReceive + dataBlockParamSeparator + conf.paramNameConnectionID + dataBlockNameValueSeparator + connectionID + dataBlockParamSeparator + conf.paramNameData + dataBlockNameValueSeparator + clientMessageB64
					if len(encryptionKey) > 0:
						#plaintextMessage = conf.paramNameOperation + dataBlockNameValueSeparator + conf.opModeStringSendReceive + dataBlockParamSeparator + conf.paramNameConnectionID + dataBlockNameValueSeparator + connectionID + dataBlockParamSeparator + conf.paramNameData + dataBlockNameValueSeparator + clientMessageB64
						ciphertextMessage = base64.b64encode(encrypt(plaintextMessage, str(encryptionKey), encryptionBlockSize))
						if conf.echoData:
							outputTunnelIOMessage('C2S', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, 'Raw Data (Encrypted) (base64)', '%s%s' % (os.linesep, ciphertextMessage))
						if conf.accessKeyMode == "header":
							body = {conf.paramNameEncryptedBlock: ciphertextMessage }
						else:
							body = {conf.paramNameAccessKey: conf.headerValueKey, conf.paramNameEncryptedBlock: ciphertextMessage }
					else:
						#body = {conf.paramNameOperation: conf.opModeStringSendReceive, conf.paramNameConnectionID: connectionID, conf.paramNameData: clientMessageB64 }
						plaintextMessage = base64.b64encode(plaintextMessage)
						
						if conf.accessKeyMode == "header":
							body = {conf.paramNamePlaintextBlock: plaintextMessage }
						else:
							body = {conf.paramNameAccessKey: conf.headerValueKey, conf.paramNamePlaintextBlock: plaintextMessage }

					encodedBody = urllib.urlencode(body)
					if conf.echoHTTPBody:
							outputTunnelIOMessage('C2S', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, 'HTTP Request Body', '%s%s' % (os.linesep, encodedBody))
					response = []
					madeRequest = False
					httpRetryCount = 0
					while madeRequest == False:
						try:
							response, content = http.request(forwardingURL, 'POST', headers=headers, body=encodedBody)
							madeRequest = True
						except Exception as e:
							httpRetryCount += 1
							if httpRetryCount > httpRequestRetryLimit:
								outputTunnelIOMessage('C2S', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'Error - HTTP request retry limit of %i has been reached, and this request will not be retried. Final error was: %s' % (httpRequestRetryLimit, e))
								madeRequest = True
							else:
								outputTunnelIOMessage('C2S', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'Error - HTTP request failed with the following message: %s. This request will be retried up to %i times.' % (e, httpRequestRetryLimit))
								time.sleep(httpRequestRetryDelay)
					
					content = getServerResponseFromResponseBody(content, responseStringWrapperText, formattedServerAddress, formattedClientAddress, listeningAddress, connectionID)
					cookieVal = getCookieFromServerResponse(connectionID, cookieVal, response)
					headers['Cookie'] = cookieVal
				except Exception as e:
					raise e
				
				serverClosedConnection = False
				
				try:
					srb = getServerResponseFromResponseBody(content, responseStringWrapperText, formattedServerAddress, formattedClientAddress, listeningAddress, connectionID)
					#print '"' + srb + '"'
					srbArray = srb.split(" ", 1)
					fromServer = ""
					if len(srbArray) > 1:
						if srbArray[0] == conf.responseStringData:
							fromServerB64 = srbArray[1]
							fromServer = base64.b64decode(fromServerB64)
							if len(encryptionKey) > 0:
								if conf.echoData:
									outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, 'Raw Data (Encrypted) (base64)', '%s%s' % (os.linesep, fromServerB64))
								fromServer = decrypt(fromServer, str(encryptionKey), encryptionBlockSize)
								#print '"' + fromServer + '"'
							else:
								if conf.echoData:
									outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, 'Raw Data (Plaintext) (base64)', '%s%s' % (os.linesep, fromServerB64))							
							fullMessageSize = len(fromServer)
							numBlocks = int(math.ceil(float(fullMessageSize) / float(conf.clientBlockSizeLimitFromServer)))
							if conf.echoDebugMessages:
								if numBlocks > 1:
									outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'Splitting large block (%i bytes) into %i blocks for relay to client' % (fullMessageSize, numBlocks))
							for blockNum in range(0, numBlocks):
								firstByte = blockNum * conf.clientBlockSizeLimitFromServer
								lastByte = (blockNum + 1) * conf.clientBlockSizeLimitFromServer
								if lastByte > fullMessageSize:
									lastByte = fullMessageSize
								currentBlock = fromServer[firstByte:lastByte]
								serverSentByteCounter = serverSentByteCounter + len(currentBlock)
								if conf.echoData:
									outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, 'Raw Data (Plaintext) (base64)', '%s%s' % (os.linesep, base64.b64encode(currentBlock)))
								if conf.echoDebugMessages:
									outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', '(Block %i/%i) %i bytes' % (blockNum + 1, numBlocks, len(currentBlock)))
								try:
									clientsock.send(currentBlock)
								except Exception as e:
									outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'Error sending to client - %s' % (e))
								if conf.clientBlockTransmitSleepTime > 0.0:
									if blockNum < (numBlocks - 1):
										time.sleep(conf.clientBlockTransmitSleepTime)
					else:
						foundResponseType = False
						if srb == conf.responseStringNoData:
							foundResponseType = True
							if conf.echoDebugMessages:
								outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'No data to receive from server at this time')
						else:
							trafficSent = True
						if srb == conf.responseStringErrorInvalidRequest:
							outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'The server reported that the request was invalid. Verify that that you are using a client configuration compatible with the server-side component.')
							foundResponseType = True
						if srb == conf.responseStringErrorConnectionOpenFailed:
							outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'The server reported that the requested connection could not be opened. You may have requested a destination host/port that is inaccessible to the server, the server may have exhausted ephemeral ports (although this is unlikely), or another component (e.g. firewall) may be interfering with connectivity.')
							foundResponseType = True
						if srb == conf.responseStringErrorConnectionSendFailed:
							outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'The server reported that an error occurred while sending data over the TCP connection.')
							foundResponseType = True
						if srb == conf.responseStringErrorConnectionReceiveFailed:
							outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'The server reported that an error occurred while receiving data over the TCP connection.')
							foundResponseType = True
						if srb == conf.responseStringErrorDecryptFailed:
							outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'The server reported a decryption failure. Verify that the encryption keys in the client and server configurations match.')
							foundResponseType = True
						if srb == conf.responseStringErrorEncryptFailed:
							outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'The server reported an encryption failure. Verify that the encryption keys in the client and server configurations match.')
							foundResponseType = True
						if srb == conf.responseStringErrorEncryptionNotSupported:
							outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'The server reported that it does not support encryption. Verify that that you are using a client configuration compatible with the server-side component.')
							foundResponseType = True
						if foundResponseType == False:
							outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'Unexpected response from server: %s' % (content))
							serverClosedConnection = True
					
					if conf.responseStringConnectionClosed in content:
						outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'The server explicitly closed connection ID %s' % (connectionID))
						serverClosedConnection = True
					if conf.responseStringErrorConnectionNotFound in content:
						outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'The server reported that connection ID %s was not found - assuming connection has been closed.' % (connectionID))
						serverClosedConnection = True				
				except socket.error as e:
					if "timed out" not in str(e):
						raise e
						
				if trafficSent:
					scaleSocketTimeoutDown = True
					scaleSocketTimeoutUp = False
				else:
					scaleSocketTimeoutDown = False
					scaleSocketTimeoutUp = True
					
				if serverClosedConnection == True:
					runChildLoop = 0
					closeConnections = 1
					try:
						responseArray = content.split(" ")
						if len(responseArray) > 1:
							connectionID = responseArray[1]
							outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'The server closed connection ID %s' % (connectionID))
						else:
							outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'The server closed connection ID %s without specifying its ID' % (connectionID))
					except:
						outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', 'The server closed connection ID %s without sending a response' % (connectionID))
						
				iterationCounter = iterationCounter + 1
				if iterationCounter > conf.statsUpdateIterations:
					outputTunnelIOMessage('C2S', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', '%i bytes sent since last report' % (clientSentByteCounter))
					outputTunnelIOMessage('S2C', formattedClientAddress, listeningAddress, formattedServerAddress, connectionID, '', '%i bytes sent since last report' % (serverSentByteCounter))
					iterationCounter = 0
					clientSentByteCounter = 0
					serverSentByteCounter = 0
					
				if runServer == 0:
					outputHandler.outputMessage('Server shutdown request received in thread for connection ID %s' % (connectionID))
					runChildLoop = 0
					closeConnections = 1
				else:
					if conf.autoscaleClientSocketTimeout:
						# scale socket timeout up/down if the criteria for doing so was met
						timeoutChange = 0.0
						#global socketTimeoutCurrent
						newSocketTimeout = socketTimeoutCurrent
						if scaleSocketTimeoutDown or scaleSocketTimeoutUp:
							timeoutChange = conf.clientSocketTimeoutScalingMultiplier * socketTimeoutCurrent
						if scaleSocketTimeoutDown:
							newSocketTimeout = conf.clientSocketTimeoutMin
						if scaleSocketTimeoutUp:
							newSocketTimeout = socketTimeoutCurrent + timeoutChange
						# make sure socket timeout is within specified range
						if newSocketTimeout < conf.clientSocketTimeoutMin:
							newSocketTimeout = conf.clientSocketTimeoutMin
						if newSocketTimeout > conf.clientSocketTimeoutMax:
							newSocketTimeout = conf.clientSocketTimeoutMax
						if newSocketTimeout != socketTimeoutCurrent:
							if conf.echoDebugMessages:
								outputHandler.outputMessage('[Connection ID %s]: Client-side socket timeout has been changed from %f to %f' % (connectionID, socketTimeoutCurrent, newSocketTimeout))
							socketTimeoutCurrent = newSocketTimeout
							
						# apply random socket timeout variation
						timeoutVar = random.uniform(clientSocketTimeoutVariationNeg, conf.clientSocketTimeoutVariation)
						timeoutModifier = (socketTimeoutCurrent * timeoutVar)
						effectiveTimeout = (socketTimeoutCurrent + timeoutModifier)
						if conf.echoDebugMessages:
							outputHandler.outputMessage('[Connection ID %s]: Applying random variation of %f to client-side socket timeout for this iteration - timeout will be %f' % (connectionID, timeoutModifier, effectiveTimeout))
							
						clientsock.settimeout(effectiveTimeout)
					

		except Exception as e:
			outputHandler.outputMessage('Connection-level exception: %s in thread for tunnel (%s -> %s -> %s)' % (e, formattedClientAddress, listeningAddress, formattedServerAddress))
			closeConnections = 1
			runChildLoop = 0
		if closeConnections == 1:
			outputHandler.outputMessage('Disengaging tunnel (%s -> %s -> %s)' % (formattedClientAddress, listeningAddress, formattedServerAddress))
			outputHandler.outputMessage('Closing client socket (%s -> %s)' % (formattedClientAddress, listeningAddress))
			try:
				clientsock.shutdown(1)
				clientsock.close()
			except Exception as e2:
				outputHandler.outputMessage('Exception while closing client socket (%s -> %s): %s' % (formattedClientAddress, listeningAddress, e2))
			plaintextMessage = conf.paramNameOperation + dataBlockNameValueSeparator + conf.opModeStringCloseConnection + dataBlockParamSeparator + conf.paramNameConnectionID + dataBlockNameValueSeparator + connectionID
			if len(encryptionKey) > 0:
				#plaintextMessage = conf.paramNameOperation + dataBlockNameValueSeparator + conf.opModeStringCloseConnection + dataBlockParamSeparator + conf.paramNameConnectionID + dataBlockNameValueSeparator + connectionID
				ciphertextMessage = base64.b64encode(encrypt(plaintextMessage, str(encryptionKey), encryptionBlockSize))
				if conf.accessKeyMode == "header":
					body = {conf.paramNameEncryptedBlock: ciphertextMessage }
				else:
					body = {conf.paramNameAccessKey: conf.headerValueKey, conf.paramNameEncryptedBlock: ciphertextMessage }

			else:
				#body = {conf.paramNameOperation: conf.opModeStringCloseConnection, conf.paramNameConnectionID: connectionID }
				plaintextMessage = base64.b64encode(plaintextMessage)
				if conf.accessKeyMode == "header":
					body = {conf.paramNamePlaintextBlock: plaintextMessage }
				else:
					body = {conf.paramNameAccessKey: conf.headerValueKey, conf.paramNamePlaintextBlock: plaintextMessage }
			
			http = httplib2.Http(timeout=httpConnectionTimeout, disable_ssl_certificate_validation=unsafeTLSMode)
			response, content = http.request(forwardingURL, 'POST', headers=headers, body=urllib.urlencode(body))
			content = getServerResponseFromResponseBody(content, responseStringWrapperText, formattedServerAddress, formattedClientAddress, listeningAddress, connectionID)
			cookieVal = getCookieFromServerResponse(connectionID, cookieVal, response)
			headers['Cookie'] = cookieVal
			if conf.responseStringConnectionClosed in content:
				responseArray = content.split(" ")
				if len(responseArray) > 1:
					connectionID = responseArray[1]
					outputHandler.outputMessage('Server closed connection ID %s' % (connectionID))
			else:
				outputHandler.outputMessage('Error: could not close connection ID %s (may have already been closed on the server). Raw server response: %s' % (connectionID, content))
		else:
			outputHandler.outputMessage("Unexpected state: child loop exited without closeConnections being set to 1")

	except Exception as bigE:
		outputHandler.outputMessage("High-level exception: %s" % (str(bigE)))

def StartListener(forwardingURL, localAddress, localPort, destAddress, destPort):
	#formattedAddress = str(localAddress) + ":" + str(localPort)
	formattedAddress = '%s:%s' % (localAddress, localPort)
	try:
		myserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		myserver.bind((localAddress, localPort))
		myserver.listen(2)
		#outputHandler.outputMessage('Server started')
		outputHandler.outputMessage('Listener ready to forward connections from %s to %s:%i via %s' % (formattedAddress, destAddress, destPort, forwardingURL))
		while runServer > 0:
			try:
				outputHandler.outputMessage('Waiting for client connection to %s' % (formattedAddress))
				client, addr = myserver.accept()
				outputHandler.outputMessage('Client connected to %s' %(formattedAddress))
				thread.start_new_thread(child, (client, addr, formattedAddress, forwardingURL, destAddress, destPort))
			except Exception as e:
				if "Closing connections" not in str(e):
					raise e
	except Exception as e:
		outputHandler.outputMessage('Error in listener on %s: %s' % (formattedAddress, e))
	outputHandler.outputMessage('Shutting down listener on %s' % (formattedAddress))


def ShowUsage():
	print 'Usage: %s -c CONFIG_FILE_1 -c CONFIG_FILE_2 [...] -c CONFIG_FILE_n -u FORWARDINGURL -f LOCALHOST1:LOCALPORT1/TARGETHOST1:TARGETPORT1 -f LOCALHOST2:LOCALPORT2/TARGETHOST2:TARGETPORT2 [...] LOCALHOSTn:LOCALPORTn/TARGETHOSTn:TARGETPORTn [--debug]' % (sys.argv[0])
	print os.linesep
	print 'Example: %s -c CONFIG_FILE_1 -u https://vulnerableserver/EStatus/ -f 127.0.0.1:28443/10.10.20.11:8443' % (sys.argv[0])
	print os.linesep
	print 'Example: %s  -c CONFIG_FILE_1 -c CONFIG_FILE_2 -u https://vulnerableserver/EStatus/ -f 127.0.0.1:135/10.10.20.37:135 -f 127.0.0.1:139/10.10.20.37:139 -f 127.0.0.1:445/10.10.20.37:445' % (sys.argv[0])
	print os.linesep
	print 'Data from configuration files is applied in sequential order, to allow partial customization files to be overlayed on top of more complete base files.'
	print os.linesep
	print 'IE if the same parameter is defined twice in the same file, the later value takes precedence, and if it is defined in two files, the value in whichever file is specified last on the command line takes precedence.'
	print os.linesep
	print '--debug will enable verbose output.'
	print os.linesep
	print '--unsafetls will disable TLS/SSL certificate validation when connecting to the server, if the connection is over HTTPS'
	# logging-related options not mentioned because file output is buggy - just redirect stdout to a file instead
	#print os.linesep
	#print '--log LOGFILEPATH will cause all output to be written to the specified file (as well as the console, unless --quiet is also specified).'
	#print os.linesep
	#print '--quiet will suppress console output (but still allow log file output if that option is enabled).'
	
def SplitOnLast(inputString, splitCharacter):
	result = []
	splitCharPosition = inputString.rfind(splitCharacter)
	#print "Split character position: %i" % splitCharPosition
	#print inputString[:splitCharPosition]
	#print inputString[(splitCharPosition + 1):]
	if splitCharPosition > 0:
		result.append(inputString[:splitCharPosition])
		result.append(inputString[(splitCharPosition + 1):])
	else:
		result.append(inputString)
	return result
	
if __name__=='__main__':
	showBanner()
	if len(sys.argv) < 5:
		ShowUsage()
		sys.exit(1)
	
	forwardingURL = ""
	forwardingConfigurationList = []
	configFileList = []
	cliLogFileLocation = ""
	cliDebugOutput = False
	cliQuietOutput = False
	
	basePath = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
	
	args2 = []
	
	argNum = 0
	while argNum < len(sys.argv):
		currentArg = sys.argv[argNum]
		foundArg = False
		if argNum < (len(sys.argv) - 1):
			nextArg = sys.argv[argNum + 1]
			if currentArg == "-c":
				foundArg = True
				#configFileList = nextArg.split(",")
				configFileList.append(nextArg)
			if foundArg == False:
				if currentArg == "-u":
					foundArg = True
					forwardingURL = nextArg
			if foundArg == False:
				if currentArg == "-f":
					foundArg = True
					#forwardingConfigurationList = nextArg.split(",")
					forwardingConfigurationList.append(nextArg)
			if foundArg == False:
				if currentArg == "--log":
					foundArg = True
					cliLogFileLocation = nextArg
			if foundArg:
				argNum += 2
		if foundArg == False:
			args2.append(currentArg)
			argNum += 1

	# this is done twice to cause these settings to apply for all output...
	if cliLogFileLocation != "":
		conf.writeToLog = True
		conf.logFilePath = cliLogFileLocation
	for a in args2:
		if a == "--debug":
			conf.echoDebugMessages = True
		if a == "--unsafetls":
			unsafeTLSMode = True
			outputHandler.outputMessage('WARNING: The current configuration ignores TLS/SSL certificate validation errors for connection to the server component. This increases the risk of the communication channel being intercepted or tampered with.')
			
		#if a == "--quiet":
		#	conf.writeToStandardOut = False
			
	parameterFileArray = []
	parameterFileArray.append(os.path.join(basePath, 'data', 'settings-default.txt'))
	parameterFileArray.append(os.path.join(basePath, 'data', 'settings-fallback.txt'))
	for cf in configFileList:
		parameterFileArray.append(cf)
	if conf.echoDebugMessages:
		conf.LoadParameters(parameterFileArray, True)
	else:
		conf.LoadParameters(parameterFileArray, False)
	
	# only compute this once
	#global clientSocketTimeoutVariationNeg
	clientSocketTimeoutVariationNeg = conf.clientSocketTimeoutVariation * -1.0

	# Handle not only the "normal" prefix/suffix blocks, but also any variations created 
	# by "helpful" servers, e.g. Apache Tomcat, which transparently strips 
	# \r characters from output
	#global responseStringWrapperText
	responseStringWrapperText = []
	responseStringPrefix = base64.b64decode(conf.responseStringPrefixB64)
	responseStringWrapperText.append(responseStringPrefix)
	responseStringWrapperText.append(responseStringPrefix.replace("\r", ""))
	responseStringSuffix = base64.b64decode(conf.responseStringSuffixB64)
	responseStringWrapperText.append(responseStringSuffix)
	responseStringWrapperText.append(responseStringSuffix.replace("\r", ""))

	#global dataBlockNameValueSeparator
	#global dataBlockParamSeparator
	dataBlockNameValueSeparator = base64.b64decode(conf.dataBlockNameValueSeparatorB64)
	dataBlockParamSeparator = base64.b64decode(conf.dataBlockParamSeparatorB64)

	
	#socketTimeoutCurrent = clientSocketTimeoutBase
	#global encryptionKey
	encryptionKey = []
	encryptedTraffic = False

	if len(conf.encryptionKeyHex) > 0:
		try:
			encryptionKey = binascii.unhexlify(conf.encryptionKeyHex)
			encryptedTraffic = True
		except:
			encryptionKey = []
			
	if encryptedTraffic == False:
		outputHandler.outputMessage('WARNING: The current configuration DOES NOT ENCRYPT tunneled traffic. If you wish to use symmetric encryption, restart this utility with a configuration file which defines a valid encryption key.')
	
	# ...as well as override contrary values in the settings file(s)
	if cliLogFileLocation != "":
		conf.writeToLog = True
		conf.logFilePath = cliLogFileLocation
	for a in args2:
		if a == "--debug":
			conf.echoDebugMessages = True
		
	#time.sleep(0.1)
	
	if conf.echoDebugMessages:
		conf.ShowParameters()
	
	#time.sleep(0.1)
	
	if forwardingURL == "":
		outputHandler.outputMessage('Error: no ABPTTS forwarding URL was specified. This utility will now exit.')
		sys.exit(2)
	
	forwarderCount = 0
	
	for fw in forwardingConfigurationList:
		parsedMap = False
		#try:
		forwardingConfigurationString1 = fw.split("/")
		if len(forwardingConfigurationString1) > 1:
			#forwardingConfigurationString1a = forwardingConfigurationString1[0].split(":")
			#forwardingConfigurationString1b = forwardingConfigurationString1[1].split(":")
			forwardingConfigurationString1a = SplitOnLast(forwardingConfigurationString1[0], ":")
			forwardingConfigurationString1b = SplitOnLast(forwardingConfigurationString1[1], ":")
			if len(forwardingConfigurationString1a) > 1:
				if len(forwardingConfigurationString1b) > 1:
					localAddress = forwardingConfigurationString1a[0]
					localPortString = forwardingConfigurationString1a[1]
					destAddress = forwardingConfigurationString1b[0]
					destPortString = forwardingConfigurationString1b[1]
					#print "Local address: %s" % localAddress
					#print "Local port: %s" % localPortString
					#print "Dest address: %s" % destAddress
					#print "Dest port: %s" % destPortString
					try:
						localPort = int(localPortString)
					except:
						print "Could not parse a local port number as an integer"
						sys.exit(1)
					try:
						destPort = int(destPortString)
					except:
						print "Could not parse a destination port number as an integer"
						sys.exit(1)
					parsedMap = True
					#sys.exit(0)
		#except:
		#	parsedMap = False
		if parsedMap:
			thread.start_new_thread(StartListener, (forwardingURL, localAddress, localPort, destAddress, destPort))
			forwarderCount += 1
		else:
			print "Could not map the input parameter '%s' to a source/destination host/port definition" % (fw)
	
	if forwarderCount == 0:
		outputHandler.outputMessage('Error: no valid port-forwarding definitions were specified. This utility will now exit.')
	else:
		try:
			while 1:
				time.sleep(1)
		except KeyboardInterrupt:
			outputHandler.outputMessage('Console operator terminated server')
			runServer = 0

		outputHandler.outputMessage('Server shutdown')
		
	if conf.writeToLog:
		outputHandler.outputMessage('Please wait - writing remaining log output buffer to disk')
	runLoggingThread = 0


