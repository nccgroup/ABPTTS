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

# Configuration file/server component package generator for A Black Path Toward The Sun

import base64
import binascii
import inspect
import math
import os
import random
import re
import sys
import zipfile

import libabptts

from datetime import datetime, date
from shutil import copyfile

outputHandler = libabptts.OutputHandler()
conf = libabptts.ABPTTSConfiguration(outputHandler)

serverFilenameJSP = 'abptts.jsp'
serverFilenameASPX = 'abptts.aspx'

serverFileTemplates = []
serverFileTemplates.append(serverFilenameJSP)
serverFileTemplates.append(serverFilenameASPX)

wrapperTemplateFileContentPlaceholder = "%ABPTTS_RESPONSE_CONTENT%"

# minimum number of entries in the wordlist used for certain random name/value generation
wordlistMinCount = 10

# minimum number of bytes to generate for the authentication key
authKeyMinLength = 16

# maximum number of bytes to generate for the authentication key
authKeyMaxLength = 32

# number of bytes to generate for the encryption key
encryptionKeyLength = 16

# \\\\\\ Do not modify below this line unless you know what you're doing! //////
#

def showBanner():
	outputHandler.outputMessage("---===[[[ A Black Path Toward The Sun ]]]===---")
	outputHandler.outputMessage("   --==[[        -  Factory  -        ]]==--")
	outputHandler.outputMessage("            Ben Lincoln, NCC Group")
	outputHandler.outputMessage('           Version %s - %s' % (libabptts.ABPTTSVersion.GetVersionString(), libabptts.ABPTTSVersion.GetReleaseDateString()))

def ShowUsage():
	print 'This utility generates a configuration file and matching server-side code (JSP, etc.) to be used with the ABPTTS client component.'
	print os.linesep
	print 'Usage: %s -c CONFIG_FILE_1 -c CONFIG_FILE_2 [...] -c CONFIG_FILE_n -o BASE_OUTPUT_DIRECTORY [--output-filename OUTPUT_CONFIG_FILE] [-w OUTPUT_WRAPPER_TEMLATE_FILE] [--ignore-defaults] [--wordlist WORDLIST_FILE] [--debug]' % (sys.argv[0])
	print os.linesep
	print 'Example: %s -c CONFIG_FILE_1 -o /home/blincoln/abptts/config/10.87.134.12' % (sys.argv[0])
	print os.linesep
	print 'Example: %s -c CONFIG_FILE_1 -c CONFIG_FILE_2 -o /home/blincoln/abptts/config/supervulnerable.goingtogethacked.internet' % (sys.argv[0])
	print os.linesep
	print 'Data from configuration files is applied in sequential order, to allow partial customization files to be overlayed on top of more complete base files.'
	print os.linesep
	print 'IE if the same parameter is defined twice in the same file, the later value takes precedence, and if it is defined in two files, the value in whichever file is specified last on the command line takes precedence.'
	print os.linesep
	print '--output-filename specifies an alternate output filename for the configuration (as opposed to the default of "config.txt")'	
	print os.linesep
	print '-w specifies a template file to use for generating the response wrapper prefix/suffix - see the documentation for details'	
	print os.linesep
	print '--ignore-defaults prevents loading the default configuration as the base. For example, use this mode to merge two or more custom configuration overlay files without including options not explicitly defined in them. IMPORTANT: this will disable generation of server-side files (because if the defaults are not available, it would be very complicated to determine if all necessary parameters have been specified).'
	print os.linesep
	print '--wordlist allows specification of a custom wordlist file (for random parameter name/value generation) instead of the default.'
	print os.linesep
	print '--debug will enable verbose output.'
	
def GetRandomListEntry(sourceList):
	entryNum = random.randint(0, len(sourceList) - 1)
	return sourceList[entryNum].strip()

def CapitalizeFirst(inputString):
	return inputString[0:1].upper() + inputString[1:].lower()
	
def RandomlyModifyCaps(inputString):
	mode = random.randint(0, 5)
	if mode < 2:
		return inputString
	if mode == 2:
		return CapitalizeFirst(inputString)
	if mode == 3:
		return inputString.upper()
	if mode == 4:
		return inputString.lower()
	return inputString
	
def RandomlyCapitalizeFirst(inputString):
	mode = random.randint(0, 10)
	if mode < 5:
		return inputString
	return CapitalizeFirst(inputString)
	
if __name__=='__main__':
	showBanner()
	if len(sys.argv) < 3:
		ShowUsage()
		sys.exit(1)

	configFileList = []
	cliDebugOutput = False
	ignoreDefaults = False
	
	basePath = os.path.abspath(os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe()))))
	dataFilePath = os.path.join(basePath, 'data')
	templateFilePath = os.path.join(basePath, 'template')
	
	wordListPath = os.path.join(dataFilePath, 'american-english-lowercase-4-64.txt')

	userAgentListPath = os.path.join(dataFilePath, 'user-agents.txt')
	
	baseOutputDirectory = ""
	outputConfigFileName = 'config.txt'
	wrapperTemplateFilePath = os.path.join(templateFilePath, 'response_wrapper.html')
	
	args2 = []
	
	argNum = 0
	while argNum < len(sys.argv):
		currentArg = sys.argv[argNum]
		foundArg = False
		if argNum < (len(sys.argv) - 1):
			nextArg = sys.argv[argNum + 1]
			if currentArg == "-c":
				foundArg = True
				configFileList.append(nextArg)
			if currentArg == "-o":
				foundArg = True
				baseOutputDirectory = os.path.abspath(nextArg)
			if currentArg == "--output-filename":
				foundArg = True
				outputConfigFileName = nextArg
			if currentArg == "-w":
				foundArg = True
				wrapperTemplateFilePath = nextArg
			if currentArg == "--wordlist":
				foundArg = True
				wordListPath = nextArg
			if foundArg:
				argNum += 2
		if foundArg == False:
			args2.append(currentArg)
			argNum += 1

	for a in args2:
		if a == "--debug":
			cliDebugOutput = True
		if a == "--ignore-defaults":
			ignoreDefaults = True
			
	parameterFileArray = []
	if ignoreDefaults == False:
		parameterFileArray.append(os.path.join(dataFilePath, 'settings-default.txt'))
		
	if len(parameterFileArray) < 1:
		outputHandler.outputMessage('Error: you have included the --ignore-defaults flag, but not explicitly specified any configuration files. At least one configuration file must be specified.')
		sys.exit(4)
			
	for cf in configFileList:
		parameterFileArray.append(cf)
	parameterHash = conf.LoadParameters(parameterFileArray, True)
	
	validDirectory = False
	
	if os.path.exists(baseOutputDirectory):
		if os.path.isdir(baseOutputDirectory):
			validDirectory = True
		else:
			outputHandler.outputMessage('Error: a file named "%s" already exists, so that location cannot be used as an output directory. Delete/rename the existing file, or choose a new output directory.' % (baseOutputDirectory))
			sys.exit(3)
	else:
		mdr = conf.MakeDir(baseOutputDirectory, outputHandler)
		if mdr:
			validDirectory = True
		else:
			sys.exit(3)
	
	outputConfigFilePath = os.path.join(baseOutputDirectory, outputConfigFileName)
	
	outputHandler.outputMessage('Output files will be created in "%s"' % (baseOutputDirectory))
	outputHandler.outputMessage('Client-side configuration file will be written as "%s"' % (outputConfigFilePath))
	
	if os.path.exists(wordListPath):
		outputHandler.outputMessage('Using "%s" as a wordlist file' % (wordListPath))
	else:
		outputHandler.outputMessage('Error: could not find the wordlist file "%s".' % (wordListPath))
		sys.exit(5)
		
	wl = conf.GetFileAsString(wordListPath)
	if wl == "":
		outputHandler.outputMessage('Error: no content obtained from wordlist file "%s".' % (wordListPath))
		sys.exit(6)
	wordList = wl.splitlines()
	
	wc = len(wordList)
	if len(wordList) < wordlistMinCount:
		outputHandler.outputMessage('Error: the wordlist file "%s" only contained %i entries, but at least %i are required.' % (wordListPath, wc, wordlistMinCount))
		sys.exit(7)
	
	ual = conf.GetFileAsString(userAgentListPath)
	if wl == "":
		outputHandler.outputMessage('Error: no content obtained from user-agent list file "%s".' % (userAgentListPath))
		sys.exit(6)
	userAgentList = ual.splitlines()
	
	wrapperPrefix = ""
	wrapperSuffix = ""
	
	if wrapperTemplateFilePath != "":
		if os.path.exists(wrapperTemplateFilePath):
			try:
				wrapperTemplateFileContents = conf.GetFileAsString(wrapperTemplateFilePath)
				wtfcArray = wrapperTemplateFileContents.split(wrapperTemplateFileContentPlaceholder)
				if len(wtfcArray) > 1:
					wrapperPrefix = wtfcArray[0]
					wrapperSuffix = wtfcArray[1]
			except Exception as e:
				outputHandler.outputMessage('Error while processing response wrapper template file "%s" - %s' % (baseOutputDirectory, e))
				wrapperPrefix = ""
				wrapperSuffix = ""

	if wrapperPrefix != "":
		conf.responseStringPrefixB64 = base64.b64encode(wrapperPrefix)
	if wrapperSuffix != "":
		conf.responseStringSuffixB64 = base64.b64encode(wrapperSuffix)
	
	#separators = [ '', '.', '_', '-', '~', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '[', ']', '{', '}', '|', '/', '?' ]
	separators = [ '', '.', '_', '-', '@', '#', '$', '&', '|', '/' ]
	randomStrings = []
	randomStringsWithSeparators = []
	checkStrings = []
	while len(randomStrings) < 16:
		word1 = RandomlyCapitalizeFirst(GetRandomListEntry(wordList))
		word2 = CapitalizeFirst(GetRandomListEntry(wordList))
		newString = '%s%s' % (word1, word2)
		if newString.lower() not in checkStrings:
			randomStrings.append(newString)
			checkStrings.append(newString.lower())
			
	while len(randomStringsWithSeparators) < 16:
		#word1 = RandomlyModifyCaps(GetRandomListEntry(wordList))
		#word2 = RandomlyModifyCaps(GetRandomListEntry(wordList))
		word1 = binascii.hexlify(bytearray(os.urandom(random.randint(1, 36))))
		word2 = binascii.hexlify(bytearray(os.urandom(random.randint(1, 36))))
		newString = '%s%s%s' % (word1, GetRandomListEntry(separators), word2)
		if newString.lower() not in checkStrings:
			randomStringsWithSeparators.append(newString)
			checkStrings.append(newString.lower())
	
	
	conf.headerValueUserAgent = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'headerValueUserAgent', conf.headerValueUserAgent, GetRandomListEntry(userAgentList))
	conf.headerNameKey = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'headerNameKey', conf.headerNameKey, 'x-%s-%s-%s' % (GetRandomListEntry(wordList).lower(), GetRandomListEntry(wordList).lower(), GetRandomListEntry(wordList).lower()))
	authKeyLength = random.randint(authKeyMinLength, authKeyMaxLength)
	conf.headerValueKey = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'headerValueKey', conf.headerValueKey, base64.b64encode(str(bytearray(os.urandom(authKeyLength)))))
	conf.encryptionKeyHex = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'encryptionKeyHex', conf.encryptionKeyHex,  binascii.hexlify(bytearray(os.urandom(encryptionKeyLength))))
	
	conf.paramNameAccessKey = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'paramNameAccessKey', conf.paramNameAccessKey, randomStrings[11])
	conf.paramNameOperation = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'paramNameOperation', conf.paramNameOperation, randomStrings[0])
	conf.paramNameDestinationHost = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'paramNameDestinationHost', conf.paramNameDestinationHost, randomStrings[1])
	conf.paramNameDestinationPort = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'paramNameDestinationPort', conf.paramNameDestinationPort, randomStrings[2])
	conf.paramNameConnectionID = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'paramNameConnectionID', conf.paramNameConnectionID, randomStrings[3])
	conf.paramNameData = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'paramNameData', conf.paramNameData, randomStrings[4])
	conf.paramNamePlaintextBlock = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'paramNamePlaintextBlock', conf.paramNamePlaintextBlock, randomStrings[5])
	conf.paramNameEncryptedBlock = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'paramNameEncryptedBlock', conf.paramNameEncryptedBlock, randomStrings[6])
	conf.opModeStringOpenConnection = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'opModeStringOpenConnection', conf.opModeStringOpenConnection, randomStrings[7])
	conf.opModeStringSendReceive = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'opModeStringSendReceive', conf.opModeStringSendReceive, randomStrings[8])
	conf.opModeStringCloseConnection = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'opModeStringCloseConnection', conf.opModeStringCloseConnection, randomStrings[9])
	conf.fileGenerationAppNameShort = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'fileGenerationAppNameShort', conf.fileGenerationAppNameShort, randomStrings[10])
	
	conf.responseStringHide = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'responseStringHide', conf.responseStringHide, randomStringsWithSeparators[0])
	conf.responseStringConnectionCreated = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'responseStringConnectionCreated', conf.responseStringConnectionCreated, randomStringsWithSeparators[1])
	conf.responseStringConnectionClosed = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'responseStringConnectionClosed', conf.responseStringConnectionClosed, randomStringsWithSeparators[2])
	conf.responseStringData = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'responseStringData', conf.responseStringData, randomStringsWithSeparators[3])
	conf.responseStringNoData = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'responseStringNoData', conf.responseStringNoData, randomStringsWithSeparators[4])
	conf.responseStringErrorGeneric = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'responseStringErrorGeneric', conf.responseStringErrorGeneric, randomStringsWithSeparators[5])
	conf.responseStringErrorInvalidRequest = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'responseStringErrorInvalidRequest', conf.responseStringErrorInvalidRequest, randomStringsWithSeparators[6])
	conf.responseStringErrorConnectionNotFound = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'responseStringErrorConnectionNotFound', conf.responseStringErrorConnectionNotFound, randomStringsWithSeparators[7])
	conf.responseStringErrorConnectionOpenFailed = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'responseStringErrorConnectionOpenFailed', conf.responseStringErrorConnectionOpenFailed, randomStringsWithSeparators[8])
	conf.responseStringErrorConnectionCloseFailed = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'responseStringErrorConnectionCloseFailed', conf.responseStringErrorConnectionCloseFailed, randomStringsWithSeparators[9])
	conf.responseStringErrorConnectionSendFailed = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'responseStringErrorConnectionSendFailed', conf.responseStringErrorConnectionSendFailed, randomStringsWithSeparators[10])
	conf.responseStringErrorConnectionReceiveFailed = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'responseStringErrorConnectionReceiveFailed', conf.responseStringErrorConnectionReceiveFailed, randomStringsWithSeparators[11])
	conf.responseStringErrorDecryptFailed = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'responseStringErrorDecryptFailed', conf.responseStringErrorDecryptFailed, randomStringsWithSeparators[12])
	conf.responseStringErrorEncryptFailed = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'responseStringErrorEncryptFailed', conf.responseStringErrorEncryptFailed, randomStringsWithSeparators[13])
	conf.responseStringErrorEncryptionNotSupported = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'responseStringErrorEncryptionNotSupported', conf.responseStringErrorEncryptionNotSupported, randomStringsWithSeparators[14])

	
	blockSeparatorChars = []
	# use entire ASCII non-printable range except for null bytes
	for i in range(1, 32):
		blockSeparatorChars.append(chr(i))
	
	#for i in range(128, 256):
	#	blockSeparatorChars.append(chr(i))
	
	bscl = len(blockSeparatorChars) - 1
	nvsIndex = random.randint(0, bscl)
	psIndex = random.randint(0, bscl)

	while nvsIndex == psIndex:
		psIndex = random.randint(0, bscl)
		
	conf.dataBlockNameValueSeparatorB64 = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'dataBlockNameValueSeparatorB64', conf.dataBlockNameValueSeparatorB64, base64.b64encode(blockSeparatorChars[nvsIndex]))
	conf.dataBlockParamSeparatorB64 = conf.ReplaceIfRandomizationPlaceholder(parameterHash, 'dataBlockParamSeparatorB64', conf.dataBlockParamSeparatorB64, base64.b64encode(blockSeparatorChars[psIndex]))
	
	if cliDebugOutput:
		outputHandler.outputMessage('Building ABPTTS configuration with the following values:')
		conf.ShowParameters()
	
	conf.WriteParametersBasedOnHashtable(parameterHash, outputConfigFilePath)
	
	if ignoreDefaults:
		outputHandler.outputMessage('The --ignore-defaults flag was specified, so no server-side files will be generated')
	else:
		# reload the configuration with the generated content
		parameterFileArray.append(outputConfigFilePath)
		parameterHash = conf.LoadParameters(parameterFileArray, False)
		
		for sft in serverFileTemplates:
			conf.GenerateServerFileFromTemplate(templateFilePath, sft, baseOutputDirectory, parameterHash)
			
		# auto-generate WAR file based on the generated JSP
		createWAR = True
		warRelativePath = 'war'
		jspFilename = '%s.%s' % (conf.fileGenerationAppNameShort, 'jsp')
		warFilename = '%s.%s' % (conf.fileGenerationAppNameShort, 'war')
		
		warInputDirectory = os.path.abspath(os.path.join(templateFilePath, warRelativePath))
		warOutputDirectory = os.path.abspath(os.path.join(baseOutputDirectory, warRelativePath))
		warWEBINFInputDirectory = os.path.join(warInputDirectory, 'WEB-INF')
		warMETAINFInputDirectory = os.path.join(warInputDirectory, 'META-INF')
		warWEBINFOutputDirectory = os.path.join(warOutputDirectory, 'WEB-INF')
		warMETAINFOutputDirectory = os.path.join(warOutputDirectory, 'META-INF')
		warJSPInputPath = os.path.join(baseOutputDirectory, serverFilenameJSP)
		warJSPOutputPath = os.path.join(warOutputDirectory, jspFilename)
		warOutputPath = os.path.join(baseOutputDirectory, warFilename)
		
		mdr = conf.MakeDir(warOutputDirectory, outputHandler)
		if not mdr:
			createWAR = False
		if createWAR:
			mdr = conf.MakeDir(warWEBINFOutputDirectory, outputHandler)
			if not mdr:
				createWAR = False
		if createWAR:
			mdr = conf.MakeDir(warMETAINFOutputDirectory, outputHandler)
			if not mdr:
				createWAR = False
		if createWAR:
			conf.GenerateServerFileFromTemplate(warWEBINFInputDirectory, 'web.xml', warWEBINFOutputDirectory, parameterHash)
			conf.GenerateServerFileFromTemplate(warMETAINFInputDirectory, 'MANIFEST.MF', warMETAINFOutputDirectory, parameterHash)
			createWAR = conf.CopyFile(warJSPInputPath, warJSPOutputPath, outputHandler)
		if createWAR:
			createWAR = conf.ZipDir(warOutputDirectory, warOutputPath, outputHandler)
		if createWAR:
			outputHandler.outputMessage('Prebuilt JSP WAR file: %s' % (warOutputPath))
			outputHandler.outputMessage('Unpacked WAR file contents: %s' % (warOutputDirectory))

		
		

