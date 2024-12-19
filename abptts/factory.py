#!/usr/bin/env python3

#	This file is part of A Black Path Toward The Sun ("ABPTTS")

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

# Configuration file/server component package generator for A Black Path Toward The Sun

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter,  RawDescriptionHelpFormatter
from base64 import b64encode, b64decode
import inspect
import logging
import random
import string
import sys
import os

from utils.config import Config
from utils.utils import Utils

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s')

def set_wrappers(conf, template_file):
	template_placeholder = "|ABPTTS_RESPONSE_CONTENT|"
	wrapper_prefix = ""
	wrapper_suffix = ""

	if os.path.exists(template_file):
		success, template_content = Utils.read_file(template_file)
		if not success:
			sys.exit(1)

		template_lines = template_content.split(template_placeholder)

		if len(template_lines) > 1:
			wrapper_prefix = template_lines[0]
			wrapper_suffix = template_lines[1]
		else:
			logger.fatal(f"Could not get wrapper prefix and suffix.")
			sys.exit(1)
	else:
		logger.fatal(f"File '{template_file}' doesn't exist.")
		sys.exit(1)

	if wrapper_prefix:
		success = conf.update_value("Obfuscation", "responseStringPrefixB64", b64encode(wrapper_prefix.encode()).decode())
		if not success:
			sys.exit(1)

	if wrapper_suffix:
		success = conf.update_value("Obfuscation", "responseStringSuffixB64", b64encode(wrapper_suffix.encode()).decode())
		if not success:
			sys.exit(1)

def set_random_values(conf, values):
	params = [
		"paramNameOperation", "paramNameDestinationHost", "paramNameDestinationPort", "paramNameConnectionID", "paramNameData", "paramNamePlaintextBlock", "paramNameEncryptedBlock",
		"opModeStringOpenConnection", "opModeStringSendReceive", "opModeStringCloseConnection", "fileGenerationAppNameShort", "paramNameAccessKey"
	]

	for p, v in zip(params, values["random_values"]):
		conf.replace_if_placeholder(p, v)

	params_with_sep = [
		"responseStringHide", "responseStringConnectionCreated", "responseStringConnectionClosed", "responseStringData", "responseStringNoData", "responseStringErrorGeneric",
		"responseStringErrorInvalidRequest", "responseStringErrorConnectionNotFound", "responseStringErrorConnectionOpenFailed", "responseStringErrorConnectionCloseFailed",
		"responseStringErrorConnectionSendFailed", "responseStringErrorConnectionReceiveFailed", "responseStringErrorDecryptFailed", "responseStringErrorEncryptFailed",
		"responseStringErrorEncryptionNotSupported"
	]

	for p, v in zip(params_with_sep, values["random_values_with_sep"]):
		conf.replace_if_placeholder(p, v)

	conf.replace_if_placeholder('dataBlockNameValueSeparatorB64', b64encode(values["name_value_sep"].encode()).decode())
	conf.replace_if_placeholder('dataBlockParamSeparatorB64', b64encode(values["param_sep"].encode()).decode())

def gen_random_values(conf, wordlist_lines):
	separators = [ '', '.', '_', '-', '@', '#', '$', '&', '|', '/' ]
	results = {}
	results["random_values"] = []
	results["random_values_with_sep"] = []
	all_candidates = []

	while len(results["random_values"]) < 12:
		candidate = ''.join(random.SystemRandom().choice(wordlist_lines) for _ in range(2))
		if candidate not in all_candidates:
			results["random_values"].append(candidate)

	
	while len(results["random_values_with_sep"]) < 15:
		first = os.urandom(random.randint(1, 36)).hex()
		second = os.urandom(random.randint(1, 36)).hex()
		candidate = f"{first}{Utils.get_random_entry(separators)}{second}"
		if candidate not in all_candidates:
			results["random_values_with_sep"].append(candidate)
			all_candidates.append(candidate)

	# use entire ASCII non-printable range except for null bytes
	block_sep_chars = [chr(i) for i in range(1, 32)]

	bscl = len(block_sep_chars) - 1
	results["name_value_sep"] = block_sep_chars[random.randint(0, bscl)]
	results["param_sep"] = block_sep_chars[random.randint(0, bscl)]

	while results["name_value_sep"] == results["param_sep"]:
		results["param_sep"] = block_sep_chars[random.randint(0, bscl)]

	return results

def create_war(conf, template_path, output_dir, jsp_server_filename):
	war_relative_path = "war"

	war_src_dir = os.path.abspath(os.path.join(template_path, war_relative_path))
	war_web_inf_src = os.path.join(war_src_dir, "WEB-INF")
	war_meta_inf_src = os.path.join(war_src_dir, "META-INF")
	war_jsp_src = os.path.join(output_dir, jsp_server_filename)

	war_dst_dir = os.path.abspath(os.path.join(output_dir, war_relative_path))
	war_web_inf_dst = os.path.join(war_dst_dir, 'WEB-INF')
	war_meta_inf_dst = os.path.join(war_dst_dir, 'META-INF')
	filename = conf.get_key("Output", "fileGenerationAppNameShort")

	war_jsp_dst = os.path.join(war_dst_dir, f"{filename}.jsp")
	war_dst_file = os.path.join(output_dir, f"{filename}.war")

	for path in [war_dst_dir, war_web_inf_dst, war_meta_inf_dst]:
		success = Utils.make_dir(path)
		if not success:
			sys.exit(1)

	success = conf.create_from_template(war_web_inf_src, "web.xml", war_web_inf_dst)
	if not success:
		sys.exit(1)

	success = conf.create_from_template(war_meta_inf_src, "MANIFEST.MF", war_meta_inf_dst)
	if not success:
		sys.exit(1)

	success = Utils.copy_file(war_jsp_src, war_jsp_dst)
	if not success:
		sys.exit(1)

	success = Utils.zip_dir(war_dst_dir, war_dst_file)
	if success:
		logger.info(f"Pre-built JSP WAR file: '{war_dst_file}'")
		logger.info(f"Unpacked WAR file content: '{war_dst_dir}'")
	else:
		sys.exit(1)

if __name__=='__main__':
	Utils.print_banner()

	base_path = os.path.abspath(os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe()))))
	template_path = os.path.join(base_path, "config", "template")
	data_path = os.path.join(base_path, "config", "data")
	ua_path = os.path.join(data_path, "user-agents.txt")

	parser = ArgumentParser(prog='ABPTTS',
    	formatter_class=ArgumentDefaultsHelpFormatter,
		usage='%(prog)s -c CONFIG_FILE_1 -c CONFIG_FILE_2 -o BASE_OUTPUT_DIRECTORY [--output-filename OUTPUT_CONFIG_FILE] [-w OUTPUT_WRAPPER_TEMLATE_FILE] [--ignore-defaults] [--wordlist WORDLIST_FILE] [--debug]',
		description='This utility generates a configuration file and matching server-side code (JSP, etc.) to be used with the ABPTTS client component.',
		epilog='Example: %(prog)s -c CONFIG_FILE_1 -o /home/blincoln/abptts/config/10.87.134.12 \
			Example: %(prog)s -c CONFIG_FILE_1 -c CONFIG_FILE_2 -o /home/blincoln/abptts/config/supervulnerable.goingtogethacked.internet \
			Data from configuration files is applied in sequential order, to allow partial customization files to be overlayed on top of more complete base files. \
			IE if the same parameter is defined twice in the same file, the later value takes precedence, and if it is defined in two files, the value in whichever file is specified last on the command line takes precedence.')
	parser.add_argument('-c', help='specifies configuration files', default=[], action='append', dest='config_files')
	parser.add_argument('-o', help='specifies an output directory for the configuration', required=True, dest='output_dir')
	parser.add_argument('--output-filename', help='specifies an alternate output filename for the configuration', default='config.txt', dest='output_file')
	parser.add_argument('-t', help='specifies a template file to use for generating the response wrapper prefix/suffix - see the documentation for details', default=os.path.join(template_path, 'response_wrapper.html'), dest='template_file')
	parser.add_argument('--ignore-defaults', help='prevents loading the default configuration as the base. For example, use this mode to merge two or more custom configuration overlay files without including options not explicitly defined in them. IMPORTANT: this will disable generation of server-side files (because if the defaults are not available, it would be very complicated to determine if all necessary parameters have been specified).', action='store_true')
	parser.add_argument('--wordlist', help='allows specification of a custom wordlist file (for random parameter name/value generation) instead of the default.', default=os.path.join(data_path, 'american-english-lowercase-4-64.txt'), dest='wordlist_file',)
	parser.add_argument('--debug', help='enables verbose output.', action='store_true')

	args = parser.parse_args()

	jsp_server_filename = 'abptts.jsp'
	aspx_server_filename = 'abptts.aspx'

	template_files = []
	template_files.append(jsp_server_filename)
	template_files.append(aspx_server_filename)

	# minimum number of entries in the wordlist used for certain random name/value generation
	wordlist_min_size = 10
	
	# Min/Max number of bytes to generate for the authentication key
	auth_key_min_size = 16
	auth_key_max_size = 32
	auth_key_size = random.randint(auth_key_min_size, auth_key_max_size)

	# number of bytes to generate for the encryption key
	encryption_key_size = 16

	output_dir = os.path.abspath(args.output_dir)

	if not args.ignore_defaults:
		args.config_files.append(os.path.join(data_path, 'settings-default.txt'))

	if not args.config_files:
		logger.critical("You have specified the --ignore-defaults flag, but not explicitly specified any configuration files. At least one configuration file must be specified.")
		sys.exit(1)

	conf = Config()	
	success = conf.load_config(args.config_files)

	if not success:
		sys.exit(1)

	if os.path.exists(output_dir):
		if not os.path.isdir(output_dir):
			logger.exception(f"A file named '{output_dir}' already exists, so that location cannot be used as an output directory. Delete/rename the existing file, or choose a new output directory.")
			sys.exit(1)
	else:
		success = Utils.make_dir(output_dir)
		if not success:
			sys.exit(1)

	output_file = os.path.join(output_dir, args.output_file)

	logger.info(f"Output files will be created in '{output_dir}'")
	logger.info(f"Client-side configuration file will be written as '{output_file}'")

	if os.path.exists(args.wordlist_file):
		logger.info(f"Using '{args.wordlist_file}' as a wordlist file")
	else:
		logger.critical(f"Could not find the wordlist file '{args.wordlist_file}'")
		sys.exit(1)

	success, wordlist_content = Utils.read_file(args.wordlist_file)
	if not success:
		sys.exit(1)

	wordlist_lines = wordlist_content.splitlines()

	if len(wordlist_lines) < wordlist_min_size:
		logger.critical(f"The wordlist file '{args.wordlist_file}' only contained {len(wordlist_lines)} entries, but at least {wordlist_min_size} are required.")
		sys.exit(1)

	success, user_agents_content = Utils.read_file(ua_path)
	if not success:
		sys.exit(1)

	user_agents_lines = user_agents_content.splitlines()

	if not user_agents_lines:
		logger.critical(f"No content obtained from user-agent list file {ua_path}")
		sys.exit(1)

	set_wrappers(conf, args.template_file)
	set_random_values(conf, gen_random_values(conf, wordlist_lines))
	
	conf.replace_if_placeholder('headerValueUserAgent', Utils.get_random_entry(user_agents_lines))
	conf.replace_if_placeholder('headerNameKey', f"X-{Utils.get_random_entries(wordlist_lines, 3, '-')}")
	conf.replace_if_placeholder('headerValueKey', b64encode(os.urandom(auth_key_size)).decode())
	conf.replace_if_placeholder('encryptionKeyHex', os.urandom(encryption_key_size).hex())

	if args.debug:
		logger.debug("Building ABPTTS configuration with the following values:")
		conf.dump()

	success = conf.write_config(output_file)
	if not success:
		sys.exit(1)

	if args.ignore_defaults:
		logger.info("The --ignore-defaults flag was specified, so no server-side files will be generated")
	else:
		# reload the configuration with the generated content
		args.config_files.append(output_file)
		conf.load_config(args.config_files)
		for template_name in template_files:
			success = conf.create_from_template(template_path, template_name, output_dir)
			if not success:
				sys.exit(1)
		create_war(conf, template_path, output_dir, jsp_server_filename)
	