#!/usr/bin/env python3

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

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import pathlib
import logging
import os
import sys
import time

from utils.config import Config
from utils.utils import Utils
from client.listener import Listener

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s')

if __name__=='__main__':
	conf = Config()
	Utils.print_banner()

	base_path = pathlib.Path(__file__).parent.resolve()

	parser = ArgumentParser(prog='ABPTTS',
    	formatter_class=ArgumentDefaultsHelpFormatter,
		usage='Usage: %(prog)s -c CONFIG_FILE_1 -c CONFIG_FILE_2 [...] -c CONFIG_FILE_n -u FORWARDINGURL -f LOCALHOST1:LOCALPORT1/TARGETHOST1:TARGETPORT1 -f LOCALHOST2:LOCALPORT2/TARGETHOST2:TARGETPORT2 [...] -f LOCALHOSTn:LOCALPORTn/TARGETHOSTn:TARGETPORTn [--debug]',
		epilog='Example: %(prog)s -c CONFIG_FILE_1 -u https://vulnerableserver/EStatus/ -f 127.0.0.1:28443/10.10.20.11:8443 \
			Example: %(prog)s -c CONFIG_FILE_1 -c CONFIG_FILE_2 -u https://vulnerableserver/EStatus/ -f 127.0.0.1:135/10.10.20.37:135 -f 127.0.0.1:139/10.10.20.37:139 -f 127.0.0.1:445/10.10.20.37:445 \
			Data from configuration files is applied in sequential order, to allow partial customization files to be overlayed on top of more complete base files. \
			IE if the same parameter is defined twice in the same file, the later value takes precedence, and if it is defined in two files, the value in whichever file is specified last on the command line takes precedence.')
	parser.add_argument('-c', help='specifies configuration files', default=[os.path.join(base_path, "data", "settings-default.txt"), os.path.join(base_path, "data", "settings-fallback.txt")], action='append', dest='config_files')
	parser.add_argument('-u', help='specifies fowarding URL', dest='forwarding_url', required=True)
	parser.add_argument('-f', help='specifies fowarding configurations', default=[], action='append', dest='forwarding_configs', required=True)
	parser.add_argument('--log', help='specifies logfile name', dest='logfile')
	parser.add_argument('--unsafe-tls', help='will disable TLS/SSL certificate validation when connecting to the server, if the connection is over HTTPS', action='store_true')
	parser.add_argument('--debug', help='enables verbose output.', action='store_true')

	args = parser.parse_args()

	if args.unsafe_tls:
		logger.warning("The current configuration ignores TLS/SSL certificate validation errors for connection to the server component.\nThis increases the risk of the communication channel being intercepted or tampered with.")

	conf.load_config(args.config_files)

	if args.logfile:
		conf.ReplaceValue("Logging", "writeToLog", "True")
		conf.ReplaceValue("Logging", "logFilePath", args.logfile)

	if args.debug:
		conf.dump()

	queue = []

	for forwarding_config in args.forwarding_configs:
		try:
			local, dst = forwarding_config.split("/")
			ip_local, port_local = local.split(":")
			ip_dst, port_dst = dst.split(":")
			port_local = int(port_local)
			port_dst = int(port_dst)
		except:
			logger.exception(f"Error while parsing the following forwarding config {forwarding_config}")
			sys.exit(1)

		params = {
			"unsafe_tls": args.unsafe_tls,
			"forwarding_url": args.forwarding_url,
			"local": { "host": ip_local, "port": port_local },
			"remote": { "host": ip_dst, "port": port_dst }
		}
		listener = Listener(params, conf)
		listener.start()
		queue.append(listener)

	try:
		while True:
			time.sleep(1)
	except KeyboardInterrupt:
		logger.info('Terminating listeners')
		for q in queue:
			q.stop()

	logger.info('Server shutdown')
