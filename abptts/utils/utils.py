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
import random
import logging
from zipfile import ZipFile
from shutil import copyfile

logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

class Utils:
	@staticmethod
	def get_version():
		return "2.0"

	@staticmethod
	def get_realase_date():
		return "2024-11-30"

	@staticmethod
	def print_banner():
		print("---===[[[ A Black Path Toward The Sun ]]]===---")
		print("   --==[[       -  Client  -          ]]==--")
		print("            Ben Lincoln, NCC Group")
		print(f"           Version {Utils.get_version()} - {Utils.get_realase_date()}{os.linesep}")
	
	@staticmethod
	def make_dir(path):
		success = False

		if os.path.exists(path):
			logger.critical(f"Directory '{path}' already exists")
			return success

		try:
			os.mkdir(path)
			success = True
		except Exception as e:
			logger.exception(f"Could not create a directory named '{path}'")

		return success

	@staticmethod
	def copy_file(src, dst):
		success = False

		try:
			copyfile(src, dst)
			success = True
		except Exception as e:
			logger.exception(f"Could not copy '{src}' to '{dst}'")

		return success

	@staticmethod
	def zip_dir(src, dst):
		success = False
		current_dir = os.getcwd()

		try:
			os.chdir(src)
			relroot = os.path.abspath(os.path.join(src))
			with ZipFile(dst, "w") as zip:
				for root, dirs, files in os.walk(src):
					# add directory (needed for empty dirs)
					# this is commented out because Tomcat 8 will reject WAR files with "./" in them.
					#zip.write(root, os.path.relpath(root, relroot))
					for file in files:
						filename = os.path.join(root, file)
						if os.path.isfile(filename): # regular files only
							arcname = os.path.join(os.path.relpath(root, relroot), file)
							zip.write(filename, arcname)			
			success = True
		except Exception as e:
			logger.exception(f"Could not create zip file '{dst}' from directory '{src}'")

		os.chdir(current_dir)
		return success	

	@staticmethod
	def read_file(src):
		content = ""
		success = False

		try:
			with open(src, 'r') as f:
				content = f.read()
				success = True
		except Exception as e:
			logger.exception(f"Could not read the file '{src}'")

		return success, content

	@staticmethod
	def get_random_entry(choices):
		return random.SystemRandom().choice(choices)

	@staticmethod
	def get_random_entries(choices, size, sep=''):
		return f"{sep}".join(random.SystemRandom().choice(choices) for _ in range(size))