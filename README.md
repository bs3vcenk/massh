# Shodan-RPi

This script can be used to quickly test out a SSH key or a credential pair on several hosts.

## Requirements
Shodan-RPi uses the following modules:
* `paramiko` - for SSHing into remote hosts
* `shodan` - for accessing the Shodan API
* `colorama` - for colored output
* `tqdm` - for pretty progress bars

...which can be installed by running:
```pip3 install -r requirements.txt```

## Usage
```
usage: shodan_raspi.py [-h] (-i FILE | -k SHODAN_KEY) [-q QUERY] -u USERNAME
                       (-p PASSWORD | --ssh-key SSH_KEY) [-c CMD] [-o FILE]
                       [-t THREADS] [--limit LIMIT] [--debug]
                       [--singlethreaded] [--paramiko-log FILE]

massh (Mass-SSH): multithreaded ssh bruteforcer/cred-tester

optional arguments:
  -h, --help            show this help message and exit
  -i FILE, --input FILE
                        input file (one IP:port per line)
  -k SHODAN_KEY, --shodan-key SHODAN_KEY
                        Set Shodan API key
  -q QUERY, --query QUERY
                        Set Shodan search query
  -u USERNAME, --username USERNAME
                        Set username [default: root]
  -p PASSWORD, --password PASSWORD
                        Set password
  --ssh-key SSH_KEY     Set SSH key
  -c CMD, --command CMD
                        Command to run after a successful connection [default:
                        none]
  -o FILE, --output FILE
                        Output successful IPs to FILE [default:
                        successful.log]
  -t THREADS, --threads THREADS
                        Threads for multiprocessing [default: 8]
  --limit LIMIT         Limit number of shodan results [default: 100]
  --debug               Show debug information [default: off]
  --singlethreaded      Disable multiprocessing support [default: no]
  --paramiko-log FILE   Paramiko debug log [default: none/off]
```

So, for example, scan Shodan for OpenSSH servers, and try to connect using the the username `root` and password `123456`
```
./shodan_raspi.py -k SHODAN_KEY --query "OpenSSH" -u root -p 123456
```

If you want to use a list of IPs, you can use the `-i` argument to specify a file containing the IPs and ports, one per line. The format is `IP:PORT`, for example:
```
1.1.1.1:22
2.2.2.2:22
```

Another useful option is to use the `--ssh-key` argument to specify a SSH key to use for authentication. This can be used to test if a key is valid on a list of hosts:
```
./shodan_raspi.py -i hosts.txt -u root --ssh-key ~/.ssh/id_rsa
```
