# massh

This Python script can be used to quickly test out a SSH key or a credential pair on several hosts.

## Installation

The easiest way to install massh is to use `pipx` ([install it](https://pipx.pypa.io/stable/installation/) if you don't have it):
```bash
pipx install git+https://github.com/bs3vcenk/massh
```
This will install massh in an isolated environment, and you can run it with `massh`.

Alternatively, you can clone the repository and install the dependencies manually:
```bash
git clone https://github.com/bs3vcenk/massh
cd massh
# Optional: create a virtual environment
python3 -m venv venv
source venv/bin/activate
# Install the dependencies
pip install -r requirements.txt
```

## Get started

Say you have a list of IPs and ports in a file called `hosts.txt`:
```
192.168.1.11:22
192.168.1.12:22
192.168.1.13:22
```

You can use massh to test an SSH key on these hosts:
```bash
./massh.py -f hosts.txt -u root -i ~/.ssh/id_rsa
```

Or, you want to run a command on the hosts:
```bash
./massh.py -f hosts.txt -u root -p 123456 -c "uname -a"
```

If you have a Shodan API key, you can use it to search for hosts:
```bash
./massh.py -k SHODAN_KEY --query "OpenSSH" -u root -p 123456
```

## Usage
```
usage: massh [-h] (-f FILE | -k SHODAN_KEY) [-q QUERY] -u USERNAME (-p PASSWORD | -i SSH_KEY) [-c CMD] [-o FILE] [-t THREADS] [--limit LIMIT] [--debug]
             [--singlethreaded]

massh (Mass-SSH): multithreaded ssh crendential tester

options:
  -h, --help            show this help message and exit
  -f, --file FILE       Input file (one IP:port per line)
  -k, --shodan-key SHODAN_KEY
                        Set Shodan API key
  -q, --query QUERY     Set Shodan search query
  -u, --username USERNAME
                        Set username [default: root]
  -p, --password PASSWORD
                        Set password
  -i, --ssh-key SSH_KEY
                        Set SSH key path
  -c, --command CMD     Command to run after successful connection
  -o, --output FILE     Output successful IPs to FILE [default: successful.log]
  -t, --threads THREADS
                        Threads for multiprocessing [default: 8]
  --limit LIMIT         Limit number of Shodan results [default: 100]
  --debug               Show debug information [default: off]
  --singlethreaded      Disable multiprocessing [default: off]
```
