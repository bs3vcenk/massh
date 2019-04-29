# Shodan-RPi

This script can be used to quickly test out a SSH key or a credential pair on several hosts.

By default it uses the Shodan API to search for Raspbian devices running an SSH server, and tries to SSH into them by using the default credentials `pi:raspberry`.

## Requirements
* `paramiko` (the SSH client)  
* `shodan` (the API client)
* `colorama` (the colored output module)

...which can be installed by running `pip3 install -r requirements.txt` on Linux and `python3 -m pip install -r requirements.txt` on Windows.

## Usage
```
usage: shodan_raspi.py [-h] [-i FILE] [-indefinite] [-k KEY]
                       [-paramiko-log FILE] [-o FILE] [-u U] [-p P] [-t T]
                       [-debug] [-query-string SSTRING] [-ssh-key KEY]
                       [-c CMD] [-limit RESULTS] [-enable-multiproc]

optional arguments:
  -h, --help            show this help message and exit
  -i FILE               List of IPs
  -k KEY                Use KEY as the Shodan API key
  -paramiko-log FILE    Log Paramiko SSH's progress to FILE
  -o FILE               Output successful IPs to FILE
  -u USER               Use alternate username
  -p PASS               Use alternate password
  -t THREADS            Threads for multiprocessing
  -debug                Show debug information
  -query-string SSTRING
                        Use SSTRING as the Shodan query string
  -ssh-key KEY          Try auth with KEY as SSH key
  -c CMD                Run CMD after a successful connection
  -limit RESULTS        Maximum number of results to get from Shodan (default
                        100)
  -disable-multiproc    Disable multiprocessing support (slower, more complete output)
```

So, for example, scan Shodan for OpenSSH servers, and try to connect using the the username `root` and password `123456`
```
./shodan_raspi.py -k SHODAN_KEY -query-string "OpenSSH" -u root -p 123456
```

Additionally, the script can be edited (specifically the variable `api_key`) to not require an API key in the arguments.

By default, the script will poll Shodan for results and write the IPs into a list, trying them until it reaches the end.
## Bugs

MULTIPROCESSING: Multiprocessing will not work in some environments like Termux (`This platform lacks a functioning sem_open implementation.`). In case this happens, append `-disable-multiproc` to the command line.

MULTIPROCESSING: Incomplete error handling

GENERAL: Sometimes, even if authentication is successful, command execution will not work on some devices - for example Cisco gear - due to the way shells are implemented in these systems.
