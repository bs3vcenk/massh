# Shodan-RPi
  
This script uses the Shodan API to search for Raspbian devices running an SSH server, and tries to SSH into them by using the default credentials `pi:raspberry`.

## Requirements:
###### Python Modules:
* `paramiko` (the SSH client)  
* `shodan` (the API client)
* `colorama` (the colored output module)

...which can be installed by running `pip install -r requirements.txt` on Linux and `python -m pip install -r requirements.txt` on Windows.

## Usage:  
```
$ python shodan_raspi.py -k <API_KEY>
```
By default, the script will poll Shodan for results and write the IPs into a list, trying them until it reaches the end.

Providing a file with the `-i` argument will read the file into a list, and do the same.

The `-n` argument will repeat the above process until Ctrl+C is pressed.

Arguments `-u` and `-p` can be used to change the default username and password to something else.
