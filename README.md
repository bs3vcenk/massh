# Shodan-RPi

This script uses the Shodan API to search for Raspbian devices running an SSH server, and tries to SSH into them by using the default credentials `pi:raspberry`.

## Requirements
* `paramiko` (the SSH client)  
* `shodan` (the API client)
* `colorama` (the colored output module)

...which can be installed by running `pip3 install -r requirements.txt` on Linux and `python3 -m pip install -r requirements.txt` on Windows.

## Usage
```
usage: shodan_raspi.py [-h] [-i FILE] [--indefinite] [-k KEY]
                       [--paramiko-log FILE] [-w FILE] [-u U] [-p P] [--debug]
                       [--query-string SSTRING] [--ssh-key KEY] [-c CMD]

optional arguments:
  -h, --help            show this help message and exit
  -i FILE               List of IPs
  --indefinite          Run indefinitely, restarting once the scan is finished
  -k KEY                Use KEY as the Shodan API key
  --paramiko-log FILE   Log Paramiko SSH's progress to FILE
  -w FILE               Output successful IPs to FILE
  -u U                  Use alternate username
  -p P                  Use alternate password
  --debug               Show debug information
  --query-string SSTRING
                        Use SSTRING as the Shodan query string
  --ssh-key KEY         Try auth with KEY as SSH key
  -c CMD                Run CMD after a successful connection
```

Additionally, the script can be edited (specifically the variable `api_key`) to not require an API key in the arguments.

By default, the script will poll Shodan for results and write the IPs into a list, trying them until it reaches the end.
## Bugs

Running with `--indefinite` resets the successful and total tries counters on every loop.

Sometimes, even if authentication is successful, command execution will not work on some devices - for example Cisco gear - due to the way shells are implemented in these systems.

## Example
[![asciicast](https://asciinema.org/a/IiwLQtHtnPhIWGcElwHbx5vEU.png)](https://asciinema.org/a/IiwLQtHtnPhIWGcElwHbx5vEU)

(The sequence above doesn't include the process of getting results from Shodan, which may take a while, but instead reads from a pre-generated list of IPs to make the recording shorter.)
