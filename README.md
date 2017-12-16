# Shodan-RPi

This script uses the Shodan API to search for Raspbian devices running an SSH server, and tries to SSH into them by using the default credentials `pi:raspberry`.

## Requirements
* `paramiko` (the SSH client)  
* `shodan` (the API client)
* `colorama` (the colored output module)

...which can be installed by running `pip install -r requirements.txt` on Linux and `python -m pip install -r requirements.txt` on Windows.

## Usage
```
$ python shodan_raspi.py -k <API_KEY>
```
Additionally, the script can be edited (specifically the variable `api_key`) to not require an API key argument.

By default, the script will poll Shodan for results and write the IPs into a list, trying them until it reaches the end.

`-i FILE` or `--input FILE` will do the same, but instead using FILE as the source. If FILE doesn't exist, it will be created.

`-n` or `--no-exit` will keep polling Shodan for results and retrying.

`-u USER` or `--username USER` and `-p PASS` or `--password PASS` will change the default credentials.

`-s SSTRING` or `--search-string SSTRING` will user SSTRING as the Shodan search string.

`-w FILE` or `--workfile FILE` will write all successful IPs to FILE. By default this is `successful.txt`.

`-l FILE` or `--log-paramiko FILE` will write `paramiko`'s log to FILE.

`-d` or `--debug` will show the reason for a failed connection.

## Bugs

Running with `-n`/`--no-exit` resets the successful and total tries counters on every try.

`-n`/`--no-exit` doesn't yet work on text files.

## Example
[![ASCIInema recording](https://asciinema.org/a/RE6ze9T70wtJxL5IFmo7KFowW.png)](https://asciinema.org/a/RE6ze9T70wtJxL5IFmo7KFowW)

(The sequence above doesn't include the process of getting results from Shodan, which may take a while, but instead reads from a pre-generated list of IPs to make the recording shorter.)

## Testing/Python 3 Support
If you want to help with the development of a faster version of Shodan-RPi, or if you just like testing, please consider checking out [the python3 branch](https://github.com/btx3/Shodan-RPi/tree/python3), or cloning it directly instead of the python2 branch:

`git clone https://github.com/btx3/Shodan-RPi -b python3`
