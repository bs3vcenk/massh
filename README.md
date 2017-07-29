# Shodan_Raspi
###### ***Hack Raspberry Pi(s) across the world !***  
   
   
This script basically uses `shodan` api to search Raspberry Pi's ip addresses , and tries to `ssh` into them by using the default username: ***pi*** and password: ***raspberrry***, then stores the successful ip addresses into a  text file.  

## Requirements:
###### Python Modules:
1. Paramiko (~$easy_install paramiko)  
2. Shodan (~$easy_install shodan)  

Or, Simply run --  
```
$ pip install -r requirements.txt
```
###### >> Setup your `Shodan` api key in the script << 

## Usage:  
```
$ python shodan_raspi.py  
```
###### OR
```
$ python shodan_raspi.py -i source_file_name  
``` 
If the source file doesn't exist , it'll be created, using `Shodan` api.  
The Source File consists of ip address, only one per line.  

