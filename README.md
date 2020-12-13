# **Palo Alto Networks Global Protect Report Script**

This repository is for generating Palo Alto Networks Global Protect Report.  

***__Company logo__*** can be added by customizing below line of the script. You can copy your company logo image to the same directory of the script and name it as "logo.png":
```
img src="logo.png"
```
## Install Required Python Libraries
You need to install below libraries before running the script:  
```
$ pip install requests
$ pip install bs4
$ pip install xmltodict
$ pip install argparse
```
## Running the script
You can run the script with below parameters:
```
"-ip"or "--ipaddr"     --> Firewall Management IP address for API request (Mandatory)
"-u" or "--username"   --> API username (Mandatory)
"-p" or "--password"   --> Password for the API username (Mandatory)
"-s" or "--start-date" --> Report query from date. Example format "2020/03/30 19:10:10" (Mandatory)
"-e" or "--end-date"   --> Report query to date. Example format "2020/04/30 19:10:10" (Mandatory)
"-t" or "--type"       --> Report type: html or csv. If it is not set, it generates both by default." (Optional)
```
Usage Syntax:
```
$ python gpreport.py -ip <ip address of your firewall> -u <api username> -p <password> -s <start-date> -e <end-date> -t <html|csv>
 ```
 Example of Usage:
 ```
 $ python gpreport.py -ip "192.168.1.1" -u "admin" -p "password" -s "2020/03/1 00:00:00" -e "2020/03/30 23:59:59" -t "html"
 ```
 ## **IMPORTANT NOTE!**
This script is tested with Python 3.7.2. Please make sure your default Python is version 3 or use **__"python3"__** command instead of ~~python~~ when you run the command
 ## Sample Reports
 You can find sample html and csv reports at the repository.
