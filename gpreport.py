import requests
from bs4 import BeautifulSoup
requests.packages.urllib3.disable_warnings
from json2html import *
import json
import xmltodict
import argparse
from datetime import date
import csv

# Parameter Parser for variables

def get_arguments():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("-ip", "--ipaddr", dest="ip", help="Firewall Management IP address for API request")
        parser.add_argument("-u", "--username", dest="username", help="API username")
        parser.add_argument("-p", "--password", dest="password", help="Password for the API username")
        parser.add_argument("-s", "--start-date", dest="startdate", help="Report query from date. Example format '2020/03/30 19:10:10'")
        parser.add_argument("-e", "--end-date", dest="enddate", help="Report query to date. Example format '2020/04/30 19:10:10'")
        parser.add_argument("-t", "--type", dest="type", help="Report type: html and csv are the options. By default it generates both.")
        options = parser.parse_args()
        return options
    except :
        print("Exception Error: Unknown error occurred during parameter parsing!")
        print("Please check your input parameters...")

# Connect to PAN REST-API to generate the API Key

def connect (ip, username, password):
    url = "https://%s/api/?type=keygen&user=%s&password=%s" %(ip, username, password)

    try:
        connect = requests.post(url,verify=False)
        result = BeautifulSoup(connect.text,"html.parser")
        resultTag = result.find("response").attrs["status"]
        connect.connection.close()
    
        if resultTag == "success":
            print("Authentication Successful")
            key = result.find("key").get_text()
            return key
    
        elif resultTag == "error":
            print("Authentication Failed!")
            error = result.find("msg").get_text()
            return ("Error Details: %s" %(error))
    
        else:
            return ("Unknown error occurred during Firewall API connect request!")
    
    except :
        print("Exception Error: Unknown error occurred during Firewall API connect request!")


# Generate the Log Query for Global Protect Logs

def gpquery(ip, username, password, startdate, enddate):
    url = "https://%s/api/?type=log&log-type=system&nlogs=1000&query=((subtype eq globalprotect) and ((eventid eq globalprotectgateway-auth-succ) or (eventid eq globalprotectgateway-logout-succ)) and ((receive_time geq '%s') and (receive_time leq '%s')))" %(ip,startdate,enddate)
    key = connect (ip, username, password)
    headers = {'X-PAN-KEY': key}
    
    try:
        request = requests.get(url, headers=headers, verify=False)
        result = BeautifulSoup(request.text, "html.parser")
        resultTag = result.find("response").attrs["status"]
        print()
        print("Starting the query, please wait...")
        
        if resultTag == "success":
            jobID = result.find("job").get_text()
            print(jobID)
            queryURL = "https://%s/api/?key=apikey&type=log&log-type=system&action=get&job-id=%s" %(ip,jobID)
            jobQuery = requests.post(queryURL, headers=headers, verify=False)
            xpars = xmltodict.parse(jobQuery.text)
            jsonData = json.dumps(xpars)
            print("Query finished successfully!")
            return jsonData
        
        elif resultTag == "error":
            print("Log Query Failed!")
            error = result.find("msg").get_text()
            print ("Error Details: %s" % (error))
        
        else:
            print ("Unknown error occurred during the log query!")
    
    except:
        print("Exception Error: Unknown error occurred during the log query!")


# Parse "opaque" Log field output for better visibility

def lineParser(logLine):
    try:
        if logLine.__contains__("GlobalProtect gateway user authentication succeeded. "):
            logLine = logLine.replace("GlobalProtect gateway user authentication succeeded. ", "")
            logLine = logLine.replace("Source region", "Region")
            logLine = logLine.replace("User name", "User")
            logLine = logLine.replace("Login from", "IP")
            logLine = logLine.replace("Auth type", "AuthType")
            logLine = logLine.replace("Client OS version", "OS")

            if logLine.__contains__(", 64-bit."):
                logLine = logLine.replace(", 64-bit.", "64-bit")

            if logLine.__contains__(", 32-bit."):
                logLine = logLine.replace(", 32-bit.", "32-bit")
            dictionaryLog = {i.split(": ")[0]: i.split(": ")[1] for i in logLine.split(", ")}
        return dictionaryLog
    except:
        print("Exception Error: Unknown error occurred during opaque line parsing!")


# Generate Inputs for the Report Fields

def finalLogs(logData):
    try:
        csvReportFinal = []
        htmlReportFinal=[]
        for entry in logData["response"]["result"]["log"]["logs"]["entry"]:
            if (entry["eventid"] == "globalprotectgateway-auth-succ"):
                string = entry["opaque"]
                opaqueLine = lineParser(string)
                del entry["opaque"]
                entry.update(opaqueLine)
                csvReportFinal.append(entry)
        for element in csvReportFinal:
            keys = ['time_generated', 'serial', 'subtype', 'device_name', 'IP', 'Region', 'User', 'AuthType', 'OS']
            newElement = {x:element[x] for x in keys}
            htmlReportFinal.append(newElement)
        return csvReportFinal, htmlReportFinal
    except:
        print("Exception Error: Unknown error occurred during log parsing!")


# Print Reports

def csvReport(data):
    try:
        today = str(date.today())
        csvFileName="Global_Protect_CSV_Report_"+str(today)+".csv"
        csv_columns = data[1].keys()
        with open(csvFileName, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames = csv_columns)
            writer.writeheader()
            for element in data:
                writer.writerow(element)
        csvfile.close()
    except:
        print("Exception Error: Unknown error occurred during CSV Report generation!")

def htmlReport(data):
    try:
        today = str(date.today())
        reportFile = open("Global Protect Report_"+str(today)+".html", "w")
        reportFile.write("""
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <title>PAN GP Report</title>
        <style>

            h1 {
                text-align: center;
                font-family: serif;
                font-weight: normal;
                text-transform: uppercase;
                border-bottom: 1px solid #57b1dc;
                margin-top: 30px;
                }
            table {
                border-collapse:collapse;
                margin-left: auto; 
                margin-right: auto;
                }
            th {
                background-color: rgba(29,150,178);
                text-align: left;
                text-transform: uppercase;
                padding: 5px 15px;
                border-color: grey;
                border-style: solid;
                color: rgb(255, 255, 255);
                white-space: normal;
                }
            td {
                padding: 10px;
                height: 0;
                font-size: 12px;
                }
            body {
                font-family: $helvetica;
                color: rgba(94,93,82,1);
                }
        </style>
    </head>
    <body>
        <h1><img src="data:image/png;base64,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" alt="Company logo"><br>Palo Alto Networks Global Protect Report</h1>
        <p style="text-align: center">This report is generated based on the script inputs</p>
""")
        htmlTable = json2html.convert(json = data)
        reportFile.write(htmlTable)
        reportFile.write("""
    </body>
</html>
""")
        reportFile.close()
    except:
        print("Exception Error: Unknown error occurred during HTML Report code generation!")


def generateReport (select):
    try:
        if(select=="csv"):
            csvReport(csvLogResults)
            print("CSV report generated successfully")
        elif(select=="html"):
            htmlReport(htmlLogResults)
            print("HTML report generated successfully")
        else:
            csvReport(csvLogResults)
            htmlReport(htmlLogResults)
            print("Reports generated successfully")
    except:
        print("Exception Error: Unknown error occurred during Report generation!")


# Code Execution

options = get_arguments()
logQuery = gpquery (options.ip, options.username, options.password, options.startdate, options.enddate)
jsonLogResult = json.loads(logQuery)
logResults = finalLogs (jsonLogResult) 
csvLogResults = logResults[0]
htmlLogResults = logResults[1]
generateReport(options.type)