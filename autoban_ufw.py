import datetime
import json
import keyboard
# 'sudo pip install keyboard'
import os
import requests
import socket
import struct
import subprocess
import threading
import time

from pathlib import Path
from termcolor import colored
# 'sudo pip install termcolor'


# Set to True if you want to report to AbuseIPDB
# Remember to set your API key
shouldReport = True


# You must run this script as root if you want to listen on ports < 1024
# Remember to forward the selected ports in your router
ports = [
    # basic
    20, 21, 22, 23, 25,
    42, 49,
    80, 88,
    110, 119, 135, 143,
    222,
    443, 445, 464, 465,
    989, 990, 993, 995,
    # extras
    2020, 2121, 2222, 2323, 2525,
    4242, 4949,
    5900, 5901,
    8080, 8081, 8082, 8181, 8282, 8443, 8888,
    20202, 21212, 22222, 23232, 25252,
    # misc
    1234, 12345, 23456, 34567, 45678, 56789,
    11111, 33333, 44444, 55555,
    25565,
]


#########################
####### FUNCTIONS #######
#########################


def printColored(messageIn, colorIn, isBold):
    attr = []
    if isBold:
        attr.append("bold")
    print(colored(messageIn, colorIn, attrs = attr))


def printSeparator():
    print("----------------------------------------")


# Create ufw rule for each listening port
def createUFWRules(isAllowed):
    # TODO: differentiate added and removed, skipped
    if isAllowed:
        printColored("Creating port rules...", "white", True)
        printSeparator()
        for port in ports:
            print(str(port) + " --- ", end = "")
            reason = subprocess.run(
                ["ufw", "allow", str(port)],
                capture_output = True
            ).stderr.decode()
            if len(reason) > 0:
                printColored("FAIL: " + reason, "red", True)
                exit()
            else:
                printColored("OK", "green", True)
    else:
        printColored("Removing port rules...", "white", True)
        printSeparator()
        for port in ports:
            print(str(port) + " --- ", end = "")
            reason = subprocess.run(
                ["ufw", "delete", "allow", str(port)],
                capture_output = True
            ).stderr.decode()
            if len(reason) > 0:
                printColored("FAIL: " + reason, "red", True)
                exit()
            else:
                printColored("OK", "green", True)


# Exit program on esc key
def exitOnEsc():
    def callback(event):
        if event.name == "esc":
            printSeparator()
            printColored("ESC pressed! Shutting down...", "white", True)
            createUFWRules(False)
            os._exit(1)
    return callback


def clearTerminal():
    i = 0
    while i < 64:
        print("")
        i += 1


# Print successful connection result
def printResult(address, port, isExisting):
    text = datetime.datetime.now().strftime("%H:%M:%S")
    bold = False
    if isExisting:
        color = "yellow"
        text += " = "
    else:
        bold = True
        color = "red"
        text += " + "
    text += address + " (" + str(port) + ")"
    printColored(text, color, bold)


def reportToAbuseIPDB(ipIn, portIn):
    api_file = Path("ABUSEIPDB_API_KEY.txt").read_text()
    api_key = api_file.encode().decode("utf-8")
    if len(api_key) > 0 and api_key != "enter_your_abuseipdb_api_key_here":
        categories = "14"
        comment = "Triggered honeypot on port " + str(portIn) + ". (" + ipIn + ")"
        timestamp = datetime.datetime.now().astimezone().replace(microsecond = 0).isoformat()
        
        url = "https://api.abuseipdb.com/api/v2/report"
        params = {
            "ip": ipIn,
            "categories": categories,
            "comment": comment,
            "timestamp": timestamp
        }
        
        headers = {
            "Accept": "application/json",
            "Key": api_key.strip()
        }
        
        response = requests.request(method = "POST", url = url, headers = headers, params = params)
        decodedResponse = json.loads(response.text)
        print(json.dumps(decodedResponse, sort_keys = True, indent = 4))
    else:
        global shouldReport
        shouldReport = False
        printColored("AbuseIPDB API key is not set - disabling reports.", "red", False)


def socketAccept(portNumber, theSocket):
    while True:
        conn, address = theSocket.accept()
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        result = subprocess.run(
            ["ufw", "deny", "from", address[0], "to", "any"],
            capture_output = True
        ).stdout.decode()
        # Print address and the port used
        printResult(address[0], portNumber, "existing" in result)
        # Aggressive connection abort
        time.sleep(1)
        theSocket.close()
        time.sleep(1)
        # Re-bind socket
        theSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        theSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        theSocket.bind(("", portNumber))
        theSocket.listen()
        # Report IP if this is a new address to us
        if not "existing" in result and shouldReport:
            reportToAbuseIPDB(address[0], portNumber)


#########################
######### BEGIN #########
#########################


sockets = {}


clearTerminal()


printSeparator()
printColored("Starting...", "white", True)
createUFWRules(True)
print("")
print("")
print("")


printSeparator()
printColored("Binding selected ports...", "white", True)
printSeparator()


for port in ports:
    # IPv4, TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Reuse socket
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print(str(port), end = " --- ")
    try:
        s.bind(("", port))
        printColored("OK", "green", True)
        s.listen()
        sockets[port] = s
    except Exception as e:
        printColored("FAIL: " + str(e).split("] ")[1], "red", True)
        createUFWRules(False)
        exit()


clearTerminal()


# Create threads
for key, value in sockets.items():
    t = threading.Thread(
        target = socketAccept,
        args = (key,value,)
    ).start()


printSeparator()
printColored("Listening for connections on ports: ", "white", True)
printSeparator()


for k in sockets.keys():
    printColored(str(k), "dark_grey", False)


printSeparator()
printColored("Press 'ESC' to stop at any time.", "white", True)
keyboard.hook(exitOnEsc())
printSeparator()
