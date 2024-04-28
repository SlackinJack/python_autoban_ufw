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

# Set to True if you want UFW rules to be made/removed automatically
shouldManageUFWRules = False


# You must run this script as root if you want to listen on ports < 1024
# Remember to forward the selected ports in your router
ports = [
    # basic
    # removed: 80, 443
    20, 21, 22, 23, 25,
    42, 49,
    88,
    110, 119, 135, 143,
    222,
    445, 464, 465,
    989, 990, 993, 995,
    # extras
    2020, 2121, 2222, 2323, 2525,
    4242, 4949,
    5900, 5901,
    8080, 8081, 8082, 8181, 8282, 8443, 8888,
    20202, 21212, 22222, 23232, 25252,
    # misc
    # removed: 25565
    1234, 12345, 23456, 34567, 45678, 56789,
    11111, 33333, 44444, 55555,
]


#########################
####### FUNCTIONS #######
#########################


# Dictionary of [port_number, thread]
threads = {}


# Global thread-running variable
shouldReviveThreads = True


def printColored(messageIn, colorIn, isBold):
    attr = []
    if isBold:
        attr.append("bold")
    print(colored(messageIn, colorIn, attrs = attr))


def printSeparator():
    print("----------------------------------------")


def clearTerminal():
    i = 0
    while i < 64:
        print("")
        i += 1


# Create ufw rule for each listening port
def createUFWRules(isAllowed):
    # only if 'shouldManageUFWRules' is enabled
    if shouldManageUFWRules:
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
                    printSeparator()
                    createUFWRules(False)
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
                else:
                    printColored("OK", "green", True)
    else:
        printColored("Automatic UFW rule management is disabled.", "grey", True)
        if isAllowed:
            printColored("(Assuming the ports are now open!)", "green", True)
        else:
            printColored("(Assuming the ports are now closed!)", "red", True)


# Exit program on esc key
def exitOnEsc():
    def callback(event):
        if event.name == "esc":
            printSeparator()
            printColored("ESC pressed! Shutting down...", "white", True)
            global shouldReviveThreads
            shouldReviveThreads = False
            createUFWRules(False)
            printSeparator()
            os._exit(1)
    return callback


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


# Report IP to AbuseIPDB using API key
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
        try:
            score = str(decodedResponse["data"]["abuseConfidenceScore"])
            printColored("Report generated: ", "light_grey", True)
            printColored("https://www.abuseipdb.com/check/" + ipIn, "light_grey", False)
            printColored("(Confidence: " + score + "%)", "dark_grey", False)
        except:
            try:
                errors = str(decodedResponse["errors"]["detail"])
                if "You can only report the same IP address" in errors:
                    printColored("Tried to report duplicate IP!", "red", True)
                    printColored("(Are rules being added to UFW?)", "white", False)
                else:
                    printColored("Error:", "red", True)
                    printColored(json.dumps(decodedResponse, sort_keys = True, indent = 4), "white", False)
            except:
                printColored("An unknown error has occurred:", "red", True)
                printColored(json.dumps(decodedResponse, sort_keys = True, indent = 4), "white", False)
    else:
        global shouldReport
        shouldReport = False
        printColored("AbuseIPDB API key is not set - disabling reports.", "red", False)


# Worker thread function
def socketAccept(portNumber):
    # bind socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("", portNumber))
    except Exception as e:
        printColored("Error binding " + str(portNumber) + ".", "red", True)
        printColored("(" + str(e) + ")", "red", True)
    # listen
    s.listen()
    conn, address = s.accept()
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    # Add rule to UFW
    result = subprocess.run(
        ["ufw", "deny", "from", address[0], "to", "any"],
        capture_output = True
    ).stdout.decode()
    # Print address and the port used
    printResult(address[0], portNumber, "existing" in result)
    # Abort the connection
    # TODO: refresh ufw rules??
    s.close()
    # Report IP if this is a new address to us
    if not "existing" in result and shouldReport:
        reportToAbuseIPDB(address[0], portNumber)
    global threads
    # Mark this thread as completed
    threads[portNumber] = None


# Restarts threads when they are completed
def threadWatcher():
    while shouldReviveThreads:
        for key, value in threads.items():
            if value is None:
                t = threading.Thread(
                    target = socketAccept,
                    args = (key,)
                )
                threads[key] = t
                t.start() 
        time.sleep(5)


#########################
######### BEGIN #########
#########################


clearTerminal()


printSeparator()
printColored("Starting...", "white", True)
createUFWRules(True)


printSeparator()
printColored("Starting workers...", "white", True)
printSeparator()


# Create threads
for port in ports:
    print(str(port), end = " --- ")
    t = threading.Thread(
        target = socketAccept,
        args = (port,)
    )
    threads[port] = t
    t.start()
    printColored("OK", "green", True)


# Create a thread to watch the threads
print("Thread Watcher", end = " --- ")
threading.Thread(
    target = threadWatcher
).start()
printColored("OK", "green", True)


printSeparator()
printColored("Press 'ESC' to stop at any time.", "white", True)
keyboard.hook(exitOnEsc())
printSeparator()

