import datetime
import keyboard
# 'sudo pip install keyboard'
import os
import socket
import subprocess
import threading

from termcolor import colored
# 'sudo pip install termcolor'


# You must run this script as root if you want to listen on ports < 1024
# Remember to forward the selected ports in your router
ports = [
    # basic
    20, 21, 22, 23, 25,
    42, 49,
    80, 81, 88,
    110, 119, 135, 143,
    220, 222,
    443, 445, 464, 465,
    989, 990, 993, 995,
    # extras
    2000, 2020, 2121, 2200, 2222, 2323, 2525,
    4242, 4949,
    5900, 5901,
    8080, 8081, 8082, 8181, 8282, 8443, 8888,
    20000, 20202, 21212, 22222, 23232, 25252,
    # misc
    1234, 12345, 23456, 34567, 45678, 56789,
    11111, 33333, 44444, 55555,
    25565,
]


#########################
####### FUNCTIONS #######
#########################


def exitOnEsc():
    def callback(event):
        if event.name == 'esc':
            os._exit(1)
    return callback


def clearTerminal():
    i = 0
    while i < 64:
        print("")
        i += 1


def printResult(address, port, isExisting):
    text = datetime.datetime.now().strftime("%H:%M:%S")
    if isExisting:
        att = []
        color = "yellow"
        text += " = "
    else:
        att = ["bold"]
        color = "red"
        text += " + "
    text += address + " (" + str(port) + ")"
    print(colored(text, color, attrs = att))


def socketAccept(portNumber, theSocket):
    while True:
        conn, address = theSocket.accept()
        result = subprocess.run(
            ["ufw", "deny", "from", address[0], "to", "any"],
            capture_output = True
        ).stdout.decode()
        printResult(address[0], portNumber, "existing" in result)


#########################
######### BEGIN #########
#########################


sockets = {}


clearTerminal()


# Will exit if any selected port is in use!
print("Binding selected ports...")
for port in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(str(port), end = " --- ")
    try:
        s.bind(("", port))
        print(colored("OK", "green", attrs = ["bold"]))
        s.listen()
        sockets[port] = s
    except Exception as e:
        print(colored("FAIL: " + str(e).split("] ")[1], "red", attrs = ["bold"]))
        exit()


clearTerminal()


# Create threads
for key, value in sockets.items():
    t = threading.Thread(
        target = socketAccept,
        args = (key,value,)
    ).start()


print("----------------------------------------")
print(colored("Listening for connections on ports: ", "white", attrs = ["bold"]))
print("----------------------------------------")
for k in sockets.keys():
    print(colored(str(k), "dark_grey"))
print("----------------------------------------")
print(colored("Press 'ESC' to stop at any time.", "white", attrs = ["bold"]))
keyboard.hook(exitOnEsc())
print("----------------------------------------")
