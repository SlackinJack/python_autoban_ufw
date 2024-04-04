import socket
import subprocess
import threading

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
    8080, 8081, 8082, 8181, 8282, 8888,
    21212, 23232, 25252,
    # misc
    1234, 12345, 23456, 34567, 45678, 56789,
    11111, 22222, 33333, 44444, 55555,
]
sockets = {}

def socketAccept(portNumber, theSocket):
    while True:
        conn, address = theSocket.accept()
        subprocess.run(["ufw", "deny", "from", address[0], "to", "any"])
        print("[" + str(portNumber) + "] Banned address: " + address[0])

# Not error-catched - will exit if the port is in use!
for port in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", port))
    print("Bound port: " + str(port))
    s.listen()
    sockets[port] = s

# Clear the terminal
i = 0
while i < 64:
    print("")
    i += 1

print("Listening for connections on ports: " + str(list(sockets.keys())))

# Create threads
for key, value in sockets.items():
    t = threading.Thread(
        target = socketAccept,
        args = (key,value,)
    ).start()
