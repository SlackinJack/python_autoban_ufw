import socket
import subprocess
import threading

# You must run this script as root if you want to listen on ports < 1024
# Remember to forward the selected ports in your router
ports = [22, 80]
sockets = {}

def socketAccept(portNumber, theSocket):
    while True:
        conn, address = theSocket.accept()
        subprocess.run(["ufw", "deny", "from", address[0], "to", "any"])
        print("[" + str(portNumber) + "] Banned address: " + address[0])

# Not error-catched - will exit if the port is in use!
for port in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', port))
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

