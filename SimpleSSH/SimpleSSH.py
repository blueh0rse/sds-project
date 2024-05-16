import socket
from threading import Thread
import struct
import sys
import os

VALID_CREDS = {
    "admin": "admin",
    "h1": "h1h1h1",
    "h2": "h2h2h2",
    "h3": "h3h3h3"
}

def notify_wrong_login(ip_owner):
    # Create a raw socket
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    # Set the IP header
    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Set the destination IP address
    dest_ip = "10.0.1.1"

    ip_header = b'\x45\x00\x00\x1c' # Version, IHL, Type of Service | Total Length
    ip_header += b'\xab\xcd\x00\x00' # Identification | Flags, Fragment Offset
    ip_header += b'\x40\x01\x6b\xd8' # TTL, Protocol | Header Checksum
    ip_header += socket.inet_aton(ip_owner) # Source Address
    ip_header += b'\xff\xff\xff\xff' # Destination Address

    icmp_header = b'\x08\x00\xe5\xca' # Type of message, Code | Checksum
    icmp_header += b'\x12\x34\x00\x01' # Identifier | Sequence Number

    icmp_packet = ip_header + icmp_header

    # Send the ICMP packet
    raw_socket.sendto(icmp_packet, (dest_ip, 0))
    raw_socket.close()

def handle_client(client_socket):
    # Receive username and password from the client
    client_socket.send("Enter username: ".encode())
    username = str(client_socket.recv(1024).decode()).strip()
    client_socket.send("Enter password: ".encode())
    password = str(client_socket.recv(1024).decode()).strip()

    # Check if the username and password are valid
    if not (username in VALID_CREDS and password == VALID_CREDS[username]):
        notify_wrong_login(client_socket.getpeername()[0])
        response = "Invalid username or password"
        client_socket.send(response.encode())
        client_socket.close()
        return

    # Send the response back to the client
    client_socket.send("Login successful\n".encode())
    client_socket.send("Welcome to the server!\n".encode())
    client_socket.send("To disconect to must press `Ctrl+]` and afterwards write `quit` and press `enter`, once `telnet> ` appears.\n".encode())

    while True:
        # Receive data from the client
        data = client_socket.recv(1024)
        if not data:
            break

        # Send the data back to the client
        client_socket.send(data)

    # Close the client socket
    client_socket.close()

def main(ip, port):
    # Create a TCP socket to listen for incoming connections
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to localhost and port 2222, delete the previous port binding
    server_address = (ip, port)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(server_address)

    # Listen for incoming connections
    server_socket.listen(5)
    print("Server is listening on {}:{}".format(*server_address))

    while True:
        print("Waiting for a connection...")
        # Accept a client connection
        client_socket, client_address = server_socket.accept()
        print("Received connection from {}:{}".format(*client_address))

        thread = Thread(target=handle_client, args=(client_socket,))
        thread.start()


def help():
    print("Usage: python SimpleSSH.py [ip] [port]")
    print("This is a simple SSH server that authenticates users with a username and password.")
    print("The server listens on localhost:2222 and accepts connections from clients.")
    print("The client sends a username and password to the server for authentication.")
    print("To test the server, you can use the 'telnet' command in a terminal to connect to the server.")
    print("Example: telnet localhost 2222 or telnet 10.0.2.1 2222")

if __name__ == "__main__":
    ip = "localhost"
    port = 2222

    if len(sys.argv) == 1:
        help()
        sys.exit(1)
    elif len(sys.argv) == 3:
        ip = sys.argv[1]
        port = int(sys.argv[2])

    main(ip, port)
