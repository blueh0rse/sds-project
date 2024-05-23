import socket
import requests
import random
import time
import os
from threading import Thread

def curl_webserver():
    pages = ['/', '/about', '/contact']
    server = ['http://10.0.0.100:80']

    random_page = random.choice(pages)
    random_server = random.choice(server)

    try:
        print('Curling', random_server + random_page)
        requests.get(random_server + random_page)
        wait = random.randint(5, 10)
        time.sleep(wait)
        os.system("ip -s -s neigh flush all")
    except requests.exceptions.RequestException as e:
        pass

def random_ping():
    ip = '10.0.' + str(random.randint(1, 5)) + '.' + str(random.randint(1, 3))

    ip_header = b'\x45\x00\x00\x1c' # Version, IHL, Type of Service | Total Length
    ip_header += b'\xab\xcd\x00\x00' # Identification | Flags, Fragment Offset
    ip_header += b'\x40\x01\x6b\xd8' # TTL, Protocol | Header Checksum
    ip_header += b'\xaa\xaa\xaa\xaa' # Source Address
    ip_header += socket.inet_aton(ip) # Destination Address

    icmp_header = b'\x08\x00\xe5\xca' # Type of message, Code | Checksum
    icmp_header += b'\x12\x34\x00\x01' # Identifier | Sequence Number

    icmp_packet = ip_header + icmp_header

    # send the ICMP packet
    try:
        print('Pinging', ip)
        # Create a raw socket
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        # Set the IP header
        raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # Send the ICMP packet
        raw_socket.sendto(icmp_packet, (ip, 0))
        raw_socket.close()
    except Exception as e:
        pass

def random_traffic():
    while True:
        id = random.choice([0])
        if id == 0:
            curl_webserver()
        else:
            random_ping()
        time.sleep(2)

if __name__ == '__main__':
    for _ in range(3):
        t = Thread(target=random_traffic)
        t.start()