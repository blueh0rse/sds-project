import socket
import requests
import random
import time
from threading import Thread

def curl_webserver():
    pages = ['/', '/about', '/contact']
    server = ['10.0.5.1:80', '10.0.5.2:80']

    random_page = random.choice(pages)
    random_server = random.choice(server)

    try:
        print('Curling', random_server + random_page)
        requests.get(random_server + random_page)
    except requests.exceptions.RequestException as e:
        pass

def random_ping():
    ip = '10.0.' + str(random.randint(1, 5)) + '.' + str(random.randint(1, 3))

    # send the ICMP packet
    try:
        print('Pinging', ip)
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.sendto(b'hello', (ip, 0))
        s.close()
    except Exception as e:
        pass

def random_traffic():
    while True:
        id = random.choice([0, 1, 2, 4, 5])
        if id == 0:
            curl_webserver()
        else:
            random_ping()
        time.sleep(2)

if __name__ == '__main__':
    for _ in range(3):
        t = Thread(target=random_traffic)
        t.start()