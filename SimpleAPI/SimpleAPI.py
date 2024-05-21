from flask import Flask, request
import socket
import sys

app = Flask(__name__)

def notify_api_honey_pot(ip_owner):
    # Create a raw socket
    print(ip_owner)
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    # Set the IP header
    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    ip_header = b'\x45\x00\x00\x1c' # Version, IHL, Type of Service | Total Length
    ip_header += b'\xab\xcd\x00\x00' # Identification | Flags, Fragment Offset
    ip_header += b'\x40\x01\x6b\xd8' # TTL, Protocol | Header Checksum
    ip_header += socket.inet_aton(ip_owner) # Source Address
    ip_header += b'\xfe\xfe\xfe\xfe' # Destination Address

    icmp_header = b'\x08\x00\xe5\xca' # Type of message, Code | Checksum
    icmp_header += b'\x12\x34\x00\x01' # Identifier | Sequence Number

    icmp_packet = ip_header + icmp_header

    # Send the ICMP packet
    raw_socket.sendto(icmp_packet, (ip_owner, 0))
    raw_socket.close()

@app.route('/')
def home():
    # Return the home page and all the routes of the API as a html page
    return '''
    <h1>Simple API</h1>
    <p>A prototype API for distant reading of science fiction novels.</p>
    <p>Available routes:</p>
    <ul>
        <a href="/about">About</a>
        <a href="/contact">Contact</a>
    </ul>
    ''' + "\n"

@app.route('/about')
def about():
    return 'This is the about page.\n'

@app.route('/contact')
def contact():
    return 'You can contact us at contact@example.com.\n'

@app.route('/honeypot')
def honeypot():
    notify_api_honey_pot(request.remote_addr)
    return 'This is a honeypot route.\n'

if __name__ == '__main__':
    app.run(host=sys.argv[1], port=80)