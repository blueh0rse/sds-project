import socket
import sys

if len(sys.argv) != 2:
    print("Usage: %s <destination IP>" % sys.argv[0])
    sys.exit(1)

# Create a raw socket
raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# Set the IP header
raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

ip_header = b'\x45\x00\x00\x1c' # Version, IHL, Type of Service | Total Length
ip_header += b'\xab\xcd\x00\x00' # Identification | Flags, Fragment Offset
ip_header += b'\x40\x01\x6b\xd8' # TTL, Protocol | Header Checksum
ip_header += b'\xff\xff\xff\xff' # Source Address
ip_header += socket.inet_aton(sys.argv[1]) # Destination Address

icmp_header = b'\x08\x00\xe5\xca' # Type of message, Code | Checksum
icmp_header += b'\x12\x34\x00\x01' # Identifier | Sequence Number

icmp_packet = ip_header + icmp_header

# Send the ICMP packet
raw_socket.sendto(icmp_packet, ("10.0.2.1", 0))
raw_socket.close()