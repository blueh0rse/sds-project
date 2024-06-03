import socket
import sys

def scan_ports(host, start_port, end_port):
    for port in range(start_port, end_port + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.01)
            s.connect((host, port))
            print(f"Port {port} is open")
        except:
            pass
        finally:
            s.close()

if __name__ == "__main__":
    try:
        host = sys.argv[1]
        start_port = int(sys.argv[2])
        end_port = int(sys.argv[3])
        scan_ports(host, start_port, end_port)
        print("Ports scanned")
    except:
        print("Usage: python portScanning.py <host> <start_port> <end_port>")
        sys.exit(1)