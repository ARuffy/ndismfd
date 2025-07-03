import socket
import sys
import time

def send_tcp_packets(ipaddr, port):
    """Send 4 TCP packets to the specified IP address and port."""
    try:
        # Create a TCP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Connect to the remote address
            sock.connect((ipaddr, port))
            print(f"Connected to {ipaddr}:{port}")

            # Define the string payload
            payloads = [
                "Packet 1: Hello from Python!",
                "Packet 2: Sending TCP packets!",
                "Packet 3: NDIS Filter Driver Test",
                "Packet 4: Final packet!"
            ]

            # Send 4 packets
            for payload in payloads:
                sock.sendall(payload.encode('utf-8'))  # Send data
                print(f"Sent: {payload}")
                time.sleep(1)


    except ConnectionRefusedError:
        print(f"Connection to {ipaddr}:{port} was refused. Is the server running?")
    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    # Check if the correct number of arguments is provided
    if len(sys.argv) != 3:
        print("Usage: python send_tcp_packets.py <ipaddr> <port>")
        sys.exit(1)

    # Read command-line arguments
    ipaddr = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print("Error: Port must be an integer")
        sys.exit(1)

    # Call the function to send packets
    send_tcp_packets(ipaddr, port)