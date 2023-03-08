from scapy_client import scapy_client

def client_program():
    scapy_server = scapy_client()
    data = scapy_server.tcp_handshake()
    while data:
        message = input(" -> ")  # take input
        data = scapy_server.send_receive_package(message)
        print("Server reply:", data)


if __name__ == '__main__':
    print("Started the program btw")
    client_program()