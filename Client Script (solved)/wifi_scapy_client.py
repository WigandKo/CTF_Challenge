from scapy_client import scapy_client

#Hash code for authentication
payload = [0x24, 0x32, 0x79, 0x24, 0x31, 0x30, 0x24, 0x2f, 0x4d, 0x6e, 0x75, 0x30, 0x49, 0x69, 0x6c, 0x63, 0x4b, 0x63, 0x45, 0x4e, 0x6a, 0x4a, 0x46, 0x59, 0x41, 0x6b, 0x52, 0x4c, 0x75, 0x59, 0x6f, 0x4e, 0x71, 0x4d, 0x57, 0x49, 0x6c, 0x46, 0x35, 0x54, 0x74, 0x4d, 0x4a, 0x79, 0x7a, 0x4d, 0x39, 0x45, 0x4c, 0x59, 0x38, 0x38, 0x47, 0x4b, 0x67, 0x45, 0x4c, 0x34, 0x36, 0x6d]
payload = bytearray(payload)

def client_program():
    scapy_server = scapy_client()
    data = scapy_server.tcp_handshake()
    data = scapy_server.send_receive_package(payload)
    while data:
        message = input(" -> ")  # take input
        data = scapy_server.send_receive_package(message)
        print("Server reply:", data)


if __name__ == '__main__':
    print("Started the program btw")
    client_program()