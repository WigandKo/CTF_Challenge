from scapy.all import *

"""
    This script implements the required network communication functions for the CTF challenge.
    It can perform the three-way handshake, send short messages, transmit image files, and terminate a connection.
"""

#creates a socket with scapy
class scapy_socket(object):

    #sets the required credentials
    def __init__(self, src_ip, port):
        self.src_ip = src_ip
        self.port = port
        self.seq = random.randint(1, 4294967295)

    #manages the adjustment of sequence number and ACK number based on the received packets
    def adjust_control_numbers(self,l_pack):
        if l_pack.haslayer(Raw):
            l = len(l_pack[Raw].load)
        elif l_pack[TCP].flags.S or l_pack[TCP].flags.F:
            l = 1
        else:
            l = 0
        s_c, a_c= l_pack[TCP].seq, l_pack[TCP].ack
        self.seq = a_c
        self.ack = s_c + l

    #sniffs for incoming packets that want to establish a connection
    #then performs the three-way handshake
    def tcp_handshake(self):
        syn = sniff(count=1, lfilter = lambda x: x.haslayer(TCP) and x[TCP].dport == 6000)[0]

        print("Starting the Handshake ...")
        self.dest_ip = syn[IP].src
        self.ip_eth_layer = Ether(src=Ether().src, dst=syn[Ether].src)/IP(src = self.src_ip, dst = self.dest_ip)
        syn_ack = TCP(flags = 'SA', seq = self.seq, ack = syn[TCP].seq + 1, sport = 6000, dport = 6000)
        client_ack = srp1(self.ip_eth_layer/syn_ack, retry = -3, timeout = 5 )
        self.seq = client_ack[TCP].ack
        self.ack = client_ack[TCP].seq       
        print("Handshake Done")

    #Sends the packets to the communication partner with whom a connection was previously established
    #The window size is constantly set to one, which is necessary due to the implementation structure
    #statImageXP is used to mark a specific packet with an urgent pointer and a timestamp value
    def send_receive_packet(self, payload, startImageXP = False):
        first = TCP(flags = 'PA', seq = self.seq , ack = self.ack, sport = 6000, dport = 6000,window=1) #, options=[('Timestamp', (11200111, 0))]
        s_pack = self.ip_eth_layer/first/Raw(load=payload)
        if startImageXP:
            s_pack[TCP].options = [('Timestamp', (285, 0))]
            s_pack.urgptr=140
        rec_p = srp1(s_pack, retry = -3, timeout = 10)
        self.adjust_control_numbers(rec_p)

        if rec_p[TCP].flags.P:
            return(rec_p[Raw].load.decode())

    #used to transmit images
    def send_image(self, imagename):
        print("Sending image...")
        file = open(imagename, "rb")
        image_data = file.read(1440)

        #first packet send of the image windowsXPBackground is marked with a specific urgent pointer and timestamp
        if imagename == "windowsXPBackground.png":
            rec_p = self.send_receive_packet(image_data, startImageXP=True)
            image_data = file.read(1440)

        while image_data:
            rec_p = self.send_receive_packet(image_data)
            image_data = file.read(1440)
        print("Finished image transmittion")
        return (">>>")
    
    #Initiates termination of a connection
    def fin_conv(self):
        print("Ending Conversation ...")
        fin_ack = TCP(flags = 'FA', seq = self.seq , ack = self.ack, sport = 6000, dport = 6000)
        rec_fin = srp1(self.ip_eth_layer/fin_ack, retry = -3, timeout = 5)
        self.adjust_control_numbers(rec_fin)
        ack = TCP(flags = 'A', seq = self.seq , ack = self.ack, sport = 6000, dport = 6000)
        sendp(self.ip_eth_layer/ack)
        print("Finished Conversation")


if __name__ == "__main__":
    scapy_server = scapy_socket("101.101.101.1", "6000")
    scapy_server.tcp_handshake()
    scapy_server.send_receive_packet("Example Message")
