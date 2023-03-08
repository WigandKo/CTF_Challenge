from scapy.all import *


class scapy_client(object):
    def __init__(self, src_ip = "88.152.8.116", dest_ip = "101.101.101.1"):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.port = 6000
        self.seq = 100

    def adjust_control_numbers(self,l_pack):
        if l_pack.haslayer(Raw):
            l = len(l_pack[Raw].load)
        else:
            l = 1
        s_c, a_c= l_pack[TCP].seq, l_pack[TCP].ack
        self.seq = a_c
        self.ack = s_c + l

    def tcp_handshake(self):
        print("StartHandshake")
        # SYN packet
        self.ip_layer = IP(src=self.src_ip,dst=self.dest_ip)
        SYN = TCP(sport=6000, dport=6000, flags='S', seq=self.seq)
        SYNACK = sr1(self.ip_layer/SYN)

        # ACK packet
        print(SYNACK.seq)
        ACK = TCP(sport=6000, dport=6000, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)#+ 1
        f_m = sr1(self.ip_layer/ACK)
        self.adjust_control_numbers(f_m)
        print("Handshake Done")
        print("First Message:", f_m[Raw].load.decode())
        return(f_m[Raw].load.decode())

    def send_receive_package(self, payload):
        first = TCP(flags = "PA", seq = self.seq, ack=self.ack, sport = 6000, dport = 6000)
        print("waiting")
        rec_p = sr1(self.ip_layer/first/Raw(load=payload), retry = -3, timeout = 5)
        self.adjust_control_numbers(rec_p)

        if rec_p[TCP].flags.F:
            print("Recognized Finisher")
            self.fin_conv()
            return None

        if rec_p.haslayer(Raw):
            #print(rec_p[Raw].load)
            if rec_p[TCP].flags.P:
                try:
                    str_payload = rec_p[Raw].load.decode()
                    return(str_payload)
                except (UnicodeDecodeError, AttributeError):
                    return self.get_image(rec_p)

    def get_image(self, rec_p):
        file = open("whatsThat.png", "wb")
        end_Of_File = False
        while not end_Of_File:
            self.adjust_control_numbers(rec_p)
            file.write(rec_p[Raw].load)
            img_m = TCP(flags = "A", seq = self.seq, ack=self.ack, sport = 6000, dport = 6000)
            rec_p = sr1(self.ip_layer/img_m, retry = -3, timeout = 5)

            if "\\x00\\x00IEND\\xaeB`\\x82" in str(rec_p[Raw].load):
                end_Of_File = True
                self.adjust_control_numbers(rec_p)
                img_m = TCP(flags = "A", seq = self.seq, ack=self.ack, sport = 6000, dport = 6000)
                rec_p = sr1(self.ip_layer/img_m, retry = -3, timeout = 5)
        print("END OF FILE")
        return rec_p[Raw].load.decode()     

    def fin_conv(self):
        fin_ack = TCP(flags = 'FA', seq = self.seq , ack = self.ack, sport = 6000, dport = 6000)
        rec_fin = sr1(self.ip_layer/fin_ack, retry = -3, timeout = 5)
        print("Finished Conversation")
        return False

if __name__ == "__main__":
    scapy_server = scapy_client()
    scapy_server.tcp_handshake()
    scapy_server.send_receive_package("Esample Message")

