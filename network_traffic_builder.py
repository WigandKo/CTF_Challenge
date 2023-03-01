
"""
    Scripts creates the network traffic for CTF Challenge
    For simplicity reasons no loop is used
"""


from scapy.all import *

help_message = """GNU bash, version 5.1.4 (1)-release (arm-unknown-linux-gnueabihf)
These shell commands are defined internally. Type `help' to see this list.
			
cat			
cd [dir]
dir
exit
ls [-l] [-la]
pwd
"""

ls_l = """-rwxr-xr-x 3 1000 65534 4.0K Oct 19 14:48 WifiFiles
"-r--r----- 1 1000 65534 4.0K Oct 19 14:48 flag.txt\n"""


custom_IP = "88.152.8.56"

#Hash code in Byte form that is used for authentication
payload = [0x24, 0x32, 0x79, 0x24, 0x31, 0x30, 0x24, 0x2f, 0x4d, 0x6e, 0x75, 0x30, 0x49, 0x69, 0x6c, 0x63, 0x4b, 0x63, 0x45, 0x4e, 0x6a, 0x4a, 0x46, 0x59, 0x41, 0x6b, 0x52, 0x4c, 0x75, 0x59, 0x6f, 0x4e, 0x71, 0x4d, 0x57, 0x49, 0x6c, 0x46, 0x35, 0x54, 0x74, 0x4d, 0x4a, 0x79, 0x7a, 0x4d, 0x39, 0x45, 0x4c, 0x59, 0x38, 0x38, 0x47, 0x4b, 0x67, 0x45, 0x4c, 0x34, 0x36, 0x6d]
payload = bytearray(payload)
s_port = 6000
c_port = 6000

ip=IP(src=custom_IP, dst="101.101.101.1")
TCP_SYN=TCP(sport=c_port, dport=s_port, flags="S", seq=100)
TCP_SYN= ip/TCP_SYN 

my_ack = TCP_SYN.seq + 1
ip=IP(src="101.101.101.1", dst=custom_IP)
TCP_ACK=TCP(sport=s_port, dport=c_port, flags="SA", seq=200, ack=my_ack)
TCP_SYNACK = ip/TCP_ACK

my_payload="space for rent!"
ip=IP(src=custom_IP, dst="101.101.101.1")
C_TCP_PUSH=TCP(sport=c_port, dport=s_port, flags="A", seq=my_ack, ack=TCP_ACK.seq + 1)
ACK = ip/C_TCP_PUSH

ip=IP(src="101.101.101.1", dst=custom_IP)
S_TCP_ACK=TCP(sport=s_port, dport=c_port, flags="PA", seq=ACK.ack, ack=my_ack)
S_PUSH_1 = ip/S_TCP_ACK/"Connection successfully established\n"

ip=IP(src=custom_IP, dst="101.101.101.1")
C_TCP_PUSH=TCP(sport=c_port, dport=s_port, flags="PA", seq=S_TCP_ACK.ack, ack=S_TCP_ACK.seq + len(S_PUSH_1[Raw].load))
C_PUSH_1 = ip/C_TCP_PUSH/payload

ip=IP(src="101.101.101.1", dst=custom_IP)
S_TCP_ACK=TCP(sport=s_port, dport=c_port, flags="PA", seq=C_PUSH_1.ack, ack=C_TCP_PUSH.seq + len(C_PUSH_1[Raw].load))
S_PUSH_2 = ip/S_TCP_ACK/"\nYou successfully logged in!\n"


ip=IP(src=custom_IP, dst="101.101.101.1")
C_TCP_PUSH=TCP(sport=c_port, dport=s_port, flags="PA", seq=S_PUSH_2.ack, ack=S_PUSH_2.seq + len(S_PUSH_2[Raw].load))
C_PUSH_2 = ip/C_TCP_PUSH/b"ls -l\n"


ip=IP(src="101.101.101.1", dst=custom_IP)
S_TCP_ACK=TCP(sport=s_port, dport=c_port, flags="PA", seq=C_PUSH_2.ack, ack=C_TCP_PUSH.seq + len(C_PUSH_2[Raw].load))
S_PUSH_3 = ip/S_TCP_ACK/ls_l

ip=IP(src=custom_IP, dst="101.101.101.1")
C_TCP_PUSH=TCP(sport=c_port, dport=s_port, flags="PA", seq=S_PUSH_3.ack, ack=S_PUSH_3.seq + len(S_PUSH_3[Raw].load))
C_PUSH_3 = ip/C_TCP_PUSH/"help\n"


ip=IP(src="101.101.101.1", dst=custom_IP)
S_TCP_ACK=TCP(sport=s_port, dport=c_port, flags="PA", seq=C_PUSH_3.ack, ack=C_TCP_PUSH.seq + len(C_PUSH_3[Raw].load))
S_PUSH_4 = ip/S_TCP_ACK/help_message

ip=IP(src=custom_IP, dst="101.101.101.1")
C_TCP_PUSH=TCP(sport=c_port, dport=s_port, flags="PA", seq=S_PUSH_4.ack, ack=S_PUSH_4.seq + len(S_PUSH_4[Raw].load))    
C_PUSH_4 = ip/C_TCP_PUSH/"exit\n"


ip=IP(src="101.101.101.1", dst=custom_IP)
S_TCP_ACK=TCP(sport=s_port, dport=c_port, flags="FA", seq=C_PUSH_4.ack, ack=C_TCP_PUSH.seq + len(C_PUSH_4[Raw].load))
S_PUSH_5 = ip/S_TCP_ACK

ip=IP(src=custom_IP, dst="101.101.101.1")
C_TCP_PUSH=TCP(sport=c_port, dport=s_port, flags="FA", seq=S_PUSH_5.ack, ack=S_PUSH_5.seq + 1)
C_PUSH_5 = ip/C_TCP_PUSH

ip=IP(src="101.101.101.1", dst=custom_IP)
S_TCP_ACK=TCP(sport=s_port, dport=c_port, flags="A", seq=C_PUSH_5.ack, ack=C_TCP_PUSH.seq + 1)
S_PUSH_6 = ip/S_TCP_ACK

wrpcap('captured_traffic.pcap', [TCP_SYN,TCP_SYNACK, ACK,S_PUSH_1,C_PUSH_1,S_PUSH_2, C_PUSH_2,S_PUSH_3, C_PUSH_3,S_PUSH_4, C_PUSH_4, S_PUSH_5, C_PUSH_5, S_PUSH_6])#
