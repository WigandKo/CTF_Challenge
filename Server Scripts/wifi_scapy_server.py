
import fnmatch
from scapy.all import *
from scapy_server import scapy_socket

AUTH_PAYLOAD = "$2y$10$/Mnu0IilcKcENjJFYAkRLuYoNqMWIlF5TtMJyzM9ELY88GKgEL46m"

#This method starts the server for the CTF challenge.
def server_program(server_ip, port):
	scapy_server = scapy_socket(server_ip, port)
	scapy_server.tcp_handshake()

	loggedin = False
	loginStateMessage = ""
	command = ""

	#While loop for login
	while not loggedin:
		usernamequery = loginStateMessage + "Connection successfully established"
		send_payload = scapy_server.send_receive_packet(usernamequery)


		if send_payload == AUTH_PAYLOAD:
			succLogin = "You successfully logged in!"
			loggedin = True
			command = scapy_server.send_receive_packet(succLogin)
		else:
			loginStateMessage = "[ERROR] The information entered is incorrect!\n"


	currentDirectory = "Documents"

	#After login, this whileloop simulates the server files and the shell
	while loggedin:
		serverFiles = ["WifiFiles", "someOldFlag.png", "windowsXPBackground.png", "windows98Background.png", "motivation.txt"]
		
		#Variable that will be the output of the server shell depending on the input command
		message = ""

		#If nothing is transmitted from the communication partner as payload
		if not command:
			command = ""

		if command.startswith("ls") or fnmatch.fnmatch(command, "dir"):
			output = []
			if currentDirectory == "Documents":
				if fnmatch.fnmatch(command, "ls -l"):
					output.append(str("-rwxr-xr-x 3 1000 65534 4.0K Oct 19 14:48" +" "+ serverFiles[0]+ "\n"))
					output.append(str("-r--r----- 1 1000 65534 4.0K Oct 19 14:48" +" "+ serverFiles[1]+ "\n"))

				if fnmatch.fnmatch(command, "ls -la*"):
					output.append(str("drwxr-xr-x 2 1000 65534 4.0K Oct 19 14:48 ."+ "\n"))
					output.append(str("drwxrwx--- 16 1000 65534 4.0K Oct 19 14:48 .."+ "\n"))
					output.append(str("-rwxr-xr-x 3 1000 65534 4.0K Oct 19 14:48" +" "+ serverFiles[0]+ "\n"))
					output.append(str("-r--r----- 1 1000 65534 4.0K Oct 19 14:48" +" "+ serverFiles[1]+ "\n"))

				if fnmatch.fnmatch(command, "ls") or fnmatch.fnmatch(command, "dir"):
					output.append(str(serverFiles[0] +" "+ serverFiles[1]))

			if currentDirectory == "WifiFiles":
				if fnmatch.fnmatch(command, "ls -l"):
					output.append(str("-r--r----- 1 1000 65534 4.0K Oct 19 14:48" +" "+ serverFiles[2]+ "\n"))
					output.append(str("-r--r----- 1 1000 65534 4.0K Oct 19 14:48" +" "+ serverFiles[3]+ "\n"))
					output.append(str("-r--r----- 1 1000 65534 4.0K Oct 19 14:48" +" "+ serverFiles[4]+ "\n"))

				if fnmatch.fnmatch(command, "ls -la*"):
					output.append(str("drwxr-xr-x 3 1000 65534 4.0K Oct 19 14:48 ."+ "\n"))
					output.append(str("drwxrwx--- 2 1000 65534 4.0K Oct 19 14:48 .."+ "\n"))
					output.append(str("-r--r----- 1 1000 65534 4.0K Oct 19 14:48" +" "+ serverFiles[2]+ "\n"))
					output.append(str("-r--r----- 1 1000 65534 4.0K Oct 19 14:48" +" "+ serverFiles[3]+ "\n"))
					output.append(str("-r--r----- 1 1000 65534 4.0K Oct 19 14:48" +" "+ serverFiles[4]+ "\n"))

				if fnmatch.fnmatch(command, "ls") or fnmatch.fnmatch(command, "dir"):
					output.append(str(serverFiles[2] +" "+ serverFiles[3] +" "+ serverFiles[4]))

			if len(output) > 0:
				message = "".join(output)


		if fnmatch.fnmatch(command, "cd*"):
			if command == "cd .." and currentDirectory == "WifiFiles":
				currentDirectory = "Documents"
				message = "home/user/Documents"
			elif command == "cd WifiFiles" and currentDirectory == "Documents":
				currentDirectory = "WifiFiles"
				message = "home/user/Documents/WifiFiles"

		if fnmatch.fnmatch(command, "pwd*"):
			if currentDirectory == "WifiFiles":
				message = "home/user/Documents/WifiFiles"
			if currentDirectory == "Documents":
				message = "home/user/Documents"

		if fnmatch.fnmatch(command, "help*"):
			message = """GNU bash, version 5.1.4 (1)-release (arm-unknown-linux-gnueabihf)
These shell commands are defined internally. Type `help' to see this list.
			
cat			
cd [dir]
dir
exit
ls [-l] [-la]
pwd
"""

		if fnmatch.fnmatch(command, "cat*"):
			if (fnmatch.fnmatch(command, "cat " + serverFiles[1]) and currentDirectory == "Documents"):
				message = scapy_server.send_image(serverFiles[1])
			if (fnmatch.fnmatch(command, "cat " + serverFiles[2]) and currentDirectory == "WifiFiles"):
				message = scapy_server.send_image(serverFiles[2])
			if (fnmatch.fnmatch(command, "cat " + serverFiles[3]) and currentDirectory == "WifiFiles"):
				message = scapy_server.send_image(serverFiles[3])
			if (fnmatch.fnmatch(command, "cat " + serverFiles[4]) and currentDirectory == "WifiFiles"):
				message = """Slow but steady wins the race was yesterday.
Today it is time x urgency that resolves the challenge"""
			if not message:
				message = "No such file or directory. Type `help' for further information"
		
		if fnmatch.fnmatch(command, "exit"):
			scapy_server.fin_conv() # close the connection
			break
		if not message:
			message = f"[ERROR] Could not execute {command}, Permission denied. Type `help' for further information"

		#sends the corresponding output of the input command to the communication partner	
		command = scapy_server.send_receive_packet(message)		


if __name__ == '__main__':
	server_program("101.101.101.1", "6000")
