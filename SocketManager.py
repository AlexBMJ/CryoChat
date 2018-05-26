from socket import socket, gethostbyname, gethostname, AF_INET, SOCK_DGRAM, SHUT_RDWR
from tkinter import messagebox
import sys, threading

class ConnectionSetup():
	def StartListener(config_dict):
		if config_dict['PeerPort'].isdigit():
			PORT_NUMBER = int(config_dict['PeerPort'])
			hostName = gethostbyname('0.0.0.0')
			global MainSocket
			MainSocket = socket(AF_INET, SOCK_DGRAM)
			try:
				MainSocket.bind((hostName, PORT_NUMBER))
				return PORT_NUMBER
			except:
				MainSocket.shutdown(SHUT_RDWR)
				messagebox.showerror("Broadcast Error", 'Only one listener can be opened on this port (' + str(PORT_NUMBER) + ').\nTry closing any previous instances of the program.')
				sys.exit()
		else:
			messagebox.showerror("Port Error", "Port must be an integer!")
			sys.exit()

	def GetIPaddress():
		return gethostbyname(gethostname())

	def StartSocketThread(recv_queue):
		ThreadedLoop(recv_queue).start()


class ThreadedLoop(threading.Thread):
	def __init__(self, queue):
		MainSocket = socket
		self.recv_queue = queue
		MainSocket.settimeout(0.1)
		threading.Thread.__init__(self)

	def run(self):
		try:
			(self.data,self.addr) = MainSocket.recvfrom(4096)
			self.recv_queue.put((self.data, self.addr))
		except:
			pass