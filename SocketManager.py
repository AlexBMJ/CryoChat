from socket import socket, gethostbyname, gethostname, AF_INET, SOCK_DGRAM, SHUT_RDWR
from tkinter import messagebox
import sys, threading

class SocketSetup():
	def __init__(self, config_dict, recv_queue):
		self.config_dict = config_dict
		self.recv_queue = recv_queue


	def StartListener(self, ):
		if self.config_dict['PeerPort'].isdigit():
			PORT_NUMBER = int(self.config_dict['PeerPort'])
			hostName = gethostbyname('0.0.0.0')
			self.MainSocket = socket(AF_INET, SOCK_DGRAM)
			try:
				self.MainSocket.bind((hostName, PORT_NUMBER))
				return PORT_NUMBER
			except:
				self.MainSocket.shutdown(SHUT_RDWR)
				messagebox.showerror("Broadcast Error", 'Only one listener can be opened on this port (' + str(PORT_NUMBER) + ').\nTry closing any previous instances of the program.')
				sys.exit()
		else:
			messagebox.showerror("Port Error", "Port must be an integer!")
			sys.exit()

		ThreadedLoop(self.MainSocket, self.recv_queue).start()

class ThreadedLoop(threading.Thread):
	def __init__(self, socket, queue):
		self.ThreadSocket = socket
		self.recv_queue = queue
		self.ThreadSocket.settimeout(0.1)
		threading.Thread.__init__(self)

	def run(self):
		try:
			(self.data,self.addr) = self.ThreadSocket.recvfrom(4096)
			self.recv_queue.put((self.data, self.addr))
		except:
			pass