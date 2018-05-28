from socket import socket, gethostbyname, gethostname, AF_INET, SOCK_DGRAM, SHUT_RDWR
from tkinter import messagebox
import sys, threading

class SocketSetup():
	def __init__(self, port):
		self.port = port
		self.StartListener()

	def StartListener(self):
		if self.port.isdigit():
			PORT_NUMBER = int(self.port)
			hostName = gethostbyname('0.0.0.0')
			try:
				MainSocket.bind((hostName, PORT_NUMBER))
			except:
				MainSocket.shutdown(SHUT_RDWR)
				messagebox.showerror("Broadcast Error", 'Only one listener can be opened on this port (' + str(PORT_NUMBER) + ').\nTry closing any previous instances of the program.')
				sys.exit()
		else:
			messagebox.showerror("Port Error", "Port must be an integer!")
			sys.exit()

def RecvThreadedMsg():
	ThreadedLoop(MainSocket, recv_queue).start()


def InitializeSocketProtocol(port, recv):
	SocketSetup(port)
	global recv_queue
	recv_queue = recv
	return str(gethostbyname(gethostname()) + ":" + str(port))

MainSocket = socket(AF_INET, SOCK_DGRAM)







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
