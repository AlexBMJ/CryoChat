from socket import socket, gethostbyname, gethostname, AF_INET, SOCK_DGRAM, SHUT_RDWR
from tkinter import messagebox
import sys, threading
import KeyExchange

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

def SendMsg(msg_string):
	self.StartSocket.sendto(msg_string.encode('utf-8'),(self.target_ip_address, self.PORT_NUMBER))


MainSocket = socket(AF_INET, SOCK_DGRAM)

class EstablishConnection():
	def __init__(self, GUI, ):



	def EstablishPeerConnection(self):
		eval("self.Stage_" + str(self.stage) + "()")

	# Stage 0 checks for an incoming connection or a user starting it
	def Stage_0(self):
		if self.raw_msg == b'<PEER_START>' or self.startconnect == True:
			self.GUI.connectButton.config(state='disabled',text='Connecting')
			self.keygen = KeyExchange.KeyGenerator()
			self.PriKey = self.keygen.private_key(1024)
			self.own_public = bytes(str(self.keygen.public_key()).encode('utf-8'))

			if self.startconnect == True:
				self.StartSocket.sendto(self.own_public,(self.target_ip_address, self.PORT_NUMBER))
				self.stage = 1
				self.notif_disp_queue.put("[Connecting to " + self.target_ip_address + "]")
			else:
				self.StartSocket.sendto(self.own_public,(self.IPaddress, self.PORT_NUMBER))
				self.stage = 1
				self.notif_disp_queue.put("[Incoming connection from " + self.IPaddress + "]")
	# Stage 1 Generates keys for Diffie-hellman key exchange and sends it to the peer
	def Stage_1(self):
		if self.raw_msg != None:
			if len(self.raw_msg) > 2000:
				self.recieved_public = self.raw_msg
				self.keygen.secret_key(int(self.recieved_public))
				self.encryption_key = self.keygen.key
				self.ip_connected_client = self.IPaddress
				self.timer = 0
				if self.startconnect == False:
					self.stage = 2
				else:
					try:
						enc_msg = self.encrypt(str(self.config_dict['DefaultName']), str(self.encryption_key))
					except:
						enc_msg = None
						return None

					verification_hash = hashlib.sha256(enc_msg + self.encryption_key.encode('utf-8')).hexdigest()
					self.StartSocket.sendto(enc_msg + b'|' + verification_hash.encode('utf-8'),(self.ip_connected_client, self.PORT_NUMBER))

					self.stage = 3
					self.notif_disp_queue.put("[Waiting for user verification...]")
		else:
			if self.timer > 100:
				self.StartSocket.sendto("<PEER_STOP>".encode('utf-8'),(self.target_ip_address, self.PORT_NUMBER))
				self.alert_disp_queue.put("[Connection timed out]")
				self.startconnect = False
				self.ip_connected_client = None
				self.connected = False
				self.stage = 0
				self.timer = 0
				self.GUI.connectButton.config(state='normal',text='Connect')
			else:
				self.timer += 1
	# Stage 2 is only run by the receiving user, Shows a dialogue box for request verification
	def Stage_2(self):
		if self.raw_msg != None:
			try:
				msg = self.raw_msg.decode('utf-8').split('|')[0]
				returned_hash = self.raw_msg.decode('utf-8').split('|')[1]
				verification_hash = hashlib.sha256(msg.encode('utf-8') + self.encryption_key.encode('utf-8')).hexdigest()
			except:
				self.alert_disp_queue.put("[Mismatched verification hash returned!]")
				self.stage = 0
				return None

			if returned_hash == verification_hash:
				try:
					dec_msg = self.decrypt(msg.encode('utf-8'), str(self.encryption_key))
				except:
					dec_msg = None
					return None

				self.recv_name = dec_msg
			else:
				self.alert_disp_queue.put("[Mismatched verification hash returned!]")
				self.stage = 0
				return None

			msgbox_result = messagebox.askyesno("Incoming Connection", 'The user "{0}" ({1}) has requested a peer connect.\nStart the connection?'.format(str(self.recv_name), str(self.IPaddress)))
			if msgbox_result == True:
				self.connected = True
				try:
					enc_msg = self.encrypt("<CONNECTION_ALLOWED>", str(self.encryption_key))
				except:
					enc_msg = None
					return None

				verification_hash = hashlib.sha256(enc_msg + self.encryption_key.encode('utf-8')).hexdigest()
				self.StartSocket.sendto(enc_msg + b'|' + verification_hash.encode('utf-8'),(self.ip_connected_client, self.PORT_NUMBER))

				try:
					enc_msg2 = self.encrypt(str(self.config_dict['DefaultName']), str(self.encryption_key))
				except:
					enc_msg2 = None
					return None
				verification_hash2 = hashlib.sha256(enc_msg2 + self.encryption_key.encode('utf-8')).hexdigest()
				self.StartSocket.sendto(enc_msg2 + b'|' + verification_hash2.encode('utf-8'),(self.ip_connected_client, self.PORT_NUMBER))

				self.notif_disp_queue.put('[Connection has been established with "{0}"]'.format(self.recv_name))
				self.GUI.connectButton.config(state='normal',text='Disconnect')
			else:
				try:
					enc_msg = self.encrypt("<CONNECTION_DENIED>", str(self.encryption_key))
				except:
					enc_msg = None
					return None

				verification_hash = hashlib.sha256(enc_msg + self.encryption_key.encode('utf-8')).hexdigest()
				self.StartSocket.sendto(enc_msg + b'|' + verification_hash.encode('utf-8'),(self.ip_connected_client, self.PORT_NUMBER))

				self.startconnect = False
				self.ip_connected_client = None
				self.connected = False
				self.stage = 0
				self.notif_disp_queue.put("[Connection denied]")
				self.GUI.connectButton.config(state='normal',text='Connect')
				
	# Stage 3 is only run by the connecting user. It checks to see if the reciving user has requested the connection.
	def Stage_3(self):
		if self.raw_msg != None:
			try:
				msg = self.raw_msg.decode('utf-8').split('|')[0]
				returned_hash = self.raw_msg.decode('utf-8').split('|')[1]
				verification_hash = hashlib.sha256(msg.encode('utf-8') + self.encryption_key.encode('utf-8')).hexdigest()
			except:
				self.alert_disp_queue.put("[Mismatched verification hash returned!]")
				return None

			if returned_hash == verification_hash:
				try:
					dec_msg = self.decrypt(msg.encode('utf-8'), str(self.encryption_key))
				except:
					dec_msg = None
					return None

			if dec_msg == "<CONNECTION_ALLOWED>":
				self.stage = 4
			elif dec_msg == "<CONNECTION_DENIED>":
				self.startconnect = False
				self.ip_connected_client = None
				self.connected = False
				self.stage = 0
				self.alert_disp_queue.put("[User has denied connection request]")
				self.GUI.connectButton.config(state='normal',text='Connect')

#This completes the setup process, and get's the name of the other client
	def Stage_4(self):
		if self.raw_msg != None:
			try:
				msg = self.raw_msg.decode('utf-8').split('|')[0]
				returned_hash = self.raw_msg.decode('utf-8').split('|')[1]
				verification_hash = hashlib.sha256(msg.encode('utf-8') + self.encryption_key.encode('utf-8')).hexdigest()
			except:
				self.alert_disp_queue.put("[Mismatched verification hash returned!]")
				return None

			if returned_hash == verification_hash:
				try:
					dec_msg = self.decrypt(msg.encode('utf-8'), str(self.encryption_key))
				except:
					dec_msg = None
					return None

			self.recv_name = dec_msg
			self.connected = True
			self.notif_disp_queue.put('[Connection has been established with "{0}"]'.format(self.recv_name))
			self.GUI.connectButton.config(state='normal',text='Disconnect')





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
