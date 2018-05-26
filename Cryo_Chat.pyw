# Made by Alex & Lasse

# Import Statements
from tkinter import Tk, PhotoImage, Frame, Entry, Button, Text, ttk, messagebox, Toplevel, Listbox, Label, ANCHOR, END, WORD
from tkinter.ttk import Entry, Button, Separator
from subprocess import Popen, PIPE
from Crypto import Random
from Crypto.Cipher import AES
from socket import socket, gethostbyname, gethostname, AF_INET, SOCK_DGRAM, SHUT_RDWR
import os, hashlib, binascii, sys, subprocess, time, threading, queue, ssl, base64, collections

import KeyExchange
import ConfigHandler


# Settings Window GUI
class SettingsWindow():
	def __init__(self, root, cfg_dict, send_queue):
		# Redefine Arguments for Class
		self.config_dict = cfg_dict
		self.send_queue = send_queue

		# Topelevel of a tkinter root raises it to a new window independent from other tkinter loops
		self.stRoot = Toplevel(root)
		self.stRoot.title("Settings")
		self.stRoot.resizable(0, 0)
		self.stRoot.iconbitmap(folderpath + "\\bin\\settings.ico")
		self.stRoot.geometry("212x270")
		self.stFrame = Frame(self.stRoot)
		self.stFrame.grid(padx=4, pady=4)
		self.nameLabel = Label(self.stFrame, text="Name: ")
		self.nameLabel.grid(column=0, row=0, sticky="e")
		self.nameEntry = Entry(self.stFrame, width=13)
		self.nameEntry.grid(column=1, row=0)
		self.portLabel = Label(self.stFrame, text="Port: ")
		self.portLabel.grid(column=2, row=0, sticky="e")
		self.portEntry = Entry(self.stFrame, width=5)
		self.portEntry.grid(column=3, row=0, pady=4, sticky="w")
		self.blacklistFrame = Frame(self.stFrame)
		self.blacklistFrame.grid(column=0, row=2, columnspan=4)
		Separator(self.blacklistFrame).grid(column=0, row=0, columnspan=2, ipadx=20, sticky="ew", pady=4)
		self.blacklistEntry = Entry(self.blacklistFrame, width=21)
		self.blacklistEntry.grid(column=0, row=1, sticky="e")
		self.blacklistaddButton = Button(self.blacklistFrame, text="Add IP", width=8, command=self.AddIp)
		self.blacklistaddButton.grid(column=1, row=1, padx=2)
		self.blacklistListbox = Listbox(self.blacklistFrame, width=32, height=8)
		self.blacklistListbox.grid(column=0, row=2, columnspan=2, padx=4, pady=2, sticky="s")
		self.removeFrame = Frame(self.stRoot)
		self.removeFrame.grid()
		self.removesingleButton = Button(self.removeFrame, text="Remove IP", width=12, command=lambda lb=self.blacklistListbox: self.blacklistListbox.delete(ANCHOR))
		self.removesingleButton.grid(column=0, row=3, padx=9, pady=0)
		self.removeallButton = Button(self.removeFrame, text="Clear All", width=12, command=lambda lb=self.blacklistListbox: self.blacklistListbox.delete(0, END))
		self.removeallButton.grid(column=1, row=3, padx=9)
		self.applyButton = Button(self.removeFrame, text="Apply", width=15, command=self.WriteChanges)
		self.applyButton.grid(column=0, row=4, padx=9, pady=5, columnspan=2)

		# Insert info from config file into settings window
		self.nameEntry.insert(0, self.config_dict['DefaultName'])
		self.portEntry.insert(0, self.config_dict['PeerPort'])

		for obj in eval(self.config_dict['Blacklist']):
			self.blacklistListbox.insert(0, obj)

	# When the "APPLY" button is pressed this function is executed
	def WriteChanges(self):
		# Test if the port entered is an integer
		if self.portEntry.get().isdigit():
			# Ask the user if they want to restart the application
			msgbox_result = messagebox.askyesno("Saving Changes", 'You have to restart to apply changes,\nQuit now?')
			if (msgbox_result == True):
				# Write changes to text file (config.txt)
				self.config_dict.update({'DefaultName':self.nameEntry.get()})
				self.config_dict.update({'PeerPort':self.portEntry.get()}) 
				self.config_dict.update({'Blacklist':str(self.blacklistListbox.get(0, END))})

				write_config = str(self.config_dict).replace('{','{\n').replace('}','\n}').replace(',',',\n').replace(' ', '')

				self.configfile = open(folderpath + '\\bin\\config.txt', 'w')
				self.configfile.write(write_config)
				self.configfile.close()
				self.send_queue.put('/restart')
			else:
				self.stRoot.focus()
		# if the port is not an intetger, show and error 
		else:
			messagebox.showerror("Port Error", "Port must be an integer!")
			self.stRoot.focus()

		#Function that adds an ip to the blacklist from the entry field
	def AddIp(self):
		self.blacklistListbox.insert(0, str(self.blacklistEntry.get()))
		self.blacklistEntry.delete(0, END)

# Main Window containing GUI elements
class MainWindow():
	def __init__(self, master, send_queue, notdisp_queue, recvdisp_queue, alertdisp_queue, ownmsgdisp_queue, cfg_dict, history):		
		self.config_dict = cfg_dict

		# Define history and queue variables
		self.history_index = -1
		self.history = history
		self.send_queue = send_queue
		self.notif_disp_queue = notdisp_queue
		self.alert_disp_queue = alertdisp_queue
		self.recvmsg_disp_queue = recvdisp_queue
		self.ownmsgdisp_queue = ownmsgdisp_queue

		# bind exit tkinter window to a function
		master.protocol("WM_DELETE_WINDOW", self.OnClosing)

		# GUI elements
		self.settingsImage = PhotoImage(file=folderpath + '\\bin\\settings.png')
		self.master = master
		self.master.iconbitmap(folderpath + '\\bin\\logo.ico')
		self.mainFrame = Frame(master)
		self.mainFrame.grid(padx=4, pady=4)
		self.menuFrame = Frame(self.mainFrame)
		self.menuFrame.grid(column=0, row=0)
		self.targetIpEntry = Entry(self.menuFrame, width=14)
		self.targetIpEntry.grid(column=0, row=0, padx=4)
		self.connectButton = Button(self.menuFrame, text="Connect", width=12, command=self.Connect)
		self.connectButton.grid(column=1, row=0, padx=(0,4))
		self.settingsButton = Button(self.menuFrame, width=3, image=self.settingsImage, command=self.OpenSettings)
		self.settingsButton.grid(column=3, row=0, padx=(153, 2), pady=1, sticky="w")
		self.chatText = Text(self.mainFrame, width=45, height=25, font=("Verdana", 10), wrap=WORD)
		self.chatText.grid(column=0, row=1, padx=1, pady=1)
		self.sendFrame = Frame(self.mainFrame)
		self.sendFrame.grid(column=0, row=2, padx=1, pady=1)
		self.sendButton = Button(self.sendFrame, text="Send", width=10, command=self.SendMsg)
		self.sendButton.grid(column=1, row=2, padx=1, pady=1)
		self.inputEntry = Entry(self.sendFrame, width=48)
		self.inputEntry.grid(column=0, row=2, padx=1, pady=1)
		self.inputEntry.bind('<Return>', self.SendMsg)
		self.inputEntry.bind('<Up>', self.EntryHistory)
		self.inputEntry.bind('<Down>', self.EntryHistory)
		
		# Insert last ip connected to, from config file
		self.targetIpEntry.insert(0, self.config_dict["LastConnectedIP"])

		# Run update display function loop
		self.UpdateDisplay()

	# Function that calls the settings window class
	def OpenSettings(self):
		try:
			self.sett_wind.stRoot.focus()
		except:
			self.sett_wind = SettingsWindow(self.master, self.config_dict, self.send_queue)

	# Function called when the connect button is pressed
	def Connect(self): # YES I KNOW THIS FUNCTION IS HARDCODED TO THE GUI, i'm lazy.
		if self.connectButton.cget('text') == 'Connect':
			self.connectButton.config(state='disabled',text='Connecting')
			self.send_queue.put("/connect " + self.targetIpEntry.get())
		else:
			self.connectButton.config(state='normal',text='Connect')
			self.send_queue.put("/disconnect")

	# Entry History handler
	def EntryHistory(self, arg):
		if len(self.history) > 0:
			if arg.keysym == 'Up' and self.history_index < len(self.history)-1:
				self.history_index += + 1

			elif arg.keysym == 'Down' and self.history_index >= 0:
				self.history_index -= 1

			self.inputEntry.delete(0, END)
			if self.history_index != -1:
				self.inputEntry.insert(0, self.history[self.history_index])

	# Update display function, updates the textfield with messages
	def UpdateDisplay(self):
		self.chatText.configure(state="normal")
		self.insertNotification()
		self.insertRecMsg()
		self.insertAlert()
		self.insertOwnMsg()

		while len(self.chatText.get("1.0", END).split("\n"))-2 > 150:
			self.chatText.delete("1.0", "2.0")
		
		self.chatText.configure(state="disabled")

	def insertNotification(self):
		try:
			displaytext = self.notif_disp_queue.get(0)
		except queue.Empty:
			displaytext = None
			return None

		pos0 = self.chatText.index("end-1c")
		self.chatText.insert(END, displaytext+"\n")
		self.chatText.tag_add("noti", pos0, "end-1c")
		self.chatText.tag_config("noti", background="light sky blue", foreground="black")
		self.chatText.see("end")

	def insertRecMsg(self):
		try:
			displaytext = self.recvmsg_disp_queue.get(0)
		except queue.Empty:
			displaytext = None
			return None

		pos0 = self.chatText.index("end-1c")
		self.chatText.insert(END, displaytext+"\n")
		self.chatText.tag_add("msg", pos0, "end-1c")
		self.chatText.tag_config("msg", background="gray90", foreground="black")
		self.chatText.see("end")

	def insertOwnMsg(self):
		try:
			displaytext = self.ownmsgdisp_queue.get(0)
		except queue.Empty:
			displaytext = None
			return None

		self.chatText.insert(END, displaytext + "\n")
		self.chatText.see("end")

	def insertAlert(self):
		try:
			displaytext = self.alert_disp_queue.get(0)
		except queue.Empty:
			displaytext = None
			return None

		pos0 = self.chatText.index("end-1c")
		self.chatText.insert(END, displaytext+"\n")
		self.chatText.tag_add("alert", pos0, "end-1c")
		self.chatText.tag_config("alert", background="salmon", foreground="black")
		self.chatText.see("end")

	def SendMsg(self, NULL=""):
		self.history_index = -1
		self.send_queue.put(self.inputEntry.get())
		self.inputEntry.delete(0, END)

	# Before closing the application, ask the user if they are sure
	def OnClosing(self):
		if messagebox.askokcancel("Quit?", "All current sessions will be disconnected."):
			threading.Thread(target=self.CloseApp).start()

	def CloseApp(self):
		self.send_queue.put('/exit')

	# Main class which handles everything else
class MainClass:
	def __init__(self, master):
		super(MainClass, self).__init__()
		
		# Define all variables for this class
		self.stage = 0
		self.raw_msg = str()
		self.IPaddress = str()
		self.connected = False
		self.startconnect = False
		self.ip_connected_client = str()
		self.full_raw_data = None
		self.recv_name = "Anonymous"
		self.own_public = bytes()
		self.timer = 0
		
		self.command_list = ('connect', 'disconnect', 'help', 'clear', 'exit', 'restart')

		self.history = collections.deque(maxlen=20)

		self.master = master
		self.send_queue = queue.Queue()
		self.recv_queue = queue.Queue()
		self.notif_disp_queue = queue.Queue()
		self.recvmsg_disp_queue = queue.Queue()
		self.alert_disp_queue = queue.Queue()
		self.ownmsg_disp_queue = queue.Queue()

		self.config_dict = ConfigHandler.ReadConfig.main(folderpath)

		self.GUI = MainWindow(self.master, self.send_queue, self.notif_disp_queue, self.recvmsg_disp_queue, self.alert_disp_queue, self.ownmsg_disp_queue, self.config_dict, self.history)
		self.GUI.inputEntry.focus()

		self.TKLoop()



	def StartListener(self):
		try:
			self.PORT_NUMBER = int(self.config_dict['PeerPort'])
		except ValueError:
			messagebox.showerror("Port Error", "Port must be an integer!")
			sys.exit()

		hostName = gethostbyname('0.0.0.0')
		self.StartSocket = socket(AF_INET, SOCK_DGRAM)
		try:
			self.StartSocket.bind((hostName, self.PORT_NUMBER))
		except:
			self.StartSocket.shutdown(SHUT_RDWR)
			messagebox.showerror("Broadcast Error", 'Only one listener can be opened on this port (' + str(self.PORT_NUMBER) + ').\nTry closing any previous instances of the program.')
			sys.exit()

		self.notif_disp_queue.put(gethostbyname(gethostname()) + ":" + str(self.PORT_NUMBER))
		
	# Main loop which updates all functions needed
	def TKLoop(self):
		ThreadedLoop(self.StartSocket, self.recv_queue).start()
		self.ProcessOutgoing()
		self.ProcessIncoming()
		self.GUI.UpdateDisplay()
		self.master.after(100, self.TKLoop)

	# Processes all outgoing messages
	def ProcessOutgoing(self):
		try:
			msg_send = self.send_queue.get(0)
		except queue.Empty:
			return None

		if len(msg_send) <= 500 and len(msg_send) > 0:
			self.history.appendleft(msg_send)

		if msg_send.startswith("/"):
			self.CommandHandler(msg_send)
		else:
			if self.connected == True:
				if len('<' + self.config_dict["DefaultName"] + '> ' + msg_send) <= 500 and len(msg_send) > 0:
					try:
						enc_msg = self.encrypt('<' + self.config_dict["DefaultName"] + '> ' + str(msg_send), str(self.encryption_key))
					except:
						enc_msg = None
						return None

					verification_hash = hashlib.sha256(enc_msg + self.encryption_key.encode('utf-8')).hexdigest()
					self.ownmsg_disp_queue.put('<' + self.config_dict["DefaultName"] + '> ' + msg_send)
					self.StartSocket.sendto(enc_msg + b'|' + verification_hash.encode('utf-8'),(self.ip_connected_client, self.PORT_NUMBER))

				else:
					if len(msg_send) > 0:
						self.alert_disp_queue.put("[The message cannot be longer than 500 characters]")
			else:
				self.alert_disp_queue.put("[No connection has been established]")

	# If the command syntax is detected, this function is run. It takes one arguement which is the actual command. 
	# The argument is directly translated into a function call. If aa runtime error is called. An error is shown.
	def CommandHandler(self, string):
		rawcommand = string.replace("/", "")
		self.commandsplit = rawcommand.split(" ")

		if self.commandsplit[0] in self.command_list:
			eval('self.' + self.commandsplit[0] + 'cmd()')
		else:
			self.alert_disp_queue.put('["' + self.commandsplit[0] + '" is not a valid command]')

	def connectcmd(self):
		if self.connected == False:
			self.target_ip_address = ""

			try:
				self.target_ip_address = self.commandsplit[1]
				self.StartSocket.sendto("<PEER_START>".encode('utf-8'),(self.target_ip_address, self.PORT_NUMBER))
			except:
				messagebox.showerror("Broadcast Error", 'Invalid IP address:"' + str(self.target_ip_address) + '"')
				self.GUI.connectButton.config(state='normal',text='Connect')
				return None

			self.startconnect = True
			self.config_dict.update({'LastConnectedIP':str(self.target_ip_address)})
			write_config = str(self.config_dict).replace('{','{\n').replace('}','\n}').replace(',',',\n').replace(' ', '')
			configfile = open(folderpath + '\\bin\\config.txt', 'w')
			configfile.write(write_config)
			configfile.close()
		else:
			self.alert_disp_queue.put('[You are already connected to "{0}"]'.format(self.ip_connected_client))

	def helpcmd(self):
		self.notif_disp_queue.put(str(self.command_list))

	def clearcmd(self):
		self.GUI.chatText.config(state='normal')
		self.GUI.chatText.delete(1.0, END)
		self.GUI.chatText.config(state='disabled')

	def disconnectcmd(self):
		if self.connected == True:
			self.StartSocket.sendto("<PEER_STOP>".encode('utf-8'),(self.IPaddress, self.PORT_NUMBER))
			self.startconnect = False
			self.ip_connected_client = None
			self.connected = False
			self.stage = 0
			self.alert_disp_queue.put("[Connection has been terminated]")
			self.GUI.connectButton.config(state='normal',text='Connect')
		else:
			self.alert_disp_queue.put("[No connection has been established]")

	def exitcmd(self):
		self.disconnectcmd()
		self.GUI.master.destroy()
		sys.exit()

	def restartcmd(self):
		self.disconnectcmd()
		threading.Thread(target=self.RestartThread).start()
		sys.exit()

	def RestartThread(self):
		time.sleep(0.2)
		Popen(['python', scriptpath], stdout=PIPE, stderr=PIPE)
		sys.exit()

	# This function handles all outgoing messages
	def ProcessIncoming(self):
		try:
			self.full_raw_data = self.recv_queue.get(0)
			self.raw_msg = self.full_raw_data[0]
			self.IPaddress = str(self.full_raw_data[1][0])
		except queue.Empty:
			self.full_raw_data = None
			self.raw_msg = None

		if self.connected == True:
			if self.raw_msg != None:
				if len(self.raw_msg) > 0:

					if self.raw_msg == b'<PEER_STOP>':
						if self.IPaddress == self.ip_connected_client:
							self.disconnectcmd()
							return None
					try:
						msg = self.raw_msg.decode('utf-8').split('|')[0]
						returned_hash = self.raw_msg.decode('utf-8').split('|')[1]
						verification_hash = hashlib.sha256(msg.encode('utf-8') + self.encryption_key.encode('utf-8')).hexdigest()
					except:
						self.alert_disp_queue.put("[Mismatched verification hash returned!]")
						return None

					if returned_hash == verification_hash:
						try:
							self.dec_msg = self.decrypt(msg.encode('utf-8'), str(self.encryption_key))
						except:
							self.dec_msg = None
							return None

						self.recvmsg_disp_queue.put(self.dec_msg)

					else:
						self.alert_disp_queue.put("[Mismatched verification hash returned!]")
		else:
			if self.IPaddress not in eval(self.config_dict['Blacklist']):
				self.EstablishPeerConnection()

	# Encryption function using AES from the crypto library
	def encrypt(self, raw, key):
		raw = " ".join([str(ord(x)) for x in raw])
		key = hashlib.sha256(key.encode()).digest()
		raw = raw + (32 - len(raw) % 32) * chr(32 - len(raw) % 32)
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(key, AES.MODE_CBC, iv)
		return base64.b64encode(iv + cipher.encrypt(raw.encode()))
	# Decryption function using AES from the crypto library
	def decrypt(self, raw, key):
		key = hashlib.sha256(key.encode()).digest()
		raw = base64.b64decode(raw)
		iv = raw[:AES.block_size]
		cipher = AES.new(key, AES.MODE_CBC, iv)
		def _unpad(s):
			return s[:-ord(s[len(s)-1:])]
		out = "".join([chr(int(x)) for x in _unpad(cipher.decrypt(raw[AES.block_size:])).decode('utf-8').split(" ")])
		return out

	# Function which handles what stage the current setup is in
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

# Threaded process to avoid the wait from the "recvfrom" function
class ThreadedLoop(threading.Thread):
	def __init__(self, socket, queue):
		self.StartSocket = socket
		self.recv_queue = queue
		self.StartSocket.settimeout(0.1)
		threading.Thread.__init__(self)

	def run(self):
		try:
			(self.data,self.addr) = self.StartSocket.recvfrom(4096)
			self.recv_queue.put((self.data, self.addr))
		except:
			pass

# main function, defines tkinter and runs MainClass
def main():
	root = Tk()
	root.title("Cryo Chat")
	root.resizable(0,0)
	MainClass(root)
	root.mainloop()

# tests to make sure this script is being run correctly, then sets two global variables (paths), and then runs main function
if __name__ == '__main__':
	global scriptpath
	global folderpath
	folderpath = os.path.dirname(os.path.abspath(__file__))
	scriptpath = os.path.abspath(__file__)
	main()
