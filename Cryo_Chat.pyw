from tkinter import *
from tkinter import ttk, messagebox
from subprocess import Popen, PIPE
from tkinter.ttk import *
from Crypto import Random
from Crypto.Cipher import AES
from socket import socket, gethostbyname, gethostname, AF_INET, SOCK_DGRAM, SHUT_RDWR
import os, hashlib, binascii, sys, subprocess, time, threading, queue, ssl, base64, collections

random_function = ssl.RAND_bytes
PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF
GENERATOR = 2

class SettingsWindow():
	def __init__(self, root, cfg_dict, send_queue):
		self.config_dict = cfg_dict
		self.send_queue = send_queue

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

		self.nameEntry.insert(0, self.config_dict['DefaultName'])
		self.portEntry.insert(0, self.config_dict['PeerPort'])

		for obj in eval(self.config_dict['Blacklist']):
			self.blacklistListbox.insert(0, obj)

	def WriteChanges(self):
		if self.portEntry.get().isdigit():
			msgbox_result = messagebox.askyesno("Saving Changes", 'You have to restart to apply changes,\nQuit now?')
			if (msgbox_result == True):
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
		else:
			messagebox.showerror("Port Error", "Port must be an integer!")
			self.stRoot.focus()

	def AddIp(self):
		self.blacklistListbox.insert(0, str(self.blacklistEntry.get()))
		self.blacklistEntry.delete(0, END)

class MainWindow():
	def __init__(self, master, send_queue, notdisp_queue, recvdisp_queue, alertdisp_queue, ownmsgdisp_queue, cfg_dict, history):		
		self.config_dict = cfg_dict

		self.history_index = -1
		self.history = history
		self.send_queue = send_queue
		self.notif_disp_queue = notdisp_queue
		self.alert_disp_queue = alertdisp_queue
		self.recvmsg_disp_queue = recvdisp_queue
		self.ownmsgdisp_queue = ownmsgdisp_queue

		master.protocol("WM_DELETE_WINDOW", self.OnClosing)

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

		self.targetIpEntry.insert(0, self.config_dict["LastConnectedIP"])

		self.UpdateDisplay()

	def OpenSettings(self):
		try:
			self.sett_wind.stRoot.focus()
		except:
			self.sett_wind = SettingsWindow(self.master, self.config_dict, self.send_queue)

	def Connect(self):
		if self.connectButton.cget('text') == 'Connect':
			self.connectButton.config(state='disabled',text='Connecting')
			self.send_queue.put("/connect " + self.targetIpEntry.get())
		else:
			self.connectButton.config(state='normal',text='Connect')
			self.send_queue.put("/disconnect")

	def EntryHistory(self, arg):
		if len(self.history) > 0:
			if arg.keysym == 'Up' and self.history_index < len(self.history)-1:
				self.history_index += + 1

			elif arg.keysym == 'Down' and self.history_index >= 0:
				self.history_index -= 1

			self.inputEntry.delete(0, END)
			if self.history_index != -1:
				self.inputEntry.insert(0, self.history[self.history_index])


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

	def OnClosing(self):
		if messagebox.askokcancel("Quit?", "All current sessions will be disconnected."):
			threading.Thread(target=self.CloseApp).start()

	def CloseApp(self):
		self.send_queue.put('/exit')

class MainClass:
	def __init__(self, master):
		super(MainClass, self).__init__()
		
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
		
		self.ReadConfig()
		self.GUI = MainWindow(self.master, self.send_queue, self.notif_disp_queue, self.recvmsg_disp_queue, self.alert_disp_queue, self.ownmsg_disp_queue, self.config_dict, self.history)
		self.GUI.inputEntry.focus()
		self.TKLoop()

	def ReadConfig(self):
		if (os.path.exists(folderpath + '\\bin') == False):
			messagebox.showerror("bin folder missing", 'The "bin" folder is missing.\nPlease install the missing assets!')
			os.remove(folderpath + '\\bin\\config.txt')
			sys.exit()

		if (os.path.exists(folderpath + '\\bin\\config.txt') == False):

			self.config_dict = {'DefaultName':"Anonymous",'PeerPort':"4422",'Blacklist':"[""]",'LastConnectedIP':""}

			write_config = str(self.config_dict).replace('{','{\n').replace('}','\n}').replace(',',',\n').replace(' ', '')

			configfile = open(folderpath + '\\bin\\config.txt', 'w')
			configfile.write(write_config)
			configfile.close()

		configfile = open(folderpath + '\\bin\\config.txt', 'r')
		cfg_content = configfile.read().replace('\n','')
		configfile.close()

		try:
			self.config_dict = eval(cfg_content)

		except:
			msgbox_result = messagebox.askyesno("Config File Error", '"config.txt" is either corrupt or has missing data.\nWould you like to create a new one?')
			if (msgbox_result == True):
				os.remove(folderpath + '\\bin\\config.txt')
			sys.exit()

		self.StartListener()

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
		

	def TKLoop(self):
		ThreadedLoop(self.StartSocket, self.recv_queue).start()
		self.ProcessOutgoing()
		self.ProcessIncoming()
		self.GUI.UpdateDisplay()
		self.master.after(100, self.TKLoop)

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

	def encrypt(self, raw, key):
		raw = " ".join([str(ord(x)) for x in raw])
		key = hashlib.sha256(key.encode()).digest()
		raw = raw + (32 - len(raw) % 32) * chr(32 - len(raw) % 32)
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(key, AES.MODE_CBC, iv)
		return base64.b64encode(iv + cipher.encrypt(raw.encode()))

	def decrypt(self, raw, key):
		key = hashlib.sha256(key.encode()).digest()
		raw = base64.b64decode(raw)
		iv = raw[:AES.block_size]
		cipher = AES.new(key, AES.MODE_CBC, iv)
		def _unpad(s):
			return s[:-ord(s[len(s)-1:])]
		out = "".join([chr(int(x)) for x in _unpad(cipher.decrypt(raw[AES.block_size:])).decode('utf-8').split(" ")])
		return out

	def EstablishPeerConnection(self):
		eval("self.Stage_" + str(self.stage) + "()")

	def Stage_0(self):
		if self.raw_msg == b'<PEER_START>' or self.startconnect == True:
			self.GUI.connectButton.config(state='disabled',text='Connecting')
			self.keygen = KeyGenerator()
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

class KeyGenerator:
	def __init__(self, key_length=600):
		self.key_length = max(600, key_length)
		self.prime = PRIME
		self.generator = GENERATOR

	def private_key(self, length):
		_rand = 0
		_bytes = length // 8 + 8
		while(_rand.bit_length() < length):
			_rand = int.from_bytes(random_function(_bytes), byteorder='big')
		self.private_key = _rand

	def public_key(self):
		self.pk = self.public_key = pow(self.generator, self.private_key, self.prime)
		return self.pk

	def secret_key(self, public_key):
		self.shared_secret = pow(public_key, self.private_key, self.prime)
		shared_secret_bytes = self.shared_secret.to_bytes(self.shared_secret.bit_length() // 8 + 1, byteorder='big')

		hash_alg = hashlib.sha256()
		hash_alg.update(bytes(shared_secret_bytes))
		self.key = hash_alg.hexdigest()

def main():
	root = Tk()
	root.title("Cryo Chat")
	root.resizable(0,0)
	MainClass(root)
	root.mainloop()

if __name__ == '__main__':
	global scriptpath
	global folderpath
	folderpath = os.path.dirname(os.path.abspath(__file__))
	scriptpath = os.path.abspath(__file__)
	main()