import os, sys
from tkinter import messagebox

if __name__ == '__main__':
	print('module file')
	sys.exit()

def ReadConfig(folderpath):
	if (os.path.exists(folderpath + '\\bin') == False):
		messagebox.showerror("bin folder missing", 'The "bin" folder is missing.\nPlease install the missing assets!')
		os.remove(folderpath + '\\bin\\config.txt')
		sys.exit()
	if (os.path.exists(folderpath + '\\bin\\config.txt') == False):
		config_dict = {'DefaultName':"Anonymous",'PeerPort':"4422",'Blacklist':"[""]",'LastConnectedIP':""}
		write_config = str(config_dict).replace('{','{\n').replace('}','\n}').replace(',',',\n').replace(' ', '')
		configfile = open(folderpath + '\\bin\\config.txt', 'w')
		configfile.write(write_config)
		configfile.close()
		return config_dict
	configfile = open(folderpath + '\\bin\\config.txt', 'r')
	cfg_content = configfile.read().replace('\n','')
	configfile.close()
	if cfg_content.startswith('{') and cfg_content.endswith('}') and cfg_content.count('{') == 1 and cfg_content.count('}') == 1:
		try:
			return eval(cfg_content)
		except:
			error()
	else:
		error()

	def error():
		msgbox_result = messagebox.askyesno("Config File Error", '"config.txt" is either corrupt or has missing data.\nWould you like to create a new one?')
		if (msgbox_result == True):
			os.remove(folderpath + '\\bin\\config.txt')
		sys.exit()